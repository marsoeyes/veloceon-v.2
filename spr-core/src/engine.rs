//! Parallel candidate search: enumerate, checksum-filter, stretch, derive, match.

use std::borrow::Cow;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use crate::deriv::{default_derivations, DerivationSpec, Network, PreparedDerivations};
use crate::mnemonic::{self, Layout};
use crate::target::Target;
use crate::wordlist::{Language, WordList};
use crate::{Error, Result};

/// Maximum number of fully unknown words for an unrestricted search.
pub const MAX_MISSING_WORDS: usize = 3;

/// Hard cap on the candidate space accepted without restricted word lists.
const MAX_UNRESTRICTED_SPACE: u64 = 50_000_000;

#[derive(Clone, Debug)]
pub struct SearchConfig {
    pub language: Language,
    /// One entry per word; `None` marks an unknown position.
    pub template: Vec<Option<String>>,
    /// Optional restricted candidate words per position (0-based index).
    pub position_candidates: Vec<(usize, Vec<String>)>,
    pub passphrase: String,
    pub derivations: Vec<DerivationSpec>,
    pub targets: Vec<Target>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Hit {
    pub phrase: String,
    pub network: Network,
    pub path: String,
    pub address: String,
    pub target: String,
    pub mode: String,
    pub found_at: u64,
}

pub struct SearchPlan {
    pub language: Language,
    pub layout: Layout,
    pub template: Vec<Option<u16>>,
    pub phrase_template: Vec<Option<String>>,
    pub unknown: Vec<usize>,
    pub values: Vec<Vec<u16>>,
    pub total: u64,
    pub passphrase: String,
    pub word_table: &'static [&'static str; 2048],
    pub derivations: PreparedDerivations,
    pub targets: Vec<Target>,
    pub networks: Vec<Network>,
    need_normalize: bool,
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn build_plan(cfg: &SearchConfig) -> Result<SearchPlan> {
    let layout = Layout::new(cfg.template.len())
        .ok_or(Error::WordCount(cfg.template.len()))?;
    let wordlist = WordList::new(cfg.language);

    let mut template = Vec::with_capacity(cfg.template.len());
    let mut unknown = Vec::new();
    for (i, word) in cfg.template.iter().enumerate() {
        match word {
            Some(w) => match wordlist.index_of(w) {
                Some(idx) => template.push(Some(idx)),
                None => {
                    return Err(Error::UnknownWord {
                        position: i + 1,
                        word: w.clone(),
                    })
                }
            },
            None => {
                template.push(None);
                unknown.push(i);
            }
        }
    }
    if unknown.is_empty() {
        return Err(Error::Msg(
            "no unknown words: nothing to recover (use `spr derive` to inspect a complete phrase)"
                .into(),
        ));
    }

    let mut values: Vec<Vec<u16>> = Vec::with_capacity(unknown.len());
    for &pos in &unknown {
        let restricted = cfg
            .position_candidates
            .iter()
            .find(|(p, _)| *p == pos)
            .map(|(_, words)| words.clone());
        match restricted {
            Some(words) => {
                if words.is_empty() {
                    return Err(Error::Msg(format!(
                        "position {} has an empty candidate list",
                        pos + 1
                    )));
                }
                let mut idxs = Vec::with_capacity(words.len());
                for w in words {
                    match wordlist.index_of(&w) {
                        Some(i) => idxs.push(i),
                        None => {
                            return Err(Error::UnknownWord {
                                position: pos + 1,
                                word: w,
                            })
                        }
                    }
                }
                idxs.sort_unstable();
                idxs.dedup();
                values.push(idxs);
            }
            None => values.push((0..2048u16).collect()),
        }
    }

    let mut total: u64 = 1;
    for v in &values {
        total = total
            .checked_mul(v.len() as u64)
            .ok_or_else(|| Error::Msg("candidate space overflows u64".into()))?;
    }
    if unknown.len() > MAX_MISSING_WORDS && total > MAX_UNRESTRICTED_SPACE {
        return Err(Error::TooManyMissing(unknown.len()));
    }

    if cfg.targets.is_empty() {
        return Err(Error::Msg(
            "no target address supplied: recovery only reports candidates that derive one of \
             your known addresses (use --target net:address)"
                .into(),
        ));
    }

    let mut specs = cfg.derivations.clone();
    if specs.is_empty() {
        let mut nets: Vec<Network> = cfg.targets.iter().map(|t| t.network).collect();
        nets.sort_by_key(|n| n.as_str());
        nets.dedup();
        for n in nets {
            specs.extend(default_derivations(n, 1));
        }
    }
    let target_networks: Vec<Network> = {
        let mut v: Vec<Network> = cfg.targets.iter().map(|t| t.network).collect();
        v.sort_by_key(|n| n.as_str());
        v.dedup();
        v
    };
    let derivations = PreparedDerivations::new(&specs, &target_networks);
    if derivations.is_empty() {
        return Err(Error::Empty(
            "no derivation paths match the target networks".into(),
        ));
    }

    let need_normalize = cfg.language != Language::English
        && wordlist.words().iter().any(|w| !w.is_ascii());
    let passphrase = if cfg.passphrase.is_ascii() {
        cfg.passphrase.clone()
    } else {
        mnemonic::nfkd(&cfg.passphrase)
    };

    Ok(SearchPlan {
        language: cfg.language,
        layout,
        template,
        phrase_template: cfg.template.clone(),
        unknown,
        values,
        total,
        passphrase,
        word_table: wordlist.words(),
        derivations,
        targets: cfg.targets.clone(),
        networks: target_networks,
        need_normalize,
    })
}

pub struct Progress {
    pub total: u64,
    pub checked: AtomicU64,
    pub seeds: AtomicU64,
    pub found: Mutex<Vec<Hit>>,
    pub stop: AtomicBool,
    pub pause: AtomicBool,
    pub finished: AtomicBool,
    pub started: Instant,
    pub threads: usize,
    pub stop_on_first: bool,
    pub max_hits: usize,
    pub message: Mutex<String>,
}

impl Progress {
    pub fn new(total: u64, threads: usize, stop_on_first: bool, max_hits: usize) -> Self {
        Self {
            total,
            checked: AtomicU64::new(0),
            seeds: AtomicU64::new(0),
            found: Mutex::new(Vec::new()),
            stop: AtomicBool::new(false),
            pause: AtomicBool::new(false),
            finished: AtomicBool::new(false),
            started: Instant::now(),
            threads,
            stop_on_first,
            max_hits: max_hits.max(1),
            message: Mutex::new(String::new()),
        }
    }

    pub fn record(&self, hit: Hit) {
        let mut found = self.found.lock().unwrap();
        if found
            .iter()
            .any(|h| h.address == hit.address && h.network == hit.network && h.phrase == hit.phrase)
        {
            return;
        }
        found.push(hit);
        let count = found.len();
        drop(found);
        if self.stop_on_first || count >= self.max_hits {
            self.stop.store(true, Ordering::SeqCst);
        }
    }

    pub fn hits(&self) -> Vec<Hit> {
        self.found.lock().unwrap().clone()
    }

    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
    }

    pub fn pause(&self) {
        self.pause.store(true, Ordering::SeqCst);
    }

    pub fn resume(&self) {
        self.pause.store(false, Ordering::SeqCst);
    }

    pub fn snapshot(&self) -> Snapshot {
        let checked = self.checked.load(Ordering::Relaxed);
        let elapsed = self.started.elapsed().as_secs_f64();
        let rate = if elapsed > 0.0 {
            checked as f64 / elapsed
        } else {
            0.0
        };
        let remaining = self.total.saturating_sub(checked);
        let eta = if rate > 1.0 {
            remaining as f64 / rate
        } else {
            0.0
        };
        let pct = if self.total > 0 {
            (checked as f64 / self.total as f64) * 100.0
        } else {
            0.0
        };
        let hits = self.hits();
        Snapshot {
            total: self.total,
            checked,
            seeds: self.seeds.load(Ordering::Relaxed),
            found: hits.len(),
            elapsed_secs: elapsed,
            rate,
            eta_secs: eta,
            pct,
            finished: self.finished.load(Ordering::SeqCst),
            stopped: self.stop.load(Ordering::SeqCst),
            paused: self.pause.load(Ordering::SeqCst),
            threads: self.threads,
            message: self.message.lock().unwrap().clone(),
            hits,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Snapshot {
    pub total: u64,
    pub checked: u64,
    pub seeds: u64,
    pub found: usize,
    pub elapsed_secs: f64,
    pub rate: f64,
    pub eta_secs: f64,
    pub pct: f64,
    pub finished: bool,
    pub stopped: bool,
    pub paused: bool,
    pub threads: usize,
    pub message: String,
    pub hits: Vec<Hit>,
}

struct Worker {
    indices: Vec<u16>,
    entropy: [u8; 32],
    phrase: String,
}

impl Worker {
    fn new(plan: &SearchPlan) -> Self {
        Self {
            indices: plan.template.iter().map(|x| x.unwrap_or(0)).collect(),
            entropy: [0u8; 32],
            phrase: String::with_capacity(plan.layout.words * 10),
        }
    }

    #[inline]
    fn test(&mut self, mut flat: u64, plan: &SearchPlan, progress: &Progress) {
        if progress.stop.load(Ordering::Relaxed) {
            return;
        }
        while progress.pause.load(Ordering::Relaxed) && !progress.stop.load(Ordering::Relaxed) {
            std::thread::sleep(Duration::from_millis(20));
        }

        // Derive the word indices for this flat index (last unknown varies fastest).
        for j in (0..plan.unknown.len()).rev() {
            let len = plan.values[j].len() as u64;
            let v = (flat % len) as usize;
            flat /= len;
            self.indices[plan.unknown[j]] = plan.values[j][v];
        }
        progress.checked.fetch_add(1, Ordering::Relaxed);

        // 1) BIP39 checksum: rejects 15/16 (12 words) to 255/256 (24 words) of candidates.
        if !mnemonic::checksum_ok(&self.indices, &plan.layout) {
            return;
        }
        progress.seeds.fetch_add(1, Ordering::Relaxed);

        // 2) Build the phrase (only for checksum-valid candidates).
        self.phrase.clear();
        for (i, &idx) in self.indices.iter().enumerate() {
            if i > 0 {
                self.phrase.push_str(plan.language.separator());
            }
            self.phrase.push_str(plan.word_table[idx as usize]);
        }
        let phrase: Cow<'_, str> = if plan.need_normalize {
            Cow::Owned(mnemonic::nfkd(&self.phrase))
        } else {
            Cow::Borrowed(self.phrase.as_str())
        };

        // 3) Seed stretching (PBKDF2-HMAC-SHA512, 2048 rounds).
        let seed = mnemonic::seed_from_phrase(phrase.as_ref(), &plan.passphrase);
        mnemonic::extract_entropy(&self.indices, &plan.layout, &mut self.entropy);
        let entropy = &self.entropy[..plan.layout.ent_bytes];

        // 4) Derive and compare.
        let mut matched: Vec<Hit> = Vec::new();
        plan.derivations.evaluate(
            &seed,
            entropy,
            &plan.passphrase,
            &mut |network, path, address| {
                if let Some(t) = plan.targets.iter().find(|t| t.matches(network, &address)) {
                    matched.push(Hit {
                        phrase: phrase.as_ref().to_string(),
                        network,
                        path: path.to_string(),
                        address,
                        target: t.value.clone(),
                        mode: t.mode.as_str().to_string(),
                        found_at: now_unix(),
                    });
                }
            },
        );
        for hit in matched {
            progress.record(hit);
        }
    }
}

/// Run the plan to completion (or until stopped / first hit).
pub fn run(plan: Arc<SearchPlan>, progress: Arc<Progress>) -> Result<()> {
    let total = plan.total;
    run_range(plan, progress, 0, total)
}

/// Run only the `[start, end)` slice of the candidate space. This is what lets a
/// single search be split over several processes or machines (`--shard i/n`).
pub fn run_range(
    plan: Arc<SearchPlan>,
    progress: Arc<Progress>,
    start: u64,
    end: u64,
) -> Result<()> {
    let threads = progress.threads.max(1);
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .thread_name(|i| format!("spr-worker-{i}"))
        .build()
        .map_err(|e| Error::Msg(format!("could not start worker pool: {e}")))?;

    let end = end.min(plan.total);
    let start = start.min(end);
    let result = pool.install(|| {
        (start..end)
            .into_par_iter()
            .try_for_each_init(
                || Worker::new(&plan),
                |worker, i| {
                    if progress.stop.load(Ordering::Relaxed) {
                        Err(())
                    } else {
                        worker.test(i, &plan, &progress);
                        Ok(())
                    }
                },
            )
    });

    progress.finished.store(true, Ordering::SeqCst);
    let hits = progress.found.lock().unwrap().len();
    let mut msg = progress.message.lock().unwrap();
    *msg = if hits > 0 {
        format!("{hits} match(es) found")
    } else if result.is_err() {
        "stopped".to_string()
    } else {
        "search complete: no match".to_string()
    };
    Ok(())
}

/// Derive every address for a complete phrase (used by `spr derive` and the dashboard).
pub fn derive_all(
    phrase: &str,
    language: Language,
    passphrase: &str,
    specs: &[DerivationSpec],
) -> Result<Vec<(Network, String, String)>> {
    let wordlist = WordList::new(language);
    let words: Vec<&str> = phrase.split_whitespace().collect();
    let layout = Layout::new(words.len()).ok_or(Error::WordCount(words.len()))?;
    let mut indices = Vec::with_capacity(words.len());
    for (i, w) in words.iter().enumerate() {
        let idx = wordlist
            .index_of(w)
            .ok_or_else(|| Error::UnknownWord {
                position: i + 1,
                word: w.to_string(),
            })?;
        indices.push(idx);
    }
    if !mnemonic::checksum_ok(&indices, &layout) {
        return Err(Error::Msg("phrase fails the BIP39 checksum".into()));
    }
    let mut entropy = [0u8; 32];
    mnemonic::extract_entropy(&indices, &layout, &mut entropy);

    let norm_phrase = if language != Language::English && words.iter().any(|w| !w.is_ascii()) {
        mnemonic::nfkd(phrase)
    } else {
        phrase.to_string()
    };
    let pass = if passphrase.is_ascii() {
        passphrase.to_string()
    } else {
        mnemonic::nfkd(passphrase)
    };
    let seed = mnemonic::seed_from_phrase(&norm_phrase, &pass);
    let prepared = PreparedDerivations::new(specs, &[]);
    let mut out = Vec::new();
    prepared.evaluate(
        &seed,
        &entropy[..layout.ent_bytes],
        &pass,
        &mut |network, path, address| {
            out.push((network, path.to_string(), address));
        },
    );
    Ok(out)
}
