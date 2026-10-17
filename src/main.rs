//! `spr` — offline seed phrase recovery CLI + dashboard.

mod web;

use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::{Args, Parser, Subcommand};
use indicatif::{ProgressBar, ProgressStyle};
use spr_core::deriv::{default_derivations, spec_from_path};
use spr_core::{
    build_plan, derive_all, run_range, Hit, Language, MatchMode, Network, Progress, SearchConfig,
    Target,
    VERSION,
};

const BANNER: &str = r#"
  ___  ___ ___
 / __|| _ \ _ \   seed phrase recoverer
 \__ \|  _/  _/   EVM · BTC · SOL · XRP · TRX · DOGE · ADA
 |___/|_| |_|     offline · multi-threaded · deterministic
"#;

#[derive(Parser)]
#[command(
    name = "spr",
    version = VERSION,
    about = "Recover a lost or partial BIP39 seed phrase by matching your own known addresses",
    long_about = None,
    after_help = "Examples:\n  \
      spr recover --phrase \"lucky ? ? yourself\" --target evm:0x9858EfFD232B4033E47d90003D41EC34EcaEda94\n  \
      spr recover --phrase \"...\" --missing 4,9 --target btc:1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA\n  \
      spr derive --phrase \"<full mnemonic>\" --network all\n  \
      spr selfcheck\n  \
      spr serve --port 8080\n"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Search for the missing words of a partial seed phrase.
    Recover(RecoverArgs),
    /// Derive every address for a complete phrase (sanity check / backup sheet).
    Derive(DeriveArgs),
    /// Verify this build against published derivation vectors.
    Selfcheck(SelfcheckArgs),
    /// Measure how many seeds per second this machine can try.
    Bench(BenchArgs),
    /// Serve the web dashboard (usable from Colab / Kaggle / vast.ai port forwards).
    Serve(ServeArgs),
    /// Inspect the BIP39 wordlists.
    Wordlist(WordlistArgs),
}

#[derive(Args)]
struct RecoverArgs {
    /// Phrase template; use `?`, `*` or `_` for unknown words.
    #[arg(long, value_name = "WORDS")]
    phrase: Option<String>,
    /// Read the phrase template from a file.
    #[arg(long, value_name = "PATH", conflicts_with = "phrase")]
    file: Option<PathBuf>,
    /// 1-based positions that are unknown, e.g. `--missing 4,9`.
    #[arg(long, value_delimiter = ',', value_name = "POSITIONS")]
    missing: Vec<usize>,
    /// Restrict a position to specific words, e.g. `--at 3=lucky,lonely`.
    #[arg(long = "at", value_name = "POS=WORDS")]
    at: Vec<String>,
    /// BIP39 wordlist language.
    #[arg(long, default_value = "english")]
    lang: String,
    /// BIP39 passphrase (the optional "25th word").
    #[arg(long, default_value = "")]
    passphrase: String,
    /// Networks to derive addresses for (default: networks of the targets).
    #[arg(long, value_delimiter = ',', value_name = "NETS")]
    network: Vec<String>,
    /// Known address, as `network:address` (repeatable).
    #[arg(long, value_name = "NET:ADDR")]
    target: Vec<String>,
    /// File with one `network:address` per line ('#' comments allowed).
    #[arg(long, value_name = "PATH")]
    target_file: Option<PathBuf>,
    /// How to compare candidates against the target addresses.
    #[arg(long, default_value = "exact")]
    r#match: String,
    /// Number of addresses per derivation path (account index breadth).
    #[arg(long, default_value_t = 1)]
    breadth: u32,
    /// Explicit derivation path (repeatable), e.g. `--path "m/44'/60'/0'/0/0"`.
    #[arg(long, value_name = "PATH")]
    path: Vec<String>,
    /// Worker threads (default: all CPU cores).
    #[arg(long, short = 't')]
    threads: Option<usize>,
    /// Print the search plan and exit.
    #[arg(long)]
    dry_run: bool,
    /// Abort if the candidate space is larger than this.
    #[arg(long, value_name = "N")]
    max_candidates: Option<u64>,
    /// Split the space over N processes: run `--shard 1/4`, `--shard 2/4`, ...
    #[arg(long, value_name = "I/N")]
    shard: Option<String>,
    /// Keep searching after the first hit and report every match.
    #[arg(long)]
    all: bool,
    /// Stop after this many matches (default 1, or unlimited with --all).
    #[arg(long, default_value_t = 1)]
    max_hits: usize,
    /// Write results as JSON to this path ('-' for stdout).
    #[arg(long, value_name = "PATH")]
    json: Option<String>,
    /// Suppress the live progress bar.
    #[arg(long, short = 'q')]
    quiet: bool,
}

#[derive(Args)]
struct DeriveArgs {
    /// Complete mnemonic (or a word list).
    #[arg(long, value_name = "WORDS")]
    phrase: Option<String>,
    #[arg(long, value_name = "PATH", conflicts_with = "phrase")]
    file: Option<PathBuf>,
    #[arg(long, default_value = "english")]
    lang: String,
    #[arg(long, default_value = "")]
    passphrase: String,
    /// `all` or a comma separated list of networks.
    #[arg(long, default_value = "all")]
    network: String,
    #[arg(long, default_value_t = 1)]
    breadth: u32,
    #[arg(long, value_name = "PATH")]
    path: Vec<String>,
    #[arg(long, value_name = "PATH")]
    json: Option<String>,
}

#[derive(Args)]
struct SelfcheckArgs {
    /// Run only the fast derivation vectors.
    #[arg(long)]
    quick: bool,
    #[arg(long)]
    json: Option<String>,
}

#[derive(Args)]
struct BenchArgs {
    #[arg(long, default_value_t = 5)]
    seconds: u64,
    #[arg(long, short = 't')]
    threads: Option<usize>,
}

#[derive(Args)]
struct ServeArgs {
    #[arg(long, default_value = "0.0.0.0")]
    host: String,
    #[arg(long, default_value_t = 8080)]
    port: u16,
}

#[derive(Args)]
struct WordlistArgs {
    #[arg(long, default_value = "english")]
    lang: String,
    /// Check whether a word is in the list.
    #[arg(long, value_name = "WORD")]
    check: Option<String>,
    /// Print the full wordlist.
    #[arg(long)]
    list: bool,
}

fn main() {
    let cli = Cli::parse();
    let code = match cli.cmd {
        Cmd::Recover(a) => cmd_recover(a),
        Cmd::Derive(a) => cmd_derive(a),
        Cmd::Selfcheck(a) => cmd_selfcheck(a),
        Cmd::Bench(a) => cmd_bench(a),
        Cmd::Serve(a) => web::serve(&a.host, a.port),
        Cmd::Wordlist(a) => cmd_wordlist(a),
    };
    std::process::exit(code);
}

fn threads_or_default(t: Option<usize>) -> usize {
    t.unwrap_or_else(|| {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
    })
    .max(1)
}

fn human_int(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
}

fn human_duration(secs: f64) -> String {
    if !secs.is_finite() || secs <= 0.0 {
        return "—".to_string();
    }
    let s = secs as u64;
    if s < 60 {
        format!("{s}s")
    } else if s < 3600 {
        format!("{}m {:02}s", s / 60, s % 60)
    } else if s < 86_400 {
        format!("{}h {:02}m", s / 3600, (s % 3600) / 60)
    } else {
        format!("{}d {:02}h", s / 86_400, (s % 86_400) / 3600)
    }
}

fn parse_shard(spec: Option<&str>, total: u64) -> Result<(u64, u64), String> {
    let Some(spec) = spec else {
        return Ok((0, total));
    };
    let (idx, count) = spec
        .split_once('/')
        .ok_or_else(|| format!("--shard expects I/N, got {spec:?}"))?;
    let idx: u64 = idx
        .trim()
        .parse()
        .map_err(|_| format!("--shard index {idx:?} is not a number"))?;
    let count: u64 = count
        .trim()
        .parse()
        .map_err(|_| format!("--shard count {count:?} is not a number"))?;
    if count == 0 || idx == 0 || idx > count {
        return Err(format!("--shard {spec:?} must satisfy 1 <= I <= N"));
    }
    let size = total / count;
    let start = (idx - 1) * size;
    let end = if idx == count { total } else { start + size };
    Ok((start, end))
}

fn read_phrase(phrase: Option<String>, file: Option<PathBuf>) -> Result<String, String> {
    if let Some(p) = phrase {
        return Ok(p);
    }
    if let Some(f) = file {
        let text = std::fs::read_to_string(&f).map_err(|e| format!("{}: {e}", f.display()))?;
        let line = text
            .lines()
            .find(|l| !l.trim().is_empty())
            .ok_or_else(|| format!("{} is empty", f.display()))?;
        return Ok(line.trim().to_string());
    }
    Err("provide --phrase or --file".to_string())
}

fn parse_template(
    raw: &str,
    missing: &[usize],
    at: &[String],
    lang: Language,
) -> Result<(Vec<Option<String>>, Vec<(usize, Vec<String>)>), String> {
    let mut template = spr_core::mnemonic::split_template(raw);
    for pos in missing {
        if *pos == 0 || *pos > template.len() {
            return Err(format!(
                "--missing {pos} is outside the phrase (1..{})",
                template.len()
            ));
        }
        template[pos - 1] = None;
    }
    let mut restricted = Vec::new();
    for spec in at {
        let (pos, words) = spec
            .split_once('=')
            .ok_or_else(|| format!("--at expects POS=word1,word2, got {spec:?}"))?;
        let pos: usize = pos
            .trim()
            .parse()
            .map_err(|_| format!("--at position {pos:?} is not a number"))?;
        if pos == 0 || pos > template.len() {
            return Err(format!("--at {pos} is outside the phrase"));
        }
        let words: Vec<String> = words
            .split(',')
            .map(|w| w.trim().to_string())
            .filter(|w| !w.is_empty())
            .collect();
        if words.is_empty() {
            return Err(format!("--at {pos} has no candidate words"));
        }
        let wl = spr_core::WordList::new(lang);
        for w in &words {
            if !wl.contains(w) {
                return Err(format!("--at {pos}: {w:?} is not in the wordlist"));
            }
        }
        template[pos - 1] = None;
        restricted.push((pos - 1, words));
    }
    Ok((template, restricted))
}

fn load_targets(a: &RecoverArgs, mode: MatchMode) -> Result<Vec<Target>, String> {
    let mut raw: Vec<String> = a.target.clone();
    if let Some(path) = &a.target_file {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        for line in text.lines() {
            let line = line.split('#').next().unwrap_or("").trim();
            if !line.is_empty() {
                raw.push(line.to_string());
            }
        }
    }
    if raw.is_empty() {
        return Err(
            "no target address: pass --target network:address (the address you know belongs to \
             the wallet you are recovering) or --target-file"
                .to_string(),
        );
    }
    let default_net = if a.network.len() == 1 {
        Some(
            a.network[0]
                .parse::<Network>()
                .map_err(|e| e.to_string())?,
        )
    } else {
        None
    };
    let mut out = Vec::new();
    for spec in raw {
        let t = Target::parse(&spec, default_net).map_err(|e| e.to_string())?;
        out.push(t.with_mode(mode));
    }
    Ok(out)
}

fn build_derivations(
    networks: &[String],
    paths: &[String],
    breadth: u32,
    targets: &[Target],
) -> Result<Vec<spr_core::DerivationSpec>, String> {
    let mut nets: Vec<Network> = Vec::new();
    for n in networks {
        let net: Network = n.parse().map_err(|e: spr_core::Error| e.to_string())?;
        if !nets.contains(&net) {
            nets.push(net);
        }
    }
    if nets.is_empty() {
        for t in targets {
            if !nets.contains(&t.network) {
                nets.push(t.network);
            }
        }
    }
    let mut specs = Vec::new();
    if paths.is_empty() {
        for n in nets {
            specs.extend(default_derivations(n, breadth));
        }
    } else {
        for p in paths {
            let mut matched = false;
            for n in &nets {
                match spec_from_path(*n, p) {
                    Ok(s) => {
                        specs.push(s);
                        matched = true;
                    }
                    Err(_) => continue,
                }
            }
            if !matched {
                return Err(format!(
                    "--path {p:?} does not apply to the selected networks ({})",
                    nets
                        .iter()
                        .map(|n| n.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
        }
    }
    Ok(specs)
}

fn cmd_recover(a: RecoverArgs) -> i32 {
    let lang: Language = match a.lang.parse() {
        Ok(l) => l,
        Err(e) => {
            eprintln!("error: {e}");
            return 2;
        }
    };
    let mode = match MatchMode::parse(&a.r#match) {
        Some(m) => m,
        None => {
            eprintln!("error: --match must be exact, prefix, suffix or contains");
            return 2;
        }
    };
    let raw_phrase = match read_phrase(a.phrase.clone(), a.file.clone()) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: {e}");
            return 2;
        }
    };
    let (template, restricted) = match parse_template(&raw_phrase, &a.missing, &a.at, lang) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: {e}");
            return 2;
        }
    };
    let targets = match load_targets(&a, mode) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("error: {e}");
            return 2;
        }
    };
    let derivations = match build_derivations(&a.network, &a.path, a.breadth, &targets) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("error: {e}");
            return 2;
        }
    };

    let threads = threads_or_default(a.threads);
    let cfg = SearchConfig {
        language: lang,
        template,
        position_candidates: restricted,
        passphrase: a.passphrase.clone(),
        derivations,
        targets: targets.clone(),
    };
    let plan = match build_plan(&cfg) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: {e}");
            return 2;
        }
    };
    if let Some(cap) = a.max_candidates {
        if plan.total > cap {
            eprintln!(
                "error: candidate space is {} (over --max-candidates {})",
                human_int(plan.total),
                human_int(cap)
            );
            return 2;
        }
    }

    if !a.quiet {
        print!("{BANNER}");
        println!("  workers        {threads}");
        println!(
            "  wordlist       {} ({} words)",
            lang.code(),
            spr_core::WordList::new(lang).words().len()
        );
        println!(
            "  template       {}",
            plan.phrase_template
                .iter()
                .map(|w| w.clone().unwrap_or_else(|| "?".into()))
                .collect::<Vec<_>>()
                .join(" ")
        );
        println!(
            "  unknown        {} word(s) at {}",
            plan.unknown.len(),
            plan.unknown
                .iter()
                .map(|i| (i + 1).to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
        println!("  combinations   {}", human_int(plan.total));
        let seeds = plan.total / (1u64 << plan.layout.cs_bits);
        println!(
            "  after checksum ≈ {} seeds ({} checksum bits)",
            human_int(seeds),
            plan.layout.cs_bits
        );
        println!("  derivations    {}", plan.derivations.len());
        for t in &targets {
            println!(
                "  target         {} · {} · {}",
                t.network,
                t.value,
                t.mode.as_str()
            );
        }
        println!();
    }
    if a.dry_run {
        return 0;
    }

    let (shard_start, shard_end) = match parse_shard(a.shard.as_deref(), plan.total) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: {e}");
            return 2;
        }
    };
    if !a.quiet && shard_end - shard_start != plan.total {
        println!(
            "  shard          {}..{} of {}",
            human_int(shard_start),
            human_int(shard_end),
            human_int(plan.total)
        );
    }

    let max_hits = if a.all { usize::MAX } else { a.max_hits };
    let progress = Arc::new(Progress::new(
        shard_end - shard_start,
        threads,
        !a.all,
        max_hits,
    ));
    let started = Instant::now();

    let bar = if a.quiet {
        None
    } else {
        let bar = ProgressBar::new(shard_end - shard_start);
        bar.set_style(
            ProgressStyle::with_template(
                "{spinner:.yellow} {msg} · {per_sec} checked · ETA {eta}",
            )
            .unwrap()
            .tick_chars("⠁⠂⠄⡀⢀⠠⠐⠈ "),
        );
        bar.enable_steady_tick(Duration::from_millis(120));
        Some(bar)
    };

    let printed = Arc::new(AtomicU64::new(0));
    let monitor = {
        let progress = progress.clone();
        let printed = printed.clone();
        let bar = bar.clone();
        let quiet = a.quiet;
        std::thread::spawn(move || loop {
            let snap = progress.snapshot();
            let done = snap.finished || progress.stop.load(Ordering::Relaxed);
            if let Some(bar) = &bar {
                bar.set_position(snap.checked);
                bar.set_message(format!(
                    "seed {}/s · {} found",
                    snap.rate.round() as u64,
                    snap.found
                ));
            }
            let seen = printed.load(Ordering::Relaxed) as usize;
            if snap.hits.len() > seen {
                if let Some(bar) = &bar {
                    bar.suspend(|| {});
                }
                for hit in &snap.hits[seen..] {
                    if !quiet {
                        println!("\n  ✔ MATCH  {}  {}\n", hit.network, hit.path);
                        println!("    phrase  {}", hit.phrase);
                        println!("    address {}", hit.address);
                        println!("    target  {}\n", hit.target);
                    }
                    let _ = std::io::stdout().flush();
                }
                printed.store(snap.hits.len() as u64, Ordering::Relaxed);
            }
            if done {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        })
    };

    let result = run_range(
        Arc::new(plan),
        progress.clone(),
        shard_start,
        shard_end,
    );
    let _ = monitor.join();
    if let Some(bar) = bar {
        bar.finish_and_clear();
    }

    let elapsed = started.elapsed().as_secs_f64();
    let snapshot = progress.snapshot();
    let hits: Vec<Hit> = snapshot.hits.clone();

    if let Err(e) = result {
        eprintln!("error: {e}");
        return 1;
    }

    if a.json.is_some() || !a.quiet {
        let report = serde_json::json!({
            "version": VERSION,
            "checked": snapshot.checked,
            "seeds": snapshot.seeds,
            "total": snapshot.total,
            "elapsed_secs": elapsed,
            "rate": snapshot.rate,
            "found": hits.len(),
            "hits": hits,
        });
        if let Some(path) = &a.json {
            let text = serde_json::to_string_pretty(&report).unwrap_or_default();
            if path == "-" {
                println!("{text}");
            } else if let Err(e) = std::fs::write(path, text) {
                eprintln!("error writing {path}: {e}");
                return 1;
            } else if !a.quiet {
                println!("  results written to {path}");
            }
        } else if !a.quiet {
            println!(
                "  done in {} · {} checked · {:.0}/s · {} match(es)",
                human_duration(elapsed),
                human_int(snapshot.checked),
                snapshot.rate,
                hits.len()
            );
        }
    }

    if hits.is_empty() {
        1
    } else {
        0
    }
}

fn cmd_derive(a: DeriveArgs) -> i32 {
    let lang: Language = match a.lang.parse() {
        Ok(l) => l,
        Err(e) => {
            eprintln!("error: {e}");
            return 2;
        }
    };
    let phrase = match read_phrase(a.phrase.clone(), a.file.clone()) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: {e}");
            return 2;
        }
    };
    let nets: Vec<Network> = if a.network.eq_ignore_ascii_case("all") {
        Network::ALL.to_vec()
    } else {
        let mut v = Vec::new();
        for n in a.network.split(',') {
            match n.trim().parse::<Network>() {
                Ok(net) => {
                    if !v.contains(&net) {
                        v.push(net);
                    }
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    return 2;
                }
            }
        }
        v
    };
    let mut specs = Vec::new();
    if a.path.is_empty() {
        for n in &nets {
            specs.extend(default_derivations(*n, a.breadth));
        }
    } else {
        for p in &a.path {
            for n in &nets {
                if let Ok(s) = spec_from_path(*n, p) {
                    specs.push(s);
                }
            }
        }
    }
    let rows = match derive_all(&phrase, lang, &a.passphrase, &specs) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {e}");
            return 2;
        }
    };
    if let Some(path) = &a.json {
        let json = serde_json::json!({
            "phrase": phrase,
            "language": lang.code(),
            "passphrase": !a.passphrase.is_empty(),
            "addresses": rows.iter().map(|(n, p, a)| serde_json::json!({
                "network": n.as_str(), "path": p, "address": a
            })).collect::<Vec<_>>(),
        });
        let text = serde_json::to_string_pretty(&json).unwrap_or_default();
        if path == "-" {
            println!("{text}");
        } else if let Err(e) = std::fs::write(path, text) {
            eprintln!("error writing {path}: {e}");
            return 1;
        }
        return 0;
    }
    println!("{BANNER}");
    for (network, path, address) in rows {
        println!("  {:<8} {:<22} {}", network.as_str(), path, address);
    }
    0
}

fn cmd_selfcheck(a: SelfcheckArgs) -> i32 {
    let checks = spr_core::vectors::all_checks(!a.quick);
    let mut failed = 0;
    if let Some(path) = &a.json {
        let text = serde_json::to_string_pretty(&checks).unwrap_or_default();
        if path == "-" {
            println!("{text}");
        } else if let Err(e) = std::fs::write(path, text) {
            eprintln!("error writing {path}: {e}");
            return 1;
        }
    } else {
        println!("{BANNER}");
        for c in &checks {
            if c.ok {
                println!("  ✔ {}", c.name);
            } else {
                failed += 1;
                println!("  ✘ {}", c.name);
                println!("      expected {}", c.expected);
                println!("      actual   {}", c.actual);
            }
        }
        println!(
            "\n  {}/{} checks passed\n",
            checks.len() - failed,
            checks.len()
        );
    }
    if failed == 0 {
        0
    } else {
        1
    }
}

fn cmd_bench(a: BenchArgs) -> i32 {
    let threads = threads_or_default(a.threads);
    println!("{BANNER}");
    println!("  threads: {threads}");
    let words = spr_core::WordList::new(Language::English);
    let mut indices = vec![0u16; 12];
    // A valid checksum-valid phrase so the bench measures the full hot path.
    for i in 0..2048u16 {
        indices[11] = i;
        if spr_core::mnemonic::checksum_ok(&indices, &spr_core::mnemonic::Layout::new(12).unwrap()) {
            break;
        }
    }
    let mut phrase = String::new();
    for (i, idx) in indices.iter().enumerate() {
        if i > 0 {
            phrase.push(' ');
        }
        phrase.push_str(words.word(*idx));
    }
    let deadline = Instant::now() + Duration::from_secs(a.seconds);
    let counter = Arc::new(AtomicU64::new(0));
    let per_thread = Arc::clone(&counter);
    let start = Instant::now();
    let handles: Vec<_> = (0..threads)
        .map(|_| {
            let counter = Arc::clone(&per_thread);
            let phrase = phrase.clone();
            std::thread::spawn(move || {
                let mut local = 0u64;
                while Instant::now() < deadline {
                    for _ in 0..16 {
                        let seed = spr_core::mnemonic::seed_from_phrase(&phrase, "");
                        std::hint::black_box(&seed);
                        local += 1;
                    }
                    counter.fetch_add(16, Ordering::Relaxed);
                }
                local
            })
        })
        .collect();
    let mut total = 0u64;
    for h in handles {
        total += h.join().unwrap_or(0);
    }
    let elapsed = start.elapsed().as_secs_f64();
    let rate = total as f64 / elapsed;
    println!("  BIP39 seed derivation: {total} seeds in {elapsed:.2}s");
    println!("  {rate:.0} seeds/s ({:.0}/s per thread)", rate / threads as f64);
    println!("  single-thread throughput implies ~{:.1} ms per seed", 1000.0 / (rate / threads as f64).max(1.0));
    0
}

fn cmd_wordlist(a: WordlistArgs) -> i32 {
    let lang: Language = match a.lang.parse() {
        Ok(l) => l,
        Err(e) => {
            eprintln!("error: {e}");
            return 2;
        }
    };
    let wl = spr_core::WordList::new(lang);
    if let Some(word) = a.check {
        match wl.index_of(&word) {
            Some(i) => {
                println!("{:?} is word #{i} in the {} list", word, lang.code());
                0
            }
            None => {
                println!("{:?} is NOT in the {} list", word, lang.code());
                1
            }
        }
    } else if a.list {
        for (i, w) in wl.words().iter().enumerate() {
            println!("{:4}  {w}", i + 1);
        }
        0
    } else {
        let all = Language::ALL
            .iter()
            .map(|l| l.code())
            .collect::<Vec<_>>()
            .join(", ");
        println!("  language: {} ({} words)", lang.code(), wl.words().len());
        println!("  available: {all}");
        0
    }
}
