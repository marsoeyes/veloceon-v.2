//! Web dashboard: same engine, driven from a browser (handy on Colab/Kaggle/vast.ai).

use std::convert::Infallible;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::sse::{Event, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use futures_util::stream::{self, Stream};
use serde::Deserialize;
use serde_json::json;

use spr_core::deriv::{default_derivations, spec_from_path};
use spr_core::{
    build_plan, derive_all, run, Language, MatchMode, Network, Progress, SearchConfig, Target,
};

const INDEX_HTML: &str = include_str!("assets/index.html");
const STYLE_CSS: &str = include_str!("assets/style.css");
const APP_JS: &str = include_str!("assets/app.js");

struct Job {
    progress: Arc<Progress>,
    started: Instant,
    summary: serde_json::Value,
    _handle: Option<std::thread::JoinHandle<()>>,
}

struct AppState {
    job: Mutex<Option<Job>>,
    history: Mutex<Vec<(f64, u64, u64)>>,
    log: Mutex<Vec<String>>,
    last_job: Mutex<Option<serde_json::Value>>,
}

impl AppState {
    fn log(&self, line: impl Into<String>) {
        let mut log = self.log.lock().unwrap();
        log.push(line.into());
        if log.len() > 400 {
            let drop_n = log.len() - 400;
            log.drain(0..drop_n);
        }
    }
}

#[derive(Deserialize)]
struct StartRequest {
    phrase: String,
    #[serde(default = "default_language")]
    language: String,
    #[serde(default)]
    passphrase: String,
    #[serde(default)]
    networks: Vec<String>,
    #[serde(default)]
    targets: Vec<String>,
    #[serde(default = "default_match")]
    r#match: String,
    #[serde(default = "default_breadth")]
    breadth: u32,
    #[serde(default)]
    paths: Vec<String>,
    #[serde(default)]
    threads: usize,
    #[serde(default)]
    max_candidates: Option<u64>,
    #[serde(default)]
    all: bool,
}

fn default_language() -> String {
    "english".into()
}
fn default_match() -> String {
    "exact".into()
}
fn default_breadth() -> u32 {
    1
}

#[derive(Deserialize)]
struct ControlRequest {
    action: String,
}

#[derive(Deserialize)]
struct DeriveRequest {
    phrase: String,
    #[serde(default = "default_language")]
    language: String,
    #[serde(default)]
    passphrase: String,
    #[serde(default = "default_all")]
    network: String,
    #[serde(default = "default_breadth")]
    breadth: u32,
}

fn default_all() -> String {
    "all".into()
}

#[derive(Deserialize)]
struct AnalyzeRequest {
    phrase: String,
    #[serde(default = "default_language")]
    language: String,
}

fn language_of(name: &str) -> Result<Language, String> {
    name.parse::<Language>().map_err(|e| e.to_string())
}

async fn index() -> Response {
    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        INDEX_HTML,
    )
        .into_response()
}

async fn style() -> Response {
    ([(header::CONTENT_TYPE, "text/css")], STYLE_CSS).into_response()
}

async fn app_js() -> Response {
    (
        [(header::CONTENT_TYPE, "application/javascript")],
        APP_JS,
    )
        .into_response()
}

async fn status(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let job = state.job.lock().unwrap();
    let last = state.last_job.lock().unwrap().clone();
    let running = job.as_ref().map(|j| !j.progress.finished.load(Ordering::SeqCst));
    let snapshot = job.as_ref().map(|j| j.progress.snapshot());
    let summary = job.as_ref().map(|j| j.summary.clone());
    Json(json!({
        "version": spr_core::VERSION,
        "running": running.unwrap_or(false),
        "snapshot": snapshot,
        "summary": summary,
        "last_job": last,
        "history": *state.history.lock().unwrap(),
        "log": *state.log.lock().unwrap(),
    }))
}

async fn events(
    State(state): State<Arc<AppState>>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let stream = stream::unfold(state, |state| async move {
        tokio::time::sleep(Duration::from_millis(500)).await;
        let (payload, finished) = {
            let job = state.job.lock().unwrap();
            match job.as_ref() {
                Some(j) => {
                    let snap = j.progress.snapshot();
                    if !snap.finished {
                        let elapsed = j.started.elapsed().as_secs_f64();
                        let mut history = state.history.lock().unwrap();
                        let last = history.last().map(|h| h.0).unwrap_or(0.0);
                        if elapsed - last >= 0.5 {
                            history.push((elapsed, snap.checked, snap.seeds));
                            if history.len() > 720 {
                                let drop_n = history.len() - 720;
                                history.drain(0..drop_n);
                            }
                        }
                    }
                    let running = !snap.finished && !snap.stopped;
                    let payload = json!({
                        "snapshot": snap,
                        "running": running,
                        "summary": j.summary,
                        "history": *state.history.lock().unwrap(),
                        "log": *state.log.lock().unwrap(),
                    });
                    (payload, snap.finished || snap.stopped)
                }
                None => (
                    json!({
                        "snapshot": serde_json::Value::Null,
                        "running": false,
                        "history": *state.history.lock().unwrap(),
                        "log": *state.log.lock().unwrap(),
                    }),
                    false,
                ),
            }
        };
        let event = Event::default().data(payload.to_string());
        if finished {
            // keep streaming so the UI stays in sync after the job ends
        }
        Some((Ok(event), state))
    });
    Sse::new(stream).keep_alive(axum::response::sse::KeepAlive::default())
}

async fn start(
    State(state): State<Arc<AppState>>,
    Json(req): Json<StartRequest>,
) -> Response {
    if state
        .job
        .lock()
        .unwrap()
        .as_ref()
        .map(|j| !j.progress.finished.load(Ordering::SeqCst))
        .unwrap_or(false)
    {
        return (
            StatusCode::CONFLICT,
            Json(json!({"ok": false, "error": "a search is already running"})),
        )
            .into_response();
    }
    let language = match language_of(&req.language) {
        Ok(l) => l,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"ok": false, "error": e})),
            )
                .into_response()
        }
    };
    let mode = MatchMode::parse(&req.r#match).unwrap_or(MatchMode::Exact);
    let mut targets: Vec<Target> = Vec::new();
    for spec in &req.targets {
        let spec = spec.trim();
        if spec.is_empty() {
            continue;
        }
        match Target::parse(spec, None) {
            Ok(t) => targets.push(t.with_mode(mode)),
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"ok": false, "error": e.to_string()})),
                )
                    .into_response()
            }
        }
    }
    if targets.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "error": "add at least one target address, e.g. evm:0x..."})),
        )
            .into_response();
    }
    let template = spr_core::mnemonic::split_template(&req.phrase);
    let mut networks: Vec<Network> = Vec::new();
    for n in &req.networks {
        if let Ok(net) = n.parse::<Network>() {
            if !networks.contains(&net) {
                networks.push(net);
            }
        }
    }
    if networks.is_empty() {
        for t in &targets {
            if !networks.contains(&t.network) {
                networks.push(t.network);
            }
        }
    }
    let mut specs = Vec::new();
    if req.paths.is_empty() {
        for n in &networks {
            specs.extend(default_derivations(*n, req.breadth.max(1)));
        }
    } else {
        for p in &req.paths {
            for n in &networks {
                if let Ok(s) = spec_from_path(*n, p) {
                    specs.push(s);
                }
            }
        }
    }

    let cfg = SearchConfig {
        language,
        template,
        position_candidates: Vec::new(),
        passphrase: req.passphrase.clone(),
        derivations: specs,
        targets: targets.clone(),
    };
    let plan = match build_plan(&cfg) {
        Ok(p) => p,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"ok": false, "error": e.to_string()})),
            )
                .into_response()
        }
    };
    if let Some(cap) = req.max_candidates {
        if plan.total > cap {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"ok": false, "error": format!("candidate space {} exceeds the cap {}", plan.total, cap)})),
            )
                .into_response();
        }
    }

    let threads = if req.threads == 0 {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
    } else {
        req.threads
    };
    // Only networks that actually have a target get derived: push that list to the UI
    // so the dashboard reports what is really being computed.
    let mut active_networks: Vec<&str> = targets.iter().map(|t| t.network.as_str()).collect();
    active_networks.sort_unstable();
    active_networks.dedup();
    let summary = json!({
        "phrase": plan.phrase_template.iter().map(|w| w.clone().unwrap_or_else(|| "?".into())).collect::<Vec<_>>().join(" "),
        "language": language.code(),
        "unknown": plan.unknown.iter().map(|i| i + 1).collect::<Vec<_>>(),
        "combinations": plan.total,
        "seeds": plan.total / (1u64 << plan.layout.cs_bits),
        "checksum_bits": plan.layout.cs_bits,
        "derivations": plan.derivations.len(),
        "threads": threads,
        "networks": active_networks,
        "requested_networks": networks.iter().map(|n| n.as_str()).collect::<Vec<_>>(),
        "targets": targets.iter().map(|t| json!({"network": t.network.as_str(), "address": t.value, "mode": t.mode.as_str()})).collect::<Vec<_>>(),
    });

    let max_hits = if req.all { usize::MAX } else { 1 };
    let progress = Arc::new(Progress::new(plan.total, threads, !req.all, max_hits));
    state.log(format!(
        "search started: {} combinations, {} derivations, {} threads",
        plan.total,
        plan.derivations.len(),
        threads
    ));
    {
        let mut history = state.history.lock().unwrap();
        history.clear();
    }
    *state.last_job.lock().unwrap() = Some(summary.clone());

    let handle_progress = progress.clone();
    let handle = std::thread::spawn(move || {
        let _ = run(Arc::new(plan), handle_progress);
    });

    let mut job = state.job.lock().unwrap();
    *job = Some(Job {
        progress,
        started: Instant::now(),
        summary: summary.clone(),
        _handle: Some(handle),
    });

    Json(json!({"ok": true, "summary": summary})).into_response()
}

async fn control(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ControlRequest>,
) -> Json<serde_json::Value> {
    let job = state.job.lock().unwrap();
    let Some(job) = job.as_ref() else {
        return Json(json!({"ok": false, "error": "no job"}));
    };
    match req.action.as_str() {
        "pause" => {
            job.progress.pause();
            state.log("paused");
        }
        "resume" => {
            job.progress.resume();
            state.log("resumed");
        }
        "stop" => {
            job.progress.stop();
            state.log("stop requested");
        }
        other => {
            return Json(json!({"ok": false, "error": format!("unknown action {other}")}));
        }
    }
    Json(json!({"ok": true}))
}

async fn analyze(Json(req): Json<AnalyzeRequest>) -> Json<serde_json::Value> {
    let language = match language_of(&req.language) {
        Ok(l) => l,
        Err(e) => return Json(json!({"ok": false, "error": e})),
    };
    let template = spr_core::mnemonic::split_template(&req.phrase);
    let unknown: Vec<usize> = template
        .iter()
        .enumerate()
        .filter(|(_, w)| w.is_none())
        .map(|(i, _)| i + 1)
        .collect();
    let layout = spr_core::mnemonic::Layout::new(template.len());
    let per_unknown: u128 = 2048;
    let combinations: u128 = per_unknown.pow(unknown.len() as u32);
    let checksum_bits = layout.map(|l| l.cs_bits).unwrap_or(0);
    let seeds = if checksum_bits > 0 {
        combinations >> checksum_bits
    } else {
        combinations
    };
    let words_valid = {
        let wl = spr_core::WordList::new(language);
        template
            .iter()
            .enumerate()
            .filter_map(|(i, w)| w.as_ref().map(|w| (i + 1, w.clone(), wl.contains(w))))
            .filter(|(_, _, ok)| !ok)
            .map(|(i, w, _)| json!({"position": i, "word": w}))
            .collect::<Vec<_>>()
    };
    Json(json!({
        "ok": layout.is_some(),
        "words": template.len(),
        "valid_length": layout.is_some(),
        "unknown": unknown,
        "combinations": combinations,
        "seeds": seeds,
        "checksum_bits": checksum_bits,
        "invalid_words": words_valid,
        "error": if layout.is_none() { Some("phrase length must be 12, 15, 18, 21 or 24 words") } else { None },
    }))
}

#[derive(Deserialize)]
struct WordlistRequest {
    #[serde(default = "default_language")]
    language: String,
    #[serde(default)]
    word: String,
}

async fn wordlist(Json(req): Json<WordlistRequest>) -> Json<serde_json::Value> {
    let language = match language_of(&req.language) {
        Ok(l) => l,
        Err(e) => return Json(json!({"ok": false, "error": e, "language": req.language, "word": req.word})),
    };
    let wl = spr_core::WordList::new(language);
    match wl.index_of(&req.word) {
        Some(i) => Json(json!({"ok": true, "index": i, "language": language.code(), "word": req.word})),
        None => Json(json!({
            "ok": false,
            "error": format!("not one of the {} BIP39 words", wl.words().len()),
            "language": language.code(),
            "word": req.word
        })),
    }
}

async fn derive(Json(req): Json<DeriveRequest>) -> Json<serde_json::Value> {
    let language = match language_of(&req.language) {
        Ok(l) => l,
        Err(e) => return Json(json!({"ok": false, "error": e})),
    };
    let nets: Vec<Network> = if req.network.eq_ignore_ascii_case("all") {
        Network::ALL.to_vec()
    } else {
        req.network
            .split(',')
            .filter_map(|n| n.trim().parse::<Network>().ok())
            .collect()
    };
    let mut specs = Vec::new();
    for n in &nets {
        specs.extend(default_derivations(*n, req.breadth.max(1)));
    }
    match derive_all(&req.phrase, language, &req.passphrase, &specs) {
        Ok(rows) => Json(json!({
            "ok": true,
            "addresses": rows.iter().map(|(n, p, a)| json!({
                "network": n.as_str(), "path": p, "address": a
            })).collect::<Vec<_>>(),
        })),
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}

pub fn serve(host: &str, port: u16) -> i32 {
    let state = Arc::new(AppState {
        job: Mutex::new(None),
        history: Mutex::new(Vec::new()),
        log: Mutex::new(Vec::new()),
        last_job: Mutex::new(None),
    });
    let app = Router::new()
        .route("/", get(index))
        .route("/assets/style.css", get(style))
        .route("/assets/app.js", get(app_js))
        .route("/api/status", get(status))
        .route("/api/events", get(events))
        .route("/api/start", post(start))
        .route("/api/control", post(control))
        .route("/api/analyze", post(analyze))
        .route("/api/wordlist", post(wordlist))
        .route("/api/derive", post(derive))
        .fallback(get(index))
        .with_state(state);

    let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("error: could not start runtime: {e}");
            return 1;
        }
    };
    let addr = format!("{host}:{port}");
    println!(
        "\n  dashboard: http://{addr}  (bind {host})\n  \
         Colab:     from google.colab import output; output.serve_kernel_port_as_window({port})\n"
    );
    rt.block_on(async move {
        match tokio::net::TcpListener::bind(&addr).await {
            Ok(listener) => {
                if let Err(e) = axum::serve(listener, app).await {
                    eprintln!("error: {e}");
                    std::process::exit(1);
                }
            }
            Err(e) => {
                eprintln!("error: cannot bind {addr}: {e}");
                std::process::exit(1);
            }
        }
    });
    0
}
