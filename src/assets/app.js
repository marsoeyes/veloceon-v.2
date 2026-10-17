"use strict";

const NETWORKS = ["evm", "btc", "doge", "xrp", "tron", "solana", "cardano"];
const PALETTE = ["#d9a13b", "#f0cd82", "#5ec8ae", "#c98b4b", "#8d6c2a", "#e2705f", "#7f8bd1"];
const state = { snapshot: null, history: [], summary: null, log: [], running: false, networks: [] };

const $ = (id) => document.getElementById(id);
const fmt = (n) => (n == null ? "—" : Number(n).toLocaleString("en-US"));
const fmtCompact = (n) => {
  if (n == null) return "—";
  const u = [[1e12, "T"], [1e9, "B"], [1e6, "M"], [1e3, "k"]];
  for (const [v, s] of u) if (n >= v) return (n / v).toFixed(n / v < 10 ? 1 : 0) + s;
  return String(n);
};
const dur = (s) => {
  if (s == null || !isFinite(s) || s <= 0) return "—";
  s = Math.floor(s);
  if (s < 60) return s + "s";
  if (s < 3600) return `${Math.floor(s / 60)}m ${String(s % 60).padStart(2, "0")}s`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ${String(Math.floor((s % 3600) / 60)).padStart(2, "0")}m`;
  return `${Math.floor(s / 86400)}d ${Math.floor((s % 86400) / 3600)}h`;
};

/* ---------- navigation ---------- */
document.querySelectorAll(".nav-item").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".nav-item").forEach((b) => b.classList.toggle("active", b === btn));
    document.querySelectorAll(".view").forEach((v) => v.classList.toggle("active", v.id === "view-" + btn.dataset.view));
    if (btn.dataset.view === "dashboard") drawAll();
  });
});

/* ---------- network chips ---------- */
const chipBox = $("network-chips");
NETWORKS.forEach((n) => {
  const el = document.createElement("div");
  el.className = "nchip";
  el.textContent = n;
  el.dataset.net = n;
  el.addEventListener("click", () => {
    el.classList.toggle("on");
    state.networks = [...chipBox.querySelectorAll(".nchip.on")].map((c) => c.dataset.net);
    renderChips();
  });
  chipBox.appendChild(el);
});
// EVM on by default
chipBox.querySelector('[data-net="evm"]').classList.add("on");
state.networks = ["evm"];

function renderChips() {
  const phrase = $("in-phrase").value.trim();
  const box = $("phrase-chips");
  box.innerHTML = "";
  if (!phrase) return;
  phrase.split(/\s+/).forEach((w, i) => {
    const chip = document.createElement("span");
    const unknown = ["?", "??", "*", "_", "-", "x", "X"].includes(w);
    chip.className = "chip" + (unknown ? " unknown" : "");
    chip.textContent = `${i + 1}. ${w}`;
    box.appendChild(chip);
  });
}
$("in-phrase").addEventListener("input", renderChips);
$("in-phrase").addEventListener("blur", analyzePhrase);

/* ---------- api helpers ---------- */
async function post(url, body) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  return res.json();
}

async function analyzePhrase() {
  const phrase = $("in-phrase").value.trim();
  if (!phrase) return;
  const out = await post("/api/analyze", { phrase, language: $("in-language").value });
  const box = $("analyze-out");
  if (!out.ok) {
    box.textContent = out.error || "invalid phrase";
    return;
  }
  box.textContent =
    `${out.words} words · ${out.unknown.length} unknown (${out.unknown.join(", ") || "none"})\n` +
    `combinations: ${fmt(out.combinations)}  →  ≈ ${fmt(out.seeds)} seeds after the ${out.checksum_bits}-bit checksum filter` +
    (out.invalid_words.length ? `\nunknown words: ${out.invalid_words.map((w) => `#${w.position} ${w.word}`).join(", ")}` : "");
}
$("btn-analyze").addEventListener("click", analyzePhrase);

/* ---------- start / control ---------- */
$("btn-start").addEventListener("click", async () => {
  const phrase = $("in-phrase").value.trim();
  const targets = $("in-targets").value.split("\n").map((s) => s.trim()).filter(Boolean);
  if (!phrase) return setNotice("Enter a phrase template first.");
  if (!targets.length) return setNotice("Add at least one target address (network:address).");
  const cap = parseInt($("set-cap").value || "0", 10);
  const body = {
    phrase,
    language: $("in-language").value,
    passphrase: $("in-passphrase").value,
    networks: state.networks.length ? state.networks : undefined,
    targets,
    match: $("in-match").value,
    breadth: parseInt($("in-breadth").value || "1", 10),
    paths: $("in-paths").value.split("\n").map((s) => s.trim()).filter(Boolean),
    threads: parseInt($("in-threads").value || $("set-threads").value || "0", 10),
    all: $("in-all").checked,
    max_candidates: cap > 0 ? cap : null,
  };
  const out = await post("/api/start", body);
  if (!out.ok) return setNotice(out.error);
  setNotice("Search started.");
  state.summary = out.summary;
  document.querySelector('.nav-item[data-view="dashboard"]').click();
});

function setNotice(text) {
  $("analyze-out").textContent = text;
}

$("btn-pause").addEventListener("click", async () => {
  const action = state.snapshot && state.snapshot.paused ? "resume" : "pause";
  await post("/api/control", { action });
});
$("btn-stop").addEventListener("click", () => post("/api/control", { action: "stop" }));

/* ---------- results ---------- */
function renderHits(snapshot) {
  const hits = (snapshot && snapshot.hits) || [];
  const rows = hits
    .map(
      (h) => `<tr>
        <td class="mono-cell">${escapeHtml(h.phrase)}</td>
        <td><span class="badge">${escapeHtml(h.network)}</span></td>
        <td class="mono-cell">${escapeHtml(h.path)}</td>
        <td class="mono-cell">${escapeHtml(h.address)}</td>
        <td><button class="copy" data-copy="${escapeAttr(h.phrase)}">copy</button></td>
      </tr>`
    )
    .join("");
  $("hits-body").innerHTML = rows || '<tr class="empty"><td colspan="5">No matches yet</td></tr>';
  $("results-body").innerHTML =
    hits
      .map(
        (h) => `<tr>
          <td class="mono-cell">${escapeHtml(h.phrase)}</td>
          <td><span class="badge">${escapeHtml(h.network)}</span></td>
          <td class="mono-cell">${escapeHtml(h.path)}</td>
          <td class="mono-cell">${escapeHtml(h.address)}</td>
          <td class="mono-cell">${escapeHtml(h.target || "")}</td>
          <td><button class="copy" data-copy="${escapeAttr(h.phrase)}">copy</button></td>
        </tr>`
      )
      .join("") || '<tr class="empty"><td colspan="6">No results yet</td></tr>';
  $("hits-count").textContent = `${hits.length} match${hits.length === 1 ? "" : "es"}`;
  document.querySelectorAll(".copy").forEach((b) =>
    b.addEventListener("click", () => {
      navigator.clipboard?.writeText(b.dataset.copy);
      b.textContent = "copied";
      setTimeout(() => (b.textContent = "copy"), 1200);
    })
  );
}

$("btn-copy-all").addEventListener("click", () => {
  const hits = (state.snapshot && state.snapshot.hits) || [];
  navigator.clipboard?.writeText(hits.map((h) => `${h.network} ${h.phrase}`).join("\n"));
});

$("btn-export").addEventListener("click", () => {
  const payload = { exported_at: new Date().toISOString(), summary: state.summary, snapshot: state.snapshot };
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "spr-recovery-results.json";
  a.click();
});

/* ---------- render loop ---------- */
function escapeHtml(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
const escapeAttr = escapeHtml;

function applyStatus(data) {
  state.snapshot = data.snapshot;
  state.history = data.history || [];
  state.summary = data.summary || state.summary;
  state.log = data.log || [];
  state.running = !!data.running;
  const s = data.snapshot;

  const pill = $("status-pill");
  pill.classList.toggle("running", state.running && !(s && s.paused));
  $("status-text").textContent = !s ? "Idle" : s.paused ? "Paused" : s.finished ? "Finished" : state.running ? "Running" : "Stopped";
  $("s-status").textContent = $("status-text").textContent;
  $("btn-pause").textContent = s && s.paused ? "Resume" : "Pause";

  $("k-checked").textContent = fmt(s ? s.checked : 0);
  $("k-seeds").textContent = fmt(s ? s.seeds : 0);
  $("k-found").textContent = fmt(s ? s.found : 0);
  $("k-rate").innerHTML = `${fmtCompact(s ? Math.round(s.rate) : 0)} <small>/s</small>`;
  $("k-elapsed").textContent = dur(s ? s.elapsed_secs : 0);
  $("k-eta").textContent = s && !s.finished ? dur(s.eta_secs) : "—";
  $("p-rate").textContent = fmtCompact(s ? Math.round(s.rate) : 0);
  $("p-elapsed").textContent = dur(s ? s.elapsed_secs : 0);
  $("p-eta").textContent = s && !s.finished ? dur(s.eta_secs) : "—";
  $("p-checked").textContent = fmt(s ? s.checked : 0);
  $("p-total").textContent = fmt(s ? s.total : 0);
  $("p-status").textContent = s ? (s.paused ? "paused" : s.finished ? "complete" : s.stopped ? "stopped" : "running") : "idle";
  $("bar-fill").style.width = `${s ? Math.min(100, s.pct) : 0}%`;
  $("b-threads").textContent = s ? s.threads : state.summary ? state.summary.threads : "—";
  $("b-rate").textContent = fmtCompact(s ? Math.round(s.rate) : 0);
  $("b-checked").textContent = fmtCompact(s ? s.checked : 0);
  $("b-seeds").textContent = fmtCompact(s ? s.seeds : 0);

  const sum = state.summary;
  $("s-threads").textContent = s ? s.threads : sum ? sum.threads : "—";
  $("s-language").textContent = sum ? sum.language : "—";
  $("s-combos").textContent = sum ? fmtCompact(sum.combinations) : "—";
  $("s-derivs").textContent = sum ? sum.derivations : "—";
  $("s-elapsed").textContent = dur(s ? s.elapsed_secs : 0);

  $("log").innerHTML = state.log
    .slice(-120)
    .reverse()
    .map((l) => `<div>${escapeHtml(l)}</div>`)
    .join("");

  renderHits(s);
  drawAll();
}

/* ---------- charts ---------- */
function fitCanvas(canvas) {
  const dpr = window.devicePixelRatio || 1;
  const rect = canvas.getBoundingClientRect();
  if (!rect.width) return null;
  canvas.width = rect.width * dpr;
  canvas.height = rect.height * dpr;
  const ctx = canvas.getContext("2d");
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  return { ctx, w: rect.width, h: rect.height };
}

function drawSparklines() {
  const hist = state.history;
  document.querySelectorAll(".spark").forEach((canvas) => {
    const fit = fitCanvas(canvas);
    if (!fit) return;
    const { ctx, w, h } = fit;
    ctx.clearRect(0, 0, w, h);
    if (hist.length < 2) return;
    const series = {
      checked: hist.map(([, c]) => c),
      seeds: hist.map(([, , s]) => s),
      found: hist.map(() => (state.snapshot ? state.snapshot.found : 0)),
      rate: hist.map(([t, c], i) => (i ? (c - hist[i - 1][1]) / Math.max(1e-6, t - hist[i - 1][0]) : 0)),
    }[canvas.dataset.series];
    if (!series) return;
    const max = Math.max(...series, 1);
    const color = canvas.dataset.series === "seeds" ? "#5ec8ae" : canvas.dataset.series === "found" ? "#e2707f" : "#d9a13b";
    ctx.beginPath();
    series.forEach((v, i) => {
      const x = (i / (series.length - 1)) * w;
      const y = h - (v / max) * (h - 4) - 2;
      i ? ctx.lineTo(x, y) : ctx.moveTo(x, y);
    });
    ctx.strokeStyle = color;
    ctx.lineWidth = 1.6;
    ctx.stroke();
    ctx.lineTo(w, h);
    ctx.lineTo(0, h);
    ctx.closePath();
    const grad = ctx.createLinearGradient(0, 0, 0, h);
    grad.addColorStop(0, color + "44");
    grad.addColorStop(1, color + "00");
    ctx.fillStyle = grad;
    ctx.fill();
  });
}

function drawChart() {
  const canvas = $("chart");
  const fit = fitCanvas(canvas);
  if (!fit) return;
  const { ctx, w, h } = fit;
  ctx.clearRect(0, 0, w, h);
  const pad = { l: 46, r: 12, t: 12, b: 22 };
  const hist = state.history;
  const total = state.snapshot ? state.snapshot.total : 0;
  ctx.strokeStyle = "#1f1d27";
  ctx.fillStyle = "#6d6862";
  ctx.font = "11px Inter, sans-serif";
  for (let i = 0; i <= 4; i++) {
    const y = pad.t + ((h - pad.t - pad.b) * i) / 4;
    ctx.beginPath();
    ctx.moveTo(pad.l, y);
    ctx.lineTo(w - pad.r, y);
    ctx.stroke();
    const val = total ? total * (1 - i / 4) : 0;
    ctx.fillText(fmtCompact(val), 4, y + 4);
  }
  if (hist.length < 2) {
    ctx.fillText("waiting for samples…", pad.l + 8, h / 2);
    return;
  }
  const maxX = hist[hist.length - 1][0] || 1;
  const maxY = Math.max(total, ...hist.map(([, c]) => c), 1);
  const plot = (idx, color, fill) => {
    ctx.beginPath();
    hist.forEach((row, i) => {
      const x = pad.l + (row[0] / maxX) * (w - pad.l - pad.r);
      const y = h - pad.b - (row[idx] / maxY) * (h - pad.t - pad.b);
      i ? ctx.lineTo(x, y) : ctx.moveTo(x, y);
    });
    ctx.strokeStyle = color;
    ctx.lineWidth = 2;
    ctx.stroke();
    if (fill) {
      ctx.lineTo(w - pad.r, h - pad.b);
      ctx.lineTo(pad.l, h - pad.b);
      ctx.closePath();
      const grad = ctx.createLinearGradient(0, pad.t, 0, h - pad.b);
      grad.addColorStop(0, color + "33");
      grad.addColorStop(1, color + "00");
      ctx.fillStyle = grad;
      ctx.fill();
    }
  };
  plot(1, "#d9a13b", true);
  plot(2, "#5ec8ae", false);
  ctx.fillStyle = "#d9a13b";
  ctx.fillText("checked", pad.l + 6, pad.t + 12);
  ctx.fillStyle = "#5ec8ae";
  ctx.fillText("seeds", pad.l + 66, pad.t + 12);
}

function drawDonut() {
  const canvas = $("donut");
  const fit = fitCanvas(canvas);
  if (!fit) return;
  const { ctx, w, h } = fit;
  ctx.clearRect(0, 0, w, h);
  const hits = (state.snapshot && state.snapshot.hits) || [];
  const counts = {};
  hits.forEach((x) => (counts[x.network] = (counts[x.network] || 0) + 1));
  const entries = Object.entries(counts);
  const cx = w / 2, cy = h / 2, r = Math.min(w, h) / 2 - 8, inner = r * 0.62;
  if (!entries.length) {
    ctx.beginPath();
    ctx.arc(cx, cy, r, 0, Math.PI * 2);
    ctx.strokeStyle = "#242230";
    ctx.lineWidth = r - inner;
    ctx.stroke();
    ctx.fillStyle = "#6d6862";
    ctx.font = "12px Inter, sans-serif";
    ctx.fillText("no matches", cx - 30, cy + 4);
    $("donut-legend").innerHTML = "";
    return;
  }
  const total = entries.reduce((a, [, v]) => a + v, 0);
  let angle = -Math.PI / 2;
  entries.forEach(([net, v], i) => {
    const sweep = (v / total) * Math.PI * 2;
    ctx.beginPath();
    ctx.arc(cx, cy, r - (r - inner) / 2, angle, angle + sweep);
    ctx.strokeStyle = PALETTE[i % PALETTE.length];
    ctx.lineWidth = r - inner;
    ctx.stroke();
    angle += sweep;
  });
  ctx.fillStyle = "#ece7dd";
  ctx.font = "600 18px Inter, sans-serif";
  ctx.fillText(String(total), cx - String(total).length * 5, cy + 2);
  $("donut-legend").innerHTML = entries
    .map(
      ([net, v], i) =>
        `<li><span class="swatch" style="background:${PALETTE[i % PALETTE.length]}"></span>${net} · ${v} (${((v / total) * 100).toFixed(0)}%)</li>`
    )
    .join("");
}

function drawAll() {
  drawSparklines();
  drawChart();
  drawDonut();
}
window.addEventListener("resize", drawAll);

/* ---------- derive ---------- */
$("btn-derive").addEventListener("click", async () => {
  const out = await post("/api/derive", {
    phrase: $("d-phrase").value.trim(),
    language: $("d-language").value,
    passphrase: $("d-passphrase").value,
    network: $("d-network").value,
    breadth: 1,
  });
  const body = $("derive-body");
  if (!out.ok) {
    body.innerHTML = `<tr class="empty"><td colspan="4">${escapeHtml(out.error)}</td></tr>`;
    return;
  }
  body.innerHTML = out.addresses
    .map(
      (a) => `<tr><td><span class="badge">${escapeHtml(a.network)}</span></td>
      <td class="mono-cell">${escapeHtml(a.path)}</td>
      <td class="mono-cell">${escapeHtml(a.address)}</td>
      <td><button class="copy" data-copy="${escapeAttr(a.address)}">copy</button></td></tr>`
    )
    .join("");
  document.querySelectorAll(".copy").forEach((b) =>
    b.addEventListener("click", () => {
      navigator.clipboard?.writeText(b.dataset.copy);
      b.textContent = "copied";
      setTimeout(() => (b.textContent = "copy"), 1200);
    })
  );
});

/* ---------- wordlist ---------- */
$("btn-wcheck").addEventListener("click", async () => {
  const out = await post("/api/wordlist", { language: $("w-language").value, word: $("w-word").value });
  $("w-out").textContent = out.ok
    ? `"${out.word}" is word #${out.index + 1} of the ${out.language} list`
    : `"${out.word}" is not in the ${out.language} list (${out.error || "not found"})`;
});

/* ---------- live connection ---------- */
function connect() {
  const es = new EventSource("/api/events");
  es.onmessage = (ev) => {
    try {
      applyStatus(JSON.parse(ev.data));
    } catch (e) {
      /* ignore malformed frame */
    }
  };
  es.onerror = () => {
    es.close();
    setTimeout(connect, 2000);
  };
}
fetch("/api/status")
  .then((r) => r.json())
  .then((data) => {
    $("version").textContent = "v" + (data.version || "");
    applyStatus(data);
  })
  .finally(connect);
renderChips();
setInterval(drawAll, 2000);
