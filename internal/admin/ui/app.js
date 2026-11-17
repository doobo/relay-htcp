// relay-htcp admin panel — vanilla JS single-page app.
"use strict";

const $ = (sel) => document.querySelector(sel);

const state = {
  token: sessionStorage.getItem("rhtcp_token") || "",
  role: "",
  username: "",
  statusTimer: null,
  statusLoaded: false,
  configMode: "form",
  configSection: "",
  form: null,
  tokens: [],
  tokenRoutes: [],
  tokenEdit: -1,
  tokenLoaded: false,
  restarting: false,
};

/* ---------- API ---------- */

async function api(method, path, body, options) {
  const opts = Object.assign({ method, headers: {} }, options || {});
  opts.headers = Object.assign({}, opts.headers || {});
  if (state.token) opts.headers["Authorization"] = "Bearer " + state.token;
  if (body !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  const resp = await fetch(path, opts);
  if (resp.status === 401 && !path.endsWith("auth/login")) {
    showLogin();
    throw new Error("unauthorized");
  }
  let data = null;
  if (resp.status !== 204) {
    const text = await resp.text();
    try { data = text ? JSON.parse(text) : null; } catch { data = { error: text }; }
  }
  if (!resp.ok) {
    const msg = (data && data.error) || resp.statusText;
    const err = new Error(msg);
    err.status = resp.status;
    throw err;
  }
  return data;
}

/* ---------- theme ---------- */

const THEME_KEY = "relay-htcp.theme";
const THEMES = ["auto", "dark", "light", "black"];

function storedTheme() {
  try {
    const value = localStorage.getItem(THEME_KEY);
    return THEMES.includes(value) ? value : "auto";
  } catch {
    return "auto";
  }
}

function systemTheme() {
  return window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
}

function resolveTheme(choice) {
  return choice === "auto" ? systemTheme() : choice;
}

function syncThemeSelects(choice) {
  document.querySelectorAll("[data-theme-select]").forEach((el) => {
    el.value = choice;
  });
}

function applyTheme(choice) {
  choice = THEMES.includes(choice) ? choice : "auto";
  const theme = resolveTheme(choice);
  const root = document.documentElement;
  root.dataset.theme = theme;
  root.dataset.themeChoice = choice;
  root.style.colorScheme = theme === "light" ? "light" : "dark";
  const meta = document.querySelector('meta[name="theme-color"]');
  if (meta) {
    const bg = getComputedStyle(root).getPropertyValue("--bg").trim();
    if (bg) meta.setAttribute("content", bg);
  }
  syncThemeSelects(choice);
  try { localStorage.setItem(THEME_KEY, choice); } catch { /* ignore */ }
}

function initTheme() {
  let choice = storedTheme();
  document.querySelectorAll("[data-theme-select]").forEach((el) => {
    el.value = choice;
    el.addEventListener("change", () => {
      choice = el.value;
      applyTheme(choice);
    });
  });
  window.matchMedia("(prefers-color-scheme: light)").addEventListener("change", () => {
    if (choice === "auto") applyTheme("auto");
  });
  applyTheme(choice);
}

/* ---------- formatting ---------- */

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

function fmtBytes(n) {
  if (n == null) return "-";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return n.toFixed(n >= 100 || i === 0 ? 0 : 1) + " " + units[i];
}

function fmtUptime(sec) {
  if (sec == null) return "-";
  const d = Math.floor(sec / 86400);
  const h = Math.floor((sec % 86400) / 3600);
  const m = Math.floor((sec % 3600) / 60);
  if (d > 0) return d + "d " + h + "h";
  if (h > 0) return h + "h " + m + "m";
  return m + "m " + Math.floor(sec % 60) + "s";
}

function fmtMs(ms) {
  if (!ms) return "-";
  return new Date(ms).toLocaleString();
}

function strategyLabel(s) {
  if (s === "failover") return "第一个可用（故障转移）";
  if (s === "round_robin") return "轮询";
  return s || "轮询";
}

function card(k, v, cls) {
  return '<div class="card"><div class="k">' + esc(k) + '</div>' +
    '<div class="v ' + (cls || "") + '">' + esc(v) + "</div></div>";
}

function table(headers, rows) {
  if (!rows.length) return '<p class="muted">暂无数据</p>';
  const th = headers.map((h) => "<th>" + esc(h) + "</th>").join("");
  const trs = rows.map((r) => "<tr>" + r.map((c) => "<td>" + c + "</td>").join("") + "</tr>").join("");
  return "<table><thead><tr>" + th + "</tr></thead><tbody>" + trs + "</tbody></table>";
}

/* ---------- views ---------- */

function showLogin() {
  stopPolling();
  $("#app-view").classList.add("hidden");
  $("#login-view").classList.remove("hidden");
  $("#login-error").textContent = "";
  state.token = "";
  sessionStorage.removeItem("rhtcp_token");
}

async function showApp() {
  $("#login-view").classList.add("hidden");
  $("#app-view").classList.remove("hidden");
  try {
    const me = await api("GET", "api/auth/me");
    state.role = me.role;
    state.username = me.username;
    $("#whoami").textContent = me.username;
    // The role badge (server/client) is set by the first status poll.
    // Viewer role cannot manage users.
    $("#users-tab").style.display = me.role === "admin" ? "" : "none";
    $("#token-add").style.display = me.role === "admin" ? "" : "none";
    $("#ip-tab").style.display = me.role === "admin" ? "" : "none";
    startPolling();
  } catch (e) { /* showLogin already fired on 401 */ }
}

/* ---------- login (encrypted payload) ---------- */

function toBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function fromBase64(value) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

// Preferred: AES-GCM payload, AES key wrapped with the server's RSA-OAEP key.
async function encryptWithWebCrypto(challenge, username, password) {
  const publicKey = await crypto.subtle.importKey(
    "jwk", challenge.publicKey,
    { name: "RSA-OAEP", hash: "SHA-256" }, false, ["encrypt"],
  );
  const aesKey = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 }, true, ["encrypt"],
  );
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const payload = new TextEncoder().encode(
    JSON.stringify({ username, password, nonce: challenge.nonce }),
  );
  const data = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, payload);
  const rawKey = await crypto.subtle.exportKey("raw", aesKey);
  const key = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, publicKey, rawKey);
  return { key: toBase64(key), iv: toBase64(iv), data: toBase64(data) };
}

let naclPromise = null;

// Fallback for insecure contexts (plain HTTP on a LAN address): TweetNaCl's
// anonymous box, loaded on demand so the 32 KB bundle only costs a login.
function loadNacl() {
  if (globalThis.nacl) return Promise.resolve(globalThis.nacl);
  if (!naclPromise) {
    naclPromise = new Promise((resolve, reject) => {
      const s = document.createElement("script");
      s.src = "vendor/tweetnacl.js";
      s.onload = () => resolve(globalThis.nacl);
      s.onerror = () => reject(new Error("无法加载登录加密组件"));
      document.head.appendChild(s);
    });
  }
  return naclPromise;
}

async function encryptWithTweetNacl(challenge, username, password) {
  if (!globalThis.crypto?.getRandomValues || !challenge.box?.publicKey) {
    throw new Error("当前浏览器不支持加密登录，请使用新版浏览器");
  }
  const nacl = await loadNacl();
  const keyPair = nacl.box.keyPair();
  const nonce = nacl.randomBytes(nacl.box.nonceLength);
  const payload = new TextEncoder().encode(
    JSON.stringify({ username, password, nonce: challenge.nonce }),
  );
  const data = nacl.box(payload, nonce, fromBase64(challenge.box.publicKey), keyPair.secretKey);
  return {
    publicKey: toBase64(keyPair.publicKey),
    nonce: toBase64(nonce),
    data: toBase64(data),
  };
}

async function buildLoginBody(username, password) {
  const challenge = await api("POST", "api/auth/challenge", undefined, { cache: "no-store" });
  if (globalThis.crypto?.subtle && challenge.publicKey) {
    return { encrypted: await encryptWithWebCrypto(challenge, username, password) };
  }
  return { box: await encryptWithTweetNacl(challenge, username, password) };
}

async function postLogin(username, password) {
  return api("POST", "api/auth/login", await buildLoginBody(username, password));
}

async function doLogin(e) {
  e.preventDefault();
  const btn = $("#login-btn");
  btn.disabled = true;
  $("#login-error").textContent = "";
  const username = $("#login-user").value.trim();
  const password = $("#login-pass").value;
  try {
    let data;
    try {
      data = await postLogin(username, password);
    } catch (err) {
      // A stale challenge (cached page / server restart) fails with 400.
      // Retry once with a fresh nonce; auth failures are 401 and skip this.
      if (err.status !== 400) throw err;
      data = await postLogin(username, password);
    }
    state.token = data.token;
    sessionStorage.setItem("rhtcp_token", data.token);
    $("#login-pass").value = "";
    $("#login-error").textContent = "";
    await showApp();
  } catch (err) {
    if (err.message !== "unauthorized") $("#login-error").textContent = "登录失败:" + err.message;
  } finally {
    btn.disabled = false;
  }
}

async function doLogout() {
  try { await api("POST", "api/auth/logout"); } catch { /* ignore */ }
  showLogin();
}

/* ---------- restart client ---------- */

async function restartClient() {
  if (state.restarting) return;
  if (!(await uiConfirm("重启客户端", "当前连接会短暂中断，重启后页面会自动重新加载。", { okText: "重启" }))) return;
  state.restarting = true;
  const btn = $("#restart-btn");
  btn.disabled = true;
  btn.textContent = "重启中…";
  try {
    await api("POST", "api/restart");
  } catch (err) {
    state.restarting = false;
    btn.disabled = false;
    btn.textContent = "重启";
    if (err.message !== "unauthorized") await uiAlert("重启请求失败", err.message);
    return;
  }
  // The panel goes away while the client reinitializes. Poll until it is
  // serving again (the DB sessions survive the restart), then reload.
  for (let i = 0; i < 60; i++) {
    await new Promise((r) => setTimeout(r, 500));
    try {
      const resp = await fetch("api/status", {
        headers: state.token ? { Authorization: "Bearer " + state.token } : {},
        cache: "no-store",
      });
      if (resp.ok) {
        location.reload();
        return;
      }
      if (resp.status === 401) {
        showLogin();
        return;
      }
    } catch { /* still restarting */ }
  }
  state.restarting = false;
  btn.disabled = false;
  btn.textContent = "重启";
  await uiAlert("重启超时", "请检查客户端日志");
}

/* ---------- tabs ---------- */

function switchTab(name) {
  document.querySelectorAll(".tab").forEach((b) =>
    b.classList.toggle("active", b.dataset.tab === name));
  document.querySelectorAll("main > section").forEach((s) =>
    s.classList.toggle("hidden", s.id !== "tab-" + name));
  if (name === "config") loadConfig();
  if (name === "tokens") loadTokens();
  if (name === "ip-access") loadIPAccess();
  if (name === "users" && !state.usersLoaded) loadUsers();
}

/* ---------- status ---------- */

function startPolling() {
  stopPolling();
  pollStatus();
  state.statusTimer = setInterval(pollStatus, 3000);
}

function stopPolling() {
  if (state.statusTimer) clearInterval(state.statusTimer);
  state.statusTimer = null;
}

async function pollStatus() {
  let st;
  try {
    st = await api("GET", "api/status");
  } catch { return; }

  const badge = $("#role-badge");
  badge.textContent = st.role;
  badge.className = "badge" + (st.role === "client" ? " client" : "");
  $("#tokens-tab").style.display = st.role === "server" ? "" : "none";
  // Only the client supports an in-place restart, and only admins may do it.
  const canRestart = st.role === "client" && state.role === "admin" && !state.restarting;
  $("#restart-btn").classList.toggle("hidden", !canRestart);

  const cards = [card("版本", st.version), card("运行时长", fmtUptime(st.uptime_sec))];
  let live = "";

  if (st.role === "server" && st.server) {
    const s = st.server;
    cards.push(card("监听地址", s.listen_addr));
    cards.push(card("TLS", s.tls ? "启用" : "关闭", s.tls ? "ok" : ""));
    cards.push(card("活跃隧道", String(s.active_tunnels)));
    cards.push(card("入站流量", fmtBytes(s.bytes_in)));
    cards.push(card("出站流量", fmtBytes(s.bytes_out)));
    cards.push(card("decoy 命中", String(s.decoy_views), "warn"));
    live = table(
      ["路由", "令牌", "远端", "入站", "出站", "开始时间"],
      (s.active_streams || []).map((x) => [
        esc(x.route), esc(x.token), esc(x.remote),
        fmtBytes(x.bytes_in), fmtBytes(x.bytes_out), fmtMs(x.started_at),
      ])
    );
  } else if (st.role === "client" && st.client) {
    const c = st.client;
    const servers = c.servers || [];
    cards.push(card("服务端", servers.length
      ? servers.map((s) => s.name).join("、")
      : c.server_addr));
    if (c.proxy) cards.push(card("出口代理", c.proxy, "ok"));
    const online = (c.slots || []).filter((s) => s.state === "connected").length;
    cards.push(card("连接池", online + " / " + (c.slots || []).length + " 就绪",
      online > 0 ? "ok" : "warn"));
    live =
      "<h3 class='muted' style='margin:14px 0 6px'>服务端</h3>" +
      table(["名称", "地址", "传输", "连接"],
        servers.map((s) => [
          esc(s.name), esc(s.url), esc(s.transport || "http"),
          '<span class="pill ' + (s.online > 0 ? "ok" : "warn") + '">' +
            s.online + " / " + s.total + "</span>",
        ])) +
      "<h3 class='muted' style='margin:14px 0 6px'>连接池</h3>" +
      table(["服务端", "槽位", "状态", "建立时间", "最后 PONG"],
        (c.slots || []).map((s) => [
          esc(s.server || "-"), String(s.index),
          '<span class="pill ' + (s.state === "connected" ? "ok" : "warn") + '">' +
            esc(s.state) + "</span>",
          fmtMs(s.connected_at), fmtMs(s.last_pong_at),
        ])) +
      "<h3 class='muted' style='margin:14px 0 6px'>本地监听</h3>" +
      table(["本地地址", "路由", "服务端", "策略", "活跃连接"],
        (c.listeners || []).map((l) => [
          esc(l.local), esc(l.target),
          (l.servers && l.servers.length) ? esc(l.servers.join(", ")) : "全部",
          esc(strategyLabel(l.strategy)), String(l.active_conns),
        ])) +
      "<h3 class='muted' style='margin:14px 0 6px'>活跃连接</h3>" +
      table(["本地", "来源", "路由", "服务端", "入站", "出站", "开始时间"],
        (c.active_conns || []).map((x) => [
          esc(x.local), esc(x.from), esc(x.route), esc(x.server || "-"),
          fmtBytes(x.bytes_in), fmtBytes(x.bytes_out), fmtMs(x.started_at),
        ]));
  }

  $("#summary").innerHTML = cards.join("");
  $("#live").innerHTML = live;
  state.statusLoaded = true;
}

/* ---------- config ---------- */

function setConfigMode(mode) {
  state.configMode = mode;
  $("#cfg-mode-form").classList.toggle("active", mode === "form");
  $("#cfg-mode-yaml").classList.toggle("active", mode === "yaml");
  $("#cfg-result").textContent = "";
  loadConfig();
}

async function loadConfig() {
  if (state.configMode === "yaml") return loadConfigYAML();
  return loadConfigForm();
}

async function loadConfigForm() {
  try {
    const data = await api("GET", "api/config/form");
    state.form = data;
    $("#cfg-source").textContent = data.source === "db" ? "数据库" : "配置文件";
    renderConfigForm(data);
    $("#cfg-yaml").classList.add("hidden");
    $("#cfg-form").classList.remove("hidden");
  } catch (err) {
    $("#cfg-result").textContent = "加载失败:" + err.message;
  }
}

async function loadConfigYAML() {
  try {
    const data = await api("GET", "api/config");
    $("#cfg-yaml").value = data.yaml;
    $("#cfg-source").textContent = data.source === "db" ? "数据库" : "配置文件";
    $("#cfg-form").classList.add("hidden");
    $("#cfg-yaml").classList.remove("hidden");
  } catch (err) {
    $("#cfg-result").textContent = "加载失败:" + err.message;
  }
}

/* ---------- structured config form (schema-driven) ---------- */

function findFormField(path) {
  if (!state.form) return null;
  for (const sec of state.form.sections || []) {
    for (const f of sec.fields || []) {
      if (f.path === path) return f;
    }
  }
  return null;
}

function renderConfigForm(form) {
  const sections = form.sections || [];
  const keyed = sections.filter((sec) => !!sec.key);
  const active = keyed.length ? activeSectionKey(keyed) : "";
  renderConfigSubtabs(keyed);
  const values = form.values || {};
  $("#cfg-form").innerHTML = sections.map((sec) => {
    const hidden = keyed.length && sec.key && sec.key !== active;
    return '<section class="form-section' + (hidden ? " hidden" : "") + '"' +
      (sec.key ? ' data-section="' + esc(sec.key) + '"' : "") + ">" +
      "<h2>" + esc(sec.title) + "</h2>" +
      '<div class="form-grid">' +
        sec.fields.map((f) => fieldHTML(f, values[f.path])).join("") +
      "</div>" +
    "</section>";
  }).join("");
}

// Config sections with a key are shown one at a time via sub-tabs. All
// sections stay in the DOM so switching tabs never loses unsaved edits.
function activeSectionKey(keyed) {
  if (state.configSection && keyed.some((s) => s.key === state.configSection)) {
    return state.configSection;
  }
  state.configSection = keyed[0] ? keyed[0].key : "";
  return state.configSection;
}

function renderConfigSubtabs(keyed) {
  const el = $("#cfg-subtabs");
  if (!keyed.length) {
    el.classList.add("hidden");
    el.innerHTML = "";
    return;
  }
  el.classList.remove("hidden");
  el.innerHTML = keyed.map((s) =>
    '<button type="button" class="small" data-cfg-section="' +
      esc(s.key) + '">' + esc(s.title) + "</button>").join("");
  syncConfigSubtabs();
}

function syncConfigSubtabs() {
  document.querySelectorAll("#cfg-subtabs [data-cfg-section]").forEach((b) =>
    b.classList.toggle("active", b.dataset.cfgSection === state.configSection));
  document.querySelectorAll("#cfg-form .form-section[data-section]").forEach((s) =>
    s.classList.toggle("hidden", s.dataset.section !== state.configSection));
}

function selectConfigSection(key) {
  state.configSection = key;
  syncConfigSubtabs();
}

function fieldHTML(f, value) {
  if (f.type === "table") return tableFieldHTML(f, value || []);
  const cls = f.type === "bool" ? "form-row form-check" : "form-row";
  return '<label class="' + cls + '">' +
    '<span class="form-label">' + esc(f.label) + "</span>" +
    inputHTML(f, value, "") +
    (f.help ? '<small class="muted">' + esc(f.help) + "</small>" : "") +
  "</label>";
}

// colPath is set for table cells; scalar fields use their dot path.
function inputHTML(f, value, colPath) {
  const attr = colPath
    ? 'data-col="' + esc(colPath) + '"'
    : 'data-path="' + esc(f.path) + '"';
  const ph = f.placeholder ? ' placeholder="' + esc(f.placeholder) + '"' : "";
  switch (f.type) {
  case "secret":
    return '<input type="password" ' + attr + ' value="" autocomplete="new-password"' +
      (f.placeholder ? ph : ' placeholder="留空保持不变"') + ">";
  case "number":
    return '<input type="number" ' + attr + ' value="' + esc(value ?? "") + '"' + ph + ">";
  case "bool":
    return '<input type="checkbox" ' + attr + (value ? " checked" : "") + ">";
  case "select":
    return '<select ' + attr + ">" +
      (f.options || []).map((o) =>
        '<option value="' + esc(o) + '"' + (String(value) === o ? " selected" : "") +
        ">" + esc(o) + "</option>").join("") +
      "</select>";
  case "duration":
    return '<input type="text" ' + attr + ' value="' + esc(value ?? "") + '"' + ph + ">";
  default:
    return '<input type="text" ' + attr + ' value="' + esc(value ?? "") + '"' + ph + ">";
  }
}

function tableFieldHTML(f, rows) {
  const head = f.columns.map((c) => "<th>" + esc(c.label) + "</th>").join("") + "<th></th>";
  const body = rows.map((row) => tableRowHTML(f, row)).join("");
  return '<div class="form-table-wrap">' +
    '<span class="form-label">' + esc(f.label) + "</span>" +
    '<table class="form-table" data-table="' + esc(f.path) + '">' +
      "<thead><tr>" + head + "</tr></thead>" +
      "<tbody>" + body + "</tbody>" +
    "</table>" +
    '<button type="button" class="ghost small" data-act="add-row" data-field="' +
      esc(f.path) + '">+ 添加一行</button>' +
    (f.help ? '<small class="muted">' + esc(f.help) + "</small>" : "") +
  "</div>";
}

function tableRowHTML(f, row) {
  const id = row && row._id != null ? row._id : -1;
  const cells = f.columns.map((c) =>
    "<td>" + inputHTML(c, row ? row[c.path] : "", c.path) + "</td>").join("");
  return '<tr data-id="' + id + '">' + cells +
    '<td><button type="button" class="small danger" data-act="del-row">删除</button></td></tr>';
}

function readInput(el) {
  if (el.type === "checkbox") return el.checked;
  return el.value;
}

function collectConfigForm() {
  const values = {};
  document.querySelectorAll("#cfg-form [data-path]").forEach((el) => {
    values[el.dataset.path] = readInput(el);
  });
  document.querySelectorAll("#cfg-form table[data-table]").forEach((table) => {
    const rows = [];
    table.querySelectorAll("tbody tr").forEach((tr) => {
      const row = { _id: Number(tr.dataset.id) };
      tr.querySelectorAll("[data-col]").forEach((el) => {
        row[el.dataset.col] = readInput(el);
      });
      rows.push(row);
    });
    values[table.dataset.table] = rows;
  });
  return values;
}

function configFormAction(e) {
  const btn = e.target.closest("button[data-act]");
  if (!btn) return;
  if (btn.dataset.act === "del-row") {
    btn.closest("tr").remove();
    return;
  }
  if (btn.dataset.act === "add-row") {
    const f = findFormField(btn.dataset.field);
    const tbody = btn.closest(".form-table-wrap").querySelector("tbody");
    if (f) tbody.insertAdjacentHTML("beforeend", tableRowHTML(f, null));
  }
}

function reportText(rep) {
  const parts = [];
  if (rep.applied && rep.applied.length) parts.push("已生效: " + rep.applied.join(", "));
  if (rep.restart_required && rep.restart_required.length)
    parts.push("需要重启: " + rep.restart_required.join(", "));
  return parts.length ? parts.join("\n") : "已保存(无变更)";
}

async function saveConfig() {
  const out = $("#cfg-result");
  out.textContent = "保存中…";
  try {
    let rep;
    if (state.configMode === "form") {
      rep = await api("PUT", "api/config/form", { values: collectConfigForm() });
    } else {
      rep = await api("PUT", "api/config", { yaml: $("#cfg-yaml").value });
    }
    out.textContent = reportText(rep);
    await loadConfig();
  } catch (err) {
    out.textContent = "保存失败: " + err.message;
  }
}

/* ---------- client tokens ---------- */

function routeChecklist(selected) {
  const set = new Set(selected || []);
  if (!state.tokenRoutes.length) {
    return '<span class="muted">暂无路由，请先在配置页添加</span>';
  }
  return state.tokenRoutes.map((r) =>
    '<label class="check-row"><input type="checkbox" value="' + esc(r) + '"' +
    (set.has(r) ? " checked" : "") + "> " + esc(r) + "</label>").join("");
}

async function loadTokens() {
  try {
    const data = await api("GET", "api/tokens");
    state.tokens = data.tokens || [];
    state.tokenRoutes = data.routes || [];
    state.tokenLoaded = true;
    renderTokens();
  } catch (err) {
    $("#token-result").textContent = "加载失败: " + err.message;
  }
}

function renderTokens() {
  const tbody = $("#tokens-table tbody");
  if (!state.tokens.length) {
    tbody.innerHTML = '<tr><td colspan="5" class="muted">暂无 Token</td></tr>';
    return;
  }
  tbody.innerHTML = state.tokens.map((t) => {
    const route = (t.routes && t.routes.length)
      ? esc(t.routes.join(", "))
      : '<span class="muted">全部</span>';
    const status = t.enabled ? '<span class="pill ok">启用</span>' : '<span class="pill err">禁用</span>';
    const secret = t.token_set
      ? '<span class="mono">已设置 ' + esc(t.token_hint || "") + "</span>"
      : '<span class="muted">未设置</span>';
    const actions = state.role === "admin"
      ? '<button class="small" data-act="edit" data-index="' + t.index + '">编辑</button> ' +
        '<button class="small danger" data-act="del" data-index="' + t.index + '">删除</button>'
      : "";
    return "<tr><td>" + esc(t.name || "（未命名）") + "</td><td>" + route + "</td><td>" +
      status + "</td><td>" + secret + "</td><td>" + actions + "</td></tr>";
  }).join("");
}

function tokenFormOpen(index) {
  state.tokenEdit = index;
  const t = index >= 0 ? state.tokens.find((x) => x.index === index) : null;
  $("#token-dialog-title").textContent = t ? "编辑 Token" : "新建 Token";
  $("#token-index").value = index;
  $("#token-name").value = t ? t.name : "";
  $("#token-routes").innerHTML = routeChecklist(t ? t.routes : []);
  $("#token-value").value = "";
  $("#token-value").disabled = false;
  $("#token-enabled").checked = t ? t.enabled : true;
  $("#token-generate").checked = false;
  $("#token-hint").textContent = t
    ? "Token 留空表示保持不变；勾选“重新生成”会生成新值。"
    : "Token 留空会自动生成一个随机值，保存后只显示一次。";
  $("#token-dialog").showModal();
  $("#token-name").focus();
}

function tokenFormClose() {
  $("#token-dialog").close();
  state.tokenEdit = -1;
}

function showNewToken(tok) {
  const el = $("#token-result");
  el.textContent = "";
  if (!tok) return;
  const label = document.createElement("span");
  label.textContent = "新 Token（仅显示一次）：";
  const code = document.createElement("code");
  code.textContent = tok;
  const btn = document.createElement("button");
  btn.type = "button";
  btn.className = "secondary small";
  btn.textContent = "复制";
  btn.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(tok);
      btn.textContent = "已复制";
    } catch {
      btn.textContent = "请手动复制";
    }
  });
  el.append(label, code, btn);
}

async function saveToken(e) {
  e.preventDefault();
  const index = Number($("#token-index").value);
  const body = {
    name: $("#token-name").value.trim(),
    routes: [...document.querySelectorAll("#token-routes input:checked")].map((el) => el.value),
    token: $("#token-value").value,
    enabled: $("#token-enabled").checked,
    generate: $("#token-generate").checked,
  };
  try {
    const rep = index >= 0
      ? await api("PUT", "api/tokens/" + index, body)
      : await api("POST", "api/tokens", body);
    tokenFormClose();
    await loadTokens();
    showNewToken(rep.token);
    if (!rep.token) $("#token-result").textContent = "已保存";
  } catch (err) {
    $("#token-hint").textContent = "保存失败: " + err.message;
  }
}

async function tokenAction(e) {
  const btn = e.target.closest("button[data-act]");
  if (!btn) return;
  const index = Number(btn.dataset.index);
  if (btn.dataset.act === "edit") {
    tokenFormOpen(index);
    return;
  }
  if (btn.dataset.act === "del") {
    if (!(await uiConfirm("删除 Token", "使用该 Token 的客户端会立即断开。确认删除？", { danger: true, okText: "删除" }))) return;
    try {
      await api("DELETE", "api/tokens/" + index);
      await loadTokens();
      $("#token-result").textContent = "已删除";
    } catch (err) {
      $("#token-result").textContent = "删除失败: " + err.message;
    }
  }
}

/* ---------- ip access ---------- */

function parseIPLines(value) {
  return value.split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
}

async function loadIPAccess() {
  try {
    const data = await api("GET", "api/ip-access");
    $("#ip-whitelist").value = (data.whitelist || []).join("\n");
    $("#ip-blacklist").value = (data.blacklist || []).join("\n");
    $("#ip-client").textContent = data.client_ip || "-";
    $("#ip-result").textContent = "";
  } catch (err) {
    $("#ip-result").textContent = "加载失败: " + err.message;
  }
}

async function saveIPAccess(e) {
  e.preventDefault();
  try {
    const data = await api("PUT", "api/ip-access", {
      whitelist: parseIPLines($("#ip-whitelist").value),
      blacklist: parseIPLines($("#ip-blacklist").value),
    });
    $("#ip-client").textContent = data.client_ip || "-";
    $("#ip-result").textContent = "已保存";
  } catch (err) {
    $("#ip-result").textContent = "保存失败: " + err.message;
  }
}

/* ---------- shared dialogs ---------- */

function openDialog(opts) {
  return new Promise((resolve) => {
    const dlg = $("#app-dialog");
    const form = $("#app-dialog-form");
    const input = $("#app-dialog-input");
    const ok = $("#app-dialog-ok");
    $("#app-dialog-title").textContent = opts.title || "";
    const message = $("#app-dialog-message");
    message.textContent = opts.message || "";
    message.classList.toggle("hidden", !opts.message);
    input.classList.toggle("hidden", !opts.input);
    input.type = opts.password ? "password" : "text";
    input.value = "";
    input.placeholder = opts.placeholder || "";
    ok.textContent = opts.okText || "确定";
    ok.classList.toggle("danger", !!opts.danger);
    $("#app-dialog-cancel").classList.toggle("hidden", !!opts.hideCancel);

    let settled = false;
    const finish = (value) => {
      if (settled) return;
      settled = true;
      form.onsubmit = null;
      dlg.oncancel = null;
      dlg.close();
      resolve(value);
    };
    form.onsubmit = (event) => {
      event.preventDefault();
      finish(opts.input ? input.value : true);
    };
    $("#app-dialog-cancel").onclick = () => finish(null);
    dlg.oncancel = (event) => {
      event.preventDefault();
      finish(null);
    };
    dlg.showModal();
    if (opts.input) setTimeout(() => input.focus(), 0);
  });
}

async function uiConfirm(title, message, opts) {
  const o = opts || {};
  return (await openDialog({
    title, message,
    okText: o.okText || "确定",
    danger: o.danger,
  })) === true;
}

async function uiAlert(title, message) {
  await openDialog({ title, message, okText: "知道了", hideCancel: true });
}

async function uiPrompt(title, message, placeholder, password) {
  const value = await openDialog({ title, message, input: true, placeholder, password, okText: "确定" });
  return typeof value === "string" ? value : null;
}

/* ---------- user menu ---------- */

function setUserMenu(open) {
  $("#user-menu-panel").classList.toggle("hidden", !open);
  $("#user-menu-toggle").setAttribute("aria-expanded", String(open));
}

function initUserMenu() {
  $("#user-menu-toggle").addEventListener("click", () =>
    setUserMenu($("#user-menu-panel").classList.contains("hidden")));
  document.addEventListener("click", (e) => {
    if (!$("#user-menu").contains(e.target)) setUserMenu(false);
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") setUserMenu(false);
  });
}

/* ---------- users ---------- */

async function loadUsers() {
  try {
    const data = await api("GET", "api/users");
    const tbody = $("#users-table tbody");
    tbody.innerHTML = (data.users || []).map((u) => {
      const enabled = u.enabled;
      return "<tr>" +
        "<td>" + u.id + "</td>" +
        "<td>" + esc(u.username) + "</td>" +
        "<td>" + esc(u.role) + "</td>" +
        '<td><span class="pill ' + (enabled ? "ok" : "err") + '">' +
          (enabled ? "启用" : "禁用") + "</span></td>" +
        "<td>" + fmtMs(u.last_login_at) + "</td>" +
        "<td>" +
          '<button class="small" data-act="pass" data-id="' + u.id + '">改密</button> ' +
          '<button class="small" data-act="toggle" data-id="' + u.id + '" data-en="' +
            (enabled ? "1" : "0") + '">' + (enabled ? "禁用" : "启用") + "</button> " +
          '<button class="small danger" data-act="del" data-id="' + u.id + '">删除</button>' +
        "</td></tr>";
    }).join("");
    state.usersLoaded = true;
  } catch (err) {
    $("#user-result").textContent = "加载失败: " + err.message;
  }
}

async function userAction(act, id, extra) {
  const out = $("#user-result");
  try {
    if (act === "pass") {
      const pw = await uiPrompt("修改密码", "请输入新密码（至少 8 位）。", "新密码", true);
      if (!pw) return;
      await api("PUT", "api/users/" + id, { password: pw });
      out.textContent = "密码已修改";
    } else if (act === "toggle") {
      await api("PUT", "api/users/" + id, { enabled: extra === "0" });
      out.textContent = extra === "0" ? "用户已启用" : "用户已禁用";
    } else if (act === "del") {
      if (!(await uiConfirm("删除用户", "确认删除该用户？此操作不可撤销。", { danger: true, okText: "删除" }))) return;
      await api("DELETE", "api/users/" + id);
      out.textContent = "用户已删除";
    }
    loadUsers();
  } catch (err) {
    out.textContent = "操作失败: " + err.message;
  }
}

async function createUser(e) {
  e.preventDefault();
  const out = $("#user-result");
  try {
    await api("POST", "api/users", {
      username: $("#new-user").value,
      password: $("#new-pass").value,
      role: $("#new-role").value,
    });
    out.textContent = "用户已创建";
    $("#new-user").value = "";
    $("#new-pass").value = "";
    loadUsers();
  } catch (err) {
    out.textContent = "创建失败: " + err.message;
  }
}

/* ---------- init ---------- */

initTheme();

$("#login-form").addEventListener("submit", doLogin);
["login-user", "login-pass"].forEach((id) => {
  $("#" + id).addEventListener("input", () => { $("#login-error").textContent = ""; });
});
$("#logout-btn").addEventListener("click", () => {
  setUserMenu(false);
  doLogout();
});
$("#restart-btn").addEventListener("click", restartClient);
initUserMenu();
$("#cfg-save").addEventListener("click", saveConfig);
$("#cfg-mode-form").addEventListener("click", () => setConfigMode("form"));
$("#cfg-mode-yaml").addEventListener("click", () => setConfigMode("yaml"));
$("#cfg-reload").addEventListener("click", () => {
  $("#cfg-result").textContent = "";
  loadConfig();
});
$("#cfg-form").addEventListener("click", configFormAction);
$("#cfg-subtabs").addEventListener("click", (e) => {
  const btn = e.target.closest("button[data-cfg-section]");
  if (btn) selectConfigSection(btn.dataset.cfgSection);
});
$("#token-add").addEventListener("click", () => tokenFormOpen(-1));
$("#token-cancel").addEventListener("click", tokenFormClose);
$("#token-dialog").addEventListener("close", () => { state.tokenEdit = -1; });
$("#token-form").addEventListener("submit", saveToken);
$("#token-generate").addEventListener("change", () => {
  const generate = $("#token-generate").checked;
  $("#token-value").disabled = generate;
  if (generate) $("#token-value").value = "";
});
$("#tokens-table").addEventListener("click", tokenAction);
$("#ip-form").addEventListener("submit", saveIPAccess);
$("#ip-reload").addEventListener("click", loadIPAccess);
$("#user-form").addEventListener("submit", createUser);
document.querySelectorAll(".tab").forEach((b) =>
  b.addEventListener("click", () => switchTab(b.dataset.tab)));
$("#users-table").addEventListener("click", (e) => {
  const btn = e.target.closest("button[data-act]");
  if (btn) userAction(btn.dataset.act, btn.dataset.id, btn.dataset.en);
});

if (state.token) {
  showApp();
} else {
  showLogin();
}
