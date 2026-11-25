// relay-htcp admin panel — vanilla JS single-page app.
"use strict";

const $ = (sel) => document.querySelector(sel);

const state = {
  token: sessionStorage.getItem("rhtcp_token") || "",
  role: "",
  username: "",
  statusTimer: null,
  statusLoaded: false,
  pollBusy: false,
  pollFails: 0,
  pollInterval: 0, // 0 = no auto refresh (default)
  lastStatusJSON: "",
  connected: true,
  visibilityBound: false,
  configMode: "form",
  configSection: "",
  form: null,
  tokens: [],
  tokenRoutes: [],
  tokenEdit: -1,
  tokenLoaded: false,
  restarting: false,
  trafficRole: "",
  trafficLoadedAt: 0,
  trafficBusy: false,
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
    toast("会话已过期，请重新登录", "err");
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

/* ---------- toasts & guards ---------- */

// Global feedback for errors that would otherwise only surface in a section
// result box — or nowhere at all (session expiry). Auto-dismisses.
function toast(message, kind, ttl) {
  const region = $("#toast-region");
  const el = document.createElement("div");
  el.className = "toast" + (kind ? " " + kind : "");
  el.textContent = message;
  region.appendChild(el);
  setTimeout(() => {
    el.style.opacity = "0";
    setTimeout(() => el.remove(), 320);
  }, ttl || (kind === "err" ? 6000 : 3500));
}

// Disables the triggering control while the action runs so a double click
// cannot fire the same request twice.
async function guard(btn, fn) {
  if (btn) btn.disabled = true;
  try {
    await fn();
  } finally {
    if (btn) btn.disabled = false;
  }
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
  document.documentElement.classList.remove("has-auth");
  $("#app-view").classList.add("hidden");
  $("#login-view").classList.remove("hidden");
  $("#login-error").textContent = "";
  state.token = "";
  sessionStorage.removeItem("rhtcp_token");
}

async function showApp() {
  document.documentElement.classList.add("has-auth");
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
    // The raw YAML view contains client tokens in cleartext: admins only.
    const canYAML = me.role === "admin";
    $("#cfg-mode-yaml").classList.toggle("hidden", !canYAML);
    if (!canYAML && state.configMode === "yaml") setConfigMode("form");
    handleHashChange();
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

const VALID_TABS = ["status", "config", "tokens", "ip-access", "users"];

function switchTab(name, updateHash = true) {
  if (!VALID_TABS.includes(name)) name = "status";
  document.querySelectorAll(".tab").forEach((b) =>
    b.classList.toggle("active", b.dataset.tab === name));
  document.querySelectorAll("main > section").forEach((s) =>
    s.classList.toggle("hidden", s.id !== "tab-" + name));
  if (updateHash && window.location.hash !== "#" + name) {
    history.replaceState(null, "", "#" + name);
  }
  if (name === "config") loadConfig();
  if (name === "tokens") loadTokens();
  if (name === "ip-access") loadIPAccess();
  if (name === "users" && !state.usersLoaded) loadUsers();
}

function handleHashChange() {
  const hash = window.location.hash.replace(/^#/, "");
  if (hash && VALID_TABS.includes(hash)) {
    // Check permission visibility
    if (hash === "users" && state.role !== "admin") return;
    if (hash === "ip-access" && state.role !== "admin") return;
    switchTab(hash, false);
  }
}

/* ---------- status ---------- */

const POLL_BASE = 3000; // normal poll interval default
const POLL_MAX = 15000; // backoff ceiling while the API is unreachable

function startPolling(immediate = true) {
  stopPolling();
  state.pollFails = 0;
  if (!state.visibilityBound) {
    state.visibilityBound = true;
    // Pause polling in background tabs; an immediate poll resumes it on return.
    document.addEventListener("visibilitychange", () => {
      if (!state.token) return;
      if (document.hidden) stopPolling();
      else if (state.pollInterval > 0) schedulePoll(state.pollInterval);
    });
  }
  if (immediate) {
    schedulePoll(0);
  } else if (state.pollInterval > 0) {
    schedulePoll(state.pollInterval);
  }
}

function stopPolling() {
  if (state.statusTimer) {
    clearTimeout(state.statusTimer);
    state.statusTimer = null;
  }
}

function schedulePoll(delay) {
  stopPolling();
  state.statusTimer = setTimeout(pollStatus, delay);
}

// Self-rescheduling poll: at most one request in flight (no pile-up when a
// round trip takes longer than the interval), exponential back-off while the
// API is down, and a visible offline badge instead of silent stale data.
async function pollStatus(isManual = false) {
  if (state.pollBusy) return;
  state.pollBusy = true;
  const refreshBtn = $("#refresh-status-btn");
  if (isManual && refreshBtn) refreshBtn.classList.add("spinning");
  let st = null;
  let ok = false;
  try {
    st = await api("GET", "api/status");
    ok = true;
  } catch { /* handled below */ }
  state.pollBusy = false;
  if (refreshBtn) refreshBtn.classList.remove("spinning");

  if (!ok) {
    state.pollFails += 1;
    setConnIndicator(false);
    if (state.pollInterval > 0) {
      schedulePoll(Math.min(Math.max(POLL_BASE, state.pollInterval) << Math.min(state.pollFails, 4), POLL_MAX));
    }
    return;
  }
  state.pollFails = 0;
  setConnIndicator(true);
  const now = new Date();
  const timeStr = [now.getHours(), now.getMinutes(), now.getSeconds()]
    .map((n) => String(n).padStart(2, "0")).join(":");
  const lastUpdated = $("#last-updated");
  if (lastUpdated) lastUpdated.textContent = "更新于 " + timeStr;
  renderStatus(st);

  if (state.pollInterval > 0) {
    schedulePoll(state.pollInterval);
  }
}

function setConnIndicator(online) {
  if (state.connected === online) return;
  state.connected = online;
  $("#conn-badge").classList.toggle("hidden", online);
}

function renderStatus(st) {
  // Skip the full innerHTML rebuild when the payload is unchanged.
  const snap = JSON.stringify(st);
  if (state.statusLoaded && snap === state.lastStatusJSON) return;
  state.statusLoaded = true;
  state.lastStatusJSON = snap;

  const badge = $("#role-badge");
  badge.textContent = st.role;
  badge.className = "badge" + (st.role === "client" ? " client" : "");
  $("#tokens-tab").style.display = st.role === "server" ? "" : "none";
  // Only the client supports an in-place restart, and only admins may do it.
  const canRestart = st.role === "client" && state.role === "admin" && !state.restarting;
  $("#restart-btn").classList.toggle("hidden", !canRestart);

  const cards = [card("版本", st.version), card("运行时长", fmtUptime(st.uptime_sec))];
  const liveTitle = $("#live-title");
  let live = "";
  let showLive = true;

  if (st.role === "server" && st.server) {
    const s = st.server;
    showLive = false;
    cards.push(card("监听地址", s.listen_addr));
    if (s.proxy) cards.push(card("出口代理", s.proxy, "ok"));
    cards.push(card("活跃隧道", String(s.active_tunnels)));
    cards.push(card("活跃连接", String((s.active_streams || []).length)));
    cards.push('<div class="card"><div class="k">累计流量</div>' +
      '<div class="v traffic">' +
        '<span>入站 ' + esc(fmtBytes(s.bytes_in)) + "</span>" +
        '<span>出站 ' + esc(fmtBytes(s.bytes_out)) + "</span>" +
      "</div></div>");
    cards.push(card("诱饵页访问", String(s.decoy_views), "warn"));
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
      ((c.providers || []).length
        ? "<h3 class='muted' style='margin:14px 0 6px'>STCP 提供端</h3>" +
          table(["路由", "本地服务", "服务端", "并发流"],
            (c.providers || []).map((p) => [
              esc(p.route), esc(p.local),
              (p.servers && p.servers.length) ? esc(p.servers.join(", ")) : "全部",
              String(p.pool),
            ]))
        : "") +
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

  liveTitle.classList.toggle("hidden", !showLive);
  $("#summary").innerHTML = cards.join("");
  $("#live").innerHTML = showLive ? live : "";
  updateTrafficPanel(st.role);
}

/* ---------- daily traffic ---------- */

function updateTrafficPanel(role) {
  const section = $("#traffic-section");
  if (role !== "server" && role !== "client") {
    section.classList.add("hidden");
    return;
  }
  section.classList.remove("hidden");
  const isServer = role === "server";
  $("#traffic-title").textContent = isServer ? "客户端 Token 日流量" : "服务端路由当日流量";
  $("#traffic-kind").textContent = isServer ? "Token" : "服务端";
  if (state.trafficRole !== role) {
    state.trafficRole = role;
    state.trafficLoadedAt = 0;
    $("#traffic-filter").innerHTML = '<option value="">全部</option>';
  }
  const stale = Date.now() - state.trafficLoadedAt > 30000;
  if (!state.trafficBusy && (state.trafficLoadedAt === 0 || stale)) loadTraffic();
}

async function loadTraffic() {
  if (state.trafficBusy) return;
  state.trafficBusy = true;
  try {
    const role = state.trafficRole;
    const filter = $("#traffic-filter").value;
    let url = "api/traffic/daily?limit=20";
    if (role === "server") url += "&token=" + encodeURIComponent(filter);
    else url += "&server=" + encodeURIComponent(filter);
    const data = await api("GET", url);
    state.trafficLoadedAt = Date.now();
    renderTraffic(data);
  } catch (err) {
    $("#traffic-rows").textContent = "加载失败: " + err.message;
  } finally {
    state.trafficBusy = false;
  }
}

/* ---------- traffic charts (lightweight pure SVG) ---------- */

function renderSVGBarChart(container, items, labelKey, value1Key, value2Key, label1, label2) {
  if (!container) return;
  if (!items || !items.length) {
    container.classList.add("hidden");
    container.innerHTML = "";
    return;
  }
  container.classList.remove("hidden");

  // Determine max value for Y scale
  let maxVal = 0;
  items.forEach((item) => {
    const v1 = Number(item[value1Key] || 0);
    const v2 = Number(item[value2Key] || 0);
    const sum = v1 + v2;
    if (sum > maxVal) maxVal = sum;
  });
  if (maxVal === 0) maxVal = 1024; // fallback baseline

  const n = items.length;
  // Increase SVG bottom padding and overall height so rotated labels never clip
  const width = Math.max(800, n * 50);
  const height = 230;
  const padLeft = 55;
  const padRight = 30;
  const padTop = 15;
  const padBottom = 65;
  const chartW = width - padLeft - padRight;
  const chartH = height - padTop - padBottom;

  const barGap = 8;
  const groupW = chartW / n;
  const barW = Math.max(6, Math.min(28, groupW - barGap));

  // Grid lines (3 lines: 0, 50%, 100%)
  const yLines = [0, 0.5, 1];
  const gridSVG = yLines.map((ratio) => {
    const y = padTop + chartH * (1 - ratio);
    const valStr = fmtBytes(maxVal * ratio);
    return '<line x1="' + padLeft + '" y1="' + y + '" x2="' + (width - padRight) + '" y2="' + y +
      '" stroke="var(--border)" stroke-dasharray="3,3" stroke-width="1"/>' +
      '<text x="' + (padLeft - 8) + '" y="' + (y + 3) +
      '" fill="var(--muted)" font-size="10" text-anchor="end">' + esc(valStr) + '</text>';
  }).join("");

  // Bars and labels
  const barsSVG = items.map((item, idx) => {
    const v1 = Number(item[value1Key] || 0);
    const v2 = Number(item[value2Key] || 0);
    const total = v1 + v2;
    const h1 = (v1 / maxVal) * chartH;
    const h2 = (v2 / maxVal) * chartH;

    const groupX = padLeft + idx * groupW + (groupW - barW) / 2;
    const yBase = padTop + chartH;
    const y1 = yBase - h1;
    const y2 = y1 - h2;

    const rawLabel = String(item[labelKey] || "");
    const tooltipText = (item[labelKey] || "-") + " | " + label1 + ": " + fmtBytes(v1) + " | " + label2 + ": " + fmtBytes(v2) + " (合计: " + fmtBytes(total) + ")";
    const labelX = groupX + barW / 2;
    const labelY = yBase + 12;

    return '<g class="chart-group" data-tip="' + esc(tooltipText) + '">' +
      (h1 > 0 ? '<rect class="chart-bar" x="' + groupX + '" y="' + y1 + '" width="' + barW + '" height="' + h1 + '" fill="var(--accent)" rx="2"/>' : '') +
      (h2 > 0 ? '<rect class="chart-bar" x="' + groupX + '" y="' + y2 + '" width="' + barW + '" height="' + h2 + '" fill="var(--ok)" rx="2"/>' : '') +
      '<rect class="chart-hover-trigger" x="' + (padLeft + idx * groupW) + '" y="' + padTop + '" width="' + groupW + '" height="' + (chartH + 45) + '" fill="transparent"/>' +
      '<text class="chart-x-label" x="' + labelX + '" y="' + labelY + '" fill="var(--muted)" font-size="11" text-anchor="end" transform="rotate(-30 ' + labelX + ' ' + labelY + ')">' + esc(rawLabel) + '</text>' +
      '</g>';
  }).join("");

  container.innerHTML =
    '<div class="svg-chart-wrap">' +
      '<svg class="svg-chart" viewBox="0 0 ' + width + ' ' + height + '">' +
        gridSVG +
        barsSVG +
      '</svg>' +
      '<div class="chart-tooltip hidden" id="chart-tip"></div>' +
      '<div class="chart-legend">' +
        '<span class="chart-legend-item"><span class="chart-legend-color" style="background:var(--accent)"></span> ' + esc(label1) + '</span>' +
        '<span class="chart-legend-item"><span class="chart-legend-color" style="background:var(--ok)"></span> ' + esc(label2) + '</span>' +
      '</div>' +
    '</div>';

  const tip = container.querySelector("#chart-tip");
  const wrap = container.querySelector(".svg-chart-wrap");
  container.querySelectorAll(".chart-group").forEach((g) => {
    g.addEventListener("mouseenter", (e) => {
      const tipText = g.dataset.tip;
      if (!tipText || !tip) return;
      tip.textContent = tipText;
      tip.classList.remove("hidden");
    });
    g.addEventListener("mousemove", (e) => {
      if (!tip || !wrap) return;
      const rect = wrap.getBoundingClientRect();
      const x = e.clientX - rect.left;
      const y = e.clientY - rect.top;
      tip.style.left = Math.max(30, Math.min(rect.width - 30, x)) + "px";
      tip.style.top = y + "px";
    });
    g.addEventListener("mouseleave", () => {
      if (tip) tip.classList.add("hidden");
    });
  });
}

function renderTraffic(data) {
  const isServer = data.filter_kind === "token";
  $("#traffic-day").textContent = data.day ? "统计日期 " + data.day : "";
  const select = $("#traffic-filter");
  const current = select.value;
  const labels = {};
  (data.filters || []).forEach((f) => { labels[f.key] = f.label; });
  select.innerHTML = '<option value="">全部</option>' +
    (data.filters || []).map((f) =>
      '<option value="' + esc(f.key) + '">' + esc(f.label) + "</option>").join("");
  if (current && (data.filters || []).some((f) => f.key === current)) select.value = current;

  const rows = (data.rows || []).map((r) => {
    const name = isServer ? (labels[r.token] || r.token || "-") : (r.server || "-");
    const total = (r.bytes_in || 0) + (r.bytes_out || 0);
    return [
      esc(r.day), esc(name), esc(r.route || "-"),
      fmtBytes(r.bytes_in), fmtBytes(r.bytes_out), fmtBytes(total),
    ];
  });
  const headers = isServer
    ? ["日期", "Token", "路由", "入站", "出站", "合计"]
    : ["日期", "服务端", "路由", "入站", "出站", "合计"];
  $("#traffic-rows").innerHTML = table(headers, rows);

  // Render SVG chart for daily traffic
  const chartItems = (data.rows || []).map((r) => ({
    name: isServer ? (labels[r.token] || r.token || "-") : (r.server || "-"),
    bytes_in: r.bytes_in || 0,
    bytes_out: r.bytes_out || 0,
  }));
  renderSVGBarChart($("#traffic-chart"), chartItems, "name", "bytes_in", "bytes_out", "入站", "出站");
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
  if (f.type === "bool") {
    return '<div class="form-row form-check">' +
      '<span class="form-label">' + esc(f.label) + "</span>" +
      '<label class="check-line">' + inputHTML(f, value, "") +
        '<span class="muted">勾选启用</span></label>' +
      (f.help ? '<small class="muted">' + esc(f.help) + "</small>" : "") +
    "</div>";
  }
  return '<label class="form-row">' +
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
  case "multiselect":
    return multiSelectHTML(f, attr, value);
  case "duration":
    return '<input type="text" ' + attr + ' value="' + esc(value ?? "") + '"' + ph + ">";
  default:
    return '<input type="text" ' + attr + ' value="' + esc(value ?? "") + '"' + ph + ">";
  }
}

// The routes table shows one address cell for both route types: the cell is
// the tcp target or the stcp server-exposed bind, depending on the row's type.
const SHARED_ADDR_TABLE = "routes";

function tableColumns(f) {
  if (f.path !== SHARED_ADDR_TABLE) return f.columns;
  return f.columns.filter((c) => c.path !== "bind").map((c) =>
    c.path === "target" ? Object.assign({}, c, { label: "地址" }) : c);
}

function sharedAddrColumn(stcp) {
  return stcp ? "bind" : "target";
}

function sharedAddrPlaceholder(stcp) {
  return stcp ? "127.0.0.1:1234（可选，服务端暴露）" : "127.0.0.1:22 或 https://host";
}

function sharedAddrHTML(row) {
  const stcp = !!row && row.type === "stcp";
  return inputHTML({ type: "text", placeholder: sharedAddrPlaceholder(stcp) },
    row ? row[sharedAddrColumn(stcp)] : "", sharedAddrColumn(stcp));
}

// Switching a row's type moves the address cell to the matching key and
// clears it, so a tcp target never leaks into a stcp bind or the reverse.
function switchRouteAddr(tr) {
  const typeEl = tr.querySelector('[data-col="type"]');
  const input = tr.querySelector('input[data-col="target"], input[data-col="bind"]');
  if (!typeEl || !input) return;
  const stcp = typeEl.value === "stcp";
  const col = sharedAddrColumn(stcp);
  if (input.dataset.col === col) return;
  input.dataset.col = col;
  input.placeholder = sharedAddrPlaceholder(stcp);
  input.value = "";
}

function tableFieldHTML(f, rows) {
  const head = tableColumns(f).map((c) =>
    "<th" + (c.type === "bool" ? ' class="col-bool"' : "") + ">" +
      esc(c.label) + "</th>").join("") + "<th>操作</th>";
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
  const cells = tableColumns(f).map((c) => {
    if (f.path === SHARED_ADDR_TABLE && c.path === "target") {
      return "<td>" + sharedAddrHTML(row) + "</td>";
    }
    return "<td" + (c.type === "bool" ? ' class="col-bool"' : "") + ">" +
      inputHTML(c, row ? row[c.path] : "", c.path) + "</td>";
  }).join("");
  return '<tr data-id="' + id + '">' + cells +
    '<td><button type="button" class="small danger" data-act="del-row">删除</button></td></tr>';
}

function readInput(el) {
  if (el.type === "checkbox") return el.checked;
  if (el.classList && el.classList.contains("multi-select")) {
    return multiSelectChecked(el).join(", ");
  }
  return el.value;
}

/* ---------- dropdown multi-select (e.g. listener -> servers) ---------- */

const MULTI_ALL_LABEL = "全部服务端";

function valueList(value) {
  if (Array.isArray(value)) return value.map((v) => String(v)).filter(Boolean);
  return String(value == null ? "" : value)
    .split(",").map((s) => s.trim()).filter(Boolean);
}

// Server names typed into the servers table right now, so the dropdown tracks
// unsaved renames in the other sub-tab.
function liveServerNames() {
  const names = [];
  document.querySelectorAll('#cfg-form table[data-table="servers"] tbody tr [data-col="name"]')
    .forEach((el) => {
      const name = (el.value || "").trim();
      if (name && !names.includes(name)) names.push(name);
    });
  return names;
}

function multiSelectChecked(ms) {
  return Array.from(ms.querySelectorAll('.ms-menu input[type="checkbox"]:checked'))
    .map((el) => el.value).filter(Boolean);
}

function multiSelectLabel(selected) {
  return selected.length ? selected.join(", ") : MULTI_ALL_LABEL;
}

function multiSelectOptionsHTML(selected, options) {
  const seen = [];
  (options || []).forEach((o) => {
    if (o && !seen.includes(o)) seen.push(o);
  });
  if (!seen.length) return '<div class="ms-empty">尚未配置服务端</div>';
  return seen.map((o) =>
    '<label class="ms-item"><input type="checkbox" value="' + esc(o) + '"' +
      (selected.includes(o) ? " checked" : "") + "> " + esc(o) + "</label>").join("") +
    '<div class="ms-actions">' +
      '<button type="button" class="small ghost" data-ms="all">全选</button>' +
      '<button type="button" class="small ghost" data-ms="none">清空</button>' +
    "</div>";
}

function multiSelectHTML(f, attr, value) {
  const selected = valueList(value);
  return '<div class="multi-select" ' + attr + ">" +
    '<button type="button" class="ms-toggle" aria-haspopup="true" aria-expanded="false">' +
      '<span class="ms-label">' + esc(multiSelectLabel(selected)) + "</span>" +
      '<span class="ms-caret" aria-hidden="true">▾</span>' +
    "</button>" +
    '<div class="ms-menu hidden">' +
      multiSelectOptionsHTML(selected, (f.options || []).concat(selected)) +
    "</div>" +
  "</div>";
}

function refreshMultiSelectLabel(ms) {
  const label = ms.querySelector(".ms-label");
  if (label) label.textContent = multiSelectLabel(multiSelectChecked(ms));
}

function openMultiSelect(ms) {
  const checked = multiSelectChecked(ms);
  const menu = ms.querySelector(".ms-menu");
  // Rebuild on open so renamed/added servers from the servers table show up
  // immediately, while keeping already-checked values selectable.
  menu.innerHTML = multiSelectOptionsHTML(checked, liveServerNames().concat(checked));
  menu.classList.remove("hidden");
  const toggle = ms.querySelector(".ms-toggle");
  if (toggle) toggle.setAttribute("aria-expanded", "true");
}

function closeMultiSelects(except) {
  document.querySelectorAll("#cfg-form .multi-select").forEach((ms) => {
    if (ms === except) return;
    const menu = ms.querySelector(".ms-menu");
    if (menu) menu.classList.add("hidden");
    const toggle = ms.querySelector(".ms-toggle");
    if (toggle) toggle.setAttribute("aria-expanded", "false");
  });
}

function multiSelectAction(e) {
  const ms = e.target.closest(".multi-select");
  if (!ms) return false;
  if (e.target.closest(".ms-toggle")) {
    const menu = ms.querySelector(".ms-menu");
    const willOpen = menu.classList.contains("hidden");
    closeMultiSelects(ms);
    if (willOpen) {
      openMultiSelect(ms);
    } else {
      menu.classList.add("hidden");
      ms.querySelector(".ms-toggle").setAttribute("aria-expanded", "false");
    }
    return true;
  }
  const bulk = e.target.closest("[data-ms]");
  if (bulk) {
    ms.querySelectorAll('.ms-menu input[type="checkbox"]').forEach((box) => {
      box.checked = bulk.dataset.ms === "all";
    });
    refreshMultiSelectLabel(ms);
    return true;
  }
  // Clicks on items/checkbox labels fall through to the browser so the
  // checkbox toggles; the change handler updates the summary on the button.
  return true;
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
  if (multiSelectAction(e)) return;
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
  await guard($("#cfg-save"), async () => {
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
  });
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
    let status = t.enabled ? '<span class="pill ok">启用</span>' : '<span class="pill err">禁用</span>';
    if (t.blocked) status += ' <span class="pill err">流量超限</span>';
    if (t.limit_enabled) {
      const limits = [];
      if (t.daily_limit_mb > 0) limits.push("日 " + t.daily_limit_mb + "MB");
      if (t.weekly_limit_mb > 0) limits.push("周 " + t.weekly_limit_mb + "MB");
      if (t.monthly_limit_mb > 0) limits.push("月 " + t.monthly_limit_mb + "MB");
      status += '<br><small class="muted">' +
        (limits.length ? esc(limits.join(" / ")) : "已启用限流（未设上限）") + "</small>";
    }
    const secret = t.token_set
      ? '<span class="mono">已设置 ' + esc(t.token_hint || "") + "</span>"
      : '<span class="muted">未设置</span>';
    const actions =
      '<button class="small secondary" data-act="detail" data-index="' + t.index + '">详细</button> ' +
      (state.role === "admin"
        ? '<button class="small" data-act="edit" data-index="' + t.index + '">编辑</button> ' +
          '<button class="small danger" data-act="del" data-index="' + t.index + '">删除</button>'
        : "");
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
  $("#token-limit-enabled").checked = t ? !!t.limit_enabled : false;
  $("#token-limit-day").value = t ? t.daily_limit_mb || 0 : 0;
  $("#token-limit-week").value = t ? t.weekly_limit_mb || 0 : 0;
  $("#token-limit-month").value = t ? t.monthly_limit_mb || 0 : 0;
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
  await guard(e.submitter, async () => {
    const index = Number($("#token-index").value);
    const body = {
      name: $("#token-name").value.trim(),
      routes: [...document.querySelectorAll("#token-routes input:checked")].map((el) => el.value),
      token: $("#token-value").value,
      enabled: $("#token-enabled").checked,
      generate: $("#token-generate").checked,
      limit_enabled: $("#token-limit-enabled").checked,
      daily_limit_mb: Math.max(0, parseInt($("#token-limit-day").value, 10) || 0),
      weekly_limit_mb: Math.max(0, parseInt($("#token-limit-week").value, 10) || 0),
      monthly_limit_mb: Math.max(0, parseInt($("#token-limit-month").value, 10) || 0),
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
  });
}

async function tokenAction(e) {
  const btn = e.target.closest("button[data-act]");
  if (!btn) return;
  const index = Number(btn.dataset.index);
  if (btn.dataset.act === "detail") {
    await tokenDetail(index);
    return;
  }
  if (btn.dataset.act === "edit") {
    tokenFormOpen(index);
    return;
  }
  if (btn.dataset.act === "del") {
    await guard(btn, async () => {
      if (!(await uiConfirm("删除 Token", "使用该 Token 的客户端会立即断开。确认删除？", { danger: true, okText: "删除" }))) return;
      try {
        await api("DELETE", "api/tokens/" + index);
        await loadTokens();
        $("#token-result").textContent = "已删除";
      } catch (err) {
        $("#token-result").textContent = "删除失败: " + err.message;
      }
    });
  }
}

async function tokenDetail(index) {
  const dlg = $("#token-detail-dialog");
  const body = $("#token-detail-body");
  const t = state.tokens.find((x) => x.index === index);
  $("#token-detail-title").textContent = "Token 详情" + (t && t.name ? " · " + t.name : "");
  body.textContent = "加载中…";
  if (!dlg.open) dlg.showModal();
  try {
    const data = await api("GET", "api/tokens/" + index + "/traffic?days=14");
    drawTokenDetail(data);
  } catch (err) {
    body.textContent = "加载失败: " + err.message;
  }
}

function usageLine(label, u) {
  if (!u) return [esc(label), "-", "-", "-"];
  return [
    esc(label), fmtBytes(u.bytes_in), fmtBytes(u.bytes_out),
    fmtBytes((u.bytes_in || 0) + (u.bytes_out || 0)),
  ];
}

function drawTokenDetail(data) {
  const t = data.token || {};
  const usage = data.usage || {};
  const limit = [];
  if (t.daily_limit_mb > 0) limit.push("日 " + t.daily_limit_mb + "MB");
  if (t.weekly_limit_mb > 0) limit.push("周 " + t.weekly_limit_mb + "MB");
  if (t.monthly_limit_mb > 0) limit.push("月 " + t.monthly_limit_mb + "MB");
  let statePill = t.enabled ? '<span class="pill ok">启用</span>' : '<span class="pill err">禁用</span>';
  if (data.blocked || t.blocked) statePill += ' <span class="pill err">流量超限</span>';
  const summary =
    '<div class="detail-summary">' +
      '<div><span class="muted">状态</span><div>' + statePill + "</div></div>" +
      '<div><span class="muted">专属路由</span><div>' +
        ((t.routes && t.routes.length) ? esc(t.routes.join(", ")) : "全部") + "</div></div>" +
      '<div><span class="muted">流量限制</span><div>' +
        (t.limit_enabled
          ? (limit.length ? esc(limit.join(" / ")) : "已启用（未设上限）")
          : "未启用") + "</div></div>" +
    "</div>" +
    '<h3 class="muted detail-heading">周期统计</h3>' +
    table(["周期", "入站", "出站", "合计"], [
      usageLine("今日", usage.day),
      usageLine("本周", usage.week),
      usageLine("本月", usage.month),
    ]) +
    '<h3 class="muted detail-heading">最近 ' + (data.days || 14) + ' 天</h3>';
  const rows = (data.rows || []).map((r) => [
    esc(r.day), esc(r.route || "-"), fmtBytes(r.bytes_in),
    fmtBytes(r.bytes_out), fmtBytes((r.bytes_in || 0) + (r.bytes_out || 0)),
  ]);
  $("#token-detail-body").innerHTML = summary +
    table(["日期", "路由", "入站", "出站", "合计"], rows);
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
  await guard(e.submitter, async () => {
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
  });
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

// passwordDialog asks for the new password twice and only resolves when both
// fields match (and meet the minimum length). Mismatches keep the dialog open.
function passwordDialog() {
  return new Promise((resolve) => {
    const dlg = $("#password-dialog");
    const form = $("#password-form");
    const first = $("#password-new");
    const second = $("#password-confirm");
    const err = $("#password-error");
    first.value = "";
    second.value = "";
    err.textContent = "";
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
      const a = first.value;
      const b = second.value;
      if (a.length < 8) {
        err.textContent = "密码至少 8 位";
        return;
      }
      if (a !== b) {
        err.textContent = "两次输入的密码不一致";
        return;
      }
      err.textContent = "";
      finish(a);
    };
    $("#password-cancel").onclick = () => finish(null);
    dlg.oncancel = (event) => {
      event.preventDefault();
      finish(null);
    };
    dlg.showModal();
    setTimeout(() => first.focus(), 0);
  });
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

async function userAction(act, id, extra, btn) {
  const out = $("#user-result");
  await guard(btn, async () => {
    try {
      if (act === "pass") {
        const pw = await passwordDialog();
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
  });
}

async function createUser(e) {
  e.preventDefault();
  const out = $("#user-result");
  await guard(e.submitter, async () => {
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
  });
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
$("#cfg-form").addEventListener("change", (e) => {
  const ms = e.target.closest(".multi-select");
  if (ms && e.target.matches('input[type="checkbox"]')) refreshMultiSelectLabel(ms);
  if (e.target.matches('table[data-table="routes"] select[data-col="type"]')) {
    switchRouteAddr(e.target.closest("tr"));
  }
});
document.addEventListener("click", (e) => {
  if (!e.target.closest(".multi-select")) closeMultiSelects();
});
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") closeMultiSelects();
});
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
$("#token-detail-close").addEventListener("click", () => $("#token-detail-dialog").close());
$("#traffic-filter").addEventListener("change", () => {
  state.trafficLoadedAt = 0;
  loadTraffic();
});
$("#ip-form").addEventListener("submit", saveIPAccess);
$("#ip-reload").addEventListener("click", loadIPAccess);
$("#user-form").addEventListener("submit", createUser);
$("#refresh-status-btn")?.addEventListener("click", () => pollStatus(true));
$("#auto-refresh-select")?.addEventListener("change", (e) => {
  const interval = parseInt(e.target.value, 10) || 0;
  state.pollInterval = interval;
  stopPolling();
  if (interval > 0) schedulePoll(interval);
});
window.addEventListener("hashchange", handleHashChange);
document.querySelectorAll(".tab").forEach((b) =>
  b.addEventListener("click", () => switchTab(b.dataset.tab)));
$("#users-table").addEventListener("click", (e) => {
  const btn = e.target.closest("button[data-act]");
  if (btn) userAction(btn.dataset.act, btn.dataset.id, btn.dataset.en, btn);
});

if (state.token) {
  showApp();
} else {
  showLogin();
}
