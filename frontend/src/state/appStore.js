import { reactive } from "vue";
import { apiBaseEnv } from "../utils/runtimeEnv";

const AUTH_SESSION_PATH = "/api/auth/session";
const STORAGE_KEY_API = "sniffhound.apiBase";
const STORAGE_KEY_AUTH = "sniffhound.securityCode";
const LEGACY_STORAGE_KEY_AUTH = "sniffhound.sessionToken";
const STORAGE_KEY_NOTIFY_SOUND = "sniffhound.notifySoundEnabled";
const WS_RECONNECT_DELAY_MS = 1800;
const WS_REFRESH_THROTTLE_MS = 10000;
const WS_AUTH_CLOSE_CODE = 4401;
const APP_SHUTDOWN_DELAY_SECONDS = 0.2;
const WS_REFRESH_EVENT_TYPES = new Set([
  "welcome",
  "packet",
  "stats_update",
  "runtime_mode",
  "chat_message",
]);
// What counts as "important enough for a popup" - everything else stays
// available in the regular views (Monitors/SOC/etc.) without interrupting.
const NOTIFY_MONITOR_SEVERITIES = new Set(["high", "critical"]);
const NOTIFICATION_HISTORY_LIMIT = 30;

const state = reactive({
  apiBase: "",
  wsStatus: "offline",
  runtimeMode: "sniffer",
  runtime: {},
  realtimeMapSnapshot: null,
  realtimeMapGeneratedAt: "",
  authReady: false,
  authRequired: false,
  authStatus: "unknown",
  authToken: "",
  authError: "",
  authPromptOpen: false,
  shutdownPending: false,
  notifications: [],
  notifySoundEnabled: true,
});

const tableRefreshSubscribers = new Set();
const mapSnapshotSubscribers = new Set();

let inMemoryAuthToken = "";
let wsClient = null;
let wsReconnectTimer = null;
let wsRefreshTimer = null;
let wsPendingRefreshPayload = null;
let notificationIdSeq = 0;
let audioContext = null;
let lastRuntimeForNotify = null;
let hasEverConnectedRealtime = false;
let isRealtimeCurrentlyOnline = false;

function suggestApiBaseFromLocation(locationLike = null) {
  const locationRef =
    locationLike ||
    (typeof window !== "undefined" && window.location ? window.location : null);
  if (!locationRef) return "";

  const protocol = String(locationRef.protocol || "http:");
  const hostname = String(locationRef.hostname || "127.0.0.1");
  const port = String(locationRef.port || "");
  const isDevPort = port === "8080" || port === "5173" || port === "3000";
  if (isDevPort) {
    return `${protocol}//${hostname}:45678`;
  }
  return String(locationRef.origin || `${protocol}//${hostname}${port ? `:${port}` : ""}`);
}

function initApiBase() {
  if (typeof window === "undefined") {
    state.apiBase = "";
    return;
  }
  const storedApiBase = window.localStorage
    ? window.localStorage.getItem(STORAGE_KEY_API)
    : "";
  const base = storedApiBase || apiBaseEnv() || suggestApiBaseFromLocation(window.location) || "";
  state.apiBase = String(base || "").replace(/\/+$/, "");
}

function setApiBase(value) {
  const cleaned = String(value || "").trim().replace(/\/+$/, "");
  state.apiBase = cleaned;
  state.realtimeMapSnapshot = null;
  state.realtimeMapGeneratedAt = "";
  if (typeof window !== "undefined" && window.localStorage) {
    window.localStorage.setItem(STORAGE_KEY_API, cleaned);
  }
  reconnectRealtime();
}

function readStoredAuthToken() {
  clearLegacyAuthTokenArtifacts();
  if (typeof window === "undefined" || !window.localStorage) {
    return String(inMemoryAuthToken || "").trim();
  }
  const stored = window.localStorage.getItem(STORAGE_KEY_AUTH);
  inMemoryAuthToken = String(stored || "").trim();
  return inMemoryAuthToken;
}

function persistAuthToken(token) {
  const cleaned = String(token || "").trim();
  inMemoryAuthToken = cleaned;
  if (typeof window === "undefined" || !window.localStorage) {
    return;
  }
  if (cleaned) {
    window.localStorage.setItem(STORAGE_KEY_AUTH, cleaned);
  } else {
    window.localStorage.removeItem(STORAGE_KEY_AUTH);
  }
}

function clearLegacyAuthTokenArtifacts() {
  if (typeof window === "undefined") {
    return;
  }
  if (window.sessionStorage) {
    window.sessionStorage.removeItem(LEGACY_STORAGE_KEY_AUTH);
  }
  if (window.localStorage) {
    window.localStorage.removeItem(LEGACY_STORAGE_KEY_AUTH);
  }
}

function setAuthToken(token) {
  const cleaned = String(token || "").trim();
  state.authToken = cleaned;
  persistAuthToken(cleaned);
}

function lockRealtimeForAuth() {
  state.wsStatus = "locked";
}

function applyRuntimeSnapshot(payload) {
  const runtime = payload && typeof payload === "object" ? payload.runtime || payload : {};
  const mode = String(runtime.mode || payload.mode || "").trim().toLowerCase();
  if (mode) {
    state.runtimeMode = mode;
  }
  state.runtime = runtime && typeof runtime === "object" ? runtime : {};
  return state.runtime;
}

function initRuntime() {
  if (state.authRequired && state.authStatus !== "authenticated") {
    return Promise.resolve(null);
  }
  return fetchJsonPromise("/api/runtime/")
    .then((payload) => {
      applyRuntimeSnapshot(payload);
      return payload;
    })
    .catch(() => null);
}

function setRuntimeMode(mode) {
  const normalized = String(mode || "").trim().toLowerCase();
  if (!normalized) {
    return Promise.resolve(state.runtime);
  }
  return fetchJsonPromise("/api/runtime/", {
    method: "POST",
    body: JSON.stringify({ mode: normalized }),
  }).then((payload) => {
    applyRuntimeSnapshot(payload);
    return payload;
  });
}

function controlRuntimeMode(mode, action) {
  const normalizedMode = String(mode || "").trim().toLowerCase();
  const normalizedAction = String(action || "").trim().toLowerCase();
  if (!normalizedAction) {
    return Promise.resolve(state.runtime);
  }
  const body = { action: normalizedAction };
  if (normalizedMode) {
    body.mode = normalizedMode;
  }
  return fetchJsonPromise("/api/runtime/", {
    method: "POST",
    body: JSON.stringify(body),
  }).then((payload) => {
    applyRuntimeSnapshot(payload);
    return payload;
  });
}

function setSnifferInterface(interfaceName) {
  const values = String(interfaceName || "").trim();
  return setSnifferInterfaces(values ? [values] : []);
}

function setSnifferInterfaces(interfaceNames) {
  const normalized = Array.isArray(interfaceNames)
    ? [...new Set(interfaceNames.map((item) => String(item || "").trim()).filter(Boolean))]
    : [];
  return fetchJsonPromise("/api/runtime/", {
    method: "POST",
    body: JSON.stringify({
      interfaces: normalized,
    }),
  }).then((payload) => {
    applyRuntimeSnapshot(payload);
    return payload;
  });
}

function setWifiMonitor(enabled, interfaceName) {
  return fetchJsonPromise("/api/wifi/monitor", {
    method: "POST",
    body: JSON.stringify({
      enabled: Boolean(enabled),
      interface: String(interfaceName || "").trim(),
    }),
  }).then((payload) => {
    applyRuntimeSnapshot(payload);
    return payload;
  });
}

function listMonitors() {
  return fetchJsonPromise("/api/monitors/");
}

function saveMonitor(payload) {
  const method = payload && payload.id ? "PUT" : "POST";
  return fetchJsonPromise("/api/monitors/", {
    method,
    body: JSON.stringify(payload || {}),
  });
}

function deleteMonitor(id) {
  return fetchJsonPromise("/api/monitors/", {
    method: "DELETE",
    body: JSON.stringify({ id }),
  });
}

function toggleMonitorEnabled(id, enabled) {
  return fetchJsonPromise("/api/monitors/toggle", {
    method: "POST",
    body: JSON.stringify({ id, enabled: Boolean(enabled) }),
  });
}

function getMonitorConfig() {
  return fetchJsonPromise("/api/monitors/config");
}

function listHoneypotListeners() {
  return fetchJsonPromise("/api/honeypot/listeners/");
}

function createHoneypotListener(proto, port, label) {
  return fetchJsonPromise("/api/honeypot/listeners/", {
    method: "POST",
    body: JSON.stringify({ proto, port, label: label || "" }),
  });
}

function toggleHoneypotListenerEnabled(id, enabled) {
  return fetchJsonPromise("/api/honeypot/listeners/toggle", {
    method: "POST",
    body: JSON.stringify({ id, enabled: Boolean(enabled) }),
  });
}

function setMonitorConfig(payload) {
  return fetchJsonPromise("/api/monitors/config", {
    method: "POST",
    body: JSON.stringify(payload || {}),
  });
}

function buildIntelQuery({ search = "", limit = 200, offset = 0 } = {}) {
  const params = new URLSearchParams();
  if (search) params.set("search", search);
  if (limit) params.set("limit", String(limit));
  if (offset) params.set("offset", String(offset));
  const query = params.toString();
  return query ? `?${query}` : "";
}

function listDomains(options) {
  return fetchJsonPromise(`/api/domains/${buildIntelQuery(options)}`);
}

function listPaths(options) {
  return fetchJsonPromise(`/api/paths/${buildIntelQuery(options)}`);
}

function listIpCatalog(options) {
  return fetchJsonPromise(`/api/intel/ips/${buildIntelQuery(options)}`);
}

function listMonitorPackets(monitorId, options) {
  const params = new URLSearchParams();
  params.set("monitor_id", monitorId);
  const search = (options && options.search) || "";
  const limit = (options && options.limit) || 200;
  if (search) params.set("search", search);
  if (limit) params.set("limit", String(limit));
  return fetchJsonPromise(`/api/monitors/packets/?${params.toString()}`);
}

function apiUrl(path) {
  const base = state.apiBase ? state.apiBase.replace(/\/+$/, "") : "";
  const safePath = path && path.startsWith("/") ? path : `/${path || ""}`;
  return `${base}${safePath}`;
}

function parseJsonSafe(text) {
  try {
    return text ? JSON.parse(text) : null;
  } catch {
    return null;
  }
}

function buildHttpError(res, text, data) {
  const trimmed = (text || "").trim();
  const looksLikeHtml =
    trimmed.startsWith("<!DOCTYPE") ||
    trimmed.startsWith("<html") ||
    trimmed.startsWith("<!doctype");
  const message =
    (data && data.message) ||
    (data && data.status) ||
    (looksLikeHtml
      ? `HTTP ${res.status} ${res.statusText}`
      : trimmed || `HTTP ${res.status} ${res.statusText}`);
  const error = new Error(message);
  error.status = res.status;
  error.payload = data;
  return error;
}

function applyAuthHeader(headers = {}, token = state.authToken) {
  const nextHeaders = { ...headers };
  if (token && !nextHeaders["X-Security-Code"] && !nextHeaders["x-security-code"]) {
    nextHeaders["X-Security-Code"] = token;
  }
  if (
    token &&
    !nextHeaders.Authorization &&
    !nextHeaders.authorization
  ) {
    nextHeaders.Authorization = `Bearer ${token}`;
  }
  return nextHeaders;
}

function clearReconnectTimer() {
  if (!wsReconnectTimer) return;
  clearTimeout(wsReconnectTimer);
  wsReconnectTimer = null;
}

function destroyRealtime() {
  clearReconnectTimer();
  if (wsRefreshTimer) {
    clearTimeout(wsRefreshTimer);
    wsRefreshTimer = null;
  }
  wsPendingRefreshPayload = null;
  if (!wsClient) {
    if (state.authRequired && state.authStatus !== "authenticated") {
      lockRealtimeForAuth();
    } else {
      state.wsStatus = "offline";
    }
    return;
  }
  const socket = wsClient;
  wsClient = null;
  try {
    socket.close();
  } catch {
    // ignore close failures
  } finally {
    if (state.authRequired && state.authStatus !== "authenticated") {
      lockRealtimeForAuth();
    } else {
      state.wsStatus = "offline";
    }
  }
}

function openAuthPrompt(message = "") {
  if (message) {
    state.authError = String(message);
  }
  state.authPromptOpen = true;
  state.authReady = true;
  if (state.authRequired) {
    state.authStatus = "required";
  }
  destroyRealtime();
}

function handleUnauthorized(message = "Authentication required") {
  setAuthToken("");
  state.authRequired = true;
  state.authStatus = "required";
  state.authError = String(message || "Authentication required");
  state.authPromptOpen = true;
  state.authReady = true;
  destroyRealtime();
}

function fetchJsonPromise(path, options = {}, config = {}) {
  const opts = { ...options };
  const attachAuth = config.attachAuth !== false;
  const token = Object.prototype.hasOwnProperty.call(config, "token")
    ? config.token
    : state.authToken;
  opts.headers = attachAuth ? applyAuthHeader(opts.headers || {}, token) : { ...(opts.headers || {}) };
  if (opts.body && !opts.headers["Content-Type"] && !opts.headers["content-type"]) {
    opts.headers["Content-Type"] = "application/json";
  }
  return fetch(apiUrl(path), opts).then((res) =>
    res.text().then((text) => {
      const data = parseJsonSafe(text);
      if (!res.ok) {
        const error = buildHttpError(res, text, data);
        if (res.status === 401 && config.handleUnauthorized !== false) {
          handleUnauthorized((data && data.message) || error.message);
        }
        throw error;
      }
      return data;
    })
  );
}

function fetchJson(path, options = {}) {
  return fetchJsonPromise(path, options);
}

function requestSessionAuth(token = state.authToken) {
  const headers = token ? { "X-Security-Code": token } : {};
  return fetchJsonPromise(
    AUTH_SESSION_PATH,
    { method: "GET", headers },
    { attachAuth: false, handleUnauthorized: false }
  );
}

function activateAuthenticatedSession() {
  state.authStatus = "authenticated";
  state.authError = "";
  state.authPromptOpen = false;
  state.authReady = true;
  return initRuntime().finally(() => {
    reconnectRealtime();
  });
}

function bootstrap() {
  state.authReady = false;
  state.authError = "";
  state.shutdownPending = false;
  state.authToken = readStoredAuthToken();
  return requestSessionAuth(state.authToken)
    .then((payload) => {
      state.authRequired = Boolean(payload && payload.require_auth);
      if (!state.authRequired) {
        return activateAuthenticatedSession().then(() => payload);
      }
      if (payload && payload.authenticated) {
        return activateAuthenticatedSession().then(() => payload);
      }
      state.authStatus = "required";
      state.authReady = true;
      state.authPromptOpen = true;
      state.authError = String((payload && payload.message) || "Security code required");
      setAuthToken("");
      destroyRealtime();
      return payload;
    })
    .catch(() => {
      state.authReady = true;
      if (state.authRequired && state.authStatus !== "authenticated") {
        lockRealtimeForAuth();
      }
      return null;
    });
}

function authenticateSessionToken(rawToken) {
  const token = String(rawToken || "").trim();
  if (!token) {
    const error = new Error("Security code required");
    state.authRequired = true;
    state.authStatus = "required";
    state.authError = error.message;
    state.authPromptOpen = true;
    return Promise.reject(error);
  }
  return requestSessionAuth(token).then((payload) => {
    state.authRequired = Boolean(payload && payload.require_auth);
    if (!payload || !payload.authenticated) {
      handleUnauthorized((payload && payload.message) || "Invalid security code");
      throw new Error((payload && payload.message) || "Invalid security code");
    }
    setAuthToken(token);
    return activateAuthenticatedSession().then(() => payload);
  });
}

function extractArray(payload) {
  if (Array.isArray(payload)) return payload;
  if (payload && Array.isArray(payload.datas)) return payload.datas;
  return [];
}

function notifyTableRefresh(payload) {
  if (!tableRefreshSubscribers.size) return;
  tableRefreshSubscribers.forEach((subscriber) => {
    try {
      subscriber(payload);
    } catch {
      // ignore subscriber-level failures
    }
  });
}

function notifyMapSnapshotSubscribers(snapshot, meta = {}) {
  if (!mapSnapshotSubscribers.size) return;
  const payload = { snapshot, meta };
  mapSnapshotSubscribers.forEach((subscriber) => {
    try {
      subscriber(payload);
    } catch {
      // ignore subscriber-level failures
    }
  });
}

function applyRealtimeMapSnapshot(snapshot, meta = {}) {
  const normalized = snapshot && typeof snapshot === "object" ? snapshot : null;
  state.realtimeMapSnapshot = normalized;
  state.realtimeMapGeneratedAt = String(meta.generatedAt || meta.generated_at || "").trim();
  if (!normalized) return;
  notifyMapSnapshotSubscribers(normalized, meta);
}

function requestRealtimeMapSnapshot(limit = 300) {
  if (typeof window === "undefined" || typeof window.WebSocket === "undefined") {
    return false;
  }
  if (!wsClient || wsClient.readyState !== window.WebSocket.OPEN) {
    return false;
  }
  try {
    wsClient.send(JSON.stringify({ action: "scan_map_snapshot", limit: Number(limit) || 300 }));
    return true;
  } catch {
    return false;
  }
}

function initNotifySound() {
  if (typeof window === "undefined" || !window.localStorage) {
    state.notifySoundEnabled = true;
    return;
  }
  const stored = window.localStorage.getItem(STORAGE_KEY_NOTIFY_SOUND);
  state.notifySoundEnabled = stored === null ? true : stored === "1";
}

function setNotifySoundEnabled(enabled) {
  state.notifySoundEnabled = Boolean(enabled);
  if (typeof window !== "undefined" && window.localStorage) {
    window.localStorage.setItem(STORAGE_KEY_NOTIFY_SOUND, state.notifySoundEnabled ? "1" : "0");
  }
}

function ensureAudioContext() {
  if (typeof window === "undefined") return null;
  const AudioContextClass = window.AudioContext || window.webkitAudioContext;
  if (!AudioContextClass) return null;
  if (!audioContext) {
    try {
      audioContext = new AudioContextClass();
    } catch {
      return null;
    }
  }
  if (audioContext.state === "suspended" && typeof audioContext.resume === "function") {
    audioContext.resume().catch(() => {});
  }
  return audioContext;
}

function playTone(ctx, { frequency, startTime, duration, gain = 0.07 }) {
  const oscillator = ctx.createOscillator();
  const gainNode = ctx.createGain();
  oscillator.type = "sine";
  oscillator.frequency.setValueAtTime(frequency, startTime);
  gainNode.gain.setValueAtTime(0, startTime);
  gainNode.gain.linearRampToValueAtTime(gain, startTime + 0.015);
  gainNode.gain.exponentialRampToValueAtTime(0.0001, startTime + duration);
  oscillator.connect(gainNode);
  gainNode.connect(ctx.destination);
  oscillator.start(startTime);
  oscillator.stop(startTime + duration + 0.03);
}

function playNotificationSound(severity) {
  if (!state.notifySoundEnabled) return;
  const ctx = ensureAudioContext();
  if (!ctx) return;
  try {
    const now = ctx.currentTime;
    if (severity === "critical" || severity === "high") {
      // Two-tone rising chirp - more urgent, harder to miss.
      playTone(ctx, { frequency: 880, startTime: now, duration: 0.11, gain: 0.09 });
      playTone(ctx, { frequency: 1108, startTime: now + 0.12, duration: 0.14, gain: 0.09 });
    } else {
      // Single soft ping for everything else.
      playTone(ctx, { frequency: 660, startTime: now, duration: 0.15, gain: 0.055 });
    }
  } catch {
    // Best-effort only - autoplay restrictions or a missing AudioContext
    // must never break the notification itself.
  }
}

function pushNotification({
  kind = "info",
  severity = "info",
  title = "",
  message = "",
  groupKey = "",
  href = "",
} = {}) {
  const cleanTitle = String(title || "").trim();
  if (!cleanTitle) return null;
  const normalizedSeverity = String(severity || "info").trim().toLowerCase();
  const normalizedHref = String(href || "").trim();
  const now = Date.now();
  // Every notification belongs to a group (defaulting to kind+title); a
  // second hit for the same group never adds a second entry - it bumps the
  // existing one's counter and moves it back to the top instead. This is
  // what keeps a noisy, repeatedly-firing monitor (or a flapping
  // connection) from flooding the list with near-duplicates.
  const key = groupKey || `${kind}:${cleanTitle}`;
  const existingIndex = state.notifications.findIndex((item) => item.groupKey === key);
  if (existingIndex >= 0) {
    const existing = state.notifications[existingIndex];
    existing.count += 1;
    existing.severity = normalizedSeverity;
    existing.title = cleanTitle;
    existing.message = String(message || "").trim();
    existing.href = normalizedHref || existing.href;
    existing.createdAt = now;
    // A repeat occurrence is new information even if the entry itself
    // isn't - bring it back as a popup if the toast had already faded.
    existing.toastDismissed = false;
    if (existingIndex !== 0) {
      state.notifications.splice(existingIndex, 1);
      state.notifications.unshift(existing);
    }
    playNotificationSound(normalizedSeverity);
    return existing;
  }
  const item = {
    id: `notif-${++notificationIdSeq}-${now}`,
    kind: String(kind || "info"),
    severity: normalizedSeverity,
    title: cleanTitle,
    message: String(message || "").trim(),
    href: normalizedHref,
    groupKey: key,
    count: 1,
    createdAt: now,
    toastDismissed: false,
  };
  state.notifications.unshift(item);
  if (state.notifications.length > NOTIFICATION_HISTORY_LIMIT) {
    state.notifications.length = NOTIFICATION_HISTORY_LIMIT;
  }
  playNotificationSound(normalizedSeverity);
  return item;
}

// Hides a notification from the popup toast stack only - it stays in the
// bell/notification-center history. Used by the toast's own auto-dismiss
// timer and its close button, neither of which should erase history the
// user might still want to review.
function dismissToast(id) {
  const item = state.notifications.find((entry) => entry.id === id);
  if (item) {
    item.toastDismissed = true;
  }
}

// Toast stack's own "Clear all" - hides currently-popped-up toasts without
// wiping the bell's history (that's what the bell's own "Clear all" is for).
function dismissAllToasts() {
  state.notifications.forEach((item) => {
    item.toastDismissed = true;
  });
}

// Fully removes a notification from history (bell "x" / "Clear all").
function dismissNotification(id) {
  const index = state.notifications.findIndex((item) => item.id === id);
  if (index >= 0) {
    state.notifications.splice(index, 1);
  }
}

function clearNotifications() {
  state.notifications = [];
}

function parsePacketTags(packet) {
  if (!packet) return [];
  if (Array.isArray(packet.tags)) return packet.tags;
  const raw = packet.tags_json;
  if (typeof raw !== "string" || !raw) return [];
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function extractMonitorHitsFromTags(tags) {
  // sniffhound.sniffer._build_packet_tags emits a "monitor" tag immediately
  // followed by that same hit's "monitor_id" (and "detail") tags, in that
  // fixed order - see sniffhound/sniffer.py. Group consecutive entries back
  // into one hit per monitor instead of relying on a shared index.
  const hits = [];
  let current = null;
  tags.forEach((tag) => {
    if (!tag) return;
    if (tag.key === "monitor") {
      const label = String(tag.value || "").trim();
      if (!label) {
        current = null;
        return;
      }
      current = { label, severity: String(tag.severity || "info").trim().toLowerCase(), monitorId: "" };
      hits.push(current);
    } else if (tag.key === "monitor_id" && current) {
      current.monitorId = String(tag.value || "").trim();
    }
  });
  return hits;
}

function notifyForPacketEvent(payload) {
  const packet = payload && payload.packet;
  const tags = parsePacketTags(packet);
  if (!tags.length) return;
  const hits = extractMonitorHitsFromTags(tags).filter((hit) => NOTIFY_MONITOR_SEVERITIES.has(hit.severity));
  if (!hits.length) return;
  const srcIp = String((packet && packet.src_ip) || "").trim();
  const dstIp = String((packet && packet.dst_ip) || "").trim();
  const dstPort = (packet && packet.dst_port) || "";
  const route = srcIp && dstIp ? `${srcIp} → ${dstIp}${dstPort ? `:${dstPort}` : ""}` : "";
  hits.forEach((hit) => {
    // Honeypot hits are tagged with monitor_id="builtin-honeypot-hit" (see
    // honeypot.py) but that id has no real entry in the monitors catalog -
    // honeypot traffic never runs through evaluate_packet/AnomalyEngine, so
    // /monitors?monitor=builtin-honeypot-hit had nothing to scroll to. Send
    // those to the Honeypot view's own "Honeypot hits" table instead.
    const isHoneypotHit = hit.monitorId === "builtin-honeypot-hit";
    pushNotification({
      kind: "monitor",
      severity: hit.severity,
      title: hit.label,
      message: route,
      // Grouped by monitor alone (not monitor+source) - "solo una por
      // monitor maximo": every hit for the same monitor bumps one counter
      // instead of piling up a separate entry per source IP.
      groupKey: `monitor:${hit.monitorId || hit.label}`,
      href: isHoneypotHit ? "/honeypot" : `/monitors?monitor=${encodeURIComponent(hit.monitorId || hit.label)}`,
    });
  });
}

function notifyForRuntimeChange(payload) {
  const runtime = (payload && (payload.runtime || payload)) || {};
  const mode = String(runtime.mode || "").trim().toLowerCase();
  const active = runtime.active && typeof runtime.active === "object" ? runtime.active : {};
  const running = Boolean(active.running);
  const previous = lastRuntimeForNotify;
  lastRuntimeForNotify = { mode, running };
  if (!mode || !previous) return; // skip the very first snapshot after (re)connecting
  if (previous.mode !== mode) {
    pushNotification({
      kind: "runtime",
      severity: "medium",
      title: "Runtime mode changed",
      message: `Switched to ${mode} mode`,
      groupKey: "runtime:mode",
    });
    return;
  }
  if (previous.running !== running) {
    pushNotification({
      kind: "runtime",
      severity: running ? "low" : "medium",
      title: running ? "Capture started" : "Capture stopped",
      message: `${mode} engine is now ${running ? "running" : "stopped"}`,
      groupKey: "runtime:running",
    });
  }
}

function notifyForChatMessage(payload) {
  const message = payload && payload.message;
  const content = message && String(message.content || "").trim();
  if (!content) return;
  const author = String((message && message.author) || "operator").trim() || "operator";
  pushNotification({
    kind: "broadcast",
    severity: "info",
    title: `Note from ${author}`,
    message: content,
    groupKey: `broadcast:${content}`,
  });
}

function notifyForConnectionChange(kind) {
  if (kind === "restored") {
    pushNotification({
      kind: "connection",
      severity: "low",
      title: "Realtime connection restored",
      message: "Live packet/stats stream reconnected.",
      groupKey: "connection:restored",
    });
  } else if (kind === "lost") {
    pushNotification({
      kind: "connection",
      severity: "medium",
      title: "Realtime connection lost",
      message: "Reconnecting to the live packet/stats stream...",
      groupKey: "connection:lost",
    });
  }
}

function evaluateNotificationsForMessage(type, payload) {
  if (type === "packet") {
    notifyForPacketEvent(payload);
  } else if (type === "runtime_mode") {
    notifyForRuntimeChange(payload);
  } else if (type === "chat_message") {
    notifyForChatMessage(payload);
  }
}

function scheduleTableRefresh(payload) {
  wsPendingRefreshPayload = payload;
  if (wsRefreshTimer) return;
  wsRefreshTimer = setTimeout(() => {
    wsRefreshTimer = null;
    const pending = wsPendingRefreshPayload;
    wsPendingRefreshPayload = null;
    const type = String((pending && pending.type) || "").trim().toLowerCase();
    if (
      mapSnapshotSubscribers.size &&
      (type === "packet" || type === "stats_update" || type === "scan_map_update")
    ) {
      requestRealtimeMapSnapshot(300);
    }
    notifyTableRefresh(pending);
  }, WS_REFRESH_THROTTLE_MS);
}

function wsUrl() {
  let base = state.apiBase;
  if (!base && typeof window !== "undefined") {
    base = window.location.origin;
  }
  try {
    const parsed = new URL(base);
    parsed.protocol = parsed.protocol === "https:" ? "wss:" : "ws:";
    parsed.pathname = "/ws/";
    parsed.search = "";
    if (state.authToken) {
      parsed.searchParams.set("security_code", state.authToken);
    }
    return parsed.toString();
  } catch {
    if (typeof window !== "undefined") {
      const protocol = window.location.protocol === "https:" ? "wss" : "ws";
      const suffix = state.authToken
        ? `?security_code=${encodeURIComponent(state.authToken)}`
        : "";
      return `${protocol}://${window.location.host}/ws/${suffix}`;
    }
  }
  const suffix = state.authToken
    ? `?security_code=${encodeURIComponent(state.authToken)}`
    : "";
  return `ws://127.0.0.1:45678/ws/${suffix}`;
}

function scheduleReconnect() {
  if (typeof window === "undefined") return;
  if (state.shutdownPending) {
    state.wsStatus = "offline";
    return;
  }
  if (state.authRequired && state.authStatus !== "authenticated") {
    lockRealtimeForAuth();
    return;
  }
  if (wsReconnectTimer) return;
  clearReconnectTimer();
  state.wsStatus = "offline";
  wsReconnectTimer = setTimeout(() => {
    wsReconnectTimer = null;
    connectRealtime();
  }, WS_RECONNECT_DELAY_MS);
}

function reconnectRealtime() {
  if (typeof window === "undefined") return;
  if (state.shutdownPending) {
    state.wsStatus = "offline";
    return;
  }
  destroyRealtime();
  connectRealtime();
}

function connectRealtime() {
  if (typeof window === "undefined" || typeof window.WebSocket === "undefined") {
    state.wsStatus = "offline";
    return;
  }
  if (state.shutdownPending) {
    state.wsStatus = "offline";
    return;
  }
  if (state.authRequired && state.authStatus !== "authenticated") {
    lockRealtimeForAuth();
    return;
  }
  if (
    wsClient &&
    (wsClient.readyState === window.WebSocket.OPEN ||
      wsClient.readyState === window.WebSocket.CONNECTING)
  ) {
    return;
  }

  let socket = null;
  try {
    socket = new window.WebSocket(wsUrl());
  } catch {
    state.wsStatus = "error";
    scheduleReconnect();
    return;
  }

  wsClient = socket;
  state.wsStatus = "connecting";

  socket.addEventListener("open", () => {
    if (wsClient !== socket) return;
    clearReconnectTimer();
    const isReconnect = hasEverConnectedRealtime;
    state.wsStatus = "online";
    if (!requestRealtimeMapSnapshot(300)) {
      state.wsStatus = "error";
    }
    isRealtimeCurrentlyOnline = true;
    if (isReconnect) {
      notifyForConnectionChange("restored");
    }
    hasEverConnectedRealtime = true;
  });

  socket.addEventListener("message", (event) => {
    if (wsClient !== socket) return;
    const payload = parseJsonSafe(event.data);
    if (!payload || typeof payload !== "object") return;
    const type = String(payload.type || "").trim().toLowerCase();
    if (type === "auth_required") {
      handleUnauthorized(payload.message || "Session expired. Re-enter the security code.");
      try {
        socket.close(WS_AUTH_CLOSE_CODE, "Unauthorized");
      } catch {
        // ignore close failures
      }
      return;
    }
    if (type === "runtime_mode") {
      applyRuntimeSnapshot(payload);
    }
    if (type === "scan_map_snapshot" || type === "scan_map_update") {
      applyRealtimeMapSnapshot(payload.data, {
        type,
        generatedAt: payload.generated_at,
        receivedAt: Date.now(),
      });
    }
    evaluateNotificationsForMessage(type, payload);
    if (!WS_REFRESH_EVENT_TYPES.has(type)) return;
    scheduleTableRefresh({
      type,
      payload,
      receivedAt: Date.now(),
    });
  });

  socket.addEventListener("error", () => {
    if (wsClient !== socket) return;
    state.wsStatus = "error";
  });

  socket.addEventListener("close", (event) => {
    if (wsClient !== socket) return;
    wsClient = null;
    if (event && event.code === WS_AUTH_CLOSE_CODE) {
      handleUnauthorized("Session expired. Re-enter the security code.");
      return;
    }
    if (isRealtimeCurrentlyOnline) {
      notifyForConnectionChange("lost");
    }
    isRealtimeCurrentlyOnline = false;
    state.wsStatus = "offline";
    scheduleReconnect();
  });
}

function initRealtime() {
  if (state.shutdownPending) return;
  connectRealtime();
}

function shutdownApplication() {
  if (state.shutdownPending) {
    return Promise.resolve({ status: "ok", shutdown_pending: true, shutdown_requested: false });
  }
  state.shutdownPending = true;
  clearReconnectTimer();
  destroyRealtime();
  return fetchJsonPromise("/api/app/shutdown", {
    method: "POST",
    body: JSON.stringify({ delay: APP_SHUTDOWN_DELAY_SECONDS }),
  }).catch((error) => {
    state.shutdownPending = false;
    reconnectRealtime();
    throw error;
  });
}

function subscribeTableRefresh(handler) {
  if (typeof handler !== "function") {
    return () => {};
  }
  tableRefreshSubscribers.add(handler);
  return () => {
    tableRefreshSubscribers.delete(handler);
  };
}

function subscribeMapSnapshot(handler) {
  if (typeof handler !== "function") {
    return () => {};
  }
  mapSnapshotSubscribers.add(handler);
  if (state.realtimeMapSnapshot) {
    try {
      handler({
        snapshot: state.realtimeMapSnapshot,
        meta: {
          type: "cached",
          generatedAt: state.realtimeMapGeneratedAt,
        },
      });
    } catch {
      // ignore subscriber-level failures
    }
  }
  return () => {
    mapSnapshotSubscribers.delete(handler);
  };
}

function getRealtimeMapSnapshot() {
  return state.realtimeMapSnapshot;
}

export default {
  state,
  suggestApiBaseFromLocation,
  initApiBase,
  bootstrap,
  initRealtime,
  setApiBase,
  apiUrl,
  fetchJsonPromise,
  fetchJson,
  extractArray,
  initRuntime,
  setRuntimeMode,
  controlRuntimeMode,
  shutdownApplication,
  setSnifferInterface,
  setSnifferInterfaces,
  setWifiMonitor,
  listMonitors,
  saveMonitor,
  deleteMonitor,
  toggleMonitorEnabled,
  getMonitorConfig,
  setMonitorConfig,
  listHoneypotListeners,
  createHoneypotListener,
  toggleHoneypotListenerEnabled,
  listDomains,
  listPaths,
  listIpCatalog,
  listMonitorPackets,
  reconnectRealtime,
  destroyRealtime,
  subscribeTableRefresh,
  subscribeMapSnapshot,
  getRealtimeMapSnapshot,
  requestRealtimeMapSnapshot,
  openAuthPrompt,
  authenticateSessionToken,
  initNotifySound,
  setNotifySoundEnabled,
  dismissNotification,
  dismissToast,
  dismissAllToasts,
  clearNotifications,
};
