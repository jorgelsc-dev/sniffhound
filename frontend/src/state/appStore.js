import { reactive } from "vue";
import { apiBaseEnv } from "../utils/runtimeEnv";

const AUTH_SESSION_PATH = "/api/auth/session";
const STORAGE_KEY_API = "sniffhound.apiBase";
const STORAGE_KEY_AUTH = "sniffhound.sessionToken";
const WS_RECONNECT_DELAY_MS = 1800;
const WS_REFRESH_THROTTLE_MS = 10000;
const WS_AUTH_CLOSE_CODE = 4401;
const WS_REFRESH_EVENT_TYPES = new Set([
  "welcome",
  "scan_map_snapshot",
  "scan_map_update",
  "packet",
  "stats_update",
  "runtime_mode",
  "chat_message",
]);

const state = reactive({
  apiBase: "",
  wsStatus: "offline",
  runtimeMode: "sniffer",
  runtime: {},
  authReady: false,
  authRequired: false,
  authStatus: "unknown",
  authToken: "",
  authError: "",
  authPromptOpen: false,
});

const tableRefreshSubscribers = new Set();

let wsClient = null;
let wsReconnectTimer = null;
let wsRefreshTimer = null;
let wsPendingRefreshPayload = null;

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
  if (typeof window !== "undefined" && window.localStorage) {
    window.localStorage.setItem(STORAGE_KEY_API, cleaned);
  }
  reconnectRealtime();
}

function readStoredAuthToken() {
  if (typeof window === "undefined" || !window.sessionStorage) {
    return "";
  }
  return String(window.sessionStorage.getItem(STORAGE_KEY_AUTH) || "").trim();
}

function persistAuthToken(token) {
  if (typeof window === "undefined" || !window.sessionStorage) {
    return;
  }
  if (token) {
    window.sessionStorage.setItem(STORAGE_KEY_AUTH, token);
    return;
  }
  window.sessionStorage.removeItem(STORAGE_KEY_AUTH);
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
  const headers = token ? { Authorization: `Bearer ${token}` } : {};
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
      state.authError = String((payload && payload.message) || "Access token required");
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
    const error = new Error("Access token required");
    state.authRequired = true;
    state.authStatus = "required";
    state.authError = error.message;
    state.authPromptOpen = true;
    return Promise.reject(error);
  }
  return requestSessionAuth(token).then((payload) => {
    state.authRequired = Boolean(payload && payload.require_auth);
    if (!payload || !payload.authenticated) {
      handleUnauthorized((payload && payload.message) || "Invalid access token");
      throw new Error((payload && payload.message) || "Invalid access token");
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

function scheduleTableRefresh(payload) {
  wsPendingRefreshPayload = payload;
  if (wsRefreshTimer) return;
  wsRefreshTimer = setTimeout(() => {
    wsRefreshTimer = null;
    const pending = wsPendingRefreshPayload;
    wsPendingRefreshPayload = null;
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
      parsed.searchParams.set("access_token", state.authToken);
    }
    return parsed.toString();
  } catch {
    if (typeof window !== "undefined") {
      const protocol = window.location.protocol === "https:" ? "wss" : "ws";
      const suffix = state.authToken
        ? `?access_token=${encodeURIComponent(state.authToken)}`
        : "";
      return `${protocol}://${window.location.host}/ws/${suffix}`;
    }
  }
  const suffix = state.authToken
    ? `?access_token=${encodeURIComponent(state.authToken)}`
    : "";
  return `ws://127.0.0.1:45678/ws/${suffix}`;
}

function scheduleReconnect() {
  if (typeof window === "undefined") return;
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
  destroyRealtime();
  connectRealtime();
}

function connectRealtime() {
  if (typeof window === "undefined" || typeof window.WebSocket === "undefined") {
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
    state.wsStatus = "online";
    try {
      socket.send(JSON.stringify({ action: "scan_map_snapshot", limit: 300 }));
    } catch {
      state.wsStatus = "error";
    }
  });

  socket.addEventListener("message", (event) => {
    if (wsClient !== socket) return;
    const payload = parseJsonSafe(event.data);
    if (!payload || typeof payload !== "object") return;
    const type = String(payload.type || "").trim().toLowerCase();
    if (type === "auth_required") {
      handleUnauthorized(payload.message || "Session expired. Re-enter access token.");
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
      handleUnauthorized("Session expired. Re-enter access token.");
      return;
    }
    state.wsStatus = "offline";
    scheduleReconnect();
  });
}

function initRealtime() {
  connectRealtime();
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
  setSnifferInterface,
  setSnifferInterfaces,
  reconnectRealtime,
  destroyRealtime,
  subscribeTableRefresh,
  openAuthPrompt,
  authenticateSessionToken,
};
