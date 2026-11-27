/**
 * Secure API Client, XSS-Safe DOM Helpers, Authenticated Blob Downloads, & Bearer SSE Stream.
 */
import { DEFAULT_API_BASE } from "./firebase-config.js";

let _authToken = sessionStorage.getItem("securefl_token") || "";

export function getToken() {
  return _authToken;
}

export function setToken(tok) {
  _authToken = tok || "";
  if (_authToken) {
    sessionStorage.setItem("securefl_token", _authToken);
  } else {
    sessionStorage.removeItem("securefl_token");
  }
}

export function escapeHtml(str) {
  return String(str ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

export async function apiFetch(path, options = {}) {
  const headers = { ...(options.headers || {}) };
  if (!(options.body instanceof FormData) && !headers["Content-Type"]) {
    headers["Content-Type"] = "application/json";
  }
  if (_authToken) {
    headers["Authorization"] = `Bearer ${_authToken}`;
  }
  return fetch(`${DEFAULT_API_BASE}${path}`, { ...options, headers });
}

export async function downloadAuthenticatedBlob(path, fallbackFilename) {
  const res = await apiFetch(path, { method: "GET" });
  if (!res.ok) {
    const msg = await res.text();
    throw new Error(msg || `Download failed (${res.status})`);
  }
  const blob = await res.blob();
  const cd = res.headers.get("Content-Disposition") || "";
  const match = cd.match(/filename=([^;]+)/i);
  const filename = match ? match[1].replace(/["']/g, "").trim() : fallbackFilename;

  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/**
 * Connect to SSE using fetch() + Authorization header so tokens never appear in URLs.
 */
export function startBearerSSE(onEvent, onStatus) {
  const controller = new AbortController();
  if (!_authToken) {
    onStatus(false);
    return () => controller.abort();
  }

  (async () => {
    try {
      const res = await fetch(`${DEFAULT_API_BASE}/api/v1/threats/realtime`, {
        headers: { Authorization: `Bearer ${_authToken}` },
        signal: controller.signal,
      });
      if (!res.ok || !res.body) {
        onStatus(false);
        return;
      }
      onStatus(true);
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";

      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const frames = buffer.split("\n\n");
        buffer = frames.pop() || "";
        for (const frame of frames) {
          for (const line of frame.split("\n")) {
            if (line.startsWith("data: ")) {
              try {
                onEvent(JSON.parse(line.slice(6)));
              } catch {
                // Ignore malformed SSE event
              }
            }
          }
        }
      }
    } catch {
      if (!controller.signal.aborted) {
        onStatus(false);
      }
    }
  })();

  return () => controller.abort();
}
