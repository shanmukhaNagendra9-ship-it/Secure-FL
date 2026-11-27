/**
 * Runtime Firebase Web SDK & API Gateway configuration.
 * Safe to host publicly on Firebase Hosting (contains NO server secrets).
 */
export const DEFAULT_API_BASE =
  window.location.port === "5000" || window.location.hostname.endsWith("web.app") || window.location.hostname.endsWith("firebaseapp.com")
    ? "http://127.0.0.1:8000"
    : window.location.origin.startsWith("http")
      ? window.location.origin
      : "http://127.0.0.1:8000";

export async function loadRuntimeFirebaseConfig(apiBase = DEFAULT_API_BASE) {
  try {
    const res = await fetch(`${apiBase}/api/v1/firebase/client-config`);
    if (res.ok) {
      return await res.json();
    }
  } catch {
    // Fallback cleanly when offline or hosting static bundle only
  }
  return { enabled: false, useEmulator: false, firebaseConfig: {} };
}
