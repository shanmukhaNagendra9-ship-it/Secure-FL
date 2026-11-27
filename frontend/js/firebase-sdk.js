/**
 * Modular Firebase Web SDK v10 wrapper (Auth, Firestore real-time listeners, Storage, Password Reset).
 * Loads from Google CDN only when Firebase Web config is active.
 */
let _auth = null;
let _db = null;
let _app = null;
let _sdkAuthMod = null;
let _sdkFsMod = null;

export async function initFirebaseWeb(runtimeCfg) {
  if (!runtimeCfg || !runtimeCfg.enabled || !runtimeCfg.firebaseConfig?.apiKey) {
    return { ready: false };
  }
  try {
    const appMod = await import("https://www.gstatic.com/firebasejs/10.14.1/firebase-app.js");
    _sdkAuthMod = await import("https://www.gstatic.com/firebasejs/10.14.1/firebase-auth.js");
    _sdkFsMod = await import("https://www.gstatic.com/firebasejs/10.14.1/firebase-firestore.js");

    _app = appMod.initializeApp(runtimeCfg.firebaseConfig);
    _auth = _sdkAuthMod.getAuth(_app);
    _db = _sdkFsMod.getFirestore(_app);

    if (runtimeCfg.useEmulator && runtimeCfg.emulatorHosts) {
      _sdkAuthMod.connectAuthEmulator(_auth, `http://${runtimeCfg.emulatorHosts.auth}`, {
        disableWarnings: true,
      });
      const [fsHost, fsPort] = runtimeCfg.emulatorHosts.firestore.split(":");
      _sdkFsMod.connectFirestoreEmulator(_db, fsHost, Number(fsPort));
    }
    return { ready: true };
  } catch (err) {
    console.warn("Firebase Web SDK init skipped:", err);
    return { ready: false };
  }
}

export async function firebaseSignInEmail(email, password) {
  if (!_auth || !_sdkAuthMod) throw new Error("Firebase Web Auth not configured");
  const cred = await _sdkAuthMod.signInWithEmailAndPassword(_auth, email, password);
  return await cred.user.getIdToken();
}

export async function firebaseSendReset(email) {
  if (!_auth || !_sdkAuthMod) return false;
  await _sdkAuthMod.sendPasswordResetEmail(_auth, email);
  return true;
}

export async function firebaseSignOut() {
  if (_auth && _sdkAuthMod) {
    await _sdkAuthMod.signOut(_auth);
  }
}

export function subscribeTenantAlertsFirestore(tenantId, onUpdate) {
  if (!_db || !_sdkFsMod || !tenantId) return null;
  const q = _sdkFsMod.query(
    _sdkFsMod.collection(_db, "tenants", tenantId, "security_alerts"),
    _sdkFsMod.orderBy("timestamp", "desc"),
    _sdkFsMod.limit(20)
  );
  return _sdkFsMod.onSnapshot(q, (snap) => {
    const items = [];
    snap.forEach((doc) => items.push(doc.data()));
    onUpdate(items);
  });
}
