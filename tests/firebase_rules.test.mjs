/**
 * Firebase Emulator Security Rules Unit Tests (Firestore & Storage).
 *
 * Requires Node.js + Firebase CLI (`firebase emulators:exec --only firestore,storage "node tests/firebase_rules.test.mjs"`).
 * Install test dependency once: `npm install --no-save @firebase/rules-unit-testing firebase`
 */

import fs from "node:fs";
import assert from "node:assert/strict";
import {
  initializeTestEnvironment,
  assertFails,
  assertSucceeds,
} from "@firebase/rules-unit-testing";

const PROJECT_ID = "securefl-rules-test";

async function run() {
  const testEnv = await initializeTestEnvironment({
    projectId: PROJECT_ID,
    firestore: {
      rules: fs.readFileSync("firestore.rules", "utf8"),
    },
    storage: {
      rules: fs.readFileSync("storage.rules", "utf8"),
    },
  });

  try {
    // Seed baseline tenant documents via rules-disabled admin context
    await testEnv.withSecurityRulesDisabled(async (ctx) => {
      const db = ctx.firestore();
      await db.doc("users/user_a").set({
        uid: "user_a",
        role: "user",
        tenantId: "tenant_a",
        isVerified: true,
        isActive: true,
      });
      await db.doc("users/admin_u").set({
        uid: "admin_u",
        role: "admin",
        tenantId: "tenant_a",
        isVerified: true,
        isActive: true,
      });
      await db.doc("tenants/tenant_a").set({ name: "Alpha", isActive: true });
      await db.doc("tenants/tenant_b").set({ name: "Beta", isActive: true });
      await db.doc("tenants/tenant_a/threat_events/evt1").set({
        tenantId: "tenant_a",
        severity: "high",
      });
      await db.doc("tenants/tenant_b/threat_events/evt2").set({
        tenantId: "tenant_b",
        severity: "critical",
      });
    });

    const tenantACtx = testEnv.authenticatedContext("user_a", {
      role: "user",
      tenant_id: "tenant_a",
      is_verified: true,
      is_active: true,
    });
    const unauthCtx = testEnv.unauthenticatedContext();
    const adminCtx = testEnv.authenticatedContext("admin_u", {
      role: "admin",
      tenant_id: "tenant_a",
      is_verified: true,
      is_active: true,
    });

    // 1. Tenant A can read its own threat event
    await assertSucceeds(tenantACtx.firestore().doc("tenants/tenant_a/threat_events/evt1").get());

    // 2. Tenant A CANNOT read or write Tenant B threat events
    await assertFails(tenantACtx.firestore().doc("tenants/tenant_b/threat_events/evt2").get());
    await assertFails(
      tenantACtx.firestore().doc("tenants/tenant_b/threat_events/evt_evil").set({
        tenantId: "tenant_b",
        severity: "low",
      })
    );

    // 3. Unauthenticated user CANNOT read tenants or threats
    await assertFails(unauthCtx.firestore().doc("tenants/tenant_a/threat_events/evt1").get());

    // 4. Self-registration CANNOT elevate to admin or pre-verify
    const evilCtx = testEnv.authenticatedContext("evil_uid", {});
    await assertFails(
      evilCtx.firestore().doc("users/evil_uid").set({
        uid: "evil_uid",
        role: "admin",
        tenantId: "tenant_a",
        isVerified: true,
        isActive: true,
      })
    );

    // 5. Audit logs cannot be modified by clients (even admins)
    await assertFails(
      adminCtx.firestore().doc("tenants/tenant_a/audit_logs/log1").set({
        tenantId: "tenant_a",
        eventType: "tampered",
      })
    );

    // 6. Storage: Tenant A CANNOT read/write Tenant B encrypted archives
    const payload = new Uint8Array([1, 2, 3, 4]);
    await assertFails(
      tenantACtx.storage().ref("tenants/tenant_b/archives/dump.enc").put(payload, {
        contentType: "application/octet-stream",
      })
    );
    await assertSucceeds(
      tenantACtx.storage().ref("tenants/tenant_a/archives/dump.enc").put(payload, {
        contentType: "application/octet-stream",
      })
    );

    console.log("ALL FIRESTORE & STORAGE SECURITY RULES TESTS PASSED.");
  } finally {
    await testEnv.cleanup();
  }
}

run().catch((err) => {
  console.error(err);
  process.exit(1);
});
