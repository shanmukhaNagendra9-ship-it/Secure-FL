/**
 * Cloud Functions v2 triggers for SecureFL Multi-Tenant Cloud Security.
 *
 * Deployment Note:
 * - Runs locally under the Firebase Emulator Suite at zero cost.
 * - Live cloud deployment requires Firebase Blaze billing; when running on the
 *   Spark plan without live Functions, the FastAPI backend response_engine.py
 *   executes the exact same threat escalation and audit trail hooks locally.
 */

const { onDocumentCreated } = require("firebase-functions/v2/firestore");
const { initializeApp } = require("firebase-admin/app");
const { getFirestore, FieldValue } = require("firebase-admin/firestore");
const crypto = require("crypto");

initializeApp();
const db = getFirestore();

/**
 * Automatically escalates critical/high threat_events into security_alerts
 * and queues an admin-approval automated response record.
 */
exports.onThreatEventCreated = onDocumentCreated(
  "tenants/{tenantId}/threat_events/{eventId}",
  async (event) => {
    const snap = event.data;
    if (!snap) return;

    const data = snap.data();
    const { tenantId, eventId } = event.params;
    const confidence = Number(data.confidence || 0);
    const severity = data.severity || (confidence >= 0.9 ? "critical" : confidence >= 0.7 ? "high" : "medium");

    if (severity !== "critical" && severity !== "high") {
      return;
    }

    const alertRef = db.collection("tenants").doc(tenantId).collection("security_alerts").doc();
    const requiresApproval = severity === "critical";

    await alertRef.set({
      id: alertRef.id,
      tenantId,
      threatEventId: eventId,
      threatType: data.threatType || data.threatLabel || "Anomaly Detected",
      severity,
      confidence,
      sourceIp: data.sourceIp || null,
      description: data.explanation || data.description || "ML threat event escalated by Cloud Function",
      status: "open",
      requiresApproval,
      timestamp: FieldValue.serverTimestamp(),
    });

    if (requiresApproval) {
      const respRef = db.collection("tenants").doc(tenantId).collection("response_history").doc();
      await respRef.set({
        id: respRef.id,
        tenantId,
        alertId: alertRef.id,
        actionType: data.recommendedAction || "restrict_account",
        approvalStatus: "pending",
        triggerSource: "cloud_function_v2",
        timestamp: FieldValue.serverTimestamp(),
      });
    }
  }
);

/**
 * Stamps cryptographic SHA-256 integrity hash onto audit records when created.
 */
exports.onSecurityAlertCreated = onDocumentCreated(
  "tenants/{tenantId}/security_alerts/{alertId}",
  async (event) => {
    const snap = event.data;
    if (!snap) return;

    const data = snap.data();
    const { tenantId, alertId } = event.params;
    const payload = JSON.stringify({
      tenantId,
      alertId,
      threatType: data.threatType,
      severity: data.severity,
    });
    const integrityHash = crypto.createHash("sha256").update(payload).digest("hex");

    await db.collection("tenants").doc(tenantId).collection("audit_logs").add({
      tenantId,
      eventType: "security_alert_escalated",
      severity: data.severity || "high",
      sourceIp: data.sourceIp || null,
      details: { alertId, threatType: data.threatType, requiresApproval: !!data.requiresApproval },
      integrityHash,
      timestamp: FieldValue.serverTimestamp(),
    });
  }
);
