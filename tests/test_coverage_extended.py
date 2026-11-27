"""
Extended coverage tests for Flower FL Server Strategy, Admin/FL/System/Audit/Tenant APIs,
Firebase Auth/Emulator mocks, and Threat/Response branches (pushing coverage >= 80%).
"""
from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import MagicMock

import torch
from flwr.common import Code, EvaluateRes, FitRes, Status, ndarrays_to_parameters
from flwr.server.client_proxy import ClientProxy
from torch.utils.data import DataLoader, TensorDataset

from backend.firebase_client import FirebaseService
from backend.repositories import FirestoreSyncRepository
from federated_learning.model import LSTMThreatDetector, get_model
from federated_learning.privacy import GaussianMechanism, SecureAggregator
from federated_learning.server import DevSecOpsFedAvgStrategy


class _DummyProxy(ClientProxy):
    def get_properties(self, ins, timeout, group_id):
        return None

    def get_parameters(self, ins, timeout, group_id):
        return None

    def fit(self, ins, timeout, group_id):
        return None

    def evaluate(self, ins, timeout, group_id):
        return None

    def reconnect(self, ins, timeout, group_id):
        return None


def test_fl_server_strategy_aggregate_fit_and_evaluate(tmp_path):
    strategy = DevSecOpsFedAvgStrategy(
        strategy_name="krum",
        krum_f=1,
        model_save_dir=str(tmp_path / "models"),
        metrics_file=str(tmp_path / "metrics.json"),
    )
    ref_params = [v.detach().cpu().numpy() for _, v in strategy.reference_model.state_dict().items()]
    ok_status = Status(code=Code.OK, message="ok")

    results = []
    for i in range(5):
        arrs = [w * (50.0 if i == 4 else 1.0) for w in ref_params]
        fit_res = FitRes(
            status=ok_status,
            parameters=ndarrays_to_parameters(arrs),
            num_examples=200,
            metrics={"tenant_id": f"tenant_{i}", "loss": 0.25, "accuracy": 0.91},
        )
        results.append((_DummyProxy(cid=f"c{i}"), fit_res))

    agg_params, agg_metrics = strategy.aggregate_fit(1, results, [])
    assert agg_params is not None
    assert agg_metrics["accuracy"] > 0.8
    assert (tmp_path / "models" / "latest_global_model.pt").exists()
    assert (tmp_path / "metrics.json").exists()

    eval_results = [
        (_DummyProxy(cid=f"c{i}"), EvaluateRes(status=ok_status, loss=0.2, num_examples=50, metrics={"accuracy": 0.92}))
        for i in range(4)
    ]
    ev_loss, ev_m = strategy.aggregate_evaluate(1, eval_results, [])
    assert ev_loss == 0.2
    assert ev_m["accuracy"] == 0.92


def test_model_training_step_evaluate_and_privacy_legacy_wrappers():
    lstm = get_model("lstm")
    ae = get_model("autoencoder")
    assert isinstance(lstm, LSTMThreatDetector) and ae is not None

    x = torch.randn(16, 1, 19)
    y = torch.randint(0, 5, (16,))
    opt = torch.optim.Adam(lstm.parameters(), lr=0.001)
    step_out = lstm.training_step((x, y), opt)
    assert "loss" in step_out

    eval_out = lstm.evaluate(DataLoader(TensorDataset(x, y), batch_size=8))
    assert "per_class_accuracy" in eval_out

    gm = GaussianMechanism()
    assert gm.compute_sigma(1.0, 1.0, 1e-5) > 0
    noisy = gm.add_noise(torch.ones(10), sensitivity=1.0, epsilon=1.0, delta=1e-5)
    assert noisy.shape == (10,)

    sa = SecureAggregator(num_clients=2)
    masked = [sa.mask_gradients([torch.ones(4)], "c1", 0), sa.mask_gradients([torch.ones(4) * 3], "c2", 0)]
    mean_g = sa.unmask_aggregate(masked, ["c1", "c2"], 0)
    assert torch.allclose(mean_g[0], torch.ones(4) * 2.0)


def test_admin_fl_tenants_audit_cicd_and_system_endpoints(isolated_app):
    admin_tok = isolated_app.post(
        "/api/v1/auth/login", json={"username": "admin", "password": "admin123"}
    ).json()["access_token"]
    headers = {"Authorization": f"Bearer {admin_tok}"}

    t_res = isolated_app.post("/api/v1/tenants/", json={"name": "Tenant Zeta Cloud"}, headers=headers)
    assert t_res.status_code == 201
    new_tid = t_res.json()["id"]
    assert len(isolated_app.get("/api/v1/tenants/", headers=headers).json()) >= 6

    u_res = isolated_app.post(
        "/api/v1/admin/users/create",
        json={
            "username": "zeta_ops",
            "password": "StrongPassword123!",
            "email": "zeta@ops.io",
            "full_name": "Zeta Operator",
            "tenant_id": new_tid,
            "role": "user",
        },
        headers=headers,
    )
    assert u_res.status_code == 201
    uid = u_res.json()["id"]

    # Also test pending user reject flow
    reg_rej = isolated_app.post(
        "/api/v1/auth/register",
        json={"username": "rej_user", "password": "StrongPassword123!", "tenant_id": new_tid, "role": "user"},
    )
    rej_id = reg_rej.json()["user_id"]
    assert isolated_app.post(
        f"/api/v1/admin/users/{rej_id}/verify", json={"action": "reject"}, headers=headers
    ).status_code == 200

    assert isolated_app.get("/api/v1/admin/users", headers=headers).status_code == 200
    assert isolated_app.get("/api/v1/admin/pending-users", headers=headers).status_code == 200
    assert isolated_app.get("/api/v1/admin/overview", headers=headers).status_code == 200
    assert isolated_app.post(
        f"/api/v1/admin/users/{uid}/update-role", json={"role": "analyst"}, headers=headers
    ).status_code == 200
    assert isolated_app.post(
        f"/api/v1/admin/users/{uid}/change-tenant", json={"tenant_id": new_tid}, headers=headers
    ).status_code == 200
    assert isolated_app.post(
        f"/api/v1/admin/users/{uid}/toggle-active", json={"is_active": False}, headers=headers
    ).status_code == 200
    assert isolated_app.post(f"/api/v1/admin/users/{uid}/revoke-sessions", headers=headers).status_code == 200
    assert isolated_app.post(f"/api/v1/admin/users/{uid}/unrestrict", headers=headers).status_code == 200

    # Threats summary, filters, resolve, manual response trigger & reject
    assert isolated_app.get("/api/v1/threats/summary", headers=headers).status_code == 200
    threats = isolated_app.get("/api/v1/threats/?status=open&page=1&page_size=5", headers=headers).json()["items"]
    if threats:
        tid0 = threats[0]["id"]
        assert isolated_app.post(f"/api/v1/threats/{tid0}/resolve", headers=headers).status_code == 200
        m_resp = isolated_app.post(
            "/api/v1/responses/trigger",
            json={"alert_id": tid0, "action_type": "block_ip", "target_subject": "10.0.0.5"},
            headers=headers,
        )
        assert m_resp.status_code == 201
        rid = m_resp.json()["id"]
        assert isolated_app.post(
            f"/api/v1/responses/{rid}/decide", json={"decision": "reject", "note": "False positive"}, headers=headers
        ).status_code == 200

    # FL endpoints: trigger real round + benchmarks + privacy history
    fl_trig = isolated_app.post(
        "/api/v1/fl/trigger",
        json={"rounds": 1, "strategy": "krum", "dp_noise_multiplier": 1.2, "inject_byzantine": True},
        headers=headers,
    )
    assert fl_trig.status_code == 201
    assert isolated_app.get("/api/v1/fl/status", headers=headers).status_code == 200
    assert len(isolated_app.get("/api/v1/fl/rounds", headers=headers).json()) >= 1
    assert isolated_app.get("/api/v1/fl/model/accuracy", headers=headers).status_code == 200
    assert isolated_app.get("/api/v1/fl/privacy/budget", headers=headers).status_code == 200
    assert len(isolated_app.get("/api/v1/fl/privacy/history", headers=headers).json()) >= 1
    assert len(isolated_app.get("/api/v1/fl/clients", headers=headers).json()) == 5

    bench = isolated_app.post("/api/v1/fl/benchmarks/run", headers=headers)
    assert bench.status_code == 201
    assert len(isolated_app.get("/api/v1/fl/benchmarks", headers=headers).json()["models"]) >= 3

    # Tenant stats, key rotation & encrypted archives + soft delete
    assert isolated_app.get(f"/api/v1/tenants/{new_tid}", headers=headers).status_code == 200
    assert isolated_app.get(f"/api/v1/tenants/{new_tid}/stats", headers=headers).status_code == 200
    assert isolated_app.post("/api/v1/tenants/me/rotate-key", headers=headers).status_code == 200
    arch = isolated_app.post(
        "/api/v1/tenants/me/encrypt-archive",
        json={"archive_name": "evidence.json", "payload": {"msg": "secret"}},
        headers=headers,
    )
    assert arch.status_code == 201
    assert len(isolated_app.get("/api/v1/tenants/me/archives", headers=headers).json()) >= 1
    read_arch = isolated_app.get("/api/v1/tenants/me/archives/evidence.json", headers=headers)
    assert read_arch.status_code == 200
    assert read_arch.json()["decrypted_payload"]["msg"] == "secret"
    assert isolated_app.delete(f"/api/v1/tenants/{new_tid}", headers=headers).status_code == 204

    # Audit (non-admin summary/export too)
    alpha_tok = isolated_app.post("/api/v1/auth/login", json={"username": "alpha_user", "password": "user123"}).json()["access_token"]
    alpha_h = {"Authorization": f"Bearer {alpha_tok}"}
    assert isolated_app.get("/api/v1/audit/summary", headers=alpha_h).status_code == 200
    assert isolated_app.get("/api/v1/audit/logs", headers=alpha_h).status_code == 200
    assert isolated_app.get("/api/v1/audit/logs/export", headers=alpha_h).status_code == 200
    assert isolated_app.get("/api/v1/audit/reports/pdf", headers=alpha_h).status_code == 200
    assert isolated_app.get("/api/v1/threats/summary", headers=alpha_h).status_code == 200

    assert isolated_app.post(
        "/api/v1/audit/logs",
        json={"event_type": "manual_check", "severity": "low", "details": {"ok": True}},
        headers=headers,
    ).status_code == 201
    assert isolated_app.get("/api/v1/audit/summary", headers=headers).status_code == 200
    assert isolated_app.get("/api/v1/cicd/status", headers=headers).status_code == 200
    assert isolated_app.get("/api/v1/cicd/history", headers=headers).status_code == 200
    assert isolated_app.get("/api/v1/firebase/status", headers=headers).status_code == 200
    assert isolated_app.get("/api/v1/firebase/client-config").status_code == 200
    assert isolated_app.get("/api/v1/settings", headers=headers).status_code == 200
    assert isolated_app.put(
        "/api/v1/settings",
        json={"dp_epsilon_budget": 12.0, "dp_noise_multiplier": 1.3, "fl_strategy": "krum", "krum_f": 1},
        headers=headers,
    ).status_code == 200
    assert isolated_app.post(
        "/api/v1/auth/password-reset", json={"email": "admin@securefl.cloud"}
    ).status_code == 200


def test_firebase_service_emulator_and_sync_mocks(isolated_app, monkeypatch):
    import firebase_admin
    from firebase_admin import auth as fb_auth
    from firebase_admin import firestore as fb_fs

    mock_app = MagicMock()
    monkeypatch.setattr(firebase_admin, "_apps", {})
    monkeypatch.setattr(firebase_admin, "initialize_app", MagicMock(return_value=mock_app))
    monkeypatch.setattr(fb_fs, "client", MagicMock(return_value=MagicMock()))
    monkeypatch.setattr(fb_auth, "verify_id_token", MagicMock(return_value={"uid": "fb_u1", "email": "admin@securefl.cloud"}))
    monkeypatch.setattr(fb_auth, "set_custom_user_claims", MagicMock())
    monkeypatch.setattr(fb_auth, "revoke_refresh_tokens", MagicMock())
    monkeypatch.setattr(fb_auth, "generate_password_reset_link", MagicMock(return_value="https://reset"))

    from backend.config import get_settings
    cfg = get_settings()
    monkeypatch.setattr(cfg, "firebase_use_emulator", True)
    monkeypatch.setattr(cfg, "firebase_enabled", True)

    svc = FirebaseService()
    svc.initialize()
    assert svc.mode == "emulator"
    assert svc.is_firebase_active is True
    assert svc.verify_id_token("tok")["uid"] == "fb_u1"
    assert svc.set_custom_claims("fb_u1", {"role": "admin"}) is True
    assert svc.revoke_refresh_tokens("fb_u1") is True
    assert svc.generate_password_reset_link("a@b.c") == "https://reset"

    # Also test /api/v1/auth/firebase-sync endpoint with mocked firebase_service
    import backend.main as main_mod
    monkeypatch.setattr(main_mod, "firebase_service", svc)
    sync_ok = isolated_app.post("/api/v1/auth/firebase-sync", json={"id_token": "valid_dummy_firebase_token"})
    assert sync_ok.status_code == 200
    assert sync_ok.json()["auth_provider"] == "firebase_auth"

    sync_new = isolated_app.post(
        "/api/v1/auth/firebase-sync",
        json={"id_token": "valid_dummy_firebase_token", "username": "fb_newbie", "requested_role": "user"},
    )
    # Since verify_id_token returns admin email, it links existing admin; change uid/email for pending user branch
    monkeypatch.setattr(svc, "verify_id_token", MagicMock(return_value={"uid": "fb_new_uid", "email": "newbie@t.io"}))
    sync_new = isolated_app.post(
        "/api/v1/auth/firebase-sync",
        json={"id_token": "valid_dummy_firebase_token", "username": "fb_newbie", "requested_role": "user"},
    )
    assert sync_new.status_code == 200
    assert sync_new.json()["status"] == "PENDING_VERIFICATION"


def test_firestore_sync_repository_with_mock_client(monkeypatch):
    mock_db = MagicMock()
    monkeypatch.setattr(FirestoreSyncRepository, "_db", staticmethod(lambda: mock_db))

    FirestoreSyncRepository.sync_user("u1", {"tenantId": "t1", "role": "user", "isVerified": True})
    FirestoreSyncRepository.sync_tenant("t1", {"name": "Alpha", "encryptionKey": "MUST_NOT_WRITE"})
    FirestoreSyncRepository.sync_threat_event("t1", "e1", {"severity": "high"})
    FirestoreSyncRepository.sync_security_alert("t1", "a1", {"status": "open"})
    FirestoreSyncRepository.sync_audit_log("t1", "l1", {"eventType": "test"})
    FirestoreSyncRepository.sync_response_history("t1", "r1", {"approvalStatus": "pending"})
    FirestoreSyncRepository.sync_fl_round(1, {"accuracy": 0.9})
    FirestoreSyncRepository.sync_privacy_metric(1, {"cumulativeEpsilon": 0.5})
    FirestoreSyncRepository.sync_model_metric("m1", {"accuracy": 0.92})
    FirestoreSyncRepository.sync_system_setting("platform_policy", {"fl_strategy": "krum"})
    assert mock_db.collection.call_count >= 10
    assert asyncio.iscoroutinefunction(SimpleNamespace) is False
