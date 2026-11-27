"""
Tests for ML Benchmark (LSTM vs Random Forest vs XGBoost), Explainable AI, & Admin Approval Response Engine.
"""
from __future__ import annotations

from federated_learning.ml_benchmark import inference_engine, run_comparative_benchmark


def test_comparative_ml_benchmark_and_xai(tmp_path):
    bench = run_comparative_benchmark(
        output_path=str(tmp_path / "bench.json"),
        models_dir=str(tmp_path / "models"),
        lstm_epochs=2,
    )
    names = {m["model_name"] for m in bench["models"]}
    assert "Random Forest" in names
    assert "XGBoost" in names
    assert "LSTM (Federated/PyTorch)" in names
    for m in bench["models"]:
        assert 0.0 <= m["accuracy"] <= 1.0
        assert len(m["confusion_matrix"]) == 5

    for mtype in ("lstm", "random_forest", "xgboost"):
        out = inference_engine.analyze(
            {"num_failed_logins": 30, "request_frequency": 220.0, "response_code_status": 1, "is_new_device": 1},
            model_type=mtype,
        )
        assert len(out["top_features"]) == 5
        assert out["recommended_action"]
        assert out["explanation"]


def test_real_time_analyze_and_response_approval_gate(isolated_app):
    admin_tok = isolated_app.post(
        "/api/v1/auth/login", json={"username": "admin", "password": "admin123"}
    ).json()["access_token"]
    headers = {"Authorization": f"Bearer {admin_tok}"}

    # Analyze suspicious cross-tenant telemetry -> should create threat alert & pending response
    res = isolated_app.post(
        "/api/v1/threats/analyze",
        json={
            "model_type": "lstm",
            "source_ip": "10.99.99.99",
            "features": {
                "cross_tenant_access_attempts": 10,
                "suspicious_artifact_activity": 1,
                "response_code_status": 1,
                "is_new_device": 1,
                "unusual_access_time": 1,
                "hour_of_day": 1,
            },
        },
        headers=headers,
    )
    assert res.status_code == 200
    body = res.json()
    assert len(body["top_features"]) == 5

    if body["alert_id"]:
        exp = isolated_app.get(f"/api/v1/threats/{body['alert_id']}/explain", headers=headers)
        assert exp.status_code == 200
        assert "top_features" in exp.json()

    if body["response_id"]:
        resp_list = isolated_app.get("/api/v1/responses/", headers=headers).json()
        assert any(r["id"] == body["response_id"] for r in resp_list)
        target_rec = next(r for r in resp_list if r["id"] == body["response_id"])
        if target_rec["approval_status"] == "pending":
            dec = isolated_app.post(
                f"/api/v1/responses/{body['response_id']}/decide",
                json={"decision": "approve", "note": "Verified malicious probe"},
                headers=headers,
            )
            assert dec.status_code == 200
            assert dec.json()["approval_status"] == "executed"


def test_brute_force_triggers_pending_restriction_and_approval_blocks_user(isolated_app):
    # 5 failed attempts on beta_user trigger pending restrict_account response (NOT auto-locked)
    for _ in range(5):
        r = isolated_app.post("/api/v1/auth/login", json={"username": "beta_user", "password": "wrong_password"})
        assert r.status_code == 401

    # Before admin approves, beta_user is NOT auto-blocked (prevents false-positive DoS)
    ok_before = isolated_app.post("/api/v1/auth/login", json={"username": "beta_user", "password": "user123"})
    assert ok_before.status_code == 200

    admin_tok = isolated_app.post("/api/v1/auth/login", json={"username": "admin", "password": "admin123"}).json()["access_token"]
    headers = {"Authorization": f"Bearer {admin_tok}"}
    pending = isolated_app.get("/api/v1/responses/?approval_status=pending", headers=headers).json()
    bf_resp = next(r for r in pending if r["target_subject"] == "beta_user")

    dec = isolated_app.post(
        f"/api/v1/responses/{bf_resp['id']}/decide",
        json={"decision": "approve", "note": "Confirmed credential stuffing"},
        headers=headers,
    )
    assert dec.status_code == 200
    assert dec.json()["approval_status"] == "executed"

    # Now beta_user login is restricted (403)
    blocked = isolated_app.post("/api/v1/auth/login", json={"username": "beta_user", "password": "user123"})
    assert blocked.status_code == 403
