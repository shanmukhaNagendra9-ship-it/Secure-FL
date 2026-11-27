"""
Comprehensive API, Auth Security ([SEC-01], [SEC-02]), RBAC, & Report Tests.
"""
from __future__ import annotations


def _login(client, username: str, password: str) -> dict:
    r = client.post("/api/v1/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return r.json()


def test_health_info_and_metrics(isolated_app):
    assert isolated_app.get("/health").status_code == 200
    info = isolated_app.get("/api/v1/info").json()
    assert info["version"] == "3.0.0"

    metrics = isolated_app.get("/metrics")
    assert metrics.status_code == 200
    assert "securefl_http_requests_total" in metrics.text

    root_html = isolated_app.get("/")
    assert root_html.status_code == 200
    assert "SecureFL" in root_html.text


def test_sec01_admin_self_registration_blocked(isolated_app):
    res = isolated_app.post(
        "/api/v1/auth/register",
        json={
            "username": "evil_admin",
            "password": "StrongPassword123",
            "email": "evil@attacker.io",
            "role": "admin",
        },
    )
    assert res.status_code == 422


def test_unverified_user_cannot_login_and_admin_verifies(isolated_app):
    tenants = isolated_app.get("/api/v1/auth/public-tenants").json()
    assert len(tenants) >= 5

    reg = isolated_app.post(
        "/api/v1/auth/register",
        json={
            "username": "new_analyst",
            "password": "Password123!",
            "email": "new@alpha.io",
            "full_name": "New Analyst",
            "tenant_id": tenants[0]["id"],
            "role": "analyst",
        },
    )
    assert reg.status_code == 201
    uid = reg.json()["user_id"]

    # Login blocked before approval
    denied = isolated_app.post("/api/v1/auth/login", json={"username": "new_analyst", "password": "Password123!"})
    assert denied.status_code == 403

    admin_tok = _login(isolated_app, "admin", "admin123")["access_token"]
    app_res = isolated_app.post(
        f"/api/v1/admin/users/{uid}/verify",
        json={"action": "approve"},
        headers={"Authorization": f"Bearer {admin_tok}"},
    )
    assert app_res.status_code == 200
    assert _login(isolated_app, "new_analyst", "Password123!")["is_verified"] is True


def test_sec02_sse_requires_auth_and_blocks_tenant_override(isolated_app):
    assert isolated_app.get("/api/v1/threats/realtime").status_code == 401
    assert isolated_app.get("/api/v1/threats/realtime?token=invalid.jwt").status_code == 401

    alpha_tok = _login(isolated_app, "alpha_user", "user123")["access_token"]
    tenants = isolated_app.get("/api/v1/auth/public-tenants").json()
    beta_id = next(t["id"] for t in tenants if "Beta" in t["name"])

    override = isolated_app.get(
        f"/api/v1/threats/realtime?token={alpha_tok}&tenant_id={beta_id}"
    )
    assert override.status_code == 403


def test_cross_tenant_api_isolation_and_admin_alert_ack(isolated_app):
    admin_tok = _login(isolated_app, "admin", "admin123")["access_token"]
    alpha_data = _login(isolated_app, "alpha_user", "user123")
    alpha_tok = alpha_data["access_token"]
    tenants = isolated_app.get("/api/v1/auth/public-tenants").json()
    beta_id = next(t["id"] for t in tenants if "Beta" in t["name"])

    # Alpha user CANNOT access Beta tenant metadata or stats
    assert isolated_app.get(
        f"/api/v1/tenants/{beta_id}", headers={"Authorization": f"Bearer {alpha_tok}"}
    ).status_code == 403
    assert isolated_app.get(
        f"/api/v1/tenants/{beta_id}/stats", headers={"Authorization": f"Bearer {alpha_tok}"}
    ).status_code == 403

    # Admin CAN acknowledge a Beta alert (previously broken 404 bug)
    beta_alerts = isolated_app.get(
        f"/api/v1/threats/?tenant_id={beta_id}",
        headers={"Authorization": f"Bearer {admin_tok}"},
    ).json()["items"]
    assert len(beta_alerts) >= 1
    beta_alert_id = beta_alerts[0]["id"]
    ack_res = isolated_app.post(
        f"/api/v1/threats/{beta_alert_id}/acknowledge",
        headers={"Authorization": f"Bearer {admin_tok}"},
    )
    assert ack_res.status_code == 200
    assert ack_res.json()["status"] == "acknowledged"


def test_invalid_uuid_returns_400_and_token_logout_revokes(isolated_app):
    admin_tok = _login(isolated_app, "admin", "admin123")["access_token"]
    bad_admin = isolated_app.get("/api/v1/tenants/not-a-uuid", headers={"Authorization": f"Bearer {admin_tok}"})
    assert bad_admin.status_code == 400

    alpha_tok = _login(isolated_app, "alpha_user", "user123")["access_token"]
    # Non-admin requesting a foreign/malformed tenant ID fails closed with 403
    bad_user = isolated_app.get("/api/v1/tenants/not-a-uuid", headers={"Authorization": f"Bearer {alpha_tok}"})
    assert bad_user.status_code == 403

    out = isolated_app.post("/api/v1/auth/logout", headers={"Authorization": f"Bearer {alpha_tok}"})
    assert out.status_code == 200

    after = isolated_app.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {alpha_tok}"})
    assert after.status_code == 401


def test_csv_pdf_exports_and_cicd_gates(isolated_app):
    admin_tok = _login(isolated_app, "admin", "admin123")["access_token"]
    headers = {"Authorization": f"Bearer {admin_tok}"}

    csv_res = isolated_app.get("/api/v1/audit/logs/export", headers=headers)
    assert csv_res.status_code == 200
    assert "text/csv" in csv_res.headers["content-type"]

    pdf_res = isolated_app.get("/api/v1/audit/reports/pdf", headers=headers)
    assert pdf_res.status_code == 200
    assert pdf_res.content[:4] == b"%PDF"

    cicd_block = isolated_app.post(
        "/api/v1/cicd/scan",
        json={"repository_name": "pay-api", "commit_sha": "abc123", "secrets_detected": 2, "vulnerabilities_detected": 0},
        headers=headers,
    )
    assert cicd_block.status_code == 200
    assert cicd_block.json()["decision"] == "BLOCK"
