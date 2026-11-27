"""
End-to-End Integration Flow Test against Isolated Temp DB (No Dirty DB Assumptions).
"""
from __future__ import annotations


def test_full_system_flow(isolated_app):
    assert isolated_app.get("/").status_code == 200
    assert isolated_app.get("/dashboard").status_code == 200

    tenants = isolated_app.get("/api/v1/auth/public-tenants").json()
    assert len(tenants) >= 5

    admin_data = isolated_app.post("/api/v1/auth/login", json={"username": "admin", "password": "admin123"}).json()
    admin_tok = admin_data["access_token"]
    assert admin_data["role"] == "admin"

    alpha_data = isolated_app.post("/api/v1/auth/login", json={"username": "alpha_user", "password": "user123"}).json()
    alpha_tok = alpha_data["access_token"]

    t_info = isolated_app.get(
        "/api/v1/tenants/me/current",
        headers={"Authorization": f"Bearer {alpha_tok}"},
    )
    assert t_info.status_code == 200
    assert "key_fingerprint" in t_info.json()
    assert "encryption_key" not in t_info.json()

    # Pending user blocked with 403
    unv = isolated_app.post("/api/v1/auth/login", json={"username": "pending_analyst", "password": "pending123"})
    assert unv.status_code == 403

    # Simulate synthetic threat & verify real stats
    sim = isolated_app.post("/api/v1/threats/simulate", headers={"Authorization": f"Bearer {admin_tok}"})
    assert sim.status_code == 201

    stats = isolated_app.get("/api/v1/stats", headers={"Authorization": f"Bearer {admin_tok}"})
    assert stats.status_code == 200
    assert stats.json()["threats"] >= 1
