"""
Unit and Integration Tests for DevSecOps CI/CD Security Pipeline and Feature Extractor.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from federated_learning.pipeline_security import (
    PipelineSecurityScanner,
    TelemetryFeatureExtractor,
)


def test_secret_scanner_detects_aws_key():
    scanner = PipelineSecurityScanner(tenant_id="tenant_a")
    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = Path(tmpdir) / "app_config.py"
        test_file.write_text('AWS_SECRET_KEY = "AKIAIOSFODNN7EXAMPLE12"\n', encoding="utf-8")

        result = scanner.scan_source_code(tmpdir)
        assert result["status"] == "FAIL"
        assert result["secrets_found"] >= 1
        assert any("AWS" in finding["secret_type"] for finding in result["findings"])


def test_secret_scanner_passes_clean_code():
    scanner = PipelineSecurityScanner(tenant_id="tenant_a")
    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = Path(tmpdir) / "clean.py"
        test_file.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")

        result = scanner.scan_source_code(tmpdir)
        assert result["status"] == "PASS"
        assert result["secrets_found"] == 0


def test_dependency_scanner_flags_cve():
    scanner = PipelineSecurityScanner(tenant_id="tenant_b")
    with tempfile.NamedTemporaryFile("w+", delete=False, suffix=".txt") as f:
        f.write("requests==2.25.0\n")
        f.write("flask==2.2.0\n")
        f_path = f.name

    try:
        res = scanner.scan_dependencies(f_path)
        assert res["status"] == "FAIL"
        assert res["vulnerabilities_count"] == 1
        assert res["vulnerabilities"][0]["package"] == "requests"
    finally:
        Path(f_path).unlink(missing_ok=True)


def test_cross_tenant_leakage_detector_blocks():
    scanner = PipelineSecurityScanner(tenant_id="tenant_a")

    # Accessing tenant_b while in tenant_a context
    allowed, msg = scanner.inspect_cross_tenant_leakage(
        requested_tenant_id="tenant_b", payload_data={"data": "sample"}
    )
    assert not allowed
    assert "Cross-Tenant Access Violation Blocked" in msg


def test_cross_tenant_payload_leak_detection():
    scanner = PipelineSecurityScanner(tenant_id="tenant_a")

    # In tenant_a context, but payload contains leaked tenant_b records
    payload = {"records": [{"id": 1, "owner": "tenant_b", "secret": "top-secret"}]}
    allowed, msg = scanner.inspect_cross_tenant_leakage(
        requested_tenant_id="tenant_a", payload_data=payload
    )
    assert not allowed
    assert "Data Leakage Detected" in msg


def test_telemetry_feature_extractor_dimension():
    sample_event = {
        "num_failed_logins": 5,
        "request_frequency": 25.5,
        "unusual_access_time": 1,
        "hour_of_day": 3,
        "day_of_week": 2,
        "bytes_transferred_kb": 12000.0,
        "duration_ms": 450.0,
        "response_code_status": 1,
        "is_vpn": 1,
        "is_new_device": 1,
        "session_duration_sec": 3600.0,
        "repo_commit_rate": 4.5,
        "file_change_count": 22,
        "vulnerable_deps_count": 2,
        "secret_detection_count": 1,
        "build_failure_count": 2,
        "cross_tenant_access_attempts": 3,
        "suspicious_artifact_activity": 1,
        "privilege_level": 3,
    }

    vec = TelemetryFeatureExtractor.extract_vector(sample_event)
    assert len(vec) == 19
    assert vec[0] == 5.0
    assert vec[5] == 12000.0
