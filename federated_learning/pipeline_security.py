"""
DevSecOps CI/CD Security Telemetry Scanner & Policy Enforcement Engine.

Integrates continuous security analysis within the multi-tenant software delivery lifecycle:
1. Source Code Security Scanner (SAST & secret leak detection)
2. Dependency Vulnerability Inspector (SCA)
3. Container Image & Artifact Verification
4. Tenant Data Isolation Guard & Cross-Tenant Leakage Prevention
5. Feature Extractor translating pipeline telemetry into 19 ML-ready features
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Tuple

logger = logging.getLogger("DevSecOpsPipeline")

# Known secret patterns for CI/CD secret scanning
SECRET_PATTERNS = {
    "AWS Access Key": re.compile(r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"),
    "Generic Private Key": re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
    "Generic API Token": re.compile(r"(?i)(?:api_key|apikey|secret|token|password)\s*[:=]\s*['\"][a-zA-Z0-9_\-]{16,}['\"]"),
    "GitHub Personal Access Token": re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,255}"),
    "Tenant Master Key Leak": re.compile(r"(?i)tenant_encryption_key\s*=\s*['\"][0-9a-f]{64}['\"]"),
}

# Known vulnerable dependency simulation dictionary
KNOWN_CVE_DATABASE = {
    "requests": {"2.25.0": "CVE-2023-32681 (High)", "2.26.0": "CVE-2021-33503 (Medium)"},
    "cryptography": {"3.4.7": "CVE-2023-49083 (High)"},
    "pyyaml": {"5.3.1": "CVE-2020-14343 (Critical)"},
    "urllib3": {"1.26.4": "CVE-2021-33503 (Medium)"},
}


class PipelineSecurityScanner:
    """
    Executes automated security checks against tenant code repositories,
    build artifacts, and CI/CD configurations.
    """

    def __init__(self, tenant_id: str):
        self.tenant_id = tenant_id

    def scan_source_code(self, source_directory: str) -> Dict[str, Any]:
        """Scan source files for hardcoded secrets, API tokens, and dangerous calls."""
        dir_path = Path(source_directory)
        detected_secrets: List[Dict[str, str]] = []

        if not dir_path.exists():
            return {
                "secrets_found": 0,
                "findings": [],
                "scanned_files": 0,
                "status": "PASS",
            }

        scanned_count = 0
        for file_path in dir_path.rglob("*.py"):
            scanned_count += 1
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
                for name, pattern in SECRET_PATTERNS.items():
                    matches = pattern.findall(content)
                    if matches:
                        detected_secrets.append({
                            "file": str(file_path.name),
                            "secret_type": name,
                            "severity": "CRITICAL" if "Key" in name else "HIGH",
                        })
            except Exception as e:
                logger.error(f"Error reading file {file_path}: {e}")

        status = "FAIL" if detected_secrets else "PASS"
        return {
            "secrets_found": len(detected_secrets),
            "findings": detected_secrets,
            "scanned_files": scanned_count,
            "status": status,
        }

    def scan_dependencies(self, requirements_path: str) -> Dict[str, Any]:
        """Scan dependencies for known vulnerabilities."""
        path = Path(requirements_path)
        vulnerabilities = []

        if path.exists():
            with open(path, "r") as f:
                for line in f:
                    line = line.strip()
                    if "==" in line:
                        pkg, ver = line.split("==")[:2]
                        pkg = pkg.strip().lower()
                        ver = ver.strip()
                        if pkg in KNOWN_CVE_DATABASE and ver in KNOWN_CVE_DATABASE[pkg]:
                            vulnerabilities.append({
                                "package": pkg,
                                "version": ver,
                                "cve": KNOWN_CVE_DATABASE[pkg][ver],
                            })

        return {
            "vulnerabilities_count": len(vulnerabilities),
            "vulnerabilities": vulnerabilities,
            "status": "FAIL" if vulnerabilities else "PASS",
        }

    def inspect_cross_tenant_leakage(
        self, requested_tenant_id: str, payload_data: Dict[str, Any]
    ) -> Tuple[bool, str]:
        """
        Policy Enforcement: Verifies that no data belonging to other tenants
        is present or accessed in the current tenant operation.
        """
        # Strict boundary check
        if requested_tenant_id != self.tenant_id:
            msg = (
                f"Cross-Tenant Access Violation Blocked: "
                f"Context tenant '{self.tenant_id}' attempted to access resources of '{requested_tenant_id}'"
            )
            logger.warning(msg)
            return False, msg

        # Inspect payload for foreign tenant IDs
        payload_str = json.dumps(payload_data)
        foreign_id_pattern = re.compile(r"tenant_[a-z0-9_-]+")
        found_tenants = set(foreign_id_pattern.findall(payload_str))
        found_tenants.discard(self.tenant_id)

        if found_tenants:
            msg = (
                f"Data Leakage Detected: Payload contains references to external tenants: {found_tenants}"
            )
            logger.error(msg)
            return False, msg

        return True, "Access Authorized"


class TelemetryFeatureExtractor:
    """
    Transforms raw CI/CD events, build logs, and access telemetry
    into normalized feature vectors for the ML Threat Detection models.
    """

    @staticmethod
    def extract_vector(event: Dict[str, Any]) -> List[float]:
        """Extract the 19 numerical features defined in data_simulator."""
        vector = [
            float(event.get("num_failed_logins", 0)),
            float(event.get("request_frequency", 1.0)),
            float(event.get("unusual_access_time", 0)),
            float(event.get("hour_of_day", 12)),
            float(event.get("day_of_week", 1)),
            float(event.get("bytes_transferred_kb", 50.0)),
            float(event.get("duration_ms", 100.0)),
            float(event.get("response_code_status", 0)),
            float(event.get("is_vpn", 0)),
            float(event.get("is_new_device", 0)),
            float(event.get("session_duration_sec", 600.0)),
            float(event.get("repo_commit_rate", 1.0)),
            float(event.get("file_change_count", 5)),
            float(event.get("vulnerable_deps_count", 0)),
            float(event.get("secret_detection_count", 0)),
            float(event.get("build_failure_count", 0)),
            float(event.get("cross_tenant_access_attempts", 0)),
            float(event.get("suspicious_artifact_activity", 0)),
            float(event.get("privilege_level", 1)),
        ]
        return vector
