"""
Prometheus metrics definitions and /metrics exposition helpers for SecureFL API Gateway.
"""
from __future__ import annotations

from prometheus_client import Counter, Gauge, Histogram, generate_latest, CONTENT_TYPE_LATEST

HTTP_REQUESTS_TOTAL = Counter(
    "securefl_http_requests_total",
    "Total HTTP requests processed by the API Gateway",
    ["method", "path", "status"],
)

HTTP_REQUEST_DURATION = Histogram(
    "securefl_http_request_duration_seconds",
    "HTTP request latency in seconds",
    ["method", "path"],
)

THREAT_ALERTS_TOTAL = Counter(
    "threat_alerts_total",
    "Total security threat alerts detected across tenants",
    ["tenant_id", "severity", "threat_type"],
)

CROSS_TENANT_DENIED_TOTAL = Counter(
    "security_cross_tenant_access_denied_total",
    "Total cross-tenant access attempts blocked by isolation guards",
    ["source"],
)

SECURITY_RESPONSES_TOTAL = Counter(
    "security_responses_total",
    "Total security response actions queued or executed",
    ["action_type", "status"],
)

FL_ROUNDS_TOTAL = Gauge(
    "fl_rounds_completed_total",
    "Total federated learning rounds completed",
)

FL_GLOBAL_ACCURACY = Gauge(
    "fl_global_accuracy",
    "Latest global federated learning model accuracy",
)

FL_PRIVACY_EPSILON = Gauge(
    "fl_privacy_epsilon_spent",
    "Cumulative differential privacy epsilon spent",
)

FL_BYZANTINE_FILTERED = Counter(
    "fl_byzantine_filtered_updates_total",
    "Total malicious client gradient updates filtered by Byzantine-robust aggregation",
)

FL_ACTIVE_CLIENTS = Gauge(
    "fl_active_clients",
    "Number of active federated learning tenant clients",
)


def prometheus_payload() -> tuple[bytes, str]:
    return generate_latest(), CONTENT_TYPE_LATEST
