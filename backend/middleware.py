"""
Security middleware for SecureFL API Gateway:
- TenantIsolationMiddleware (with guaranteed ContextVar cleanup in finally)
- DataLeakageInspectionMiddleware (scans JSON API responses for foreign tenant IDs)
- SlidingWindowRateLimitMiddleware (protects auth & simulation endpoints)
- SecurityHeadersMiddleware & PrometheusMetricsMiddleware
"""
from __future__ import annotations

import json
import logging
import time
from collections import defaultdict, deque
from typing import Deque, Dict

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from .auth import decode_bearer_claims_sync
from .config import get_settings
from .isolation import clear_tenant_context, data_leakage_detector, set_tenant_context
from .metrics import (
    CROSS_TENANT_DENIED_TOTAL,
    HTTP_REQUEST_DURATION,
    HTTP_REQUESTS_TOTAL,
)

logger = logging.getLogger("SecureFL.Middleware")


class TenantIsolationMiddleware(BaseHTTPMiddleware):
    """Binds tenant & admin ContextVar for the duration of the request and resets in finally."""

    async def dispatch(self, request: Request, call_next):
        tokens = None
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()
            claims = decode_bearer_claims_sync(token)
            if claims and claims.get("tenant_id"):
                tokens = set_tenant_context(
                    str(claims["tenant_id"]),
                    is_admin=(claims.get("role") == "admin"),
                )
        try:
            response = await call_next(request)
            return response
        finally:
            if tokens is not None:
                clear_tenant_context(tokens)


class DataLeakageInspectionMiddleware(BaseHTTPMiddleware):
    """Inspects JSON responses for non-admin requests and blocks foreign-tenant leakage."""

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        if not request.url.path.startswith("/api/v1/"):
            return response
        if request.url.path.startswith("/api/v1/auth/public-tenants"):
            return response

        content_type = response.headers.get("content-type", "")
        if "application/json" not in content_type or response.status_code >= 400:
            return response

        body_bytes = b""
        async for chunk in response.body_iterator:
            body_bytes += chunk

        try:
            parsed = json.loads(body_bytes.decode("utf-8"))
            if data_leakage_detector.inspect(parsed, raise_on_leakage=False):
                CROSS_TENANT_DENIED_TOTAL.labels(source="data_leakage_detector").inc()
                return JSONResponse(
                    status_code=403,
                    content={"detail": "Blocked by DataLeakageDetector: cross-tenant payload mismatch."},
                )
        except Exception:
            pass

        headers = dict(response.headers)
        headers.pop("content-length", None)
        return Response(
            content=body_bytes,
            status_code=response.status_code,
            headers=headers,
            media_type=response.media_type,
        )


class SlidingWindowRateLimitMiddleware(BaseHTTPMiddleware):
    """In-memory sliding-window rate limiter protecting auth and ML analysis endpoints."""

    def __init__(self, app):
        super().__init__(app)
        self._hits: Dict[str, Deque[float]] = defaultdict(deque)

    async def dispatch(self, request: Request, call_next):
        settings = get_settings()
        path = request.url.path
        if path in ("/health", "/metrics") or not path.startswith("/api/"):
            return await call_next(request)

        client_ip = request.client.host if request.client else "unknown"
        is_auth_route = (
            path.startswith("/api/v1/auth/login")
            or path.startswith("/api/v1/auth/register")
            or path.startswith("/api/v1/auth/password-reset")
        )
        limit = settings.rate_limit_auth_per_min if is_auth_route else settings.rate_limit_api_per_min
        bucket_key = f"{client_ip}:{'auth' if is_auth_route else 'api'}"

        now = time.monotonic()
        window = self._hits[bucket_key]
        while window and now - window[0] > 60.0:
            window.popleft()

        if len(window) >= limit:
            logger.warning("Rate limit exceeded for %s on %s", client_ip, path)
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded. Please retry after 60 seconds."},
                headers={"Retry-After": "60"},
            )

        window.append(now)
        return await call_next(request)


class SecurityAndMetricsMiddleware(BaseHTTPMiddleware):
    """Records Prometheus HTTP latency/counts and applies security response headers."""

    async def dispatch(self, request: Request, call_next):
        start = time.perf_counter()
        response = await call_next(request)
        elapsed = time.perf_counter() - start

        path = request.url.path
        if path != "/metrics":
            HTTP_REQUESTS_TOTAL.labels(
                method=request.method,
                path=path,
                status=str(response.status_code),
            ).inc()
            HTTP_REQUEST_DURATION.labels(method=request.method, path=path).observe(elapsed)

        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        return response
