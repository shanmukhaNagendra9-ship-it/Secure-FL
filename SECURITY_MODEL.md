# Security Model & Threat Mitigation Architecture — SecureFL

## 1. Zero-Trust Identity & Access Control
- **No Unverified Admin Registration (`[SEC-01]` Mitigated)**: Public registration (`UserRegisterRequest`) permits only `user` or `analyst`. Both `resolve_user_from_token` and `/api/v1/auth/login` strictly require `is_verified == True`, `is_active == True`, and `is_restricted == False` for **all** roles including `admin`.
- **Firebase ID Token + Session Revocation**: `backend/auth.py` verifies Firebase ID tokens with `verify_id_token(token, check_revoked=True)` and checks local JWT `jti` claims against `RevokedToken`. Admins can revoke sessions immediately via `/api/v1/admin/users/{id}/revoke-sessions`.
- **Firestore & Storage Rules**: Enforced independently at the database/storage layer (`firestore.rules`, `storage.rules`), prohibiting client self-elevation, cross-tenant reads/writes, and audit log tampering.

## 2. Multi-Tenant Isolation & Cryptography
- **Fail-Closed Isolation Guards**: `TenantIsolationMiddleware` clears `_tenant_context_var` inside a `finally` block on every request; `@enforce_tenant_isolation` raises HTTP `401` if unset and `403` on cross-tenant mismatch; `DataLeakageInspectionMiddleware` scans JSON responses for foreign `tenant_id` / `tenantId` fields.
- **Salted HKDF-SHA256 + AES-256-GCM**: `TenantKeyVault` derives per-tenant versioned 256-bit DEKs using `HKDF(SHA-256)` with salt and `securefl:tenant-dek:{tenant_id}:v{ver}` context info. Encryption binds `associated_data=tenant_id.encode("utf-8")` so ciphertext cannot be decrypted under another tenant's key or AAD. Raw encryption keys are never stored in SQLite or Firestore.

## 3. Federated Learning, Differential Privacy & Secure Aggregation
- **Transport vs. Aggregation Security**:
  - **Transport**: Flower gRPC supports TLS (`--tls`, server cert + CA cert).
  - **Pairwise Secure Aggregation**: `PairwiseSecureAggregator` uses ephemeral **X25519** ECDH + HKDF pairwise additive masks ($m_{i,j} = -m_{j,i}$) so updates cancel algebraically without sharing static seeds with the server.
- **Byzantine Defense**: 5 tenant nodes (`tenant_a`..`tenant_e`) satisfy Krum's $n > 2f + 2$ bound ($n=5, f=1$), paired with MAD modified Z-score outlier screening (`detect_malicious_clients`) and Coordinate-wise Trimmed Mean.
- **Validated RDP Moments Accountant**: `RDPPrivacyAccountant` computes exact subsampled Gaussian Rényi DP composition across orders $\alpha \in [1.25, 64]$ and converts to $(\varepsilon, \delta)$-DP, bound directly to client L2 clipping (`max_grad_norm`) and `noise_multiplier`.

## 4. Automated Response Safety & Web Security
- **Admin Approval Gate**: High-impact actions (`restrict_account`, `revoke_session`, `block_ip`) enter `pending` status in `response_history` and require explicit admin approval before execution.
- **Browser Hardening**: XSS-safe HTML escaping (`escapeHtml`), no `innerHTML` with raw DB strings, `sessionStorage` token storage, authenticated Blob downloads for CSV/PDF, `fetch` ReadableStream Bearer SSE (no `?token=` query params), CSP headers, strict CORS allowlists, and sliding-window rate limiting.
