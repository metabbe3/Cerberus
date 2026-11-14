# ADR-0005: Database-Backed Identity Architecture and SSO Readiness

## Status
Accepted

## Context
Previously, Owl utilized a single shared administrative password (`OWL_PASSWORD`) verified in-memory within the Next.js process. This model lacked per-user audit trails, RBAC distinction between operators and read-only viewers, account lifecycle controls (disable, reset credentials), and centralized lockout enforcement.

As Cerberus scales towards production-grade multi-operator environments and prepares for enterprise SSO (OIDC/SAML/Google Workspace), authentication and session authority must reside in the authoritative policy engine rather than individual frontend instances.

## Decision
We implement a **DB-first, Engine-authoritative identity model**:

1. **System of Record in Engine**:
   - The Cerberus engine manages the `users` and `sessions` tables within its existing SQLite/PostgreSQL persistence layer.
   - User credentials are encrypted using standard **Argon2id** (RFC 9106 interactive profile: 64MB memory, 1 iteration, 4 threads, 32-byte key) with backward-compatible bcrypt verification fallback.
   - Passwords enforce a minimum 12-character policy.
   - Initial bootstrap seeds the `admin` account via `CERBERUS_ADMIN_BOOTSTRAP_PASSWORD` or `OWL_PASSWORD` (or generates a secure one-time secret logged at startup).

2. **Centralized Authentication & Lockout Gate**:
   - All authentication requests terminate at engine endpoints: `POST /v1/auth/login`, `POST /v1/auth/logout`, `GET /v1/auth/me`.
   - Brute-force protection is enforced centrally at the engine (sliding window: 5 failed attempts per username+IP within 15 minutes triggers a 15-minute lockout).
   - Every login success, failure, lockout, user creation, disablement, and password reset emits an immutable audit event (`auth.login`, `auth.login_failed`, `auth.user_created`, `auth.user_disabled`, `auth.password_reset`).

3. **Engine-Enforced Role-Based Access Control (RBAC)**:
   - Two foundational roles are established: `admin` and `viewer`.
   - The engine strictly enforces authorization on mutating endpoints: requests from `viewer` sessions attempting state changes (`PUT`, `DELETE`, or mutating `POST` actions such as key rotation, policy rollback, break-glass invocation, data updates, or user administration) receive an HTTP `403 Forbidden` response.
   - `viewer` accounts retain full read-only visibility (dashboards, audit queries, breach analysis, policy inspection, simulation runs).

4. **Stateless Frontend (Owl)**:
   - Owl does not validate credentials locally.
   - Upon successful engine authentication, Owl stores the 256-bit cryptographically random session token in an `httpOnly`, `SameSite=Lax` cookie (`owl_session`) with a 12-hour TTL.
   - Owl proxies all data requests with the session token passed in the `Authorization: Bearer <token>` header.

5. **SSO Readiness (Future-Proofing)**:
   - Because all session generation and verification occur at the engine gateway (`/v1/auth/*`), future SSO integrations (OIDC, OAuth2, SAML) can be introduced entirely as provider modules within the engine.
   - Upon completing an external IdP callback, the engine provisions/maps the user record and issues the same standardized session token.
   - Owl and all other downstream consumers require zero architectural modifications to support future SSO providers.
