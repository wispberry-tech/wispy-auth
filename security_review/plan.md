# Security Review Remediation Plan

## TL;DR

- Close the confirmed authentication vulnerabilities first: session-token disclosure, refresh-token revocation gaps, replayable 2FA codes, and broken password checks behind the real middleware.
- Make security-sensitive multi-step operations atomic and enforce forced password changes.
- Harden request parsing, client IP handling, rate limiting, storage lifecycle, and OAuth identity linking.
- Add integration, concurrency, migration, and PostgreSQL tests that prove the security invariants; then establish non-gating performance benchmarks.
- Resolve the open product and compatibility decisions below before implementing changes that affect token semantics, trusted proxies, OAuth linking, or audit retention.

## Purpose and scope

This plan turns the second-pass security and structure review into ordered, verifiable work. The review found that `go test ./...`, race tests, build, and `go vet` pass, but passing tests do not establish the security properties listed here. No originating product spec was available; acceptance criteria below are proposed security invariants based on the existing library behavior and review findings.

This plan covers authentication and session security, HTTP boundary hardening, storage consistency, OAuth identity handling, regression tests, performance baselines, and documentation alignment. It does not authorize implementation by itself. The existing root `plan.md` contains stale and contradictory feature status; keep it separate until its scope is reconciled with this plan.

## Priority definitions

- **P0 — Blocker:** permits credential/session compromise, authentication bypass, or replay of a one-time factor.
- **P1 — High:** breaks security state or allows practical abuse, data loss, or account-integrity failures.
- **P2 — Hardening:** closes resource, operational, compatibility, or maintainability risks and improves detection.

## Phase 0: Confirm behavior and decisions

Before changing externally observable behavior, record decisions for the open questions at the end of this plan. Inspect the current worktree and preserve unrelated local changes. Do not weaken existing behavior or silently change API semantics to make a test pass.

### Exit criteria

- Token lifecycle, proxy trust, account linking, audit retention, and migration support policy are documented.
- Each finding below has an owner/issue or is explicitly deferred with a reason.

## Phase 1: Close confirmed authentication vulnerabilities (P0)

### 1.1 Stop returning bearer session tokens

`GetSessionsHandler` currently serializes session records that include `Session.Token`.

- Return a dedicated public session DTO that excludes raw session and refresh tokens and other internal fields.
- Keep the current session-management behavior while ensuring token values never appear in response bodies, logs, or error messages.
- Add handler tests that seed distinctive sentinel token strings and assert none occur in the response, including for current and other sessions.

**Acceptance:** no session-list response can disclose a usable bearer token; API docs describe the redacted response shape.

### 1.2 Enforce refresh-token revocation and rotation policy

Refresh tokens survive logout and password reset/change, and the refresh path does not validate the linked session. Storage deletion methods have no effective production callers.

- Define the refresh-token lifecycle and whether refresh is one-time/rotating.
- Validate token expiry, revocation, linked session status, and ownership before issuing a replacement session/token.
- Revoke the relevant refresh token on use according to the chosen rotation policy.
- Revoke all refresh tokens on logout of all sessions and on password reset/change; revoke the current session/token on ordinary logout.
- Add storage constraints/foreign keys for refresh-token-to-session relationships where compatible with supported schemas.
- Verify cleanup and failed storage operations do not silently leave tokens usable.

**Acceptance:** revoked, expired, replayed, or session-detached refresh tokens cannot issue a session; logout and credential changes invalidate tokens according to the documented policy; tests cover sequential and concurrent replay.

### 1.3 Make one-time 2FA code consumption atomic

Both storage implementations conditionally update a code but treat zero affected rows as success, allowing concurrent requests to accept the same code.

- Make `Use2FACode` report success only when exactly one unexpired, unused record was consumed.
- Ensure the handler creates a session only after successful atomic consumption.
- Apply the same single-use invariant to backup codes and any other one-time credentials.
- Add concurrent tests against SQLite and PostgreSQL asserting that exactly one consumer succeeds.

**Acceptance:** under concurrent verification of one code, at most one request succeeds and at most one authenticated session is created.

### 1.4 Repair authenticated password checks

`AuthMiddleware` clears `PasswordHash` before adding the user to request context, while password change and 2FA handlers compare a password against that field. Tests that insert a user directly into context do not exercise the actual path.

- Keep password hashes out of request context and public user objects.
- Change sensitive handlers to retrieve the credential verifier through an internal service/storage operation, without reintroducing the hash into context or JSON serialization.
- Add end-to-end handler tests that authenticate through `AuthMiddleware`, then exercise password change and all password-confirmed 2FA operations.

**Acceptance:** real middleware-backed flows succeed for correct credentials, reject incorrect credentials, and never serialize a password hash.

### 1.5 Enforce forced password changes

The reset flow can set `ForcePasswordChange`, but login does not enforce it.

- Define the expected restricted state and allowed operation for forced-change users.
- Prevent normal authenticated use until the password is changed, while allowing the minimum flow needed to complete that change.
- Clear the flag only after a successful password update.
- Test login, middleware authorization, password change, and failed password change for this state.

**Acceptance:** users marked for a forced password change cannot use protected routes with the temporary/reset password and can regain access only after a successful change.

## Phase 2: Make security state changes consistent (P1)

### 2.1 Make password reset/change operations atomic

Current multi-step flows can update the password/security record and then fail while deleting sessions or updating related state; some errors are ignored.

- Define transaction boundaries for password update, security metadata, forced-change state, session revocation, refresh-token revocation, and audit event persistence.
- Use storage transactions or compensating behavior so an operation either reaches its documented final state or returns an error without misleading partial success.
- Stop swallowing session-deletion and revocation errors; distinguish “credential changed but revocation failed” only if the design can safely recover and expose that state.
- Add fault-injection tests for each storage operation in the sequence.

**Acceptance:** no successful password-reset/change response leaves prior credentials or sessions usable contrary to policy; partial failures are observable and recoverable.

### 2.2 Make backup-code regeneration atomic

Regeneration currently deletes existing codes before inserting replacements.

- Replace old backup codes and insert the new set in a transaction.
- Ensure codes are stored only as secure verifiers/hashes if current representation stores reusable plaintext secrets.
- Test rollback on insert failure and concurrent regeneration/consumption behavior.

**Acceptance:** a failed regeneration leaves a usable prior set or a complete new set; it never leaves the account with an unintended empty or mixed set.

### 2.3 Preserve OAuth account identity

OAuth linking overwrites provider identity fields, and the current single-provider representation cannot link multiple providers safely.

- Do not overwrite an existing provider identity during account linking.
- Define whether one user may link multiple providers and whether provider identities are unique globally.
- Prefer a separate provider-identity relation with a unique `(provider, provider_subject)` constraint if multiple identities are supported; otherwise reject conflicting links explicitly.
- Test linking, duplicate identity claims, sign-in lookup, unlinking policy, and concurrent link attempts.

**Acceptance:** linking one provider cannot orphan or redirect another identity; one external identity cannot authenticate as two local users.

### 2.4 Validate OAuth callback behavior and claims

- Verify callback state is single-use, unexpired, and bound to the expected provider and initiating flow.
- Verify provider subject and email claims according to each provider’s documented trust model; do not mark an email verified without evidence.
- Decide whether callbacks return JSON or redirect to the configured `RedirectURL`, then align implementation, OpenAPI, and examples.
- For custom providers, define a usable user-info integration contract rather than accepting arbitrary endpoints that the callback cannot consume.

**Acceptance:** invalid, expired, mismatched, or replayed state is rejected; provider configuration and documented callback behavior agree; account verification follows validated provider claims.

## Phase 3: Harden HTTP and resource boundaries (P1/P2)

### 3.1 Bound and validate request bodies (P1)

- Add configurable or documented maximum request-body sizes to JSON handlers.
- Reject oversized, malformed, trailing, and unexpectedly empty JSON bodies consistently.
- Ensure parsing errors use the documented JSON error shape and do not echo secrets or full request bodies.
- Add tests for oversized payloads and malformed input across representative handlers.

**Acceptance:** each JSON endpoint has a finite body limit and predictable failure behavior.

### 3.2 Define trusted client IP extraction (P1)

Rate limiting trusts forwarded headers directly, allowing callers to spoof client IPs and evade IP-based limits.

- Use the direct peer address by default.
- Only honor forwarded headers when explicitly configured with trusted proxy CIDRs and a documented chain-parsing rule.
- Test spoofed headers, multiple proxy hops, malformed addresses, IPv4/IPv6, and direct connections.

**Acceptance:** an untrusted client cannot choose its rate-limit identity with request headers.

### 3.3 Bound rate-limiter memory and lifecycle (P2)

- Expire inactive client buckets periodically or as part of normal access, not only on service close.
- Bound memory under high-cardinality client keys and define behavior at capacity.
- Make service shutdown idempotent and ensure cleanup goroutines stop without leaks or races.
- Add tests for expiry, capacity behavior, concurrent access, repeated `Close`, and cleanup termination.

**Acceptance:** arbitrary unique client keys cannot grow memory without bound; repeated close is safe and cleanup terminates.

### 3.4 Validate helper inputs (P2)

- Make token/code generation return errors for invalid lengths instead of panicking.
- Add edge tests for zero, negative, and excessive lengths.

**Acceptance:** invalid caller configuration produces a controlled error and no panic.

## Phase 4: Verify database correctness and schema evolution (P1/P2)

### 4.1 Fix storage correctness gaps (P1)

- Check `rows.Err()` after iteration in every query path, including session and backup-code reads.
- Correct the backup-code index to match actual lookup/delete predicates and verify query plans where useful.
- Add a uniqueness constraint for provider identities according to the Phase 2 decision.
- Align nullable database columns with Go types/scanning behavior; test `NULL` values explicitly.
- Ensure audit-event deletion/retention policy is intentional rather than an accidental user-delete cascade.

**Acceptance:** storage errors are propagated; schema constraints enforce identity invariants; nullable data cannot cause unexpected scan failures.

### 4.2 Fix SQLite connection behavior (P1)

- Ensure `PRAGMA foreign_keys=ON` applies to every pooled connection (or constrain the pool appropriately).
- Ensure in-memory SQLite uses one shared database across connections or a single-connection pool.
- Test foreign-key enforcement and data visibility while forcing multiple connections.

**Acceptance:** foreign keys are consistently enforced, and in-memory tests cannot observe per-connection databases.

### 4.3 Add migration guarantees (P1)

- Define supported starting schema versions and the behavior for existing installations.
- Add versioned, ordered, idempotent migration tests for fresh databases and every supported prior schema for SQLite and PostgreSQL.
- Test rollback/failure behavior and preservation of representative user, session, OAuth, security-event, and 2FA data.
- Ensure UUID schema changes do not rely on `CREATE TABLE IF NOT EXISTS` to update existing tables.
- Keep destructive PostgreSQL test setup isolated; never drop a shared `public` schema.

**Acceptance:** documented supported schemas migrate deterministically without data loss; repeat initialization is safe; CI tests both database backends or clearly identifies the unavailable integration environment.

## Phase 5: Build a security-focused test suite (P0-P2)

Add tests alongside each fix rather than deferring all coverage to the end.

- **Authentication path:** middleware-backed password change, 2FA setup/disable, backup-code use, forced password change, and credential rejection.
- **Token lifecycle:** session response redaction, refresh expiry/rotation/replay/revocation, logout, password reset/change, and linked-session invalidation.
- **Concurrency:** one-time 2FA use, backup-code use/regeneration, refresh rotation, OAuth linking, and concurrent password operations. Assertions must fail on invariant violations rather than log them.
- **Failure injection:** storage failures between each step of reset/change, token rotation, and backup-code regeneration.
- **HTTP hardening:** body limits, invalid JSON, forwarded-IP spoofing, and response redaction.
- **OAuth:** state binding/expiry/replay, provider claim verification, identity collisions, and callback contract.
- **Database:** migration compatibility, foreign keys, nullable fields, query iteration errors, and backend parity.
- **Test quality:** replace permissive tests that only log when races produce unexpected counts or events are missing with explicit invariant assertions.

**Acceptance:** each P0/P1 invariant has a regression test that fails against the vulnerable behavior; tests run with `-race`; test failures cannot be converted into logs or skipped assertions.

## Phase 6: Benchmarks and performance baselines (P2)

Benchmarks follow correctness fixes so they measure accepted behavior. No performance target is established yet; initially record baselines rather than making noisy timing tests release gates.

- Add `testing.B` benchmarks for password hashing and verification at configured cost, sign-in success/failure, middleware token validation, refresh rotation, and representative SQLite/PostgreSQL storage operations.
- Report allocations with `b.ReportAllocs()` and document hardware/Go version/database setup for reproducibility.
- Include parallel benchmarks only for concurrency-safe operations and avoid real network dependencies in default benchmark runs.
- Use profiling to investigate regressions; agree thresholds only after collecting stable CI or local baselines.

**Acceptance:** benchmarks are discoverable with `go test -bench`, produce reproducible allocation/time baselines, and do not compromise ordinary unit-test determinism.

## Phase 7: Documentation and API contract cleanup (P2)

- Reconcile root `plan.md` with delivered behavior or mark/archive obsolete sections according to repository policy; it currently repeats completed and pending work inconsistently.
- Update OpenAPI and READMEs for session redaction, refresh lifecycle, password-reset responses, OAuth callback behavior, forced password changes, 2FA, and migration guarantees.
- Document trusted-proxy configuration and default IP behavior.
- Standardize handler error responses and avoid leaking internal storage details.
- Document that audit events may be retained/deleted according to an explicit policy.

**Acceptance:** public documentation describes actual handler responses and supported schema upgrades; no stale plan item contradicts the implementation.

## Verification sequence

Run these after each relevant phase and on the final integrated change:

1. `gofmt` on changed Go files.
2. `go test ./...`.
3. `go test -race ./...`.
4. `go vet ./...` and `go build ./...`.
5. Migration and integration tests against SQLite and PostgreSQL.
6. `go test -bench . -benchmem ./...` for benchmark collection; compare only against an established baseline.
7. Review generated/API documentation and `git diff --check`.

## Open decisions

These affect API behavior or deployment assumptions and should be decided before the corresponding implementation:

1. **Refresh semantics:** Are refresh tokens one-time rotating credentials? Should password changes revoke every session or only sessions other than the current one?
2. **Forced password change:** Should affected users receive a restricted session that can access only password-change endpoints, or should login return a dedicated challenge without a normal session?
3. **Trusted proxies:** Should forwarded IP parsing be configurable by CIDR, or should the library use only the direct peer address and require host applications to provide a trusted client-IP resolver?
4. **OAuth identities:** Should a local user be able to link multiple providers, and what proof is required to link/unlink an identity?
5. **OAuth callback contract:** Should the library redirect to `RedirectURL`, return JSON, or expose a host callback hook?
6. **Audit retention:** Should deleting a user delete audit rows, anonymize them, or preserve them under a configurable retention policy?
7. **Migration compatibility:** Which released schemas must remain upgradeable, and should destructive schema changes fail closed with an explicit migration command?
8. **Benchmarks:** Which Go versions and CI hardware are stable enough to support performance regression thresholds?

## Review evidence and limitations

The audit reported passing `go test ./...`, race/coverage tests, build, vet, and whitespace checks. Reported coverage was 31.3% overall (55.7% in `core`, 6.5% in `core/storage`). No benchmarks or migration tests were found. PostgreSQL integration behavior was not verified against a live PostgreSQL service. These are baseline observations, not proof that all unlisted code paths are correct.
