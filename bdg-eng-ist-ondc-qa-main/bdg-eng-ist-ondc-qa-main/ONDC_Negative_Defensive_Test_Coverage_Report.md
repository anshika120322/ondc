# ONDC Platform — Negative / Defensive Test Coverage

---

## 1. Overview

This document outlines the negative and defensive test coverage built into the ONDC QA automation suite across three core modules — **Gateway**, **Registry**, and **Admin**. The intent is to demonstrate that beyond standard functional validation, the platform's APIs are rigorously tested against malformed inputs, unauthorized access, protocol violations, injection attacks, and boundary conditions.

| Metric | Value |
|--------|-------|
| Total Negative / Defensive Test Cases | **~460+** |
| Modules Covered | Gateway, Registry, Admin |
| API Endpoints Under Test | 30+ (forward, callback, lookup, subscribe, admin CRUD) |
| Defensive Strategy Categories | 15 (auth, crypto, schema, injection, DoS, state machine, etc.) |

The tests are designed to validate that every externally exposed surface rejects invalid traffic predictably, returns appropriate HTTP status codes, and never leaks internal state or data under adversarial conditions.

---

## 2. Gateway Module

### Scope

The following Beckn protocol API endpoints are tested — each covering both the forward path (`/action`) and the asynchronous callback path (`/on_action`):

| Forward Endpoint | Callback Endpoint |
|-----------------|-------------------|
| `/search` | `/on_search` |
| `/select` | `/on_select` |
| `/init` | `/on_init` |
| `/confirm` | `/on_confirm` |
| `/cancel` | `/on_cancel` |
| `/status` | `/on_status` |
| `/update` | `/on_update` |
| `/track` | `/on_track` |
| `/support` | `/on_support` |
| `/rating` | `/on_rating` |
| `/issue` | `/on_issue` |

**Approximate count: ~290 negative test cases**

### Standardized Negative Pattern (Applied Across All 11 Endpoints)

A consistent set of 20–26 negative test cases is executed against every endpoint. This ensures uniform coverage and prevents any single API from being undertested relative to others.

#### Forward Path (`/action`) Tests

| Test Scenario | What Gets Validated | Defence Category |
|--------------|---------------------|-----------------|
| Missing `Authorization` header | Request without auth is rejected (401) | Authentication |
| Tampered / invalid ONDC signature | Modified signature bytes are caught (401) | Cryptographic verification |
| Missing `context.domain` | Required protocol field enforced (400/NACK) | Schema validation |
| Missing `context.bap_id` | BAP identity required (400/NACK) | Schema validation |
| Missing `context.bpp_id` | BPP identity required (400/NACK) | Schema validation |
| Expired signature (TTL elapsed) | Stale auth is rejected (401) | Temporal auth |
| Invalid `core_version` ("99.abcd") | Unsupported protocol version rejected | Version validation |
| Invalid domain ("INVALID:DOMAIN999") | Unrecognised ONDC domain code rejected | Domain validation |
| Invalid city code format | Malformed city identifier rejected | Input validation |
| Invalid country code ("XYZZY") | Non-ISO country code rejected | Input validation |
| Malformed JSON structure | Valid JSON but wrong ONDC schema shape (400/NACK) | Schema validation |
| Invalid JSON syntax | Unparseable body rejected (400) | Input parsing |
| Empty JSON payload `{}` | No context/message data rejected (400) | Schema validation |
| Wrong HTTP method (GET on POST endpoint) | Method not allowed (404/405) | Method enforcement |
| Wrong Content-Type (text/plain) | Invalid media type rejected (400) | Content-Type check |
| Invalid auth header format (`Bearer token_xyz`) | Non-ONDC signature format rejected (401) | Auth format check |
| Missing `context.transaction_id` | Required field enforced (400/NACK) | Schema validation |
| Missing `context.timestamp` | Required field enforced (400/NACK) | Schema validation |
| Extremely large payload (100+ oversized items) | Size limits enforced | DoS / payload limit |
| Mismatched `context.action` value | Action field doesn't match endpoint (400/NACK) | Action validation |

#### Callback Path (`/on_action`) Tests

| Test Scenario | Defence Category |
|--------------|------------------|
| Missing Authorization header on callback | Authentication |
| Tampered signature on callback | Cryptographic verification |
| Missing `context.bpp_id` (sender) | Routing validation |
| Missing `context.bap_id` (target) | Routing validation |
| Missing `context.domain` on callback | Schema validation |
| Wrong HTTP method on callback | Method enforcement |

### Endpoint-Specific Extended Negatives

Beyond the standardised set, certain endpoints carry additional  negative cases. The `/confirm` and `/on_confirm` paths are tested for:

| Test Scenario | Defence Category |
|--------------|-----------------|
| Missing `message.order.id` | Schema validation |
| Missing `message.order.billing` | Schema validation |
| Missing `message.order.payment` | Schema validation |
| Missing `message.order.fulfillments` | Schema validation |
| Quote price breakup ≠ total | Business logic validation |
| Missing items array | Schema validation |
| Missing provider block | Schema validation |
| Expired timestamp (30 min in past) | Temporal validation |
| `on_confirm` with invalid `order.state` | State validation |
| `on_confirm` missing `order.id` | Schema validation |

### Endpoint Accessibility Checks

A separate test script validates that all configured Gateway endpoints are reachable and not unintentionally firewalled (403 detection), ensuring infrastructure-level access hasn't regressed.

---

## 3. Registry Module

### 3.1 Lookup APIs (V1, V2, V3)

The registry lookup surface is the most publicly exposed interface and receives the deepest negative coverage.

**Approximate count: ~100 negative + ~27 boundary test cases across V1/V2/V3**

#### V1 Lookup — 20 Negative + 7 Boundary Tests

| Category | Representative Tests |
|----------|---------------------|
| Missing / empty fields | Missing `country`, missing `type`, empty payload, null values |
| Type coercion | Country as number, type as array, country as boolean |
| Malformed JSON | Missing brace, invalid syntax, trailing comma |
| Injection defence | SQL injection in field values (`'; DROP TABLE...`), special characters |
| Encoding / boundary | Unicode characters, extremely long strings, extra unknown fields |

#### V2 Lookup — 30 Negative + 10 Boundary Tests

V2 adds authenticated access, which expands the attack surface:

| Category | Representative Tests |
|----------|---------------------|
| Auth failures | Missing auth header, invalid auth format, expired timestamp, forged signature, unknown subscriber |
| Schema / input | Invalid JSON, unknown fields, wrong Content-Type, insufficient filters |
| Format validation | Invalid domain (missing `ONDC:` prefix), invalid city (missing `std:` prefix), invalid subscriber_id format |
| Boundary / DoS | `max_results` = 50000, 1000-char subscriber_id, 100KB oversized payload, negative `max_results` |
| Injection defence | XSS attempts in domain field, SQL injection in values |
| Temporal | Future timestamp filter, invalid timestamp format |

#### V3 Lookup — 30 Negative + 10 Boundary Tests

V3 extends V2 patterns with additional fields: `include` sections, `select_keys`, content-length validation, wrong data types (array instead of string), duplicate city entries.

### 3.2 V3 Subscribe API — 16 Negative Tests

These tests validate the participant self-service registration path, which involves cryptographic signatures, state machine transitions, and entity integrity checks.

| Test Scenario | Defence Category |
|--------------|-----------------|
| Missing Signature header | Authentication |
| Invalid Ed25519 signature | Cryptographic verification |
| Missing Digest header | Integrity check |
| Signature/payload mismatch (tampered digest) | Tamper detection |
| PATCH on non-existent participant | Resource existence |
| Subscribe without prior admin whitelisting | State pre-condition |
| Invalid `location_id` / `uri_id` references | Referential integrity |
| User attempting to add new domain config | Authorization scope |
| Changing immutable field (`np_type` BPP→BAP) | Business rule enforcement |
| POST without required fields | Schema validation |
| Cross-participant update attempt (IDOR) | Authorization / IDOR prevention |
| Update while SUSPENDED | State transition block |
| Multiple invalid field formats in single request | Composite validation |
| PATCH with disallowed `configs` field | Field restriction |
| Invalid transition SUBSCRIBED→WHITELISTED | State machine enforcement |
| Admin adding new domain after subscribe | Post-subscribe domain lock |

### 3.3 Workflow Negative Scenarios (WF-ERR Series)

Twelve end-to-end error-path workflows validate the full request-response cycle for each error category:

| Scenario | HTTP Code | What Gets Validated |
|----------|-----------|---------------------|
| Missing required fields | 400 | `participant_id` and `configs` array absence |
| Invalid formats | 400 | Bad GSTIN, non-HTTPS URL, invalid city code |
| Non-existent resources | 404 | Unknown participant, key, credential |
| Non-existent metadata | 404 | Invalid domain code, unknown enum category |
| Missing Authorization header | 401 | Anonymous access to protected endpoint |
| Tampered signature | 401 | Corrupted Ed25519 signature rejection |
| Unregistered signing key | 401 | PUBLIC_KEY_NOT_FOUND error |
| Expired signing key | 401 | KEY_EXPIRED temporal check |
| Insufficient privileges | 403 | Non-admin role on admin endpoint |
| Duplicate subscriber conflict | 409 | Duplicate creation + PATCH recovery path |
| State-restricted operation | 400 | V3 PATCH on non-SUBSCRIBED participant |
| Incomplete credentials | 400 | Missing PAN when GST is present |

### 3.4 Advanced Registry Negatives

The registry suite also covers adversarial scenarios that go beyond standard input validation:

| Scenario | Defence Category |
|----------|-----------------|
| SQL injection in `participant_id` (`'; DROP TABLE...`) | Injection prevention |
| XSS in contact name (`<script>alert('XSS')</script>`) | XSS prevention |
| Oversized payload (1000 contacts in single request) | DoS defence |
| Self-referencing `parent_location_id` (circular reference) | Circular dependency detection |
| Orphaned entity references (non-existent `location_id`, `uri_id`, `key_id`) | Referential integrity |
| Concurrent Admin PATCH + V3 PATCH on same participant | Concurrency control |
| Transaction rollback on failed creation | Atomicity |
| Null values in optional fields (`credentials: null`, `contacts: null`) | Null handling |

---

## 4. Admin Module

### 4.1 Admin Subscribe API — 33+ Negative Tests

| Category | Representative Tests |
|----------|---------------------|
| JWT authentication | Missing Bearer token (401), invalid JWT (401), expired JWT (401) |
| Schema validation | Missing `participant_id`, missing `action`, missing `configs` array, empty configs `[]` |
| Enum / format validation | Invalid action value, invalid domain (no `ONDC:` prefix), malformed email, invalid URL, bad city code format |
| Encoding / crypto | Invalid base64 in signing key, missing `uk_id`, missing `signing_public_key` |
| Method enforcement | GET on POST endpoint (405), PUT on POST endpoint (405) |
| Boundary | 100KB oversized payload, 200+ char participant name, deprecated V2 field names |
| Duplicate / conflict | Duplicate subscriber_id collision (Buyer vs Seller) |
| Injection | Special characters in data fields |
| State machine | Invalid transition SUBSCRIBED→WHITELISTED |

### 4.2 Admin Portal Auth Service — 10 Negative Tests

| Test Scenario | Defence Category |
|--------------|-----------------|
| Login with wrong password | Credential validation (401) |
| Login with non-existent email | User existence check (401) |
| Login with missing password field | Required field enforcement (400) |
| Login with missing email field | Required field enforcement (400) |
| `/auth/me` without token | Authentication gate (401) |
| `/auth/refresh` with tampered token | Token integrity check (401) |
| `/auth/profile` without token | Authentication enforcement (401) |
| Change password with wrong current password | Current-password verification |
| Reset password with invalid OTP | OTP rejection (400) |
| Reset password with expired OTP | OTP temporal validation (400) |

### 4.3 Admin Portal Service — 4 Negative Tests

| Test Scenario | Defence Category |
|--------------|-----------------|
| `/audit/logs` without Authorization header | Middleware auth enforcement (401) |
| Protected endpoint with `Bearer invalid.jwt.token` | JWT validation (401) |
| Registry proxy endpoint without auth | Proxy auth enforcement (401) |
| GET participants with non-existent ID | Resource not found (404) |

### 4.4 Admin Entity CRUD Negatives

Embedded within the broader admin test suite (A36–A49):

| Test Scenario | Defence Category |
|--------------|-----------------|
| Invalid status transition | State machine enforcement |
| Duplicate participant creation | Conflict detection (409) |
| Missing required fields | Schema validation |
| Invalid field formats | Format enforcement |
| Invalid domain format | Domain validation |
| Unauthorized request (no JWT) | Authentication (401) |
| Config missing required fields | Nested schema validation |
| Top-level `policy_id` rejected | Field restriction (NACK) |
| Error-125 recovery (duplicate subscriber PATCH retry) | Conflict recovery workflow |

---

## 5. Defensive Strategy Matrix

This matrix shows which defensive strategies are tested across each module. The numbers indicate approximate test case counts.

| Defensive Strategy | Gateway | Registry | Admin | Total |
|-------------------|---------|----------|-------|-------|
| **Authentication (missing/invalid auth)** | ~22 | ~12 | ~8 | ~42 |
| **Cryptographic verification (signature tampering)** | ~22 | ~8 | ~8 | ~30 |
| **Schema validation (missing required fields)** | ~55 | ~20 | ~10 | ~85 |
| **Input validation (bad formats/values)** | ~44 | ~25 | ~8 | ~77 |
| **HTTP method enforcement** | ~22 | ~16 | ~4 | ~26 |
| **Content-Type validation** | ~11 | ~3 | ~8 | ~14 |
| **Temporal checks (expired sig/token/key)** | ~11 | ~5 | ~2 | ~18 |
| **JSON parsing (malformed payloads)** | ~22 | ~10 | ~2 | ~34 |
| **DoS / payload size limits** | ~11 | ~5 | ~2 | ~18 |
| **Injection defence (SQL/XSS)** | ~8 | ~8 | ~2 | ~10 |
| **State machine enforcement** | ~8 | ~8 | ~3 | ~11 |
| **Business rule enforcement** | ~10 | ~6 | ~2 | ~18 |
| **Boundary conditions** | ~8 | ~27 | ~3 | ~30 |
| **Authorization scope / IDOR** | ~3 | ~3 | ~2 | ~5 |
| **Referential integrity** | ~3 | ~4 | ~4 | ~4 |
| | | | **Grand Total** | **~460+** |

---

## 6. Key Considerations

- **Callback path coverage mirrors forward path coverage.** Every defensive check applied to a forward endpoint (`/action`) has a corresponding check on the callback (`/on_action`). In production, an attacker could target either direction — the suite accounts for both.

- **Boundary tests serve a dual purpose.** They validate not only that the system handles edge values gracefully, but also that it doesn't degrade under near-limit conditions — a distinction worth noting during security reviews.

- **Negative tests are designed to produce specific error codes.** Each test validates not just rejection (4xx) but the correct error code and message structure. This ensures client applications receive actionable feedback rather than generic failures.

- **Concurrency and atomicity tests guard against race conditions.** Simultaneous Admin PATCH + V3 PATCH on the same participant, and transaction rollback checks, address real-world scenarios where multiple actors operate on shared state.

- **The test suite is config-driven.** YAML-defined test cases allow new negative scenarios to be added without code changes. This lowers the barrier for expanding coverage as the platform evolves.

- **Immutability enforcement is explicitly validated.** Expired policies, terminal participant states, and locked fields (like `np_type`) are all tested to ensure the system honours its own data integrity contracts even under direct API manipulation.

---

*End of document.*
