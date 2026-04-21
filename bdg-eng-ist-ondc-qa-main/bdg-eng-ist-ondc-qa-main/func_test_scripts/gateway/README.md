# ONDC Gateway API Test Scripts

Automated test runners for the ONDC Gateway UAT environment. Each script runs a full suite of functional and negative test cases against a specific gateway API endpoint and generates a self-contained HTML report.

---

## Scripts Overview

| Script | Endpoint(s) tested | Test cases | Report prefix |
|---|---|---|---|
| `ondc_gw_search_api_tests.py` | `/search`, `/on_search` | ~63 | `Gateway-search-` |
| `ondc_gw_confirm_api_tests.py` | `/confirm` | ~72 | `Gateway-confirm-` |
| `ondc_gw_search_extended_api_tests.py` | `/search` (extended) | ~24 | _(console only)_ |

### What each script does

1. **Participant registration** — On startup, the script attempts to register the test BAP participant (`participant-1.participant.ondc`) in the UAT Registry via `/admin/subscribe`. If the participant is already registered (or admin credentials are unavailable), the step is silently skipped and tests continue.

2. **Test execution** — Loads test cases from YAML config files, signs each request with an ONDC `Authorization` header (Ed25519 + BLAKE2b-512), sends it to the gateway, and validates the response status, ACK/NACK, and payload.

3. **Report generation** — Writes a dark-theme HTML report to the `reports/` folder with per-test pass/fail status, request/response payloads, response times, and an overall summary.

---

## Prerequisites

### 1. Activate the virtual environment

**Windows (PowerShell):**
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
& .\.venv\Scripts\Activate.ps1
```

**Linux / macOS:**
```bash
source .venv/bin/activate
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

> The `cryptography` package is required for ONDC auth header generation. Without it, headers will be skipped and most tests will fail.

---

## Running the scripts

> **All commands must be run from the repository root**, not from inside `func_test_scripts/gateway/`.

### Search API tests
```bash
# Full suite (functional + negative) — recommended
python func_test_scripts/gateway/ondc_gw_search_api_tests.py

# Functional tests only
python func_test_scripts/gateway/ondc_gw_search_api_tests.py --suite functional

# Negative tests only
python func_test_scripts/gateway/ondc_gw_search_api_tests.py --suite negative

# Custom report path
python func_test_scripts/gateway/ondc_gw_search_api_tests.py --output reports/my_search_report.html

# Increase timeout (default: 10s)
python func_test_scripts/gateway/ondc_gw_search_api_tests.py --timeout 30

# Skip registration step (participant already registered)
python func_test_scripts/gateway/ondc_gw_search_api_tests.py --skip-register
```

### Confirm API tests
```bash
# Full suite
python func_test_scripts/gateway/ondc_gw_confirm_api_tests.py

# Functional tests only
python func_test_scripts/gateway/ondc_gw_confirm_api_tests.py --suite functional

# Negative tests only
python func_test_scripts/gateway/ondc_gw_confirm_api_tests.py --suite negative

# Run a specific test case (e.g. N-TC003)
python func_test_scripts/gateway/ondc_gw_confirm_api_tests.py --filter N-TC003

# Skip registration step
python func_test_scripts/gateway/ondc_gw_confirm_api_tests.py --skip-register
```

### Extended search tests
```bash
python func_test_scripts/gateway/ondc_gw_search_extended_api_tests.py
```
> This script prints results to the console. No HTML report is generated.

---

## CLI flags reference

| Flag | Scripts | Default | Description |
|---|---|---|---|
| `--suite` | search, confirm | `all` | Which suite to run: `all`, `functional`, or `negative` |
| `--output` | search, confirm | auto-generated | Path for the HTML report |
| `--timeout` | search, confirm | `10` | HTTP request timeout in seconds |
| `--func-config` | search, confirm | see below | Path to functional test YAML config |
| `--neg-config` | search, confirm | see below | Path to negative test YAML config |
| `--filter` | confirm | _(none)_ | Run only test cases whose ID starts with this string |
| `--skip-register` | search, confirm | `false` | Skip the BAP participant registration step |

**Default config paths:**

| Script | `--func-config` | `--neg-config` |
|---|---|---|
| search | `resources/gateway/ondc_gateway_search_functional.yml` | `resources/gateway/ondc_gateway_search_negative.yml` |
| confirm | `resources/gateway/ondc_gateway_confirm_functional.yml` | `resources/gateway/ondc_gateway_confirm_negative.yml` |

---

## Configuration files

All test data, credentials, and endpoint URLs live in `resources/gateway/`:

| File | Used by |
|---|---|
| `ondc_gateway_search_functional.yml` | Search functional tests |
| `ondc_gateway_search_negative.yml` | Search negative tests |
| `ondc_gateway_confirm_functional.yml` | Confirm functional tests |
| `ondc_gateway_confirm_negative.yml` | Confirm negative tests |

Key fields in the YAML configs:
- `host` — Gateway base URL (e.g. `https://gateway-uat.kynondc.net`)
- `private_key_seed` — Base64-encoded Ed25519 private key seed for signing
- `participant_id` — Subscriber ID used in ONDC auth header
- `uk_id` — Unique key ID for the signing key pair
- `bap_uri` — Callback URI for the BAP

---

## BAP Participant Registration

Both main scripts automatically attempt to register the test BAP participant at startup before running tests. The registration:

- Posts to `https://registry-uat.kynondc.net/admin/subscribe`
- Uses admin credentials from `resources/registry/admin/ondc_admin_auth.yml`
- Skips gracefully if the participant is already registered or if admin login fails
- **Never blocks test execution** — tests run regardless of registration outcome

To skip registration (e.g. in CI or when the participant is known to be registered):
```bash
python func_test_scripts/gateway/ondc_gw_search_api_tests.py --skip-register
```

---

## Reports

HTML reports are saved to the `reports/` directory with auto-generated filenames:

```
reports/Gateway-search-all-2026-04-16_09-32-24.html
reports/Gateway-confirm-all-2026-04-16_09-32-26.html
```

Reports include:
- Overall pass/fail summary with percentages
- Per-test breakdown: test ID, description, status, response time
- Expandable request/response payload viewer
- Failure reason for each failed test

---

## Environment

All scripts target the **UAT environment** by default:

| Service | URL |
|---|---|
| Gateway | `https://gateway-uat.kynondc.net` |
| Registry | `https://registry-uat.kynondc.net` |
| Admin Auth | `https://admin-auth-uat.kynondc.net` |

> UAT services use self-signed TLS certificates. SSL verification is disabled automatically — this is expected behaviour for the UAT environment.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `cryptography library not found` warning | Missing package | `pip install cryptography` |
| All tests `HTTP None` | SSL cert failure or wrong `PROJECT_ROOT` | Run from repo root; scripts handle SSL internally |
| Registration `401 Invalid credentials` | Admin token expired | Use `--skip-register`; tests will still run |
| `ModuleNotFoundError` | Script run from wrong directory | Always run from the repo root |
| Negative tests failing (gateway returns 200) | Gateway-side validation gap | Expected — document as known issues |
