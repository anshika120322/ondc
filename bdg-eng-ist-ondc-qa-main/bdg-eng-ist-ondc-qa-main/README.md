# ONDC QA Test Suite

Automated API, workflow, and cross-language signature testing for the **ONDC Registry** and **Gateway** platforms. This repository contains functional, negative, integration, and performance tests maintained by the QA Engineering team.

---

## Repository Structure

| Folder | Description |
|--------|-------------|
| `func_test_scripts/` | Standalone Python API test scripts for Gateway and Registry endpoints |
| `workflow-suite/` | Primary YAML-driven test orchestrator — admin, V3, combined, and advanced workflow tests |
| `registry-workflow-suite/` | Registry-specific workflow tests with universal test runner |
| `gateway-workflow-suite/` | Gateway workflow tests — security, routing, policy enforcement, domain isolation |
| `test-suite-v2 3/` | Extended test framework with advanced reporting and CI-ready output |
| `ondc-signature-multi-language/` | Cross-language Ed25519 signature verification (Python, Java, Node.js, Go, PHP, Ruby) |
| `resources/` | Test configurations, YAML payloads, environment settings, and cryptographic keys |
| `reports/` | Generated HTML test reports (Gateway, Registry, consolidated summaries) |
| `results/` | Structured test output organized by category (admin, gateway, registry) |

---

## Test Coverage Overview

| Component | Focus Areas |
|-----------|-------------|
| Registry Admin API | Create, update, status transitions, field changes, CRUD operations |
| Registry V3 API | Self-subscribe, multi-domain, Ed25519 signing, edge cases |
| Gateway Endpoints | Functional + negative tests for search, confirm, init, select, cancel, status, track, update, rating, support, issue |
| Gateway Workflows | Security, routing, participant status, policy enforcement, domain isolation, cache propagation |
| Registry Lookup | V1, V2, V3 lookup variations with filters |
| Cross-Language Signatures | Ed25519 + BLAKE2b-512 compatibility across Python, Java, Node.js, Go, PHP, Ruby |
| Integration & Advanced | Multi-step workflows, concurrency, state management |

---

## Tech Stack

| Category | Technology |
|----------|-----------|
| **Language** | Python 3 |
| **HTTP Client** | `requests` |
| **Test Configuration** | YAML-driven test definitions |
| **Cryptography** | Ed25519 signing, BLAKE2b-512 digest (PyNaCl) |
| **Authentication** | JWT (Admin) + ONDC Ed25519 (V3) |
| **Containerization** | Docker + docker-compose (multi-language signature tests) |
| **Report Formats** | HTML (dark-theme), JSON, JUnit XML, Postman Collection v2.1 |

---

## Quick Start

### 1. Setup Environment

```bash
# Create and activate virtual environment
python -m venv venv
source venv/bin/activate        # Linux/macOS
venv\Scripts\activate           # Windows

# Install dependencies
pip install -r requirements.txt
```

### 2. Run Tests

**Workflow Suite** — primary test orchestrator:
```bash
python workflow-suite/run_tests.py run --all                          # All tests
python workflow-suite/run_tests.py run --category admin               # Admin tests only
python workflow-suite/run_tests.py run --category v3 --test-id V01-V05  # V3 range
python workflow-suite/run_tests.py run --all --parallel               # Parallel execution
```

**Gateway Workflow Suite:**
```bash
python gateway-workflow-suite/run_tests.py run --all
```

**Registry Workflow Suite:**
```bash
python registry-workflow-suite/run_tests.py run --category v3 --skip-optional
```

**Standalone API Tests** (scripts):
```bash
python func_test_scripts/gateway/ondc_gw_search_api_tests.py --suite functional
python func_test_scripts/registry/ondc_reg_v3_lookup_api_tests.py
```

**Multi-Language Signature Tests:**
```bash
cd ondc-signature-multi-language
./run-tests.sh            # Linux/macOS
docker-compose up         # Any OS with Docker
```

### 3. View Results

- **HTML Reports:** Generated in `reports/` — open in any browser.
- **Structured Results:** Written to `results/` organized by category.
- **Consolidated Summaries:** Markdown email reports in `reports/` (e.g., `customer_qa_consolidated_email_*.md`).

---

## Test Execution Features

The workflow suites support:

- **Test ID Filtering:** `--test-id V01-V10` (range notation)
- **Optional Test Control:** `--skip-optional`, `--include-optional`, `--only-optional`
- **Tags & Dependencies:** Per-test tagging and dependency tracking
- **Setup / Teardown:** `setup_steps:` and `teardown_steps:` per test
- **Retry & Conditional Execution:** `retry:`, `skip_if:`, `run_if:`, `allow_failure:`
- **Validation:** `is_null`, `type`, `length`, `schema`, `not_empty` checks
- **Dry Run:** `--dry-run` lists tests without executing
- **Fail Fast:** `--fail-fast` stops on first failure
- **Fake Data Generation:** `{{fake:email}}`, `{{fake:uuid}}`, `{{fake:name}}`
- **Environment Variables:** `{{env:VAR}}` and `.env` auto-loading
- **Config Overrides:** `--override key=value`
- **Multi-URL Comparison:** Run against multiple environments and generate diff reports
- **Postman Export:** Generate Postman Collection v2.1 with auth scripts

---

## Report Formats

| Format | Description | Location |
|--------|-------------|----------|
| HTML | Dark-theme reports with per-test pass/fail, request/response payloads, timing | `reports/` |
| JSON | Structured test results for programmatic consumption | `results/` |

---

## Troubleshooting

| Issue | Fix |
|-------|-----|
| Ed25519 signing failures | Verify keys in `resources/registry/keys/` and check PyNaCl install |
| SSL verification errors | Check `verify_ssl` setting in the suite's YAML config |
