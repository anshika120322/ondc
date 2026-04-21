# ONDC Registry Test Suite v2.0 🚀

**Comprehensive End-to-End Test Automation for ONDC Registry**

Complete restructured test suite with **115 tests** across **5 categories**, featuring full **Admin JWT** and **V3 ONDC Ed25519 signature** authentication.

**🆕 New Features:**
- ✅ **Test ID Filtering** - Run specific tests by ID (e.g., `--test-id V01-V10`)
- ✅ **Optional Test Control** - Skip, include, or run only optional tests
- ✅ **Range Notation** - Easily run test ranges (e.g., `V01-V20`)
- ✅ **Multi-URL Comparison** - Run the same tests against multiple environments and generate a visual diff report
- ✅ **Shared-Data Mode** - Use identical generated test data across all environments for true apples-to-apples comparison
- ✅ **Postman Export** - Generate a ready-to-import Postman Collection v2.1 with pre-request auth and test assertion scripts

---

## 📋 Overview

This test suite provides comprehensive coverage for:
- ✅ **Admin API** - 45 tests (JWT authentication)
- ✅ **V3 API** - 25 tests (ONDC signature authentication)
- ✅ **Combined Workflows** - 20 tests (Admin + V3 mixed flows)
- ✅ **Advanced Scenarios** - 15 tests (multi-domain, concurrency, edge cases)
- ✅ **Integration Tests** - 10 tests (authentication, DB state, cross-feature)

**Total: 115 Tests**

---

## 🏗️ Architecture

```
test-suite-v2/
├── config/                          # Test configurations (YAML)
│   ├── test_suite.yaml             # Main orchestration config (+ comparison_targets)
│   ├── admin_tests.yaml            # 45 Admin tests
│   ├── v3_tests.yaml               # 25 V3 tests
│   ├── combined_tests.yaml         # 20 Combined workflows
│   ├── advanced_tests.yaml         # 15 Advanced scenarios
│   └── integration_tests.yaml      # 10 Integration tests
│
├── src/
│   ├── auth/                        # Authentication modules
│   │   ├── admin_auth.py           # Admin JWT authentication
│   │   └── ondc_signature.py       # V3 ONDC Ed25519 signatures
│   │
│   ├── executors/                   # Test runners
│   │   ├── base_runner.py          # Base test runner (abstract)
│   │   ├── admin_runner.py         # Admin test executor
│   │   ├── v3_runner.py            # V3 test executor
│   │   └── combined_runner.py      # Combined workflow executor
│   │
│   └── utils/                       # Utilities
│       ├── http_client.py          # HTTP client (dual auth)
│       ├── data_generator.py       # Test data generation
│       ├── state_manager.py        # State tracking
│       ├── comparison_reporter.py  # 🆕 Multi-URL HTML diff report generator
       └── postman_exporter.py     # 🆕 Postman Collection v2.1 exporter
│
├── output/                          # Test results (auto-generated)
├── run_tests.py                     # Main CLI orchestrator
├── requirements.txt                 # Python dependencies
└── README.md                        # This file
```

---

## 🚀 Quick Start

### **1. Install Dependencies**

```powershell
# Create virtual environment (recommended)
python -m venv venv
.\venv\Scripts\Activate.ps1

# Install requirements
pip install -r requirements.txt
```

### **2. Configure Base URL**

Edit `config/test_suite.yaml`:

```yaml
config:
  base_url: "http://localhost:8080"  # Change if needed
  admin_username: "admin"
  admin_password: "admin123"
```

### **3. Run Tests**

```powershell
# Run all tests (115 tests)
python run_tests.py run --all

# Run specific category
python run_tests.py run --category admin
python run_tests.py run --category v3
python run_tests.py run --category combined

# Run multiple categories
python run_tests.py run -c admin -c v3

# 🆕 Run specific tests by ID
python run_tests.py run --category v3 --test-id V01-V05

# 🆕 Run only required tests (skip optional)
python run_tests.py run --category v3 --skip-optional
```

---

## 📊 Test Categories

### **1. Admin Tests (45 tests)** - `admin_tests.yaml`

**Admin End-to-End Testing with JWT Authentication**

#### Create Operations (5 tests)
- A01: Create WHITELISTED (minimal)
- A02: Create WHITELISTED (all fields)
- A03: Create SUBSCRIBED (direct, minimal)
- A04: Create SUBSCRIBED (all fields)
- A05: Create with multiple domains

#### Status Transitions (14 tests)
All valid transitions from `StatusTransitionMap`:
- A06-A19: WHITELISTED→SUBSCRIBED, SUBSCRIBED→INACTIVE, INACTIVE→WHITELISTED, etc.

#### Field Updates (12 tests)
- A20-A31: Update credentials, contacts, locations, URIs, keys, configs

#### Multi-Step Workflows (8 tests)
- A32-A39: Create→Update→Change status, Suspend→Restore, Multi-domain updates

#### Error & Validation (6 tests)
- A40-A45: Invalid transitions, duplicates, missing fields, unauthorized access

---

### **2. V3 Tests (25 tests)** - `v3_tests.yaml`

**V3 Self-Subscribe Testing with ONDC Ed25519 Signature**

#### Self-Subscribe (4 tests)
- V01: WHITELISTED → SUBSCRIBED (minimal)
- V02: WHITELISTED → SUBSCRIBED (all fields)
- V03: INACTIVE → SUBSCRIBED (self-restore)
- V04: SUBSCRIBED → SUBSCRIBED (idempotent)

#### Field Updates (10 tests)
- V05-V14: Update credentials, contacts, locations, URIs, keys, configs via V3 PATCH

#### Multi-Domain (3 tests)
- V15-V17: Subscribe with multiple domains, update across domains

#### Error & Validation (8 tests)
- V18-V25: Invalid transitions, missing signature, wrong participant, suspended updates

---

### **3. Combined Tests (20 tests)** - `combined_tests.yaml`

**Mixed Admin + V3 Workflow Testing**

#### Admin Creates → V3 Manages (6 tests)
- C01-C06: Admin whitelists, V3 subscribes and updates

#### Admin Manages → V3 Self-Manages (6 tests)
- C07-C12: Admin suspends/restores, V3 self-restores, mixed updates

#### Complete Lifecycle Workflows (8 tests)
- C13-C20: Full cycles, multi-domain flows, concurrent operations, batch updates

---

### **4. Advanced Tests (15 tests)** - `advanced_tests.yaml`

**Advanced Scenarios: Multi-Domain, Concurrency, Edge Cases**

#### Multi-Domain Operations (5 tests)
- D01-D05: 5+ domains, dynamic add/remove, credential rotations, partial subscription

#### Concurrency & Performance (5 tests)
- D06-D10: Concurrent updates, rapid transitions, batch operations (50 participants)

#### Edge Cases & Boundary (5 tests)
- D11-D15: Maximum lengths, minimum fields, special characters, empty arrays, schema compatibility

---

### **5. Integration Tests (10 tests)** - `integration_tests.yaml`

**Integration: Authentication, DB State, Cross-Feature**

#### Authentication Integration (4 tests)
- I01-I04: JWT token lifecycle, V3 signature algorithms, invalid credentials, token refresh

#### Database & State (3 tests)
- I05-I07: Verify DB state, rollback on failure, state consistency across APIs

#### Cross-Feature Integration (3 tests)
- I08-I10: Subscription + Lookup, DNS validation, np_type validation

---

## 🔐 Authentication

### **Admin JWT Authentication**

Automatically handled by `AdminAuth` class:
1. Login to `/admin/login` with username/password
2. Obtain JWT token
3. Auto-refresh before expiry
4. Include in `Authorization: Bearer <token>` header

### **V3 ONDC Ed25519 Signature**

Automatically handled by `ONDCSignature` class:
1. Generate Ed25519 key pair for each participant
2. Create signing string: `(created)\n(expires)\ndigest`
3. Sign with Ed25519 private key
4. Build `Signature` authorization header:
   ```
   Signature keyId="{subscriber_id}|{unique_key_id}|ed25519",
             algorithm="ed25519",
             created=<timestamp>,
             expires=<timestamp>,
             headers="(created) (expires) digest",
             signature="<base64_signature>"
   ```

---

## 📖 CLI Commands

### **Run Tests**

```powershell
# Run all 115 tests
python run_tests.py run --all

# Run specific category
python run_tests.py run --category admin

# Run multiple categories
python run_tests.py run -c admin -c v3 -c combined

# Use custom config
python run_tests.py run --all --config path/to/config.yaml
```

### **🆕 Test Filtering (New!)**

Run specific tests by ID or control optional test execution:

```powershell
# Run specific test by ID
python run_tests.py run --category v3 --test-id V01

# Run multiple specific tests
python run_tests.py run --category v3 --test-id V01 --test-id V02 --test-id V05

# Run range of tests (inclusive)
python run_tests.py run --category v3 --test-id V01-V10

# Combine ranges and individual IDs
python run_tests.py run --category v3 --test-id V01-V05 --test-id V15 --test-id V20

# Skip optional tests (default behavior)
python run_tests.py run --category v3 --skip-optional

# Include optional tests
python run_tests.py run --category v3 --include-optional

# Run ONLY optional tests
python run_tests.py run --category v3 --only-optional

# Combine filters
python run_tests.py run --category v3 --test-id V01-V20 --include-optional
```

**Test ID Filtering Features:**
- ✅ **Single test**: `--test-id V01`
- ✅ **Multiple tests**: `--test-id V01 --test-id V02`
- ✅ **Range notation**: `--test-id V01-V10` (expands to V01, V02, ..., V10)
- ✅ **Combined ranges**: `--test-id V01-V05 --test-id V15-V20`

**Optional Test Control:**
- ✅ `--skip-optional` - Skip optional tests (default)
- ✅ `--include-optional` - Include optional tests
- ✅ `--only-optional` - Run only optional tests

> 📚 **See [FILTERING_GUIDE.md](FILTERING_GUIDE.md) for detailed examples and best practices**

### **List Tests**

```powershell
# List all available test categories
python run_tests.py list-tests

# Display detailed suite information
python run_tests.py info
```

**Note:** To see all available test IDs, check the config files in `config/` directory:
- `config/admin_tests.yaml` - Admin test IDs (A01-A45)
- `config/v3_tests.yaml` - V3 test IDs (V00-V26)
- `config/combined_tests.yaml` - Combined test IDs (C01-C20)
- `config/advanced_tests.yaml` - Advanced test IDs (D01-D15)
- `config/integration_tests.yaml` - Integration test IDs (I01-I10)

### **View Results**

```powershell
# View results in output directory
python run_tests.py results

# View specific output directory
python run_tests.py results --output custom-output
```

### **🆕 Compare Across Environments**

Run the same tests against multiple base URLs and produce a side-by-side HTML diff report.

```powershell
# Use URLs defined in config/test_suite.yaml (comparison_targets)
python run_tests.py compare --category admin --category v3

# Pass URLs directly on the command line (Label=URL format)
python run_tests.py compare -u "Local=http://localhost:8080" -u "Dev=http://34.180.2.104" --all

# Compare all enabled categories (from config URLs)
python run_tests.py compare --all

# Limit to specific test IDs across environments
python run_tests.py compare -u "Staging=http://34.14.152.92" -u "UAT=http://34.93.208.52" -t V01-V10

# Custom report output path
python run_tests.py compare --all --output reports/my_comparison.html

# 🆕 Use identical test data across all environments (same subscriber IDs, same request bodies)
python run_tests.py compare --category admin --shared-data
python run_tests.py compare -u "Local=http://localhost:8080" -u "Dev=http://34.180.2.104" --all --shared-data
```

**Options:**

| Flag | Description |
|------|-------------|
| `-u / --url` | `"Label=http://host"` — add a target URL (repeatable, overrides config) |
| `-c / --category` | Category to compare (repeatable, default: all enabled) |
| `-a / --all` | Compare all enabled categories |
| `-t / --test-id` | Test ID filter, supports ranges (e.g., `V01-V10`) |
| `-o / --output` | Output HTML path (default: `output/comparison_<timestamp>.html`) |
| `--include-optional` | Include optional tests |
| `--only-optional` | Run only optional tests |
| `--shared-data` | Use the same generated test data (subscriber IDs, etc.) across all environments. Useful when envs share a DB or for true request-level comparison |

**Configure default target URLs** in `config/test_suite.yaml`:

```yaml
config:
  comparison_targets:
    - label: "Local"
      url: "http://localhost:8080"
    - label: "Dev"
      url: "http://34.180.2.104"
    - label: "Staging"
      url: "http://34.14.152.92"
```

### **Suite Information**

```powershell
# Display test suite details
python run_tests.py info
```

---

## 📁 Output & Results

Test results are saved to `output/` directory:

```
output/
├── admin_results_20260213_143022.json       # Admin test results (JSON)
├── admin_results_20260213_143022.html       # Admin test results (HTML)
├── v3_results_20260213_143145.json          # V3 test results
├── combined_results_20260213_143308.json    # Combined test results
├── advanced_results_20260213_143425.json    # Advanced test results
├── integration_results_20260213_143540.json # Integration test results
├── test_suite_summary_20260213_143600.json  # Overall summary
├── comparison_20260213_144000.html          # 🆕 Multi-URL comparison report (HTML)
├── comparison_20260213_144000.json          # 🆕 Multi-URL comparison data (JSON)
├── postman_collection_20260213_144500.json  # 🆕 Postman Collection v2.1
└── postman_environment_20260213_144500.json # 🆕 Postman Environment (base_url, credentials)
```

### **Result JSON Format**

```json
{
  "test_suite": "Admin End-to-End Tests",
  "timestamp": "2026-02-13T14:30:22.123456",
  "results": [
    {
      "test_id": "A01",
      "name": "Create WHITELISTED participant (minimal fields)",
      "passed": true,
      "status_code": 200,
      "expected_status": 200,
      "execution_time_ms": 145,
      "validations": [...]
    }
  ],
  "summary": {
    "total": 45,
    "passed": 43,
    "failed": 2
  }
}
```

---

## 🎯 Test Execution Flow

### **Standard Test Flow**

1. **Load Configuration** - Read YAML test config
2. **Setup** - Initialize auth (Admin JWT / V3 signature)
3. **Execute Tests** - Run each test sequentially
4. **Validate** - Check status codes and response fields
5. **Track State** - Update participant state in state manager
6. **Save Results** - Write JSON results to output/
7. **Teardown** - Cleanup resources

### **Workflow Test Flow**

1. **Load Workflow Steps** - Multiple sequential steps
2. **Execute Step 1** - e.g., Admin creates WHITELISTED
3. **Save Context** - Store `subscriber_id` for next steps
4. **Execute Step 2** - e.g., V3 subscribes (using saved ID)
5. **Resolve Variables** - Replace `{{subscriber_id}}` placeholders
6. **Validate Each Step** - Check status and fields
7. **Track State Changes** - Update status after each transition

---

## 🔧 Configuration Guide

### **Main Suite Config** - `config/test_suite.yaml`

```yaml
suite_info:
  name: "ONDC Registry Comprehensive Test Suite"
  version: "2.0.0"
  total_tests: 115

categories:
  - name: "admin"
    config_file: "admin_tests.yaml"
    test_count: 45
    enabled: true

config:
  base_url: "http://localhost:8080"
  admin_username: "admin"
  admin_password: "admin123"
  default_timeout: 30

execution_order:
  - "admin"
  - "v3"
  - "combined"
  - "advanced"
  - "integration"
```

### **Test Config Example** - `config/admin_tests.yaml`

```yaml
test_suite:
  name: "Admin End-to-End Tests"
  category: "admin"
  total_tests: 45

tests:
  - id: "A01"
    name: "Create WHITELISTED participant"
    method: "POST"
    endpoint: "/admin/subscribe"
    auth_type: "admin"
    data:
      action: "WHITELISTED"
      configs:
        - domain: "ONDC:RET10"
          np_type: "SELLER"
    expected_status: 200
    validate:
      - field: "status"
        value: "WHITELISTED"
```

---

## 🐛 Troubleshooting

### **Common Issues**

#### 1. Admin Login Failed
```
✗ Admin login failed
```
**Solution**: Check admin credentials in `config/test_suite.yaml`

#### 2. V3 Signature Error
```
✗ V3 signature authentication failed (401)
```
**Solution**: Ensure cryptography package installed: `pip install cryptography==41.0.7`

#### 3. Connection Refused
```
✗ Error: Connection refused to http://localhost:8080
```
**Solution**: Start the ONDC Registry server first

#### 4. Import Errors
```
ModuleNotFoundError: No module named 'yaml'
```
**Solution**: Install dependencies: `pip install -r requirements.txt`

---

## 📈 Performance Thresholds

Defined in `config/test_suite.yaml`:

```yaml
performance:
  max_response_time_ms: 2000      # Single request
  max_workflow_time_ms: 30000     # Multi-step workflow
  max_batch_time_ms: 60000        # Batch operations
```

---

## 🔄 Extending the Suite

### **Add New Test**

Edit appropriate config file (e.g., `config/admin_tests.yaml`):

```yaml
tests:
  - id: "A46"
    name: "My New Test"
    optional: false          # Mark as required (default) or optional: true
    method: "POST"
    endpoint: "/admin/subscribe"
    auth_type: "admin"
    data:
      action: "WHITELISTED"
      configs:
        - domain: "ONDC:RET10"
          np_type: "SELLER"
    expected_status: 200
```

**Optional Test Field:**
- `optional: false` - Required test (runs by default) 
- `optional: true` - Optional test (skipped unless `--include-optional` or `--only-optional`)
- Omitted - Treated as required

### **Add New Category**

1. Create config file: `config/my_category_tests.yaml`
2. Update `config/test_suite.yaml`:
   ```yaml
   categories:
     - name: "my_category"
       config_file: "my_category_tests.yaml"
       test_count: 10
       enabled: true
   ```
3. Add to execution order if needed

---

## 📝 Test Status Transitions

Valid transitions (from `internal/service/subscription/types.go`):

```
WHITELISTED  → SUBSCRIBED, INACTIVE, SUSPENDED
SUBSCRIBED   → INACTIVE, UNSUBSCRIBED, SUSPENDED
INACTIVE     → SUBSCRIBED, WHITELISTED, UNSUBSCRIBED
SUSPENDED    → SUBSCRIBED, INACTIVE, UNSUBSCRIBED
UNSUBSCRIBED → WHITELISTED, SUBSCRIBED
```

**V3 Specific Rules**:
- V3 can only: `WHITELISTED → SUBSCRIBED` or `INACTIVE → SUBSCRIBED`
- Admin can perform all transitions

---

## 🎓 Example Usage

### **Run Admin Tests Only**

```powershell
python run_tests.py run --category admin
```

Expected output:
```
======================================================================
Running Admin End-to-End Tests
Total tests: 45
======================================================================

[A01] Create WHITELISTED participant (minimal fields)
  ✓ PASSED (145ms)

[A02] Create WHITELISTED participant (all fields)
  ✓ PASSED (187ms)

...

======================================================================
SUMMARY: 43/45 passed (95.6%)
======================================================================
```

### **🆕 Run Specific Tests by ID**

```powershell
# Run only tests V01 and V02
python run_tests.py run --category v3 --test-id V01 --test-id V02
```

Expected output:
```
[FILTER] Running tests: V01, V02
[FILTER] Skipping optional tests

Running V3 End-to-End Tests
Total tests: 2

[V01] V3: WHITELISTED → SUBSCRIBED (minimal fields)
  ✓ PASSED (212ms)

[V02] V3: WHITELISTED → SUBSCRIBED (all fields)
  ✓ PASSED (58ms)

SUMMARY: 2/2 passed (100.0%)
```

### **🆕 Run Test Range**

```powershell
# Run tests V00 through V10
python run_tests.py run --category v3 --test-id V00-V10
```

Expected output:
```
[FILTER] Running tests: V00-V10
Total tests: 11

[V00] V3: SUBSCRIBED Without Whitelisting
  ✓ PASSED (103ms)
[V01] V3: WHITELISTED → SUBSCRIBED (minimal fields)
  ✓ PASSED (85ms)
...
SUMMARY: 11/11 passed (100.0%)
```

### **🆕 Run Only Optional Tests**

```powershell
python run_tests.py run --category v3 --only-optional
```

Expected output:
```
[FILTER] Running ONLY optional tests
Total tests: 2

[V15] V3: Subscribe with multiple domains
  ✓ PASSED (148ms)
[V19] Error: Missing ONDC signature
  ✓ PASSED (27ms)

SUMMARY: 2/2 passed (100.0%)
```

### **Run Full Suite**

```powershell
python run_tests.py run --all
```

Expected execution time: **~5-10 minutes** for all 115 tests.

---

## 📊 Test Coverage Matrix

| **Category** | **Tests** | **Focus Area** | **Auth Type** |
|--------------|-----------|----------------|---------------|
| Admin | 45 | Admin operations, status transitions | JWT |
| V3 | 25 | Self-subscribe, field updates | ONDC Signature |
| Combined | 20 | Mixed workflows, complete lifecycles | Both |
| Advanced | 15 | Multi-domain, concurrency, edge cases | Both |
| Integration | 10 | Auth, DB state, cross-feature | Both |
| **TOTAL** | **115** | **Complete E2E Coverage** | **Dual Auth** |

---

## 🎯 Common Filtering Scenarios

Quick reference for common test filtering use cases:

```powershell
# Quick smoke test - Run first 5 tests
python run_tests.py run --category v3 --test-id V01-V05

# Test specific feature - Run tests for a feature area
python run_tests.py run --category v3 --test-id V10-V15

# Skip slow/optional tests during development
python run_tests.py run --category v3 --skip-optional

# Full regression with optional tests
python run_tests.py run --all --include-optional

# Debug single failing test
python run_tests.py run --category v3 --test-id V15

# Run only edge cases and advanced scenarios
python run_tests.py run --category v3 --only-optional

# Combined: specific tests + optional
python run_tests.py run --category v3 --test-id V01-V10 --include-optional
```

> 💡 **Tip:** Use `--skip-optional` (default) for faster development iterations, and `--include-optional` for comprehensive release testing.

---

## 📦 Postman Export

Export the full test suite (or specific categories) as a **Postman Collection v2.1** with auto-generated pre-request and test scripts.

```powershell
# Export all enabled categories
python run_tests.py export-postman --all

# Export specific categories only
python run_tests.py export-postman --category admin --category v3

# Custom output paths
python run_tests.py export-postman --all --output postman/ondc_collection.json --environment postman/ondc_env.json
```

**Output files:**
| File | Description |
|------|-------------|
| `postman_collection_<ts>.json` | Importable Postman Collection v2.1 |
| `postman_environment_<ts>.json` | Matching environment: `base_url`, credentials, token vars |

**Import into Postman:**
1. `File → Import` → select `postman_collection_<ts>.json`
2. `File → Import` → select `postman_environment_<ts>.json`
3. Switch to the imported environment in the top-right dropdown
4. Run requests or use the **Collection Runner**

**What's included per request:**

| Script | Content |
|--------|---------|
| **Pre-request** (Admin) | Auto-login to `/admin/auth/login`, caches JWT in `admin_token`, re-fetches when expired |
| **Pre-request** (V3) | Comment block with ONDC signature instructions; sets `subscriber_id` if not set |
| **Pre-request** (Workflow step 1) | Seeds `subscriber_id` / `uk_id` env vars |
| **Tests tab** | `pm.test` assertions for `expected_status`, every `validate` field check, `pm.environment.set` for every `store` capture |

**Workflow tests** are exported as sub-folders — each step is a separate request in sequence, with `store` captures wiring variables to the next step via `pm.environment.set()`.

> ⚠️ **V3 ONDC Ed25519 signing** cannot be automated inside Postman's sandbox (no native Ed25519 support). Pre-request scripts include a clear comment with manual steps. Use `python run_tests.py run --category v3` for automated V3 execution.

**Options:**
| Flag | Description |
|------|-------------|
| `-c / --category` | Category to export (repeatable, default: all enabled) |
| `-a / --all` | Export all enabled categories |
| `-o / --output` | Collection JSON path (default: `output/postman_collection_<ts>.json`) |
| `-e / --environment` | Environment JSON path (default: `output/postman_environment_<ts>.json`) |

---

## ⚖️ Environment Comparison Report

The `compare` command generates a fully self-contained HTML report at `output/comparison_<timestamp>.html`.

### Report Sections

1. **Environment Cards** — At-a-glance summary per URL: Passed / Failed / Pass-Rate % / Avg Response Time. When `--shared-data` is used, the first (primary) environment is tagged with a **primary** badge and the report header shows a **🔗 Shared Data** indicator.
2. **Summary Table** — All environments in one table with an inline pass-rate bar chart
3. **Test Matrix** — One section per category. Each row = one test, each column = one environment:
   - 🟢 `✓` green cell = passed (hover shows response time)
   - 🔴 `✗` red cell = failed (hover shows error message)
   - ⬜ `—` grey cell = test not run on that environment
   - 🟡 highlighted row = **divergent** — result differs across environments
4. **Per-test Drilldown** — Click `▼` on any row to expand a side-by-side panel showing each environment's error message, request body, and response body
5. **Category Search** — Instant filter within each matrix section

### Console Output

A summary table is also printed to the terminal:

```
======================================================================
COMPARISON SUMMARY
======================================================================
Environment         URL                                  Pass  Fail    Rate  AvgMs
----------------------------------------------------------------------
Local               http://localhost:8080                  42     3   93.3%    145ms
Dev                 http://34.180.2.104                    40     5   88.9%    312ms
Staging             http://34.14.152.92                    45     0  100.0%    198ms
======================================================================

[OK] Report: output/comparison_20260322_143000.html
```

---

## 🤝 Contributing

To add new tests:
1. Edit appropriate YAML config file
2. Follow existing test structure
3. Update test counts in `test_suite.yaml`
4. Run and validate: `python run_tests.py run --category <category>`

---

## 📜 License

Part of ONDC Registry project. See main repository for license details.

---

## ✅ Summary

**115 comprehensive tests** across **5 categories** with **complete authentication automation** for both **Admin JWT** and **V3 ONDC Ed25519 signature** schemes.

**Ready to run:** `python run_tests.py run --all`

🚀 **Happy Testing!**
