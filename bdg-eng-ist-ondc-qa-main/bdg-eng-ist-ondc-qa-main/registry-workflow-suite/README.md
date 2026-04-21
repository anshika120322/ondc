# ONDC Registry Test Suite v2.0 🚀

**Comprehensive End-to-End Test Automation for ONDC Registry**

Complete restructured test suite with **115 tests** across **5 categories**, featuring full **Admin JWT** and **V3 ONDC Ed25519 signature** authentication.

**Features:**
- ✅ **Universal Runner** - Single `UniversalTestRunner` handles Admin, V3, and mixed workflows
- ✅ **Test ID Filtering** - Run specific tests by ID (e.g., `--test-id V01-V10`)
- ✅ **Optional Test Control** - Skip, include, or run only optional tests
- ✅ **Range Notation** - Easily run test ranges (e.g., `V01-V20`)
- ✅ **Tags & Dependencies** - Annotate tests with `tags:`, skip dependents via `depends_on:`
- ✅ **Setup / Teardown Steps** - Per-test `setup_steps:` and `teardown_steps:` blocks
- ✅ **Advanced Step Control** - `retry:`, `sleep_seconds:`, `skip_if:`, `run_if:`, `allow_failure:`
- ✅ **Rich Validation** - `is_null`, `type`, `length`, `schema`, `not_empty` checks
- ✅ **Dry Run & Fail Fast** - `--dry-run` lists tests; `--fail-fast` stops on first failure
- ✅ **JUnit XML Output** - `--output-format junit` for CI/CD integration
- ✅ **Fake Data Generation** - `{{fake:email}}`, `{{fake:uuid}}`, `{{fake:name}}` etc.
- ✅ **Environment Variables** - `{{env:VAR}}` and `.env` file auto-loading
- ✅ **Config Overrides** - `--override key=value` at runtime
- ✅ **YAML Includes** - Compose test configs with `include:` directives
- ✅ **Multi-URL Comparison** - Run the same tests against multiple environments and generate a visual diff report
- ✅ **Shared-Data Mode** - Identical generated test data across all environments for true apples-to-apples comparison
- ✅ **Postman Export** - Generate a ready-to-import Postman Collection v2.1 with pre-request auth and test assertion scripts
- ✅ **HTML Report Enhancements** - Collapsible timeline, "Failed Only" filter, ONDC Key Pair section
- ✅ **Diff Command** - Compare two result JSON files and generate a visual HTML diff
- ✅ **Parallel Execution** - `--parallel` runs all categories concurrently with `--all`

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
│   │   ├── base_runner.py          # Core execution engine (all features)
│   │   └── universal_runner.py     # UniversalTestRunner (Admin + V3 + Combined)
│   │
│   └── utils/                       # Utilities
│       ├── http_client.py          # HTTP client (dual auth)
│       ├── data_generator.py       # Test data + fake data generation
│       ├── state_manager.py        # State tracking
│       ├── html_reporter.py        # HTML report generator (timeline, toggles)
│       ├── comparison_reporter.py  # Multi-URL HTML diff report generator
│       └── postman_exporter.py     # Postman Collection v2.1 exporter
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

# Run specific tests by ID
python run_tests.py run --category v3 --test-id V01-V05

# Run only required tests (skip optional)
python run_tests.py run --category v3 --skip-optional

# Dry-run: list tests without executing
python run_tests.py run --category admin --dry-run

# Stop on first failure
python run_tests.py run --all --fail-fast

# Run all categories in parallel
python run_tests.py run --all --parallel
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

# Run a standalone YAML test file directly
python run_tests.py run --file path/to/my_test.yaml

# Override a config key at runtime
python run_tests.py run --category admin --override base_url=http://staging:8080

# Run all categories in parallel
python run_tests.py run --all --parallel
```

### **Test Filtering**

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

# Filter by tag
python run_tests.py run --category admin --tag smoke

# Skip optional tests (default behavior)
python run_tests.py run --category v3 --skip-optional

# Include optional tests
python run_tests.py run --category v3 --include-optional

# Run ONLY optional tests
python run_tests.py run --category v3 --only-optional
```

**Test ID Filtering Features:**
- ✅ **Single test**: `--test-id V01`
- ✅ **Multiple tests**: `--test-id V01 --test-id V02`
- ✅ **Range notation**: `--test-id V01-V10` (expands to V01, V02, ..., V10)
- ✅ **Combined ranges**: `--test-id V01-V05 --test-id V15-V20`
- ✅ **Tag filter**: `--tag smoke` runs only tests annotated with `tags: [smoke]`

**Optional Test Control:**
- ✅ `--skip-optional` - Skip optional tests (default)
- ✅ `--include-optional` - Include optional tests
- ✅ `--only-optional` - Run only optional tests

### **Execution Control**

```powershell
# Dry-run: list matching tests without executing them
python run_tests.py run --category admin --dry-run

# Stop immediately on the first test failure
python run_tests.py run --all --fail-fast

# Generate JUnit XML output (for CI/CD pipelines)
python run_tests.py run --category admin --output-format junit

# Set a random seed for reproducible fake-data generation
python run_tests.py run --category v3 --seed 42
```

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

### **Diff Two Result Files**

Compare two test result JSON files and generate a visual HTML diff report:

```powershell
# Compare baseline vs latest results
python run_tests.py diff output/admin_results_old.json output/admin_results_new.json

# Custom output path
python run_tests.py diff results_a.json results_b.json -o output/diff_report.html
```

The diff report highlights tests that changed status (pass → fail, fail → pass) and shows side-by-side response details for divergent results.

### **Compare Across Environments**

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

# Use identical test data across all environments (same subscriber IDs, same request bodies)
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
├── admin_results_20260213_143022.html       # Admin test results (HTML report)
├── admin_results_20260213_143022_junit.xml  # Admin JUnit XML (--output-format junit)
├── v3_results_20260213_143145.json          # V3 test results
├── combined_results_20260213_143308.json    # Combined test results
├── advanced_results_20260213_143425.json    # Advanced test results
├── integration_results_20260213_143540.json # Integration test results
├── test_suite_summary_20260213_143600.json  # Overall summary
├── comparison_20260213_144000.html          # Multi-URL comparison report (HTML)
├── comparison_20260213_144000.json          # Multi-URL comparison data (JSON)
├── diff_20260213_144500.html               # Diff report (diff command)
├── postman_collection_20260213_144500.json  # Postman Collection v2.1
└── postman_environment_20260213_144500.json # Postman Environment (base_url, credentials)
```

### **HTML Report Features**

The per-category HTML report includes:
- **Summary cards** — Total / Passed / Failed / Avg Time
- **Timeline bar chart** — Response times per test (collapsible)
- **"Failed Only" filter** — Toggle to show only failed tests
- **ONDC Key Pair section** — Generated Ed25519 key pairs for V3 tests (collapsible, hidden by default for admin-only tests)
- **Per-test details** — Request body, response body, validation results

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
    runner: "universal"           # Uses UniversalTestRunner
    test_count: 45
    enabled: true

config:
  base_url: "http://localhost:8080"
  admin_username: "admin"
  admin_password: "admin123"
  default_timeout: 30
  comparison_targets:
    - label: "Local"
      url: "http://localhost:8080"
    - label: "Dev"
      url: "http://34.180.2.104"

execution_order:
  - "admin"
  - "v3"
  - "combined"
  - "advanced"
  - "integration"

performance:
  max_response_time_ms: 2000
  max_workflow_time_ms: 30000
  max_batch_time_ms: 60000
```

### **Environment Variables & .env**

Create a `.env` file in `test-suite-v2/` and values are auto-loaded:

```env
BASE_URL=http://localhost:8080
ADMIN_USERNAME=admin
ADMIN_PASSWORD=secret123
```

Reference from test YAML using `{{env:VAR_NAME}}`:

```yaml
data:
  callback_url: "{{env:CALLBACK_URL}}"
```

Override any config key at runtime:

```powershell
python run_tests.py run --category admin --override base_url=http://staging:8080 --override default_timeout=60
```

### **Test Config Example** - `config/admin_tests.yaml`

```yaml
test_suite:
  name: "Admin End-to-End Tests"
  category: "admin"
  total_tests: 45

# Optionally include another YAML file
include:
  - shared_fixtures.yaml

tests:
  - id: "A01"
    name: "Create WHITELISTED participant"
    tags: [smoke, create]           # Tag-based filtering with --tag
    optional: false                  # true = skip unless --include-optional
    method: "POST"
    endpoint: "/admin/subscribe"
    auth_type: "admin"
    headers:
      X-Request-ID: "{{fake:uuid}}"  # Auto-generated fake data
    data:
      action: "WHITELISTED"
      subscriber_url: "{{fake:url}}"
      configs:
        - domain: "ONDC:RET10"
          np_type: "SELLER"
    expected_status: 200
    validate:
      - field: "status"
        value: "WHITELISTED"
      - field: "subscriber_id"
        not_empty: true              # Field must be non-empty
      - field: "created_at"
        type: "string"               # Type assertion: string | int | bool | list | dict
      - field: "configs"
        type: "list"
        length: {min: 1, max: 10}   # Length check on string or list
      - field: "deleted_at"
        is_null: true                # Null/None assertion
    store:
      - field: "subscriber_id"
        as: "subscriber_id"         # Saved to context for later steps
```

### **Multi-Step Workflow Test**

```yaml
  - id: "A32"
    name: "Create → Update → Deactivate"
    tags: [workflow]
    variables:                       # Per-test local variables
      domain: "ONDC:RET10"
    setup_steps:                     # Runs before main steps (cleanup/seed)
      - name: "Ensure no prior participant"
        method: "GET"
        endpoint: "/admin/subscribe/{{subscriber_id}}"
        auth_type: "admin"
        allow_failure: true          # Setup errors don't fail the test
    steps:
      - name: "Create WHITELISTED"
        method: "POST"
        endpoint: "/admin/subscribe"
        auth_type: "admin"
        data:
          action: "WHITELISTED"
          configs:
            - domain: "{{domain}}"
              np_type: "SELLER"
        expected_status: 200
        store:
          - field: "subscriber_id"
            as: "subscriber_id"
        retry:
          count: 3                   # Retry up to 3 times
          delay_seconds: 1           # Wait 1s between retries
      - name: "Subscribe via Admin"
        method: "POST"
        endpoint: "/admin/subscribe"
        auth_type: "admin"
        skip_if: "{{subscriber_id}} == ''"   # Skip if condition is true
        data:
          action: "SUBSCRIBED"
          subscriber_id: "{{subscriber_id}}"
        expected_status: 200
        sleep_seconds: 0.5           # Pause after this step
      - name: "Deactivate"
        method: "PATCH"
        endpoint: "/admin/subscribe/{{subscriber_id}}"
        auth_type: "admin"
        run_if: "{{subscriber_id}} != ''"    # Run only if condition is true
        data:
          action: "INACTIVE"
        expected_status: 200
    teardown_steps:                  # Always runs after main steps (even on failure)
      - name: "Cleanup participant"
        method: "DELETE"
        endpoint: "/admin/subscribe/{{subscriber_id}}"
        auth_type: "admin"
        allow_failure: true
```

### **V3 Test with Auto-Registration**

```yaml
  - id: "V02"
    name: "V3: WHITELISTED → SUBSCRIBED (all fields)"
    inject_v3_key: true              # Injects generated Ed25519 pub keys into admin step
    steps:
      - name: "Admin whitelist"
        method: "POST"
        endpoint: "/admin/subscribe"
        auth_type: "admin"
        data:
          action: "WHITELISTED"
          key:
            signing_public_key: "placeholder"   # Replaced automatically
            encryption_public_key: "placeholder"
          configs:
            - domain: "ONDC:RET10"
              np_type: "SELLER"
        expected_status: 200
        store:
          - field: "subscriber_id"
            as: "subscriber_id"
      - name: "V3 self-subscribe"
        method: "POST"
        endpoint: "/subscribe"
        auth_type: "v3"              # Triggers ONDC Ed25519 signature auth
        data:
          subscriber_id: "{{subscriber_id}}"
          action: "SUBSCRIBED"
        expected_status: 200
```

### **Fake Data Generators**

Use `{{fake:TYPE}}` in any `data`, `headers`, or `endpoint` field:

| Token | Example Output |
|-------|---------------|
| `{{fake:uuid}}` | `a1b2c3d4-e5f6-...` |
| `{{fake:email}}` | `user_a1b2@example.com` |
| `{{fake:name}}` | `Jane Smith` |
| `{{fake:url}}` | `https://app-a1b2.example.com` |
| `{{fake:domain}}` | `app-a1b2.example.com` |
| `{{fake:phone}}` | `+919876543210` |
| `{{fake:subscriber_id}}` | `app-a1b2.example.com` |

Use `--seed INTEGER` for reproducible data across runs:

```powershell
python run_tests.py run --category v3 --seed 42
```

---

## 🐛 Troubleshooting

### **Common Issues**

#### 1. Admin Login Failed
```
✗ Admin login failed
```
**Solution**: Check admin credentials in `config/test_suite.yaml` or use `--override admin_password=...`

#### 2. V3 Signature Error
```
✗ V3 signature authentication failed (401)
```
**Solution**: Ensure cryptography package is installed: `pip install cryptography==41.0.7`

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

#### 5. V3 ERR_509 Invalid public key encoding
Make sure the test config includes `inject_v3_key: true` at the test level and that the admin whitelist step has a `key:` field — the runner replaces the placeholder values with the generated Ed25519 public keys automatically.

#### 6. Test skipped unexpectedly
If a test is skipped due to a failed dependency, check the `depends_on:` list in the YAML and ensure the referenced test ID ran and passed.

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

Edit the appropriate config file (e.g., `config/admin_tests.yaml`):

```yaml
tests:
  - id: "A46"
    name: "My New Test"
    tags: [smoke]
    optional: false          # true = skipped unless --include-optional
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
      - field: "subscriber_id"
        not_empty: true
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
       runner: "universal"
       test_count: 10
       enabled: true
   ```
3. Add to execution order if needed

### **Compose with Includes**

Split large test files and include them in a parent:

```yaml
# config/admin_tests.yaml
include:
  - admin_create_tests.yaml
  - admin_transition_tests.yaml

test_suite:
  name: "Admin End-to-End Tests"
  category: "admin"
```

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

### **Run Specific Tests by ID**

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

### **Dry Run to Preview Tests**

```powershell
python run_tests.py run --category admin --tag smoke --dry-run
```

Expected output:
```
[DRY RUN] Would execute 8 tests in category: admin
  - A01: Create WHITELISTED participant (minimal fields)  [tags: smoke, create]
  - A02: Create WHITELISTED participant (all fields)      [tags: smoke, create]
  ...
```

### **JUnit XML for CI/CD**

```powershell
python run_tests.py run --category admin --output-format junit
# Generates: output/admin_results_<timestamp>_junit.xml
```

### **Run Full Suite**

```powershell
python run_tests.py run --all
```

Expected execution time: **~5-10 minutes** for all 115 tests.

```powershell
# Faster with parallel category execution
python run_tests.py run --all --parallel
```

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
# Quick smoke test - Run tagged smoke tests
python run_tests.py run --category admin --tag smoke

# Run first 5 V3 tests
python run_tests.py run --category v3 --test-id V01-V05

# Test specific feature area
python run_tests.py run --category v3 --test-id V10-V15

# Skip slow/optional tests during development
python run_tests.py run --category v3 --skip-optional

# Full regression with optional tests
python run_tests.py run --all --include-optional

# Debug single failing test
python run_tests.py run --category v3 --test-id V15

# Run edge cases only
python run_tests.py run --category v3 --only-optional

# Combined: specific range + optional
python run_tests.py run --category v3 --test-id V01-V10 --include-optional

# Stop immediately on first failure
python run_tests.py run --all --fail-fast

# Dry-run to see what would execute
python run_tests.py run --all --dry-run

# Stable reproducible run with seeded fake data
python run_tests.py run --all --seed 2026
```

> **Tip:** Use `--skip-optional` (default) for faster development iterations, and `--include-optional` for comprehensive release testing.

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

Key highlights:
- **`UniversalTestRunner`** — single runner handling admin, V3, and mixed workflows via `runner: "universal"` in config
- **Rich step control** — retry, sleep, skip_if, run_if, allow_failure, setup/teardown steps
- **Advanced validation** — value, type, length, is_null, not_empty, JSON schema
- **Fake data & env vars** — `{{fake:email}}`, `{{env:BASE_URL}}`, `.env` auto-loading, `--seed`
- **CI/CD ready** — `--output-format junit`, `--fail-fast`, `--dry-run`, `--parallel`
- **Visual reports** — HTML with timeline and toggle sections; multi-env comparison; diff command

**Ready to run:** `python run_tests.py run --all`

Happy Testing!
