# ONDC Admin Service – Endpoint Accessibility Tests

Checks all Admin Portal Service API endpoints to ensure none are blocked (returning `403 Forbidden`).

Supports single-environment (UAT only) or dual-environment (UAT vs PreProd) comparison when a second environment is configured.

## Files

| File | Purpose |
|------|---------|
| `func_test_scripts/admin-service/ondc_admin_svc_endpoint_accessibility_tests.py` | Test runner + HTML report generator |
| `resources/admin-service/test_endpoint_accessibility.yml` | YAML config – environment URLs and endpoint list |

## How to Run

```bash
python func_test_scripts/admin-service/ondc_admin_svc_endpoint_accessibility_tests.py
```

The HTML report is saved to `results/admin-service/admin_svc_endpoint_accessibility_<timestamp>.html`.

## Pass / Fail Criteria

| Response | Verdict |
|----------|---------|
| `403 Forbidden` | **FAIL** – endpoint is blocked |
| Any other status (2xx, 4xx, 5xx, redirect, connection error) | **PASS** – endpoint is reachable |

## Configuration

Edit `resources/admin-service/test_endpoint_accessibility.yml`:

```yaml
ondcAdminService:
  environments:
    uat:
      host: https://admin-service-uat.kynondc.net/api/v1
      verify_ssl: true
    # Uncomment when preprod is available:
    # preprod:
    #   host: https://admin-service-preprod.ondc.org/api/v1
    #   verify_ssl: true
```

- **1 environment** → single-environment report with pass/fail table
- **2 environments** → side-by-side comparison report with mismatch highlighting

## Endpoints Covered

23 endpoints across: Health, Audit Logs, RBAC, Pages, Groups, Users, and Registry Proxy (Enums, Configs/Stats, Participants, Policies, Domains).
