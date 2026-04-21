# ONDC Registry – Endpoint Accessibility Tests

Checks all registry API endpoints across **UAT** and **PreProd** environments to ensure none are blocked (returning `403 Forbidden`).

## Files

| File | Purpose |
|------|---------|
| `func_test_scripts/registry/ondc_reg_endpoint_accessibility_tests.py` | Test runner + HTML report generator |
| `resources/registry/test_endpoint_accessibility.yml` | YAML config – environment URLs and endpoint list |

## How to Run

```bash
python func_test_scripts/registry/ondc_reg_endpoint_accessibility_tests.py
```

The HTML report is saved to `results/registry/reg_endpoint_accessibility_<timestamp>.html`.

## Pass / Fail Criteria

| Response | Verdict |
|----------|---------|
| `403 Forbidden` | **FAIL** – endpoint is blocked |
| Any other status (2xx, 4xx, 5xx, redirect, connection error) | **PASS** – endpoint is reachable |

## Configuration

Edit `resources/registry/test_endpoint_accessibility.yml` to:

- **Add/remove environments** under `ondcRegistry.environments`
- **Add/remove endpoints** under `endpoints` (each entry needs `method` and `path`)

```yaml
ondcRegistry:
  environments:
    uat:
      host: https://registry-uat.kynondc.net
      auth_host: https://admin-auth-uat.kynondc.net
    preprod:
      host: https://registry-preprod.ondc.org
      auth_host: https://admin-auth-preprod.ondc.org

endpoints:
  - method: GET
    path: /health
  - method: POST
    path: /v3.0/lookup
  # ...
```

> Endpoints starting with `/api/auth` are routed to `auth_host`; all others use `host`.

## Report Features

- Side-by-side UAT vs PreProd summary cards
- Mismatch counter (endpoints that differ between environments)
- Sortable/filterable table: All | Mismatches | Both Passed | Both Failed
- Click any row to expand response details from both environments
- Search by endpoint path

## Endpoints Covered

71 endpoints across: Health, Auth, Admin (Participants, Subscribe, Policies, Domains, Enums, Configs, Audit), Users, Sessions, Lookup, Subscribe, and Utility.
