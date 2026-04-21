# ONDC Gateway – Endpoint Accessibility Tests

Checks all Gateway API endpoints across **UAT** and **PreProd** environments to ensure none are blocked (returning `403 Forbidden`).

## Files

| File | Purpose |
|------|---------|
| `func_test_scripts/gateway/ondc_gw_endpoint_accessibility_tests.py` | Test runner + HTML report generator |
| `resources/gateway/test_endpoint_accessibility.yml` | YAML config – environment URLs and endpoint list |

## How to Run

```bash
python func_test_scripts/gateway/ondc_gw_endpoint_accessibility_tests.py
```

The HTML report is saved to `results/gateway/gw_endpoint_accessibility_<timestamp>.html`.

## Pass / Fail Criteria

| Response | Verdict |
|----------|---------|
| `403 Forbidden` | **FAIL** – endpoint is blocked |
| Any other status (2xx, 4xx, 5xx, redirect, connection error) | **PASS** – endpoint is reachable |

## Configuration

Edit `resources/gateway/test_endpoint_accessibility.yml` to:

- **Add/remove environments** under `ondcGateway.environments`
- **Add/remove endpoints** under `endpoints` (each entry needs `method` and `path`)

```yaml
ondcGateway:
  environments:
    uat:
      host: https://gateway-uat.kynondc.net
      verify_ssl: true
    preprod:
      host: https://gateway-preprod.ondc.org
      verify_ssl: true

endpoints:
  - method: GET
    path: /health
  - method: POST
    path: /search
  # ...
```

## Report Features

- Side-by-side UAT vs PreProd summary cards
- Mismatch counter (endpoints that differ between environments)
- Filterable table: All | Mismatches | Both Passed | Both Failed
- Click any row to expand response details from both environments
- Search by endpoint path

## Endpoints Covered

22 endpoints: Health (`/`, `/health`), Beckn async APIs (`/search`, `/select`, `/init`, `/confirm`, `/status`, `/track`, `/cancel`, `/update`, `/rating`, `/support`, `/issue`), and their callbacks (`/on_search`, `/on_select`, `/on_init`, `/on_confirm`, `/on_status`, `/on_track`, `/on_cancel`, `/on_update`, `/on_rating`, `/on_support`, `/on_issue_status`).
