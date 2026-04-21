# ONDC Registry - Policy Management Tests

## Overview

This folder contains policy management test cases for the ONDC Registry API. These tests validate policy object handling, upserting, and validation in the admin subscribe endpoint.

## Test Cases

The test suite includes 4 comprehensive test cases:

### P01: Admin subscribe rejects top-level policy_id
- **Description**: Validate that top-level policy_id is no longer accepted in admin subscribe payload
- **Expected Result**: 400 Bad Request with NACK status
- **Test Type**: Negative test

### P02: Admin subscribe with Policy object (upsert new)
- **Description**: Create new NETWORK routing policy via upsert and link to participant
- **Expected Result**: 200 OK with ACK status
- **Test Type**: Positive test
- **Policy Type**: NETWORK

### P03: Admin subscribe with Policy object (upsert existing)
- **Description**: Update existing NETWORK_PARTICIPANT whitelist policy via upsert by name and link to participant
- **Expected Result**: 200 OK with ACK status
- **Test Type**: Positive test
- **Policy Type**: NETWORK_PARTICIPANT
- **Features Tested**: Multiple rules, ALLOW/NOT_ALLOW actions

### P04: Admin subscribe with Policy object only
- **Description**: Upsert policy using policy object only and link to participant
- **Expected Result**: 200 OK with ACK status
- **Test Type**: Positive test
- **Policy Type**: NETWORK

## File Structure

```
resources/registry/policy/
├── test_policy_functional.yml    # YAML test configuration

tests/registry/policy/
├── __init__.py
└── test_policy_functional.py     # Python test implementation
```

## Running the Tests

### Run all policy tests:
```bash
python driver.py --test ondc_policy_functional --environment ondcRegistry --users 1 --iterations 1
```

### Run with HTML report:
```bash
python driver.py --test ondc_policy_functional \
  --environment ondcRegistry \
  --users 1 --iterations 1 \
  --html results/registry/policy_test_report_{datetime}.html
```

### Run using the script:
```bash
./func_test_scripts/gateway/ondc_gw_policy_tests.sh
```

## Configuration

The tests use the following configuration files:
- **Test Cases**: `resources/registry/policy/test_policy_functional.yml`
- **Base Config**: `resources/registry/subscribe/test_subscribe_functional.yml`
- **Test Registration**: `config.yml` (registered as `ondc_policy_functional`)
- **Environments**: `resources/environments.yml`

## Test Data

Tests use dynamic test data:
- **Participant IDs**: Auto-generated with UUID suffix
- **Timestamps**: Dynamic timestamp replacement using `{{timestamp}}` placeholder
- **Policy IDs**: Predefined UUIDs for reproducibility
- **Keys**: Fresh ED25519 keypairs generated per test

## Policy Types Tested

1. **NETWORK**: System-level routing policies
   - Route traffic to specific gateways
   - Domain and action-based matching

2. **NETWORK_PARTICIPANT**: Participant-level whitelist/blacklist policies
   - ALLOW/NOT_ALLOW actions
   - BPP-specific filtering
   - Multi-rule support

## Expected Outcomes

All tests validate:
- Correct HTTP status codes (200/400)
- Response message acknowledgment status (ACK/NACK)
- Policy object structure and validation
- Proper linking between policies and participants

## Dependencies

- Python 3.8+
- CTF (Common Test Foundation)
- PyYAML
- Locust
- NaCl (for Ed25519 key generation)

## Notes

- Tests use admin authentication via JWT token
- Each test generates fresh participant data to avoid conflicts
- Policy IDs are fixed for reproducibility but names include timestamps
- Tests support both POST and PATCH methods
- Validation includes nested field checking (e.g., `message.ack.status`)

## Troubleshooting

### Test fails with "No test cases loaded"
- Check that `resources/registry/policy/test_policy_functional.yml` exists
- Verify YAML syntax is valid

### Authentication errors
- Ensure admin credentials are configured in `resources/registry/subscribe/test_subscribe_functional.yml`
- Check admin username and password

### Policy validation errors
- Review policy object structure in YAML
- Ensure all required fields are present (policy_id, name, type, rule_definition)
- Verify rule IDs are unique

## Related Documentation

- Admin Subscribe API: `/admin/subscribe`
- Policy Management Specification
- Test Suite v2: `test-suite-v2 2/config/admin_tests.yaml`
