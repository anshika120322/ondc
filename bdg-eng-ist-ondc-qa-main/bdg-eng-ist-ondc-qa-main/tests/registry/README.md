# Registry Tests - Structure and Relationships

## Quick Reference Guide

| Test File | Base Class File | YAML Config File | Test Count | Purpose |
|-----------|----------------|------------------|------------|---------|
| **ondc_reg_subscribe_functional.py** | registry_subscribe_base.py | ondc_reg_subscribe_functional.yml | 23 | Positive functional tests (TC-01 to TC-23) |
| **ondc_reg_subscribe_negative.py** | registry_subscribe_base.py | ondc_reg_subscribe_negative.yml | 40 | Negative/error tests (TC-028 to TC-067) |
| **ondc_reg_subscribe_performance.py** | registry_subscribe_base.py | ondc_reg_subscribe_functional.yml | - | Performance/load tests |
| **ondc_reg_v3_comprehensive.py** | registry_subscribe_base.py | ondc_reg_v3_comprehensive_tests.yml | 26 | V3 API comprehensive tests (V00-V25) |
| **ondc_reg_advanced.py** | advanced_subscribe_base.py | ondc_reg_advanced_tests.yml | 15 | Advanced scenarios (multi-domain, concurrency) |
| **ondc_admin_comprehensive.py** | admin_subscribe_base.py | ondc_admin_comprehensive_tests.yml | 45 | Admin operations comprehensive tests |
| **ondc_reg_lookup_functional.py** | registry_lookup_base.py | ondc_reg_lookup_functional.yml | - | Registry lookup functional tests |
| **ondc_reg_lookup_negative.py** | registry_lookup_base.py | ondc_reg_lookup_negative.yml | - | Registry lookup negative tests |

## Base Classes Explained

### 1. **registry_subscribe_base.py** (SHARED BASE)
**Class:** `RegistrySubscribeBase`  
**Purpose:** Common functionality for Registry Subscribe API tests  
**Used by:** Multiple test files (functional, negative, performance, v3)  
**Provides:**
- JWT Bearer token authentication
- ED25519 signature generation for V3 API
- Admin and V3 API request methods
- Payload generators and helpers

### 2. **advanced_subscribe_base.py**
**Class:** `AdvancedSubscribeBase`  
**Purpose:** Advanced test scenarios (multi-domain, concurrency, edge cases)  
**Used by:** `ondc_reg_advanced.py`  
**Provides:**
- Multi-domain operations support
- Concurrency handling
- YAML-driven test execution
- Extended HTTP methods (GET, POST, PATCH)

### 3. **admin_subscribe_base.py**
**Class:** `AdminSubscribeBase`  
**Purpose:** Admin-specific operations and workflows  
**Used by:** `ondc_admin_comprehensive.py`  
**Provides:**
- Admin API specific operations
- State transition workflows
- Credential and contact management
- YAML-driven test execution

### 4. **registry_lookup_base.py**
**Class:** `RegistryLookupBase`  
**Purpose:** Registry lookup API operations  
**Used by:** Lookup test files  
**Provides:**
- Lookup payload generation
- Public and admin lookup methods
- Response validation

## YAML Config Files Location

All YAML config files are in: `resources/registry/`

## Running Tests

```bash
# From launch.json in VS Code
- "ONDC Registry: V3 Comprehensive (1x)"
- "ONDC Registry: Advanced (1x)"
- "ONDC Admin: Comprehensive (1x)"

# From command line
python driver.py --test ondc_reg_v3_comprehensive --env ondcRegistry --iterations 1
python driver.py --test ondc_reg_advanced --env ondcRegistry --iterations 1
python driver.py --test ondc_admin_comprehensive --env ondcRegistry --iterations 1
```

## File Naming Convention

✅ **Test files** start with `ondc_` prefix  
✅ **Base classes** end with `_base.py` suffix  
✅ **YAML configs** end with `_tests.yml` or just `.yml`  

This matching pattern makes it easier to identify related files!
