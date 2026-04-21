"""ONDC Gateway error-code catalogue loader and validator.

Loads resources/gateway/ondc_gateway_error_codes.yml once at import time
and exposes helpers used by GatewayConfirmBase, GatewaySearchBase, and
any other consumer that needs to validate NACK response fields.
"""
import logging
import os
from typing import Optional, Tuple

import yaml

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Load catalogue from YAML at import time
# ---------------------------------------------------------------------------
_CATALOGUE: dict = {}


def _load() -> None:
    global _CATALOGUE
    # Resolve path: tests/utils/ → project_root/resources/gateway/
    base = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    yml_path = os.path.join(base, "resources", "gateway", "ondc_gateway_error_codes.yml")
    try:
        with open(yml_path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        _CATALOGUE = {str(k): v for k, v in data.get("error_codes", {}).items()}
        logger.debug(f"Loaded {len(_CATALOGUE)} entries from ONDC error catalogue ({yml_path})")
    except Exception as exc:
        logger.warning(f"Could not load ONDC error catalogue ({yml_path}): {exc}")
        _CATALOGUE = {}


_load()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_entry(code: Optional[str]) -> dict:
    """Return the catalogue entry dict for a given error code, or {} if unknown."""
    return _CATALOGUE.get(str(code), {}) if code else {}


def validate_nack_error(
    actual_code: Optional[str],
    actual_type: Optional[str],
    expected_code: Optional[str],
) -> Tuple[bool, str]:
    """Validate a NACK response against the error catalogue.

    Checks:
      1. actual_code == expected_code  (strict)
      2. actual_type == catalogue[expected_code].type  (strict when both are present)

    Returns:
        (ok, note)  — ok=False means the caller should mark the test as FAILED.
    """
    if not expected_code:
        # No code expectation set — nothing to validate
        code_part = f"error.code={actual_code}" if actual_code else "error.code=<none>"
        type_part = f", error.type={actual_type}" if actual_type else ""
        return True, f"{code_part}{type_part}"

    # 1. Code match
    if str(actual_code) != str(expected_code):
        return False, (
            f"error.code={actual_code!r} (expected {expected_code!r})"
        )

    # 2. Type match (only when the catalogue has an entry and the response has a type)
    entry = get_entry(expected_code)
    expected_type = entry.get("type")
    if expected_type and actual_type and str(actual_type) != str(expected_type):
        return False, (
            f"error.code={actual_code} OK but "
            f"error.type={actual_type!r} (expected {expected_type!r} per catalogue)"
        )

    # Build a short passing note for log output
    type_part = f", error.type={actual_type}" if actual_type else ""
    return True, f"error.code={actual_code}{type_part}"
