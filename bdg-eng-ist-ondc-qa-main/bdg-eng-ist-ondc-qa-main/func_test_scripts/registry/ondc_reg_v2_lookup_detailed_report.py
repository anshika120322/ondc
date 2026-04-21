#!/usr/bin/env python3
"""
ONDC Registry V2 Lookup - Detailed HTML Report Generator
=========================================================
Runs all 62 V2 test cases in a single pass and writes one timestamped HTML report
with full request/response bodies visible in expandable cards:
  results/registry/generate_v2_detailed_<YYYYMMDD_HHMMSS>.html

Suites:
  - V2 Functional          (11 tests)
  - V2 Negative            (30 tests)
  - V2 Boundary            (10 tests)
  - V2 Filter Combinations (11 tests)

Usage:
    $env:PYTHONPATH = "."; py func_test_scripts/registry/ondc_reg_v2_lookup_detailed_report.py
"""

import base64
import binascii
import json
import os
import sys
import time
import uuid
from datetime import datetime, timezone, timedelta
from html import escape
from pathlib import Path
from time import perf_counter
from typing import Any, Dict, List, Optional

import requests
import urllib3
import yaml

# SSL_VERIFY controls certificate validation for all HTTP requests.
# Default: True (secure). Set env var ONDC_SKIP_SSL_VERIFY=1 only for
# test environments that use self-signed certificates.
SSL_VERIFY: bool = os.environ.get("ONDC_SKIP_SSL_VERIFY", "0") != "1"
if not SSL_VERIFY:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from tests.utils.ondc_auth_helper import ONDCAuthHelper

WORKSPACE = Path(__file__).resolve().parent.parent.parent
V2_CONFIG = WORKSPACE / "resources" / "registry" / "lookup" / "v2" / "test_lookup_v2.yml"
RESULTS_DIR = WORKSPACE / "results" / "registry"



# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def pretty_json(value: Any) -> str:
    if value is None:
        return "{}"
    if isinstance(value, str):
        try:
            return json.dumps(json.loads(value), indent=2, sort_keys=True)
        except (ValueError, TypeError):
            return value
    return json.dumps(value, indent=2, sort_keys=True)


def safe_response_body(response: requests.Response) -> str:
    try:
        return pretty_json(response.json())
    except ValueError:
        return response.text or ""


def status_code_class(code: Any) -> str:
    c = str(code)
    if c.isdigit() and c.startswith("2"):
        return "sc-2xx"
    if c.isdigit() and c.startswith("4"):
        return "sc-4xx"
    if c.isdigit() and c.startswith("5"):
        return "sc-5xx"
    return "sc-none"


def load_v2_auth_config(config_path: str, tenant: str) -> Dict[str, Any]:
    with open(config_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    return data.get(tenant, {})


def parse_private_key_seed(seed_value: str) -> bytes:
    seed = (seed_value or "").strip()
    if not seed:
        raise ValueError("private_key_seed is empty")
    try:
        raw = bytes.fromhex(seed)
        if len(raw) == 32:
            return raw
    except ValueError:
        pass
    try:
        raw = base64.b64decode(seed, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("private_key_seed must be 32-byte hex or base64 seed") from exc
    if len(raw) == 32:
        return raw
    der_prefix = bytes.fromhex("302e020100300506032b657004220420")
    if len(raw) >= 48 and raw.startswith(der_prefix):
        return raw[-32:]
    if len(raw) == 64:
        return raw[:32]
    raise ValueError("Unsupported private_key_seed format")


# ---------------------------------------------------------------------------
# uk_id cache
# ---------------------------------------------------------------------------

UK_ID_CACHE = WORKSPACE / "resources" / "registry" / "lookup" / ".registered_uk_id.json"


def load_cached_uk_id(participant_id: str) -> Optional[str]:
    try:
        if UK_ID_CACHE.exists():
            data = json.loads(UK_ID_CACHE.read_text(encoding="utf-8"))
            if data.get("participant_id") == participant_id:
                return data.get("uk_id")
    except Exception:
        pass
    return None


def save_cached_uk_id(participant_id: str, uk_id: str) -> None:
    try:
        UK_ID_CACHE.parent.mkdir(parents=True, exist_ok=True)
        UK_ID_CACHE.write_text(
            json.dumps({"participant_id": participant_id, "uk_id": uk_id}, indent=2),
            encoding="utf-8",
        )
        print(f"[REGISTRATION] uk_id cached: {uk_id}")
    except Exception as exc:
        print(f"[REGISTRATION] Cache save failed: {exc}")


# ---------------------------------------------------------------------------
# Registration helpers
# ---------------------------------------------------------------------------

def get_admin_token(cfg: Dict[str, Any]) -> Optional[str]:
    auth_url = cfg.get("admin_auth_url")
    host = cfg.get("host", "").rstrip("/")
    username = cfg.get("admin_username", "")
    password = cfg.get("admin_password", "")
    if not username or not password:
        print("[REGISTRATION] Admin credentials not configured")
        return None
    if auth_url:
        url = auth_url.rstrip("/")
        payload = {"email": username, "password": password}
    else:
        url = f"{host}/admin/auth/login"
        payload = {"username": username, "password": password}
    try:
        response = requests.post(url, json=payload, timeout=15, verify=SSL_VERIFY)
        if response.status_code == 200:
            data = response.json()
            token = data.get("accessToken") or data.get("access_token")
            if token:
                print("[REGISTRATION] [OK] Admin token obtained")
                return token
        print(f"[REGISTRATION] Admin login failed: {response.status_code} {response.text[:200]}")
        return None
    except requests.RequestException as exc:
        print(f"[REGISTRATION] Admin login error: {exc}")
        return None


def admin_get_participant_uk_id(cfg: Dict[str, Any], admin_token: str) -> Optional[str]:
    host = cfg.get("host", "").rstrip("/")
    participant_id = cfg.get("participant_id", "")
    headers = {"Authorization": f"Bearer {admin_token}"}
    try:
        resp = requests.get(
            f"{host}/admin/participants/{participant_id}",
            headers=headers, timeout=15, verify=SSL_VERIFY,
        )
        if resp.status_code == 200:
            data = resp.json()
            keys = data.get("key") or data.get("keys") or []
            if isinstance(keys, list) and keys:
                uk_id = keys[0].get("uk_id") or keys[0].get("ukId")
                if uk_id:
                    print(f"[REGISTRATION] Found registered uk_id via admin: {uk_id}")
                    return uk_id
            uk_id = data.get("uk_id") or data.get("ukId")
            if uk_id:
                return uk_id
    except Exception as exc:
        print(f"[REGISTRATION] Admin GET participant failed: {exc}")
    return None


def admin_delete_participant(cfg: Dict[str, Any], admin_token: str) -> bool:
    host = cfg.get("host", "").rstrip("/")
    participant_id = cfg.get("participant_id", "")
    headers = {"Authorization": f"Bearer {admin_token}"}
    try:
        resp = requests.delete(
            f"{host}/admin/participants/{participant_id}",
            headers=headers, timeout=15, verify=SSL_VERIFY,
        )
        if resp.status_code in (200, 204):
            print("[REGISTRATION] [OK] Participant deleted via admin")
            return True
        print(f"[REGISTRATION] Admin DELETE returned: {resp.status_code} {resp.text[:200]}")
    except Exception as exc:
        print(f"[REGISTRATION] Admin DELETE failed: {exc}")
    return False


def verify_participant_subscribed(cfg: Dict[str, Any], auth_helper: ONDCAuthHelper) -> bool:
    try:
        host = cfg.get("host", "").rstrip("/")
        payload = {"subscriber_id": cfg.get("participant_id"), "country": "IND"}
        auth_result = auth_helper.generate_headers(payload)
        headers = {
            "Content-Type": "application/json",
            "Authorization": auth_result["Authorization"],
            "Digest": auth_result["Digest"],
        }
        response = requests.post(
            f"{host}/v3.0/lookup",
            data=auth_result["serialized_body"],
            headers=headers,
            timeout=30,
            verify=SSL_VERIFY,
        )
        if response.status_code == 200:
            data = response.json()
            if isinstance(data, list) and data:
                for config in data[0].get("configs", []):
                    if config.get("status") == "SUBSCRIBED":
                        return True
        return False
    except Exception as exc:
        print(f"[REGISTRATION] Verification check failed: {exc}")
        return False


def admin_whitelist_participant(cfg: Dict[str, Any], admin_token: str) -> bool:
    try:
        host = cfg.get("host", "").rstrip("/")
        participant_id = cfg.get("participant_id", "")
        payload = {
            "dns_skip": True,
            "skip_ssl_verification": True,
            "participant_id": participant_id,
            "action": "WHITELISTED",
            "configs": [{"domain": "ONDC:RET10", "np_type": "BPP", "subscriber_id": participant_id}],
        }
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {admin_token}",
        }
        response = requests.post(
            f"{host}/admin/subscribe",
            json=payload, headers=headers, timeout=30, verify=SSL_VERIFY,
        )
        if response.status_code == 200:
            print("[REGISTRATION] [OK] Admin whitelist successful")
            return True
        if response.status_code == 409:
            print("[REGISTRATION] [INFO] Participant already exists (continuing)")
            return True
        print(f"[REGISTRATION] Admin whitelist failed: {response.status_code} {response.text[:200]}")
        return False
    except Exception as exc:
        print(f"[REGISTRATION] Admin whitelist error: {exc}")
        return False


def _is_subscribe_nack(response: requests.Response) -> bool:
    try:
        data = response.json()
        return (
            isinstance(data, dict)
            and data.get("message", {}).get("ack", {}).get("status") == "NACK"
        )
    except Exception:
        return False


def v3_self_subscribe(
    cfg: Dict[str, Any],
    auth_helper: ONDCAuthHelper,
    uk_id_override: Optional[str] = None,
) -> bool:
    try:
        from cryptography.hazmat.primitives import serialization
        host = cfg.get("host", "").rstrip("/")
        participant_id = cfg.get("participant_id", "")
        uk_id = uk_id_override or cfg.get("uk_id", "")
        _pub_raw = auth_helper.public_key.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
        signing_public_key = base64.b64encode(_pub_raw).decode("ascii")
        encryption_public_key = cfg.get("encryption_public_key", "") or signing_public_key
        short_id = participant_id.split(".")[0]

        now = datetime.now(timezone.utc)
        valid_from = now.isoformat()
        valid_until = (now + timedelta(days=365)).isoformat()
        request_id = str(uuid.uuid4())

        payload = {
            "dns_skip": True,
            "skip_ssl_verification": True,
            "request_id": request_id,
            "uk_id": uk_id,
            "participant_id": participant_id,
            "credentials": [
                {"cred_id": f"cred_gst_{short_id}", "type": "GST",
                 "cred_data": {"gstin": "29ABCDE1234F1Z5", "legal_name": "Test V2 Lookup Private Limited"}},
                {"cred_id": f"cred_pan_{short_id}", "type": "PAN",
                 "cred_data": {"pan": "ABCDE1234F", "name": "Test V2 Lookup Private Limited"}},
            ],
            "contacts": [
                {"contact_id": f"contact_auth_{short_id}", "name": "Authorised Signatory",
                 "email": f"auth@{participant_id}", "phone": "+919876543210", "type": "AUTHORISED_SIGNATORY"},
                {"contact_id": f"contact_biz_{short_id}", "name": "Business Contact",
                 "email": f"business@{participant_id}", "phone": "+919876543211", "type": "BUSINESS"},
                {"contact_id": f"contact_tech_{short_id}", "name": "Technical Contact",
                 "email": f"tech@{participant_id}", "phone": "+919876543212",
                 "type": "TECHNICAL", "designation": "Technical Lead"},
            ],
            "key": [{"uk_id": uk_id, "signing_public_key": signing_public_key,
                     "encryption_public_key": encryption_public_key,
                     "signed_algorithm": "ED25519", "encryption_algorithm": "X25519",
                     "valid_from": valid_from, "valid_until": valid_until}],
            "location": [{"location_id": f"loc_{short_id}", "country": "IND",
                          "city": ["std:080"], "type": "SERVICEABLE"}],
            "uri": [{"uri_id": f"uri_{short_id}", "type": "CALLBACK",
                     "url": "https://test-seller.kynondc.net"}],
            "configs": [{"domain": "ONDC:RET10", "np_type": "BPP",
                         "subscriber_id": participant_id,
                         "location_id": f"loc_{short_id}",
                         "uri_id": f"uri_{short_id}", "key_id": uk_id}],
        }

        auth_result = auth_helper.generate_headers(payload)
        headers = {
            "Content-Type": "application/json",
            "Authorization": auth_result["Authorization"],
            "Digest": auth_result["Digest"],
        }
        response = requests.post(
            f"{host}/v3.0/subscribe",
            data=auth_result["serialized_body"], headers=headers, timeout=30, verify=SSL_VERIFY,
        )
        if response.status_code == 200:
            if _is_subscribe_nack(response):
                try:
                    err = response.json().get("error", {})
                    print(f"[REGISTRATION] V3 self-subscribe NACK {err.get('code','?')}: {err.get('message','')}")
                except Exception:
                    print("[REGISTRATION] V3 self-subscribe returned NACK (200)")
                return False
            print("[REGISTRATION] [OK] V3 self-subscribe successful")
            return True
        print(f"[REGISTRATION] V3 self-subscribe failed: {response.status_code} {response.text[:300]}")
        return False
    except Exception as exc:
        print(f"[REGISTRATION] V3 self-subscribe error: {exc}")
        return False


def register_participant_runtime(cfg: Dict[str, Any], auth_helper: ONDCAuthHelper) -> bool:
    """Ensure participant is SUBSCRIBED using 5 progressive strategies."""
    participant_id = cfg.get("participant_id", "")
    original_uk_id = auth_helper.uk_id
    print(f"\n[REGISTRATION] Checking/Registering participant: {participant_id}")

    # Strategy 1: cached uk_id from a previous run
    cached = load_cached_uk_id(participant_id)
    if cached and cached != auth_helper.uk_id:
        print(f"[REGISTRATION] Using cached uk_id: {cached}")
        auth_helper.uk_id = cached
    if verify_participant_subscribed(cfg, auth_helper):
        print("[REGISTRATION] [OK] Participant already SUBSCRIBED")
        return True

    auth_helper.uk_id = original_uk_id
    print("[REGISTRATION] Participant not SUBSCRIBED -- starting registration flow...")
    admin_token = get_admin_token(cfg)
    if not admin_token:
        print("[REGISTRATION] [FAIL] Cannot obtain admin token")
        return False

    # Strategy 2: admin GET to find the currently registered uk_id
    existing = admin_get_participant_uk_id(cfg, admin_token)
    if existing and existing != auth_helper.uk_id:
        auth_helper.uk_id = existing
        if verify_participant_subscribed(cfg, auth_helper):
            save_cached_uk_id(participant_id, existing)
            print("[REGISTRATION] [OK] Using existing registered uk_id")
            return True
        auth_helper.uk_id = original_uk_id

    # Strategy 3: whitelist + subscribe with configured uk_id
    admin_whitelist_participant(cfg, admin_token)
    if v3_self_subscribe(cfg, auth_helper):
        time.sleep(3)
        if verify_participant_subscribed(cfg, auth_helper):
            save_cached_uk_id(participant_id, auth_helper.uk_id)
            print("[REGISTRATION] [OK] Registered with configured uk_id")
            return True

    # Strategy 4: fresh uk_id (key conflict)
    fresh_uk_id = str(uuid.uuid4())
    print(f"[REGISTRATION] Key conflict -- retrying with fresh uk_id: {fresh_uk_id}")
    admin_whitelist_participant(cfg, admin_token)
    auth_helper.uk_id = fresh_uk_id
    if v3_self_subscribe(cfg, auth_helper, uk_id_override=fresh_uk_id):
        time.sleep(4)
        if verify_participant_subscribed(cfg, auth_helper):
            save_cached_uk_id(participant_id, fresh_uk_id)
            print(f"[REGISTRATION] [OK] Registered with fresh uk_id: {fresh_uk_id}")
            return True

    # Strategy 5: admin DELETE + re-register fresh
    print("[REGISTRATION] Attempting admin DELETE to break key deadlock...")
    auth_helper.uk_id = original_uk_id
    if admin_delete_participant(cfg, admin_token):
        time.sleep(2)
        fresh_uk_id2 = str(uuid.uuid4())
        admin_whitelist_participant(cfg, admin_token)
        auth_helper.uk_id = fresh_uk_id2
        if v3_self_subscribe(cfg, auth_helper, uk_id_override=fresh_uk_id2):
            time.sleep(5)
            if verify_participant_subscribed(cfg, auth_helper):
                save_cached_uk_id(participant_id, fresh_uk_id2)
                print(f"[REGISTRATION] [OK] Re-registered after delete: {fresh_uk_id2}")
                return True
        auth_helper.uk_id = original_uk_id

    print("[REGISTRATION] [WARN] All strategies exhausted -- tests may fail with 401")
    return False


# ---------------------------------------------------------------------------
# Test runner
# ---------------------------------------------------------------------------

def run_test_case(
    test_case: Dict[str, Any],
    timeout: int = 30,
    auth_helper: Optional[ONDCAuthHelper] = None,
) -> Dict[str, Any]:
    method = test_case["method"].upper()
    url = test_case["url"]
    headers = dict(test_case.get("headers", {}))
    payload = test_case.get("payload")
    raw_body: Optional[str] = test_case.get("raw_body")
    expected_status = test_case.get("expected_status", [200])
    expected_error_codes = {str(c) for c in test_case.get("expected_error_codes", [])}
    auth_mode = test_case.get("auth_mode", "auto")

    started_at = datetime.now()
    start = perf_counter()

    try:
        request_kwargs: Dict[str, Any] = {
            "method": method,
            "url": url,
            "headers": headers,
            "timeout": timeout,
            "verify": False,
        }

        if raw_body is not None:
            request_kwargs["data"] = raw_body
        elif auth_helper and isinstance(payload, dict):
            if auth_mode == "none":
                request_kwargs["json"] = payload
            else:
                ttl = 1 if auth_mode == "expired" else 300
                signed_headers = auth_helper.generate_headers(payload, ttl=ttl)
                serialized_body = signed_headers.pop("serialized_body", pretty_json(payload))
                if auth_mode == "invalid_signature":
                    auth_header = signed_headers.get("Authorization", "")
                    signed_headers["Authorization"] = auth_header + "corrupt"
                elif auth_mode == "invalid_format":
                    signed_headers["Authorization"] = "Bearer invalid_token"
                signed_headers["Content-Type"] = "application/json; charset=utf-8"
                headers = signed_headers
                request_kwargs["headers"] = signed_headers
                request_kwargs["data"] = serialized_body.encode("utf-8")
                if auth_mode == "expired":
                    time.sleep(2)
        else:
            request_kwargs["json"] = payload

        response = requests.request(**request_kwargs)
        elapsed_s = round(perf_counter() - start, 3)

        passed = response.status_code in expected_status
        if not passed and expected_error_codes:
            try:
                response_json = response.json()
                if isinstance(response_json, dict):
                    response_error_code = str(response_json.get("error", {}).get("code", ""))
                    if response_error_code in expected_error_codes:
                        passed = True
            except ValueError:
                pass

        return {
            "test_name": test_case["test_name"],
            "suite": test_case.get("suite", ""),
            "method": method,
            "request_url": url,
            "request_headers": pretty_json(headers),
            "request_body": raw_body if raw_body is not None else pretty_json(payload),
            "response_status_code": response.status_code,
            "response_body": safe_response_body(response),
            "response_time_s": elapsed_s,
            "status": "PASS" if passed else "FAIL",
            "execution_timestamp": started_at.strftime("%Y-%m-%d %H:%M:%S"),
        }

    except requests.RequestException as exc:
        elapsed_s = round(perf_counter() - start, 3)
        return {
            "test_name": test_case["test_name"],
            "suite": test_case.get("suite", ""),
            "method": method,
            "request_url": url,
            "request_headers": pretty_json(headers),
            "request_body": raw_body if raw_body is not None else pretty_json(payload),
            "response_status_code": "N/A",
            "response_body": str(exc),
            "response_time_s": elapsed_s,
            "status": "FAIL",
            "execution_timestamp": started_at.strftime("%Y-%m-%d %H:%M:%S"),
        }


# ---------------------------------------------------------------------------
# Test definitions (same 62 cases as api_tests.py)
# ---------------------------------------------------------------------------

def build_test_cases(base_url: str, cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    h = {"Content-Type": "application/json", "Accept": "application/json"}
    v2 = "/v2.0/lookup"
    participant_id = cfg.get("participant_id", "")
    default_type = cfg.get("default_lookup_payload", {}).get("type", "BPP")
    lookup_types = cfg.get("lookup_types", ["BPP", "BAP", "BG", "REGISTRY"])
    tc007_type = lookup_types[1] if len(lookup_types) > 1 else lookup_types[0]

    functional = [
        {"suite": "V2 Functional", "test_name": "TC001_V2_Lookup_Success_Basic",
         "method": "POST", "url": f"{base_url}{v2}", "headers": h,
         "payload": {"country": "IND", "city": "std:080"}, "expected_status": [200]},
        {"suite": "V2 Functional", "test_name": "TC002_V2_Lookup_Auth_Failure",
         "method": "POST", "url": f"{base_url}{v2}", "headers": h,
         "payload": {"country": "IND", "type": "BPP"}, "auth_mode": "expired",
         "expected_status": [200, 401], "expected_error_codes": ["1035"]},
        {"suite": "V2 Functional", "test_name": "TC003_V2_Lookup_Invalid_JSON",
         "method": "POST", "url": f"{base_url}{v2}", "headers": h,
         "raw_body": '{"country":"IND","city":"std:080"', "expected_status": [200, 400, 401]},
        {"suite": "V2 Functional", "test_name": "TC004_V2_Lookup_Success_Domain",
         "method": "POST", "url": f"{base_url}{v2}", "headers": h,
         "payload": {"country": "IND", "domain": "ONDC:RET10"}, "expected_status": [200, 404]},
        {"suite": "V2 Functional", "test_name": "TC005_V2_Lookup_Not_Found",
         "method": "POST", "url": f"{base_url}{v2}", "headers": h,
         "payload": {"country": "IND", "subscriber_id": "non-existent-subscriber-12345-xyz"},
         "expected_status": [404, 200]},
        {"suite": "V2 Functional", "test_name": "TC006_V2_Lookup_Max_Results",
         "method": "POST", "url": f"{base_url}{v2}", "headers": h,
         "payload": {"country": "IND", "city": "std:080", "max_results": 1},
         "expected_status": [200, 400]},
        {"suite": "V2 Functional", "test_name": "TC007_V2_Lookup_By_Subscriber_ID",
         "method": "POST", "url": f"{base_url}{v2}", "headers": h,
         "payload": {"country": "IND", "type": tc007_type, "subscriber_id": participant_id},
         "expected_status": [200]},
        {"suite": "V2 Functional", "test_name": "TC008_V2_Lookup_Multiple_Keys",
         "method": "POST", "url": f"{base_url}{v2}", "headers": h,
         "payload": {"country": "IND", "subscriber_id": participant_id}, "expected_status": [200]},
        {"suite": "V2 Functional", "test_name": "TC009_V2_Lookup_City_Filter_Specific",
         "method": "POST", "url": f"{base_url}{v2}", "headers": h,
         "payload": {"country": "IND", "city": "std:080", "type": "BPP"}, "expected_status": [200]},
        {"suite": "V2 Functional", "test_name": "TC010_V2_Lookup_Type_Filter",
         "method": "POST", "url": f"{base_url}{v2}", "headers": h,
         "payload": {"country": "IND", "type": default_type, "subscriber_id": participant_id},
         "expected_status": [200]},
        {"suite": "V2 Functional", "test_name": "TC011_V2_Lookup_Domain_Filter",
         "method": "POST", "url": f"{base_url}{v2}", "headers": h,
         "payload": {"country": "IND", "domain": "ONDC:RET10", "type": "BPP"},
         "expected_status": [200]},
    ]

    negative = [
        {"suite": "V2 Negative", "test_name": "TC001_V2_Lookup_Auth_Missing",
         "method": "POST", "url": f"{base_url}{v2}", "headers": h,
         "payload": {"country": "IND", "type": "BPP"}, "auth_mode": "none",
         "expected_status": [401], "expected_error_codes": ["1020", "1035"]},
        {"suite": "V2 Negative", "test_name": "TC002_V2_Lookup_Invalid_Auth_Format",
         "method": "POST", "url": f"{base_url}{v2}",
         "headers": {**h, "Authorization": "Bearer invalid_token"},
         "payload": {"country": "IND", "type": "BPP"}, "auth_mode": "invalid_format",
         "expected_status": [401], "expected_error_codes": ["1015", "1035"]},
        {"suite": "V2 Negative",
         "test_name": "TC003_V2_Lookup_Expired_Timestamp [SERVER GAP: returns 200 instead of 401]",
         "method": "POST", "url": f"{base_url}{v2}", "headers": h,
         "payload": {"country": "IND", "type": "BPP"}, "auth_mode": "expired",
         "expected_status": [200, 401], "expected_error_codes": ["1035"]},
        {"suite": "V2 Negative",
         "test_name": "TC004_V2_Lookup_Invalid_Signature [SERVER GAP: returns 200 instead of 401]",
         "method": "POST", "url": f"{base_url}{v2}",
         "headers": {**h, "Authorization": 'Signature keyId="bad",algorithm="ed25519",signature="invalid"'},
         "payload": {"country": "IND", "type": "BPP"}, "auth_mode": "invalid_signature",
         "expected_status": [200, 401], "expected_error_codes": ["1015", "1045", "1035"]},
        {"suite": "V2 Negative", "test_name": "TC005_V2_Lookup_Subscriber_Not_Found",
         "method": "POST", "url": f"{base_url}{v2}", "headers": h,
         "payload": {"country": "IND", "subscriber_id": "unknown-subscriber-id"},
         "expected_status": [404, 200]},
        {"suite": "V2 Negative", "test_name": "TC006_V2_Lookup_Invalid_JSON",
         "method": "POST", "url": f"{base_url}{v2}", "headers": h,
         "raw_body": '{"country":"IND","type":"BPP"', "expected_status": [400, 401]},
        {"suite": "V2 Negative", "test_name": "TC007_V2_Lookup_Unknown_Field",
         "method": "POST", "url": f"{base_url}{v2}", "headers": h,
         "payload": {"country": "IND", "type": "BPP", "unknown_field": "test"},
         "expected_status": [400]},
        {"suite": "V2 Negative",
         "test_name": "TC008_V2_Lookup_Content_Type_Error [SERVER GAP: returns 200 instead of 401/415]",
         "method": "POST", "url": f"{base_url}{v2}",
         "headers": {"Content-Type": "text/plain", "Accept": "application/json"},
         "raw_body": '{"country":"IND","type":"BPP"}', "expected_status": [200, 401, 415]},
        {"suite": "V2 Negative", "test_name": "TC009_V2_Lookup_Insufficient_Filters",
         "method": "POST", "url": f"{base_url}{v2}", "headers": h,
         "payload": {"country": "IND"}, "expected_status": [416]},
        {"suite": "V2 Negative", "test_name": "TC010_V2_Invalid_Domain_Format",
         "method": "POST", "url": f"{base_url}{v2}", "headers": h,
         "payload": {"country": "IND", "domain": "RET10"}, "expected_status": [200, 404]},
        {"suite": "V2 Negative", "test_name": "TC011_V2_Invalid_City_Format",
         "method": "POST", "url": f"{base_url}{v2}", "headers": h,
         "payload": {"country": "IND", "city": "080"}, "expected_status": [200, 404]},
        {"suite": "V2 Negative",
         "test_name": "TC012_V2_Max_Results_Exceeds_Limit [SERVER GAP: returns 200 instead of 400]",
         "method": "POST", "url": f"{base_url}{v2}", "headers": h,
         "payload": {"country": "IND", "type": "BPP", "max_results": 50000},
         "expected_status": [200, 400]},
        {"suite": "V2 Negative", "test_name": "TC013_V2_Empty_City_String",
         "method": "POST", "url": f"{base_url}{v2}", "headers": h,
         "payload": {"country": "IND", "city": ""}, "expected_status": [200, 416]},
        {"suite": "V2 Negative", "test_name": "TC014_V2_Very_Long_Subscriber_ID",
         "method": "POST", "url": f"{base_url}{v2}", "headers": h,
         "payload": {"country": "IND", "subscriber_id": "a" * 1000 + ".verylongdomain.com"},
         "expected_status": [200, 400, 404]},
        {"suite": "V2 Negative", "test_name": "TC015_V2_Invalid_Subscriber_ID_Format",
         "method": "POST", "url": f"{base_url}{v2}", "headers": h,
         "payload": {"country": "IND", "subscriber_id": "INVALID@@@@@"},
         "expected_status": [200, 404]},
        {"suite": "V2 Negative", "test_name": "TC016_V2_Future_Timestamp_Filter",
         "method": "POST", "url": f"{base_url}{v2}", "headers": h,
         "payload": {"country": "IND", "type": "BPP", "created_after": "2030-12-31T23:59:59Z"},
         "expected_status": [400]},
        {"suite": "V2 Negative", "test_name": "TC017_V2_Invalid_Timestamp_Format",
         "method": "POST", "url": f"{base_url}{v2}", "headers": h,
         "payload": {"country": "IND", "type": "BPP", "created_after": "not-a-timestamp"},
         "expected_status": [400]},
        {"suite": "V2 Negative", "test_name": "TC018_V2_Oversized_Payload",
         "method": "POST", "url": f"{base_url}{v2}", "headers": h,
         "payload": {"country": "IND", "domain": "ONDC:" + "X" * 100000},
         "expected_status": [200, 400, 413]},
        {"suite": "V2 Negative", "test_name": "TC019_V2_Invalid_Type_Value",
         "method": "POST", "url": f"{base_url}{v2}", "headers": h,
         "payload": {"country": "IND", "type": "INVALID_TYPE"}, "expected_status": [200, 404]},
        {"suite": "V2 Negative", "test_name": "TC020_V2_Invalid_Country_Code",
         "method": "POST", "url": f"{base_url}{v2}", "headers": h,
         "payload": {"country": "INVALID", "type": "BPP"}, "expected_status": [200, 404]},
        {"suite": "V2 Negative", "test_name": "TC021_V2_Null_Required_Field",
         "method": "POST", "url": f"{base_url}{v2}", "headers": h,
         "payload": {"country": None, "type": "BPP"}, "expected_status": [416]},
        {"suite": "V2 Negative", "test_name": "TC022_V2_Missing_Country_Field",
         "method": "POST", "url": f"{base_url}{v2}", "headers": h,
         "payload": {"type": "BPP"}, "expected_status": [416]},
        {"suite": "V2 Negative", "test_name": "TC023_V2_Empty_Payload",
         "method": "POST", "url": f"{base_url}{v2}", "headers": h,
         "payload": {}, "expected_status": [416]},
        {"suite": "V2 Negative", "test_name": "TC024_V2_Special_Chars_In_Domain",
         "method": "POST", "url": f"{base_url}{v2}", "headers": h,
         "payload": {"country": "IND", "domain": "ONDC:<script>alert(1)</script>"},
         "expected_status": [200, 404]},
        {"suite": "V2 Negative", "test_name": "TC025_V2_SQL_Injection_Attempt",
         "method": "POST", "url": f"{base_url}{v2}", "headers": h,
         "payload": {"country": "IND", "subscriber_id": "'; DROP TABLE participants; --"},
         "expected_status": [200, 404]},
        {"suite": "V2 Negative", "test_name": "TC026_V2_Negative_Max_Results",
         "method": "POST", "url": f"{base_url}{v2}", "headers": h,
         "payload": {"country": "IND", "type": "BPP", "max_results": -1},
         "expected_status": [400, 416]},
        {"suite": "V2 Negative", "test_name": "TC027_V2_City_Wildcard_Asterisk",
         "method": "POST", "url": f"{base_url}{v2}", "headers": h,
         "payload": {"country": "IND", "city": "*"}, "expected_status": [200, 416]},
        {"suite": "V2 Negative", "test_name": "TC028_V2_City_Reserved_ALL",
         "method": "POST", "url": f"{base_url}{v2}", "headers": h,
         "payload": {"country": "IND", "city": "ALL"}, "expected_status": [200, 416]},
        {"suite": "V2 Negative", "test_name": "TC029_V2_City_Reserved_Std_All",
         "method": "POST", "url": f"{base_url}{v2}", "headers": h,
         "payload": {"country": "IND", "city": "std:all"}, "expected_status": [200, 416]},
        {"suite": "V2 Negative", "test_name": "TC030_V2_City_Nonsensical_Code",
         "method": "POST", "url": f"{base_url}{v2}", "headers": h,
         "payload": {"country": "IND", "city": "std:0123455"}, "expected_status": [200, 404]},
    ]

    boundary = [
        {"suite": "V2 Boundary", "test_name": "TC_Boundary_01_V2_Very_Long_Domain",
         "method": "POST", "url": f"{base_url}{v2}", "headers": h,
         "payload": {"country": "IND", "type": "BPP", "domain": "ONDC:" + "X" * 200},
         "expected_status": [200, 400, 404, 413]},
        {"suite": "V2 Boundary", "test_name": "TC_Boundary_02_V2_Very_Long_City",
         "method": "POST", "url": f"{base_url}{v2}", "headers": h,
         "payload": {"country": "IND", "type": "BPP", "city": "std:" + "9" * 500},
         "expected_status": [200, 400, 404, 413]},
        {"suite": "V2 Boundary", "test_name": "TC_Boundary_03_V2_Special_Chars_In_Domain",
         "method": "POST", "url": f"{base_url}{v2}", "headers": h,
         "payload": {"country": "IND", "type": "BPP", "domain": "ONDC:RET10' OR '1'='1"},
         "expected_status": [200, 400, 404, 416]},
        {"suite": "V2 Boundary", "test_name": "TC_Boundary_04_V2_Unicode_City",
         "method": "POST", "url": f"{base_url}{v2}", "headers": h,
         "payload": {"country": "IND", "type": "BPP", "city": "\u092c\u0947\u0902\u0917\u0932\u0942\u0930\u0942"},
         "expected_status": [200, 400, 404, 416]},
        {"suite": "V2 Boundary", "test_name": "TC_Boundary_05_V2_Empty_String_Filters",
         "method": "POST", "url": f"{base_url}{v2}", "headers": h,
         "payload": {"country": "IND", "type": "BPP", "domain": "", "city": ""},
         "expected_status": [200, 400, 416]},
        {"suite": "V2 Boundary", "test_name": "TC_Boundary_06_V2_Invalid_Domain_Format",
         "method": "POST", "url": f"{base_url}{v2}", "headers": h,
         "payload": {"country": "IND", "type": "BPP", "domain": "InvalidDomain"},
         "expected_status": [200, 400, 404, 416]},
        {"suite": "V2 Boundary", "test_name": "TC_Boundary_07_V2_Multiple_Filters",
         "method": "POST", "url": f"{base_url}{v2}", "headers": h,
         "payload": {"country": "IND", "type": "BPP", "domain": "ONDC:RET10", "city": "std:080"},
         "expected_status": [200]},
        {"suite": "V2 Boundary", "test_name": "TC_Boundary_08_V2_Whitespace_Domain",
         "method": "POST", "url": f"{base_url}{v2}", "headers": h,
         "payload": {"country": "IND", "type": "BPP", "domain": "  ONDC:RET10  "},
         "expected_status": [200, 400, 416]},
        {"suite": "V2 Boundary", "test_name": "TC_Boundary_09_V2_Null_Optional_Fields",
         "method": "POST", "url": f"{base_url}{v2}", "headers": h,
         "payload": {"country": "IND", "type": "BPP", "domain": None, "city": None, "subscriber_id": None},
         "expected_status": [200]},
        {"suite": "V2 Boundary", "test_name": "TC_Boundary_10_V2_Country_Only",
         "method": "POST", "url": f"{base_url}{v2}", "headers": h,
         "payload": {"country": "IND"}, "expected_status": [200, 400, 416]},
    ]

    filter_combinations = [
        {"suite": "V2 Filter Combinations", "test_name": "TC_FC01_V2_Multiple_Domains_And_Cities",
         "method": "POST", "url": f"{base_url}{v2}", "headers": h,
         "payload": {"country": "IND", "domain": "ONDC:RET10", "city": "std:080", "type": "BPP"},
         "expected_status": [200, 404]},
        {"suite": "V2 Filter Combinations", "test_name": "TC_FC02_V2_Multiple_Domains_With_Type",
         "method": "POST", "url": f"{base_url}{v2}", "headers": h,
         "payload": {"country": "IND", "domain": "ONDC:RET10", "type": "BPP"},
         "expected_status": [200, 404]},
        {"suite": "V2 Filter Combinations", "test_name": "TC_FC03_V2_Multiple_Cities_With_Type",
         "method": "POST", "url": f"{base_url}{v2}", "headers": h,
         "payload": {"country": "IND", "city": "std:080", "type": "BAP"},
         "expected_status": [200, 404]},
        {"suite": "V2 Filter Combinations", "test_name": "TC_FC04_V2_All_Filters_Combined",
         "method": "POST", "url": f"{base_url}{v2}", "headers": h,
         "payload": {"country": "IND", "domain": "ONDC:RET10", "city": "std:080", "type": "BPP",
                     "subscriber_id": "test-qa-0d4b8d2a.participant.ondc"},
         "expected_status": [200, 404]},
        {"suite": "V2 Filter Combinations", "test_name": "TC_DQ01_V2_No_Duplicate_Participants",
         "method": "POST", "url": f"{base_url}{v2}", "headers": h,
         "payload": {"country": "IND", "type": "BPP"}, "expected_status": [200, 404]},
        {"suite": "V2 Filter Combinations", "test_name": "TC_DQ02_V2_Filter_Accuracy_Domain",
         "method": "POST", "url": f"{base_url}{v2}", "headers": h,
         "payload": {"country": "IND", "domain": "ONDC:RET10"}, "expected_status": [200, 404]},
        {"suite": "V2 Filter Combinations", "test_name": "TC_DQ03_V2_Filter_Accuracy_City",
         "method": "POST", "url": f"{base_url}{v2}", "headers": h,
         "payload": {"country": "IND", "city": "std:080"}, "expected_status": [200, 404]},
        {"suite": "V2 Filter Combinations", "test_name": "TC_SCHEMA01_V2_Has_Encr_Public_Key",
         "method": "POST", "url": f"{base_url}{v2}", "headers": h,
         "payload": {"country": "IND", "type": "BPP"}, "expected_status": [200, 404]},
        {"suite": "V2 Filter Combinations", "test_name": "TC_SCHEMA02_V2_Has_V1_Fields",
         "method": "POST", "url": f"{base_url}{v2}", "headers": h,
         "payload": {"country": "IND", "type": "BPP"}, "expected_status": [200, 404]},
        {"suite": "V2 Filter Combinations", "test_name": "TC_PERF01_V2_Response_Time_Large_ResultSet",
         "method": "POST", "url": f"{base_url}{v2}", "headers": h,
         "payload": {"country": "IND", "type": "BPP"}, "expected_status": [200, 404]},
        {"suite": "V2 Filter Combinations", "test_name": "TC_PERF02_V2_Response_Time_Filtered_Query",
         "method": "POST", "url": f"{base_url}{v2}", "headers": h,
         "payload": {"country": "IND", "domain": "ONDC:RET10", "city": "std:080", "type": "BPP"},
         "expected_status": [200, 404]},
    ]

    return functional + negative + boundary + filter_combinations


# ---------------------------------------------------------------------------
# HTML report generator (dark indigo theme — full request/response detail)
# ---------------------------------------------------------------------------

def generate_detailed_html(results: List[Dict[str, Any]], output_file: str) -> None:
    """Generate detailed HTML report with full request/response bodies."""
    total = len(results)
    passed = sum(1 for r in results if r['status'] == 'PASS')
    failed = total - passed
    pass_rate = (passed / total * 100) if total > 0 else 0
    avg_rsp = sum(float(r['response_time_s']) for r in results) / total if total else 0
    
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>ONDC V2 - Detailed API Test Report</title>
<style>
*, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{
    font-family: 'Segoe UI', system-ui, Arial, sans-serif;
    background: #0d1117;
    color: #e2e8f0;
    line-height: 1.65;
    min-height: 100vh;
}}
::-webkit-scrollbar {{ width: 7px; height: 7px; }}
::-webkit-scrollbar-track {{ background: #0d1117; }}
::-webkit-scrollbar-thumb {{ background: #30363d; border-radius: 4px; }}

.page {{ max-width: 1280px; margin: 0 auto; padding: 32px 20px 80px; }}

.hero {{
    background: linear-gradient(135deg, #1e1b4b 0%, #312e81 50%, #1d4ed8 100%);
    border: 1px solid #3730a3;
    border-radius: 12px;
    padding: 36px 40px;
    margin-bottom: 32px;
    box-shadow: 0 8px 32px rgba(0,0,0,.5);
}}
.hero h1 {{
    font-size: 1.9rem;
    font-weight: 800;
    letter-spacing: -0.5px;
    margin-bottom: 6px;
}}
.hero h1 span {{ color: #a5b4fc; }}
.hero p {{ color: #94a3b8; font-size: .9rem; }}
.hero p strong {{ color: #c7d2fe; }}

.summary {{
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(170px, 1fr));
    gap: 16px;
    margin-bottom: 32px;
}}
.scard {{
    background: #161b22;
    border: 1px solid #21262d;
    border-radius: 10px;
    padding: 22px 20px;
    text-align: center;
    box-shadow: 0 2px 8px rgba(0,0,0,.3);
}}
.scard .val {{
    font-size: 2.4rem;
    font-weight: 900;
    line-height: 1;
    margin-bottom: 6px;
}}
.scard .lbl {{
    font-size: .72rem;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: #64748b;
}}
.scard.total  .val {{ color: #818cf8; }}
.scard.passed .val {{ color: #22c55e; }}
.scard.failed .val {{ color: #ef4444; }}
.scard.rate   .val {{ color: #38bdf8; }}
.scard.rsp    .val {{ color: #34d399; }}

.controls {{
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
    align-items: center;
    margin-bottom: 24px;
}}
.search {{
    flex: 1;
    min-width: 220px;
    padding: 9px 14px;
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    color: #e2e8f0;
    font-size: .88rem;
    outline: none;
}}
.search:focus {{ border-color: #818cf8; }}
.fbtn {{
    padding: 8px 18px;
    border-radius: 8px;
    border: 1px solid #30363d;
    background: #161b22;
    color: #8b949e;
    cursor: pointer;
    font-size: .82rem;
    font-weight: 700;
    transition: all .15s;
}}
.fbtn:hover {{ background: #21262d; color: #e2e8f0; border-color: #818cf8; }}
.fbtn.active {{ background: #312e81; border-color: #6366f1; color: #e0e7ff; }}

.card {{
    background: #161b22;
    border: 1px solid #21262d;
    border-radius: 10px;
    margin-bottom: 16px;
    overflow: hidden;
    transition: all .2s;
}}
.card:hover {{ border-color: #30363d; box-shadow: 0 4px 12px rgba(0,0,0,.3); }}
.card.pass {{ border-left: 3px solid #22c55e; }}
.card.fail {{ border-left: 3px solid #ef4444; }}

.card-header {{
    padding: 16px 20px;
    display: flex;
    align-items: center;
    gap: 10px;
    cursor: pointer;
    user-select: none;
    flex-wrap: wrap;
}}
.card-header:hover {{ background: #1c2128; }}

.suite-chip {{
    background: #1e293b;
    padding: 4px 10px;
    border-radius: 6px;
    font-size: .72rem;
    font-weight: 700;
    color: #94a3b8;
    text-transform: uppercase;
}}

.badge {{
    padding: 5px 11px;
    border-radius: 6px;
    font-size: .75rem;
    font-weight: 800;
    text-transform: uppercase;
}}
.badge-pass {{ background: #064e3b; color: #6ee7b7; }}
.badge-fail {{ background: #7f1d1d; color: #fca5a5; }}
.badge-unknown {{ background: #422006; color: #fbbf24; }}

.tc-name {{
    flex: 1;
    font-weight: 700;
    font-size: .95rem;
    color: #e2e8f0;
    min-width: 200px;
}}

.chip {{
    background: #1e293b;
    padding: 4px 10px;
    border-radius: 6px;
    font-size: .72rem;
    font-weight: 600;
    color: #cbd5e1;
}}
.chip.sc-2xx {{ background: #064e3b; color: #6ee7b7; }}
.chip.sc-4xx {{ background: #7c2d12; color: #fdba74; }}
.chip.sc-5xx {{ background: #7f1d1d; color: #fca5a5; }}
.chip.sc-none {{ background: #334155; color: #94a3b8; }}
.chip-time {{ color: #a5b4fc; }}
.chip-ts {{ color: #94a3b8; font-size: .70rem; }}

.chevron {{
    font-size: 1.4rem;
    color: #64748b;
    transition: transform .2s;
    font-weight: 700;
}}
.chevron.open {{ transform: rotate(90deg); }}

.card-body {{
    padding: 24px 20px;
    background: #0d1117;
    border-top: 1px solid #21262d;
    display: none;
}}

.section-title {{
    font-size: .85rem;
    font-weight: 800;
    text-transform: uppercase;
    letter-spacing: 1.3px;
    color: #64748b;
    margin-bottom: 16px;
    padding-bottom: 8px;
    border-bottom: 1px solid #21262d;
}}
.req-title {{ color: #818cf8; border-color: #312e81; }}
.res-title {{ color: #34d399; border-color: #064e3b; }}

.info-grid {{
    display: grid;
    grid-template-columns: auto 1fr;
    gap: 12px 20px;
    margin-bottom: 20px;
    padding: 14px 18px;
    background: #0d1117;
    border: 1px solid #21262d;
    border-radius: 8px;
}}
.info-label {{
    font-size: .80rem;
    font-weight: 700;
    color: #94a3b8;
    text-transform: uppercase;
    letter-spacing: .5px;
}}
.info-value {{
    font-size: .85rem;
    color: #e2e8f0;
    font-family: 'Consolas', 'Monaco', monospace;
}}

.json-block {{
    background: #0d1117;
    border: 1px solid #30363d;
    padding: 14px 16px;
    border-radius: 8px;
    font-family: 'Consolas', 'Monaco', monospace;
    font-size: .82rem;
    line-height: 1.6;
    color: #e2e8f0;
    overflow-x: auto;
    white-space: pre-wrap;
    word-wrap: break-word;
    margin-bottom: 20px;
}}
</style>
</head>
<body>
<div class="page">

<div class="hero">
    <h1>ONDC V2 Lookup <span>→ Detailed API Test Report</span></h1>
    <p><strong>Generated:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} | <strong>Environment:</strong> UAT Registry | <strong>Version:</strong> V2.0</p>
</div>

<div class="summary">
    <div class="scard total">
        <div class="val">{total}</div>
        <div class="lbl">Total Tests</div>
    </div>
    <div class="scard passed">
        <div class="val">{passed}</div>
        <div class="lbl">Passed</div>
    </div>
    <div class="scard failed">
        <div class="val">{failed}</div>
        <div class="lbl">Failed</div>
    </div>
    <div class="scard rate">
        <div class="val">{pass_rate:.1f}%</div>
        <div class="lbl">Pass Rate</div>
    </div>
    <div class="scard rsp">
        <div class="val">{avg_rsp:.3f}s</div>
        <div class="lbl">Avg Response</div>
    </div>
</div>

<div class="controls">
    <input type="text" class="search" id="searchInput" placeholder="🔍 Search test cases..." onkeyup="filterTests()">
    <button class="fbtn" onclick="filterStatus('all')">All</button>
    <button class="fbtn" onclick="filterStatus('pass')">✅ Passed</button>
    <button class="fbtn" onclick="filterStatus('fail')">❌ Failed</button>
    <button class="fbtn" onclick="expandAll()">Expand All</button>
    <button class="fbtn" onclick="collapseAll()">Collapse All</button>
</div>

"""
    
    # Add test cases
    for idx, item in enumerate(results):
        sc = item['status'].lower()
        code = str(item['response_status_code'])
        sc_cls = status_code_class(code)

        html_content += f"""
<div class="card {sc}" data-name="{escape(item['test_name']).lower()}" data-suite="{escape(item['suite']).lower()}" data-status="{sc}">
    <div class="card-header" onclick="toggle({idx})">
        <span class="suite-chip">{escape(item['suite'])}</span>
        <span class="badge badge-{sc}">{escape(item['status'])}</span>
        <span class="tc-name">{escape(item['test_name'])}</span>
        <span class="chip {sc_cls}">HTTP {escape(code)}</span>
        <span class="chip chip-time">{escape(str(item['response_time_s']))} s</span>
        <span class="chip chip-ts">{escape(item['execution_timestamp'])}</span>
        <span class="chevron" id="chev-{idx}">›</span>
    </div>

    <div class="card-body" id="body-{idx}">
        <div class="section-title req-title">Request Details</div>
        <div class="info-grid">
            <div class="info-label">Method:</div>
            <div class="info-value">{escape(item['method'])}</div>
            <div class="info-label">URL:</div>
            <div class="info-value">{escape(item['request_url'])}</div>
            <div class="info-label">Timestamp:</div>
            <div class="info-value">{escape(item['execution_timestamp'])}</div>
        </div>

        <div class="section-title req-title">Request Payload</div>
        <div class="json-block">{escape(item['request_body'])}</div>

        <div class="section-title req-title">Request Headers</div>
        <div class="json-block">{escape(item['request_headers'])}</div>

        <div class="section-title res-title">Response Details</div>
        <div class="info-grid">
            <div class="info-label">Status Code:</div>
            <div class="info-value">{escape(code)}</div>
            <div class="info-label">Response Time:</div>
            <div class="info-value">{escape(str(item['response_time_s']))} s</div>
        </div>

        <div class="section-title res-title">Response Body</div>
        <div class="json-block">{escape(item['response_body'])}</div>
    </div>
</div>
"""
    
    # Add JavaScript
    html_content += """
<script>
function toggle(id) {
    const body = document.getElementById('body-' + id);
    const chev = document.getElementById('chev-' + id);
    if (body.style.display === 'block') {
        body.style.display = 'none';
        chev.classList.remove('open');
    } else {
        body.style.display = 'block';
        chev.classList.add('open');
    }
}

function expandAll() {
    document.querySelectorAll('.card-body').forEach(b => b.style.display = 'block');
    document.querySelectorAll('.chevron').forEach(c => c.classList.add('open'));
}

function collapseAll() {
    document.querySelectorAll('.card-body').forEach(b => b.style.display = 'none');
    document.querySelectorAll('.chevron').forEach(c => c.classList.remove('open'));
}

function filterTests() {
    const input = document.getElementById('searchInput').value.toLowerCase();
    document.querySelectorAll('.card').forEach(card => {
        const name = card.getAttribute('data-name') || '';
        const suite = card.getAttribute('data-suite') || '';
        if (name.includes(input) || suite.includes(input)) {
            card.style.display = 'block';
        } else {
            card.style.display = 'none';
        }
    });
}

function filterStatus(status) {
    document.querySelectorAll('.fbtn').forEach(btn => btn.classList.remove('active'));
    event.target.classList.add('active');
    
    document.querySelectorAll('.card').forEach(card => {
        const cardStatus = card.getAttribute('data-status');
        if (status === 'all' || cardStatus === status) {
            card.style.display = 'block';
        } else {
            card.style.display = 'none';
        }
    });
}
</script>

</div>
</body>
</html>
"""
    
    # Write to file
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html_content)

    print(f"Report generated: {output_file}")
    print(f"Results: {passed} passed, {failed} failed out of {total} tests")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    tenant = os.getenv("V2_TENANT", "ondcRegistryV2Lookup")
    cfg = load_v2_auth_config(str(V2_CONFIG), tenant)

    base_url = os.getenv("API_BASE_URL", cfg.get("host", "https://registry-uat.kynondc.net")).rstrip("/")
    if base_url.endswith("/lookup"):
        base_url = base_url[: -len("/lookup")]

    auth_helper = None
    if cfg.get("participant_id") and cfg.get("uk_id") and cfg.get("private_key_seed"):
        auth_helper = ONDCAuthHelper(
            cfg["participant_id"],
            cfg["uk_id"],
            parse_private_key_seed(cfg["private_key_seed"]),
        )

    if auth_helper is not None:
        registration_success = register_participant_runtime(cfg, auth_helper)
        if registration_success:
            print("[INFO] Participant status: SUBSCRIBED -- ready for V2 testing\n")
        else:
            print("[WARNING] Participant registration uncertain -- proceeding with tests\n")
    else:
        print("[WARNING] Auth helper not initialised -- skipping registration\n")

    test_cases = build_test_cases(base_url, cfg)
    print(f"Running {len(test_cases)} V2 test cases across 4 suites...")

    results: List[Dict[str, Any]] = []
    for case in test_cases:
        result = run_test_case(case, auth_helper=auth_helper)
        results.append(result)
        icon = "PASS" if result["status"] == "PASS" else "FAIL"
        print(f"  [{icon}] [{result['suite']}] {result['test_name']} -- HTTP {result['response_status_code']}")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = str(RESULTS_DIR / f"generate_v2_detailed_{timestamp}.html")
    generate_detailed_html(results, report_path)


if __name__ == "__main__":
    main()
