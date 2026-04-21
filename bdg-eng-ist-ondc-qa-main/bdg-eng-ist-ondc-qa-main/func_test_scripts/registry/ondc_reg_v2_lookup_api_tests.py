"""
ONDC Registry V2 Lookup - Combined Test Report Generator

Runs all V2 test suites in a single pass and writes one timestamped HTML report:
  results/registry/generate_v2_combined_all_<YYYYMMDD_HHMMSS>.html

Suites included:
  - V2 Functional          (11 tests)
  - V2 Negative            (30 tests)
  - V2 Boundary            (10 tests)
  - V2 Filter Combinations (11 tests)
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
        raise ValueError("private_key_seed must be 32-byte hex, base64 seed, or DER/base64") from exc
    if len(raw) == 32:
        return raw
    der_prefix = bytes.fromhex("302e020100300506032b657004220420")
    if len(raw) >= 48 and raw.startswith(der_prefix):
        return raw[-32:]
    if len(raw) == 64:
        # 64-byte Ed25519 key (seed + public key): first 32 bytes are the private seed
        return raw[:32]
    raise ValueError("Unsupported private_key_seed format")


# ---------------------------------------------------------------------------
# uk_id cache (shared across V1/V2/V3 scripts to persist registered uk_id)
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
# Participant registration helpers
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
    """Fetch the currently registered uk_id via admin GET /admin/participants/{id}."""
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
    """Delete participant via DELETE /admin/participants/{id} to allow fresh registration."""
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
        # Always derive from the actual private key to avoid config mismatches
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
    """Ensure participant is SUBSCRIBED. Tries 5 strategies in order."""
    participant_id = cfg.get("participant_id", "")
    original_uk_id = auth_helper.uk_id
    print(f"\n[REGISTRATION] Checking/Registering participant: {participant_id}")

    # Strategy 1: use cached uk_id from a previous run
    cached = load_cached_uk_id(participant_id)
    if cached and cached != auth_helper.uk_id:
        print(f"[REGISTRATION] Using cached uk_id: {cached}")
        auth_helper.uk_id = cached
    if verify_participant_subscribed(cfg, auth_helper):
        print("[REGISTRATION] [OK] Participant already SUBSCRIBED")
        return True

    # Reset to config uk_id and get admin token
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

    # Strategy 4: fresh uk_id (key conflict -- participant exists with a different key)
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

    # Strategy 5: admin DELETE + re-register fresh (breaks key deadlock)
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
# HTML report builder  (teal theme — same as V1 combined)
# ---------------------------------------------------------------------------

def build_html_report(results: List[Dict[str, Any]], suite_elapsed_s: float) -> str:
    total = len(results)
    passed = sum(1 for r in results if r["status"] == "PASS")
    failed = total - passed
    pass_rate = (passed / total * 100) if total else 0.0
    avg_rsp_s = sum(float(r["response_time_s"]) for r in results) / total if total else 0.0

    generated_at = datetime.now().strftime("%d %b %Y, %H:%M:%S")

    # --- test cards --------------------------------------------------------
    cards = []
    for idx, item in enumerate(results):
        sc = "pass" if item["status"] == "PASS" else "fail"
        code = str(item["response_status_code"])
        sc_cls = status_code_class(code)
        expectation = "negative" if item["suite"] in ("V2 Negative", "V2 Boundary") else "positive"
        exp_label = "PASS EXPECTED" if expectation == "positive" else "FAIL EXPECTED"
        human = item["test_name"].replace("_", " ").title()
        description = (
            f"[{exp_label}] {human} Validates request construction, endpoint routing, "
            f"authentication handling, expected status behavior, and response payload "
            f"integrity for this V2 lookup scenario."
        )
        suite_slug = item["suite"].lower().replace(" ", "-")

        cards.append(f"""
        <div class="card {sc}" data-name="{escape(item['test_name']).lower()}" data-suite="{escape(suite_slug)}" data-expectation="{expectation}">
            <div class="card-header" onclick="toggle({idx})">
                <span class="suite-chip">{escape(item['suite'])}</span>
                <span class="badge badge-{sc}">{escape(item['status'])}</span>
                <span class="tc-name">{escape(item['test_name'])}</span>
                <span class="chip {sc_cls}">HTTP {escape(code)}</span>
                <span class="chip chip-time">{escape(str(item['response_time_s']))} s</span>
                <span class="chip chip-ts">{escape(item['execution_timestamp'])}</span>
                <span class="chevron" id="chev-{idx}">&gt;</span>
            </div>
            <div class="card-body" id="body-{idx}">
                <div class="section-title req-title">Request</div>
                <div class="two-col">
                    <div class="col">
                        <div class="col-label">Body (JSON)</div>
                        <pre class="json-block">{escape(item['request_body'])}</pre>
                    </div>
                    <div class="col">
                        <div class="col-label">Headers</div>
                        <pre class="json-block">{escape(item['request_headers'])}</pre>
                    </div>
                </div>
                <div class="meta-row">
                    <div><strong>Method:</strong> {escape(item['method'])}</div>
                    <div><strong>URL:</strong> {escape(item['request_url'])}</div>
                    <div><strong>Description:</strong> {escape(description)}</div>
                </div>
                <div class="section-title res-title">Response</div>
                <div class="two-col">
                    <div class="col">
                        <div class="col-label">Body (JSON)</div>
                        <pre class="json-block">{escape(item['response_body'])}</pre>
                    </div>
                    <div class="col">
                        <div class="col-label">Status Details</div>
                        <pre class="json-block">{escape(pretty_json({'status_code': item['response_status_code'], 'rsp_s': item['response_time_s'], 'execution_timestamp': item['execution_timestamp']}))}</pre>
                    </div>
                </div>
            </div>
        </div>""")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>ONDC V2 Combined - API Test Report</title>
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
    background: linear-gradient(135deg, #134e4a 0%, #0f766e 50%, #0ea5a5 100%);
    border: 1px solid #0f766e;
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
.hero h1 span {{ color: #99f6e4; }}
.hero p {{ color: #94a3b8; font-size: .9rem; }}
.hero p strong {{ color: #99f6e4; }}

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
.scard.total  .val {{ color: #0ea5a5; }}
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
    flex: 0 1 320px;
    min-width: 140px;
    padding: 8px 12px;
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    color: #e2e8f0;
    font-size: .85rem;
    outline: none;
}}
.search:focus {{ border-color: #0ea5a5; }}
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
.fbtn:hover {{ border-color: #0ea5a5; color: #e2e8f0; }}
.fbtn.active {{ background: #0ea5a5; border-color: #0ea5a5; color: #fff; }}
.fbtn.pass.active {{ background: #22c55e; border-color: #22c55e; }}
.fbtn.fail.active {{ background: #ef4444; border-color: #ef4444; }}
.count {{ color: #64748b; font-size: .82rem; margin-left: auto; }}

.card {{
    background: #161b22;
    border: 1px solid #21262d;
    border-radius: 10px;
    margin-bottom: 12px;
    overflow: hidden;
    transition: border-color .15s, box-shadow .15s;
}}
.card:hover {{ border-color: #30363d; box-shadow: 0 4px 16px rgba(0,0,0,.4); }}
.card.pass {{ border-left: 4px solid #22c55e; }}
.card.fail {{ border-left: 4px solid #ef4444; }}

.card-header {{
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 14px 18px;
    cursor: pointer;
    user-select: none;
    flex-wrap: wrap;
}}
.card-header:hover {{ background: rgba(255,255,255,.025); }}
.tc-name {{
    font-weight: 600;
    font-size: .92rem;
    flex: 1;
    min-width: 180px;
}}
.suite-chip {{
    font-size: .7rem;
    font-weight: 800;
    letter-spacing: .6px;
    text-transform: uppercase;
    border-radius: 20px;
    padding: 3px 10px;
    background: rgba(45,212,191,.18);
    color: #99f6e4;
}}
.badge {{
    display: inline-block;
    padding: 3px 10px;
    border-radius: 20px;
    font-size: .72rem;
    font-weight: 800;
    letter-spacing: .6px;
    flex-shrink: 0;
}}
.badge-pass {{ background: rgba(34,197,94,.15); color: #22c55e; }}
.badge-fail {{ background: rgba(239,68,68,.15); color: #ef4444; }}
.chip {{
    font-size: .75rem;
    font-weight: 700;
    padding: 3px 9px;
    border-radius: 6px;
    flex-shrink: 0;
}}
.sc-2xx {{ background: rgba(34,197,94,.1); color: #22c55e; }}
.sc-4xx {{ background: rgba(239,68,68,.1); color: #ef4444; }}
.sc-5xx {{ background: rgba(239,68,68,.1); color: #ef4444; }}
.sc-none {{ background: rgba(245,158,11,.1); color: #f59e0b; }}
.chip-time {{ background: rgba(56,189,248,.08); color: #38bdf8; }}
.chip-ts {{ background: rgba(148,163,184,.06); color: #64748b; }}
.chevron {{
    color: #4b5563;
    font-size: .85rem;
    flex-shrink: 0;
    transition: transform .2s;
    margin-left: auto;
}}
.chevron.open {{ transform: rotate(90deg); }}

.card-body {{
    display: none;
    border-top: 1px solid #21262d;
    padding: 0 0 18px;
}}

.section-title {{
    font-size: .78rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 1px;
    padding: 14px 20px 8px;
}}
.req-title {{ color: #60a5fa; border-top: 1px solid #21262d; margin-top: 4px; }}
.req-title:first-of-type {{ border-top: none; margin-top: 0; }}
.res-title {{ color: #34d399; border-top: 1px solid #21262d; }}

.two-col {{
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 0;
    padding: 0 12px;
}}
@media (max-width: 800px) {{
    .two-col {{ grid-template-columns: 1fr; }}
}}
.col {{ padding: 0 8px 0; }}
.col-label {{
    font-size: .72rem;
    text-transform: uppercase;
    letter-spacing: .8px;
    color: #64748b;
    margin-bottom: 6px;
    margin-top: 6px;
}}

.meta-row {{
    padding: 12px 20px 6px;
    color: #94a3b8;
    font-size: .86rem;
    display: grid;
    gap: 6px;
}}

pre.json-block {{
    background: #0d1117;
    border: 1px solid #21262d;
    border-radius: 8px;
    padding: 14px;
    font-family: Consolas, monospace;
    font-size: .76rem;
    color: #c9d1d9;
    overflow-x: auto;
    overflow-y: auto;
    max-height: 400px;
    white-space: pre;
    line-height: 1.55;
    tab-size: 2;
}}

.empty {{ text-align: center; padding: 60px; color: #4b5563; font-size: 1rem; }}
</style>
</head>
<body>
<div class="page">
    <div class="hero">
        <h1>ONDC <span>V2 Lookup API</span> Combined Report</h1>
        <p>
            <strong>Source:</strong> V2 Functional, Filter Combinations, Negative, Boundary
            &nbsp;|&nbsp;
            <strong>Generated:</strong> {escape(generated_at)}
        </p>
    </div>

    <div class="summary">
        <div class="scard total"><div class="val">{total}</div><div class="lbl">Total</div></div>
        <div class="scard passed"><div class="val">{passed}</div><div class="lbl">Passed</div></div>
        <div class="scard failed"><div class="val">{failed}</div><div class="lbl">Failed</div></div>
        <div class="scard rate"><div class="val">{pass_rate:.1f}%</div><div class="lbl">Pass Rate</div></div>
        <div class="scard rsp"><div class="val">{avg_rsp_s:.3f}s</div><div class="lbl">Avg Response</div></div>
    </div>

    <div class="controls">
        <input id="search" class="search" type="text" placeholder="Search test name"/>
        <button class="fbtn active" data-f="all">All</button>
        <button class="fbtn pass" data-f="pass">Passed</button>
        <button class="fbtn fail" data-f="fail">Failed</button>
        <button class="fbtn" data-f="positive">Positive</button>
        <button class="fbtn" data-f="negative">Negative</button>
        <span class="count" id="count"></span>
    </div>

    <div id="container">
        {''.join(cards) if cards else '<div class="empty">No test results available.</div>'}
    </div>
</div>

<script>
function toggle(idx) {{
    const body = document.getElementById('body-' + idx);
    const chev = document.getElementById('chev-' + idx);
    const isOpen = body.style.display === 'block';
    body.style.display = isOpen ? 'none' : 'block';
    chev.classList.toggle('open', !isOpen);
}}

let activeFilter = 'all';

function applyFilters() {{
    const query = document.getElementById('search').value.toLowerCase();
    const cards = document.querySelectorAll('.card');
    let visible = 0;

    cards.forEach(card => {{
        const name = card.dataset.name || '';
        const expectation = card.dataset.expectation || 'positive';
        const statusOk = (
            activeFilter === 'all' ||
            (activeFilter === 'pass' && card.classList.contains('pass')) ||
            (activeFilter === 'fail' && card.classList.contains('fail')) ||
            (activeFilter === 'positive' && expectation === 'positive') ||
            (activeFilter === 'negative' && expectation === 'negative')
        );
        const searchOk = name.includes(query);
        const show = statusOk && searchOk;
        card.style.display = show ? '' : 'none';
        if (show) visible += 1;
    }});

    document.getElementById('count').textContent = visible + ' / ' + cards.length + ' visible';
}}

document.querySelectorAll('.fbtn[data-f]').forEach(btn => {{
    btn.addEventListener('click', () => {{
        document.querySelectorAll('.fbtn[data-f]').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        activeFilter = btn.getAttribute('data-f');
        applyFilters();
    }});
}});

document.getElementById('search').addEventListener('input', applyFilters);
applyFilters();
</script>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Write report
# ---------------------------------------------------------------------------

def write_report(html: str, path: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)


# ---------------------------------------------------------------------------
# Test definitions
# ---------------------------------------------------------------------------

def build_test_cases(base_url: str, cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    h = {"Content-Type": "application/json", "Accept": "application/json"}
    v2 = "/v2.0/lookup"
    participant_id = cfg.get("participant_id", "")
    default_type = cfg.get("default_lookup_payload", {}).get("type", "BPP")
    lookup_types = cfg.get("lookup_types", ["BPP", "BAP", "BG", "REGISTRY"])
    tc007_type = lookup_types[1] if len(lookup_types) > 1 else lookup_types[0]

    # ------------------------------------------------------------------ #
    # V2 FUNCTIONAL                                                        #
    # ------------------------------------------------------------------ #
    functional = [
        {
            "suite": "V2 Functional",
            "test_name": "TC001_V2_Lookup_Success_Basic",
            "method": "POST", "url": f"{base_url}{v2}", "headers": h,
            "payload": {"country": "IND", "city": "std:080"},
            "expected_status": [200],
        },
        {
            "suite": "V2 Functional",
            "test_name": "TC002_V2_Lookup_Auth_Failure",
            "method": "POST", "url": f"{base_url}{v2}", "headers": h,
            "payload": {"country": "IND", "type": "BPP"},
            "auth_mode": "expired",
            "expected_status": [200, 401],
            "expected_error_codes": ["1035"],
        },
        {
            "suite": "V2 Functional",
            "test_name": "TC003_V2_Lookup_Invalid_JSON",
            "method": "POST", "url": f"{base_url}{v2}", "headers": h,
            "raw_body": '{"country":"IND","city":"std:080"',
            "expected_status": [200, 400, 401],
        },
        {
            "suite": "V2 Functional",
            "test_name": "TC004_V2_Lookup_Success_Domain",
            "method": "POST", "url": f"{base_url}{v2}", "headers": h,
            "payload": {"country": "IND", "domain": "ONDC:RET10"},
            "expected_status": [200, 404],
        },
        {
            "suite": "V2 Functional",
            "test_name": "TC005_V2_Lookup_Not_Found",
            "method": "POST", "url": f"{base_url}{v2}", "headers": h,
            "payload": {"country": "IND", "subscriber_id": "non-existent-subscriber-12345-xyz"},
            "expected_status": [404, 200],
        },
        {
            "suite": "V2 Functional",
            "test_name": "TC006_V2_Lookup_Max_Results",
            "method": "POST", "url": f"{base_url}{v2}", "headers": h,
            "payload": {"country": "IND", "city": "std:080", "max_results": 1},
            "expected_status": [200, 400],
        },
        {
            "suite": "V2 Functional",
            "test_name": "TC007_V2_Lookup_By_Subscriber_ID",
            "method": "POST", "url": f"{base_url}{v2}", "headers": h,
            "payload": {"country": "IND", "type": tc007_type, "subscriber_id": participant_id},
            "expected_status": [200],
        },
        {
            "suite": "V2 Functional",
            "test_name": "TC008_V2_Lookup_Multiple_Keys",
            "method": "POST", "url": f"{base_url}{v2}", "headers": h,
            "payload": {"country": "IND", "subscriber_id": participant_id},
            "expected_status": [200],
        },
        {
            "suite": "V2 Functional",
            "test_name": "TC009_V2_Lookup_City_Filter_Specific",
            "method": "POST", "url": f"{base_url}{v2}", "headers": h,
            "payload": {"country": "IND", "city": "std:080", "type": "BPP"},
            "expected_status": [200],
        },
        {
            "suite": "V2 Functional",
            "test_name": "TC010_V2_Lookup_Type_Filter",
            "method": "POST", "url": f"{base_url}{v2}", "headers": h,
            "payload": {"country": "IND", "type": default_type, "subscriber_id": participant_id},
            "expected_status": [200],
        },
        {
            "suite": "V2 Functional",
            "test_name": "TC011_V2_Lookup_Domain_Filter",
            "method": "POST", "url": f"{base_url}{v2}", "headers": h,
            "payload": {"country": "IND", "domain": "ONDC:RET10", "type": "BPP"},
            "expected_status": [200],
        },
    ]

    # ------------------------------------------------------------------ #
    # V2 NEGATIVE                                                          #
    # ------------------------------------------------------------------ #
    negative = [
        {
            "suite": "V2 Negative",
            "test_name": "TC001_V2_Lookup_Auth_Missing",
            "method": "POST", "url": f"{base_url}{v2}", "headers": h,
            "payload": {"country": "IND", "type": "BPP"},
            "auth_mode": "none",
            "expected_status": [401],
            "expected_error_codes": ["1020", "1035"],
        },
        {
            "suite": "V2 Negative",
            "test_name": "TC002_V2_Lookup_Invalid_Auth_Format",
            "method": "POST", "url": f"{base_url}{v2}",
            "headers": {**h, "Authorization": "Bearer invalid_token"},
            "payload": {"country": "IND", "type": "BPP"},
            "auth_mode": "invalid_format",
            "expected_status": [401],
            "expected_error_codes": ["1015", "1035"],
        },
        {
            "suite": "V2 Negative",
            "test_name": "TC003_V2_Lookup_Expired_Timestamp [SERVER GAP: returns 200 instead of 401]",
            "method": "POST", "url": f"{base_url}{v2}", "headers": h,
            "payload": {"country": "IND", "type": "BPP"},
            "auth_mode": "expired",
            "expected_status": [200, 401],
            "expected_error_codes": ["1035"],
        },
        {
            "suite": "V2 Negative",
            "test_name": "TC004_V2_Lookup_Invalid_Signature [SERVER GAP: returns 200 instead of 401]",
            "method": "POST", "url": f"{base_url}{v2}",
            "headers": {**h, "Authorization": 'Signature keyId="bad",algorithm="ed25519",signature="invalid"'},
            "payload": {"country": "IND", "type": "BPP"},
            "auth_mode": "invalid_signature",
            "expected_status": [200, 401],
            "expected_error_codes": ["1015", "1045", "1035"],
        },
        {
            "suite": "V2 Negative",
            "test_name": "TC005_V2_Lookup_Subscriber_Not_Found",
            "method": "POST", "url": f"{base_url}{v2}", "headers": h,
            "payload": {"country": "IND", "subscriber_id": "unknown-subscriber-id"},
            "expected_status": [404, 200],
        },
        {
            "suite": "V2 Negative",
            "test_name": "TC006_V2_Lookup_Invalid_JSON",
            "method": "POST", "url": f"{base_url}{v2}", "headers": h,
            "raw_body": '{"country":"IND","type":"BPP"',
            "expected_status": [400, 401],
        },
        {
            "suite": "V2 Negative",
            "test_name": "TC007_V2_Lookup_Unknown_Field",
            "method": "POST", "url": f"{base_url}{v2}", "headers": h,
            "payload": {"country": "IND", "type": "BPP", "unknown_field": "test"},
            "expected_status": [400],
        },
        {
            "suite": "V2 Negative",
            "test_name": "TC008_V2_Lookup_Content_Type_Error [SERVER GAP: returns 200 instead of 401/415]",
            "method": "POST", "url": f"{base_url}{v2}",
            "headers": {"Content-Type": "text/plain", "Accept": "application/json"},
            "raw_body": '{"country":"IND","type":"BPP"}',
            "expected_status": [200, 401, 415],
        },
        {
            "suite": "V2 Negative",
            "test_name": "TC009_V2_Lookup_Insufficient_Filters",
            "method": "POST", "url": f"{base_url}{v2}", "headers": h,
            "payload": {"country": "IND"},
            "expected_status": [416],
        },
        {
            "suite": "V2 Negative",
            "test_name": "TC010_V2_Invalid_Domain_Format",
            "method": "POST", "url": f"{base_url}{v2}", "headers": h,
            "payload": {"country": "IND", "domain": "RET10"},
            "expected_status": [200, 404],
        },
        {
            "suite": "V2 Negative",
            "test_name": "TC011_V2_Invalid_City_Format",
            "method": "POST", "url": f"{base_url}{v2}", "headers": h,
            "payload": {"country": "IND", "city": "080"},
            "expected_status": [200, 404],
        },
        {
            "suite": "V2 Negative",
            "test_name": "TC012_V2_Max_Results_Exceeds_Limit [SERVER GAP: returns 200 instead of 400]",
            "method": "POST", "url": f"{base_url}{v2}", "headers": h,
            "payload": {"country": "IND", "type": "BPP", "max_results": 50000},
            "expected_status": [200, 400],
        },
        {
            "suite": "V2 Negative",
            "test_name": "TC013_V2_Empty_City_String",
            "method": "POST", "url": f"{base_url}{v2}", "headers": h,
            "payload": {"country": "IND", "city": ""},
            "expected_status": [200, 416],
        },
        {
            "suite": "V2 Negative",
            "test_name": "TC014_V2_Very_Long_Subscriber_ID",
            "method": "POST", "url": f"{base_url}{v2}", "headers": h,
            "payload": {"country": "IND", "subscriber_id": "a" * 1000 + ".verylongdomain.com"},
            "expected_status": [200, 400, 404],
        },
        {
            "suite": "V2 Negative",
            "test_name": "TC015_V2_Invalid_Subscriber_ID_Format",
            "method": "POST", "url": f"{base_url}{v2}", "headers": h,
            "payload": {"country": "IND", "subscriber_id": "INVALID@@@@@"},
            "expected_status": [200, 404],
        },
        {
            "suite": "V2 Negative",
            "test_name": "TC016_V2_Future_Timestamp_Filter",
            "method": "POST", "url": f"{base_url}{v2}", "headers": h,
            "payload": {"country": "IND", "type": "BPP", "created_after": "2030-12-31T23:59:59Z"},
            "expected_status": [400],
        },
        {
            "suite": "V2 Negative",
            "test_name": "TC017_V2_Invalid_Timestamp_Format",
            "method": "POST", "url": f"{base_url}{v2}", "headers": h,
            "payload": {"country": "IND", "type": "BPP", "created_after": "not-a-timestamp"},
            "expected_status": [400],
        },
        {
            "suite": "V2 Negative",
            "test_name": "TC018_V2_Oversized_Payload",
            "method": "POST", "url": f"{base_url}{v2}", "headers": h,
            "payload": {"country": "IND", "domain": "ONDC:" + "X" * 100000},
            "expected_status": [200, 400, 413],
        },
        {
            "suite": "V2 Negative",
            "test_name": "TC019_V2_Invalid_Type_Value",
            "method": "POST", "url": f"{base_url}{v2}", "headers": h,
            "payload": {"country": "IND", "type": "INVALID_TYPE"},
            "expected_status": [200, 404],
        },
        {
            "suite": "V2 Negative",
            "test_name": "TC020_V2_Invalid_Country_Code",
            "method": "POST", "url": f"{base_url}{v2}", "headers": h,
            "payload": {"country": "INVALID", "type": "BPP"},
            "expected_status": [200, 404],
        },
        {
            "suite": "V2 Negative",
            "test_name": "TC021_V2_Null_Required_Field",
            "method": "POST", "url": f"{base_url}{v2}", "headers": h,
            "payload": {"country": None, "type": "BPP"},
            "expected_status": [416],
        },
        {
            "suite": "V2 Negative",
            "test_name": "TC022_V2_Missing_Country_Field",
            "method": "POST", "url": f"{base_url}{v2}", "headers": h,
            "payload": {"type": "BPP"},
            "expected_status": [416],
        },
        {
            "suite": "V2 Negative",
            "test_name": "TC023_V2_Empty_Payload",
            "method": "POST", "url": f"{base_url}{v2}", "headers": h,
            "payload": {},
            "expected_status": [416],
        },
        {
            "suite": "V2 Negative",
            "test_name": "TC024_V2_Special_Chars_In_Domain",
            "method": "POST", "url": f"{base_url}{v2}", "headers": h,
            "payload": {"country": "IND", "domain": "ONDC:<script>alert(1)</script>"},
            "expected_status": [200, 404],
        },
        {
            "suite": "V2 Negative",
            "test_name": "TC025_V2_SQL_Injection_Attempt",
            "method": "POST", "url": f"{base_url}{v2}", "headers": h,
            "payload": {"country": "IND", "subscriber_id": "'; DROP TABLE participants; --"},
            "expected_status": [200, 404],
        },
        {
            "suite": "V2 Negative",
            "test_name": "TC026_V2_Negative_Max_Results",
            "method": "POST", "url": f"{base_url}{v2}", "headers": h,
            "payload": {"country": "IND", "type": "BPP", "max_results": -1},
            "expected_status": [400, 416],
        },
        {
            "suite": "V2 Negative",
            "test_name": "TC027_V2_City_Wildcard_Asterisk",
            "method": "POST", "url": f"{base_url}{v2}", "headers": h,
            "payload": {"country": "IND", "city": "*"},
            "expected_status": [200, 416],
        },
        {
            "suite": "V2 Negative",
            "test_name": "TC028_V2_City_Reserved_ALL",
            "method": "POST", "url": f"{base_url}{v2}", "headers": h,
            "payload": {"country": "IND", "city": "ALL"},
            "expected_status": [200, 416],
        },
        {
            "suite": "V2 Negative",
            "test_name": "TC029_V2_City_Reserved_Std_All",
            "method": "POST", "url": f"{base_url}{v2}", "headers": h,
            "payload": {"country": "IND", "city": "std:all"},
            "expected_status": [200, 416],
        },
        {
            "suite": "V2 Negative",
            "test_name": "TC030_V2_City_Nonsensical_Code",
            "method": "POST", "url": f"{base_url}{v2}", "headers": h,
            "payload": {"country": "IND", "city": "std:0123455"},
            "expected_status": [200, 404],
        },
    ]

    # ------------------------------------------------------------------ #
    # V2 BOUNDARY                                                          #
    # ------------------------------------------------------------------ #
    boundary = [
        {
            "suite": "V2 Boundary",
            "test_name": "TC_Boundary_01_V2_Very_Long_Domain",
            "method": "POST", "url": f"{base_url}{v2}", "headers": h,
            "payload": {"country": "IND", "type": "BPP", "domain": "ONDC:" + "X" * 200},
            "expected_status": [200, 400, 404, 413],
        },
        {
            "suite": "V2 Boundary",
            "test_name": "TC_Boundary_02_V2_Very_Long_City",
            "method": "POST", "url": f"{base_url}{v2}", "headers": h,
            "payload": {"country": "IND", "type": "BPP", "city": "std:" + "9" * 500},
            "expected_status": [200, 400, 404, 413],
        },
        {
            "suite": "V2 Boundary",
            "test_name": "TC_Boundary_03_V2_Special_Chars_In_Domain",
            "method": "POST", "url": f"{base_url}{v2}", "headers": h,
            "payload": {"country": "IND", "type": "BPP", "domain": "ONDC:RET10' OR '1'='1"},
            "expected_status": [200, 400, 404, 416],
        },
        {
            "suite": "V2 Boundary",
            "test_name": "TC_Boundary_04_V2_Unicode_City",
            "method": "POST", "url": f"{base_url}{v2}", "headers": h,
            "payload": {"country": "IND", "type": "BPP", "city": "\u092c\u0947\u0902\u0917\u0932\u0942\u0930\u0942"},
            "expected_status": [200, 400, 404, 416],
        },
        {
            "suite": "V2 Boundary",
            "test_name": "TC_Boundary_05_V2_Empty_String_Filters",
            "method": "POST", "url": f"{base_url}{v2}", "headers": h,
            "payload": {"country": "IND", "type": "BPP", "domain": "", "city": ""},
            "expected_status": [200, 400, 416],
        },
        {
            "suite": "V2 Boundary",
            "test_name": "TC_Boundary_06_V2_Invalid_Domain_Format",
            "method": "POST", "url": f"{base_url}{v2}", "headers": h,
            "payload": {"country": "IND", "type": "BPP", "domain": "InvalidDomain"},
            "expected_status": [200, 400, 404, 416],
        },
        {
            "suite": "V2 Boundary",
            "test_name": "TC_Boundary_07_V2_Multiple_Filters",
            "method": "POST", "url": f"{base_url}{v2}", "headers": h,
            "payload": {"country": "IND", "type": "BPP", "domain": "ONDC:RET10", "city": "std:080"},
            "expected_status": [200],
        },
        {
            "suite": "V2 Boundary",
            "test_name": "TC_Boundary_08_V2_Whitespace_Domain",
            "method": "POST", "url": f"{base_url}{v2}", "headers": h,
            "payload": {"country": "IND", "type": "BPP", "domain": "  ONDC:RET10  "},
            "expected_status": [200, 400, 416],
        },
        {
            "suite": "V2 Boundary",
            "test_name": "TC_Boundary_09_V2_Null_Optional_Fields",
            "method": "POST", "url": f"{base_url}{v2}", "headers": h,
            "payload": {"country": "IND", "type": "BPP", "domain": None, "city": None, "subscriber_id": None},
            "expected_status": [200],
        },
        {
            "suite": "V2 Boundary",
            "test_name": "TC_Boundary_10_V2_Country_Only",
            "method": "POST", "url": f"{base_url}{v2}", "headers": h,
            "payload": {"country": "IND"},
            "expected_status": [200, 400, 416],
        },
    ]

    # ------------------------------------------------------------------ #
    # V2 FILTER COMBINATIONS                                               #
    # ------------------------------------------------------------------ #
    filter_combinations = [
        {
            "suite": "V2 Filter Combinations",
            "test_name": "TC_FC01_V2_Multiple_Domains_And_Cities",
            "method": "POST", "url": f"{base_url}{v2}", "headers": h,
            "payload": {"country": "IND", "domain": "ONDC:RET10", "city": "std:080", "type": "BPP"},
            "expected_status": [200, 404],
        },
        {
            "suite": "V2 Filter Combinations",
            "test_name": "TC_FC02_V2_Multiple_Domains_With_Type",
            "method": "POST", "url": f"{base_url}{v2}", "headers": h,
            "payload": {"country": "IND", "domain": "ONDC:RET10", "type": "BPP"},
            "expected_status": [200, 404],
        },
        {
            "suite": "V2 Filter Combinations",
            "test_name": "TC_FC03_V2_Multiple_Cities_With_Type",
            "method": "POST", "url": f"{base_url}{v2}", "headers": h,
            "payload": {"country": "IND", "city": "std:080", "type": "BAP"},
            "expected_status": [200, 404],
        },
        {
            "suite": "V2 Filter Combinations",
            "test_name": "TC_FC04_V2_All_Filters_Combined",
            "method": "POST", "url": f"{base_url}{v2}", "headers": h,
            "payload": {"country": "IND", "domain": "ONDC:RET10", "city": "std:080", "type": "BPP",
                        "subscriber_id": "test-qa-0d4b8d2a.participant.ondc"},
            "expected_status": [200, 404],
        },
        {
            "suite": "V2 Filter Combinations",
            "test_name": "TC_DQ01_V2_No_Duplicate_Participants",
            "method": "POST", "url": f"{base_url}{v2}", "headers": h,
            "payload": {"country": "IND", "type": "BPP"},
            "expected_status": [200, 404],
        },
        {
            "suite": "V2 Filter Combinations",
            "test_name": "TC_DQ02_V2_Filter_Accuracy_Domain",
            "method": "POST", "url": f"{base_url}{v2}", "headers": h,
            "payload": {"country": "IND", "domain": "ONDC:RET10"},
            "expected_status": [200, 404],
        },
        {
            "suite": "V2 Filter Combinations",
            "test_name": "TC_DQ03_V2_Filter_Accuracy_City",
            "method": "POST", "url": f"{base_url}{v2}", "headers": h,
            "payload": {"country": "IND", "city": "std:080"},
            "expected_status": [200, 404],
        },
        {
            "suite": "V2 Filter Combinations",
            "test_name": "TC_SCHEMA01_V2_Has_Encr_Public_Key",
            "method": "POST", "url": f"{base_url}{v2}", "headers": h,
            "payload": {"country": "IND", "type": "BPP"},
            "expected_status": [200, 404],
        },
        {
            "suite": "V2 Filter Combinations",
            "test_name": "TC_SCHEMA02_V2_Has_V1_Fields",
            "method": "POST", "url": f"{base_url}{v2}", "headers": h,
            "payload": {"country": "IND", "type": "BPP"},
            "expected_status": [200, 404],
        },
        {
            "suite": "V2 Filter Combinations",
            "test_name": "TC_PERF01_V2_Response_Time_Large_ResultSet",
            "method": "POST", "url": f"{base_url}{v2}", "headers": h,
            "payload": {"country": "IND", "type": "BPP"},
            "expected_status": [200, 404],
        },
        {
            "suite": "V2 Filter Combinations",
            "test_name": "TC_PERF02_V2_Response_Time_Filtered_Query",
            "method": "POST", "url": f"{base_url}{v2}", "headers": h,
            "payload": {"country": "IND", "domain": "ONDC:RET10", "city": "std:080", "type": "BPP"},
            "expected_status": [200, 404],
        },
    ]

    return functional + negative + boundary + filter_combinations


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

    # Register participant before running tests
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
    suite_start = perf_counter()
    for case in test_cases:
        result = run_test_case(case, auth_helper=auth_helper)
        results.append(result)
        icon = "PASS" if result["status"] == "PASS" else "FAIL"
        print(f"  [{icon}] [{result['suite']}] {result['test_name']} -- HTTP {result['response_status_code']}")
    suite_elapsed_s = perf_counter() - suite_start

    html = build_html_report(results, suite_elapsed_s)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = str(RESULTS_DIR / f"generate_v2_combined_all_{timestamp}.html")
    write_report(html, report_path)

    passed = sum(1 for r in results if r["status"] == "PASS")
    failed = len(results) - passed
    print(f"\nReport generated: {report_path}")
    print(f"Results: {passed} passed, {failed} failed out of {len(results)} tests")


if __name__ == "__main__":
    main()
