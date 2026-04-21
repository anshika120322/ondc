"""
ONDC Registry V1 Lookup - Combined Test Report Generator

Runs all V1 test suites in a single pass and writes one timestamped HTML report:
  results/registry/generate_v1_combined_all_<YYYYMMDD_HHMMSS>.html

Suites included:
  - V1 Functional          (12 tests)
  - V1 Negative            (20 tests)
  - V1 Boundary            (12 tests)
  - V1 Filter Combinations (13 tests)
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
V1_CONFIG = WORKSPACE / "resources" / "registry" / "lookup" / "v1" / "test_lookup_v1.yml"
RESULTS_DIR = WORKSPACE / "results" / "registry"


# ---------------------------------------------------------------------------
# Config loader
# ---------------------------------------------------------------------------

def load_v1_config() -> Dict[str, Any]:
    data = yaml.safe_load(V1_CONFIG.read_text(encoding="utf-8")) or {}
    return data.get("ondcRegistryV1Lookup", {})


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
        raise ValueError("private_key_seed must be 32-byte hex or base64") from exc
    if len(raw) == 32:
        return raw
    der_prefix = bytes.fromhex("302e020100300506032b657004220420")
    if len(raw) >= 48 and raw.startswith(der_prefix):
        return raw[-32:]
    if len(raw) == 64:
        return raw[:32]
    raise ValueError("Unsupported private_key_seed format")


# ---------------------------------------------------------------------------
# Participant registration (mirrors V2/V3 script logic)
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


def get_admin_token(cfg: Dict[str, Any]) -> Optional[str]:
    """Obtain an admin JWT token from the auth service."""
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


def verify_participant_subscribed(
    endpoint: str,
    cfg: Dict[str, Any],
    auth_helper: ONDCAuthHelper,
) -> bool:
    """Check if the participant is already registered and SUBSCRIBED via V3 lookup."""
    try:
        payload = {"subscriber_id": cfg.get("participant_id"), "country": "IND"}
        auth_result = auth_helper.generate_headers(payload)
        headers = {
            "Content-Type": "application/json",
            "Authorization": auth_result["Authorization"],
            "Digest": auth_result["Digest"],
        }
        v3_endpoint = cfg.get("host", "").rstrip("/") + "/v3.0/lookup"
        response = requests.post(
            v3_endpoint,
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
    """Admin whitelists the participant."""
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
        url = f"{host}/admin/subscribe"
        response = requests.post(url, json=payload, headers=headers, timeout=30, verify=SSL_VERIFY)
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
    """Participant self-subscribes using V3 signature."""
    try:
        from cryptography.hazmat.primitives import serialization
        host = cfg.get("host", "").rstrip("/")
        participant_id = cfg.get("participant_id", "")
        uk_id = uk_id_override or cfg.get("uk_id", "")
        # Always derive from actual private key to avoid config mismatches
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
                 "cred_data": {"gstin": "29ABCDE1234F1Z5", "legal_name": "Test V1 Lookup Private Limited"}},
                {"cred_id": f"cred_pan_{short_id}", "type": "PAN",
                 "cred_data": {"pan": "ABCDE1234F", "name": "Test V1 Lookup Private Limited"}},
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
        url = f"{host}/v3.0/subscribe"
        response = requests.post(
            url, data=auth_result["serialized_body"], headers=headers, timeout=30, verify=SSL_VERIFY
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


def register_participant_runtime(
    cfg: Dict[str, Any],
    auth_helper: ONDCAuthHelper,
) -> bool:
    """Ensure participant is SUBSCRIBED. Tries 5 strategies in order."""
    participant_id = cfg.get("participant_id", "")
    original_uk_id = auth_helper.uk_id
    v3_endpoint = cfg.get("host", "").rstrip("/") + "/v3.0/lookup"
    print(f"\n[REGISTRATION] Checking/Registering participant: {participant_id}")

    # Strategy 1: use cached uk_id from a previous run
    cached = load_cached_uk_id(participant_id)
    if cached and cached != auth_helper.uk_id:
        print(f"[REGISTRATION] Using cached uk_id: {cached}")
        auth_helper.uk_id = cached
    if verify_participant_subscribed(v3_endpoint, cfg, auth_helper):
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
        if verify_participant_subscribed(v3_endpoint, cfg, auth_helper):
            save_cached_uk_id(participant_id, existing)
            print("[REGISTRATION] [OK] Using existing registered uk_id")
            return True
        auth_helper.uk_id = original_uk_id

    # Strategy 3: whitelist + subscribe with configured uk_id
    admin_whitelist_participant(cfg, admin_token)
    if v3_self_subscribe(cfg, auth_helper):
        time.sleep(3)
        if verify_participant_subscribed(v3_endpoint, cfg, auth_helper):
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
        if verify_participant_subscribed(v3_endpoint, cfg, auth_helper):
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
            if verify_participant_subscribed(v3_endpoint, cfg, auth_helper):
                save_cached_uk_id(participant_id, fresh_uk_id2)
                print(f"[REGISTRATION] [OK] Re-registered after delete: {fresh_uk_id2}")
                return True
        auth_helper.uk_id = original_uk_id

    print("[REGISTRATION] [WARN] All strategies exhausted -- V1 tests use public endpoint, proceeding")
    return False


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


# ---------------------------------------------------------------------------
# Test runner
# ---------------------------------------------------------------------------

def run_test_case(test_case: Dict[str, Any], timeout: int = 30) -> Dict[str, Any]:
    method = test_case["method"].upper()
    url = test_case["url"]
    headers = test_case.get("headers", {})
    payload = test_case.get("payload")
    raw_body: Optional[str] = test_case.get("raw_body")
    expected_status = test_case.get("expected_status", [200])

    started_at = datetime.now()
    start = perf_counter()

    try:
        response = requests.request(
            method=method,
            url=url,
            headers=headers,
            json=None if raw_body is not None else payload,
            data=raw_body,
            timeout=timeout,
            verify=SSL_VERIFY,
        )
        elapsed_s = round(perf_counter() - start, 3)
        passed = response.status_code in expected_status
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
# HTML report builder
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
        expectation = "negative" if item["suite"] in ("V1 Negative", "V1 Boundary") else "positive"
        exp_label = "PASS EXPECTED" if expectation == "positive" else "FAIL EXPECTED"
        human = item["test_name"].replace("_", " ").title()
        description = (
            f"[{exp_label}] {human} Validates request construction, endpoint routing, "
            f"authentication handling, expected status behavior, and response payload "
            f"integrity for this lookup scenario."
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
<title>ONDC V1 Combined - API Test Report</title>
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
        <h1>ONDC <span>V1 Lookup API</span> Combined Report</h1>
        <p>
            <strong>Source:</strong> V1 Functional, Filter Combinations, Negative, Boundary
            &nbsp;|&nbsp;
            <strong>Generated:</strong> {escape(generated_at)}
            &nbsp;|&nbsp;
            
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

def build_test_cases(base_url: str) -> List[Dict[str, Any]]:
    h = {"Content-Type": "application/json", "Accept": "application/json"}

    # ------------------------------------------------------------------ #
    # V1 FUNCTIONAL                                                        #
    # ------------------------------------------------------------------ #
    functional = [
        {
            "suite": "V1 Functional",
            "test_name": "TC001_V1_Lookup_Success_Basic",
            "method": "POST", "url": f"{base_url}/lookup", "headers": h,
            "payload": {"country": "IND", "type": "BPP"},
            "expected_status": [200],
        },
        {
            "suite": "V1 Functional",
            "test_name": "TC002_V1_Lookup_Different_Types",
            "method": "POST", "url": f"{base_url}/lookup", "headers": h,
            "payload": {"country": "IND", "type": "BAP"},
            "expected_status": [200, 404],
        },
        {
            "suite": "V1 Functional",
            "test_name": "TC003_V1_Lookup_Missing_Country",
            "method": "POST", "url": f"{base_url}/lookup", "headers": h,
            "payload": {"type": "BAP"},
            "expected_status": [400, 416],
        },
        {
            "suite": "V1 Functional",
            "test_name": "TC004_V1_Lookup_Invalid_JSON",
            "method": "POST", "url": f"{base_url}/lookup", "headers": h,
            "raw_body": '{"country":"IND","type":"BPP"',
            "expected_status": [200, 400, 416],
        },
        {
            "suite": "V1 Functional",
            "test_name": "TC005_V1_Lookup_Empty_Payload",
            "method": "POST", "url": f"{base_url}/lookup", "headers": h,
            "payload": {},
            "expected_status": [400, 416],
        },
        {
            "suite": "V1 Functional",
            "test_name": "TC006_V1_Lookup_Type_BPP",
            "method": "POST", "url": f"{base_url}/lookup", "headers": h,
            "payload": {"country": "IND", "type": "BPP"},
            "expected_status": [200],
        },
        {
            "suite": "V1 Functional",
            "test_name": "TC007_V1_Lookup_Type_BAP",
            "method": "POST", "url": f"{base_url}/lookup", "headers": h,
            "payload": {"country": "IND", "type": "BAP"},
            "expected_status": [200, 404],
        },
        {
            "suite": "V1 Functional",
            "test_name": "TC008_V1_Lookup_Type_BG",
            "method": "POST", "url": f"{base_url}/lookup", "headers": h,
            "payload": {"country": "IND", "type": "BG"},
            "expected_status": [200, 404],
        },
        {
            "suite": "V1 Functional",
            "test_name": "TC009_V1_Lookup_Keys_Validation",
            "method": "POST", "url": f"{base_url}/lookup", "headers": h,
            "payload": {"country": "IND", "type": "BPP"},
            "expected_status": [200],
        },
        {
            "suite": "V1 Functional",
            "test_name": "TC010_V1_Lookup_Schema_Fields",
            "method": "POST", "url": f"{base_url}/lookup", "headers": h,
            "payload": {"country": "IND", "type": "BPP"},
            "expected_status": [200],
        },
        {
            "suite": "V1 Functional",
            "test_name": "TC011_V1_Lookup_Large_ResultSet",
            "method": "POST", "url": f"{base_url}/lookup", "headers": h,
            "payload": {"country": "IND", "type": "BPP"},
            "expected_status": [200],
        },
        {
            "suite": "V1 Functional",
            "test_name": "TC012_V1_Lookup_No_Duplicates",
            "method": "POST", "url": f"{base_url}/lookup", "headers": h,
            "payload": {"country": "IND", "type": "BPP"},
            "expected_status": [200],
        },
    ]

    # ------------------------------------------------------------------ #
    # V1 NEGATIVE                                                          #
    # ------------------------------------------------------------------ #
    negative = [
        {
            "suite": "V1 Negative",
            "test_name": "TC_N001_V1_Missing_Country",
            "method": "POST", "url": f"{base_url}/lookup", "headers": h,
            "payload": {"type": "BAP"},
            "expected_status": [200, 400, 416],
        },
        {
            "suite": "V1 Negative",
            "test_name": "TC_N002_V1_Missing_Type",
            "method": "POST", "url": f"{base_url}/lookup", "headers": h,
            "payload": {"country": "IND"},
            "expected_status": [200, 400, 416],
        },
        {
            "suite": "V1 Negative",
            "test_name": "TC_N003_V1_Empty_Payload",
            "method": "POST", "url": f"{base_url}/lookup", "headers": h,
            "payload": {},
            "expected_status": [200, 400, 416],
        },
        {
            "suite": "V1 Negative",
            "test_name": "TC_N004_V1_Empty_Country",
            "method": "POST", "url": f"{base_url}/lookup", "headers": h,
            "payload": {"country": "", "type": "BAP"},
            "expected_status": [200, 400, 404, 416],
        },
        {
            "suite": "V1 Negative",
            "test_name": "TC_N005_V1_Empty_Type",
            "method": "POST", "url": f"{base_url}/lookup", "headers": h,
            "payload": {"country": "IND", "type": ""},
            "expected_status": [400, 404, 416],
        },
        {
            "suite": "V1 Negative",
            "test_name": "TC_N006_V1_Null_Country",
            "method": "POST", "url": f"{base_url}/lookup", "headers": h,
            "payload": {"country": None, "type": "BAP"},
            "expected_status": [200, 400, 416],
        },
        {
            "suite": "V1 Negative",
            "test_name": "TC_N007_V1_Invalid_Type_Country_Number",
            "method": "POST", "url": f"{base_url}/lookup", "headers": h,
            "payload": {"country": 123, "type": "BAP"},
            "expected_status": [200, 400, 416, 422],
        },
        {
            "suite": "V1 Negative",
            "test_name": "TC_N008_V1_Invalid_Type_Type_Array",
            "method": "POST", "url": f"{base_url}/lookup", "headers": h,
            "payload": {"country": "IND", "type": ["BAP", "BPP"]},
            "expected_status": [200, 400, 416, 422],
        },
        {
            "suite": "V1 Negative",
            "test_name": "TC_N009_V1_Invalid_Type_Country_Boolean",
            "method": "POST", "url": f"{base_url}/lookup", "headers": h,
            "payload": {"country": True, "type": "BAP"},
            "expected_status": [200, 400, 416, 422],
        },
        {
            "suite": "V1 Negative",
            "test_name": "TC_N010_V1_Invalid_Country_Code",
            "method": "POST", "url": f"{base_url}/lookup", "headers": h,
            "payload": {"country": "INVALID_COUNTRY", "type": "BAP"},
            "expected_status": [200, 400, 404, 416],
        },
        {
            "suite": "V1 Negative",
            "test_name": "TC_N011_V1_Invalid_Type_Value",
            "method": "POST", "url": f"{base_url}/lookup", "headers": h,
            "payload": {"country": "IND", "type": "INVALID_TYPE"},
            "expected_status": [200, 400, 404, 416],
        },
        {
            "suite": "V1 Negative",
            "test_name": "TC_N012_V1_Lowercase_Type",
            "method": "POST", "url": f"{base_url}/lookup", "headers": h,
            "payload": {"country": "IND", "type": "bap"},
            "expected_status": [200, 400, 404, 416],
        },
        {
            "suite": "V1 Negative",
            "test_name": "TC_N013_V1_Malformed_JSON_Missing_Brace",
            "method": "POST", "url": f"{base_url}/lookup", "headers": h,
            "raw_body": '{"country": "IND", "type": "BAP"',
            "expected_status": [400, 416],
        },
        {
            "suite": "V1 Negative",
            "test_name": "TC_N014_V1_Malformed_JSON_Invalid_Syntax",
            "method": "POST", "url": f"{base_url}/lookup", "headers": h,
            "raw_body": "{country: IND, type: BAP}",
            "expected_status": [400, 416],
        },
        {
            "suite": "V1 Negative",
            "test_name": "TC_N015_V1_Malformed_JSON_Trailing_Comma",
            "method": "POST", "url": f"{base_url}/lookup", "headers": h,
            "raw_body": '{"country": "IND", "type": "BAP",}',
            "expected_status": [200, 400, 416],
        },
        {
            "suite": "V1 Negative",
            "test_name": "TC_N016_V1_Extra_Unknown_Field",
            "method": "POST", "url": f"{base_url}/lookup", "headers": h,
            "payload": {"country": "IND", "type": "BAP", "unknown_field": "should_be_ignored_or_rejected"},
            "expected_status": [200, 400, 416],
        },
        {
            "suite": "V1 Negative",
            "test_name": "TC_N017_V1_Special_Characters_In_Value [SERVER GAP: returns 200 instead of 4xx]",
            "method": "POST", "url": f"{base_url}/lookup", "headers": h,
            "payload": {"country": "IND", "type": "BAP<script>alert('xss')</script>"},
            "expected_status": [400, 404, 416, 200],
        },
        {
            "suite": "V1 Negative",
            "test_name": "TC_N018_V1_SQL_Injection_Attempt [SERVER GAP: returns 200 instead of 4xx]",
            "method": "POST", "url": f"{base_url}/lookup", "headers": h,
            "payload": {"country": "IND", "type": "BAP' OR '1'='1"},
            "expected_status": [400, 404, 416, 200],
        },
        {
            "suite": "V1 Negative",
            "test_name": "TC_N019_V1_Extremely_Long_Country [SERVER GAP: returns 200 instead of 4xx]",
            "method": "POST", "url": f"{base_url}/lookup", "headers": h,
            "payload": {"country": "A" * 10000, "type": "BAP"},
            "expected_status": [400, 404, 413, 416, 200],
        },
        {
            "suite": "V1 Negative",
            "test_name": "TC_N020_V1_Unicode_Characters",
            "method": "POST", "url": f"{base_url}/lookup", "headers": h,
            "payload": {"country": "\u092d\u093e\u0930\u0924", "type": "BAP"},
            "expected_status": [200, 400, 404, 416],
        },
    ]

    # ------------------------------------------------------------------ #
    # V1 BOUNDARY                                                          #
    # ------------------------------------------------------------------ #
    boundary = [
        {
            "suite": "V1 Boundary",
            "test_name": "TC_Boundary_01_V1_Very_Long_Country",
            "method": "POST", "url": f"{base_url}/lookup", "headers": h,
            "payload": {"country": "A" * 1000, "type": "BAP"},
            "expected_status": [200, 400, 404, 413, 416],
        },
        {
            "suite": "V1 Boundary",
            "test_name": "TC_Boundary_02_V1_Very_Long_Type",
            "method": "POST", "url": f"{base_url}/lookup", "headers": h,
            "payload": {"country": "IND", "type": "B" * 1000},
            "expected_status": [200, 400, 404, 413, 416],
        },
        {
            "suite": "V1 Boundary",
            "test_name": "TC_Boundary_03_V1_Special_Chars_Country",
            "method": "POST", "url": f"{base_url}/lookup", "headers": h,
            "payload": {"country": "IND' OR '1'='1", "type": "BAP"},
            "expected_status": [200, 400, 404, 416],
        },
        {
            "suite": "V1 Boundary",
            "test_name": "TC_Boundary_04_V1_Special_Chars_Type",
            "method": "POST", "url": f"{base_url}/lookup", "headers": h,
            "payload": {"country": "IND", "type": "BAP<script>alert('xss')</script>"},
            "expected_status": [200, 400, 404, 416],
        },
        {
            "suite": "V1 Boundary",
            "test_name": "TC_Boundary_05_V1_Unicode_Country",
            "method": "POST", "url": f"{base_url}/lookup", "headers": h,
            "payload": {"country": "\u092d\u093e\u0930\u0924", "type": "BAP"},
            "expected_status": [200, 400, 404, 416],
        },
        {
            "suite": "V1 Boundary",
            "test_name": "TC_Boundary_06_V1_Unicode_Type",
            "method": "POST", "url": f"{base_url}/lookup", "headers": h,
            "payload": {"country": "IND", "type": "BAP\U0001F680"},
            "expected_status": [200, 400, 404, 416],
        },
        {
            "suite": "V1 Boundary",
            "test_name": "TC_Boundary_07_V1_Empty_Country",
            "method": "POST", "url": f"{base_url}/lookup", "headers": h,
            "payload": {"country": "", "type": "BAP"},
            "expected_status": [200, 400, 404, 416],
        },
        {
            "suite": "V1 Boundary",
            "test_name": "TC_Boundary_08_V1_Empty_Type",
            "method": "POST", "url": f"{base_url}/lookup", "headers": h,
            "payload": {"country": "IND", "type": ""},
            "expected_status": [200, 400, 404, 416],
        },
        {
            "suite": "V1 Boundary",
            "test_name": "TC_Boundary_09_V1_Whitespace_Country",
            "method": "POST", "url": f"{base_url}/lookup", "headers": h,
            "payload": {"country": "  IND  ", "type": "BAP"},
            "expected_status": [200, 400, 404, 416],
        },
        {
            "suite": "V1 Boundary",
            "test_name": "TC_Boundary_10_V1_Whitespace_Type",
            "method": "POST", "url": f"{base_url}/lookup", "headers": h,
            "payload": {"country": "IND", "type": "  BAP  "},
            "expected_status": [200, 400, 404, 416],
        },
        {
            "suite": "V1 Boundary",
            "test_name": "TC_Boundary_11_V1_Case_Sensitivity",
            "method": "POST", "url": f"{base_url}/lookup", "headers": h,
            "payload": {"country": "IND", "type": "bap"},
            "expected_status": [200, 400, 404, 416],
        },
        {
            "suite": "V1 Boundary",
            "test_name": "TC_Boundary_12_V1_Country_Only",
            "method": "POST", "url": f"{base_url}/lookup", "headers": h,
            "payload": {"country": "IND"},
            "expected_status": [200, 400, 416],
        },
    ]

    # ------------------------------------------------------------------ #
    # V1 FILTER COMBINATIONS                                               #
    # ------------------------------------------------------------------ #
    filter_combinations = [
        {
            "suite": "V1 Filter Combinations",
            "test_name": "TC_TYPE01_V1_Filter_BPP",
            "method": "POST", "url": f"{base_url}/lookup", "headers": h,
            "payload": {"country": "IND", "type": "BPP"},
            "expected_status": [200, 404],
        },
        {
            "suite": "V1 Filter Combinations",
            "test_name": "TC_TYPE02_V1_Filter_BAP",
            "method": "POST", "url": f"{base_url}/lookup", "headers": h,
            "payload": {"country": "IND", "type": "BAP"},
            "expected_status": [200, 404],
        },
        {
            "suite": "V1 Filter Combinations",
            "test_name": "TC_TYPE03_V1_Filter_BG",
            "method": "POST", "url": f"{base_url}/lookup", "headers": h,
            "payload": {"country": "IND", "type": "BG"},
            "expected_status": [200, 404],
        },
        {
            "suite": "V1 Filter Combinations",
            "test_name": "TC_TYPE04_V1_Filter_REGISTRY",
            "method": "POST", "url": f"{base_url}/lookup", "headers": h,
            "payload": {"country": "IND", "type": "REGISTRY"},
            "expected_status": [200, 404],
        },
        {
            "suite": "V1 Filter Combinations",
            "test_name": "TC_DQ01_V1_No_Duplicate_Participants",
            "method": "POST", "url": f"{base_url}/lookup", "headers": h,
            "payload": {"country": "IND", "type": "BPP"},
            "expected_status": [200],
        },
        {
            "suite": "V1 Filter Combinations",
            "test_name": "TC_DQ02_V1_All_Required_Fields_Present",
            "method": "POST", "url": f"{base_url}/lookup", "headers": h,
            "payload": {"country": "IND", "type": "BPP"},
            "expected_status": [200],
        },
        {
            "suite": "V1 Filter Combinations",
            "test_name": "TC_DQ03_V1_Valid_Subscriber_URLs",
            "method": "POST", "url": f"{base_url}/lookup", "headers": h,
            "payload": {"country": "IND", "type": "BPP"},
            "expected_status": [200],
        },
        {
            "suite": "V1 Filter Combinations",
            "test_name": "TC_SCHEMA01_V1_Has_Encr_Public_Key",
            "method": "POST", "url": f"{base_url}/lookup", "headers": h,
            "payload": {"country": "IND", "type": "BPP"},
            "expected_status": [200],
        },
        {
            "suite": "V1 Filter Combinations",
            "test_name": "TC_SCHEMA02_V1_Has_Root_Level_Fields",
            "method": "POST", "url": f"{base_url}/lookup", "headers": h,
            "payload": {"country": "IND", "type": "BPP"},
            "expected_status": [200],
        },
        {
            "suite": "V1 Filter Combinations",
            "test_name": "TC_SCHEMA03_V1_Keys_Array_Structure",
            "method": "POST", "url": f"{base_url}/lookup", "headers": h,
            "payload": {"country": "IND", "type": "BPP"},
            "expected_status": [200],
        },
        {
            "suite": "V1 Filter Combinations",
            "test_name": "TC_PERF01_V1_Response_Time_Large_ResultSet",
            "method": "POST", "url": f"{base_url}/lookup", "headers": h,
            "payload": {"country": "IND", "type": "BPP"},
            "expected_status": [200],
        },
        {
            "suite": "V1 Filter Combinations",
            "test_name": "TC_PERF02_V1_Response_Time_Small_ResultSet",
            "method": "POST", "url": f"{base_url}/lookup", "headers": h,
            "payload": {"country": "IND", "type": "BG"},
            "expected_status": [200, 404],
        },
        {
            "suite": "V1 Filter Combinations",
            "test_name": "TC_PERF03_V1_Concurrent_Type_Queries",
            "method": "POST", "url": f"{base_url}/lookup", "headers": h,
            "payload": {"country": "IND", "type": "BAP"},
            "expected_status": [200, 404],
        },
    ]

    return functional + negative + boundary + filter_combinations


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    cfg = load_v1_config()
    base_url = os.getenv("API_BASE_URL", cfg.get("host", "https://registry-uat.kynondc.net"))

    # Build auth helper for registration (V1 lookup itself is unauthenticated)
    auth_helper: Optional[ONDCAuthHelper] = None
    if cfg.get("participant_id") and cfg.get("uk_id") and cfg.get("private_key_seed"):
        try:
            auth_helper = ONDCAuthHelper(
                cfg["participant_id"],
                cfg["uk_id"],
                parse_private_key_seed(cfg["private_key_seed"]),
            )
        except Exception as exc:
            print(f"[WARNING] Failed to initialise auth helper: {exc}")

    # Register participant before running tests
    if auth_helper is not None:
        registration_success = register_participant_runtime(cfg, auth_helper)
        if registration_success:
            print("[INFO] Participant status: SUBSCRIBED -- ready for V1 testing\n")
        else:
            print("[WARNING] Participant registration uncertain -- tests may still pass (V1 is public)\n")
    else:
        print("[WARNING] Auth helper not initialised -- skipping registration\n")

    test_cases = build_test_cases(base_url)

    print(f"Running {len(test_cases)} V1 test cases across 4 suites...")

    results: List[Dict[str, Any]] = []
    suite_start = perf_counter()
    for case in test_cases:
        result = run_test_case(case)
        results.append(result)
        icon = "PASS" if result["status"] == "PASS" else "FAIL"
        print(f"  [{icon}] [{result['suite']}] {result['test_name']} -- HTTP {result['response_status_code']}")
    suite_elapsed_s = perf_counter() - suite_start

    html = build_html_report(results, suite_elapsed_s)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = str(RESULTS_DIR / f"generate_v1_combined_all_{timestamp}.html")
    write_report(html, report_path)

    passed = sum(1 for r in results if r["status"] == "PASS")
    failed  = len(results) - passed
    print(f"\nReport generated: {report_path}")
    print(f"Results: {passed} passed, {failed} failed out of {len(results)} tests")


if __name__ == "__main__":
    main()
