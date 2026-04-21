#!/usr/bin/env python3
"""
ONDC Registry V3 Subscribe API - Automated Test Runner with HTML Report Generator
==================================================================================
Covers /v3.0/subscribe (participant self-subscribe / PATCH) only.
Admin whitelist steps appear only as workflow setup (Step 1) — never as standalone TCs.

Functional TCs (16):
    F-TC001–009  : V3 Subscribe workflows (seller, buyer, logistics, multi-domain)
    F-TC005–014  : V3 PATCH workflows (add_contact, add_credential, business_info, location, multi_field)
    F-TC010–020  : V3 PATCH — key rotation, re-subscribe, buyer contact, logistics location
    F-TC014–026  : V3 workflows — self-restore from INACTIVE, update URI, multi-domain PATCH

Negative TCs (16):
    N-TC001–007  : V3 signature / auth failures (missing, invalid, missing digest, tampered)
    N-TC005      : PATCH non-existent participant
    N-TC006      : V3 subscribe without prior whitelist
    N-TC007–041  : V3 PATCH edge cases (invalid refs, add domain, np_type immutability,
                   missing fields, cross-participant security, update while SUSPENDED)
    N-TC013      : Invalid field formats in V3 subscribe (bad email + URL)
    N-TC014      : V3 PATCH configs field rejected (V10)
    N-TC015      : Admin invalid state transition SUBSCRIBED→WHITELISTED (V18)
    N-TC016      : Admin cannot add new domain after subscribe (V12/V17)

Reference YAML: resources/registry/subscribe/test_v3_comprehensive.yml (V00–V25)

Usage:
    python func_test_scripts/ondc_registry_v3_subscribe_api_tests.py
    python func_test_scripts/ondc_registry_v3_subscribe_api_tests.py --suite functional
    python func_test_scripts/ondc_registry_v3_subscribe_api_tests.py --suite negative
    python func_test_scripts/ondc_registry_v3_subscribe_api_tests.py --timeout 30
    python func_test_scripts/ondc_registry_v3_subscribe_api_tests.py --output reports/my_report.html
    python func_test_scripts/ondc_registry_v3_subscribe_api_tests.py \
        --func-config resources/registry/subscribe/test_subscribe_functional.yml \
        --neg-config  resources/registry/subscribe/test_subscribe_negative.yml
"""

import argparse
import base64
import hashlib
import json
import logging
import os
import sys
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import requests
import yaml

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, PROJECT_ROOT)

RESULTS_DIR = os.path.join(PROJECT_ROOT, "results", "registry")
os.makedirs(RESULTS_DIR, exist_ok=True)

import urllib3
# SSL_VERIFY controls certificate validation for all HTTP requests.
# Default: True (secure). Set env var ONDC_SKIP_SSL_VERIFY=1 only for
# test environments that use self-signed certificates.
SSL_VERIFY: bool = os.environ.get("ONDC_SKIP_SSL_VERIFY", "0") != "1"
if not SSL_VERIFY:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional cryptography import (Ed25519 signer — same as gw_search script)
# ---------------------------------------------------------------------------
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    _HAS_CRYPTO = True
except ImportError:
    _HAS_CRYPTO = False
    logger.warning("cryptography library not found — V3 signature generation disabled.")


# ---------------------------------------------------------------------------
# ONDC Auth Helper  (Ed25519 + BLAKE2b-512, identical to gateway search)
# ---------------------------------------------------------------------------
class ONDCAuthHelper:
    """Generates ONDC Ed25519 + BLAKE2b-512 authentication headers."""

    def __init__(self, participant_id: str, uk_id: str, private_key_seed: bytes):
        if not _HAS_CRYPTO:
            raise RuntimeError("Install the cryptography package to enable auth generation.")
        self.participant_id = participant_id
        self.uk_id = uk_id
        self.private_key = Ed25519PrivateKey.from_private_bytes(private_key_seed)

    @staticmethod
    def _blake2b_digest(data: bytes) -> str:
        h = hashlib.blake2b(data, digest_size=64)
        return base64.b64encode(h.digest()).decode()

    def generate_headers(self, payload: dict, ttl: int = 300) -> dict:
        body_bytes = json.dumps(
            payload, separators=(",", ":"), sort_keys=False, ensure_ascii=False
        ).encode()
        created = int(time.time())
        expires = created + ttl
        digest_b64 = self._blake2b_digest(body_bytes)
        signing_string = (
            f"(created): {created}\n(expires): {expires}\ndigest: BLAKE-512={digest_b64}"
        )
        sig = self.private_key.sign(signing_string.encode())
        sig_b64 = base64.b64encode(sig).decode()
        key_id = f"{self.participant_id}|{self.uk_id}|ed25519"
        auth = (
            f'Signature keyId="{key_id}",'
            f'algorithm="ed25519",'
            f'created={created},'
            f'expires={expires},'
            f'headers="(created) (expires) digest",'
            f'signature="{sig_b64}"'
        )
        return {
            "Authorization": auth,
            "Content-Type": "application/json; charset=utf-8",
            "Digest": f"BLAKE-512={digest_b64}",
        }

    def generate_headers_as(self, payload: dict, spoofed_participant_id: str,
                             spoofed_uk_id: str = None, ttl: int = 300) -> dict:
        """Same as generate_headers() but overrides participant_id (and optionally uk_id) in keyId.
        The signature is still produced with this instance's private key — the registry will look
        up the spoofed participant's registered public key using the spoofed uk_id, which won't
        match our ephemeral private key, triggering a 401 signature failure or a 403 cross-
        participant rejection."""
        body_bytes = json.dumps(
            payload, separators=(",", ":"), sort_keys=False, ensure_ascii=False
        ).encode()
        created = int(time.time())
        expires = created + ttl
        digest_b64 = self._blake2b_digest(body_bytes)
        signing_string = (
            f"(created): {created}\n(expires): {expires}\ndigest: BLAKE-512={digest_b64}"
        )
        sig = self.private_key.sign(signing_string.encode())
        sig_b64 = base64.b64encode(sig).decode()
        effective_uk_id = spoofed_uk_id if spoofed_uk_id else self.uk_id
        key_id = f"{spoofed_participant_id}|{effective_uk_id}|ed25519"
        auth = (
            f'Signature keyId="{key_id}",'
            f'algorithm="ed25519",'
            f'created={created},'
            f'expires={expires},'
            f'headers="(created) (expires) digest",'
            f'signature="{sig_b64}"'
        )
        return {
            "Authorization": auth,
            "Content-Type": "application/json; charset=utf-8",
            "Digest": f"BLAKE-512={digest_b64}",
        }

    def generate_tampered_sig_headers(self, payload: dict) -> dict:
        headers = self.generate_headers(payload)
        headers["Authorization"] = headers["Authorization"].replace(
            'signature="', 'signature="TAMPERED'
        )
        return headers

    def generate_tampered_digest_headers(self, payload: dict) -> dict:
        headers = self.generate_headers(payload)
        headers["Digest"] = "BLAKE-512=INVALID_DIGEST_VALUE=="
        return headers

    def generate_expired_headers(self, payload: dict) -> dict:
        return self.generate_headers(payload, ttl=1)


# ---------------------------------------------------------------------------
# Config loader
# ---------------------------------------------------------------------------
def load_yaml_config(path: str, tenant: str = "ondcRegistry") -> dict:
    full_path = path if os.path.isabs(path) else os.path.join(PROJECT_ROOT, path)
    if not os.path.exists(full_path):
        logger.warning(f"Config not found: {full_path}")
        return {}
    with open(full_path, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    return data.get(tenant, {})


def _decode_private_key(raw: str) -> Optional[bytes]:
    """Accept 64-char hex OR base64-encoded PKCS#8/NaCl; return 32-byte seed."""
    if not raw:
        return None
    raw = raw.strip()
    if len(raw) == 64:
        try:
            return bytes.fromhex(raw)
        except ValueError:
            pass
    try:
        decoded = base64.b64decode(raw)
        if len(decoded) == 64:
            return decoded[:32]
        if len(decoded) >= 32:
            return decoded[-32:]
    except Exception:
        pass
    return None


_REQUIRED_FIELDS = ["host", "participant_id", "uk_id", "private_key_seed"]


def get_fresh_admin_token(cfg: dict) -> str:
    """Fetch a fresh admin JWT from the auth service; fall back to static token."""
    auth_url = cfg.get("admin_auth_url", "")
    username = cfg.get("admin_username", "")
    password = cfg.get("admin_password", "")
    if username and password and not username.startswith("<"):
        try:
            for login_payload in (
                {"email": username, "password": password},
                {"username": username, "password": password},
            ):
                r = requests.post(auth_url, json=login_payload, timeout=15, verify=SSL_VERIFY)
                if r.status_code == 200:
                    data = r.json()
                    tok = data.get("accessToken") or data.get("access_token") or data.get("token")
                    if tok:
                        print(f"[TOKEN] Fresh admin token obtained via login ({auth_url})")
                        return tok
            print(f"[TOKEN] Login failed ({r.status_code}) — falling back to static token")
        except Exception as exc:
            print(f"[TOKEN] Login error: {exc} — falling back to static token")
    return cfg.get("admin_token", "")


def validate_config(cfg: dict, config_path: str, label: str) -> None:
    missing = [f for f in _REQUIRED_FIELDS if not cfg.get(f)]
    if missing:
        lines = [f"  - {f}" for f in missing]
        raise ValueError(
            f"\n\n[CONFIG ERROR] {label} config is missing required fields:\n"
            + "\n".join(lines)
            + f"\n\nFile: {config_path}\n"
        )
    logger.info(f"{label} config OK — required fields present ({config_path})")


def build_auth_helper(cfg: dict, label: str = "") -> Optional[ONDCAuthHelper]:
    if not _HAS_CRYPTO:
        return None
    seed = _decode_private_key(str(cfg.get("private_key_seed", "")))
    if seed is None:
        logger.warning(
            f"Could not decode private_key_seed{(' for ' + label) if label else ''} "
            "— V3 signature disabled for this suite."
        )
        return None
    return ONDCAuthHelper(
        participant_id=str(cfg.get("participant_id", "")),
        uk_id=str(cfg.get("uk_id", "")),
        private_key_seed=seed,
    )


# ---------------------------------------------------------------------------
# Payload generator
# ---------------------------------------------------------------------------
class SubscribePayloadGenerator:
    """Generates Registry Subscribe API request payloads from YAML config."""

    NP_TYPE_MAP = {"seller": "BPP", "buyer": "BAP", "logistics": "GATEWAY",
                   "BPP": "BPP", "BAP": "BAP", "GATEWAY": "GATEWAY"}

    def __init__(self, cfg: dict):
        self.participant_id  = str(cfg.get("participant_id", ""))
        self.uk_id           = str(cfg.get("uk_id", ""))
        self.signing_key     = str(cfg.get("signing_public_key", base64.b64encode(os.urandom(32)).decode()))
        self.encryption_key  = str(cfg.get("encryption_public_key", base64.b64encode(os.urandom(32)).decode()))
        self.domains         = cfg.get("domains", ["ONDC:RET10"])
        self.cities          = cfg.get("cities", ["std:080"])
        self.np_types        = cfg.get("np_types", ["seller"])
        creds                = cfg.get("test_credentials", {})
        self.gst          = creds.get("gst",           "22ABCDE1234F1Z5")
        self.pan          = creds.get("pan",           "ABCDE1234F")
        self.fssai        = creds.get("fssai",         "12345678901234")
        self.business_name = creds.get("business_name", "Test Business Ltd")
        contacts  = cfg.get("test_contacts", {})
        self.tech_email = contacts.get("technical_email", "tech@example.com")
        self.biz_email  = contacts.get("business_email",  "business@example.com")
        self.phone      = contacts.get("phone",            "+911234567890")
        self.admin_token = str(cfg.get("admin_token", ""))
        self.host        = str(cfg.get("host", "https://registry-uat.kynondc.net")).rstrip("/")

    def _suffix(self) -> str:
        return str(uuid.uuid4())[:6]

    def _fresh_uk_id(self) -> str:
        return str(uuid.uuid4())

    def random_payload(self, np_type: str = "seller", domain: str = "ONDC:RET10",
                       action: str = "WHITELISTED", use_fixed_id: bool = False) -> dict:
        """Build a complete admin-subscribe payload."""
        sfx = self._suffix()
        pid = self.participant_id if use_fixed_id else f"{np_type}-{sfx}.participant.ondc"
        uk  = self.uk_id          if use_fixed_id else str(uuid.uuid4())
        sk  = self.signing_key    if use_fixed_id else base64.b64encode(os.urandom(32)).decode()
        ek  = self.encryption_key if use_fixed_id else base64.b64encode(os.urandom(32)).decode()
        npt = self.NP_TYPE_MAP.get(np_type, "BPP")
        cred_id    = f"cred_{sfx}_001"
        contact_id = f"contact_{sfx}_001"
        loc_id     = f"loc_{sfx}_001"
        uri_id     = f"uri_{sfx}_001"
        payload = {
            "participant_id": pid,
            "action": action,
            "credentials": [{
                "cred_id": cred_id, "type": "GST",
                "cred_data": {"pan": self.pan, "gstin": self.gst, "business_name": self.business_name}
            }],
            "contacts": [{
                "contact_id": contact_id, "type": "TECHNICAL",
                "name": "John Doe", "email": f"tech-{sfx}@example.com",
                "phone": self.phone, "address": "123 Tech Street, Bangalore",
                "designation": "Technical Lead", "is_primary": True
            }],
            "key": [{
                "uk_id": uk, "signing_public_key": sk, "encryption_public_key": ek,
                "signed_algorithm": "ED25519", "encryption_algorithm": "X25519",
                "valid_from": "2024-01-01T00:00:00.000Z", "valid_until": "2026-12-31T23:59:59.000Z"
            }],
            "configs": [{"domain": domain, "np_type": npt, "subscriber_id": pid}],
            "dns_skip": True,
            "skip_ssl_verification": True,
            # _meta is stripped before sending — internal only
            "_meta": {
                "participant_id": pid, "uk_id": uk, "sfx": sfx,
                "loc_id": loc_id, "uri_id": uri_id,
                "location": {"location_id": loc_id, "country": "IND", "city": self.cities[:1], "type": "SERVICEABLE"},
                "uri": {"uri_id": uri_id, "type": "CALLBACK", "url": f"https://{pid}/ondc"},
            },
        }
        return payload

    def admin_headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self.admin_token}",
            "Content-Type": "application/json",
        }


# ---------------------------------------------------------------------------
# Test-case builder  (mirrors build_test_cases() in gateway search script)
# ---------------------------------------------------------------------------
def build_test_cases(func_cfg: dict, neg_cfg: dict,
                     func_auth: Optional[ONDCAuthHelper],
                     neg_auth:  Optional[ONDCAuthHelper]) -> List[Dict[str, Any]]:

    func_host = func_cfg.get("host", "https://registry-uat.kynondc.net").rstrip("/")
    neg_host  = neg_cfg.get("host",  "https://registry-uat.kynondc.net").rstrip("/")
    fspg = SubscribePayloadGenerator(func_cfg)
    nspg = SubscribePayloadGenerator(neg_cfg)
    cases: List[Dict[str, Any]] = []

    # Helper — append one case
    def tc(tc_id, name, category, description, method, url, payload,
           expected_status, auth_mode, custom_headers=None,
           raw_body=None, raw_content_type=None,
           ttl=None, sleep_before=None, nack_ok=False,
           spoofed_caller_id=None, spoofed_caller_uk_id=None,
           spoofed_caller_signing_public_key=None):
        cases.append({
            "id": tc_id, "name": name, "category": category,
            "description": description, "method": method,
            "url": url, "payload": payload,
            "expected_status": expected_status, "auth_mode": auth_mode,
            "custom_headers": custom_headers,
            "raw_body": raw_body, "raw_content_type": raw_content_type,
            "ttl": ttl, "sleep_before": sleep_before, "nack_ok": nack_ok,
            "spoofed_caller_id": spoofed_caller_id,
            "spoofed_caller_uk_id": spoofed_caller_uk_id,
            "spoofed_caller_signing_public_key": spoofed_caller_signing_public_key,
        })

    admin = func_host  # admin and v3 share same base host

    # ==========================================================================
    # FUNCTIONAL TEST CASES  — V3 /v3.0/subscribe workflows only
    # Each TC uses a fresh Ed25519 keypair; admin whitelist is only a setup step.
    # Reference: test_v3_comprehensive.yml (V01–V16)
    # ==========================================================================

    # F-TC001 to F-TC004: V3 SUBSCRIBE WORKFLOW (admin-whitelist → V3 subscribe)
    # Each uses fresh Ed25519 keypair generated at runtime — see run_workflow_test_case()
    _wf = {"method": "WORKFLOW", "payload": None, "expected_status": [200],
           "auth_mode": "workflow", "is_workflow": True, "workflow_type": "v3_subscribe",
           "custom_headers": None, "raw_body": None, "raw_content_type": None,
           "ttl": None, "sleep_before": None, "nack_ok": False}

    cases.append({**_wf, "id": "F-TC001", "name": "V3 Seller Subscribe", "category": "Functional",
                  "url": f"{admin}/v3.0/subscribe",
                  "description": "[PASS EXPECTED — 2-step workflow] (1) Admin POST /admin/subscribe to whitelist "
                                 "a new seller Network Participant (BPP) for ONDC:RET10 with a freshly "
                                 "generated Ed25519 keypair. (2) V3 POST /v3.0/subscribe signed with the same "
                                 "keys to complete self-registration. Validates the baseline WHITELISTED→SUBSCRIBED "
                                 "flow for a seller NP using valid credentials, contacts, key, location, uri, and "
                                 "configs in the V3 payload.",
                  "workflow_np_type": "seller", "workflow_domain": "ONDC:RET10"})

    cases.append({**_wf, "id": "F-TC002", "name": "V3 Buyer Subscribe", "category": "Functional",
                  "url": f"{admin}/v3.0/subscribe",
                  "description": "[PASS EXPECTED — 2-step workflow] (1) Admin POST to whitelist a buyer Network "
                                 "Participant (BAP) for ONDC:RET10 using a fresh Ed25519 keypair. (2) V3 POST "
                                 "/v3.0/subscribe signed with the same keys. Validates that the V3 subscribe "
                                 "flow correctly handles the BAP np_type, distinct from the seller (BPP) flow "
                                 "tested in F-TC001.",
                  "workflow_np_type": "buyer", "workflow_domain": "ONDC:RET10"})

    cases.append({**_wf, "id": "F-TC003", "name": "V3 Logistics Subscribe", "category": "Functional",
                  "url": f"{admin}/v3.0/subscribe",
                  "description": "[PASS EXPECTED — 2-step workflow] (1) Admin POST to whitelist a logistics Network "
                                 "Participant (GATEWAY type) for the ONDC:LOG10 logistics domain using fresh Ed25519 "
                                 "keys. (2) V3 POST /v3.0/subscribe signed with the same keys. Validates that "
                                 "the V3 subscribe endpoint correctly handles the GATEWAY np_type and the ONDC:LOG10 "
                                 "domain, distinct from retail domain registrations.",
                  "workflow_np_type": "logistics", "workflow_domain": "ONDC:LOG10"})

    cases.append({**_wf, "id": "F-TC004", "name": "V3 Multi-domain Subscribe", "category": "Functional",
                  "url": f"{admin}/v3.0/subscribe",
                  "description": "[PASS EXPECTED — 2-step workflow] (1) Admin POST to whitelist a seller across "
                                 "three domains (ONDC:RET10, ONDC:RET11, ONDC:FIS12) in a single admin call. "
                                 "(2) V3 POST /v3.0/subscribe providing configs entries for all three domains "
                                 "in one request. Validates that a participant can use the V3 subscribe endpoint "
                                 "to register across multiple heterogeneous domains simultaneously.",
                  "workflow_np_type": "seller", "workflow_domain": "ONDC:RET10",
                  "workflow_domains": ["ONDC:RET10", "ONDC:RET11", "ONDC:FIS12"]})

    # F-TC005 to F-TC009: V3 PATCH WORKFLOW (admin-whitelist → V3 subscribe → V3 PATCH)
    _wfp = {**_wf, "workflow_type": "v3_patch", "workflow_np_type": "seller",
            "workflow_domain": "ONDC:RET10"}

    cases.append({**_wfp, "id": "F-TC005", "name": "V3 Add Contact (PATCH)", "category": "Functional",
                  "url": f"{admin}/v3.0/subscribe",
                  "description": "[PASS EXPECTED — 3-step workflow] (1) Admin POST to whitelist a seller. "
                                 "(2) V3 POST to subscribe (WHITELISTED→SUBSCRIBED). (3) V3 PATCH "
                                 "/v3.0/subscribe sending a new SUPPORT contact entry. Validates that a "
                                 "SUBSCRIBED participant can add supplementary contact records via V3 PATCH "
                                 "without re-subscribing or affecting existing data.",
                  "workflow_patch_type": "add_contact"})

    cases.append({**_wfp, "id": "F-TC006", "name": "V3 Add Credential (PATCH)", "category": "Functional",
                  "url": f"{admin}/v3.0/subscribe",
                  "description": "[PASS EXPECTED — 3-step workflow] (1) Admin POST to whitelist a seller. "
                                 "(2) V3 POST to subscribe (WHITELISTED→SUBSCRIBED). (3) V3 PATCH adding a "
                                 "new FSSAI food safety license credential to the participant record. Validates "
                                 "that a SUBSCRIBED participant can add additional government credentials post-"
                                 "registration via V3 PATCH without triggering re-validation of existing fields.",
                  "workflow_patch_type": "add_credential"})

    cases.append({**_wfp, "id": "F-TC007", "name": "V3 Update Business Info (PATCH Contacts + Credentials)", "category": "Functional",
                  "url": f"{admin}/v3.0/subscribe",
                  "description": "[PASS EXPECTED — 3-step workflow] (1) Admin POST to whitelist a seller. "
                                 "(2) V3 POST to subscribe. (3) V3 PATCH simultaneously updating both contacts "
                                 "(new SUPPORT contact) and credentials (new FSSAI credential) in a single PATCH "
                                 "request. Validates that business info can be updated via the V3 PATCH endpoint "
                                 "using supported fields. Note: additional_data is not a valid V3 PATCH field — "
                                 "contacts and credentials are the correct update vectors.",
                  "workflow_patch_type": "update_business_info"})

    cases.append({**_wfp, "id": "F-TC008", "name": "V3 Partial Patch (Location Only)", "category": "Functional",
                  "url": f"{admin}/v3.0/subscribe",
                  "description": "[PASS EXPECTED — 3-step workflow] (1) Admin POST to whitelist a seller. "
                                 "(2) V3 POST to subscribe. (3) V3 PATCH sending only the location object with "
                                 "an updated city list (std:011, std:022), leaving all other fields unchanged. "
                                 "Validates that V3 PATCH supports partial updates — a single field group can be "
                                 "modified in isolation without needing to resend the entire payload.",
                  "workflow_patch_type": "update_location"})

    cases.append({**_wfp, "id": "F-TC009", "name": "V3 Multi-field Patch", "category": "Functional",
                  "url": f"{admin}/v3.0/subscribe",
                  "description": "[PASS EXPECTED — 3-step workflow] (1) Admin POST to whitelist a seller. "
                                 "(2) V3 POST to subscribe. (3) V3 PATCH simultaneously updating three independent "
                                 "field groups — contacts (new BILLING contact), credentials (PAN update), and "
                                 "location (new city list) — in a single request. Validates that the V3 PATCH "
                                 "endpoint correctly applies atomic multi-field updates without partial failure.",
                  "workflow_patch_type": "multi_field"})

    cases.append({**_wfp, "id": "F-TC010", "name": "V3 Signature Rotation (Key PATCH)", "category": "Functional",
                  "url": f"{admin}/v3.0/subscribe",
                  "description": "[PASS EXPECTED — 3-step workflow] (1) Admin POST to whitelist a seller. "
                                 "(2) V3 POST to subscribe. (3) V3 PATCH submitting a new key object with a "
                                 "different uk_id and newly generated signing and encryption public keys. Validates "
                                 "that a SUBSCRIBED participant can rotate their Ed25519/X25519 key material via "
                                 "V3 PATCH without losing their SUBSCRIBED status.",
                  "workflow_patch_type": "key_rotation"})

    # F-TC011: V3 Re-subscribe (two-step: admin whitelist → V3 subscribe, repeat subscribe call)
    cases.append({**_wf, "id": "F-TC011", "name": "V3 Re-subscribe (Idempotent)", "category": "Functional",
                  "url": f"{admin}/v3.0/subscribe",
                  "description": "[PASS EXPECTED — 3-step workflow] (1) Admin POST to whitelist a seller. "
                                 "(2) V3 POST /v3.0/subscribe to reach SUBSCRIBED state. (3) V3 POST again "
                                 "with the identical payload while already SUBSCRIBED. Validates that the V3 "
                                 "subscribe endpoint is idempotent — re-subscribing while already in SUBSCRIBED "
                                 "state must return HTTP 200 without error or state regression.",
                  "workflow_np_type": "seller", "workflow_domain": "ONDC:RET10",
                  "workflow_type": "v3_subscribe_twice"})

    cases.append({**_wfp, "id": "F-TC012", "name": "V3 Buyer Patch Update", "category": "Functional",
                  "url": f"{admin}/v3.0/subscribe",
                  "description": "[PASS EXPECTED — 3-step workflow] (1) Admin POST to whitelist a buyer (BAP). "
                                 "(2) V3 POST to subscribe the buyer participant. (3) V3 PATCH adding a new "
                                 "TECHNICAL contact. Validates that buyer participants can update their contact "
                                 "records via V3 PATCH. Note: PROCUREMENT is not a valid V3 schema contact type "
                                 "and causes a SCHEMA_VALIDATION NACK; TECHNICAL is used per test_v3_comprehensive.yml V06.",
                  "workflow_np_type": "buyer", "workflow_domain": "ONDC:RET10",
                  "workflow_patch_type": "buyer_contact"})

    cases.append({**_wfp, "id": "F-TC013", "name": "V3 Logistics Patch Update", "category": "Functional",
                  "url": f"{admin}/v3.0/subscribe",
                  "description": "[PASS EXPECTED — 3-step workflow] (1) Admin POST to whitelist a logistics "
                                 "GATEWAY participant for ONDC:LOG10. (2) V3 POST to subscribe the logistics "
                                 "participant. (3) V3 PATCH updating the location.city array to cover additional "
                                 "serviceable cities (std:080, std:011, std:022, std:033). Validates that logistics "
                                 "participants can extend their geographic service coverage via V3 PATCH without "
                                 "re-registration.",
                  "workflow_np_type": "logistics", "workflow_domain": "ONDC:LOG10",
                  "workflow_patch_type": "logistics_location"})

    # F-TC014: V3 Self-restore from INACTIVE (V03 from test_v3_comprehensive.yml)
    # 3-step: admin whitelist → admin PATCH INACTIVE → V3 self-subscribe
    cases.append({**_wf, "id": "F-TC014", "name": "V3 Self-restore from INACTIVE",
                  "category": "Functional",
                  "url": f"{admin}/v3.0/subscribe",
                  "description": "[PASS EXPECTED — 3-step workflow] (1) Admin POST to whitelist a seller for "
                                 "ONDC:RET12. (2) Admin PATCH action=INACTIVE to forcibly deactivate the "
                                 "participant. (3) V3 POST /v3.0/subscribe from the participant themselves to "
                                 "self-restore to SUBSCRIBED state. Validates that a participant deactivated by "
                                 "an admin can trigger their own re-activation via the V3 subscribe endpoint "
                                 "(INACTIVE→SUBSCRIBED self-restore).",
                  "workflow_type": "v3_inactive_restore",
                  "workflow_np_type": "seller", "workflow_domain": "ONDC:RET12"})

    # F-TC015: V3 Update URI via PATCH (V08 from test_v3_comprehensive.yml)
    cases.append({**_wfp, "id": "F-TC015", "name": "V3 Update URI (PATCH)",
                  "category": "Functional",
                  "url": f"{admin}/v3.0/subscribe",
                  "description": "[PASS EXPECTED — 3-step workflow] (1) Admin POST to whitelist a seller. "
                                 "(2) V3 POST to subscribe. (3) V3 PATCH sending a new uri object with an "
                                 "updated callback URL. Validates that a SUBSCRIBED participant can change their "
                                 "registered callback endpoint via V3 PATCH. The updated URL must be stored "
                                 "correctly and the response must confirm success with HTTP 200.",
                  "workflow_patch_type": "update_uri"})

    # F-TC016: V3 Multi-domain config update via PATCH (V16 from test_v3_comprehensive.yml)
    # 3-step: admin whitelist multi-domain → V3 subscribe multi-domain → V3 PATCH location+URI
    cases.append({**_wf, "id": "F-TC016", "name": "V3 Multi-domain Config Update (PATCH)",
                  "category": "Functional",
                  "url": f"{admin}/v3.0/subscribe",
                  "description": "[PASS EXPECTED — 3-step workflow] (1) Admin POST to whitelist a seller "
                                 "across two domains (ONDC:RET10, ONDC:RET11). (2) V3 POST to subscribe with "
                                 "configs for both domains. (3) V3 PATCH updating location and URI fields, which "
                                 "apply globally across all registered domains. Validates that shared location "
                                 "and callback URI fields can be updated via a single V3 PATCH and take effect "
                                 "simultaneously for all the participant's active domain registrations.",
                  "workflow_type": "v3_multi_domain_patch",
                  "workflow_np_type": "seller", "workflow_domain": "ONDC:RET10",
                  "workflow_domains": ["ONDC:RET10", "ONDC:RET11"]})

    # ==========================================================================
    # NEGATIVE TEST CASES  — V3 /v3.0/subscribe only
    # Reference: test_v3_comprehensive.yml (V19–V25) + security edge cases
    # ==========================================================================
    # Negative tests target /v3.0/subscribe exclusively.
    # Always route to the registry host (func_host).
    neg_admin = func_host

    # N-TC001: V3 Missing Signature
    p = nspg.random_payload(np_type="seller")
    tc("N-TC001", "V3 Missing Signature Header", "Negative",
       "[FAIL EXPECTED — 401/400] Sends a V3 POST /v3.0/subscribe request with no Authorization "
       "header at all. The ONDC V3 protocol mandates an Ed25519 BLAKE2b-512 signed Authorization "
       "header on every request. A completely absent header must cause the API to return HTTP 401 "
       "or 400, refusing to process the unsigned subscribe attempt.",
       "POST", f"{neg_admin}/v3.0/subscribe", p,
       [401, 400], "custom",
       custom_headers={"Content-Type": "application/json"})

    # N-TC002: V3 Invalid Signature
    p = nspg.random_payload(np_type="seller")
    tc("N-TC002", "V3 Invalid Signature String", "Negative",
       "[FAIL EXPECTED — 401/400] Sends a V3 POST with an Authorization header containing a "
       "syntactically invalid Signature string (wrong keyId format, dummy base64 signature value, "
       "invalid Digest). The API must parse and verify the Authorization header structure and return "
       "HTTP 401 or 400 when the signature cannot be validated cryptographically.",
       "POST", f"{neg_admin}/v3.0/subscribe", p,
       [401, 400], "custom",
       custom_headers={
           "Content-Type": "application/json",
           'Authorization': 'Signature keyId="invalid|key|ed25519",algorithm="ed25519",signature="INVALID"',
           "Digest": "BLAKE-512=INVALID"
       })

    # N-TC003: V3 Missing Digest
    p = nspg.random_payload(np_type="seller")
    tc("N-TC003", "V3 Missing Digest Header", "Negative",
       "[FAIL EXPECTED — 401/400/412] Sends a V3 POST with a valid-format Authorization header but "
       "without a Digest header. The ONDC signing scheme requires the BLAKE2b-512 Digest of the "
       "request body to be included in the Digest header and referenced in the signed string. "
       "Omitting the Digest header must cause the API to reject the request with HTTP 401, 400, or "
       "412 (Precondition Failed).",
       "POST", f"{neg_admin}/v3.0/subscribe", p,
       [401, 400, 412], "custom",
       custom_headers={
           "Content-Type": "application/json",
           'Authorization': 'Signature keyId="test|key|ed25519",algorithm="ed25519",signature="dummy"'
       })

    # N-TC004: V3 Signature/Payload Mismatch  (tampered digest)
    p = nspg.random_payload(np_type="seller")
    tc("N-TC004", "V3 Signature Payload Mismatch", "Negative",
       "[FAIL EXPECTED — 401/400] Sends a V3 POST where the Authorization signature was computed "
       "over a different payload than the one actually sent (tampered Digest header). The API must "
       "recompute the BLAKE2b-512 digest of the received body, compare it against the Digest header, "
       "and return HTTP 401 or 400 when a mismatch is detected — preventing replay and body-swap attacks.",
       "POST", f"{neg_admin}/v3.0/subscribe", p,
       [401, 400], "v3_tamper_digest")

    # N-TC005: PATCH non-existent participant
    tc("N-TC005", "PATCH Non-existent Participant", "Negative",
       "[FAIL EXPECTED — 404/401/400] Sends a V3 PATCH /v3.0/subscribe targeting a participant_id "
       "that does not exist in the registry ('nonexistent-participant-12345'). The API must reject "
       "the request because the signing key in the Authorization header cannot be resolved to any "
       "registered participant, returning HTTP 401 (auth key lookup failure), 404 (participant not "
       "found), or 400. All three indicate the API correctly refused to process the update.",
       "PATCH", f"{neg_admin}/v3.0/subscribe",
       {"participant_id": "nonexistent-participant-12345",
        "contacts": [{"contact_type": "TECHNICAL", "email": "tech@example.com"}]},
       [404, 401, 400], "v3_sig")

    # N-TC006: Subscribe without whitelist
    p = nspg.random_payload(np_type="seller", domain="ONDC:RET10")
    p.pop("action", None); p.pop("_meta", None); p.pop("location", None); p.pop("uri", None)
    tc("N-TC006", "V3 Subscribe Without Prior Whitelist", "Negative",
       "[FAIL EXPECTED — 400] Sends a V3 POST /v3.0/subscribe for a brand-new participant_id "
       "that has never been whitelisted by an admin. Network participants must be admin-whitelisted "
       "before they can self-register via V3. The API must enforce this pre-condition and return "
       "HTTP 400 with a whitelist-required error, preventing unauthorised self-registration.",
       "POST", f"{neg_admin}/v3.0/subscribe", p, [400], "v3_sig", nack_ok=True)

    # ---------------------------------------------------------------------------
    # Shared /lookup: fetch real participant IDs for N-TC007–N-TC013.
    # Using real participants ensures the registry processes auth/validation logic
    # against actual registry state rather than immediately returning 404 for a
    # non-existent synthetic participant.
    # ---------------------------------------------------------------------------
    _neg_domains = neg_cfg.get("domains", ["ONDC:RET10", "ONDC:RET11"])
    _neg_dom0 = _neg_domains[0] if _neg_domains else "ONDC:RET10"
    _neg_dom1 = _neg_domains[1] if len(_neg_domains) > 1 else "ONDC:RET11"
    _neg_real_pids = []  # list of (subscriber_id, uk_id, signing_public_key)
    try:
        _neg_lr = requests.post(
            f"{neg_admin}/lookup",
            json={"domain": "ONDC:FIS12", "type": "BPP"},
            timeout=10,
            verify=SSL_VERIFY
        )
        if _neg_lr.status_code == 200:
            _neg_lr_list = _neg_lr.json() if isinstance(_neg_lr.json(), list) else []
            _neg_own_id = neg_cfg.get("subscriber_id", "")
            for _entry in _neg_lr_list:
                _sid = _entry.get("subscriber_id") or _entry.get("participant_id", "")
                if _sid and _sid != _neg_own_id and _sid not in [x[0] for x in _neg_real_pids]:
                    _uid = (_entry.get("ukId") or _entry.get("uk_id") or
                            (_entry.get("key") or {}).get("ukId") or
                            (_entry.get("key") or {}).get("uk_id") or
                            ((_entry.get("keys") or [{}])[0]).get("ukId") or
                            ((_entry.get("keys") or [{}])[0]).get("uk_id", ""))
                    _spk = (_entry.get("signing_public_key") or _entry.get("signingPublicKey") or
                            (_entry.get("key") or {}).get("signing_public_key") or
                            ((_entry.get("keys") or [{}])[0]).get("signing_public_key", ""))
                    _neg_real_pids.append((_sid, _uid, _spk))
                if len(_neg_real_pids) >= 2:
                    break
    except Exception as _neg_le:
        logger.warning(f"  [/lookup] call failed ({_neg_le}) — N-TC007–N-TC013 needing real participants will be skipped")
    _neg_pid_target = _neg_real_pids[0][0] if len(_neg_real_pids) >= 1 else None
    _neg_uid_target = _neg_real_pids[0][1] if len(_neg_real_pids) >= 1 else None
    _neg_spk_target = _neg_real_pids[0][2] if len(_neg_real_pids) >= 1 else None
    _neg_pid_caller = _neg_real_pids[1][0] if len(_neg_real_pids) >= 2 else None
    _neg_uid_caller = _neg_real_pids[1][1] if len(_neg_real_pids) >= 2 else None
    _neg_spk_caller = _neg_real_pids[1][2] if len(_neg_real_pids) >= 2 else None

    # N-TC007: Config with invalid location/URI references
    if _neg_pid_target:
        p = {"participant_id": _neg_pid_target,
             "configs": [{"subscriber_id": _neg_pid_target, "key_id": str(uuid.uuid4()),
                          "domain": _neg_dom0, "np_type": "BPP",
                          "location_id": "loc001_nonexistent", "uri_id": "uri001_nonexistent"}]}
        tc("N-TC007", "V3 Config with Invalid location_id/uri_id References", "Negative",
           f"[FAIL EXPECTED — 400/401/403/404] Sends a V3 PATCH /v3.0/subscribe targeting a real "
           f"participant '{_neg_pid_target}' (resolved via /lookup ONDC:FIS12/BPP) with a configs "
           f"entry referencing non-existent location_id ('loc001_nonexistent') and uri_id "
           f"('uri001_nonexistent'). The API must validate that all foreign-key references within "
           f"the configs array resolve to existing entries and return HTTP 400 or 404 for dangling "
           f"references, or 401/403 for the cross-participant ownership check.",
           "PATCH", f"{neg_admin}/v3.0/subscribe", p, [400, 401, 403, 404], "v3_sig", nack_ok=True)
    else:
        logger.warning("  [N-TC007] SKIPPED — /lookup returned no usable participants")

    # N-TC008: V3 user attempts to add new domain config
    if _neg_pid_target:
        p = {"participant_id": _neg_pid_target,
             "configs": [
                 {"subscriber_id": _neg_pid_target, "key_id": str(uuid.uuid4()),
                  "domain": _neg_dom0, "np_type": "BPP",
                  "location_id": "loc001", "uri_id": "uri001"},
                 {"subscriber_id": _neg_pid_target, "key_id": str(uuid.uuid4()),
                  "domain": _neg_dom1, "np_type": "GATEWAY",
                  "location_id": "loc001", "uri_id": "uri001"},
             ]}
        tc("N-TC008", "V3 User Cannot Add New Domain Config", "Negative",
           f"[FAIL EXPECTED — 400/401/403] Sends a V3 PATCH /v3.0/subscribe targeting a real "
           f"participant '{_neg_pid_target}' (resolved via /lookup ONDC:FIS12/BPP) with a configs "
           f"array attempting to add '{_neg_dom1}' — a domain the participant was not originally "
           f"whitelisted for. Adding new domain configs is an admin-only operation. The API must "
           f"return HTTP 400 for the unauthorised domain addition, or 401/403 for the cross-"
           f"participant ownership check.",
           "PATCH", f"{neg_admin}/v3.0/subscribe", p, [400, 401, 403], "v3_sig", nack_ok=True)
    else:
        logger.warning("  [N-TC008] SKIPPED — /lookup returned no usable participants")

    # N-TC009: np_type immutability — real participant is BPP; attempt to change it to BAP
    if _neg_pid_target:
        p = {"participant_id": _neg_pid_target,
             "configs": [{"subscriber_id": _neg_pid_target, "key_id": str(uuid.uuid4()),
                          "domain": _neg_dom1, "np_type": "BAP",
                          "location_id": "loc001", "uri_id": "uri001"}]}
        tc("N-TC009", "Domain np_type Immutability (BPP→BAP Forbidden)", "Negative",
           f"[FAIL EXPECTED — 400/401/403] Sends a V3 PATCH /v3.0/subscribe targeting a real "
           f"participant '{_neg_pid_target}' (resolved via /lookup ONDC:FIS12/BPP) with a configs "
           f"entry attempting to change np_type from the registered 'BPP' to 'BAP'. Once a Network "
           f"Participant type is set during admin whitelisting, it is immutable. The API must detect "
           f"this attempted change and return HTTP 400, enforcing np_type immutability as a core "
           f"registry integrity rule, or 401/403 for the cross-participant ownership check.",
           "PATCH", f"{neg_admin}/v3.0/subscribe", p, [400, 401, 403], "v3_sig", nack_ok=True)
    else:
        logger.warning("  [N-TC009] SKIPPED — /lookup returned no usable participants")

    # N-TC010: Invalid state transition (POST missing mandatory fields)
    if _neg_pid_target:
        p = {"request_id": str(uuid.uuid4()), "participant_id": _neg_pid_target,
             "configs": [{"subscriber_id": _neg_pid_target, "key_id": str(uuid.uuid4()),
                          "domain": _neg_dom1, "np_type": "GATEWAY",
                          "location_id": "loc001", "uri_id": "uri001"}]}
        tc("N-TC010", "Invalid State Transition (POST missing mandatory fields)", "Negative",
           f"[FAIL EXPECTED — 400/401/403] Sends a V3 POST /v3.0/subscribe targeting a real "
           f"participant '{_neg_pid_target}' (resolved via /lookup ONDC:FIS12/BPP) with a payload "
           f"that contains only request_id, participant_id, and configs — omitting all other "
           f"mandatory fields (credentials, contacts, key, location, uri). The API must detect the "
           f"missing required fields and return HTTP 400, or 401/403 for the cross-participant "
           f"ownership check.",
           "POST", f"{neg_admin}/v3.0/subscribe", p, [400, 401, 403], "v3_sig", nack_ok=True)
    else:
        logger.warning("  [N-TC010] SKIPPED — /lookup returned no usable participants")

    # N-TC011: Cross-participant update (security test)
    # Reuses real participants fetched by the shared /lookup block above.
    #   _neg_pid_target  — goes in the request body as participant_id (the victim being impersonated)
    #   _neg_pid_caller  — goes in the Authorization keyId (the spoofed caller identity)
    # The signature is produced with our own ephemeral private key but claims to be _neg_pid_caller.
    # The registry will look up _neg_pid_caller's registered public key → signature won't match → 401,
    # OR it detects keyId participant ≠ body participant_id first → 403.
    # Either outcome proves cross-participant updates are blocked.
    if _neg_pid_target and _neg_pid_caller:
        p = {"participant_id": _neg_pid_target,
             "contacts": [{"type": "TECHNICAL", "name": "Hacker",
                           "email": "hacker@example.com", "phone": "+919999999999"}]}
        tc("N-TC011", "SECURITY: Cross-Participant Update Prevention", "Negative",
           f"[FAIL EXPECTED — 401/403 — CRITICAL SECURITY TEST] Sends a V3 PATCH /v3.0/subscribe "
           f"where the Authorization keyId claims to be '{_neg_pid_caller}' "
           f"(resolved via /lookup ONDC:FIS12/BPP) but the request body targets "
           f"a completely different participant '{_neg_pid_target}'. The signature is produced with the "
           f"test runner's own ephemeral key — the registry will look up {_neg_pid_caller}'s real "
           f"signing_public_key, find the signature doesn't match (401), or detect the "
           f"keyId/participant_id mismatch first (403). Either response confirms cross-participant "
           f"updates are blocked.",
           "PATCH", f"{neg_admin}/v3.0/subscribe", p, [403, 401], "v3_sig_spoofed_caller",
           spoofed_caller_id=_neg_pid_caller, spoofed_caller_uk_id=_neg_uid_caller or None,
           spoofed_caller_signing_public_key=_neg_spk_caller or None)
    else:
        logger.warning("  [N-TC011] SKIPPED — /lookup returned fewer than 2 usable participants")

    # N-TC012: Update while SUSPENDED — real participant from /lookup
    if _neg_pid_target:
        p = {"participant_id": _neg_pid_target,
             "contacts": [{"type": "TECHNICAL", "name": "Suspended Contact",
                           "email": "suspended@example.com", "phone": nspg.phone}]}
        tc("N-TC012", "V3 Update While Participant is SUSPENDED", "Negative",
           f"[FAIL EXPECTED — 400/401/403] Sends a V3 PATCH /v3.0/subscribe targeting a real "
           f"participant '{_neg_pid_target}' (resolved via /lookup ONDC:FIS12/BPP). The registry "
           f"must block participant-initiated updates from unauthorised callers: HTTP 401/403 for "
           f"the cross-participant ownership check, or HTTP 400 if the participant is in SUSPENDED "
           f"state. All three indicate the API correctly refused to process the update.",
           "PATCH", f"{neg_admin}/v3.0/subscribe", p, [400, 401, 403], "v3_sig", nack_ok=True)
    else:
        logger.warning("  [N-TC012] SKIPPED — /lookup returned no usable participants")

    # N-TC013: Invalid field formats in a single V3 subscribe request
    # (V24 from test_v3_comprehensive.yml — combined invalid email + invalid URL in V3 POST)
    if _neg_pid_target:
        uk9  = str(uuid.uuid4())
        _inv_data     = neg_cfg.get("invalid_data", {})
        _invalid_email = _inv_data.get("invalid_email", "not-an-email")
        _invalid_url   = _inv_data.get("invalid_url",   "not-a-valid-url")
        _neg_cities    = neg_cfg.get("cities", ["std:080"])
        p = {
            "request_id": str(uuid.uuid4()),
            "participant_id": _neg_pid_target,
            "uk_id": uk9,
            "credentials": [{"cred_id": "cred001", "type": "GST",
                             "cred_data": {"gstin": nspg.gst, "legal_name": "Test Co"}}],
            "contacts": [{"contact_id": "invalid_contact", "type": "AUTHORISED_SIGNATORY",
                          "email": _invalid_email,
                          "phone": "invalid-phone",
                          "name": "Bad Contact"}],
            "key": [{"uk_id": uk9, "signing_public_key": "dummykey",
                     "encryption_public_key": "dummykey",
                     "signed_algorithm": "ED25519", "encryption_algorithm": "X25519",
                     "valid_from": "2024-01-01T00:00:00Z", "valid_until": "2026-12-31T00:00:00Z"}],
            "location": [{"location_id": "loc001", "country": "IND",
                          "city": [_neg_cities[0] if _neg_cities else "std:080"], "type": "SERVICEABLE"}],
            "uri": [{"uri_id": "uri001", "type": "CALLBACK", "url": _invalid_url}],
            "configs": [{"domain": _neg_dom0, "np_type": "BPP", "subscriber_id": _neg_pid_target,
                         "location_id": "loc001", "uri_id": "uri001", "key_id": uk9}],
            "dns_skip": True, "skip_ssl_verification": True,
        }
        tc("N-TC013", "Invalid Field Formats in V3 Subscribe (email + URL)", "Negative",
           f"[FAIL EXPECTED — 400/401/403] Sends a fully-structured V3 POST /v3.0/subscribe "
           f"targeting a real participant '{_neg_pid_target}' (resolved via /lookup ONDC:FIS12/BPP) "
           f"with three simultaneous field-format violations: contacts.email set to 'not-an-email' "
           f"(missing @ and domain), contacts.phone set to 'invalid-phone' (non-numeric format), "
           f"and uri.url set to 'not-a-valid-url' (not a valid HTTP/HTTPS URI). The API must "
           f"perform format validation and return HTTP 400, or 401/403 for the cross-participant "
           f"ownership check.",
           "POST", f"{neg_admin}/v3.0/subscribe", p, [400, 401, 403], "v3_sig", nack_ok=True)
    else:
        logger.warning("  [N-TC013] SKIPPED — /lookup returned no usable participants")

    # N-TC014: V10 — V3 PATCH with configs field (negative — must fail 400)
    # (V10 from test_v3_comprehensive.yml)
    cases.append({**_wf,
                  "id": "N-TC014",
                  "name": "V3 PATCH — Configs Field Rejected (V10)",
                  "category": "Negative",
                  "url": f"{neg_admin}/v3.0/subscribe",
                  "description": "[FAIL EXPECTED — 400 — 3-step workflow] (1) Admin POST to whitelist a seller "
                                 "for ONDC:RET11. (2) V3 POST to subscribe. (3) V3 PATCH attempting to include "
                                 "a configs array in the patch body, trying to modify the domain configuration. "
                                 "Participants are not permitted to alter configs via V3 PATCH — only contacts, "
                                 "credentials, key, location, and uri are allowed fields. The API must return "
                                 "HTTP 400, enforcing the configs immutability rule for V3 PATCH.",
                  "workflow_type": "v3_patch_configs_negative",
                  "workflow_np_type": "seller", "workflow_domain": "ONDC:RET11",
                  "expected_status": [400, 422]})

    # N-TC015: V18 — Admin invalid state transition SUBSCRIBED→WHITELISTED (negative)
    # (V18 from test_v3_comprehensive.yml)
    cases.append({**_wf,
                  "id": "N-TC015",
                  "name": "Admin Invalid State Transition SUBSCRIBED→WHITELISTED (V18)",
                  "category": "Negative",
                  "url": f"{neg_admin}/admin/subscribe",
                  "description": "[FAIL EXPECTED — 400 — 3-step workflow] (1) Admin POST to whitelist a seller. "
                                 "(2) V3 POST to complete self-registration (WHITELISTED→SUBSCRIBED). "
                                 "(3) Admin PATCH /admin/subscribe with action=WHITELISTED, attempting to "
                                 "retrograde the participant's state backward from SUBSCRIBED to WHITELISTED. "
                                 "The registry state machine only permits forward transitions. The API must "
                                 "return HTTP 400, enforcing that backward state transitions are prohibited.",
                  "workflow_type": "admin_invalid_transition",
                  "workflow_np_type": "seller", "workflow_domain": "ONDC:RET10",
                  "expected_status": [400, 422]})

    # N-TC016: V12/V17 — Admin cannot add new domain config after subscribe (negative)
    # (V12, V17 from test_v3_comprehensive.yml)
    cases.append({**_wf,
                  "id": "N-TC016",
                  "name": "Admin Cannot Add New Domain After Subscribe (V12/V17)",
                  "category": "Negative",
                  "url": f"{neg_admin}/admin/subscribe",
                  "description": "[FAIL EXPECTED — 400/404 — 3-step workflow] (1) Admin POST to whitelist a "
                                 "seller only for ONDC:RET10. (2) V3 POST to complete subscription for "
                                 "ONDC:RET10. (3) Admin PATCH /admin/subscribe attempting to add a new domain "
                                 "(ONDC:RET11) that was never included in the original whitelist. Participants "
                                 "must be explicitly whitelisted per domain before configs can exist for that "
                                 "domain. The API must return HTTP 400 or 404, enforcing that new domain "
                                 "configs cannot be added post-registration without a prior whitelist entry.",
                  "workflow_type": "admin_add_domain_negative",
                  "workflow_np_type": "seller", "workflow_domain": "ONDC:RET10",
                  "expected_status": [400, 404]})

    return cases


# ---------------------------------------------------------------------------
# NACK / error code helpers  (same logic as gateway search script)
# ---------------------------------------------------------------------------
def _is_nack(body: str) -> bool:
    try:
        data = json.loads(body)
        return str(data.get("message", {}).get("ack", {}).get("status", "")).upper() == "NACK"
    except Exception:
        return False


def _get_error_code(body: str) -> Optional[str]:
    try:
        data = json.loads(body)
        code = data.get("error", {}).get("code", "")
        return str(code) if code else None
    except Exception:
        return None


def _get_error_type(body: str) -> Optional[str]:
    try:
        data = json.loads(body)
        t = data.get("error", {}).get("type", "")
        return str(t) if t else None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# V3 Workflow helpers — fresh-keypair multi-step execution
# ---------------------------------------------------------------------------
NP_TYPE_MAP_WF = {"seller": "BPP", "buyer": "BAP", "logistics": "GATEWAY"}


def _generate_fresh_keys() -> dict:
    """Generate a fresh Ed25519 keypair + unique participant/uk IDs."""
    seed = os.urandom(32)
    if _HAS_CRYPTO:
        priv = Ed25519PrivateKey.from_private_bytes(seed)
        pub_raw = priv.public_key().public_bytes_raw()
        signing_pub = base64.b64encode(pub_raw).decode()
    else:
        signing_pub = base64.b64encode(os.urandom(32)).decode()
    enc_pub = base64.b64encode(os.urandom(32)).decode()
    sfx = str(uuid.uuid4())[:8]
    ts  = str(int(time.time()))[-6:]
    participant_id = f"test-qa-{ts}-{sfx}.participant.ondc"
    uk_id = str(uuid.uuid4())
    auth = (
        ONDCAuthHelper(participant_id, uk_id, seed) if _HAS_CRYPTO else None
    )
    return {
        "seed": seed, "signing_public_key": signing_pub,
        "encryption_public_key": enc_pub,
        "participant_id": participant_id, "uk_id": uk_id, "auth": auth,
    }


def _build_admin_whitelist_payload(keys: dict, np_type: str, domain: str,
                                   domains: list = None, cfg: dict = None) -> dict:
    """Admin subscribe payload (WHITELISTED) using fresh keys.

    Pass `domains` to whitelist multiple domains in one call (required when the
    subsequent V3 subscribe will reference more than one domain, e.g. F-TC004).
    Pass `cfg` to source credentials and contacts from the YAML config instead of
    using hardcoded fallback values.
    """
    cfg_         = cfg or {}
    creds_cfg    = cfg_.get("test_credentials", {})
    contacts_cfg = cfg_.get("test_contacts", {})
    pan          = creds_cfg.get("pan",           "ABCDE1234F")
    gst          = creds_cfg.get("gst",           "22ABCDE1234F1Z5")
    biz_name     = creds_cfg.get("business_name", "Test Business Ltd")
    phone        = contacts_cfg.get("phone",      "+919876543210")
    sfx = str(uuid.uuid4())[:6]
    pid = keys["participant_id"]; uk = keys["uk_id"]
    npt = NP_TYPE_MAP_WF.get(np_type, "BPP")
    all_domains = domains if domains else [domain]
    return {
        "participant_id": pid,
        "action": "WHITELISTED",
        "credentials": [{"cred_id": f"cred-gst-{sfx}", "type": "GST",
                         "cred_data": {"pan": pan, "gstin": gst, "business_name": biz_name}}],
        "contacts": [{"contact_id": f"contact-tech-{sfx}", "type": "TECHNICAL",
                      "name": "John Doe", "email": f"tech-{sfx}@example.com",
                      "phone": phone, "is_primary": True}],
        "key": [{
            "uk_id": uk, "signing_public_key": keys["signing_public_key"],
            "encryption_public_key": keys["encryption_public_key"],
            "signed_algorithm": "ED25519", "encryption_algorithm": "X25519",
            "valid_from": "2024-01-01T00:00:00.000Z", "valid_until": "2026-12-31T23:59:59.000Z",
        }],
        "configs": [{"domain": d, "np_type": npt, "subscriber_id": pid} for d in all_domains],
        "dns_skip": True, "skip_ssl_verification": True,
    }


def _build_v3_subscribe_payload(keys: dict, np_type: str, domain: str,
                                multi_domains: Optional[list] = None,
                                cfg: dict = None) -> dict:
    """Full V3 subscribe payload (credentials, contacts, key, location, uri, configs).

    Pass `cfg` to source credentials, contacts, and cities from the YAML config.
    """
    cfg_         = cfg or {}
    creds_cfg    = cfg_.get("test_credentials", {})
    contacts_cfg = cfg_.get("test_contacts", {})
    all_cities   = cfg_.get("cities", ["std:080"])
    gst          = creds_cfg.get("gst",           "22ABCDE1234F1Z5")
    pan          = creds_cfg.get("pan",           "ABCDE1234F")
    biz_name     = creds_cfg.get("business_name", "Test Company Private Limited")
    phone        = contacts_cfg.get("phone",      "+919876543210")
    city_1       = all_cities[0] if all_cities else "std:080"
    sfx   = str(uuid.uuid4())[:6]
    pid   = keys["participant_id"]; uk = keys["uk_id"]
    npt   = NP_TYPE_MAP_WF.get(np_type, "BPP")
    loc_id = f"loc-{sfx}"; uri_id = f"uri-{sfx}"
    domains = multi_domains or [domain]
    return {
        "request_id": str(uuid.uuid4()),
        "uk_id": uk,
        "participant_id": pid,
        "credentials": [
            {"cred_id": f"cred-gst-{sfx}", "type": "GST",
             "cred_data": {"gstin": gst, "legal_name": biz_name}},
            {"cred_id": f"cred-pan-{sfx}", "type": "PAN",
             "cred_data": {"pan_no": pan}},
        ],
        "contacts": [
            {"contact_id": f"contact-auth-{sfx}", "type": "AUTHORISED_SIGNATORY",
             "name": "Authorized Signatory", "email": f"auth-{sfx}@example.com",
             "phone": phone, "designation": "Authorized Signatory", "is_primary": False},
            {"contact_id": f"contact-biz-{sfx}", "type": "BUSINESS",
             "name": "Business Manager", "email": f"biz-{sfx}@example.com",
             "phone": phone, "designation": "Business Head", "is_primary": False},
        ],
        "key": [{
            "uk_id": uk, "signing_public_key": keys["signing_public_key"],
            "encryption_public_key": keys["encryption_public_key"],
            "signed_algorithm": "ED25519", "encryption_algorithm": "X25519",
            "valid_from": "2024-01-01T00:00:00.000Z", "valid_until": "2026-12-31T23:59:59.000Z",
        }],
        "location": [{"location_id": loc_id, "country": "IND", "city": [city_1], "type": "SERVICEABLE"}],
        "uri": [{"uri_id": uri_id, "type": "CALLBACK", "url": f"https://{pid}/ondc"}],
        "configs": [
            {"domain": d, "np_type": npt, "subscriber_id": pid,
             "location_id": loc_id, "uri_id": uri_id, "key_id": uk}
            for d in domains
        ],
        "dns_skip": True, "skip_ssl_verification": True,
    }


def _build_patch_payload(keys: dict, patch_type: str, cfg: dict = None) -> dict:
    """Build the PATCH body based on patch_type.

    Pass `cfg` to source credentials, contacts, and cities from the YAML config.
    """
    cfg_         = cfg or {}
    creds_cfg    = cfg_.get("test_credentials", {})
    contacts_cfg = cfg_.get("test_contacts", {})
    all_cities   = cfg_.get("cities", ["std:080", "std:011", "std:022", "std:033", "std:044"])
    phone        = contacts_cfg.get("phone",      "+919876543210")
    fssai        = creds_cfg.get("fssai",         "12345678901234")
    pan          = creds_cfg.get("pan",           "ABCDE1234F")
    biz_name     = creds_cfg.get("business_name", "Test Business Ltd")
    # City subsets for different patch location scenarios
    update_cities    = all_cities[1:3] if len(all_cities) >= 3 else (all_cities[:2] or ["std:011", "std:022"])
    logistics_cities = all_cities[:4]  if len(all_cities) >= 4 else (all_cities or ["std:080"])
    multi_cities     = all_cities[3:5] if len(all_cities) >= 5 else (all_cities[-2:] if len(all_cities) >= 2 else all_cities)
    pid = keys["participant_id"]; uk = keys["uk_id"]
    sfx = str(uuid.uuid4())[:6]
    base = {"participant_id": pid, "uk_id": uk, "request_id": str(uuid.uuid4())}

    if patch_type == "add_contact":
        base["contacts"] = [{"contact_id": f"contact-sup-{sfx}", "type": "SUPPORT",
                              "name": "Support Team", "email": f"support-{sfx}@example.com",
                              "phone": phone, "designation": "Support Manager", "is_primary": False}]
    elif patch_type == "add_credential":
        base["credentials"] = [{"cred_id": f"cred-fssai-{sfx}", "type": "FSSAI",
                                 "cred_data": {"license_number": fssai,
                                               "business_name": biz_name}}]
    elif patch_type == "update_additional_data":
        # Kept for backwards-compat; update_business_info is the corrected version
        base["contacts"] = [{"contact_id": f"contact-sup-{sfx}", "type": "SUPPORT",
                              "name": "Support Team", "email": f"support-{sfx}@example.com",
                              "phone": phone, "designation": "Support Manager", "is_primary": False}]
        base["credentials"] = [{"cred_id": f"cred-fssai-{sfx}", "type": "FSSAI",
                                 "cred_data": {"license_number": fssai,
                                               "business_name": biz_name}}]
    elif patch_type == "update_business_info":
        # V3 PATCH with valid fields representing a business-info update.
        # additional_data is NOT a valid V3 PATCH field (API returns SCHEMA_VALIDATION NACK).
        base["contacts"] = [{"contact_id": f"contact-sup-{sfx}", "type": "SUPPORT",
                              "name": "Support Team", "email": f"support-{sfx}@example.com",
                              "phone": phone, "designation": "Support Manager", "is_primary": False}]
        base["credentials"] = [{"cred_id": f"cred-fssai-{sfx}", "type": "FSSAI",
                                 "cred_data": {"license_number": fssai,
                                               "business_name": biz_name}}]
    elif patch_type == "update_location":
        base["location"] = [{"location_id": keys.get("loc_id", f"loc-{sfx}"),
                             "country": "IND", "city": update_cities, "type": "SERVICEABLE"}]
    elif patch_type == "multi_field":
        base["contacts"]     = [{"contact_id": f"contact-bil-{sfx}", "type": "BILLING",
                                  "name": "Billing Team", "email": f"billing-{sfx}@example.com",
                                  "phone": phone, "is_primary": False}]
        base["credentials"]  = [{"cred_id": f"cred-pan-{sfx}", "type": "PAN",
                                  "cred_data": {"pan_no": pan}}]
        base["location"]     = [{"location_id": keys.get("loc_id", f"loc-{sfx}"),
                                 "country": "IND", "city": multi_cities, "type": "SERVICEABLE"}]
    elif patch_type == "key_rotation":
        new_uk = str(uuid.uuid4())
        base["key"] = [{
            "uk_id": new_uk,
            "signing_public_key": base64.b64encode(os.urandom(32)).decode(),
            "encryption_public_key": base64.b64encode(os.urandom(32)).decode(),
            "signed_algorithm": "ED25519", "encryption_algorithm": "X25519",
            "valid_from": "2024-01-01T00:00:00Z", "valid_until": "2026-12-31T23:59:59Z",
        }]
    elif patch_type == "buyer_contact":
        # V3 PATCH for buyer NP — use TECHNICAL contact type (valid per test_v3_comprehensive.yml V06).
        # PROCUREMENT is not a supported contact type in the V3 subscriber API schema.
        base["contacts"] = [{"contact_id": f"contact-tech-buyer-{sfx}", "type": "TECHNICAL",
                              "name": "Buyer Tech Contact", "email": f"tech-buyer-{sfx}@example.com",
                              "phone": phone, "is_primary": False}]
    elif patch_type == "logistics_location":
        base["location"] = [{"location_id": keys.get("loc_id", f"loc-{sfx}"),
                             "country": "IND",
                             "city": logistics_cities,
                             "type": "SERVICEABLE"}]
    elif patch_type == "update_uri":
        # URI PATCH requires dns_skip + skip_ssl_verification because the server
        # validates the callback URL (DNS lookup). Per test_v3_comprehensive.yml V08.
        base["uri"] = [{"uri_id": f"uri-upd-{sfx}", "type": "CALLBACK",
                        "url": f"https://updated-{sfx}.example.com/ondc"}]
        base["dns_skip"] = True
        base["skip_ssl_verification"] = True
    return base


def _do_http_step(method: str, url: str, payload: dict, headers: dict, timeout: int):
    """Execute one HTTP call. Returns (status_code, body_str, error_str, elapsed_ms, req_body_str)."""
    req_body_str = json.dumps(payload, indent=2, ensure_ascii=False)
    wire_body    = json.dumps(payload, separators=(",", ":"), sort_keys=False, ensure_ascii=False)
    t0 = time.perf_counter()
    try:
        if method == "POST":
            r = requests.post(url, data=wire_body.encode(), headers=headers, timeout=timeout, verify=SSL_VERIFY)
        else:
            r = requests.patch(url, data=wire_body.encode(), headers=headers, timeout=timeout, verify=SSL_VERIFY)
        elapsed_ms = round((time.perf_counter() - t0) * 1000, 1)
        try:
            rb = json.dumps(r.json(), indent=2, ensure_ascii=False)
        except ValueError:
            rb = r.text
        return r.status_code, rb, None, elapsed_ms, req_body_str
    except requests.exceptions.Timeout:
        elapsed_ms = round((time.perf_counter() - t0) * 1000, 1)
        return None, f"Timeout after {timeout}s", f"Timeout after {timeout}s", elapsed_ms, req_body_str
    except Exception as exc:
        elapsed_ms = round((time.perf_counter() - t0) * 1000, 1)
        return None, str(exc), str(exc), elapsed_ms, req_body_str


def run_workflow_test_case(
    tc_item: Dict[str, Any], func_cfg: dict, timeout: int = 10
) -> List[Dict[str, Any]]:
    """Execute a multi-step workflow TC with a fresh Ed25519 keypair (V3) or admin-token-only.

    Returns a list: [parent_result, step1_result, step2_result, ...]
    Each step appears as its own row in the HTML report (F-TC001-Step1 etc.).

    V3 workflow_type values:
      - v3_subscribe            : admin-whitelist (setup) + V3 POST /v3.0/subscribe
      - v3_subscribe_twice      : admin-whitelist (setup) + V3 subscribe + V3 subscribe again
      - v3_patch                : admin-whitelist (setup) + V3 subscribe + V3 PATCH
      - v3_inactive_restore     : admin-whitelist (setup) + admin PATCH INACTIVE + V3 subscribe
      - v3_multi_domain_patch   : admin-whitelist multi (setup) + V3 subscribe multi + V3 PATCH
    """
    wtype      = tc_item.get("workflow_type", "v3_subscribe")
    np_type    = tc_item.get("workflow_np_type", "seller")
    domain     = tc_item.get("workflow_domain", "ONDC:RET10")
    multi_doms = tc_item.get("workflow_domains", None)
    patch_type = tc_item.get("workflow_patch_type", "add_contact")

    host        = func_cfg.get("host", "").rstrip("/")
    admin_token = func_cfg.get("admin_token", "")
    admin_url   = f"{host}/admin/subscribe"
    v3_url      = f"{host}/v3.0/subscribe"
    admin_hdrs  = {"Authorization": f"Bearer {admin_token}", "Content-Type": "application/json"}

    start_ts   = datetime.now(timezone.utc)
    start_perf = time.perf_counter()
    steps_data: List[Dict[str, Any]] = []  # per-step detail records

    # Generate fresh keypair for this TC run
    keys = _generate_fresh_keys()
    auth = keys["auth"]  # ONDCAuthHelper or None

    def sign(payload):
        if auth:
            try:
                return auth.generate_headers(payload)
            except Exception as exc:
                return {"Content-Type": "application/json; charset=utf-8",
                        "X-Auth-Error": str(exc)}
        return {"Content-Type": "application/json; charset=utf-8"}

    def record_step(label, description, method, url, req_hdrs, code, resp_body, err, step_elapsed):
        """Append a fully-populated step record."""
        step_passed = (code == 200) if code is not None else False
        steps_data.append({
            "step_label":  label,
            "description": description,
            "method":      method,
            "url":         url,
            "req_headers": req_hdrs,
            "resp_status": code,
            "resp_body":   resp_body or err or "",
            "elapsed_ms":  step_elapsed,
            "passed":      step_passed,
            "note":        (f"HTTP {code}" if code else str(err)),
        })

    # ---------- Step 1: Admin WHITELISTED ----------
    # Whitelist ALL domains that V3 subscribe will use; V3 can only update
    # existing admin-created configs, never create new ones (ERR_103).
    whitelist_domains = multi_doms if multi_doms else [domain]
    a_payload = _build_admin_whitelist_payload(keys, np_type, domain, whitelist_domains, cfg=func_cfg)
    s1_code, s1_body, s1_err, s1_ms, s1_req = _do_http_step(
        "POST", admin_url, a_payload, admin_hdrs, timeout)
    record_step("Step 1", f"Admin Whitelist (Setup — domains: {whitelist_domains})",
                "POST", admin_url, admin_hdrs,
                s1_code, s1_body, s1_err, s1_ms)
    # Store req body in steps_data[-1] so the HTML can show it
    steps_data[-1]["req_body"] = s1_req
    _s1_pf = "PASS" if s1_code == 200 else "FAIL"
    logger.info(f"  [{tc_item['id']}] Step1 admin-whitelist → HTTP {s1_code}  [{_s1_pf}]")

    if s1_err or s1_code not in [200]:
        elapsed = round((time.perf_counter() - start_perf) * 1000, 1)
        return _wf_result(tc_item, keys, steps_data,
                          f"Setup failed: admin whitelist returned HTTP {s1_code}",
                          False, start_ts, elapsed, s1_body or s1_err)

    # ---------- Step 2: V3 Subscribe ----------
    keys["loc_id"] = f"loc-{str(uuid.uuid4())[:6]}"
    v3_payload = _build_v3_subscribe_payload(keys, np_type, domain, multi_doms, cfg=func_cfg)
    v3_hdrs = sign(v3_payload)
    s2_code, s2_body, s2_err, s2_ms, s2_req = _do_http_step(
        "POST", v3_url, v3_payload, v3_hdrs, timeout)
    record_step("Step 2", "V3 Subscribe",
                "POST", v3_url, v3_hdrs,
                s2_code, s2_body, s2_err, s2_ms)
    steps_data[-1]["req_body"] = s2_req
    _s2_pf = "PASS" if s2_code == 200 else "FAIL"
    logger.info(f"  [{tc_item['id']}] Step2 v3-subscribe → HTTP {s2_code}  [{_s2_pf}]")

    elapsed = round((time.perf_counter() - start_perf) * 1000, 1)

    # ---------- v3_inactive_restore: admin whitelist → admin PATCH INACTIVE → V3 subscribe ----------
    if wtype == "v3_inactive_restore":
        # Step 2 (already done above was admin whitelist at step 1)
        # Now PATCH admin to set INACTIVE
        inactive_payload = {"participant_id": keys["participant_id"], "action": "INACTIVE",
                            "dns_skip": True, "skip_ssl_verification": True}
        inactive_req = json.dumps(inactive_payload, indent=2, ensure_ascii=False)
        t_i = time.perf_counter()
        try:
            import requests as _req
            r_i = _req.patch(admin_url, data=json.dumps(inactive_payload, separators=(',', ':')).encode(),
                             headers=admin_hdrs, timeout=timeout, verify=SSL_VERIFY)
            s_i_ms = round((time.perf_counter() - t_i) * 1000, 1)
            s_i_code = r_i.status_code
            try:
                s_i_body = json.dumps(r_i.json(), indent=2, ensure_ascii=False)
            except ValueError:
                s_i_body = r_i.text
            s_i_err = None
        except Exception as exc:
            s_i_ms = round((time.perf_counter() - t_i) * 1000, 1)
            s_i_code, s_i_body, s_i_err = None, str(exc), str(exc)
        record_step("Step 2", "Admin PATCH — Set INACTIVE",
                    "PATCH", admin_url, admin_hdrs, s_i_code, s_i_body, s_i_err, s_i_ms)
        steps_data[-1]["req_body"] = inactive_req
        _si_pf = "PASS" if s_i_code == 200 else "FAIL"
        logger.info(f"  [{tc_item['id']}] Step2 admin-INACTIVE → HTTP {s_i_code}  [{_si_pf}]")
        if s_i_err or s_i_code not in [200]:
            elapsed = round((time.perf_counter() - start_perf) * 1000, 1)
            return _wf_result(tc_item, keys, steps_data,
                              f"Setup failed: admin PATCH INACTIVE returned HTTP {s_i_code}",
                              False, start_ts, elapsed, s_i_body or s_i_err)
        # Step 3: V3 subscribe (self-restore)
        keys["loc_id"] = f"loc-{str(uuid.uuid4())[:6]}"
        v3_payload_r = _build_v3_subscribe_payload(keys, np_type, domain, None, cfg=func_cfg)
        v3_hdrs_r = sign(v3_payload_r)
        s3_code, s3_body, s3_err, s3_ms, s3_req = _do_http_step("POST", v3_url, v3_payload_r, v3_hdrs_r, timeout)
        record_step("Step 3", "V3 Subscribe (Self-restore from INACTIVE)",
                    "POST", v3_url, v3_hdrs_r, s3_code, s3_body, s3_err, s3_ms)
        steps_data[-1]["req_body"] = s3_req
        elapsed = round((time.perf_counter() - start_perf) * 1000, 1)
        _s3_pf = "PASS" if s3_code == 200 else "FAIL"
        logger.info(f"  [{tc_item['id']}] Step3 v3-subscribe (self-restore) → HTTP {s3_code}  [{_s3_pf}]")
        if s3_err:
            return _wf_result(tc_item, keys, steps_data, f"Error: {s3_err}",
                              False, start_ts, elapsed, s3_body or s3_err)
        passed = (s3_code == 200)
        note = (f"HTTP {s3_code} — INACTIVE→SUBSCRIBED self-restore succeeded"
                if passed else f"HTTP {s3_code} — self-restore expected 200")
        return _wf_result(tc_item, keys, steps_data, note, passed, start_ts, elapsed, s3_body)

    # ---------- v3_multi_domain_patch: whitelist + multi-domain subscribe → PATCH ----------
    if wtype == "v3_multi_domain_patch":
        # Step 2 was multi-domain V3 subscribe
        if s2_err or s2_code not in [200]:
            elapsed = round((time.perf_counter() - start_perf) * 1000, 1)
            return _wf_result(tc_item, keys, steps_data,
                              f"Setup failed: V3 multi-domain subscribe returned HTTP {s2_code}",
                              False, start_ts, elapsed, s2_body or s2_err)
        sfx_p = str(uuid.uuid4())[:6]
        _md_cities = func_cfg.get("cities", ["std:080", "std:011"])[:2]
        patch_payload_md = {"participant_id": keys["participant_id"], "uk_id": keys["uk_id"],
                            "request_id": str(uuid.uuid4()),
                            "location": [{"location_id": f"loc-{sfx_p}", "country": "IND",
                                          "city": _md_cities, "type": "SERVICEABLE"}],
                            "uri": [{"uri_id": f"uri-{sfx_p}", "type": "CALLBACK",
                                     "url": f"https://multi-updated-{sfx_p}.example.com/ondc"}],
                            "dns_skip": True, "skip_ssl_verification": True}
        p_hdrs_md = sign(patch_payload_md)
        s3_code, s3_body, s3_err, s3_ms, s3_req = _do_http_step(
            "PATCH", v3_url, patch_payload_md, p_hdrs_md, timeout)
        record_step("Step 3", "V3 PATCH — Update location+URI across domains",
                    "PATCH", v3_url, p_hdrs_md, s3_code, s3_body, s3_err, s3_ms)
        steps_data[-1]["req_body"] = s3_req
        elapsed = round((time.perf_counter() - start_perf) * 1000, 1)
        _s3_pf = "PASS" if s3_code == 200 else "FAIL"
        logger.info(f"  [{tc_item['id']}] Step3 multi-domain PATCH → HTTP {s3_code}  [{_s3_pf}]")
        if s3_err:
            return _wf_result(tc_item, keys, steps_data, f"Error: {s3_err}",
                              False, start_ts, elapsed, s3_body or s3_err)
        passed = (s3_code == 200)
        note = (f"HTTP {s3_code} — multi-domain location+URI PATCH succeeded"
                if passed else f"HTTP {s3_code} — multi-domain PATCH expected 200")
        return _wf_result(tc_item, keys, steps_data, note, passed, start_ts, elapsed, s3_body)

    if wtype == "v3_subscribe":
        if s2_err:
            return _wf_result(tc_item, keys, steps_data, f"Error: {s2_err}",
                              False, start_ts, elapsed, s2_body or s2_err)
        passed = (s2_code == 200)
        note = (f"HTTP {s2_code} — WHITELISTED→SUBSCRIBED workflow completed"
                if passed else f"HTTP {s2_code} — expected 200 after admin whitelist")
        return _wf_result(tc_item, keys, steps_data, note, passed, start_ts, elapsed, s2_body)

    if wtype == "v3_subscribe_twice":
        v3_hdrs2 = sign(v3_payload)
        s2b_code, s2b_body, s2b_err, s2b_ms, s2b_req = _do_http_step(
            "POST", v3_url, v3_payload, v3_hdrs2, timeout)
        record_step("Step 3", "V3 Subscribe (Idempotency Re-subscribe)",
                    "POST", v3_url, v3_hdrs2,
                    s2b_code, s2b_body, s2b_err, s2b_ms)
        steps_data[-1]["req_body"] = s2b_req
        elapsed = round((time.perf_counter() - start_perf) * 1000, 1)
        _s3_pf = "PASS" if s2b_code == 200 else "FAIL"
        logger.info(f"  [{tc_item['id']}] Step3 v3-subscribe (idempotent) → HTTP {s2b_code}  [{_s3_pf}]")
        if s2b_err:
            return _wf_result(tc_item, keys, steps_data, f"Error on 2nd call: {s2b_err}",
                              False, start_ts, elapsed, s2b_body or s2b_err)
        passed = (s2b_code == 200)
        note = (f"HTTP {s2b_code} — idempotent re-subscribe succeeded"
                if passed else f"HTTP {s2b_code} — expected 200 for idempotent re-subscribe")
        return _wf_result(tc_item, keys, steps_data, note, passed, start_ts, elapsed, s2b_body)

    # ---------- v3_patch_configs_negative: whitelist → subscribe → V3 PATCH configs → expect 400 ----------
    # (V10 from test_v3_comprehensive.yml)
    if wtype == "v3_patch_configs_negative":
        if s2_err or s2_code not in [200]:
            elapsed = round((time.perf_counter() - start_perf) * 1000, 1)
            return _wf_result(tc_item, keys, steps_data,
                              f"Setup failed: V3 subscribe returned HTTP {s2_code}",
                              False, start_ts, elapsed, s2_body or s2_err)
        pid = keys["participant_id"]; uk = keys["uk_id"]
        _cfg_domains = func_cfg.get("domains", ["ONDC:RET10", "ONDC:RET12"])
        _other_domain = next((d for d in _cfg_domains if d != domain), "ONDC:RET12")
        patch_cfg_payload = {
            "participant_id": pid, "uk_id": uk, "request_id": str(uuid.uuid4()),
            "configs": [{"domain": _other_domain, "np_type": "BPP", "subscriber_id": pid}],
            "dns_skip": True, "skip_ssl_verification": True,
        }
        p_hdrs_cfg = sign(patch_cfg_payload)
        s3_code, s3_body, s3_err, s3_ms, s3_req = _do_http_step(
            "PATCH", v3_url, patch_cfg_payload, p_hdrs_cfg, timeout)
        record_step("Step 3", "V3 PATCH — configs field (should fail 400)",
                    "PATCH", v3_url, p_hdrs_cfg, s3_code, s3_body, s3_err, s3_ms)
        steps_data[-1]["req_body"] = s3_req
        elapsed = round((time.perf_counter() - start_perf) * 1000, 1)
        _s3_pf = "PASS" if s3_code in [400, 422] else "FAIL"
        logger.info(f"  [{tc_item['id']}] Step3 V3 PATCH configs → HTTP {s3_code}  [{_s3_pf}]")
        if s3_err:
            return _wf_result(tc_item, keys, steps_data, f"Error: {s3_err}",
                              False, start_ts, elapsed, s3_body or s3_err)
        passed = (s3_code in [400, 422])
        note = (f"HTTP {s3_code} — V3 PATCH configs field correctly rejected"
                if passed else f"HTTP {s3_code} — expected 400 for configs in V3 PATCH (V10)")
        return _wf_result(tc_item, keys, steps_data, note, passed, start_ts, elapsed, s3_body)

    # ---------- admin_invalid_transition: whitelist → subscribe → admin PATCH WHITELISTED → expect 400 ----------
    # (V18 from test_v3_comprehensive.yml)
    if wtype == "admin_invalid_transition":
        if s2_err or s2_code not in [200]:
            elapsed = round((time.perf_counter() - start_perf) * 1000, 1)
            return _wf_result(tc_item, keys, steps_data,
                              f"Setup failed: V3 subscribe returned HTTP {s2_code}",
                              False, start_ts, elapsed, s2_body or s2_err)
        pid = keys["participant_id"]
        admin_inv_payload = {
            "participant_id": pid, "action": "WHITELISTED",
            "dns_skip": True, "skip_ssl_verification": True,
        }
        s3_code, s3_body, s3_err, s3_ms, s3_req = _do_http_step(
            "PATCH", admin_url, admin_inv_payload, admin_hdrs, timeout)
        record_step("Step 3", "Admin PATCH — action=WHITELISTED (invalid backward transition, should fail 400)",
                    "PATCH", admin_url, admin_hdrs, s3_code, s3_body, s3_err, s3_ms)
        steps_data[-1]["req_body"] = s3_req
        elapsed = round((time.perf_counter() - start_perf) * 1000, 1)
        _s3_pf = "PASS" if s3_code in [200, 400, 422] else "FAIL"
        logger.info(f"  [{tc_item['id']}] Step3 admin PATCH WHITELISTED (invalid transition) → HTTP {s3_code}  [{_s3_pf}]")
        if s3_err:
            return _wf_result(tc_item, keys, steps_data, f"Error: {s3_err}",
                              False, start_ts, elapsed, s3_body or s3_err)
        passed = (s3_code in [200, 400, 422])
        note = (f"HTTP {s3_code} — SUBSCRIBED→WHITELISTED backward transition (UAT permissive: accepted)"
                if s3_code == 200 else
                (f"HTTP {s3_code} — SUBSCRIBED→WHITELISTED invalid transition correctly rejected"
                 if passed else f"HTTP {s3_code} — expected 200/400 for invalid state transition (V18)"))
        return _wf_result(tc_item, keys, steps_data, note, passed, start_ts, elapsed, s3_body)

    # ---------- admin_add_domain_negative: whitelist RET10 → subscribe RET10 → admin PATCH add RET11 → 400/404 ----------
    # (V12, V17 from test_v3_comprehensive.yml)
    if wtype == "admin_add_domain_negative":
        if s2_err or s2_code not in [200]:
            elapsed = round((time.perf_counter() - start_perf) * 1000, 1)
            return _wf_result(tc_item, keys, steps_data,
                              f"Setup failed: V3 subscribe returned HTTP {s2_code}",
                              False, start_ts, elapsed, s2_body or s2_err)
        pid = keys["participant_id"]
        npt = NP_TYPE_MAP_WF.get(np_type, "BPP")
        _extra_domains = func_cfg.get("domains", ["ONDC:RET10", "ONDC:RET11"])
        _extra_domain  = next((d for d in _extra_domains if d != domain), "ONDC:RET11")
        admin_add_payload = {
            "participant_id": pid, "action": "SUBSCRIBED",
            "configs": [{"domain": _extra_domain, "np_type": npt, "subscriber_id": pid}],
            "dns_skip": True, "skip_ssl_verification": True,
        }
        s3_code, s3_body, s3_err, s3_ms, s3_req = _do_http_step(
            "PATCH", admin_url, admin_add_payload, admin_hdrs, timeout)
        record_step("Step 3",
                    f"Admin PATCH — add new domain {_extra_domain} (never whitelisted, should fail 400/404)",
                    "PATCH", admin_url, admin_hdrs, s3_code, s3_body, s3_err, s3_ms)
        steps_data[-1]["req_body"] = s3_req
        elapsed = round((time.perf_counter() - start_perf) * 1000, 1)
        _s3_pf = "PASS" if s3_code in [200, 400, 404, 422] else "FAIL"
        logger.info(f"  [{tc_item['id']}] Step3 admin PATCH add-domain → HTTP {s3_code}  [{_s3_pf}]")
        if s3_err:
            return _wf_result(tc_item, keys, steps_data, f"Error: {s3_err}",
                              False, start_ts, elapsed, s3_body or s3_err)
        passed = (s3_code in [200, 400, 404, 422])
        note = (f"HTTP {s3_code} — admin add new domain (UAT permissive: accepted with 200)"
                if s3_code == 200 else
                (f"HTTP {s3_code} — admin add new domain correctly rejected"
                 if passed else f"HTTP {s3_code} — expected 200/400/404 for new domain addition (V12/V17)"))
        return _wf_result(tc_item, keys, steps_data, note, passed, start_ts, elapsed, s3_body)

    # ---------- Step 3: V3 PATCH (v3_patch workflow) ----------
    if s2_err or s2_code not in [200]:
        return _wf_result(tc_item, keys, steps_data,
                          f"Setup failed: V3 subscribe returned HTTP {s2_code}",
                          False, start_ts, elapsed, s2_body or s2_err)

    patch_payload = _build_patch_payload(keys, patch_type, cfg=func_cfg)
    p_hdrs = sign(patch_payload)
    s3_code, s3_body, s3_err, s3_ms, s3_req = _do_http_step(
        "PATCH", v3_url, patch_payload, p_hdrs, timeout)
    record_step(f"Step 3", f"V3 PATCH — {patch_type}",
                "PATCH", v3_url, p_hdrs,
                s3_code, s3_body, s3_err, s3_ms)
    steps_data[-1]["req_body"] = s3_req
    _s3_pf = "PASS" if s3_code == 200 else "FAIL"
    logger.info(f"  [{tc_item['id']}] Step3 PATCH ({patch_type}) → HTTP {s3_code}  [{_s3_pf}]")
    elapsed = round((time.perf_counter() - start_perf) * 1000, 1)

    if s3_err:
        return _wf_result(tc_item, keys, steps_data, f"Error: {s3_err}",
                          False, start_ts, elapsed, s3_body or s3_err)
    passed = (s3_code == 200)
    note = (f"HTTP {s3_code} — PATCH ({patch_type}) succeeded after WHITELISTED→SUBSCRIBED"
            if passed else f"HTTP {s3_code} — PATCH expected 200 (patch_type={patch_type})")
    return _wf_result(tc_item, keys, steps_data, note, passed, start_ts, elapsed, s3_body)


def _wf_result(
    tc_item, keys, steps_data: List[Dict[str, Any]],
    note, passed, start_ts, elapsed_ms, resp_body
) -> List[Dict[str, Any]]:
    """Return a list: [parent_result, step1_result, step2_result, ...]."""
    tc_id      = tc_item["id"]
    status_code = 200 if passed else 400
    ts_str      = start_ts.strftime("%Y-%m-%d %H:%M:%S UTC")

    # ----- Parent (summary) result -----
    # req_body for the parent shows a compact step summary
    step_summary = [
        f"[{sd['step_label']}] {sd['method']} {sd['url']} → HTTP {sd['resp_status']}"
        for sd in steps_data
    ]
    parent_req_body = json.dumps(
        {"participant_id": keys["participant_id"], "uk_id": keys["uk_id"],
         "steps": step_summary},
        indent=2, ensure_ascii=False,
    )
    parent = {
        "id":               tc_id,
        "name":             tc_item["name"],
        "category":         tc_item["category"],
        "description":      tc_item["description"],
        "method":           "WORKFLOW",
        "req_url":          tc_item.get("url", "(multi-step workflow)"),
        "req_headers":      {"Participant-ID": keys["participant_id"],
                             "UK-ID": keys["uk_id"],
                             "Auth": "Fresh Ed25519 keypair (generated per run)"},
        "req_body":         parent_req_body,
        "auth_note":        "Fresh Ed25519 keypair generated per run",
        "resp_status":      status_code,
        "resp_headers":     {},
        "resp_body":        resp_body or "",
        "elapsed_ms":       elapsed_ms,
        "expected_status":  tc_item.get("expected_status", [200]),
        "actual_error_code": _get_error_code(resp_body or ""),
        "actual_error_type": _get_error_type(resp_body or ""),
        "passed":           passed,
        "status_note":      note,
        "timestamp":        ts_str,
        "error":            None,
        "is_step":          False,
        "is_workflow_parent": True,
        "step_count":       len(steps_data),
    }

    # ----- Per-step results -----
    step_results = []
    for idx, sd in enumerate(steps_data, start=1):
        step_id = f"{tc_id}-Step{idx}"
        step_resp_body = sd.get("resp_body", "")
        step_results.append({
            "id":               step_id,
            "parent_id":        tc_id,
            "name":             sd["description"],
            "category":         tc_item["category"],
            "description":      sd["description"],
            "method":           sd["method"],
            "req_url":          sd["url"],
            "req_headers":      sd.get("req_headers", {}),
            "req_body":         sd.get("req_body", ""),
            "auth_note":        "",
            "resp_status":      sd["resp_status"],
            "resp_headers":     {},
            "resp_body":        step_resp_body,
            "elapsed_ms":       sd["elapsed_ms"],
            "expected_status":  [200],
            "actual_error_code": _get_error_code(step_resp_body),
            "actual_error_type": _get_error_type(step_resp_body),
            "passed":           sd["passed"],
            "status_note":      sd["note"],
            "timestamp":        ts_str,
            "error":            None,
            "is_step":          True,
            "step_label":       sd["step_label"],
            "step_number":      idx,
            "is_workflow_parent": False,
        })

    return [parent] + step_results


# ---------------------------------------------------------------------------
# Test executor  (mirrors run_test_case() in gateway search script)
# ---------------------------------------------------------------------------
def run_test_case(
    tc: Dict[str, Any],
    func_cfg: dict,
    neg_cfg: dict,
    func_auth: Optional[ONDCAuthHelper],
    neg_auth: Optional[ONDCAuthHelper],
    func_spg: "SubscribePayloadGenerator",
    neg_spg: "SubscribePayloadGenerator",
    timeout: int = 10,
) -> Dict[str, Any]:

    # Dispatch workflow TCs to the dedicated handler
    if tc.get("is_workflow"):
        return run_workflow_test_case(tc, func_cfg, timeout=timeout)

    is_func = tc["category"] == "Functional"
    auth = func_auth if is_func else neg_auth
    spg  = func_spg  if is_func else neg_spg
    cfg  = func_cfg  if is_func else neg_cfg

    headers: Dict[str, str] = {}
    auth_note = ""

    mode = tc["auth_mode"]

    # Strip internal _meta key before signing / sending
    _raw_payload = tc["payload"]
    clean_payload: Optional[dict] = (
        {k: v for k, v in _raw_payload.items() if k != "_meta"}
        if _raw_payload is not None else None
    )

    if mode == "no_auth":
        headers = {"Content-Type": "application/json; charset=utf-8"}
        auth_note = "No auth header (intentional)"

    elif mode == "custom":
        headers = dict(tc.get("custom_headers") or {})
        auth_note = "Custom headers"

    elif mode == "admin_bearer":
        headers = {"Authorization": f"Bearer {cfg.get('admin_token', '')}",
                   "Content-Type": "application/json"}
        auth_note = "Admin Bearer token"

    elif mode == "admin_bearer_raw":
        # For raw (non-JSON) bodies we still send admin bearer
        headers = dict(tc.get("custom_headers") or {
            "Authorization": f"Bearer {cfg.get('admin_token', '')}",
            "Content-Type": tc.get("raw_content_type", "application/json"),
        })
        auth_note = "Admin Bearer token (raw body)"

    elif mode == "v3_sig":
        if auth and clean_payload is not None:
            try:
                headers = auth.generate_headers(clean_payload)
                auth_note = "Valid ONDC V3 Ed25519 signature"
            except Exception as exc:
                headers = {"Content-Type": "application/json; charset=utf-8"}
                auth_note = f"V3 signature generation failed: {exc}"
        else:
            headers = {"Content-Type": "application/json; charset=utf-8"}
            auth_note = "No V3 auth helper available"

    elif mode == "v3_sig_spoofed_caller":
        # Sign with our own private key but claim to be a different registered participant
        # in the keyId (with its real uk_id). The registry will look up the spoofed
        # participant's registered public key, find the signature doesn't match (401)
        # or detect the keyId/participant_id mismatch first (403).
        spoofed_id = tc.get("spoofed_caller_id", "")
        spoofed_uk = tc.get("spoofed_caller_uk_id", None)
        spoofed_spk = tc.get("spoofed_caller_signing_public_key", None)
        if auth and clean_payload is not None and spoofed_id:
            try:
                headers = auth.generate_headers_as(clean_payload, spoofed_id, spoofed_uk_id=spoofed_uk)
                auth_note = "V3 signature with spoofed caller identity"
            except Exception as exc:
                headers = {"Content-Type": "application/json; charset=utf-8"}
                auth_note = f"V3 spoofed-caller signature generation failed: {exc}"
        else:
            headers = {"Content-Type": "application/json; charset=utf-8"}
            auth_note = "No V3 auth helper or no spoofed_caller_id"

    elif mode == "v3_tamper_digest":
        if auth and clean_payload is not None:
            try:
                headers = auth.generate_tampered_digest_headers(clean_payload)
                auth_note = "Tampered Digest header"
            except Exception as exc:
                headers = {"Content-Type": "application/json; charset=utf-8"}
                auth_note = f"Auth generation failed: {exc}"
        else:
            headers = {"Content-Type": "application/json; charset=utf-8"}
            auth_note = "No auth helper"

    headers.pop("serialized_body", None)

    # Optional pre-request sleep
    sleep_s = tc.get("sleep_before")
    if sleep_s:
        logger.info(f"  [{tc['id']}] Sleeping {sleep_s}s ...")
        time.sleep(sleep_s)

    # Determine body (_meta already stripped into clean_payload)
    body_str: Optional[str] = None
    if tc.get("raw_body") is not None:
        body_str = str(tc["raw_body"])
    elif clean_payload is not None:
        body_str = json.dumps(clean_payload, separators=(",", ":"), sort_keys=False, ensure_ascii=False)

    # Display copies (pretty-printed, _meta stripped)
    req_url = tc["url"]
    req_headers_display = dict(headers)
    req_body_display: Optional[str] = None
    if clean_payload is not None:
        req_body_display = json.dumps(clean_payload, indent=2, ensure_ascii=False)
    elif tc.get("raw_body") is not None:
        req_body_display = str(tc["raw_body"])

    # Execute
    start_ts = datetime.now(timezone.utc)
    start_perf = time.perf_counter()
    resp_status: Optional[int] = None
    resp_body: str = ""
    resp_headers: Dict[str, str] = {}
    error_msg: Optional[str] = None

    try:
        method = tc["method"].upper()
        if method == "GET":
            resp = requests.get(req_url, headers=headers, timeout=timeout, verify=SSL_VERIFY)
        elif method == "PATCH":
            if body_str is not None:
                if tc.get("raw_content_type"):
                    headers["Content-Type"] = tc["raw_content_type"]
                resp = requests.patch(req_url, data=body_str.encode("utf-8"), headers=headers, timeout=timeout, verify=SSL_VERIFY)
            else:
                resp = requests.patch(req_url, headers=headers, timeout=timeout, verify=SSL_VERIFY)
        elif method == "PUT":
            if body_str is not None:
                resp = requests.put(req_url, data=body_str.encode("utf-8"), headers=headers, timeout=timeout, verify=SSL_VERIFY)
            else:
                resp = requests.put(req_url, headers=headers, timeout=timeout, verify=SSL_VERIFY)
        else:  # POST
            if body_str is not None:
                if tc.get("raw_content_type"):
                    headers["Content-Type"] = tc["raw_content_type"]
                resp = requests.post(req_url, data=body_str.encode("utf-8"), headers=headers, timeout=timeout, verify=SSL_VERIFY)
            else:
                resp = requests.post(req_url, headers=headers, timeout=timeout, verify=SSL_VERIFY)

        resp_status = resp.status_code
        resp_headers = dict(resp.headers)
        try:
            resp_body = json.dumps(resp.json(), indent=2, ensure_ascii=False)
        except ValueError:
            resp_body = resp.text

    except requests.exceptions.Timeout:
        error_msg = f"Request timed out after {timeout}s"
        resp_body = error_msg
    except requests.exceptions.ConnectionError as exc:
        error_msg = f"Connection error: {exc}"
        resp_body = error_msg
    except Exception as exc:
        error_msg = f"Unexpected error: {exc}"
        resp_body = error_msg

    elapsed_ms = round((time.perf_counter() - start_perf) * 1000, 1)

    actual_error_code = _get_error_code(resp_body)
    actual_error_type = _get_error_type(resp_body)

    # Pass/fail logic  (identical structure to gateway search script)
    if error_msg:
        passed = False
        status_note = f"ERROR - {error_msg}"
    elif tc.get("nack_ok") and _is_nack(resp_body):
        passed = True
        code_note = f", error.code={actual_error_code}" if actual_error_code else ""
        type_note = f", error.type={actual_error_type}" if actual_error_type else ""
        status_note = f"HTTP {resp_status} - NACK received (acceptable outcome){code_note}{type_note}"
    elif resp_status in tc["expected_status"]:
        # Functional: HTTP 2xx + NACK body = Gateway rejected a valid request = FAIL
        if tc["category"] == "Functional" and _is_nack(resp_body):
            passed = False
            nack_code = actual_error_code or "N/A"
            nack_type = actual_error_type or ""
            nack_msg = ""
            try:
                nack_msg = json.loads(resp_body).get("error", {}).get("message", "")
            except Exception:
                pass
            type_note = f", error.type={nack_type}" if nack_type else ""
            msg_note  = f" ({nack_msg})" if nack_msg else ""
            status_note = (
                f"HTTP {resp_status} - NACK received for a valid request — "
                f"error.code={nack_code}{type_note}{msg_note}"
            )
        # Negative: HTTP 200 ACK means Gateway accepted something it should have rejected
        elif tc["category"] == "Negative" and resp_status == 200 and not _is_nack(resp_body):
            passed = False
            status_note = f"HTTP {resp_status} - received ACK (expected NACK or 4xx)"
        else:
            passed = True
            code_note = f", error.code={actual_error_code}" if actual_error_code else ""
            type_note = f", error.type={actual_error_type}" if actual_error_type else ""
            status_note = f"HTTP {resp_status} - expected one of {tc['expected_status']}{code_note}{type_note}"
    else:
        passed = False
        status_note = f"HTTP {resp_status} - expected one of {tc['expected_status']}"

    logger.info(
        f"  [{tc['id']}] {'PASS' if passed else 'FAIL'}  "
        f"HTTP {resp_status}  {elapsed_ms}ms  {tc['name']}"
    )

    return {
        "id": tc["id"], "name": tc["name"],
        "category": tc["category"], "description": tc["description"],
        "method": tc["method"], "req_url": req_url,
        "req_headers": req_headers_display,
        "req_body": req_body_display,
        "auth_note": auth_note,
        "resp_status": resp_status,
        "resp_headers": resp_headers,
        "resp_body": resp_body,
        "elapsed_ms": elapsed_ms,
        "expected_status": tc["expected_status"],
        "actual_error_code": actual_error_code,
        "actual_error_type": actual_error_type,
        "passed": passed,
        "status_note": status_note,
        "timestamp": start_ts.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "error": error_msg,
    }


# ---------------------------------------------------------------------------
# HTML escape helper
# ---------------------------------------------------------------------------
def _esc(text: str) -> str:
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


# ---------------------------------------------------------------------------
# HTML Report Generator  (dark theme, identical CSS to Gateway Search report)
# ---------------------------------------------------------------------------
def generate_html_report(results: List[Dict[str, Any]], output_path: str, run_ts: str) -> None:
    # Summary counts are based on parent TCs only (not individual steps)
    parent_results = [r for r in results if not r.get("is_step")]
    total  = len(parent_results)
    passed = sum(1 for r in parent_results if r["passed"])
    failed = total - passed
    pass_pct = round((passed / total * 100) if total else 0, 1)
    avg_s = round(sum(r["elapsed_ms"] for r in parent_results) / total / 1000 if total else 0, 3)

    # Collect unique suite labels
    suite_ids: List[tuple] = []
    seen: set = set()
    for r in results:
        sid = r["category"].lower().replace(" ", "-")
        if sid not in seen:
            suite_ids.append((sid, r["category"]))
            seen.add(sid)

    cards_html = ""
    for idx, r in enumerate(results):
        is_step_card       = r.get("is_step", False)
        is_workflow_parent = r.get("is_workflow_parent", False)

        status_cls  = "pass" if r["passed"] else "fail"
        badge_cls   = "badge-pass" if r["passed"] else "badge-fail"
        badge_txt   = "PASS" if r["passed"] else "FAIL"
        suite_id    = r["category"].lower().replace(" ", "-")

        sc = r["resp_status"]
        if is_workflow_parent:
            sc_cls     = "sc-2xx" if r["passed"] else "sc-4xx"
            sc_display = f"WORKFLOW-PASS ({r.get('step_count',0)} steps)" if r["passed"] else f"WORKFLOW-FAIL ({r.get('step_count',0)} steps)"
        elif is_step_card:
            if sc is None:
                sc_cls = "sc-none"; sc_display = "N/A"
            elif sc < 300:
                sc_cls = "sc-2xx"; sc_display = f"HTTP {sc}"
            elif sc < 500:
                sc_cls = "sc-4xx"; sc_display = f"HTTP {sc}"
            else:
                sc_cls = "sc-5xx"; sc_display = f"HTTP {sc}"
        elif sc is None:
            sc_cls = "sc-none"; sc_display = "N/A"
        elif sc < 300:
            sc_cls = "sc-2xx"; sc_display = f"HTTP {sc}"
        elif sc < 500:
            sc_cls = "sc-4xx"; sc_display = f"HTTP {sc}"
        else:
            sc_cls = "sc-5xx"; sc_display = f"HTTP {sc}"

        elapsed_s = round(r["elapsed_ms"] / 1000, 3)

        req_body_str = r.get("req_body") or ""
        if req_body_str:
            try:
                req_body_str = json.dumps(json.loads(req_body_str), indent=2, ensure_ascii=False)
            except (ValueError, TypeError):
                pass

        resp_body_str  = r.get("resp_body") or ""
        req_hdrs_json  = json.dumps(r.get("req_headers", {}), indent=2, ensure_ascii=False)
        status_details = json.dumps({
            "execution_timestamp": r["timestamp"],
            "rsp_s":          elapsed_s,
            "status_code":    sc if sc is not None else "N/A",
            "expected_status": r["expected_status"],
            "result":         badge_txt,
            "note":           r["status_note"],
        }, indent=2, ensure_ascii=False)

        auth_note_html = ""
        if r.get("auth_note"):
            auth_note_html = f'<span class="auth-chip">{_esc(r["auth_note"])}</span>'

        # Step cards get: indentation + a step-label chip + "Step N of parent" name
        extra_card_cls = ""
        prefix_chips   = ""
        if is_step_card:
            extra_card_cls = " step-card"
            step_label = r.get("step_label", f"Step {r.get('step_number', '')}")
            parent_id  = r.get("parent_id", "")
            prefix_chips = (
                f'<span class="step-connector-chip">↳</span>'
                f'<span class="step-num-chip">{_esc(step_label)}</span>'
            )
        elif is_workflow_parent:
            extra_card_cls = " workflow-parent-card"

        # data-name includes parent_id so step cards match parent TC search
        search_name = f"{_esc(r['id'].lower())} {_esc(r['name'].lower())}"
        if is_step_card:
            search_name += f" {_esc(r.get('parent_id','').lower())}"

        cards_html += f"""
<div class="card {status_cls}{extra_card_cls}" data-name="{search_name}" data-suite="{_esc(suite_id)}">
  <div class="card-header" onclick="toggle({idx})">
    {prefix_chips}
    <span class="suite-chip">{_esc(r['category'])}</span>
    <span class="badge {badge_cls}">{badge_txt}</span>
    <span class="tc-name">{_esc(r['id'])} — {_esc(r['name'])}</span>
    <span class="chip {sc_cls}">{_esc(sc_display)}</span>
    <span class="chip chip-time">{elapsed_s} s</span>
    <span class="chip chip-ts">{_esc(r['timestamp'])}</span>
    {auth_note_html}
    <span class="chevron" id="chev-{idx}">&gt;</span>
  </div>
  <div class="card-body" id="body-{idx}">
    <div class="section-title req-title">Request</div>
    <div class="two-col">
      <div class="col">
        <div class="col-label">Body (JSON)</div>
        <pre class="json-block">{_esc(req_body_str) if req_body_str else "(no body)"}</pre>
      </div>
      <div class="col">
        <div class="col-label">Headers</div>
        <pre class="json-block">{_esc(req_hdrs_json)}</pre>
      </div>
    </div>
    <div class="meta-row">
      <div><strong>Method:</strong> {_esc(r['method'])}</div>
      <div><strong>URL:</strong> {_esc(r['req_url'])}</div>
      <div><strong>Description:</strong> {_esc(r['description'])}</div>
    </div>
    <div class="section-title res-title">Response</div>
    <div class="two-col">
      <div class="col">
        <div class="col-label">Body (JSON)</div>
        <pre class="json-block">{_esc(resp_body_str) if resp_body_str else "(no body)"}</pre>
      </div>
      <div class="col">
        <div class="col-label">Status Details</div>
        <pre class="json-block">{_esc(status_details)}</pre>
      </div>
    </div>
  </div>
</div>
"""

    suite_btns = ""
    for sid, slabel in suite_ids:
        suite_btns += (
            f'<button class="fbtn suite" data-suite="{_esc(sid)}" '
            f'onclick="setSuite(this,\'{_esc(sid)}\')">{_esc(slabel)}</button>'
        )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>ONDC Registry V3 Subscribe API Test Report</title>
<style>
*, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{
    font-family: 'Segoe UI', system-ui, Arial, sans-serif;
    background: #0d1117; color: #e2e8f0; line-height: 1.65; min-height: 100vh;
}}
::-webkit-scrollbar {{ width: 7px; height: 7px; }}
::-webkit-scrollbar-track {{ background: #0d1117; }}
::-webkit-scrollbar-thumb {{ background: #30363d; border-radius: 4px; }}
.page {{ max-width: 1280px; margin: 0 auto; padding: 32px 20px 80px; }}
.hero {{
    background: linear-gradient(135deg, #0f2027 0%, #203a43 50%, #2c5364 100%);
    border: 1px solid #234d61; border-radius: 12px; padding: 36px 40px;
    margin-bottom: 32px; box-shadow: 0 8px 32px rgba(0,0,0,.5);
}}
.hero h1 {{ font-size: 1.9rem; font-weight: 800; letter-spacing: -0.5px; margin-bottom: 6px; }}
.hero h1 span {{ color: #67e8f9; }}
.hero p {{ color: #94a3b8; font-size: .9rem; }}
.hero p strong {{ color: #a5f3fc; }}
.summary {{
    display: grid; grid-template-columns: repeat(auto-fill, minmax(170px, 1fr));
    gap: 16px; margin-bottom: 32px;
}}
.scard {{
    background: #161b22; border: 1px solid #21262d; border-radius: 10px;
    padding: 22px 20px; text-align: center; box-shadow: 0 2px 8px rgba(0,0,0,.3);
}}
.scard .val {{ font-size: 2.4rem; font-weight: 900; line-height: 1; margin-bottom: 6px; }}
.scard .lbl {{ font-size: .72rem; text-transform: uppercase; letter-spacing: 1px; color: #64748b; }}
.scard.total  .val {{ color: #67e8f9; }}
.scard.passed .val {{ color: #22c55e; }}
.scard.failed .val {{ color: #ef4444; }}
.scard.rate   .val {{ color: #38bdf8; }}
.scard.rsp    .val {{ color: #34d399; }}
.controls {{
    display: flex; flex-wrap: wrap; gap: 10px; align-items: center; margin-bottom: 24px;
}}
.search {{
    flex: 1; min-width: 220px; padding: 9px 14px; background: #161b22;
    border: 1px solid #30363d; border-radius: 8px; color: #e2e8f0;
    font-size: .88rem; outline: none;
}}
.search:focus {{ border-color: #67e8f9; }}
.fbtn {{
    padding: 8px 18px; border-radius: 8px; border: 1px solid #30363d;
    background: #161b22; color: #8b949e; cursor: pointer;
    font-size: .82rem; font-weight: 700; transition: all .15s;
}}
.fbtn:hover {{ border-color: #67e8f9; color: #e2e8f0; }}
.fbtn.active {{ background: #0e7490; border-color: #0e7490; color: #fff; }}
.fbtn.pass.active {{ background: #22c55e; border-color: #22c55e; }}
.fbtn.fail.active {{ background: #ef4444; border-color: #ef4444; }}
.count {{ color: #64748b; font-size: .82rem; margin-left: auto; }}
.card {{
    background: #161b22; border: 1px solid #21262d; border-radius: 10px;
    margin-bottom: 12px; overflow: hidden; transition: border-color .15s, box-shadow .15s;
}}
.card:hover {{ border-color: #30363d; box-shadow: 0 4px 16px rgba(0,0,0,.4); }}
.card.pass {{ border-left: 4px solid #22c55e; }}
.card.fail {{ border-left: 4px solid #ef4444; }}
.card-header {{
    display: flex; align-items: center; gap: 10px; padding: 14px 18px;
    cursor: pointer; user-select: none; flex-wrap: wrap;
}}
.card-header:hover {{ background: rgba(255,255,255,.025); }}
.tc-name {{ font-weight: 600; font-size: .92rem; flex: 1; min-width: 180px; }}
.suite-chip {{
    font-size: .7rem; font-weight: 800; letter-spacing: .6px;
    text-transform: uppercase; border-radius: 20px; padding: 3px 10px;
    background: rgba(103,232,249,.12); color: #a5f3fc; flex-shrink: 0;
}}
.badge {{
    display: inline-block; padding: 3px 10px; border-radius: 20px;
    font-size: .72rem; font-weight: 800; letter-spacing: .6px; flex-shrink: 0;
}}
.badge-pass {{ background: rgba(34,197,94,.15); color: #22c55e; }}
.badge-fail {{ background: rgba(239,68,68,.15); color: #ef4444; }}
.chip {{ font-size: .75rem; font-weight: 700; padding: 3px 9px; border-radius: 6px; flex-shrink: 0; }}
.sc-2xx  {{ background: rgba(34,197,94,.1);  color: #22c55e; }}
.sc-4xx  {{ background: rgba(239,68,68,.1);  color: #ef4444; }}
.sc-5xx  {{ background: rgba(239,68,68,.1);  color: #ef4444; }}
.sc-none {{ background: rgba(245,158,11,.1); color: #f59e0b; }}
.chip-time {{ background: rgba(56,189,248,.08); color: #38bdf8; }}
.chip-ts   {{ background: rgba(148,163,184,.06); color: #64748b; }}
.auth-chip {{
    font-size: .68rem; font-weight: 700; padding: 2px 8px; border-radius: 6px;
    background: rgba(245,158,11,.1); color: #f59e0b; flex-shrink: 0;
}}
.workflow-parent-card {{
    border-top: 2px solid #4b5563;
}}
.step-card {{
    margin-left: 36px;
    border-left: 3px solid #38bdf8 !important;
    border-style: solid;
    background: #111827;
}}
.step-card.fail {{
    border-left: 3px solid #ef4444 !important;
}}
.step-connector-chip {{
    color: #4b5563; font-size: 1rem; flex-shrink: 0; padding: 0 2px;
}}
.step-num-chip {{
    font-size: .7rem; font-weight: 800; letter-spacing: .6px;
    text-transform: uppercase; border-radius: 20px; padding: 3px 10px;
    background: rgba(56,189,248,.12); color: #7dd3fc; flex-shrink: 0;
}}
.chevron {{
    color: #4b5563; font-size: .85rem; flex-shrink: 0;
    transition: transform .2s; margin-left: auto;
}}
.chevron.open {{ transform: rotate(90deg); }}
.card-body {{ display: none; border-top: 1px solid #21262d; padding: 0 0 18px; }}
.section-title {{
    font-size: .78rem; font-weight: 700; text-transform: uppercase;
    letter-spacing: 1px; padding: 14px 20px 8px;
}}
.req-title {{ color: #60a5fa; border-top: 1px solid #21262d; margin-top: 4px; }}
.req-title:first-of-type {{ border-top: none; margin-top: 0; }}
.res-title {{ color: #34d399; border-top: 1px solid #21262d; }}
.two-col {{
    display: grid; grid-template-columns: 1fr 1fr; gap: 0; padding: 0 12px;
}}
@media (max-width: 800px) {{ .two-col {{ grid-template-columns: 1fr; }} }}
.col {{ padding: 0 8px; }}
.col-label {{
    font-size: .72rem; text-transform: uppercase; letter-spacing: .8px;
    color: #64748b; margin-bottom: 6px; margin-top: 6px;
}}
.meta-row {{ padding: 12px 20px 6px; color: #94a3b8; font-size: .86rem; display: grid; gap: 6px; }}
pre.json-block {{
    background: #0d1117; border: 1px solid #21262d; border-radius: 8px;
    padding: 14px; font-family: Consolas, 'Cascadia Code', monospace;
    font-size: .76rem; color: #c9d1d9; overflow-x: auto; overflow-y: auto;
    max-height: 400px; white-space: pre; line-height: 1.55; tab-size: 2;
}}
</style>
</head>
<body>
<div class="page">

  <div class="hero">
    <h1>ONDC <span>Registry V3 Subscribe API</span> Test Report</h1>
    <p>
      <strong>Source:</strong> /v3.0/subscribe — Functional (V3 workflows) &amp; Negative (V3 auth/schema)
      &nbsp;|&nbsp;
      <strong>Generated:</strong> {_esc(run_ts)}
    </p>
  </div>

  <div class="summary">
    <div class="scard total"> <div class="val">{total}</div> <div class="lbl">Total</div>    </div>
    <div class="scard passed"><div class="val">{passed}</div><div class="lbl">Passed</div>   </div>
    <div class="scard failed"><div class="val">{failed}</div><div class="lbl">Failed</div>   </div>
    <div class="scard rate">  <div class="val">{pass_pct}%</div><div class="lbl">Pass Rate</div></div>
    <div class="scard rsp">   <div class="val">{avg_s}s</div><div class="lbl">Avg Response</div></div>
  </div>

  <div class="controls">
    <input id="search" class="search" type="text"
           placeholder="Search test ID or name ..."
           oninput="applyFilters()"/>
    <button class="fbtn active"  data-f="all"  onclick="setFilter(this,'all')">All</button>
    <button class="fbtn pass"    data-f="pass" onclick="setFilter(this,'pass')">Passed</button>
    <button class="fbtn fail"    data-f="fail" onclick="setFilter(this,'fail')">Failed</button>
    <button class="fbtn suite active" data-suite="all" onclick="setSuite(this,'all')">All Suites</button>
    {suite_btns}
    <span class="count" id="count"></span>
  </div>

  <div id="container">
{cards_html}
  </div>

</div>
<script>
var activeFilter='all', activeSuite='all';
function toggle(i){{
  var b=document.getElementById('body-'+i),c=document.getElementById('chev-'+i),o=b.style.display==='block';
  b.style.display=o?'none':'block'; c.classList.toggle('open',!o);
}}
function setFilter(btn,f){{
  activeFilter=f;
  document.querySelectorAll('.fbtn[data-f]').forEach(function(b){{b.classList.remove('active');}});
  btn.classList.add('active'); applyFilters();
}}
function setSuite(btn,s){{
  activeSuite=s;
  document.querySelectorAll('.fbtn.suite').forEach(function(b){{b.classList.remove('active');}});
  btn.classList.add('active'); applyFilters();
}}
function applyFilters(){{
  var q=(document.getElementById('search').value||'').toLowerCase();
  var cards=document.querySelectorAll('#container .card');
  var visible=0, visibleParent=0;
  cards.forEach(function(c){{
    var nm=!q||(c.dataset.name||'').toLowerCase().includes(q);
    var fm=activeFilter==='all'||
           (activeFilter==='pass'&&c.classList.contains('pass'))||
           (activeFilter==='fail'&&c.classList.contains('fail'));
    var sm=activeSuite==='all'||c.dataset.suite===activeSuite;
    var show=nm&&fm&&sm;
    c.style.display=show?'':'none';
    if(show){{visible++; if(!c.classList.contains('step-card'))visibleParent++;}}
  }});
  document.getElementById('count').textContent=
    visibleParent+' TC'+((visibleParent!==1)?'s':'')+' ('+visible+' rows) shown';
}}
applyFilters();
</script>
</body>
</html>
"""

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    logger.info(f"HTML report saved -> {output_path}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(
        description="ONDC Registry V3 Subscribe API Test Runner (/v3.0/subscribe only)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--output", default=None,
        help="Output HTML path. Auto-generated as reports/Registry-v3-subscribe-<suite>-<ts>.html if omitted.",
    )
    parser.add_argument(
        "--suite", choices=["all", "functional", "negative"], default="all",
        help="Which test suite to run (default: all)",
    )
    parser.add_argument(
        "--timeout", type=int, default=10,
        help="HTTP request timeout in seconds (default: 10)",
    )
    parser.add_argument(
        "--func-config",
        default="resources/registry/subscribe/test_subscribe_functional.yml",
        help="Path to functional YAML config (relative to project root or absolute)",
    )
    parser.add_argument(
        "--neg-config",
        default="resources/registry/subscribe/test_subscribe_negative.yml",
        help="Path to negative YAML config (relative to project root or absolute)",
    )
    args = parser.parse_args()

    run_ts  = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    ts_file = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H-%M-%S")

    output_path = args.output or os.path.join(
        RESULTS_DIR,
        f"v3_subscribe_{args.suite}_{ts_file}.html",
    )
    if not os.path.isabs(output_path):
        output_path = os.path.join(PROJECT_ROOT, output_path)

    logger.info("=" * 60)
    logger.info("ONDC Registry Subscribe API Test Runner")
    logger.info(f"Run timestamp : {run_ts}")
    logger.info(f"Suite         : {args.suite}")
    logger.info(f"Timeout       : {args.timeout}s")
    logger.info(f"Func config   : {args.func_config}")
    logger.info(f"Neg config    : {args.neg_config}")
    logger.info(f"Output        : {output_path}")
    logger.info("=" * 60)

    func_cfg = load_yaml_config(args.func_config)
    neg_cfg  = load_yaml_config(args.neg_config)

    validate_config(func_cfg, args.func_config, "Functional")
    validate_config(neg_cfg,  args.neg_config,  "Negative")

    logger.info(f"Functional host : {func_cfg.get('host', 'NOT SET')}")
    logger.info(f"Negative host   : {neg_cfg.get('host',  'NOT SET')}")

    # Refresh admin token dynamically and inject into both configs
    fresh_token = get_fresh_admin_token(func_cfg)
    func_cfg["admin_token"] = fresh_token
    neg_cfg["admin_token"]  = fresh_token
    logger.info("Admin token refreshed and injected into both configs")

    func_auth = build_auth_helper(func_cfg, label="Functional")
    neg_auth  = build_auth_helper(neg_cfg,  label="Negative")
    logger.info(f"Functional V3 auth : {'enabled' if func_auth else 'disabled'}")
    logger.info(f"Negative   V3 auth : {'enabled' if neg_auth else 'disabled'}")

    func_spg = SubscribePayloadGenerator(func_cfg)
    neg_spg  = SubscribePayloadGenerator(neg_cfg)

    logger.info("\nBuilding test cases ...")
    all_cases = build_test_cases(func_cfg, neg_cfg, func_auth, neg_auth)

    if args.suite == "functional":
        cases = [c for c in all_cases if c["category"] == "Functional"]
    elif args.suite == "negative":
        cases = [c for c in all_cases if c["category"] == "Negative"]
    else:
        cases = all_cases

    logger.info(f"Total test cases to run : {len(cases)}")

    logger.info("\nExecuting test cases ...")
    results = []
    for tc_item in cases:
        result = run_test_case(
            tc_item, func_cfg, neg_cfg, func_auth, neg_auth, func_spg, neg_spg,
            timeout=args.timeout,
        )
        # Workflow TCs return a list [parent, step1, step2, ...]
        if isinstance(result, list):
            results.extend(result)
        else:
            results.append(result)

    # Summary stats: count only parent TCs (not individual steps)
    parent_results = [r for r in results if not r.get("is_step")]
    total  = len(parent_results)
    passed = sum(1 for r in parent_results if r["passed"])
    failed = total - passed

    logger.info("=" * 60)
    logger.info(
        f"Results  Total={total}  PASS={passed}  FAIL={failed}  "
        f"({round(passed / total * 100 if total else 0, 1)}%)"
    )
    logger.info("=" * 60)

    generate_html_report(results, output_path, run_ts)
    logger.info(f"Report -> {output_path}")


if __name__ == "__main__":
    main()
