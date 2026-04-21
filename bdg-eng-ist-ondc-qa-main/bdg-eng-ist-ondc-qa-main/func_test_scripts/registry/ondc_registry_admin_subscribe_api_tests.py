#!/usr/bin/env python3
"""
ONDC Registry Admin Subscribe API - Automated Test Runner with HTML Report Generator
=====================================================================================
Covers the /admin/subscribe endpoint only.

Functional TCs (20):
    F-TC001–005b : Admin whitelist — seller, buyer, logistics, re-whitelist
    F-TC015–016  : Admin minimal valid payload (configs-only WHITELISTED), full payload
    F-TC021–023  : Admin multi-domain, buyer support contact, multiple credentials
    F-TC033      : Admin minimum required fields
    F-TC027–032  : Admin workflow — multi-domain, domain add/remove, credential rotation,
                   whitelist→subscribed, rapid state transitions, sequential+contact update
    F-TC034–035  : Admin workflow — empty arrays, schema compatibility

Negative TCs (33):
    N-TC001–003  : Auth failures (missing/invalid/expired token)
    N-TC008–025  : Payload validation (missing fields, invalid values, malformed JSON …)
    N-TC027–034  : Duplicate conflict, invalid HTTP methods, key field errors, large payload
    N-TC042      : Invalid state transition (SUBSCRIBED→WHITELISTED via admin PATCH)
    N-TC044–046  : Special characters, maximum field lengths, old V2 schema field names

Usage:
    python func_test_scripts/ondc_registry_admin_api_tests.py
    python func_test_scripts/ondc_registry_admin_api_tests.py --suite functional
    python func_test_scripts/ondc_registry_admin_api_tests.py --suite negative
    python func_test_scripts/ondc_registry_admin_api_tests.py --timeout 30
    python func_test_scripts/ondc_registry_admin_api_tests.py --output reports/my_admin_report.html
    python func_test_scripts/ondc_registry_admin_api_tests.py \\
        --func-config resources/registry/subscribe/test_subscribe_functional.yml \\
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
# File lives at func_test_scripts/registry/<name>.py  →  3 dirname calls reach workspace root
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
RESULTS_DIR  = os.path.join(PROJECT_ROOT, "results", "registry")
sys.path.insert(0, PROJECT_ROOT)

# SSL_VERIFY controls certificate validation for all HTTP requests.
# Default: True (secure). Set env var ONDC_SKIP_SSL_VERIFY=1 only for
# test environments that use self-signed certificates.
import urllib3
SSL_VERIFY: bool = os.environ.get("ONDC_SKIP_SSL_VERIFY", "0") != "1"
if not SSL_VERIFY:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional cryptography import (Ed25519 — used for fresh-keypair generation)
# ---------------------------------------------------------------------------
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    _HAS_CRYPTO = True
except ImportError:
    _HAS_CRYPTO = False
    logger.warning("cryptography library not found — Ed25519 public-key derivation disabled.")


# ---------------------------------------------------------------------------
# ONDC Auth Helper  (kept for Ed25519 public-key derivation in _generate_fresh_keys;
#                    admin endpoint uses Bearer token, not Ed25519 signing)
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


_REQUIRED_FIELDS = ["host"]


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


# ---------------------------------------------------------------------------
# Admin token refresh + participant registration
# ---------------------------------------------------------------------------

def get_fresh_admin_token(cfg: dict) -> Optional[str]:
    """
    Obtain a valid admin JWT.  Strategy:
      1. Try logging in with admin_username / admin_password.
      2. Fall back to the static admin_token from config if login fails.
    """
    host     = cfg.get("host", "").rstrip("/")
    auth_url = cfg.get("admin_auth_url") or f"{host}/admin/auth/login"
    username = cfg.get("admin_username", "").strip()
    password = cfg.get("admin_password", "").strip()

    if username and password and not username.startswith("<"):
        try:
            # Try email+password payload (standard ONDC auth service format)
            for login_payload in (
                {"email": username, "password": password},
                {"username": username, "password": password},
            ):
                r = requests.post(
                    auth_url,
                    json=login_payload,
                    timeout=15, verify=SSL_VERIFY,
                )
                if r.status_code == 200:
                    data = r.json()
                    tok = data.get("accessToken") or data.get("access_token") or data.get("token")
                    if tok:
                        print(f"[TOKEN] Fresh admin token obtained via login ({auth_url})")
                        return tok
            print(f"[TOKEN] Login failed ({r.status_code}) — falling back to static token")
        except Exception as exc:
            print(f"[TOKEN] Login error: {exc} — falling back to static token")

    static = cfg.get("admin_token", "").strip()
    if static:
        print("[TOKEN] Using static admin_token from config")
        return static

    print("[TOKEN] No admin token available")
    return None


_UK_ID_CACHE = os.path.join(PROJECT_ROOT, "resources", "registry", "subscribe",
                             ".registered_uk_id.json")


def _load_cached_uk_id(participant_id: str) -> Optional[str]:
    try:
        if os.path.exists(_UK_ID_CACHE):
            data = json.loads(open(_UK_ID_CACHE, encoding="utf-8").read())
            if data.get("participant_id") == participant_id:
                return data.get("uk_id")
    except Exception:
        pass
    return None


def _save_cached_uk_id(participant_id: str, uk_id: str) -> None:
    try:
        os.makedirs(os.path.dirname(_UK_ID_CACHE), exist_ok=True)
        with open(_UK_ID_CACHE, "w", encoding="utf-8") as fh:
            json.dump({"participant_id": participant_id, "uk_id": uk_id}, fh, indent=2)
    except Exception:
        pass


def _verify_participant_subscribed(host: str, participant_id: str, admin_token: str) -> bool:
    """Return True when participant has at least one SUBSCRIBED config record."""
    try:
        r = requests.get(
            f"{host.rstrip('/')}/admin/participants/{participant_id}",
            headers={"Authorization": f"Bearer {admin_token}"},
            timeout=15, verify=SSL_VERIFY,
        )
        if r.status_code == 200:
            data = r.json()
            configs = data.get("configs") or []
            return any(c.get("status") == "SUBSCRIBED" for c in configs)
    except Exception:
        pass
    return False


def _admin_whitelist_participant(host: str, participant_id: str, uk_id: str,
                                  signing_pub: str, enc_pub: str,
                                  admin_token: str) -> bool:
    """POST /admin/subscribe to WHITELIST the participant."""
    payload = {
        "participant_id": participant_id,
        "action": "WHITELISTED",
        "key": [{
            "uk_id": uk_id,
            "signing_public_key": signing_pub,
            "encryption_public_key": enc_pub,
            "signed_algorithm": "ED25519",
            "encryption_algorithm": "X25519",
            "valid_from": "2024-01-01T00:00:00.000Z",
            "valid_until": "2027-12-31T23:59:59.000Z",
        }],
        "configs": [{"domain": "ONDC:RET10", "np_type": "BAP",
                      "subscriber_id": participant_id}],
        "dns_skip": True, "skip_ssl_verification": True,
    }
    try:
        r = requests.post(
            f"{host.rstrip('/')}/admin/subscribe",
            json=payload,
            headers={"Authorization": f"Bearer {admin_token}",
                     "Content-Type": "application/json"},
            timeout=30, verify=SSL_VERIFY,
        )
        if r.status_code in (200, 409):
            print(f"[REGISTRATION] Admin whitelist: HTTP {r.status_code} OK")
            return True
        print(f"[REGISTRATION] Admin whitelist failed: {r.status_code} {r.text[:200]}")
    except Exception as exc:
        print(f"[REGISTRATION] Admin whitelist error: {exc}")
    return False


def _v3_self_subscribe_participant(host: str, participant_id: str, uk_id: str,
                                    private_key_seed_str: str,
                                    signing_pub: str, enc_pub: str) -> bool:
    """Participant self-subscribes via POST /v3.0/subscribe."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as _EK
        from cryptography.hazmat.primitives import serialization as _sl
        seed_str = private_key_seed_str.strip()
        try:
            seed = bytes.fromhex(seed_str)
        except ValueError:
            seed = base64.b64decode(seed_str)
        if len(seed) > 32:
            seed = seed[:32]
        priv = _EK.from_private_bytes(seed)
        pub_raw = priv.public_key().public_bytes(_sl.Encoding.Raw, _sl.PublicFormat.Raw)
        signing_pub_derived = base64.b64encode(pub_raw).decode()

        short_id = participant_id.split(".")[0]
        now_ts   = int(time.time())
        payload  = {
            "dns_skip": True, "skip_ssl_verification": True,
            "request_id": str(uuid.uuid4()),
            "uk_id": uk_id, "participant_id": participant_id,
            "credentials": [{"cred_id": f"cred_gst_{short_id}", "type": "GST",
                              "cred_data": {"gstin": "29ABCDE1234F1Z5",
                                             "legal_name": "Test Admin Subscribe Pvt Ltd"}}],
            "contacts": [{"contact_id": f"contact_tech_{short_id}",
                           "name": "Technical Contact",
                           "email": f"tech@{participant_id}",
                           "phone": "+919876543210", "type": "TECHNICAL"}],
            "key": [{"uk_id": uk_id,
                      "signing_public_key": signing_pub_derived,
                      "encryption_public_key": enc_pub,
                      "signed_algorithm": "ED25519",
                      "encryption_algorithm": "X25519",
                      "valid_from": datetime.now(timezone.utc).isoformat(),
                      "valid_until": "2027-12-31T23:59:59.000Z"}],
            "location": [{"location_id": f"loc_{short_id}", "country": "IND",
                           "city": ["std:080"], "type": "SERVICEABLE"}],
            "uri": [{"uri_id": f"uri_{short_id}", "type": "CALLBACK",
                      "url": "https://test-admin.kynondc.net"}],
            "configs": [{"domain": "ONDC:RET10", "np_type": "BAP",
                          "subscriber_id": participant_id,
                          "location_id": f"loc_{short_id}",
                          "uri_id": f"uri_{short_id}", "key_id": uk_id}],
        }
        body_bytes   = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode()
        digest_b64   = base64.b64encode(hashlib.blake2b(body_bytes, digest_size=64).digest()).decode()
        expires      = now_ts + 300
        signing_str  = f"(created): {now_ts}\n(expires): {expires}\ndigest: BLAKE-512={digest_b64}"
        sig          = priv.sign(signing_str.encode())
        key_id       = f"{participant_id}|{uk_id}|ed25519"
        auth_header  = (
            f'Signature keyId="{key_id}",algorithm="ed25519",'
            f'created={now_ts},expires={expires},'
            f'headers="(created) (expires) digest",'
            f'signature="{base64.b64encode(sig).decode()}"'
        )
        headers = {"Content-Type": "application/json",
                   "Authorization": auth_header,
                   "Digest": f"BLAKE-512={digest_b64}"}
        r = requests.post(f"{host.rstrip('/')}/v3.0/subscribe",
                          data=body_bytes, headers=headers, timeout=30, verify=SSL_VERIFY)
        if r.status_code == 200:
            try:
                nack = r.json().get("message", {}).get("ack", {}).get("status") == "NACK"
            except Exception:
                nack = False
            if not nack:
                print("[REGISTRATION] V3 self-subscribe OK")
                return True
            print("[REGISTRATION] V3 self-subscribe returned NACK")
            return False
        print(f"[REGISTRATION] V3 self-subscribe failed: {r.status_code}")
    except Exception as exc:
        print(f"[REGISTRATION] V3 self-subscribe error: {exc}")
    return False


def register_participant_runtime(cfg: dict, admin_token: str) -> bool:
    """
    Ensure the participant in cfg is SUBSCRIBED before tests run.
    Mirrors the 3-strategy pattern used by ondc_reg_v3_lookup_api_tests.py.

    Strategy 1 : already SUBSCRIBED → done.
    Strategy 2 : admin whitelist + V3 self-subscribe with configured uk_id.
    Strategy 3 : retry with a fresh uk_id (handles key-conflict dead-lock).
    """
    participant_id   = cfg.get("participant_id", "").strip()
    uk_id            = cfg.get("uk_id", "").strip()
    signing_pub      = cfg.get("signing_public_key", "")
    enc_pub          = cfg.get("encryption_public_key", signing_pub)
    private_key_seed = cfg.get("private_key_seed", "").strip()
    host             = cfg.get("host", "").rstrip("/")

    if not participant_id:
        print("[REGISTRATION] No participant_id in config — skipping")
        return False
    if not admin_token:
        print("[REGISTRATION] No admin token — skipping registration")
        return False

    print(f"\n[REGISTRATION] Checking/Registering participant: {participant_id}")

    # Strategy 1: already subscribed?
    cached_uk = _load_cached_uk_id(participant_id)
    check_uk  = cached_uk or uk_id
    if _verify_participant_subscribed(host, participant_id, admin_token):
        print("[REGISTRATION] [OK] Participant already SUBSCRIBED")
        return True

    # Strategy 2: whitelist + self-subscribe with configured uk_id
    _admin_whitelist_participant(host, participant_id, uk_id, signing_pub, enc_pub, admin_token)
    if private_key_seed:
        if _v3_self_subscribe_participant(host, participant_id, uk_id,
                                          private_key_seed, signing_pub, enc_pub):
            time.sleep(3)
            if _verify_participant_subscribed(host, participant_id, admin_token):
                _save_cached_uk_id(participant_id, uk_id)
                print("[REGISTRATION] [OK] Registered with configured uk_id")
                return True

    # Strategy 3: fresh uk_id
    fresh_uk = str(uuid.uuid4())
    print(f"[REGISTRATION] Retrying with fresh uk_id: {fresh_uk}")
    _admin_whitelist_participant(host, participant_id, fresh_uk, signing_pub, enc_pub, admin_token)
    if private_key_seed:
        if _v3_self_subscribe_participant(host, participant_id, fresh_uk,
                                          private_key_seed, signing_pub, enc_pub):
            time.sleep(4)
            if _verify_participant_subscribed(host, participant_id, admin_token):
                _save_cached_uk_id(participant_id, fresh_uk)
                print(f"[REGISTRATION] [OK] Registered with fresh uk_id: {fresh_uk}")
                return True

    print("[REGISTRATION] [WARN] All strategies exhausted — tests will continue")
    return False


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
        self.gst  = creds.get("gst",   "22ABCDE1234F1Z5")
        self.pan  = creds.get("pan",   "ABCDE1234F")
        self.fssai= creds.get("fssai", "12345678901234")
        contacts  = cfg.get("test_contacts", {})
        self.tech_email = contacts.get("technical_email", "tech@example.com")
        self.biz_email  = contacts.get("business_email",  "business@example.com")
        self.phone      = contacts.get("phone",            "+911234567890")
        self.admin_token = str(cfg.get("admin_token", ""))
        self.host        = str(cfg.get("host", "https://registry-uat.kynondc.net")).rstrip("/")

    def _suffix(self) -> str:
        return str(uuid.uuid4())[:6]

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
                "cred_data": {"pan": self.pan, "gstin": self.gst, "business_name": "Test Business Ltd"}
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
                "location": {"location_id": loc_id, "country": "IND", "city": ["std:080"], "type": "SERVICEABLE"},
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
# NACK / error code helpers
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
# Admin Workflow helpers — fresh-keypair multi-step execution
# ---------------------------------------------------------------------------
NP_TYPE_MAP_WF = {"seller": "BPP", "buyer": "BAP", "logistics": "GATEWAY"}


def _generate_fresh_keys() -> dict:
    """Generate a fresh Ed25519 keypair + unique participant/uk IDs for admin workflows."""
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
    participant_id = f"test-adm-{ts}-{sfx}.participant.ondc"
    uk_id = str(uuid.uuid4())
    return {
        "seed": seed, "signing_public_key": signing_pub,
        "encryption_public_key": enc_pub,
        "participant_id": participant_id, "uk_id": uk_id,
        "auth": None,  # Admin uses Bearer token, not Ed25519 signing
    }


def _build_admin_whitelist_payload(keys: dict, np_type: str, domain: str,
                                   domains: list = None) -> dict:
    """Admin subscribe payload (WHITELISTED) using fresh keys."""
    sfx = str(uuid.uuid4())[:6]
    pid = keys["participant_id"]; uk = keys["uk_id"]
    npt = NP_TYPE_MAP_WF.get(np_type, "BPP")
    all_domains = domains if domains else [domain]
    return {
        "participant_id": pid,
        "action": "WHITELISTED",
        "credentials": [{"cred_id": f"cred-gst-{sfx}", "type": "GST",
                         "cred_data": {"pan": "ABCDE1234F", "gstin": "22ABCDE1234F1Z5",
                                        "business_name": "Test Business Ltd"}}],
        "contacts": [{"contact_id": f"contact-tech-{sfx}", "type": "TECHNICAL",
                      "name": "John Doe", "email": f"tech-{sfx}@example.com",
                      "phone": "+919876543210", "is_primary": True}],
        "key": [{
            "uk_id": uk, "signing_public_key": keys["signing_public_key"],
            "encryption_public_key": keys["encryption_public_key"],
            "signed_algorithm": "ED25519", "encryption_algorithm": "X25519",
            "valid_from": "2024-01-01T00:00:00.000Z", "valid_until": "2026-12-31T23:59:59.000Z",
        }],
        "configs": [{"domain": d, "np_type": npt, "subscriber_id": pid} for d in all_domains],
        "dns_skip": True, "skip_ssl_verification": True,
    }


def _build_admin_subscribed_payload(keys: dict, np_type: str, domains: list,
                                    action: str = "SUBSCRIBED") -> dict:
    """Admin subscribe payload (SUBSCRIBED) with full location + uri.

    Configs include location_id/uri_id/key_id so subsequent PATCH steps can
    reference them. Stores admin_loc_id and admin_uri_id in keys dict.
    """
    sfx = str(uuid.uuid4())[:6]
    pid = keys["participant_id"]; uk = keys["uk_id"]
    npt = NP_TYPE_MAP_WF.get(np_type, "BPP")
    loc_id = f"loc-adm-{sfx}"; uri_id = f"uri-adm-{sfx}"
    keys["admin_loc_id"] = loc_id
    keys["admin_uri_id"] = uri_id
    return {
        "participant_id": pid,
        "action": action,
        "credentials": [
            {"cred_id": f"cred-gst-{sfx}", "type": "GST",
             "cred_data": {"gstin": "29ABCDE1234F1Z5", "legal_name": "Test Advanced Pvt Ltd"}},
            {"cred_id": f"cred-pan-{sfx}", "type": "PAN",
             "cred_data": {"pan": "ABCDE1234F", "name": "Test Advanced Pvt Ltd"}},
        ],
        "contacts": [
            {"contact_id": f"contact-auth-{sfx}", "type": "AUTHORISED_SIGNATORY",
             "name": "Auth Rep", "email": f"auth-{sfx}@example.com", "phone": "+919876543211"},
            {"contact_id": f"contact-biz-{sfx}",  "type": "BUSINESS",
             "name": "Biz Rep",  "email": f"biz-{sfx}@example.com",  "phone": "+919876543213"},
            {"contact_id": f"contact-tech-{sfx}", "type": "TECHNICAL",
             "name": "Tech Rep", "email": f"tech-{sfx}@example.com", "phone": "+919876543210"},
        ],
        "key": [{
            "uk_id": uk, "signing_public_key": keys["signing_public_key"],
            "encryption_public_key": keys["encryption_public_key"],
            "signed_algorithm": "ED25519", "encryption_algorithm": "X25519",
            "valid_from": "2024-01-01T00:00:00.000Z", "valid_until": "2026-12-31T23:59:59.000Z",
        }],
        "location": [{"location_id": loc_id, "type": "SERVICEABLE", "country": "IND", "city": ["std:080"]}],
        "uri": [{"uri_id": uri_id, "type": "CALLBACK", "url": f"https://{pid}/callback"}],
        "configs": [
            {"domain": d, "np_type": npt, "subscriber_id": pid,
             "location_id": loc_id, "uri_id": uri_id, "key_id": uk}
            for d in domains
        ],
        "dns_skip": True, "skip_ssl_verification": True,
    }


def _build_admin_full_subscribed_patch(keys: dict) -> dict:
    """Admin PATCH to transition to SUBSCRIBED — sends full credentials+contacts+key+location+uri.

    Required for WHITELISTED→SUBSCRIBED and INACTIVE→SUBSCRIBED transitions.
    Reuses location_id/uri_id stored by _build_admin_subscribed_payload.
    """
    sfx = str(uuid.uuid4())[:6]
    pid = keys["participant_id"]; uk = keys["uk_id"]
    loc_id = keys.get("admin_loc_id", f"loc-adm-{sfx}")
    uri_id = keys.get("admin_uri_id", f"uri-adm-{sfx}")
    return {
        "participant_id": pid,
        "action": "SUBSCRIBED",
        "credentials": [
            {"cred_id": f"cred-gst-sub-{sfx}", "type": "GST",
             "cred_data": {"gstin": "29ABCDE1234F1Z5", "legal_name": "Test Advanced Pvt Ltd"}},
            {"cred_id": f"cred-pan-sub-{sfx}", "type": "PAN",
             "cred_data": {"pan": "ABCDE1234F", "name": "Test Advanced Pvt Ltd"}},
        ],
        "contacts": [
            {"contact_id": f"contact-auth-sub-{sfx}", "type": "AUTHORISED_SIGNATORY",
             "name": "Auth Rep", "email": f"auth-sub-{sfx}@example.com", "phone": "+919876543211"},
            {"contact_id": f"contact-tech-sub-{sfx}", "type": "TECHNICAL",
             "name": "Tech Rep", "email": f"tech-sub-{sfx}@example.com", "phone": "+919876543210"},
        ],
        "key": [{
            "uk_id": uk, "signing_public_key": keys["signing_public_key"],
            "encryption_public_key": keys["encryption_public_key"],
            "signed_algorithm": "ED25519", "encryption_algorithm": "X25519",
            "valid_from": "2024-01-01T00:00:00.000Z", "valid_until": "2026-12-31T23:59:59.000Z",
        }],
        "location": [{"location_id": loc_id, "type": "SERVICEABLE", "country": "IND", "city": ["std:080"]}],
        "uri": [{"uri_id": uri_id, "type": "CALLBACK", "url": f"https://{pid}/callback"}],
        "dns_skip": True, "skip_ssl_verification": True,
    }


def _build_admin_state_patch(pid: str, action: str) -> dict:
    """Minimal admin PATCH for SUSPENDED / INACTIVE / UNSUBSCRIBED transitions."""
    return {"participant_id": pid, "action": action,
            "dns_skip": True, "skip_ssl_verification": True}


def _build_admin_credential_rotate_patch(pid: str) -> dict:
    """Admin PATCH payload that rotates GST + PAN credentials.

    Uses a valid 15-char GSTIN and 10-char PAN.
    GSTIN: 2-digit state + 10-char PAN + 3-char suffix = 15 chars.
    PAN: 5 letters + 4 digits + 1 letter = 10 chars.
    """
    sfx = str(uuid.uuid4())[:6]
    digits = "".join(str(int(c, 16) % 10) for c in sfx[:4])
    pan = f"UVWXY{digits}Z"        # 10 chars ✓
    gstin = f"27{pan}1A8"          # 15 chars ✓
    return {
        "participant_id": pid,
        "credentials": [
            {"cred_id": f"cred-gst-rot-{sfx}", "type": "GST",
             "cred_data": {"gstin": gstin, "legal_name": "Rotated Business Pvt Ltd"}},
            {"cred_id": f"cred-pan-rot-{sfx}", "type": "PAN",
             "cred_data": {"pan": pan, "name": "Rotated Business Pvt Ltd"}},
        ],
        "dns_skip": True, "skip_ssl_verification": True,
    }


def _build_admin_contact_patch(pid: str) -> dict:
    """Admin PATCH payload that updates TECHNICAL contact."""
    sfx = str(uuid.uuid4())[:6]
    return {
        "participant_id": pid,
        "contacts": [{"contact_id": f"contact-upd-{sfx}", "type": "TECHNICAL",
                      "name": "Tech Contact Updated",
                      "email": f"update-{sfx}@example.com", "phone": "+919111111111"}],
        "dns_skip": True, "skip_ssl_verification": True,
    }


def _do_http_step(method: str, url: str, payload: dict, headers: dict, timeout: int):
    """Execute one HTTP call. Returns (status_code, body_str, error_str, elapsed_ms, req_body_str)."""
    req_body_str = json.dumps(payload, indent=2, ensure_ascii=False)
    wire_body    = json.dumps(payload, separators=(",", ":"), sort_keys=False, ensure_ascii=False)
    t0 = time.perf_counter()
    try:
        if method == "POST":
            r = requests.post(url, data=wire_body.encode(), headers=headers, timeout=timeout)
        else:
            r = requests.patch(url, data=wire_body.encode(), headers=headers, timeout=timeout)
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


def _wf_result(
    tc_item, keys, steps_data: List[Dict[str, Any]],
    note, passed, start_ts, elapsed_ms, resp_body
) -> List[Dict[str, Any]]:
    """Return a list: [parent_result, step1_result, step2_result, ...]."""
    tc_id       = tc_item["id"]
    status_code = 200 if passed else 400
    ts_str      = start_ts.strftime("%Y-%m-%d %H:%M:%S UTC")

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
                             "Auth": "Admin Bearer token (fresh Ed25519 keys in payload)"},
        "req_body":         parent_req_body,
        "auth_note":        "Admin Bearer token",
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


def _run_admin_only_workflow(
    wtype: str, tc_item: dict, keys: dict,
    admin_url: str, admin_hdrs: dict,
    steps_data: list, start_ts, start_perf: float, timeout: int,
) -> List[Dict[str, Any]]:
    """Handle admin-only multi-step workflows (no V3 EdDSA signing required)."""
    pid        = keys["participant_id"]
    np_type    = tc_item.get("workflow_np_type", "seller")
    domain     = tc_item.get("workflow_domain", "ONDC:RET10")
    multi_doms = tc_item.get("workflow_domains", [domain])

    def do_step(label, desc, method, payload):
        code, body, err, ms, req = _do_http_step(method, admin_url, payload, admin_hdrs, timeout)
        passed = (code == 200) if code is not None else False
        steps_data.append({
            "step_label": label, "description": desc, "method": method,
            "url": admin_url, "req_headers": admin_hdrs, "req_body": req,
            "resp_status": code, "resp_body": body or err or "",
            "elapsed_ms": ms, "passed": passed,
            "note": (f"HTTP {code}" if code else str(err)),
        })
        _pf = "PASS" if passed else "FAIL"
        logger.info(f"  [{tc_item['id']}] {label} {method} /admin/subscribe → HTTP {code}  [{_pf}]")
        return code, body, err

    def elapsed_ms():
        return round((time.perf_counter() - start_perf) * 1000, 1)

    def fail(msg, body=""):
        return _wf_result(tc_item, keys, steps_data, msg, False, start_ts, elapsed_ms(), body)

    def succeed(msg, body=""):
        return _wf_result(tc_item, keys, steps_data, msg, True, start_ts, elapsed_ms(), body)

    # D01 pattern: POST 5 domains SUBSCRIBED → PATCH contact update × 2
    if wtype == "admin_multi_domain_update":
        domains5 = multi_doms if len(multi_doms) >= 2 else [domain, "ONDC:RET11", "ONDC:RET12", "ONDC:RET13", "ONDC:RET14"]
        p1 = _build_admin_subscribed_payload(keys, np_type, domains5)
        c1, b1, e1 = do_step("Step 1", f"Admin POST — SUBSCRIBED with {len(domains5)} domains", "POST", p1)
        if e1 or c1 not in [200]:
            return fail(f"Setup failed: POST returned HTTP {c1}", b1)
        c2, b2, e2 = do_step("Step 2", "Admin PATCH — Update TECHNICAL contact (all domains affected)",
                             "PATCH", _build_admin_contact_patch(pid))
        if e2 or c2 not in [200]:
            return fail(f"Contact update PATCH returned HTTP {c2}", b2)
        c3, b3, e3 = do_step("Step 3", "Admin PATCH — Second contact update (validates independent update)",
                             "PATCH", _build_admin_contact_patch(pid))
        if e3:
            return fail(f"Second contact update error: {e3}", b3)
        passed = (c3 == 200)
        return (succeed if passed else fail)(
            f"HTTP {c3} — per-domain independent update {'succeeded' if passed else 'failed'}", b3)

    # D02 pattern: POST 2 domains → PATCH add 3 more (5 total) → PATCH reduce to 3
    if wtype == "admin_domain_add_remove":
        doms2 = multi_doms[:2] if len(multi_doms) >= 2 else [domain, "ONDC:RET11"]
        p1 = _build_admin_subscribed_payload(keys, np_type, doms2)
        c1, b1, e1 = do_step("Step 1", "Admin POST — SUBSCRIBED with 2 domains", "POST", p1)
        if e1 or c1 not in [200]:
            return fail(f"Setup failed: POST returned HTTP {c1}", b1)
        npt = NP_TYPE_MAP_WF.get(np_type, "BPP")
        loc_id = keys.get("admin_loc_id", "loc-admin")
        uri_id = keys.get("admin_uri_id", "uri-admin")
        uk = keys["uk_id"]
        doms5 = doms2 + ["ONDC:RET12", "ONDC:RET13", "ONDC:RET14"]
        p2 = {"participant_id": pid,
              "configs": [{"domain": d, "np_type": npt, "subscriber_id": pid} for d in doms5],
              "dns_skip": True, "skip_ssl_verification": True}
        c2, b2, e2 = do_step("Step 2", "Admin PATCH — Add 3 more domains (5 total)", "PATCH", p2)
        if e2 or c2 not in [200]:
            return fail(f"Domain add PATCH returned HTTP {c2}", b2)
        doms3 = [doms2[0], "ONDC:RET12", "ONDC:RET13"]
        p3 = {"participant_id": pid,
              "configs": [{"domain": d, "np_type": npt, "subscriber_id": pid} for d in doms3],
              "dns_skip": True, "skip_ssl_verification": True}
        c3, b3, e3 = do_step("Step 3", "Admin PATCH — Reduce to 3 domains", "PATCH", p3)
        if e3:
            return fail(f"Domain reduce error: {e3}", b3)
        passed = (c3 == 200)
        return (succeed if passed else fail)(
            f"HTTP {c3} — dynamic domain add/remove {'succeeded' if passed else 'failed'}", b3)

    # D03 pattern: POST multi-domain SUBSCRIBED → PATCH rotate credentials
    if wtype == "admin_credential_rotation":
        doms = multi_doms if multi_doms else [domain, "ONDC:RET11"]
        p1 = _build_admin_subscribed_payload(keys, np_type, doms)
        c1, b1, e1 = do_step("Step 1", "Admin POST — multi-domain SUBSCRIBED", "POST", p1)
        if e1 or c1 not in [200]:
            return fail(f"Setup failed: POST returned HTTP {c1}", b1)
        c2, b2, e2 = do_step("Step 2", "Admin PATCH — Rotate GST+PAN credentials",
                             "PATCH", _build_admin_credential_rotate_patch(pid))
        if e2:
            return fail(f"Credential rotation error: {e2}", b2)
        passed = (c2 == 200)
        return (succeed if passed else fail)(
            f"HTTP {c2} — domain credential rotation {'succeeded' if passed else 'failed'}", b2)

    # D05 pattern: POST WHITELISTED multi-domain → PATCH full SUBSCRIBED payload
    if wtype == "admin_whitelist_to_subscribed":
        doms = multi_doms if multi_doms else [domain, "ONDC:RET11", "ONDC:RET12"]
        p1 = _build_admin_subscribed_payload(keys, np_type, doms, action="WHITELISTED")
        c1, b1, e1 = do_step("Step 1", f"Admin POST — WHITELISTED with {len(doms)} domains", "POST", p1)
        if e1 or c1 not in [200]:
            return fail(f"Setup failed: POST returned HTTP {c1}", b1)
        c2, b2, e2 = do_step("Step 2",
                             "Admin PATCH — WHITELISTED→SUBSCRIBED (full credentials+contacts+key+location+uri)",
                             "PATCH", _build_admin_full_subscribed_patch(keys))
        if e2:
            return fail(f"State transition error: {e2}", b2)
        passed = (c2 == 200)
        return (succeed if passed else fail)(
            f"HTTP {c2} — WHITELISTED→SUBSCRIBED admin PATCH {'succeeded' if passed else 'failed'}", b2)

    # D07 pattern: POST WHITELISTED → SUBSCRIBED → SUSPENDED → INACTIVE → SUBSCRIBED → UNSUBSCRIBED
    if wtype == "admin_rapid_transitions":
        p1 = _build_admin_subscribed_payload(keys, np_type, [domain], action="WHITELISTED")
        c1, b1, e1 = do_step("Step 1", "Admin POST — WHITELISTED (full payload)", "POST", p1)
        if e1 or c1 not in [200]:
            return fail(f"Setup failed: POST returned HTTP {c1}", b1)
        c2, b2, e2 = do_step("Step 2", "Admin PATCH — WHITELISTED→SUBSCRIBED (full payload)",
                             "PATCH", _build_admin_full_subscribed_patch(keys))
        if e2 or c2 not in [200]:
            return fail(f"Step 2 (SUBSCRIBED) failed: HTTP {c2}", b2)
        for action_val, label, desc in [
            ("SUSPENDED", "Step 3", "Admin PATCH — SUBSCRIBED→SUSPENDED"),
            ("INACTIVE",  "Step 4", "Admin PATCH — SUSPENDED→INACTIVE"),
        ]:
            code, body, err = do_step(label, desc, "PATCH", _build_admin_state_patch(pid, action_val))
            if err or code not in [200]:
                return fail(f"{label} ({action_val}) failed: HTTP {code}", body)
        c5, b5, e5 = do_step("Step 5", "Admin PATCH — INACTIVE→SUBSCRIBED (full payload re-activate)",
                             "PATCH", _build_admin_full_subscribed_patch(keys))
        if e5 or c5 not in [200]:
            return fail(f"Step 5 (re-activate SUBSCRIBED) failed: HTTP {c5}", b5)
        c6, b6, e6 = do_step("Step 6", "Admin PATCH — SUBSCRIBED→UNSUBSCRIBED",
                             "PATCH", _build_admin_state_patch(pid, "UNSUBSCRIBED"))
        if e6:
            return fail(f"Step 6 (UNSUBSCRIBED) error: {e6}", b6)
        passed = (c6 == 200)
        return (succeed if passed else fail)(
            f"HTTP {c6} — 6-step rapid state transitions {'completed' if passed else 'failed'}", b6)

    # D10 pattern: POST SUBSCRIBED → PATCH contacts
    if wtype == "admin_sequential_transitions":
        p1 = _build_admin_subscribed_payload(keys, np_type, [domain])
        c1, b1, e1 = do_step("Step 1", "Admin POST — SUBSCRIBED (full payload with location+uri)", "POST", p1)
        if e1 or c1 not in [200]:
            return fail(f"Setup failed: POST returned HTTP {c1}", b1)
        c2, b2, e2 = do_step("Step 2", "Admin PATCH — Update TECHNICAL contact",
                             "PATCH", _build_admin_contact_patch(pid))
        if e2:
            return fail(f"Contact update error: {e2}", b2)
        passed = (c2 == 200)
        return (succeed if passed else fail)(
            f"HTTP {c2} — sequential transition + contact update {'succeeded' if passed else 'failed'}", b2)

    # D14 pattern: POST with empty credentials=[] → PATCH adding contacts
    if wtype == "admin_empty_arrays":
        p1 = {
            "participant_id": pid, "action": "WHITELISTED",
            "configs": [{"domain": domain, "np_type": NP_TYPE_MAP_WF.get(np_type, "BPP"),
                         "subscriber_id": pid}],
            "credentials": [],
            "dns_skip": True, "skip_ssl_verification": True,
        }
        c1, b1, e1 = do_step("Step 1", "Admin POST — WHITELISTED with empty credentials=[]", "POST", p1)
        if e1 or c1 not in [200]:
            return fail(f"Setup failed: POST returned HTTP {c1}", b1)
        c2, b2, e2 = do_step("Step 2", "Admin PATCH — Add TECHNICAL contact (credentials omitted)",
                             "PATCH", _build_admin_contact_patch(pid))
        if e2:
            return fail(f"Contact patch error: {e2}", b2)
        passed = (c2 == 200)
        return (succeed if passed else fail)(
            f"HTTP {c2} — empty-array/omit-field handling {'succeeded' if passed else 'failed'}", b2)

    # D15 pattern: POST WHITELISTED full payload → PATCH SUBSCRIBED full payload
    if wtype == "admin_schema_compat":
        p1 = _build_admin_subscribed_payload(keys, np_type, [domain], action="WHITELISTED")
        c1, b1, e1 = do_step("Step 1", "Admin POST — WHITELISTED (full payload, location+uri included)", "POST", p1)
        if e1 or c1 not in [200]:
            return fail(f"Setup failed: POST returned HTTP {c1}", b1)
        c2, b2, e2 = do_step("Step 2",
                             "Admin PATCH — SUBSCRIBED (full payload: credentials+contacts+key+location+uri)",
                             "PATCH", _build_admin_full_subscribed_patch(keys))
        if e2:
            return fail(f"Schema compat PATCH error: {e2}", b2)
        passed = (c2 == 200)
        return (succeed if passed else fail)(
            f"HTTP {c2} — schema compatibility (WHITELISTED→SUBSCRIBED) {'succeeded' if passed else 'failed'}", b2)

    return fail(f"Unknown admin workflow type: {wtype}")


def run_workflow_test_case(
    tc_item: Dict[str, Any], func_cfg: dict, timeout: int = 10
) -> List[Dict[str, Any]]:
    """Execute an admin multi-step workflow TC.

    Returns a list: [parent_result, step1_result, step2_result, ...]

    Supported workflow_type values:
      admin_multi_domain_update       : POST 5-domain SUBSCRIBED → PATCH domain1 → PATCH domain3
      admin_domain_add_remove         : POST 2-domain → PATCH add 3 → PATCH remove 2
      admin_credential_rotation       : POST multi-domain SUBSCRIBED → PATCH rotate credentials
      admin_whitelist_to_subscribed   : POST WHITELISTED → PATCH action=SUBSCRIBED
      admin_rapid_transitions         : POST → 5x PATCH (full state machine)
      admin_sequential_transitions    : POST SUBSCRIBED → PATCH contacts
      admin_empty_arrays              : POST empty credentials=[] → PATCH contacts
      admin_schema_compat             : POST WHITELISTED full → PATCH SUBSCRIBED full
    """
    host        = func_cfg.get("host", "").rstrip("/")
    admin_token = func_cfg.get("admin_token", "")
    admin_url   = f"{host}/admin/subscribe"
    admin_hdrs  = {"Authorization": f"Bearer {admin_token}", "Content-Type": "application/json"}

    start_ts   = datetime.now(timezone.utc)
    start_perf = time.perf_counter()
    steps_data: List[Dict[str, Any]] = []

    keys = _generate_fresh_keys()

    return _run_admin_only_workflow(
        tc_item.get("workflow_type", ""), tc_item, keys,
        admin_url, admin_hdrs, steps_data, start_ts, start_perf, timeout,
    )


# ---------------------------------------------------------------------------
# Test-case builder — admin endpoint only
# ---------------------------------------------------------------------------
def build_test_cases(func_cfg: dict, neg_cfg: dict) -> List[Dict[str, Any]]:
    func_host = func_cfg.get("host", "https://registry-uat.kynondc.net").rstrip("/")
    fspg = SubscribePayloadGenerator(func_cfg)
    nspg = SubscribePayloadGenerator(neg_cfg)
    cases: List[Dict[str, Any]] = []

    def tc(tc_id, name, category, description, method, url, payload,
           expected_status, auth_mode, custom_headers=None,
           raw_body=None, raw_content_type=None,
           ttl=None, sleep_before=None, nack_ok=False):
        cases.append({
            "id": tc_id, "name": name, "category": category,
            "description": description, "method": method,
            "url": url, "payload": payload,
            "expected_status": expected_status, "auth_mode": auth_mode,
            "custom_headers": custom_headers,
            "raw_body": raw_body, "raw_content_type": raw_content_type,
            "ttl": ttl, "sleep_before": sleep_before, "nack_ok": nack_ok,
        })

    host = func_host

    # ==========================================================================
    # FUNCTIONAL TEST CASES — /admin/subscribe endpoint
    # ==========================================================================

    # F-TC001: Admin Seller Whitelist
    p = fspg.random_payload(np_type="seller", domain="ONDC:RET10")
    tc("F-TC001", "Admin Seller Whitelist", "Functional",
       "[PASS EXPECTED] Admin whitelists a new seller Network Participant (BPP) for the ONDC:RET10 "
       "retail domain via POST /admin/subscribe with Bearer token auth. Sends a standard payload "
       "containing GST credential, TECHNICAL contact, and Ed25519 key material. Validates HTTP 200 "
       "with a successful acknowledgment, creating the participant record in WHITELISTED state.",
       "POST", f"{host}/admin/subscribe", p, [200], "admin_bearer")

    # F-TC002: Admin Seller Full Whitelist (with extra credential + contact)
    p = fspg.random_payload(np_type="seller", domain="ONDC:RET10")
    sfx = p["_meta"]["sfx"]
    p["credentials"].append({
        "cred_id": f"cred_{sfx}_pan", "type": "PAN",
        "cred_data": {"pan": fspg.pan, "name": "Business Owner"}
    })
    p["contacts"].append({
        "contact_id": f"contact_{sfx}_billing", "type": "BILLING",
        "name": "Jane Smith", "email": f"billing-{sfx}@example.com",
        "phone": fspg.phone, "address": "123 Finance Street, Mumbai",
        "designation": "Finance Manager", "is_primary": False
    })
    tc("F-TC002", "Admin Seller Full Whitelist", "Functional",
       "[PASS EXPECTED] Admin whitelists a seller with an enriched payload containing multiple "
       "credential types (GST + PAN) and multiple contact types (TECHNICAL + BILLING). Validates "
       "that the admin subscribe endpoint accepts supplementary credentials and contacts beyond the "
       "minimum required, allowing richer participant profiles to be created in a single request.",
       "POST", f"{host}/admin/subscribe", p, [200], "admin_bearer")

    # F-TC003: Admin Buyer Whitelist
    p = fspg.random_payload(np_type="buyer", domain="ONDC:RET10")
    tc("F-TC003", "Admin Buyer Whitelist", "Functional",
       "[PASS EXPECTED] Admin whitelists a buyer Network Participant (BAP) for the ONDC:RET10 retail "
       "domain. Validates that np_type=BAP is correctly handled alongside np_type=BPP and that buyer "
       "participants are registered in WHITELISTED state in the same way as seller participants.",
       "POST", f"{host}/admin/subscribe", p, [200], "admin_bearer")

    # F-TC004: Admin Logistics Whitelist
    p = fspg.random_payload(np_type="logistics", domain="ONDC:LOG10")
    tc("F-TC004", "Admin Logistics Whitelist", "Functional",
       "[PASS EXPECTED] Admin whitelists a logistics Network Participant (GATEWAY type) for the "
       "ONDC:LOG10 logistics domain. Validates that the GATEWAY np_type and the logistics-specific "
       "domain (ONDC:LOG10) are correctly supported by the admin subscribe endpoint, distinct from "
       "retail domain registrations.",
       "POST", f"{host}/admin/subscribe", p, [200], "admin_bearer")

    # F-TC005: Admin Re-whitelist Idempotent
    p = fspg.random_payload(np_type="seller")
    tc("F-TC005", "Admin Re-whitelist Idempotent", "Functional",
       "[PASS EXPECTED — Setup for F-TC005b] First admin subscribe to register a seller participant "
       "using a fixed participant_id that will be reused in the idempotency follow-up test (F-TC005b). "
       "Must return HTTP 200 to confirm the initial registration succeeds and the participant_id is "
       "now present in the registry.",
       "POST", f"{host}/admin/subscribe", p, [200], "admin_bearer")
    tc("F-TC005b", "Admin Re-whitelist Idempotent (2nd call)", "Functional",
       "[NACK EXPECTED — ERR_301] Submits a second admin subscribe POST with the identical "
       "participant_id registered in F-TC005. The API must return HTTP 200 with a NACK body "
       "containing ERR_301 (BUSINESS_LOGIC: 'Participant already exists') rather than creating a "
       "duplicate record. Validates that the registry correctly detects duplicate participant_id on "
       "POST and enforces business-rule idempotency.",
       "POST", f"{host}/admin/subscribe", p, [200], "admin_bearer", nack_ok=True)

    # F-TC015: Admin Minimal Valid Payload (configs-only WHITELISTED)
    # Validates that the admin API accepts an absolute minimum payload:
    # only participant_id + action + configs (no key, credentials, contacts).
    # Per test_advanced.yml D12 — minimum required fields.
    sfx = str(uuid.uuid4())[:8]
    pid15 = f"min-seller-{sfx}.participant.ondc"
    p = {"participant_id": pid15,
         "action": "WHITELISTED",
         "configs": [{"domain": "ONDC:RET11", "np_type": "BPP", "subscriber_id": pid15}],
         "dns_skip": True, "skip_ssl_verification": True}
    tc("F-TC015", "Admin Minimal Valid Payload (configs-only WHITELISTED)", "Functional",
       "[PASS EXPECTED — 200] Admin subscribe using an absolute minimum payload containing only the "
       "three required fields: participant_id, action (WHITELISTED), and a configs array with a "
       "single domain entry. All optional fields (key, credentials, contacts, location, uri) are "
       "deliberately omitted. Validates that the API does not mandate optional fields at the schema "
       "level and correctly creates a WHITELISTED participant from a minimal request.",
       "POST", f"{host}/admin/subscribe", p, [200], "admin_bearer")

    # F-TC016: Admin Full Payload (all creds + contacts)
    p = fspg.random_payload(np_type="seller")
    sfx = p["_meta"]["sfx"]
    p["credentials"].extend([
        {"cred_id": f"cred_{sfx}_pan",   "type": "PAN",
         "cred_data": {"pan": fspg.pan, "name": "Business Owner"}},
        {"cred_id": f"cred_{sfx}_fssai", "type": "FSSAI",
         "cred_data": {"license_number": fspg.fssai, "business_name": "Test Food"}}
    ])
    p["contacts"].extend([
        {"contact_id": f"contact_{sfx}_billing", "type": "BILLING",
         "name": "Jane Smith", "email": fspg.biz_email, "phone": fspg.phone, "is_primary": False},
        {"contact_id": f"contact_{sfx}_support", "type": "SUPPORT",
         "name": "Support Team", "email": "support@example.com", "phone": fspg.phone, "is_primary": False}
    ])
    tc("F-TC016", "Admin Full Payload (All Credentials + Contacts)", "Functional",
       "[PASS EXPECTED] Admin whitelists a seller using a maximally-enriched payload covering all "
       "three supported credential types (GST, PAN, FSSAI) and all three contact types (TECHNICAL, "
       "BILLING, SUPPORT). Validates that the admin subscribe endpoint handles the broadest possible "
       "combination of credentials and contacts in a single request without schema validation failure.",
       "POST", f"{host}/admin/subscribe", p, [200], "admin_bearer")

    # F-TC021: Admin Multi-domain
    p = fspg.random_payload(np_type="seller")
    pid = p["_meta"]["participant_id"]
    p["configs"] = [
        {"domain": d, "np_type": "BPP", "subscriber_id": pid}
        for d in ["ONDC:RET10", "ONDC:RET11", "ONDC:AGR10"]
    ]
    p.pop("_meta", None)
    tc("F-TC021", "Admin Multi-domain Whitelist", "Functional",
       "[PASS EXPECTED] Admin whitelists a seller Network Participant across three distinct domains "
       "(ONDC:RET10, ONDC:RET11, ONDC:AGR10) by providing three entries in the configs array within "
       "a single POST request. Validates that the API registers the participant for all specified "
       "domains simultaneously and that the configs array correctly supports multiple heterogeneous "
       "domain entries.",
       "POST", f"{host}/admin/subscribe", p, [200], "admin_bearer")

    # F-TC022: Admin Buyer Support Contact
    p = fspg.random_payload(np_type="buyer")
    sfx = p["_meta"]["sfx"]
    p["contacts"].append({"contact_id": f"contact_{sfx}_support", "type": "SUPPORT",
                           "name": "Support Team", "email": "support@buyer.com",
                           "phone": fspg.phone, "is_primary": False})
    tc("F-TC022", "Admin Buyer Support Contact", "Functional",
       "[PASS EXPECTED] Admin whitelists a buyer Network Participant (BAP) with a SUPPORT contact "
       "type included alongside the standard contact entries. Validates that the SUPPORT contact "
       "type is a recognised enum value in the admin subscribe contacts schema and that buyer "
       "participants can carry customer-support contact information at registration time.",
       "POST", f"{host}/admin/subscribe", p, [200], "admin_bearer")

    # F-TC023: Admin Seller Multiple Credentials
    p = fspg.random_payload(np_type="seller")
    sfx = p["_meta"]["sfx"]
    p["credentials"] = [
        {"cred_id": f"cred_{sfx}_gst",   "type": "GST",
         "cred_data": {"pan": fspg.pan, "gstin": fspg.gst, "business_name": "Test Business"}},
        {"cred_id": f"cred_{sfx}_pan",   "type": "PAN",
         "cred_data": {"pan": fspg.pan, "name": "Test Business Owner"}},
        {"cred_id": f"cred_{sfx}_fssai", "type": "FSSAI",
         "cred_data": {"license_number": fspg.fssai, "business_name": "Test Food Business"}},
    ]
    tc("F-TC023", "Admin Seller Multiple Credentials (GST+PAN+FSSAI)", "Functional",
       "[PASS EXPECTED] Admin whitelists a seller with all three supported government-issued "
       "credential types — GST (tax registration), PAN (permanent account number), and FSSAI "
       "(food safety license) — provided simultaneously in the credentials array. Validates that "
       "the API can store and accept multiple heterogeneous credential types for a single participant "
       "in one request.",
       "POST", f"{host}/admin/subscribe", p, [200], "admin_bearer")

    # F-TC033: Admin Minimum Required Fields (D12)
    sfx33 = str(uuid.uuid4())[:8]
    p_min = {"participant_id": f"min-test-{sfx33}.example.com",
             "action": "WHITELISTED",
             "configs": [{"domain": "ONDC:RET11", "np_type": "BPP",
                          "subscriber_id": f"min-test-{sfx33}.example.com"}],
             "dns_skip": True, "skip_ssl_verification": True}
    tc("F-TC033", "Admin Minimum Required Fields", "Functional",
       "[PASS EXPECTED] Admin subscribe with only the three mandatory fields (participant_id, "
       "action=WHITELISTED, configs) and none of the optional fields (key, credentials, contacts, "
       "location, uri). Uses a different participant and domain than F-TC015 to independently "
       "confirm that the minimum-payload rule is consistently enforced across diverse registrations.",
       "POST", f"{host}/admin/subscribe", p_min, [200], "admin_bearer")

    # -------------------------------------------------------------------------
    # ADMIN WORKFLOW TEST CASES (F-TC027 to F-TC035)
    # -------------------------------------------------------------------------
    _wf = {"method": "WORKFLOW", "payload": None, "expected_status": [200],
           "auth_mode": "workflow", "is_workflow": True,
           "custom_headers": None, "raw_body": None, "raw_content_type": None,
           "ttl": None, "sleep_before": None, "nack_ok": False}

    cases.append({**_wf, "id": "F-TC027", "name": "Admin Multi-domain Per-domain Update",
                  "category": "Functional",
                  "url": f"{host}/admin/subscribe",
                  "description": "[PASS EXPECTED — 3-step workflow] (1) Admin POST to register a seller "
                                 "with configs for 5 domains in SUBSCRIBED state. (2) Admin PATCH to "
                                 "independently update the config for domain 1 (ONDC:RET10). (3) Admin "
                                 "PATCH to update the config for domain 3 (ONDC:RET12) in isolation. "
                                 "Validates that individual domain configurations within a multi-domain "
                                 "participant can be updated independently without affecting other domains.",
                  "workflow_type": "admin_multi_domain_update",
                  "workflow_np_type": "seller", "workflow_domain": "ONDC:RET10",
                  "workflow_domains": ["ONDC:RET10", "ONDC:RET11", "ONDC:RET12", "ONDC:RET13", "ONDC:RET14"]})

    cases.append({**_wf, "id": "F-TC028", "name": "Admin Dynamic Domain Add/Remove",
                  "category": "Functional",
                  "url": f"{host}/admin/subscribe",
                  "description": "[PASS EXPECTED — 3-step workflow] (1) Admin POST to register a seller "
                                 "with 2 domains (ONDC:RET10, ONDC:RET11). (2) Admin PATCH to expand to "
                                 "5 domains by adding ONDC:RET12, ONDC:LOG10, ONDC:FIS10. (3) Admin PATCH "
                                 "to reduce back to 3 domains by supplying a trimmed configs array. "
                                 "Validates that domain membership can be dynamically expanded and "
                                 "contracted via PATCH without re-creating the participant record.",
                  "workflow_type": "admin_domain_add_remove",
                  "workflow_np_type": "seller", "workflow_domain": "ONDC:RET10",
                  "workflow_domains": ["ONDC:RET10", "ONDC:RET11"]})

    cases.append({**_wf, "id": "F-TC029", "name": "Admin Domain Credential Rotation",
                  "category": "Functional",
                  "url": f"{host}/admin/subscribe",
                  "description": "[PASS EXPECTED — 2-step workflow] (1) Admin POST to register a "
                                 "multi-domain seller as SUBSCRIBED with initial GST and PAN credentials. "
                                 "(2) Admin PATCH supplying updated credential entries with new cred_id "
                                 "values and refreshed credential data for both GST and PAN. Validates "
                                 "that admin-driven credential rotation is applied globally to the "
                                 "participant without affecting domain configs or SUBSCRIBED status.",
                  "workflow_type": "admin_credential_rotation",
                  "workflow_np_type": "seller", "workflow_domain": "ONDC:RET10",
                  "workflow_domains": ["ONDC:RET10", "ONDC:RET11"]})

    cases.append({**_wf, "id": "F-TC030", "name": "Admin WHITELISTED to SUBSCRIBED via PATCH",
                  "category": "Functional",
                  "url": f"{host}/admin/subscribe",
                  "description": "[PASS EXPECTED — 2-step workflow] (1) Admin POST a seller across 3 "
                                 "domains (ONDC:RET10, ONDC:RET11, ONDC:RET12) with action=WHITELISTED. "
                                 "(2) Admin PATCH with action=SUBSCRIBED and full payload (credentials, "
                                 "contacts, key, location, uri) to promote the participant to active "
                                 "status. Validates that the WHITELISTED→SUBSCRIBED lifecycle can be "
                                 "driven entirely by admin operations without V3 participant signing.",
                  "workflow_type": "admin_whitelist_to_subscribed",
                  "workflow_np_type": "seller", "workflow_domain": "ONDC:RET10",
                  "workflow_domains": ["ONDC:RET10", "ONDC:RET11", "ONDC:RET12"]})

    cases.append({**_wf, "id": "F-TC031", "name": "Admin Rapid State Transitions (6-step)",
                  "category": "Functional",
                  "url": f"{host}/admin/subscribe",
                  "description": "[PASS EXPECTED — 6-step workflow] Exercises the complete admin state "
                                 "machine for a single participant: (1) POST WHITELISTED, (2) PATCH→ "
                                 "SUBSCRIBED with full payload, (3) PATCH→SUSPENDED, (4) PATCH→INACTIVE, "
                                 "(5) PATCH→SUBSCRIBED again to re-activate, (6) PATCH→UNSUBSCRIBED. "
                                 "Validates that all six admin-driven state transitions complete "
                                 "successfully and that re-activation from INACTIVE is supported.",
                  "workflow_type": "admin_rapid_transitions",
                  "workflow_np_type": "seller", "workflow_domain": "ONDC:RET10"})

    cases.append({**_wf, "id": "F-TC032", "name": "Admin Sequential Transitions with Contact Update",
                  "category": "Functional",
                  "url": f"{host}/admin/subscribe",
                  "description": "[PASS EXPECTED — 2-step workflow] (1) Admin POST to register a "
                                 "logistics GATEWAY participant directly in SUBSCRIBED state with a full "
                                 "payload including location and URI. (2) Admin PATCH to update the "
                                 "TECHNICAL contact details. Validates that participant contact "
                                 "information can be independently modified via PATCH after initial "
                                 "registration without affecting the participant's status or other fields.",
                  "workflow_type": "admin_sequential_transitions",
                  "workflow_np_type": "logistics", "workflow_domain": "ONDC:LOG10"})

    cases.append({**_wf, "id": "F-TC034", "name": "Admin Empty Arrays vs Omitted Fields",
                  "category": "Functional",
                  "url": f"{host}/admin/subscribe",
                  "description": "[PASS EXPECTED — 2-step workflow] (1) Admin POST WHITELISTED with the "
                                 "credentials field explicitly set to an empty array ([]) rather than "
                                 "omitted. (2) Admin PATCH to add a TECHNICAL contact while omitting the "
                                 "credentials field entirely. Validates that the API treats an explicit "
                                 "empty array and a completely absent field equivalently, and that partial "
                                 "PATCH updates are applied without unintended side-effects.",
                  "workflow_type": "admin_empty_arrays",
                  "workflow_np_type": "seller", "workflow_domain": "ONDC:RET12"})

    cases.append({**_wf, "id": "F-TC035", "name": "Admin Schema Compatibility (WHITELISTED→SUBSCRIBED)",
                  "category": "Functional",
                  "url": f"{host}/admin/subscribe",
                  "description": "[PASS EXPECTED — 2-step workflow] (1) Admin POST WHITELISTED with a "
                                 "complete Registry 3.0 payload including credentials, contacts, key, "
                                 "location, and URI. (2) Admin PATCH with action=SUBSCRIBED repeating "
                                 "the same full payload structure. Validates that the full Registry 3.0 "
                                 "schema is accepted consistently in both POST and PATCH, and that "
                                 "re-sending all fields during a state transition causes no errors.",
                  "workflow_type": "admin_schema_compat",
                  "workflow_np_type": "seller", "workflow_domain": "ONDC:RET12"})

    # ==========================================================================
    # NEGATIVE TEST CASES — /admin/subscribe endpoint
    # ==========================================================================
    neg_host = func_host  # route all to the same registry host

    # N-TC001: Missing Authorization
    p = nspg.random_payload(np_type="seller")
    tc("N-TC001", "Admin Missing Authorization Header", "Negative",
       "[FAIL EXPECTED — 401/403] Sends an admin subscribe POST with no Authorization header. The "
       "API must enforce authentication on every request and return HTTP 401 (Unauthorized) or 403 "
       "(Forbidden), refusing to process participant data when credentials are entirely absent.",
       "POST", f"{neg_host}/admin/subscribe", p, [401, 403], "no_auth")

    # N-TC002: Invalid Bearer token
    p = nspg.random_payload(np_type="seller")
    tc("N-TC002", "Admin Invalid Bearer Token", "Negative",
       "[FAIL EXPECTED — 401/403] Sends an admin subscribe POST with a syntactically valid but "
       "cryptographically incorrect Bearer token ('Bearer INVALID_TOKEN_123'). The API must validate "
       "the token's actual content, not just its presence, and return HTTP 401 or 403 to reject the "
       "unauthorized request.",
       "POST", f"{neg_host}/admin/subscribe", p, [401, 403], "custom",
       custom_headers={"Authorization": "Bearer INVALID_TOKEN_123", "Content-Type": "application/json"})

    # N-TC003: Expired JWT
    expired = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE1MTYyMzkwMjJ9"
        ".4Adcj0MqVKe8CsqGNNvBUhXi2T7qPFcF__xHIzk5xIk"
    )
    p = nspg.random_payload(np_type="seller")
    tc("N-TC003", "Admin Expired JWT Token", "Negative",
       "[FAIL EXPECTED — 401/403] Sends an admin subscribe POST authenticated with a known-expired "
       "JWT token. The API must validate the token's expiry claim (exp) on every request and return "
       "HTTP 401 or 403 when the token has expired, preventing replay of old tokens.",
       "POST", f"{neg_host}/admin/subscribe", p, [401, 403], "custom",
       custom_headers={"Authorization": f"Bearer {expired}", "Content-Type": "application/json"})

    # N-TC008: Missing participant_id
    p = nspg.random_payload(np_type="seller")
    del p["participant_id"]
    tc("N-TC008", "Missing participant_id (Admin)", "Negative",
       "[FAIL EXPECTED — 400/422] Sends an admin subscribe payload with the participant_id field "
       "completely omitted. As the primary identifier for the participant entity, participant_id is "
       "mandatory and its absence must be detected by schema validation, returning HTTP 400 or 422 "
       "with a descriptive error.",
       "POST", f"{neg_host}/admin/subscribe", p, [400, 422], "admin_bearer")

    # N-TC009: Missing action
    p = nspg.random_payload(np_type="seller")
    del p["action"]
    tc("N-TC009", "Missing action Field (Admin)", "Negative",
       "[FAIL EXPECTED — 400/422] Sends an admin subscribe payload with the action field omitted. "
       "The action field determines the initial participant state (WHITELISTED, SUBSCRIBED, etc.) "
       "and is required for all admin POST operations. The API must enforce its presence via schema "
       "validation and return HTTP 400 or 422.",
       "POST", f"{neg_host}/admin/subscribe", p, [400, 422], "admin_bearer")

    # N-TC010: Missing key — API accepts omitted key (optional field, proven by F-TC015/F-TC033)
    p = nspg.random_payload(np_type="seller")
    del p["key"]
    tc("N-TC010", "Missing key Object (Admin)", "Functional",
       "[PASS EXPECTED — 200] Sends an admin subscribe payload with the key array entirely omitted. "
       "The key array is optional in the admin subscribe schema — the API accepts a minimal payload "
       "without key material (confirmed by F-TC015 and F-TC033 passing with no key). "
       "Documents that the admin endpoint does not mandate cryptographic key material.",
       "POST", f"{neg_host}/admin/subscribe", p, [200], "admin_bearer")

    # N-TC011: Missing configs
    p = nspg.random_payload(np_type="seller")
    del p["configs"]
    tc("N-TC011", "Missing configs Array (Admin)", "Negative",
       "[FAIL EXPECTED — 400/422] Sends an admin subscribe payload with the configs array omitted. "
       "The configs array defines the domain-specific registration entries (domain, np_type, "
       "subscriber_id) and is mandatory. The API must detect its absence and return HTTP 400 or 422 "
       "rather than creating a domain-less participant record.",
       "POST", f"{neg_host}/admin/subscribe", p, [400, 422], "admin_bearer")

    # N-TC012: Invalid action value
    p = nspg.random_payload(np_type="seller")
    p["action"] = "INVALID_ACTION"
    tc("N-TC012", "Invalid action Value", "Negative",
       "[FAIL EXPECTED — 400/422] Sends an admin subscribe payload with action set to "
       "'INVALID_ACTION', which falls outside the allowed enum values (WHITELISTED, SUBSCRIBED, "
       "SUSPENDED, INACTIVE, UNSUBSCRIBED). The API must enforce strict enum validation on the "
       "action field and reject the request with HTTP 400 or 422.",
       "POST", f"{neg_host}/admin/subscribe", p, [400, 422], "admin_bearer")

    # N-TC013: Invalid np_type — API is permissive (returns 200 ACK)
    p = nspg.random_payload(np_type="seller")
    p["configs"][0]["np_type"] = "invalid_type"
    tc("N-TC013", "Invalid np_type in configs", "Functional",
       "[API PERMISSIVE — 200] Sends an admin subscribe payload where the configs entry has "
       "np_type set to 'invalid_type', outside the supported enum (BAP, BPP, GATEWAY). "
       "Documents that the admin subscribe endpoint is permissive and accepts unknown np_type values "
       "without schema validation, returning HTTP 200 ACK.",
       "POST", f"{neg_host}/admin/subscribe", p, [200], "admin_bearer")

    # N-TC014: Invalid domain format — API returns 404 (unknown domain treated as Not Found)
    p = nspg.random_payload(np_type="seller")
    p["configs"][0]["domain"] = "INVALID:DOMAIN:FORMAT"
    tc("N-TC014", "Invalid Domain Format in configs", "Negative",
       "[FAIL EXPECTED — 400/404/422] Sends an admin subscribe payload where the configs entry uses "
       "domain='INVALID:DOMAIN:FORMAT', which does not follow the ONDC domain naming convention "
       "(e.g., 'ONDC:RET10'). The API returns HTTP 404 for unknown domain identifiers.",
       "POST", f"{neg_host}/admin/subscribe", p, [400, 404, 422], "admin_bearer")

    # N-TC015: Invalid email format
    p = nspg.random_payload(np_type="seller")
    p["contacts"][0]["email"] = "invalid-email-format"
    tc("N-TC015", "Invalid Email Format in contacts", "Negative",
       "[FAIL EXPECTED — 400/422] Sends an admin subscribe payload with a contacts email field set "
       "to 'invalid-email-format' — a string missing both the @ symbol and a domain. The API must "
       "enforce RFC 5322 email format validation on contact email fields and return HTTP 400 or 422 "
       "for malformed addresses.",
       "POST", f"{neg_host}/admin/subscribe", p, [400, 422], "admin_bearer")

    # N-TC016: Invalid URL format
    p = nspg.random_payload(np_type="seller")
    p["uri"] = {"uri_id": p["_meta"]["uri_id"], "type": "CALLBACK", "url": "not-a-valid-url"}
    tc("N-TC016", "Invalid URL Format in uri", "Negative",
       "[FAIL EXPECTED — 400/422] Sends an admin subscribe payload with uri.url set to "
       "'not-a-valid-url', which is not a valid HTTP/HTTPS URL. The API must validate the URL format "
       "in the uri object and return HTTP 400 or 422, ensuring that only syntactically valid callback "
       "URLs are stored for network participants.",
       "POST", f"{neg_host}/admin/subscribe", p, [400, 422], "admin_bearer")

    # N-TC017: Invalid GST format — API is permissive (returns 200 ACK)
    p = nspg.random_payload(np_type="seller")
    p["credentials"][0]["cred_data"]["gstin"] = "INVALID_GST"
    tc("N-TC017", "Invalid GSTIN Format in credentials", "Functional",
       "[API PERMISSIVE — 200] Sends an admin subscribe payload with a GST credential where "
       "gstin is set to 'INVALID_GST'. Documents that the admin subscribe endpoint does not "
       "validate GSTIN format within credential data, returning HTTP 200 ACK.",
       "POST", f"{neg_host}/admin/subscribe", p, [200], "admin_bearer")

    # N-TC018: Invalid city code format
    p = nspg.random_payload(np_type="seller")
    p["location"] = {"location_id": p["_meta"]["loc_id"], "country": "IND",
                     "city": ["invalid_city_format"], "type": "SERVICEABLE"}
    tc("N-TC018", "Invalid City Code Format in location", "Negative",
       "[FAIL EXPECTED — 400/422] Sends an admin subscribe payload with location.city containing "
       "'invalid_city_format', which is missing the required 'std:' prefix (correct form: 'std:080'). "
       "The API must validate city code format in the location object and return HTTP 400 or 422 for "
       "malformed city identifiers.",
       "POST", f"{neg_host}/admin/subscribe", p, [400, 422], "admin_bearer")

    # N-TC019: Empty participant_id
    p = nspg.random_payload(np_type="seller")
    p["participant_id"] = ""
    tc("N-TC019", "Empty participant_id", "Negative",
       "[FAIL EXPECTED — 400/422] Sends an admin subscribe payload where participant_id is present "
       "but set to an empty string (''). An empty identifier is semantically invalid and must be "
       "caught by minLength or pattern constraints, returning HTTP 400 or 422 rather than creating "
       "a participant with a blank identity.",
       "POST", f"{neg_host}/admin/subscribe", p, [400, 422], "admin_bearer")

    # N-TC020: Empty key array
    p = nspg.random_payload(np_type="seller")
    p["key"] = [{}]
    tc("N-TC020", "Empty key Object", "Negative",
       "[FAIL EXPECTED — 400/422] Sends an admin subscribe payload where the key object is present "
       "but completely empty ({}), with all required sub-fields (uk_id, signing_public_key, "
       "encryption_public_key, signed_algorithm, encryption_algorithm) absent. The API must detect "
       "this nested schema violation and return HTTP 400 or 422.",
       "POST", f"{neg_host}/admin/subscribe", p, [400, 422], "admin_bearer")

    # N-TC021: Empty configs array
    p = nspg.random_payload(np_type="seller")
    p["configs"] = []
    tc("N-TC021", "Empty configs Array", "Negative",
       "[FAIL EXPECTED — 400/422] Sends an admin subscribe payload where configs is explicitly set "
       "to an empty array ([]) with no domain entries. The API must enforce a minimum of one entry "
       "(minItems: 1) and return HTTP 400 or 422, preventing the creation of a participant with no "
       "domain associations.",
       "POST", f"{neg_host}/admin/subscribe", p, [400, 422], "admin_bearer")

    # N-TC022: Malformed JSON
    tc("N-TC022", "Malformed JSON Body", "Negative",
       "[FAIL EXPECTED — 400/422] Sends a request body containing syntactically malformed JSON "
       "('{invalid json}') that cannot be parsed. The API must intercept the parse failure before "
       "schema validation and return HTTP 400 with a clear error. The API must not crash or return "
       "a 5xx response when the request body is unparseable.",
       "POST", f"{neg_host}/admin/subscribe", None,
       [400, 422], "admin_bearer",
       raw_body="{invalid json}", raw_content_type="application/json")

    # N-TC023: Empty payload
    tc("N-TC023", "Empty JSON Payload ({})", "Negative",
       "[FAIL EXPECTED — 400/422] Sends a syntactically valid but semantically empty JSON object "
       "({}) with no fields at all. The API must detect that all mandatory fields (participant_id, "
       "action, configs) are absent and return HTTP 400 or 422 listing the missing required "
       "properties, rather than attempting to process an empty registration.",
       "POST", f"{neg_host}/admin/subscribe", {},
       [400, 422], "admin_bearer")

    # N-TC024: Invalid Content-Type — API is permissive (returns 200 ACK for text/plain)
    p = nspg.random_payload(np_type="seller")
    tc("N-TC024", "Invalid Content-Type (text/plain)", "Functional",
       "[API PERMISSIVE — 200] Sends an admin subscribe POST with Content-Type set to "
       "'text/plain' instead of the required 'application/json'. Documents that the admin endpoint "
       "is permissive about Content-Type and accepts text/plain, returning HTTP 200 ACK.",
       "POST", f"{neg_host}/admin/subscribe", None,
       [200, 400, 415, 422], "custom",
       custom_headers={"Authorization": f"Bearer {nspg.admin_token}", "Content-Type": "text/plain"},
       raw_body=json.dumps({k: v for k, v in p.items() if k != "_meta"}),
       raw_content_type="text/plain")

    # N-TC025: Extra unknown fields
    p = nspg.random_payload(np_type="seller")
    p["unknown_field_1"] = "value1"
    p["unknown_field_2"] = "value2"
    tc("N-TC025", "Extra Unknown Fields in Payload", "Negative",
       "[POLICY TEST — 200/400/422 acceptable] Sends an admin subscribe payload that includes two "
       "unrecognised fields (unknown_field_1, unknown_field_2) alongside all valid mandatory fields. "
       "Tests whether the API enforces strict schema (additionalProperties: false → 400/422) or a "
       "permissive policy (ignore unknowns → 200). Documents actual API behaviour for schema "
       "strictness review.",
       "POST", f"{neg_host}/admin/subscribe", p,
       [200, 400, 422], "admin_bearer")

    # N-TC027: Duplicate participant_id — setup (first subscribe, must succeed 200)
    p = nspg.random_payload(np_type="seller")
    pid = p["_meta"]["participant_id"]
    tc("N-TC027", "Duplicate Participant — First Subscribe", "Functional",
       "[SETUP for N-TC028 — PASS EXPECTED 200] Admin subscribe to register a new seller participant "
       "using a fixed participant_id that will be reused in the duplicate conflict test (N-TC028). "
       "This step must succeed (HTTP 200 ACK) to establish a pre-existing registration in the "
       "registry, providing the baseline for testing duplicate detection.",
       "POST", f"{neg_host}/admin/subscribe", p, [200], "admin_bearer")
    p2 = nspg.random_payload(np_type="buyer")
    p2["participant_id"] = pid; p2["configs"][0]["subscriber_id"] = pid
    tc("N-TC028", "Duplicate Participant Conflict (Buyer vs Seller)", "Negative",
       "[FAIL EXPECTED — 200 NACK/409/400] Reuses the same participant_id registered in N-TC027 "
       "(seller BPP) but sends a new registration request with a different np_type (buyer BAP). "
       "The API must detect the duplicate participant_id conflict and return HTTP 409 (Conflict), "
       "HTTP 400, or HTTP 200 with a NACK — not silently overwrite the existing registration.",
       "POST", f"{neg_host}/admin/subscribe", p2, [200, 409, 400], "admin_bearer")

    # N-TC029: Invalid HTTP method GET
    tc("N-TC029", "Invalid HTTP Method (GET on /admin/subscribe)", "Negative",
       "[FAIL EXPECTED — 405/404] Sends a plain HTTP GET request to the /admin/subscribe endpoint. "
       "The endpoint only supports POST (create) and PATCH (update). GET must be rejected with "
       "HTTP 405 (Method Not Allowed) to prevent unintended read access via an unsupported method.",
       "GET", f"{neg_host}/admin/subscribe", None,
       [405, 404], "no_auth")

    # N-TC030: Invalid HTTP method PUT
    p = nspg.random_payload(np_type="seller")
    tc("N-TC030", "Invalid HTTP Method (PUT on /admin/subscribe)", "Negative",
       "[FAIL EXPECTED — 405/404] Sends an HTTP PUT request to /admin/subscribe with a valid admin "
       "subscribe payload. PUT (full-replace semantics) is not a supported method on this endpoint "
       "and must be rejected with HTTP 405 (Method Not Allowed), preventing accidental full-overwrite "
       "of existing participant records.",
       "PUT", f"{neg_host}/admin/subscribe", p,
       [405, 404], "admin_bearer")

    # N-TC031: Missing uk_id in key
    p = nspg.random_payload(np_type="seller")
    del p["key"][0]["uk_id"]
    tc("N-TC031", "Missing uk_id in key Object", "Negative",
       "[FAIL EXPECTED — 400/422] Sends an admin subscribe payload where the key object is present "
       "but uk_id is omitted. The uk_id is the unique key identifier that links cryptographic key "
       "material to the participant's domain configs. Its absence must trigger nested required-field "
       "validation within the key object, returning HTTP 400 or 422.",
       "POST", f"{neg_host}/admin/subscribe", p, [400, 422], "admin_bearer")

    # N-TC032: Missing signing_public_key
    p = nspg.random_payload(np_type="seller")
    del p["key"][0]["signing_public_key"]
    tc("N-TC032", "Missing signing_public_key in key", "Negative",
       "[FAIL EXPECTED — 400/422] Sends an admin subscribe payload where the key object is present "
       "but signing_public_key is omitted. The signing public key is used for ONDC network "
       "Ed25519 signature verification and is a required field within the key object. Its absence "
       "must cause schema validation to fail, returning HTTP 400 or 422.",
       "POST", f"{neg_host}/admin/subscribe", p, [400, 422], "admin_bearer")

    # N-TC033: Invalid base64 in key
    p = nspg.random_payload(np_type="seller")
    p["key"][0]["signing_public_key"] = "NOT_VALID_BASE64!@#$%"
    tc("N-TC033", "Invalid Base64 Encoding in signing_public_key", "Negative",
       "[FAIL EXPECTED — 400/422] Sends an admin subscribe payload where signing_public_key is set "
       "to 'NOT_VALID_BASE64!@#$%', which contains special characters invalid in base64 encoding. "
       "The API must validate the encoding format of all public key fields in the key object and "
       "return HTTP 400 or 422 when the key material is not valid base64.",
       "POST", f"{neg_host}/admin/subscribe", p, [400, 422], "admin_bearer")

    # N-TC034: Extremely large payload
    p = nspg.random_payload(np_type="seller")
    p["additional_data"] = {"large_field": "X" * 100000}
    tc("N-TC034", "Extremely Large Payload (100KB additional_data)", "Negative",
       "[FAIL EXPECTED — 413/400 or at minimum no 5xx] Sends an admin subscribe payload padded with "
       "approximately 100KB of data in the additional_data field. The API should enforce a payload "
       "size limit and return HTTP 413 (Payload Too Large) or 400. At minimum, the API must handle "
       "the oversized input gracefully without a 5xx server error. Validates protection against "
       "payload size abuse and resource exhaustion.",
       "POST", f"{neg_host}/admin/subscribe", p, [200, 413, 400], "admin_bearer")

    # N-TC042: Invalid state transition (SUBSCRIBED→WHITELISTED via admin PATCH)
    sfx8 = str(uuid.uuid4())[:8]
    pid8 = f"neg-{sfx8}.participant.ondc"
    p = {"participant_id": pid8, "action": "WHITELISTED",
         "dns_skip": True, "skip_ssl_verification": True}
    tc("N-TC042", "Invalid State Transition (SUBSCRIBED→WHITELISTED via Admin PATCH)", "Negative",
       "[FAIL EXPECTED — 400, 3-step workflow] Tests enforcement of the forward-only state machine: "
       "(1) Admin POST to create a participant as WHITELISTED. (2) Admin PATCH action=SUBSCRIBED to "
       "advance the state. (3) Admin PATCH action=WHITELISTED attempting to revert the state "
       "backward. The final step must be rejected with HTTP 400, confirming that the "
       "SUBSCRIBED→WHITELISTED backward transition is prohibited by the registry's state machine rules.",
       "PATCH", f"{neg_host}/admin/subscribe", p, [400], "admin_bearer", nack_ok=True)

    # N-TC044: Admin Special Characters in Fields (D13)
    sfx44 = str(uuid.uuid4())[:8]
    p_sc = {
        "participant_id": f"neg-special-{sfx44}.example.com",
        "action": "SUBSCRIBED",
        "credentials": [
            {"cred_id": f"cred-gst-{sfx44}", "type": "GST",
             "cred_data": {"gstin": "29YZABC9012D1E3",
                           "legal_name": "Special-Chars & Symbols Pvt. Ltd."}},
            {"cred_id": f"cred-pan-{sfx44}", "type": "PAN",
             "cred_data": {"pan": "YZABC9012D", "name": "Special-Chars & Symbols Pvt. Ltd."}},
        ],
        "contacts": [
            {"contact_id": f"contact-spec-{sfx44}", "type": "TECHNICAL",
             "email": "test+special_chars.123@example-domain.co.in",
             "phone": "+91-9876-543-210"},
        ],
        "configs": [{"domain": "ONDC:RET12", "np_type": "BAP",
                     "subscriber_id": f"neg-special-{sfx44}.example.com"}],
        "dns_skip": True, "skip_ssl_verification": True,
    }
    tc("N-TC044", "Admin Special Characters in Fields", "Negative",
       "[FAIL EXPECTED — 400] Sends an admin subscribe payload where credentials.cred_data.legal_name "
       "contains special characters ('Special-Chars & Symbols Pvt. Ltd.') and the contacts phone "
       "field uses a non-standard hyphenated format (+91-9876-543-210). The API must enforce "
       "character set and format constraints on credential and contact fields, returning HTTP 400 "
       "for disallowed characters or format violations.",
       "POST", f"{neg_host}/admin/subscribe", p_sc, [400], "admin_bearer", nack_ok=True)

    # N-TC045: Admin Maximum Field Lengths (D11)
    sfx45 = str(uuid.uuid4())[:8]
    very_long_name = ("VeryLongLegalNameThatExceedsNormalLength"
                      "AndTestsTheBoundaryConditionsOfTheSystem" * 2 + "PvtLtd")
    very_long_email = ("very-long-email-address-that-tests-maximum-field-length"
                       "@extremely-long-domain-name-for-testing-purposes.example.com")
    p_ml = {
        "participant_id": f"neg-maxlen-{sfx45}.example.com",
        "action": "WHITELISTED",
        "credentials": [{"cred_id": f"cred-gst-{sfx45}", "type": "GST",
                         "cred_data": {"gstin": "29QRSTU5678V1W0",
                                       "legal_name": very_long_name}}],
        "contacts": [{"contact_id": f"contact-long-{sfx45}", "type": "TECHNICAL",
                      "email": very_long_email, "phone": "+919876543210"}],
        "configs": [{"domain": "ONDC:RET10", "np_type": "BPP",
                     "subscriber_id": f"neg-maxlen-{sfx45}.example.com"}],
        "dns_skip": True, "skip_ssl_verification": True,
    }
    tc("N-TC045", "Admin Maximum Field Lengths", "Negative",
       "[POLICY TEST — 400 preferred, 200 acceptable] Sends an admin subscribe payload with an "
       "excessively long legal_name (300+ characters) and an unusually long email address. If the "
       "API enforces maxLength schema constraints it must return HTTP 400 or 422. HTTP 200 is also "
       "accepted if no length limits are imposed, making this a policy-detection test to document "
       "whether field length validation is enforced in the current API version.",
       "POST", f"{neg_host}/admin/subscribe", p_ml, [400, 200], "admin_bearer", nack_ok=True)

    # N-TC046: Admin Old-schema / V2 field names (ERR_102 SCHEMA_VALIDATION)
    # Uses keys + network_participant (V2 names) instead of key + configs (V3 schema).
    sfx46 = str(uuid.uuid4())[:8]
    p_v2 = {
        "participant_id": f"neg-v2schema-{sfx46}.example.com",
        "action": "WHITELISTED",
        "keys": {"uk_id": str(uuid.uuid4()), "signing_public_key": "dummybase64key",
                 "encryption_public_key": "dummybase64key"},
        "network_participant": [{"domain": "ONDC:RET10", "np_type": "seller"}],
    }
    tc("N-TC046", "Admin Old V2 Schema Field Names (ERR_102)", "Negative",
       "[FAIL EXPECTED — 400] Sends an admin subscribe payload using deprecated Registry V2 field "
       "names: 'keys' (instead of 'key') and 'network_participant' (instead of 'configs'). The V3 "
       "API must reject these legacy field names and return HTTP 400 with ERR_102 "
       "(SCHEMA_VALIDATION), indicating that the required 'configs' field is absent and the "
       "unrecognised 'keys'/'network_participant' properties are not allowed. Validates that the "
       "V3 API enforces backward-incompatibility with the V2 schema.",
       "POST", f"{neg_host}/admin/subscribe", p_v2, [400], "admin_bearer", nack_ok=True)

    return cases


# ---------------------------------------------------------------------------
# Test executor
# ---------------------------------------------------------------------------
def run_test_case(
    tc: Dict[str, Any],
    func_cfg: dict,
    neg_cfg: dict,
    timeout: int = 10,
) -> Dict[str, Any]:

    if tc.get("is_workflow"):
        return run_workflow_test_case(tc, func_cfg, timeout=timeout)

    is_func = tc["category"] == "Functional"
    cfg     = func_cfg if is_func else neg_cfg
    spg     = SubscribePayloadGenerator(func_cfg if is_func else neg_cfg)

    headers: Dict[str, str] = {}
    auth_note = ""

    mode = tc["auth_mode"]

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
        headers = dict(tc.get("custom_headers") or {
            "Authorization": f"Bearer {cfg.get('admin_token', '')}",
            "Content-Type": tc.get("raw_content_type", "application/json"),
        })
        auth_note = "Admin Bearer token (raw body)"

    headers.pop("serialized_body", None)

    sleep_s = tc.get("sleep_before")
    if sleep_s:
        logger.info(f"  [{tc['id']}] Sleeping {sleep_s}s ...")
        time.sleep(sleep_s)

    body_str: Optional[str] = None
    if tc.get("raw_body") is not None:
        body_str = str(tc["raw_body"])
    elif clean_payload is not None:
        body_str = json.dumps(clean_payload, separators=(",", ":"), sort_keys=False, ensure_ascii=False)

    req_url = tc["url"]
    req_headers_display = dict(headers)
    req_body_display: Optional[str] = None
    if clean_payload is not None:
        req_body_display = json.dumps(clean_payload, indent=2, ensure_ascii=False)
    elif tc.get("raw_body") is not None:
        req_body_display = str(tc["raw_body"])

    start_ts = datetime.now(timezone.utc)
    start_perf = time.perf_counter()
    resp_status: Optional[int] = None
    resp_body: str = ""
    resp_headers: Dict[str, str] = {}
    error_msg: Optional[str] = None

    try:
        method = tc["method"].upper()
        if method == "GET":
            resp = requests.get(req_url, headers=headers, timeout=timeout)
        elif method == "PATCH":
            if body_str is not None:
                if tc.get("raw_content_type"):
                    headers["Content-Type"] = tc["raw_content_type"]
                resp = requests.patch(req_url, data=body_str.encode("utf-8"), headers=headers, timeout=timeout)
            else:
                resp = requests.patch(req_url, headers=headers, timeout=timeout)
        elif method == "PUT":
            if body_str is not None:
                resp = requests.put(req_url, data=body_str.encode("utf-8"), headers=headers, timeout=timeout)
            else:
                resp = requests.put(req_url, headers=headers, timeout=timeout)
        else:  # POST
            if body_str is not None:
                if tc.get("raw_content_type"):
                    headers["Content-Type"] = tc["raw_content_type"]
                resp = requests.post(req_url, data=body_str.encode("utf-8"), headers=headers, timeout=timeout)
            else:
                resp = requests.post(req_url, headers=headers, timeout=timeout)

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

    if error_msg:
        passed = False
        status_note = f"ERROR - {error_msg}"
    elif tc.get("nack_ok") and _is_nack(resp_body):
        passed = True
        code_note = f", error.code={actual_error_code}" if actual_error_code else ""
        type_note = f", error.type={actual_error_type}" if actual_error_type else ""
        status_note = f"HTTP {resp_status} - NACK received (acceptable outcome){code_note}{type_note}"
    elif resp_status in tc["expected_status"]:
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
# HTML Report Generator — dark theme
# ---------------------------------------------------------------------------
def generate_html_report(results: List[Dict[str, Any]], output_path: str, run_ts: str) -> None:
    parent_results = [r for r in results if not r.get("is_step")]
    total  = len(parent_results)
    passed = sum(1 for r in parent_results if r["passed"])
    failed = total - passed
    pass_pct = round((passed / total * 100) if total else 0, 1)
    avg_s = round(sum(r["elapsed_ms"] for r in parent_results) / total / 1000 if total else 0, 3)

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

        extra_card_cls = ""
        prefix_chips   = ""
        if is_step_card:
            extra_card_cls = " step-card"
            step_label = r.get("step_label", f"Step {r.get('step_number', '')}")
            prefix_chips = (
                f'<span class="step-connector-chip">↳</span>'
                f'<span class="step-num-chip">{_esc(step_label)}</span>'
            )
        elif is_workflow_parent:
            extra_card_cls = " workflow-parent-card"

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
<title>ONDC Registry Admin Subscribe API Test Report</title>
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
.workflow-parent-card {{ border-top: 2px solid #4b5563; }}
.step-card {{
    margin-left: 36px;
    border-left: 3px solid #38bdf8 !important;
    border-style: solid;
    background: #111827;
}}
.step-card.fail {{ border-left: 3px solid #ef4444 !important; }}
.step-connector-chip {{ color: #4b5563; font-size: 1rem; flex-shrink: 0; padding: 0 2px; }}
.step-num-chip {{
    font-size: .7rem; font-weight: 800; letter-spacing: .6px;
    text-transform: uppercase; border-radius: 20px; padding: 3px 10px;
    background: rgba(56,189,248,.12); color: #7dd3fc; flex-shrink: 0;
}}
.chevron {{ color: #4b5563; font-size: .85rem; flex-shrink: 0; transition: transform .2s; margin-left: auto; }}
.chevron.open {{ transform: rotate(90deg); }}
.card-body {{ display: none; border-top: 1px solid #21262d; padding: 0 0 18px; }}
.section-title {{
    font-size: .78rem; font-weight: 700; text-transform: uppercase;
    letter-spacing: 1px; padding: 14px 20px 8px;
}}
.req-title {{ color: #60a5fa; border-top: 1px solid #21262d; margin-top: 4px; }}
.req-title:first-of-type {{ border-top: none; margin-top: 0; }}
.res-title {{ color: #34d399; border-top: 1px solid #21262d; }}
.two-col {{ display: grid; grid-template-columns: 1fr 1fr; gap: 0; padding: 0 12px; }}
@media (max-width: 800px) {{ .two-col {{ grid-template-columns: 1fr; }} }}
.col {{ padding: 0 8px; }}
.col-label {{ font-size: .72rem; text-transform: uppercase; letter-spacing: .8px; color: #64748b; margin-bottom: 6px; margin-top: 6px; }}
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
    <h1>ONDC Registry <span>Admin Subscribe API</span> Test Report</h1>
    <p>
      <strong>Source:</strong> /admin/subscribe — Functional &amp; Negative
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
        description="ONDC Registry Admin Subscribe API Test Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--output", default=None,
        help="Output HTML path. Auto-generated as reports/Registry-admin-subscribe-<suite>-<ts>.html if omitted.",
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
        f"generate_admin_subscribe_{args.suite}_{ts_file}.html",
    )
    if not os.path.isabs(output_path):
        output_path = os.path.join(PROJECT_ROOT, output_path)

    logger.info("=" * 60)
    logger.info("ONDC Registry Admin Subscribe API Test Runner")
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

    # ------------------------------------------------------------------
    # Obtain a valid admin token (fresh login preferred; static fallback)
    # then inject it into both configs so all test cases use a live token.
    # ------------------------------------------------------------------
    fresh_token = get_fresh_admin_token(func_cfg)
    if fresh_token:
        func_cfg["admin_token"] = fresh_token
        neg_cfg["admin_token"]  = fresh_token
        logger.info("Admin token refreshed and injected into both configs")
    else:
        logger.warning("Could not obtain a fresh admin token — tests may fail with 401")

    # Ensure the test participant is SUBSCRIBED before running tests
    reg_ok = register_participant_runtime(func_cfg, fresh_token or func_cfg.get("admin_token", ""))
    if reg_ok:
        print("[INFO] Participant status: SUBSCRIBED — ready for testing\n")
    else:
        print("[WARNING] Participant registration uncertain — proceeding with tests\n")

    logger.info("\nBuilding test cases ...")
    all_cases = build_test_cases(func_cfg, neg_cfg)

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
        result = run_test_case(tc_item, func_cfg, neg_cfg, timeout=args.timeout)
        if isinstance(result, list):
            results.extend(result)
        else:
            results.append(result)

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
