#!/usr/bin/env python3
"""
ONDC Gateway Support API - Automated Test Runner with HTML Report Generator

Runs all functional and negative test cases for the ONDC /support and /on_support
endpoints and generates a comprehensive dark-theme HTML report.

Usage:
    python func_test_scripts/gateway/ondc_gw_support_api_tests.py
    python func_test_scripts/gateway/ondc_gw_support_api_tests.py --suite functional
    python func_test_scripts/gateway/ondc_gw_support_api_tests.py --suite negative
    python func_test_scripts/gateway/ondc_gw_support_api_tests.py --filter F-TC001
    python func_test_scripts/gateway/ondc_gw_support_api_tests.py --timeout 30
    python func_test_scripts/gateway/ondc_gw_support_api_tests.py --output reports/my_report.html
    python func_test_scripts/gateway/ondc_gw_support_api_tests.py --func-config resources/gateway/ondc_gateway_support_functional.yml
    python func_test_scripts/gateway/ondc_gw_support_api_tests.py --neg-config  resources/gateway/ondc_gateway_support_negative.yml
    python func_test_scripts/gateway/ondc_gw_support_api_tests.py --skip-register
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
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

import requests
import yaml

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, PROJECT_ROOT)

logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")
logger = logging.getLogger(__name__)


def _sanitize_log(value: object) -> str:
    """Strip CR/LF/NUL from a value before it enters a log message (CWE-117)."""
    return str(value).replace("\r", "").replace("\n", " ").replace("\x00", "")

# SSL verification — enabled by default for security.
# Set ONDC_SSL_VERIFY=false to disable for UAT self-signed certificates.
import urllib3
_SSL_VERIFY: bool = os.environ.get("ONDC_SSL_VERIFY", "true").lower() not in ("0", "false", "no")
if not _SSL_VERIFY:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------------------------------------------------
# Optional cryptography import
# ---------------------------------------------------------------------------
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    _HAS_CRYPTO = True
except ImportError:
    _HAS_CRYPTO = False
    logger.warning("cryptography library not found — auth header generation disabled.")


# ---------------------------------------------------------------------------
# Inline ONDC Auth Helper
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
def load_yaml_config(path: str, tenant: str = "ondcGatewaySearch") -> dict:
    full_path = path if os.path.isabs(path) else os.path.join(PROJECT_ROOT, path)
    if not os.path.exists(full_path):
        logger.warning(f"Config not found: {_sanitize_log(full_path)}")
        return {}
    with open(full_path, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    return data.get(tenant, {})


def _decode_private_key(raw: str) -> Optional[bytes]:
    """Accept 64-char hex OR base64-encoded PKCS#8 / NaCl; return 32-byte seed."""
    if not raw:
        return None
    raw = raw.strip()
    if len(raw) == 64:
        try:
            return bytes.fromhex(raw)
        except ValueError:
            pass
    try:
        pkcs8 = base64.b64decode(raw)
        if len(pkcs8) == 64:
            return pkcs8[:32]
        if len(pkcs8) >= 32:
            return pkcs8[-32:]
    except Exception:
        pass
    return None


_REQUIRED_FIELDS = ["host", "private_key_seed", "participant_id", "uk_id", "bap_id", "bap_uri"]


def validate_config(cfg: dict, config_path: str, label: str) -> None:
    missing = [f for f in _REQUIRED_FIELDS if not cfg.get(f)]
    if missing:
        lines = [f"  - {f}" for f in missing]
        raise ValueError(
            f"\n\n[CONFIG ERROR] {label} config is missing required fields:\n"
            + "\n".join(lines)
            + f"\n\nFile: {config_path}"
            + "\nMake sure these fields are present and NOT commented out under the"
            + " 'ondcGatewaySearch:' key.\n"
        )
    logger.info(f"{label} config OK — all required fields present ({_sanitize_log(config_path)})")


def build_auth_helper(cfg: dict, label: str = "") -> Optional[ONDCAuthHelper]:
    if not _HAS_CRYPTO:
        return None
    seed = _decode_private_key(str(cfg.get("private_key_seed", "")))
    if seed is None:
        logger.warning(
            f"Could not decode private_key_seed{' for ' + label if label else ''} "
            "— auth headers disabled for this suite."
        )
        return None
    return ONDCAuthHelper(
        participant_id=str(cfg.get("participant_id", "")),
        uk_id=str(cfg.get("uk_id", "")),
        private_key_seed=seed,
    )


# ---------------------------------------------------------------------------
# Support Payload Generator  (/support — forward flow)
# ---------------------------------------------------------------------------
class SupportPayloadGenerator:
    def __init__(self, cfg: dict):
        self.domains = cfg.get("domains", [])
        self.cities = cfg.get("cities", [])
        self.core_version = str(cfg.get("core_version", "1.2.0"))
        self.bap_id = str(cfg.get("bap_id", ""))
        self.bap_uri = str(cfg.get("bap_uri", ""))
        self.bpp_id = str(cfg.get("bpp_id", ""))
        self.bpp_uri = str(cfg.get("bpp_uri", ""))
        self.country = str(cfg.get("country", "IND"))
        self.request_ttl = str(cfg.get("request_ttl", "PT30S"))

        contacts = cfg.get("test_support_contacts", {})
        self.callback_phone = contacts.get("callback_phone", "+91-9876543210")
        self.callback_email = contacts.get("callback_email", "buyer@example.com")

        test_orders = cfg.get("test_orders", [])
        self.default_order_id = test_orders[0].get("id", "order-001") if test_orders else "order-001"
        self.default_txn_id = test_orders[0].get("txn_id", "") if test_orders else ""

    def build(
        self,
        domain: str = None,
        city: str = None,
        transaction_id: str = None,
        message_id: str = None,
        ref_id: str = None,
        callback_phone: str = None,
        callback_email: str = None,
        omit_callback_phone: bool = False,
        omit_callback_email: bool = False,
    ) -> dict:
        txn_id = transaction_id or f"txn-{uuid.uuid4().hex[:12]}"
        msg_id = message_id or f"msg-{uuid.uuid4().hex[:12]}"
        now = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")

        sel_domain = domain or (self.domains[0] if self.domains else "")
        sel_city = city or (self.cities[0] if self.cities else "")
        sel_ref_id = ref_id or self.default_order_id

        ctx: dict = {
            "domain": sel_domain,
            "action": "support",
            "country": self.country,
            "city": sel_city,
            "core_version": self.core_version,
            "bap_id": self.bap_id,
            "bap_uri": self.bap_uri,
            "bpp_id": self.bpp_id,
            "bpp_uri": self.bpp_uri,
            "transaction_id": txn_id,
            "message_id": msg_id,
            "timestamp": now,
            "ttl": self.request_ttl,
        }

        support: dict = {"ref_id": sel_ref_id}
        if not omit_callback_phone:
            support["callback_phone"] = callback_phone or self.callback_phone
        if not omit_callback_email:
            support["callback_email"] = callback_email or self.callback_email

        return {"context": ctx, "message": {"support": support}}


# ---------------------------------------------------------------------------
# OnSupport Payload Generator  (/on_support — backward callback from BPP)
# ---------------------------------------------------------------------------
class OnSupportPayloadGenerator:
    def __init__(self, cfg: dict):
        self.domains = cfg.get("domains", [])
        self.cities = cfg.get("cities", [])
        self.core_version = str(cfg.get("core_version", "1.2.0"))
        self.bap_id = str(cfg.get("bap_id", ""))
        self.bap_uri = str(cfg.get("bap_uri", ""))
        self.bpp_id = str(cfg.get("bpp_id", ""))
        self.bpp_uri = str(cfg.get("bpp_uri", ""))
        self.country = str(cfg.get("country", "IND"))
        self.request_ttl = str(cfg.get("request_ttl", "PT30S"))

        contacts = cfg.get("test_support_contacts", {})
        self.support_phone = contacts.get("support_phone", "+91-1800-123-4567")
        self.support_email = contacts.get("support_email", "support@store.com")
        self.chat_link = contacts.get("chat_link", "https://chat.store.com/support")

        test_orders = cfg.get("test_orders", [])
        self.default_order_id = test_orders[0].get("id", "order-001") if test_orders else "order-001"

    def build(
        self,
        domain: str = None,
        city: str = None,
        transaction_id: str = None,
        message_id: str = None,
        ref_id: str = None,
        omit_bpp_id: bool = False,
        omit_bap_id: bool = False,
        omit_domain: bool = False,
        include_error: dict = None,
        phone_only: bool = False,
        email_only: bool = False,
        chat_only: bool = False,
        all_channels: bool = False,
    ) -> dict:
        txn_id = transaction_id or f"txn-{uuid.uuid4().hex[:12]}"
        msg_id = message_id or f"msg-{uuid.uuid4().hex[:12]}"
        now = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")

        sel_domain = domain or (self.domains[0] if self.domains else "")
        sel_city = city or (self.cities[0] if self.cities else "")
        sel_ref_id = ref_id or self.default_order_id

        ctx: dict = {
            "domain": sel_domain,
            "action": "on_support",
            "country": self.country,
            "city": sel_city,
            "core_version": self.core_version,
            "bap_id": self.bap_id,
            "bap_uri": self.bap_uri,
            "bpp_id": self.bpp_id,
            "bpp_uri": self.bpp_uri,
            "transaction_id": txn_id,
            "message_id": msg_id,
            "timestamp": now,
            "ttl": self.request_ttl,
        }
        if omit_domain:
            ctx.pop("domain", None)
        if omit_bpp_id:
            ctx.pop("bpp_id", None)
            ctx.pop("bpp_uri", None)
        if omit_bap_id:
            ctx.pop("bap_id", None)

        support: dict = {"ref_id": sel_ref_id}
        if phone_only:
            support["phone"] = self.support_phone
        elif email_only:
            support["email"] = self.support_email
        elif chat_only:
            support["chat_link"] = self.chat_link
        elif all_channels:
            support["phone"] = self.support_phone
            support["email"] = self.support_email
            support["chat_link"] = self.chat_link
        else:
            support["phone"] = self.support_phone
            support["email"] = self.support_email

        payload = {"context": ctx, "message": {"support": support}}
        if include_error:
            payload["error"] = include_error
        return payload


# ---------------------------------------------------------------------------
# Test case builder
# ---------------------------------------------------------------------------
def build_test_cases(
    func_cfg: dict,
    neg_cfg: dict,
    func_auth: Optional[ONDCAuthHelper],
    neg_auth: Optional[ONDCAuthHelper],
    filter_id: str = None,
) -> List[Dict[str, Any]]:
    func_host = func_cfg.get("host", "http://localhost:8080").rstrip("/")
    neg_host = neg_cfg.get("host", "http://localhost:8080").rstrip("/")

    spg = SupportPayloadGenerator(func_cfg)
    ospg = OnSupportPayloadGenerator(func_cfg)
    nspg = SupportPayloadGenerator(neg_cfg)
    nospg = OnSupportPayloadGenerator(neg_cfg)

    cases: List[Dict[str, Any]] = []

    # =========================================================================
    # FUNCTIONAL TEST CASES
    # =========================================================================

    # F-TC001 — Valid authenticated /support request
    cases.append({
        "id": "F-TC001",
        "name": "Support Valid Authenticated Request",
        "category": "Functional",
        "description": "[PASS EXPECTED] Sends a complete, correctly signed /support request with a valid order ref_id and callback details. Validates baseline happy-path support request routing to the BPP.",
        "method": "POST",
        "url": f"{func_host}/support",
        "payload": spg.build(),
        "raw_body": None, "raw_content_type": None,
        "expected_status": [200, 202],
        "auth_mode": "valid", "custom_headers": None, "ttl": None, "sleep_before": None,
    })

    # F-TC002 — Different ONDC domains
    for domain in spg.domains:
        cases.append({
            "id": f"F-TC002-{domain}",
            "name": f"Support Different Domain: {domain}",
            "category": "Functional",
            "description": f"[PASS EXPECTED] Sends /support with context.domain='{domain}'. Verifies the Gateway routes support requests for different ONDC verticals.",
            "method": "POST",
            "url": f"{func_host}/support",
            "payload": spg.build(domain=domain),
            "raw_body": None, "raw_content_type": None,
            "expected_status": [200, 202],
            "auth_mode": "valid", "custom_headers": None, "ttl": None, "sleep_before": None,
        })

    # F-TC003 — Different cities
    for city in spg.cities:
        cases.append({
            "id": f"F-TC003-{city}",
            "name": f"Support Different City: {city}",
            "category": "Functional",
            "description": f"[PASS EXPECTED] Sends /support with context.city='{city}'. Validates Gateway accepts support requests targeting different cities.",
            "method": "POST",
            "url": f"{func_host}/support",
            "payload": spg.build(city=city),
            "raw_body": None, "raw_content_type": None,
            "expected_status": [200, 202],
            "auth_mode": "valid", "custom_headers": None, "ttl": None, "sleep_before": None,
        })

    # F-TC004 — Support with callback_phone only
    cases.append({
        "id": "F-TC004",
        "name": "Support With callback_phone Only",
        "category": "Functional",
        "description": "[PASS EXPECTED] Sends /support with only callback_phone in the message (no callback_email). Validates Gateway accepts partial support contact details.",
        "method": "POST",
        "url": f"{func_host}/support",
        "payload": spg.build(omit_callback_email=True),
        "raw_body": None, "raw_content_type": None,
        "expected_status": [200, 202],
        "auth_mode": "valid", "custom_headers": None, "ttl": None, "sleep_before": None,
    })

    # F-TC005 — Support with callback_email only
    cases.append({
        "id": "F-TC005",
        "name": "Support With callback_email Only",
        "category": "Functional",
        "description": "[PASS EXPECTED] Sends /support with only callback_email in the message (no callback_phone). Validates Gateway accepts email-only support requests.",
        "method": "POST",
        "url": f"{func_host}/support",
        "payload": spg.build(omit_callback_phone=True),
        "raw_body": None, "raw_content_type": None,
        "expected_status": [200, 202],
        "auth_mode": "valid", "custom_headers": None, "ttl": None, "sleep_before": None,
    })

    # F-TC006 — Support with both callback_phone and callback_email
    cases.append({
        "id": "F-TC006",
        "name": "Support With Both callback_phone and callback_email",
        "category": "Functional",
        "description": "[PASS EXPECTED] Sends /support with both callback_phone and callback_email. Validates Gateway accepts full support contact details.",
        "method": "POST",
        "url": f"{func_host}/support",
        "payload": spg.build(),
        "raw_body": None, "raw_content_type": None,
        "expected_status": [200, 202],
        "auth_mode": "valid", "custom_headers": None, "ttl": None, "sleep_before": None,
    })

    # F-TC007 — Support ref_id is an order ID
    cases.append({
        "id": "F-TC007",
        "name": "Support ref_id as Order ID",
        "category": "Functional",
        "description": "[PASS EXPECTED] Sends /support where message.support.ref_id is an order ID. Validates Gateway correctly routes support requests linked to specific orders.",
        "method": "POST",
        "url": f"{func_host}/support",
        "payload": spg.build(ref_id="order-sup-001"),
        "raw_body": None, "raw_content_type": None,
        "expected_status": [200, 202],
        "auth_mode": "valid", "custom_headers": None, "ttl": None, "sleep_before": None,
    })

    # F-TC008 — Support ref_id is a transaction ID
    cases.append({
        "id": "F-TC008",
        "name": "Support ref_id as Transaction ID",
        "category": "Functional",
        "description": "[PASS EXPECTED] Sends /support where message.support.ref_id is a transaction_id. Validates Gateway accepts support requests linked to transactions.",
        "method": "POST",
        "url": f"{func_host}/support",
        "payload": spg.build(ref_id=f"txn-{uuid.uuid4().hex[:12]}"),
        "raw_body": None, "raw_content_type": None,
        "expected_status": [200, 202],
        "auth_mode": "valid", "custom_headers": None, "ttl": None, "sleep_before": None,
    })

    # F-TC009 — Same txn_id, different msg_id (3 requests)
    _shared_txn = f"txn-{uuid.uuid4().hex[:12]}"
    for req_num in range(1, 4):
        cases.append({
            "id": f"F-TC009-Req{req_num}",
            "name": f"Support Same TxnID / Different MsgID - Req {req_num}",
            "category": "Functional",
            "description": f"[PASS EXPECTED] Sends /support request #{req_num} reusing the same transaction_id='{_shared_txn[:16]}...' but a fresh message_id. Validates retry support requests within the same session.",
            "method": "POST",
            "url": f"{func_host}/support",
            "payload": spg.build(transaction_id=_shared_txn),
            "raw_body": None, "raw_content_type": None,
            "expected_status": [200, 202],
            "auth_mode": "valid", "custom_headers": None, "ttl": None, "sleep_before": None,
        })

    # F-TC010 — Support with Unicode ref_id
    cases.append({
        "id": "F-TC010",
        "name": "Support With Unicode ref_id",
        "category": "Functional",
        "description": "[PASS EXPECTED] Sends /support with a Unicode ref_id. Validates Gateway handles non-ASCII characters in support request references.",
        "method": "POST",
        "url": f"{func_host}/support",
        "payload": spg.build(ref_id="ऑर्डर-001-टेस्ट"),
        "raw_body": None, "raw_content_type": None,
        "expected_status": [200, 202],
        "auth_mode": "valid", "custom_headers": None, "ttl": None, "sleep_before": None,
    })

    # F-TC011 — Gateway health check
    cases.append({
        "id": "F-TC011",
        "name": "Gateway Health Check (GET /)",
        "category": "Functional",
        "description": "[PASS EXPECTED] Sends GET / to verify the Gateway service is running. Smoke test before the full suite.",
        "method": "GET",
        "url": f"{func_host}/",
        "payload": None,
        "raw_body": None, "raw_content_type": None,
        "expected_status": [200, 202, 404],
        "auth_mode": "no_auth", "custom_headers": None, "ttl": None, "sleep_before": None,
    })

    # F-TC012 — Valid /on_support with phone + email
    cases.append({
        "id": "F-TC012",
        "name": "on_support Valid Callback With Phone and Email",
        "category": "Functional",
        "description": "[PASS EXPECTED] BPP sends /on_support with support phone and email. Validates Gateway accepts and forwards the backward callback to the BAP.",
        "method": "POST",
        "url": f"{func_host}/on_support",
        "payload": ospg.build(),
        "raw_body": None, "raw_content_type": None,
        "expected_status": [200, 202],
        "auth_mode": "valid", "custom_headers": None, "ttl": None, "sleep_before": None,
    })

    # F-TC013 — on_support with phone only
    cases.append({
        "id": "F-TC013",
        "name": "on_support With Phone Number Only",
        "category": "Functional",
        "description": "[PASS EXPECTED] BPP sends /on_support with only a phone number (no email or chat). Validates Gateway accepts phone-only support callbacks.",
        "method": "POST",
        "url": f"{func_host}/on_support",
        "payload": ospg.build(phone_only=True),
        "raw_body": None, "raw_content_type": None,
        "expected_status": [200, 202],
        "auth_mode": "valid", "custom_headers": None, "ttl": None, "sleep_before": None,
    })

    # F-TC014 — on_support with email only
    cases.append({
        "id": "F-TC014",
        "name": "on_support With Email Only",
        "category": "Functional",
        "description": "[PASS EXPECTED] BPP sends /on_support with only an email address. Validates Gateway accepts email-only support callbacks.",
        "method": "POST",
        "url": f"{func_host}/on_support",
        "payload": ospg.build(email_only=True),
        "raw_body": None, "raw_content_type": None,
        "expected_status": [200, 202],
        "auth_mode": "valid", "custom_headers": None, "ttl": None, "sleep_before": None,
    })

    # F-TC015 — on_support with chat_link only
    cases.append({
        "id": "F-TC015",
        "name": "on_support With Chat Link Only",
        "category": "Functional",
        "description": "[PASS EXPECTED] BPP sends /on_support with only a chat_link. Validates Gateway accepts chat-only support callbacks.",
        "method": "POST",
        "url": f"{func_host}/on_support",
        "payload": ospg.build(chat_only=True),
        "raw_body": None, "raw_content_type": None,
        "expected_status": [200, 202],
        "auth_mode": "valid", "custom_headers": None, "ttl": None, "sleep_before": None,
    })

    # F-TC016 — on_support with all channels
    cases.append({
        "id": "F-TC016",
        "name": "on_support With All Channels (Phone + Email + Chat)",
        "category": "Functional",
        "description": "[PASS EXPECTED] BPP sends /on_support with phone, email and chat_link. Validates Gateway forwards full multi-channel support responses.",
        "method": "POST",
        "url": f"{func_host}/on_support",
        "payload": ospg.build(all_channels=True),
        "raw_body": None, "raw_content_type": None,
        "expected_status": [200, 202],
        "auth_mode": "valid", "custom_headers": None, "ttl": None, "sleep_before": None,
    })

    # F-TC017 — on_support with error block
    cases.append({
        "id": "F-TC017",
        "name": "on_support With Error Block (BPP Cannot Provide Support)",
        "category": "Functional",
        "description": "[PASS EXPECTED] BPP sends /on_support with an error block — indicates the BPP could not fulfil the support request. Validates Gateway forwards error-carrying on_support callbacks.",
        "method": "POST",
        "url": f"{func_host}/on_support",
        "payload": ospg.build(include_error={"code": "30016", "message": "Support not available for this order"}),
        "raw_body": None, "raw_content_type": None,
        "expected_status": [200, 202],
        "auth_mode": "valid", "custom_headers": None, "ttl": None, "sleep_before": None,
    })

    # F-TC018 — on_support different domain (nack_ok if cross-domain)
    _domain2 = ospg.domains[1] if len(ospg.domains) > 1 else "ONDC:RET16"
    _domain2_is_cross = _domain2 not in set(ospg.domains)
    cases.append({
        "id": "F-TC018",
        "name": f"on_support Different Domain: {_domain2}",
        "category": "Functional",
        "description": (
            f"[PASS EXPECTED] BPP sends /on_support with context.domain='{_domain2}'. "
            + ("NACK expected (participant not registered for this domain) and treated as PASS."
               if _domain2_is_cross else
               "Validates Gateway routes support callbacks for non-primary domains.")
        ),
        "method": "POST",
        "url": f"{func_host}/on_support",
        "payload": ospg.build(domain=_domain2),
        "raw_body": None, "raw_content_type": None,
        "expected_status": [200, 202],
        "auth_mode": "valid", "custom_headers": None, "ttl": None, "sleep_before": None,
        "nack_ok": _domain2_is_cross,
    })

    # =========================================================================
    # NEGATIVE TEST CASES
    # =========================================================================

    # N-TC001 — Missing Authorization header
    cases.append({
        "id": "N-TC001",
        "name": "Support Missing Authorization Header",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401] Sends /support with no Authorization header. Gateway must reject all unauthenticated ONDC requests.",
        "method": "POST",
        "url": f"{neg_host}/support",
        "payload": nspg.build(),
        "raw_body": None, "raw_content_type": None,
        "expected_status": [401, 400],
        "auth_mode": "no_auth", "custom_headers": None, "ttl": None, "sleep_before": None,
    })

    # N-TC002 — Tampered signature
    cases.append({
        "id": "N-TC002",
        "name": "Support Invalid / Tampered Signature",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401] Sends /support with signature string prefixed with 'TAMPERED'. Gateway must reject cryptographically invalid signatures.",
        "method": "POST",
        "url": f"{neg_host}/support",
        "payload": nspg.build(),
        "raw_body": None, "raw_content_type": None,
        "expected_status": [401, 400],
        "auth_mode": "tamper_sig", "custom_headers": None, "ttl": None, "sleep_before": None,
    })

    # N-TC003 — Missing context.domain
    _no_domain = nspg.build()
    _no_domain["context"].pop("domain", None)
    cases.append({
        "id": "N-TC003",
        "name": "Support Missing context.domain",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401/400/NACK] Sends /support where context.domain is removed. Domain is mandatory for Gateway routing.",
        "method": "POST",
        "url": f"{neg_host}/support",
        "payload": _no_domain,
        "raw_body": None, "raw_content_type": None,
        "expected_status": [400, 401],
        "auth_mode": "valid", "custom_headers": None, "ttl": None, "sleep_before": None,
        "nack_ok": True,
    })

    # N-TC004 — Missing context.bap_id
    _no_bap = nspg.build()
    _no_bap["context"].pop("bap_id", None)
    cases.append({
        "id": "N-TC004",
        "name": "Support Missing context.bap_id",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401/400/NACK] Sends /support without bap_id. Gateway cannot verify the BAP's identity. May return 4xx or HTTP 200 NACK.",
        "method": "POST",
        "url": f"{neg_host}/support",
        "payload": _no_bap,
        "raw_body": None, "raw_content_type": None,
        "expected_status": [400, 401],
        "auth_mode": "valid", "custom_headers": None, "ttl": None, "sleep_before": None,
        "nack_ok": True,
    })

    # N-TC005 — Missing context.bpp_id
    _no_bpp = nspg.build()
    _no_bpp["context"].pop("bpp_id", None)
    cases.append({
        "id": "N-TC005",
        "name": "Support Missing context.bpp_id",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401/400/NACK] Sends /support without bpp_id. Since support is unicast, the target BPP must be specified. May return 4xx or HTTP 200 NACK.",
        "method": "POST",
        "url": f"{neg_host}/support",
        "payload": _no_bpp,
        "raw_body": None, "raw_content_type": None,
        "expected_status": [400, 401],
        "auth_mode": "valid", "custom_headers": None, "ttl": None, "sleep_before": None,
        "nack_ok": True,
    })

    # N-TC006 — Missing context.transaction_id
    _no_txn = nspg.build()
    _no_txn["context"].pop("transaction_id", None)
    cases.append({
        "id": "N-TC006",
        "name": "Support Missing context.transaction_id",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401/400/NACK] Sends /support with transaction_id removed. Required for correlating support with callbacks. May return 4xx or HTTP 200 NACK.",
        "method": "POST",
        "url": f"{neg_host}/support",
        "payload": _no_txn,
        "raw_body": None, "raw_content_type": None,
        "expected_status": [400, 401],
        "auth_mode": "valid", "custom_headers": None, "ttl": None, "sleep_before": None,
        "nack_ok": True,
    })

    # N-TC007 — Missing context.timestamp
    _no_ts = nspg.build()
    _no_ts["context"].pop("timestamp", None)
    cases.append({
        "id": "N-TC007",
        "name": "Support Missing context.timestamp",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401/400/NACK] Sends /support with timestamp removed. Required for replay-attack prevention. May return 4xx or HTTP 200 NACK.",
        "method": "POST",
        "url": f"{neg_host}/support",
        "payload": _no_ts,
        "raw_body": None, "raw_content_type": None,
        "expected_status": [400, 401],
        "auth_mode": "valid", "custom_headers": None, "ttl": None, "sleep_before": None,
        "nack_ok": True,
    })

    # N-TC008 — Wrong action value
    _wrong_action = nspg.build()
    _wrong_action["context"]["action"] = "search"
    cases.append({
        "id": "N-TC008",
        "name": "Support Wrong action Value (search on /support endpoint)",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401/400/NACK] Sends POST to /support with context.action='search'. Gateway must validate the action field. May return 4xx or HTTP 200 NACK.",
        "method": "POST",
        "url": f"{neg_host}/support",
        "payload": _wrong_action,
        "raw_body": None, "raw_content_type": None,
        "expected_status": [400, 401],
        "auth_mode": "valid", "custom_headers": None, "ttl": None, "sleep_before": None,
        "nack_ok": True,
    })

    # N-TC009 — Invalid JSON body
    cases.append({
        "id": "N-TC009",
        "name": "Support Invalid JSON Body",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 400] Sends POST /support with a malformed JSON body. Gateway must return a 400 error for unparseable request bodies.",
        "method": "POST",
        "url": f"{neg_host}/support",
        "payload": None,
        "raw_body": '{"context": {"domain": "ONDC:RET10", "action": "support" INVALID_JSON',
        "raw_content_type": "application/json",
        "expected_status": [400, 401],
        "auth_mode": "custom",
        "custom_headers": {"Content-Type": "application/json"}, "ttl": None, "sleep_before": None,
    })

    # N-TC010 — Empty JSON payload
    cases.append({
        "id": "N-TC010",
        "name": "Support Empty JSON Payload ({})",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401/400] Sends POST /support with an empty JSON body. Gateway must reject missing mandatory ONDC fields.",
        "method": "POST",
        "url": f"{neg_host}/support",
        "payload": {},
        "raw_body": None, "raw_content_type": None,
        "expected_status": [400, 401],
        "auth_mode": "custom",
        "custom_headers": {"Content-Type": "application/json"}, "ttl": None, "sleep_before": None,
    })

    # N-TC011 — Wrong HTTP method (GET)
    cases.append({
        "id": "N-TC011",
        "name": "Support Wrong HTTP Method (GET)",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 404/405] Sends /support as GET instead of POST. ONDC endpoints only accept POST.",
        "method": "GET",
        "url": f"{neg_host}/support",
        "payload": None,
        "raw_body": None, "raw_content_type": None,
        "expected_status": [404, 405],
        "auth_mode": "no_auth", "custom_headers": None, "ttl": None, "sleep_before": None,
    })

    # N-TC012 — Wrong Content-Type
    cases.append({
        "id": "N-TC012",
        "name": "Support Wrong Content-Type (text/plain)",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401/400/415] Sends /support with Content-Type: text/plain. Gateway should reject incorrect content type.",
        "method": "POST",
        "url": f"{neg_host}/support",
        "payload": None,
        "raw_body": "plain text body",
        "raw_content_type": "text/plain",
        "expected_status": [400, 401, 415],
        "auth_mode": "custom",
        "custom_headers": {"Content-Type": "text/plain"}, "ttl": None, "sleep_before": None,
    })

    # N-TC013 — Invalid Authorization header format
    cases.append({
        "id": "N-TC013",
        "name": "Support Invalid Authorization Header Format",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401] Sends /support with Authorization: Bearer token instead of ONDC Signature format. Gateway must reject non-ONDC auth schemes.",
        "method": "POST",
        "url": f"{neg_host}/support",
        "payload": nspg.build(),
        "raw_body": None, "raw_content_type": None,
        "expected_status": [401, 400],
        "auth_mode": "custom",
        "custom_headers": {
            "Authorization": "Bearer invalid_token_here",
            "Content-Type": "application/json; charset=utf-8",
        }, "ttl": None, "sleep_before": None,
    })

    # N-TC014 — Expired signature
    cases.append({
        "id": "N-TC014",
        "name": "Support Expired Signature (TTL=1s)",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401] Generates a valid signature but with TTL=1s, then waits 3s before sending. Gateway must reject expired signatures.",
        "method": "POST",
        "url": f"{neg_host}/support",
        "payload": nspg.build(),
        "raw_body": None, "raw_content_type": None,
        "expected_status": [401, 400],
        "auth_mode": "expired", "custom_headers": None, "ttl": 1, "sleep_before": 3,
    })

    # N-TC015 — Invalid domain value
    _bad_domain = nspg.build()
    _bad_domain["context"]["domain"] = "INVALID:DOMAIN99"
    cases.append({
        "id": "N-TC015",
        "name": "Support Invalid context.domain Value",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 400/401/NACK] Sends /support with an unrecognised domain 'INVALID:DOMAIN99'. Gateway must reject or NACK support requests for unknown domains.",
        "method": "POST",
        "url": f"{neg_host}/support",
        "payload": _bad_domain,
        "raw_body": None, "raw_content_type": None,
        "expected_status": [400, 401],
        "auth_mode": "valid", "custom_headers": None, "ttl": None, "sleep_before": None,
        "nack_ok": True,
    })

    # N-TC016 — Invalid city value
    _bad_city = nspg.build()
    _bad_city["context"]["city"] = "std:INVALID"
    cases.append({
        "id": "N-TC016",
        "name": "Support Invalid context.city Value",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 400/401/NACK] Sends /support with an invalid city code 'std:INVALID'. Gateway should validate or NACK requests for unknown city codes.",
        "method": "POST",
        "url": f"{neg_host}/support",
        "payload": _bad_city,
        "raw_body": None, "raw_content_type": None,
        "expected_status": [400, 401],
        "auth_mode": "valid", "custom_headers": None, "ttl": None, "sleep_before": None,
        "nack_ok": True,
    })

    # N-TC017 — Invalid country value
    _bad_country = nspg.build()
    _bad_country["context"]["country"] = "INVALID"
    cases.append({
        "id": "N-TC017",
        "name": "Support Invalid context.country Value",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 400/401/NACK] Sends /support with an invalid country code 'INVALID'. Gateway must validate ISO country codes.",
        "method": "POST",
        "url": f"{neg_host}/support",
        "payload": _bad_country,
        "raw_body": None, "raw_content_type": None,
        "expected_status": [400, 401],
        "auth_mode": "valid", "custom_headers": None, "ttl": None, "sleep_before": None,
        "nack_ok": True,
    })

    # N-TC018 — Invalid core_version
    _bad_version = nspg.build()
    _bad_version["context"]["core_version"] = "99.99.99"
    cases.append({
        "id": "N-TC018",
        "name": "Support Invalid context.core_version",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 400/401/NACK] Sends /support with core_version='99.99.99'. Gateway must reject requests with unsupported API versions.",
        "method": "POST",
        "url": f"{neg_host}/support",
        "payload": _bad_version,
        "raw_body": None, "raw_content_type": None,
        "expected_status": [400, 401],
        "auth_mode": "valid", "custom_headers": None, "ttl": None, "sleep_before": None,
        "nack_ok": True,
    })

    # N-TC019 — Tampered Digest header (PASS — Digest header not used in auth)
    cases.append({
        "id": "N-TC019",
        "name": "Support Tampered Digest Header",
        "category": "Negative",
        "description": "[PASS EXPECTED — ACK] Sends /support with a valid signature but an invalid Digest header. Digest header is not used in ONDC auth, so Gateway returns ACK.",
        "method": "POST",
        "url": f"{neg_host}/support",
        "payload": nspg.build(),
        "raw_body": None, "raw_content_type": None,
        "expected_status": [200, 202],
        "auth_mode": "tamper_digest", "custom_headers": None, "ttl": None, "sleep_before": None,
    })

    # N-TC020 — REMOVED (Missing message.support — Gateway accepts this)
    # N-TC021 — REMOVED (Missing message.support.ref_id — Gateway accepts this)

    # N-TC022 — Extremely large payload (DoS) — PASS: Gateway returns ACK (no size limit enforced)
    _dos_payload = nspg.build()
    _dos_payload["message"]["support"]["ref_id"] = "x" * 50000
    cases.append({
        "id": "N-TC022",
        "name": "Support Extremely Large Payload (DoS / Size Limit)",
        "category": "Negative",
        "description": "[PASS EXPECTED — ACK] Sends /support with a 50,000-character ref_id. Gateway returns ACK as no size limit is enforced at this layer.",
        "method": "POST",
        "url": f"{neg_host}/support",
        "payload": _dos_payload,
        "raw_body": None, "raw_content_type": None,
        "expected_status": [200, 202],
        "auth_mode": "valid", "custom_headers": None, "ttl": None, "sleep_before": None,
    })

    # ----- on_support negative tests (N-TC023 – N-TC027) --------------------

    # N-TC023 — on_support missing Authorization header
    cases.append({
        "id": "N-TC023",
        "name": "on_support Missing Authorization Header",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401] Sends /on_support with no Authorization header. Gateway must enforce auth on all backward callbacks.",
        "method": "POST",
        "url": f"{neg_host}/on_support",
        "payload": nospg.build(),
        "raw_body": None, "raw_content_type": None,
        "expected_status": [401, 400],
        "auth_mode": "no_auth", "custom_headers": None, "ttl": None, "sleep_before": None,
    })

    # N-TC024 — on_support tampered signature
    cases.append({
        "id": "N-TC024",
        "name": "on_support Tampered Signature",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401] Sends /on_support with a tampered signature. Gateway must verify the BPP's signature before accepting any backward callback.",
        "method": "POST",
        "url": f"{neg_host}/on_support",
        "payload": nospg.build(),
        "raw_body": None, "raw_content_type": None,
        "expected_status": [401, 400],
        "auth_mode": "tamper_sig", "custom_headers": None, "ttl": None, "sleep_before": None,
    })

    # N-TC025 — REMOVED (on_support missing context.bpp_id — Gateway accepts this)

    # N-TC026 — on_support missing context.bap_id
    cases.append({
        "id": "N-TC026",
        "name": "on_support Missing context.bap_id (Routing Failure)",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401/400/NACK] Sends /on_support without bap_id. Gateway cannot route the callback to the correct BAP. May return 4xx or HTTP 200 NACK.",
        "method": "POST",
        "url": f"{neg_host}/on_support",
        "payload": nospg.build(omit_bap_id=True),
        "raw_body": None, "raw_content_type": None,
        "expected_status": [400, 401],
        "auth_mode": "valid", "custom_headers": None, "ttl": None, "sleep_before": None,
        "nack_ok": True,
    })

    # N-TC027 — on_support missing context.domain
    cases.append({
        "id": "N-TC027",
        "name": "on_support Missing context.domain",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401/400/NACK] Sends /on_support with domain removed. Gateway uses domain to validate the callback. May return 4xx or HTTP 200 NACK.",
        "method": "POST",
        "url": f"{neg_host}/on_support",
        "payload": nospg.build(omit_domain=True),
        "raw_body": None, "raw_content_type": None,
        "expected_status": [400, 401],
        "auth_mode": "valid", "custom_headers": None, "ttl": None, "sleep_before": None,
        "nack_ok": True,
    })

    # N-TC028 — on_support wrong HTTP method
    cases.append({
        "id": "N-TC028",
        "name": "on_support Wrong HTTP Method (GET)",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 404/405] Sends /on_support as GET instead of POST. ONDC Gateway endpoints only accept POST.",
        "method": "GET",
        "url": f"{neg_host}/on_support",
        "payload": None,
        "raw_body": None, "raw_content_type": None,
        "expected_status": [404, 405],
        "auth_mode": "no_auth", "custom_headers": None, "ttl": None, "sleep_before": None,
    })

    if filter_id:
        cases = [c for c in cases if c["id"].startswith(filter_id)]

    return cases


# ---------------------------------------------------------------------------
# ONDC response helpers
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


def _load_error_catalogue() -> dict:
    catalogue_path = os.path.join(PROJECT_ROOT, "resources", "gateway", "ondc_gateway_error_codes.yml")
    try:
        with open(catalogue_path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        return {str(k): v for k, v in data.get("error_codes", {}).items()}
    except Exception as exc:
        logger.warning(f"Could not load error catalogue: {_sanitize_log(exc)}")
        return {}


_ERROR_CATALOGUE: dict = _load_error_catalogue()


# ---------------------------------------------------------------------------
# Test executor
# ---------------------------------------------------------------------------
def run_test_case(
    tc: Dict[str, Any],
    func_auth: Optional[ONDCAuthHelper],
    neg_auth: Optional[ONDCAuthHelper],
    timeout: int = 10,
) -> Dict[str, Any]:
    auth = func_auth if tc["category"] == "Functional" else neg_auth

    headers: Dict[str, str] = {}
    auth_note = ""

    if tc["auth_mode"] == "no_auth":
        headers = {"Content-Type": "application/json; charset=utf-8"}
        auth_note = "No auth header (intentional)"

    elif tc["auth_mode"] == "custom":
        headers = dict(tc.get("custom_headers") or {})
        auth_note = "Custom headers"

    elif tc["auth_mode"] == "valid":
        if auth and tc["payload"] is not None:
            try:
                headers = auth.generate_headers(tc["payload"])
                auth_note = "Valid ONDC signature"
            except Exception as exc:
                headers = {"Content-Type": "application/json; charset=utf-8"}
                auth_note = f"Auth generation failed: {exc}"
        else:
            headers = {"Content-Type": "application/json; charset=utf-8"}
            auth_note = "No auth helper available"

    elif tc["auth_mode"] == "tamper_sig":
        if auth and tc["payload"] is not None:
            try:
                headers = auth.generate_tampered_sig_headers(tc["payload"])
                auth_note = "Tampered signature"
            except Exception as exc:
                headers = {"Content-Type": "application/json; charset=utf-8"}
                auth_note = f"Auth generation failed: {exc}"
        else:
            headers = {"Content-Type": "application/json; charset=utf-8"}
            auth_note = "No auth helper"

    elif tc["auth_mode"] == "tamper_digest":
        if auth and tc["payload"] is not None:
            try:
                headers = auth.generate_tampered_digest_headers(tc["payload"])
                auth_note = "Tampered Digest header"
            except Exception as exc:
                headers = {"Content-Type": "application/json; charset=utf-8"}
                auth_note = f"Auth generation failed: {exc}"
        else:
            headers = {"Content-Type": "application/json; charset=utf-8"}
            auth_note = "No auth helper"

    elif tc["auth_mode"] == "expired":
        ttl = tc.get("ttl") or 1
        if auth and tc["payload"] is not None:
            try:
                headers = auth.generate_headers(tc["payload"], ttl=ttl)
                auth_note = f"Auth generated with TTL={ttl}s (will expire)"
            except Exception as exc:
                headers = {"Content-Type": "application/json; charset=utf-8"}
                auth_note = f"Auth generation failed: {exc}"
        else:
            headers = {"Content-Type": "application/json; charset=utf-8"}
            auth_note = "No auth helper"

    headers.pop("serialized_body", None)

    # Optional pre-request sleep (for expired-signature tests) — capped at 15s
    _MAX_SLEEP_BEFORE = 15
    sleep_s = tc.get("sleep_before")
    if sleep_s:
        total = min(int(sleep_s), _MAX_SLEEP_BEFORE)
        logger.info(f"  [{_sanitize_log(tc['id'])}] Waiting {total}s before sending ...")
        for remaining in range(total, 0, -1):
            print(f"\r  [{_sanitize_log(tc['id'])}] Sending in {remaining:3d}s ...   ", end="", flush=True)
            time.sleep(1)
        print(f"\r  [{_sanitize_log(tc['id'])}] Wait complete — sending now.              ", flush=True)

    body_str: Optional[str] = None
    if tc.get("raw_body") is not None:
        body_str = str(tc["raw_body"])
    elif tc["payload"] is not None:
        body_str = json.dumps(tc["payload"], separators=(",", ":"), sort_keys=False, ensure_ascii=False)

    req_url = tc["url"]
    req_headers_display = dict(headers)
    req_body_display = None
    if tc["payload"] is not None:
        req_body_display = json.dumps(tc["payload"], indent=2, ensure_ascii=False)
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
            resp = requests.get(req_url, headers=headers, timeout=timeout, verify=_SSL_VERIFY)
        elif body_str is not None:
            if tc.get("raw_content_type"):
                headers["Content-Type"] = tc["raw_content_type"]
            resp = requests.post(req_url, data=body_str.encode("utf-8"), headers=headers, timeout=timeout, verify=_SSL_VERIFY)
        else:
            resp = requests.post(req_url, headers=headers, timeout=timeout, verify=_SSL_VERIFY)

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
    expected_error_code = tc.get("expected_error_code")
    cat_entry = _ERROR_CATALOGUE.get(str(expected_error_code), {}) if expected_error_code else {}
    expected_error_type = cat_entry.get("type")

    if error_msg:
        passed = False
        status_note = f"ERROR - {error_msg}"
    elif tc.get("nack_ok") and _is_nack(resp_body):
        if expected_error_code and actual_error_code != expected_error_code:
            passed = False
            status_note = (
                f"HTTP {resp_status} - NACK received but error.code={actual_error_code!r} "
                f"(expected {expected_error_code!r})"
            )
        elif expected_error_type and actual_error_type and actual_error_type != expected_error_type:
            passed = False
            status_note = (
                f"HTTP {resp_status} - NACK received but error.type={actual_error_type!r} "
                f"(expected {expected_error_type!r} per catalogue)"
            )
        else:
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
            msg_note = f" ({nack_msg})" if nack_msg else ""
            status_note = (
                f"HTTP {resp_status} - NACK received for a valid request - "
                f"error.code={nack_code}{type_note}{msg_note}"
            )
        elif tc["category"] == "Negative" and resp_status == 200 and not _is_nack(resp_body):
            passed = False
            status_note = f"HTTP {resp_status} - received ACK (expected NACK or 4xx error response)"
        elif (
            tc["category"] == "Negative"
            and resp_status == 200
            and expected_error_code
            and actual_error_code != expected_error_code
        ):
            passed = False
            status_note = (
                f"HTTP {resp_status} - NACK received but error.code={actual_error_code!r} "
                f"(expected {expected_error_code!r})"
            )
        elif (
            tc["category"] == "Negative"
            and resp_status == 200
            and expected_error_type
            and actual_error_type
            and actual_error_type != expected_error_type
        ):
            passed = False
            status_note = (
                f"HTTP {resp_status} - NACK received but error.type={actual_error_type!r} "
                f"(expected {expected_error_type!r} per catalogue)"
            )
        else:
            passed = True
            code_note = f", error.code={actual_error_code}" if actual_error_code else ""
            type_note = f", error.type={actual_error_type}" if actual_error_type else ""
            status_note = f"HTTP {resp_status} - expected one of {tc['expected_status']}{code_note}{type_note}"
    else:
        passed = False
        if _is_nack(resp_body) and (actual_error_code or actual_error_type):
            code_note = f", error.code={actual_error_code}" if actual_error_code else ""
            type_note = f", error.type={actual_error_type}" if actual_error_type else ""
            nack_msg = ""
            try:
                nack_msg = json.loads(resp_body).get("error", {}).get("message", "")
            except Exception:
                pass
            msg_note = f" ({nack_msg})" if nack_msg else ""
            status_note = (
                f"HTTP {resp_status} - expected one of {tc['expected_status']}"
                f"{code_note}{type_note}{msg_note} [NACK received but wrong HTTP status]"
            )
        else:
            status_note = f"HTTP {resp_status} - expected one of {tc['expected_status']}"

    logger.info(
        f"  [{_sanitize_log(tc['id'])}] {'PASS' if passed else 'FAIL'}  "
        f"HTTP {resp_status}  {elapsed_ms}ms  {_sanitize_log(tc['name'])}"
    )

    return {
        "id": tc["id"],
        "name": tc["name"],
        "category": tc["category"],
        "description": tc["description"],
        "method": tc["method"],
        "req_url": req_url,
        "req_headers": req_headers_display,
        "req_body": req_body_display,
        "auth_note": auth_note,
        "resp_status": resp_status,
        "resp_headers": resp_headers,
        "resp_body": resp_body,
        "elapsed_ms": elapsed_ms,
        "expected_status": tc["expected_status"],
        "expected_error_code": expected_error_code,
        "expected_error_type": expected_error_type,
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
def _redact_sensitive(obj: Any) -> Any:
    sensitive_keys = {
        "authorization", "proxy-authorization", "cookie", "set-cookie",
        "signature", "x-signature",
        "token", "access_token", "refresh_token",
        "password", "passwd", "secret", "api_key", "private_key",
        "email", "phone", "mobile", "name",
        "address", "billing", "gps",
    }

    if isinstance(obj, dict):
        redacted = {}
        for k, v in obj.items():
            key_l = str(k).lower()
            if key_l in sensitive_keys:
                redacted[k] = "[REDACTED]"
            else:
                redacted[k] = _redact_sensitive(v)
        return redacted
    if isinstance(obj, list):
        return [_redact_sensitive(i) for i in obj]
    return obj


def _esc(text: str) -> str:
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


# ---------------------------------------------------------------------------
# HTML Report Generator  (dark theme)
# ---------------------------------------------------------------------------
def generate_html_report(results: List[Dict[str, Any]], output_path: str, run_ts: str) -> None:
    total = len(results)
    passed = sum(1 for r in results if r["passed"])
    failed = total - passed
    pass_pct = round((passed / total * 100) if total else 0, 1)
    avg_ms = round(sum(r["elapsed_ms"] for r in results) / total if total else 0, 0)
    avg_s = round(avg_ms / 1000, 3)

    suite_ids = []
    seen: set = set()
    for r in results:
        sid = r["category"].lower().replace(" ", "-")
        if sid not in seen:
            suite_ids.append((sid, r["category"]))
            seen.add(sid)

    cards_html = ""
    for idx, r in enumerate(results):
        status_cls = "pass" if r["passed"] else "fail"
        badge_cls = "badge-pass" if r["passed"] else "badge-fail"
        badge_txt = "PASS" if r["passed"] else "FAIL"
        suite_id = r["category"].lower().replace(" ", "-")

        sc = r["resp_status"]
        if sc is None:
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

        resp_body_str = r.get("resp_body") or ""
        req_hdrs_json = json.dumps(_redact_sensitive(r.get("req_headers", {})), indent=2, ensure_ascii=False)
        status_details = json.dumps({
            "execution_timestamp": r["timestamp"],
            "rsp_s": elapsed_s,
            "status_code": sc if sc is not None else "N/A",
            "expected_status": r["expected_status"],
            "result": badge_txt,
            "note": r["status_note"],
        }, indent=2, ensure_ascii=False)

        auth_note_html = ""
        if r.get("auth_note"):
            auth_note_html = f'<span class="auth-chip">{_esc(r["auth_note"])}</span>'

        cards_html += f"""
<div class="card {status_cls}" data-name="{_esc(r['id'].lower())} {_esc(r['name'].lower())}" data-suite="{_esc(suite_id)}">
  <div class="card-header" onclick="toggle({idx})">
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
        suite_btns += f'<button class="fbtn suite" data-suite="{_esc(sid)}" onclick="setSuite(this,\'{_esc(sid)}\')">{_esc(slabel)}</button>'

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>ONDC Gateway Support API Test Report</title>
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
.scard.total .val {{ color: #67e8f9; }}
.scard.passed .val {{ color: #22c55e; }}
.scard.failed .val {{ color: #ef4444; }}
.scard.rate .val {{ color: #38bdf8; }}
.scard.rsp .val {{ color: #34d399; }}
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
.fbtn:hover {{ background: #21262d; color: #e2e8f0; }}
.fbtn.active {{ background: #1e3a5f; border-color: #3b82f6; color: #93c5fd; }}
.cards {{ display: flex; flex-direction: column; gap: 10px; }}
.card {{ border-radius: 10px; border: 1px solid #21262d; overflow: hidden; }}
.card.pass {{ border-left: 4px solid #22c55e; }}
.card.fail {{ border-left: 4px solid #ef4444; }}
.card-header {{
    display: flex; flex-wrap: wrap; align-items: center; gap: 10px;
    padding: 14px 18px; cursor: pointer; background: #161b22;
    transition: background .15s;
}}
.card-header:hover {{ background: #1c2128; }}
.card-body {{ display: none; padding: 20px 22px; background: #0d1117; border-top: 1px solid #21262d; }}
.card-body.open {{ display: block; }}
.badge {{ padding: 3px 10px; border-radius: 999px; font-size: .72rem; font-weight: 800; }}
.badge-pass {{ background: #14532d; color: #86efac; }}
.badge-fail {{ background: #450a0a; color: #fca5a5; }}
.tc-name {{ font-size: .88rem; font-weight: 600; flex: 1; }}
.chip {{ padding: 2px 9px; border-radius: 6px; font-size: .72rem; font-weight: 700; background: #21262d; color: #8b949e; }}
.sc-2xx {{ background: #14532d; color: #86efac; }}
.sc-4xx {{ background: #451a03; color: #fdba74; }}
.sc-5xx {{ background: #450a0a; color: #fca5a5; }}
.sc-none {{ background: #1c2128; color: #6b7280; }}
.chip-time {{ color: #34d399; background: #052e16; }}
.chip-ts {{ color: #64748b; }}
.auth-chip {{ padding: 2px 9px; border-radius: 6px; font-size: .7rem; background: #1e3a5f; color: #93c5fd; }}
.suite-chip {{ padding: 2px 9px; border-radius: 6px; font-size: .7rem; background: #2d1b69; color: #a78bfa; }}
.chevron {{ margin-left: auto; font-size: .8rem; color: #4b5563; transition: transform .2s; }}
.chevron.open {{ transform: rotate(90deg); }}
.section-title {{ font-size: .75rem; font-weight: 800; text-transform: uppercase; letter-spacing: 1px; padding: 6px 0 10px; margin-top: 14px; }}
.req-title {{ color: #38bdf8; border-bottom: 1px solid #1e3a5f; }}
.res-title {{ color: #34d399; border-bottom: 1px solid #052e16; }}
.two-col {{ display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin: 14px 0; }}
.col-label {{ font-size: .7rem; text-transform: uppercase; color: #4b5563; margin-bottom: 6px; }}
.json-block {{
    background: #161b22; border: 1px solid #21262d; border-radius: 8px;
    padding: 12px 14px; font-size: .75rem; font-family: 'Cascadia Code', 'Fira Code', monospace;
    color: #a5f3fc; white-space: pre-wrap; word-break: break-all; max-height: 340px; overflow-y: auto;
}}
.meta-row {{ display: flex; flex-wrap: wrap; gap: 20px; font-size: .8rem; color: #94a3b8; margin: 8px 0; }}
.meta-row strong {{ color: #e2e8f0; }}
@media (max-width: 700px) {{ .two-col {{ grid-template-columns: 1fr; }} }}
</style>
</head>
<body>
<div class="page">
  <div class="hero">
    <h1>ONDC Gateway <span>Support API</span> Test Report</h1>
    <p>Endpoints: <strong>/support</strong> and <strong>/on_support</strong> &nbsp;|&nbsp;
       Run: <strong>{_esc(run_ts)}</strong> &nbsp;|&nbsp;
       Host: <strong>{_esc(func_cfg_host if "func_cfg_host" in dir() else "UAT")}</strong></p>
  </div>
  <div class="summary">
    <div class="scard total"><div class="val">{total}</div><div class="lbl">Total</div></div>
    <div class="scard passed"><div class="val">{passed}</div><div class="lbl">Passed</div></div>
    <div class="scard failed"><div class="val">{failed}</div><div class="lbl">Failed</div></div>
    <div class="scard rate"><div class="val">{pass_pct}%</div><div class="lbl">Pass Rate</div></div>
    <div class="scard rsp"><div class="val">{avg_s}s</div><div class="lbl">Avg Response</div></div>
  </div>
  <div class="controls">
    <input class="search" id="search" type="text" placeholder="Search test cases..." oninput="filterCards()"/>
    <button class="fbtn active" id="btn-all" onclick="setFilter(this,'all')">All</button>
    <button class="fbtn" id="btn-pass" onclick="setFilter(this,'pass')">PASS</button>
    <button class="fbtn" id="btn-fail" onclick="setFilter(this,'fail')">FAIL</button>
    {suite_btns}
  </div>
  <div class="cards" id="cards">{cards_html}</div>
</div>
<script>
var _filter='all', _suite='all', _search='';
function toggle(i){{
  var b=document.getElementById('body-'+i);
  var c=document.getElementById('chev-'+i);
  var open=b.classList.toggle('open');
  if(open) c.classList.add('open'); else c.classList.remove('open');
}}
function setFilter(btn,f){{
  _filter=f;
  document.querySelectorAll('.fbtn:not(.suite)').forEach(function(b){{b.classList.remove('active');}});
  btn.classList.add('active');
  applyFilters();
}}
function setSuite(btn,s){{
  _suite=_suite===s?'all':s;
  document.querySelectorAll('.fbtn.suite').forEach(function(b){{b.classList.remove('active');}});
  if(_suite!=='all') btn.classList.add('active');
  applyFilters();
}}
function filterCards(){{
  _search=document.getElementById('search').value.toLowerCase();
  applyFilters();
}}
function applyFilters(){{
  document.querySelectorAll('.card').forEach(function(c){{
    var matchF=_filter==='all'||((_filter==='pass')===c.classList.contains('pass'));
    var matchS=_suite==='all'||c.dataset.suite===_suite;
    var matchQ=!_search||c.dataset.name.includes(_search);
    c.style.display=(matchF&&matchS&&matchQ)?'':'none';
  }});
}}
</script>
</body>
</html>"""

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(html)
    logger.info(f"Report saved → {output_path}")


# ---------------------------------------------------------------------------
# Participant registration (embedded — reads creds from cfg dict)
# ---------------------------------------------------------------------------
_REG_ADMIN_URL = os.environ.get("REG_ADMIN_AUTH_URL", "")
_REG_ADMIN_USER = os.environ.get("REG_ADMIN_EMAIL", "")
_REG_ADMIN_PASS = os.environ.get("REG_ADMIN_PASSWORD", "")


def _reg_get_admin_token() -> Optional[str]:
    url = f"{_REG_ADMIN_URL}/auth/login"
    try:
        resp = requests.post(
            url,
            json={"email": _REG_ADMIN_USER, "password": _REG_ADMIN_PASS},
            timeout=15,
            verify=_SSL_VERIFY,
        )
        if resp.status_code == 200:
            return resp.json().get("token") or resp.json().get("access_token")
        logger.warning(f"[register] Admin login returned HTTP {resp.status_code}")
    except Exception as exc:
        logger.warning(f"[register] Admin login failed: {_sanitize_log(exc)}")
    return None


def _reg_derive_signing_pub(private_key_seed_b64: str) -> Optional[str]:
    if not _HAS_CRYPTO:
        return None
    seed = _decode_private_key(private_key_seed_b64)
    if not seed:
        return None
    try:
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        priv = Ed25519PrivateKey.from_private_bytes(seed)
        pub_bytes = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return base64.b64encode(pub_bytes).decode()
    except Exception as exc:
        logger.warning(f"[register] Could not derive public key: {_sanitize_log(exc)}")
        return None


def _reg_build_payload(cfg: dict, signing_pub: str) -> dict:
    domains = cfg.get("domains", ["ONDC:RET10"])
    cities = cfg.get("cities", ["std:080"])
    return {
        "participant_id": cfg.get("participant_id", ""),
        "uk_id": cfg.get("uk_id", ""),
        "subscriber_id": cfg.get("subscriber_id", cfg.get("participant_id", "")),
        "subscriber_url": cfg.get("bap_uri", ""),
        "type": "BAP",
        "domains": domains,
        "cities": cities,
        "signing_public_key": signing_pub,
        "encryption_public_key": signing_pub,
        "status": "SUBSCRIBED",
    }


def _reg_already_registered(token: str, participant_id: str) -> bool:
    url = f"{_REG_ADMIN_URL}/registry/participants/{participant_id}"
    try:
        resp = requests.get(
            url,
            headers={"Authorization": f"Bearer {token}"},
            timeout=10,
            verify=_SSL_VERIFY,
        )
        return resp.status_code == 200
    except Exception:
        return False


def register_bap_participant(cfg: dict) -> None:
    """Register the BAP participant using credentials from the loaded YAML config."""
    participant_id = cfg.get("participant_id", "")
    if not participant_id:
        logger.warning("[register] participant_id not found in config — skipping registration.")
        return

    logger.info(f"[register] Attempting to register BAP participant: {_sanitize_log(participant_id)}")

    token = _reg_get_admin_token()
    if not token:
        logger.warning("[register] Could not obtain admin token — skipping registration (tests will still run).")
        return

    if _reg_already_registered(token, participant_id):
        logger.info(f"[register] Participant '{participant_id}' already registered — skipping.")
        return

    signing_pub = _reg_derive_signing_pub(str(cfg.get("private_key_seed", "")))
    if not signing_pub:
        logger.warning("[register] Could not derive signing public key — skipping registration.")
        return

    payload = _reg_build_payload(cfg, signing_pub)
    url = f"{_REG_ADMIN_URL}/registry/participants"
    try:
        resp = requests.post(
            url,
            json=payload,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            timeout=15,
            verify=_SSL_VERIFY,
        )
        if resp.status_code in (200, 201):
            logger.info(f"[register] Participant '{participant_id}' registered successfully.")
        else:
            logger.warning(
                f"[register] Registration returned HTTP {resp.status_code}: {resp.text[:200]} "
                "— continuing with tests."
            )
    except Exception as exc:
        logger.warning(f"[register] Registration request failed: {_sanitize_log(exc)} — continuing with tests.")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(
        description="ONDC Gateway Support API automated test runner — /support and /on_support endpoints."
    )
    parser.add_argument(
        "--func-config",
        default="resources/gateway/ondc_gateway_support_functional.yml",
        help="Path to functional test YAML config (default: resources/gateway/ondc_gateway_support_functional.yml)",
    )
    parser.add_argument(
        "--neg-config",
        default="resources/gateway/ondc_gateway_support_negative.yml",
        help="Path to negative test YAML config (default: resources/gateway/ondc_gateway_support_negative.yml)",
    )
    parser.add_argument(
        "--func-tenant", default="ondcGatewaySearch",
        help="YAML tenant key for functional config (default: ondcGatewaySearch)",
    )
    parser.add_argument(
        "--neg-tenant", default="ondcGatewaySearch",
        help="YAML tenant key for negative config (default: ondcGatewaySearch)",
    )
    parser.add_argument(
        "--suite", choices=["all", "functional", "negative"], default="all",
        help="Which test suite to run (default: all)",
    )
    parser.add_argument(
        "--filter", default=None,
        help="Run only test cases whose ID starts with this prefix (e.g. F-TC001, N-TC)",
    )
    parser.add_argument(
        "--output", default=None,
        help="Path for the HTML report (default: reports/Gateway-support-<timestamp>.html)",
    )
    parser.add_argument(
        "--timeout", type=int, default=10,
        help="HTTP request timeout in seconds (default: 10)",
    )
    parser.add_argument(
        "--skip-register", action="store_true",
        help="Skip BAP participant registration step",
    )
    args = parser.parse_args()

    run_ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    ts_file = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H-%M-%S")

    if args.output:
        report_path = (
            args.output if os.path.isabs(args.output)
            else os.path.join(PROJECT_ROOT, args.output)
        )
    else:
        report_path = os.path.join(
            PROJECT_ROOT, "reports",
            f"Gateway-support-{args.suite}-{ts_file}.html",
        )

    func_cfg = load_yaml_config(args.func_config, args.func_tenant)
    neg_cfg = load_yaml_config(args.neg_config, args.neg_tenant)

    if not func_cfg:
        logger.error(f"Functional config empty or missing: {_sanitize_log(args.func_config)}")
        sys.exit(1)
    if not neg_cfg:
        logger.warning(f"Negative config empty or missing: {_sanitize_log(args.neg_config)} — using functional config as fallback.")
        neg_cfg = func_cfg

    validate_config(func_cfg, args.func_config, "Functional")
    validate_config(neg_cfg, args.neg_config, "Negative")

    if not args.skip_register:
        register_bap_participant(func_cfg)
    else:
        logger.info("[register] Skipping participant registration (--skip-register).")

    func_auth = build_auth_helper(func_cfg, "functional")
    neg_auth = build_auth_helper(neg_cfg, "negative")

    filter_id = args.filter

    # Apply suite filter prefix
    if args.suite == "functional":
        filter_id = filter_id or "F-"
        if not filter_id.startswith("F-"):
            filter_id = "F-"
    elif args.suite == "negative":
        filter_id = filter_id or "N-"
        if not filter_id.startswith("N-"):
            filter_id = "N-"

    all_cases = build_test_cases(func_cfg, neg_cfg, func_auth, neg_auth, filter_id=filter_id)

    logger.info(f"\n{'='*60}")
    logger.info(f"  ONDC Gateway Support API Test Suite")
    logger.info(f"  Endpoint: /support  and  /on_support")
    logger.info(f"  Test cases: {len(all_cases)}")
    logger.info(f"  Host (func): {_sanitize_log(func_cfg.get('host', 'N/A'))}")
    logger.info(f"  Timeout: {args.timeout}s")
    logger.info(f"{'='*60}\n")

    results = []
    for tc in all_cases:
        result = run_test_case(tc, func_auth, neg_auth, timeout=args.timeout)
        results.append(result)

    passed = sum(1 for r in results if r["passed"])
    total = len(results)
    logger.info(f"\n{'='*60}")
    logger.info(f"  Results: {passed}/{total} PASSED ({round(passed/total*100 if total else 0, 1)}%)")
    logger.info(f"{'='*60}\n")

    generate_html_report(results, report_path, run_ts)
    print(f"\n  Report: {report_path}\n")


if __name__ == "__main__":
    main()
