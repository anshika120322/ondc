#!/usr/bin/env python3
"""
ONDC Gateway Init API - Automated Test Runner with HTML Report Generator

Runs all functional and negative test cases for the ONDC /init and /on_init
endpoints and generates a comprehensive dark-theme HTML report.

Usage:
    python func_test_scripts/gateway/ondc_gw_init_api_tests.py
    python func_test_scripts/gateway/ondc_gw_init_api_tests.py --suite functional
    python func_test_scripts/gateway/ondc_gw_init_api_tests.py --suite negative
    python func_test_scripts/gateway/ondc_gw_init_api_tests.py --filter F-TC001
    python func_test_scripts/gateway/ondc_gw_init_api_tests.py --timeout 30
    python func_test_scripts/gateway/ondc_gw_init_api_tests.py --output reports/my_report.html
    python func_test_scripts/gateway/ondc_gw_init_api_tests.py --func-config resources/gateway/ondc_gateway_init_functional.yml
    python func_test_scripts/gateway/ondc_gw_init_api_tests.py --neg-config  resources/gateway/ondc_gateway_init_negative.yml
    python func_test_scripts/gateway/ondc_gw_init_api_tests.py --skip-register
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
# Init Payload Generator  (/init — forward flow)
# ---------------------------------------------------------------------------
class InitPayloadGenerator:
    def __init__(self, cfg: dict):
        self.domains = cfg.get("domains", [])
        self.cities = cfg.get("cities", [])
        self.core_version = str(cfg.get("core_version", "1.2.0"))
        self.bap_id = str(cfg.get("bap_id", ""))
        self.bap_uri = str(cfg.get("bap_uri", ""))
        self.bpp_id = str(cfg.get("bpp_id", ""))
        self.bpp_uri = str(cfg.get("bpp_uri", ""))
        self.country = str(cfg.get("country", "IND"))
        self.currency = str(cfg.get("currency", "INR"))
        self.request_ttl = str(cfg.get("request_ttl", "PT30S"))

        primary_domain = self.domains[0] if self.domains else ""

        # test_providers
        raw_providers = cfg.get("test_providers", [])
        if isinstance(raw_providers, dict):
            self.test_providers = raw_providers.get(primary_domain, next(iter(raw_providers.values()), []))
        else:
            self.test_providers = raw_providers or []

        # test_items
        raw_test_data = cfg.get("test_data", {})
        if isinstance(raw_test_data, dict) and raw_test_data:
            domain_data = raw_test_data.get(primary_domain, next(iter(raw_test_data.values()), {}))
            raw_items = domain_data.get("test_items", []) if isinstance(domain_data, dict) else []
        else:
            raw_items = cfg.get("test_items", [])
        self.test_items = raw_items or []

        # payment_types
        raw_payment_types = cfg.get("payment_types", [])
        if isinstance(raw_payment_types, dict):
            self.payment_types = raw_payment_types.get(primary_domain, next(iter(raw_payment_types.values()), []))
        else:
            self.payment_types = raw_payment_types or []

        # fulfillment_types
        raw_ft = cfg.get("fulfillment_types", [])
        if isinstance(raw_ft, dict):
            raw_ft = raw_ft.get(primary_domain, next(iter(raw_ft.values()), []))
        self.fulfillment_types = raw_ft or []

        self.test_locations = cfg.get("test_locations", [])
        self.settlement_details = cfg.get("settlement_details", [])

    def _build_billing(self) -> dict:
        return {
            "name": "Test Buyer",
            "address": {
                "door": "B-101",
                "name": "Test Apartments",
                "locality": "MG Road",
                "city": "Bangalore",
                "state": "Karnataka",
                "country": "IND",
                "area_code": "560001",
            },
            "email": "buyer@test.ondc",
            "phone": "+91-9876543210",
            "created_at": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "updated_at": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        }

    def _build_fulfillment(self, ftype: str = None) -> dict:
        _def_loc = self.test_locations[0] if self.test_locations else {}
        ft = ftype or (self.fulfillment_types[0] if self.fulfillment_types else "Delivery")
        if isinstance(ft, dict):
            ft = ft.get("type", "Delivery")
        return {
            "id": "F1",
            "type": ft,
            "end": {
                "location": {
                    "gps": _def_loc.get("gps", "12.9492953,77.7019878"),
                    "address": {
                        "door": "B-101",
                        "name": "Test Apartments",
                        "locality": "MG Road",
                        "city": "Bangalore",
                        "state": "Karnataka",
                        "country": "IND",
                        "area_code": _def_loc.get("area_code", "560001"),
                    },
                },
                "contact": {
                    "phone": "+91-9876543210",
                    "email": "buyer@test.ondc",
                },
            },
        }

    def _build_payment(self, payment_type: dict = None) -> dict:
        pt = payment_type or (self.payment_types[0] if self.payment_types else {})
        settlement = self.settlement_details[0] if self.settlement_details else {}
        pay: dict = {
            "type": pt.get("type", "PRE-ORDER") if isinstance(pt, dict) else str(pt),
            "status": pt.get("status", "NOT-PAID") if isinstance(pt, dict) else "NOT-PAID",
            "collected_by": pt.get("collected_by", "BAP") if isinstance(pt, dict) else "BAP",
        }
        if settlement:
            pay["@ondc/org/settlement_details"] = [settlement]
        return pay

    def build(
        self,
        domain: str = None,
        city: str = None,
        transaction_id: str = None,
        message_id: str = None,
        provider_id: str = None,
        items: list = None,
        fulfillment_type: str = None,
        payment_type: dict = None,
        quantity: int = 1,
    ) -> dict:
        txn_id = transaction_id or f"txn-{uuid.uuid4().hex[:12]}"
        msg_id = message_id or f"msg-{uuid.uuid4().hex[:12]}"
        now = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")

        sel_domain = domain or (self.domains[0] if self.domains else "")
        sel_city = city or (self.cities[0] if self.cities else "")

        ctx: dict = {
            "domain": sel_domain,
            "action": "init",
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

        prov = self.test_providers[0] if self.test_providers else {}
        prov_id = provider_id or prov.get("id", "IGO_Seller_0001")

        if items is not None:
            order_items = items
        else:
            item = self.test_items[0] if self.test_items else {}
            order_items = [{
                "id": item.get("id", "item-001"),
                "quantity": {"count": quantity},
                "fulfillment_id": item.get("fulfillment_id", "F1"),
            }]

        billing = self._build_billing()
        fulfillment = self._build_fulfillment(fulfillment_type)
        payment = self._build_payment(payment_type)

        order: dict = {
            "provider": {"id": prov_id, "locations": [{"id": prov.get("location_id", "store-location-001")}]},
            "items": order_items,
            "billing": billing,
            "fulfillments": [fulfillment],
            "payment": payment,
        }

        return {"context": ctx, "message": {"order": order}}


# ---------------------------------------------------------------------------
# OnInit Payload Generator  (/on_init — backward callback from BPP)
# ---------------------------------------------------------------------------
class OnInitPayloadGenerator:
    def __init__(self, cfg: dict):
        self.domains = cfg.get("domains", [])
        self.cities = cfg.get("cities", [])
        self.core_version = str(cfg.get("core_version", "1.2.0"))
        self.bap_id = str(cfg.get("bap_id", ""))
        self.bap_uri = str(cfg.get("bap_uri", ""))
        self.bpp_id = str(cfg.get("bpp_id", ""))
        self.bpp_uri = str(cfg.get("bpp_uri", ""))
        self.country = str(cfg.get("country", "IND"))
        self.currency = str(cfg.get("currency", "INR"))
        self.request_ttl = str(cfg.get("request_ttl", "PT30S"))

        primary_domain = self.domains[0] if self.domains else ""

        raw_providers = cfg.get("test_providers", [])
        if isinstance(raw_providers, dict):
            self.test_providers = raw_providers.get(primary_domain, next(iter(raw_providers.values()), []))
        else:
            self.test_providers = raw_providers or []

        raw_test_data = cfg.get("test_data", {})
        if isinstance(raw_test_data, dict) and raw_test_data:
            domain_data = raw_test_data.get(primary_domain, next(iter(raw_test_data.values()), {}))
            raw_items = domain_data.get("test_items", []) if isinstance(domain_data, dict) else []
        else:
            raw_items = cfg.get("test_items", [])
        self.test_items = raw_items or []

        raw_payment_types = cfg.get("payment_types", [])
        if isinstance(raw_payment_types, dict):
            self.payment_types = raw_payment_types.get(primary_domain, next(iter(raw_payment_types.values()), []))
        else:
            self.payment_types = raw_payment_types or []

        raw_ft = cfg.get("fulfillment_types", [])
        if isinstance(raw_ft, dict):
            raw_ft = raw_ft.get(primary_domain, next(iter(raw_ft.values()), []))
        self.fulfillment_types = raw_ft or []

        self.test_locations = cfg.get("test_locations", [])
        self.settlement_details = cfg.get("settlement_details", [])

    def build(
        self,
        domain: str = None,
        city: str = None,
        transaction_id: str = None,
        message_id: str = None,
        omit_order: bool = False,
        omit_bpp_id: bool = False,
        omit_bap_id: bool = False,
        omit_domain: bool = False,
        include_error: dict = None,
        empty_items: bool = False,
        item_count: int = 1,
    ) -> dict:
        txn_id = transaction_id or f"txn-{uuid.uuid4().hex[:12]}"
        msg_id = message_id or f"msg-{uuid.uuid4().hex[:12]}"
        now = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")

        sel_domain = domain or (self.domains[0] if self.domains else "")
        sel_city = city or (self.cities[0] if self.cities else "")

        ctx: dict = {
            "domain": sel_domain,
            "action": "on_init",
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

        if omit_order:
            payload: dict = {"context": ctx, "message": {}}
            if include_error:
                payload["error"] = include_error
            return payload

        prov = self.test_providers[0] if self.test_providers else {}
        item = self.test_items[0] if self.test_items else {}
        _item_price = item.get("price", "450.00")

        if empty_items:
            order_items = []
        else:
            order_items = [
                {
                    "id": item.get("id", "item-001") if i == 0 else f"item-{i+1:03d}",
                    "quantity": {"count": 1},
                    "fulfillment_id": item.get("fulfillment_id", "F1"),
                }
                for i in range(item_count)
            ]

        _def_loc = self.test_locations[0] if self.test_locations else {}
        ft = self.fulfillment_types[0] if self.fulfillment_types else "Delivery"
        if isinstance(ft, dict):
            ft = ft.get("type", "Delivery")

        pt = self.payment_types[0] if self.payment_types else {}
        settlement = self.settlement_details[0] if self.settlement_details else {}

        # Build quote with breakup
        item_total = float(_item_price) * item_count
        delivery_charge = 50.0
        total = item_total + delivery_charge
        quote = {
            "price": {"currency": self.currency, "value": f"{total:.2f}"},
            "breakup": [
                {
                    "@ondc/org/item_id": item.get("id", "item-001"),
                    "@ondc/org/title_type": "item",
                    "title": item.get("name", "Test Item"),
                    "price": {"currency": self.currency, "value": f"{item_total:.2f}"},
                    "item": {"quantity": {"count": item_count}},
                },
                {
                    "@ondc/org/item_id": "F1",
                    "@ondc/org/title_type": "delivery",
                    "title": "Delivery charges",
                    "price": {"currency": self.currency, "value": f"{delivery_charge:.2f}"},
                },
            ],
        }

        payment = {
            "type": pt.get("type", "PRE-ORDER") if isinstance(pt, dict) else str(pt),
            "status": pt.get("status", "NOT-PAID") if isinstance(pt, dict) else "NOT-PAID",
            "collected_by": pt.get("collected_by", "BAP") if isinstance(pt, dict) else "BAP",
        }
        if settlement:
            payment["@ondc/org/settlement_details"] = [settlement]

        order = {
            "provider": {"id": prov.get("id", "IGO_Seller_0001")},
            "items": order_items,
            "billing": {
                "name": "Test Buyer",
                "address": {
                    "door": "B-101", "name": "Test Apartments", "locality": "MG Road",
                    "city": "Bangalore", "state": "Karnataka", "country": "IND", "area_code": "560001",
                },
                "email": "buyer@test.ondc",
                "phone": "+91-9876543210",
            },
            "fulfillments": [{
                "id": "F1",
                "type": ft,
                "end": {
                    "location": {
                        "gps": _def_loc.get("gps", "12.9492953,77.7019878"),
                        "address": {
                            "door": "B-101", "name": "Test Apartments", "locality": "MG Road",
                            "city": "Bangalore", "state": "Karnataka", "country": "IND",
                            "area_code": _def_loc.get("area_code", "560001"),
                        },
                    },
                    "contact": {"phone": "+91-9876543210"},
                },
            }],
            "quote": quote,
            "payment": payment,
        }

        payload = {"context": ctx, "message": {"order": order}}
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

    ipg = InitPayloadGenerator(func_cfg)
    oipg = OnInitPayloadGenerator(func_cfg)
    nipg = InitPayloadGenerator(neg_cfg)
    noipg = OnInitPayloadGenerator(neg_cfg)

    cases: List[Dict[str, Any]] = []

    # =========================================================================
    # FUNCTIONAL TEST CASES  (/init forward + /on_init backward)
    # =========================================================================

    # F-TC001 — Valid authenticated /init request
    cases.append({
        "id": "F-TC001",
        "name": "Init Valid Authenticated Request",
        "category": "Functional",
        "description": "[PASS EXPECTED] Sends a complete, correctly signed /init request with order, billing, fulfillment and payment. Validates baseline happy-path init request routing to the BPP.",
        "method": "POST",
        "url": f"{func_host}/init",
        "payload": ipg.build(),
        "raw_body": None, "raw_content_type": None,
        "expected_status": [200, 202],
        "auth_mode": "valid", "custom_headers": None, "ttl": None, "sleep_before": None,
    })

    # F-TC002 — Different ONDC domains
    for domain in ipg.domains:
        cases.append({
            "id": f"F-TC002-{domain}",
            "name": f"Init Different Domain: {domain}",
            "category": "Functional",
            "description": f"[PASS EXPECTED] Sends /init with context.domain='{domain}'. Verifies the Gateway routes init requests for different ONDC verticals.",
            "method": "POST",
            "url": f"{func_host}/init",
            "payload": ipg.build(domain=domain),
            "raw_body": None, "raw_content_type": None,
            "expected_status": [200, 202],
            "auth_mode": "valid", "custom_headers": None, "ttl": None, "sleep_before": None,
        })

    # F-TC003 — Different cities
    for city in ipg.cities:
        cases.append({
            "id": f"F-TC003-{city}",
            "name": f"Init Different City: {city}",
            "category": "Functional",
            "description": f"[PASS EXPECTED] Sends /init with context.city='{city}'. Validates Gateway accepts init requests targeting different delivery cities.",
            "method": "POST",
            "url": f"{func_host}/init",
            "payload": ipg.build(city=city),
            "raw_body": None, "raw_content_type": None,
            "expected_status": [200, 202],
            "auth_mode": "valid", "custom_headers": None, "ttl": None, "sleep_before": None,
        })

    # F-TC004 — Different fulfillment types
    for ft_cfg in ipg.fulfillment_types:
        if isinstance(ft_cfg, dict):
            ftype = ft_cfg.get("type", "Delivery")
        else:
            ftype = str(ft_cfg)
        cases.append({
            "id": f"F-TC004-{ftype}",
            "name": f"Init Fulfillment Type: {ftype}",
            "category": "Functional",
            "description": f"[PASS EXPECTED] Sends /init with fulfillment.type='{ftype}'. Validates Gateway routes init for all fulfillment modes: Delivery, Pickup, Self-Pickup.",
            "method": "POST",
            "url": f"{func_host}/init",
            "payload": ipg.build(fulfillment_type=ftype),
            "raw_body": None, "raw_content_type": None,
            "expected_status": [200, 202],
            "auth_mode": "valid", "custom_headers": None, "ttl": None, "sleep_before": None,
        })

    # F-TC005 — Different payment types
    for pt in ipg.payment_types:
        pt_label = pt.get("type", "UNKNOWN") if isinstance(pt, dict) else str(pt)
        cases.append({
            "id": f"F-TC005-{pt_label}",
            "name": f"Init Payment Type: {pt_label}",
            "category": "Functional",
            "description": f"[PASS EXPECTED] Sends /init with payment.type='{pt_label}'. Validates Gateway accepts init with different payment modes (PRE-ORDER, ON-FULFILLMENT, POST-FULFILLMENT).",
            "method": "POST",
            "url": f"{func_host}/init",
            "payload": ipg.build(payment_type=pt),
            "raw_body": None, "raw_content_type": None,
            "expected_status": [200, 202],
            "auth_mode": "valid", "custom_headers": None, "ttl": None, "sleep_before": None,
        })

    # F-TC006 — Init with multiple items
    _multi_items = [
        {"id": it.get("id", f"item-{i+1:03d}"), "quantity": {"count": 1}, "fulfillment_id": it.get("fulfillment_id", "F1")}
        for i, it in enumerate(ipg.test_items[:3])
    ] if len(ipg.test_items) >= 2 else [
        {"id": "item-001", "quantity": {"count": 1}, "fulfillment_id": "F1"},
        {"id": "item-002", "quantity": {"count": 1}, "fulfillment_id": "F1"},
    ]
    cases.append({
        "id": "F-TC006",
        "name": "Init With Multiple Items",
        "category": "Functional",
        "description": "[PASS EXPECTED] Sends /init with multiple items in the order. Validates Gateway accepts and routes multi-item init requests without truncating the items list.",
        "method": "POST",
        "url": f"{func_host}/init",
        "payload": ipg.build(items=_multi_items),
        "raw_body": None, "raw_content_type": None,
        "expected_status": [200, 202],
        "auth_mode": "valid", "custom_headers": None, "ttl": None, "sleep_before": None,
    })

    # F-TC007 — Init with quantity > 1
    cases.append({
        "id": "F-TC007",
        "name": "Init With Quantity > 1",
        "category": "Functional",
        "description": "[PASS EXPECTED] Sends /init with item quantity count=3. Validates Gateway correctly handles multi-quantity init orders.",
        "method": "POST",
        "url": f"{func_host}/init",
        "payload": ipg.build(quantity=3),
        "raw_body": None, "raw_content_type": None,
        "expected_status": [200, 202],
        "auth_mode": "valid", "custom_headers": None, "ttl": None, "sleep_before": None,
    })

    # F-TC008 — Same txn_id, different msg_id (3 requests)
    _shared_txn = f"txn-{uuid.uuid4().hex[:12]}"
    for req_num in range(1, 4):
        cases.append({
            "id": f"F-TC008-Req{req_num}",
            "name": f"Init Same TxnID / Different MsgID - Req {req_num}",
            "category": "Functional",
            "description": f"[PASS EXPECTED] Sends /init request #{req_num} reusing the same transaction_id but a fresh message_id. Validates Gateway handles retry/polling scenarios for init.",
            "method": "POST",
            "url": f"{func_host}/init",
            "payload": ipg.build(transaction_id=_shared_txn),
            "raw_body": None, "raw_content_type": None,
            "expected_status": [200, 202],
            "auth_mode": "valid", "custom_headers": None, "ttl": None, "sleep_before": None,
        })

    # F-TC009 — Unicode item names
    _unicode_items = [
        ("Hindi", "बासमती चावल"),
        ("Arabic", "أرز بسمتي"),
        ("Chinese", "香米"),
    ]
    for lang, term in _unicode_items:
        _u_payload = ipg.build()
        _u_payload["message"]["order"]["items"][0]["descriptor"] = {"name": term}
        cases.append({
            "id": f"F-TC009-{lang}",
            "name": f"Init Unicode Item Name ({lang})",
            "category": "Functional",
            "description": f"[PASS EXPECTED] Sends /init with a non-ASCII item descriptor name in {lang} script ('{term}'). Validates the Gateway correctly handles Unicode in init payloads.",
            "method": "POST",
            "url": f"{func_host}/init",
            "payload": _u_payload,
            "raw_body": None, "raw_content_type": None,
            "expected_status": [200, 202],
            "auth_mode": "valid", "custom_headers": None, "ttl": None, "sleep_before": None,
        })

    # F-TC010 — Large payload (many items)
    _large_items = [
        {"id": f"item-{i:03d}", "quantity": {"count": 1}, "fulfillment_id": "F1"}
        for i in range(1, 26)
    ]
    cases.append({
        "id": "F-TC010",
        "name": "Init Large Payload (25 Items)",
        "category": "Functional",
        "description": "[PASS EXPECTED] Sends /init with 25 items in the order. Edge-case for payload size — validates Gateway does not truncate or reject large-but-valid init requests.",
        "method": "POST",
        "url": f"{func_host}/init",
        "payload": ipg.build(items=_large_items),
        "raw_body": None, "raw_content_type": None,
        "expected_status": [200, 202],
        "auth_mode": "valid", "custom_headers": None, "ttl": None, "sleep_before": None,
    })

    # F-TC011 — Gateway health check
    cases.append({
        "id": "F-TC011",
        "name": "Gateway Health Check (GET /)",
        "category": "Functional",
        "description": "[PASS EXPECTED] Sends GET / to verify the Gateway service is running and reachable. No authentication required. Used as a smoke test before running the full suite.",
        "method": "GET",
        "url": f"{func_host}/",
        "payload": None,
        "raw_body": None, "raw_content_type": None,
        "expected_status": [200, 202, 404],
        "auth_mode": "no_auth", "custom_headers": None, "ttl": None, "sleep_before": None,
    })

    # ----- on_init functional tests (F-TC012 – F-TC018) ---------------------

    # F-TC012 — Valid /on_init callback with quote
    cases.append({
        "id": "F-TC012",
        "name": "on_init Valid Callback With Quote",
        "category": "Functional",
        "description": "[PASS EXPECTED] BPP sends /on_init with a complete order including quote breakup. Validates Gateway correctly accepts and forwards the backward callback to the BAP.",
        "method": "POST",
        "url": f"{func_host}/on_init",
        "payload": oipg.build(),
        "raw_body": None, "raw_content_type": None,
        "expected_status": [200, 202],
        "auth_mode": "valid", "custom_headers": None, "ttl": None, "sleep_before": None,
    })

    # F-TC013 — on_init empty items
    cases.append({
        "id": "F-TC013",
        "name": "on_init Empty Items List",
        "category": "Functional",
        "description": "[PASS EXPECTED] BPP sends /on_init with an empty items list — edge case where order items are stripped. Validates Gateway forwards the callback without treating it as an error.",
        "method": "POST",
        "url": f"{func_host}/on_init",
        "payload": oipg.build(empty_items=True),
        "raw_body": None, "raw_content_type": None,
        "expected_status": [200, 202],
        "auth_mode": "valid", "custom_headers": None, "ttl": None, "sleep_before": None,
    })

    # F-TC014 — on_init with error block
    cases.append({
        "id": "F-TC014",
        "name": "on_init With Error Block (BPP Processing Failure)",
        "category": "Functional",
        "description": "[PASS EXPECTED] BPP sends /on_init with an error block — indicates the BPP could not process the init request. Validates Gateway accepts and routes error-carrying on_init responses.",
        "method": "POST",
        "url": f"{func_host}/on_init",
        "payload": oipg.build(omit_order=True, include_error={"code": "30000", "message": "Provider not available"}),
        "raw_body": None, "raw_content_type": None,
        "expected_status": [200, 202],
        "auth_mode": "valid", "custom_headers": None, "ttl": None, "sleep_before": None,
    })

    # F-TC015 — on_init multiple providers
    _multi_prov_payload = oipg.build()
    _provs = oipg.test_providers
    if len(_provs) > 1:
        _multi_prov_payload["message"]["order"]["provider"]["id"] = _provs[1].get("id", "IGO_Seller_0002")
    cases.append({
        "id": "F-TC015",
        "name": "on_init Alternate Provider",
        "category": "Functional",
        "description": "[PASS EXPECTED] BPP sends /on_init with a different provider ID. Validates Gateway handles on_init callbacks from different seller providers.",
        "method": "POST",
        "url": f"{func_host}/on_init",
        "payload": _multi_prov_payload,
        "raw_body": None, "raw_content_type": None,
        "expected_status": [200, 202],
        "auth_mode": "valid", "custom_headers": None, "ttl": None, "sleep_before": None,
    })

    # F-TC016 — on_init with detailed quote breakup
    _detailed_quote_payload = oipg.build()
    _detailed_quote_payload["message"]["order"]["quote"]["breakup"].extend([
        {
            "@ondc/org/item_id": "F1",
            "@ondc/org/title_type": "packing",
            "title": "Packing charges",
            "price": {"currency": oipg.currency, "value": "25.00"},
        },
        {
            "@ondc/org/item_id": "F1",
            "@ondc/org/title_type": "tax",
            "title": "Tax",
            "price": {"currency": oipg.currency, "value": "45.00"},
        },
        {
            "@ondc/org/item_id": "F1",
            "@ondc/org/title_type": "discount",
            "title": "Discount",
            "price": {"currency": oipg.currency, "value": "-20.00"},
        },
    ])
    cases.append({
        "id": "F-TC016",
        "name": "on_init Detailed Quote Breakup",
        "category": "Functional",
        "description": "[PASS EXPECTED] BPP sends /on_init with an extended quote breakup (item + delivery + packing + tax + discount). Validates Gateway forwards detailed pricing breakdowns without truncation.",
        "method": "POST",
        "url": f"{func_host}/on_init",
        "payload": _detailed_quote_payload,
        "raw_body": None, "raw_content_type": None,
        "expected_status": [200, 202],
        "auth_mode": "valid", "custom_headers": None, "ttl": None, "sleep_before": None,
    })

    # F-TC017 — on_init different domain (nack_ok if cross-domain)
    _domain2 = oipg.domains[1] if len(oipg.domains) > 1 else "ONDC:RET16"
    _domain2_is_cross = _domain2 not in set(oipg.domains)
    _domain2_desc = (
        f"[PASS EXPECTED] BPP sends /on_init with context.domain='{_domain2}'. "
        + (
            f"The participant is not registered for domain '{_domain2}' — the Gateway returns "
            "NACK (authentication failed for unregistered domain), which is the correct and "
            "expected behaviour. A NACK response is treated as PASS for this test case."
            if _domain2_is_cross else
            "Validates Gateway routes backward init callbacks for non-primary domains to the correct BAP."
        )
    )
    cases.append({
        "id": "F-TC017",
        "name": f"on_init Different Domain: {_domain2}",
        "category": "Functional",
        "description": _domain2_desc,
        "method": "POST",
        "url": f"{func_host}/on_init",
        "payload": oipg.build(domain=_domain2),
        "raw_body": None, "raw_content_type": None,
        "expected_status": [200, 202],
        "auth_mode": "valid", "custom_headers": None, "ttl": None, "sleep_before": None,
        "nack_ok": _domain2_is_cross,
    })

    # F-TC018 — on_init large order (25 items)
    cases.append({
        "id": "F-TC018",
        "name": "on_init Large Order (25 Items)",
        "category": "Functional",
        "description": "[PASS EXPECTED] BPP sends /on_init with 25 items in the order. Validates Gateway handles large init callback payloads efficiently without truncation or timeout.",
        "method": "POST",
        "url": f"{func_host}/on_init",
        "payload": oipg.build(item_count=25),
        "raw_body": None, "raw_content_type": None,
        "expected_status": [200, 202],
        "auth_mode": "valid", "custom_headers": None, "ttl": None, "sleep_before": None,
    })

    # =========================================================================
    # NEGATIVE TEST CASES
    # =========================================================================

    # N-TC001 — Missing Authorization header
    cases.append({
        "id": "N-TC001",
        "name": "Init Missing Authorization Header",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401] Sends /init with Content-Type but no Authorization header. Gateway must reject all unauthenticated ONDC requests.",
        "method": "POST",
        "url": f"{neg_host}/init",
        "payload": nipg.build(),
        "raw_body": None, "raw_content_type": None,
        "expected_status": [401, 400],
        "auth_mode": "no_auth", "custom_headers": None, "ttl": None, "sleep_before": None,
    })

    # N-TC002 — Tampered signature
    cases.append({
        "id": "N-TC002",
        "name": "Init Invalid / Tampered Signature",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401] Sends /init with a valid Authorization header format but signature prefixed with 'TAMPERED'. Gateway must reject cryptographically invalid signatures.",
        "method": "POST",
        "url": f"{neg_host}/init",
        "payload": nipg.build(),
        "raw_body": None, "raw_content_type": None,
        "expected_status": [401, 400],
        "auth_mode": "tamper_sig", "custom_headers": None, "ttl": None, "sleep_before": None,
    })

    # N-TC003 — Missing context.domain
    _no_domain = nipg.build()
    _no_domain["context"].pop("domain", None)
    cases.append({
        "id": "N-TC003",
        "name": "Init Missing context.domain",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401/400/NACK] Sends /init where context.domain is removed. The domain field is mandatory for Gateway routing. Gateway may return 4xx or HTTP 200 NACK.",
        "method": "POST",
        "url": f"{neg_host}/init",
        "payload": _no_domain,
        "raw_body": None, "raw_content_type": None,
        "expected_status": [400, 401],
        "auth_mode": "valid", "custom_headers": None, "ttl": None, "sleep_before": None,
        "nack_ok": True,
    })

    # N-TC004 — Missing context.bap_id
    _no_bap = nipg.build()
    _no_bap["context"].pop("bap_id", None)
    cases.append({
        "id": "N-TC004",
        "name": "Init Missing context.bap_id",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401/400/NACK] Sends /init with bap_id removed from context. Gateway cannot identify the requesting buyer application. Gateway may return 4xx or HTTP 200 NACK.",
        "method": "POST",
        "url": f"{neg_host}/init",
        "payload": _no_bap,
        "raw_body": None, "raw_content_type": None,
        "expected_status": [400, 401],
        "auth_mode": "valid", "custom_headers": None, "ttl": None, "sleep_before": None,
        "nack_ok": True,
    })

    # N-TC005 — Missing context.bpp_id (PASS — treated as broadcast)
    _no_bpp = nipg.build()
    _no_bpp["context"].pop("bpp_id", None)
    _no_bpp["context"].pop("bpp_uri", None)
    cases.append({
        "id": "N-TC005",
        "name": "Init Missing context.bpp_id",
        "category": "Negative",
        "description": "[PASS EXPECTED — ACK] Sends /init with bpp_id removed from context. When BPP ID is missing the request is treated as broadcast. Gateway returns ACK.",
        "method": "POST",
        "url": f"{neg_host}/init",
        "payload": _no_bpp,
        "raw_body": None, "raw_content_type": None,
        "expected_status": [200, 202],
        "auth_mode": "valid", "custom_headers": None, "ttl": None, "sleep_before": None,
    })

    # N-TC006 — Missing context.transaction_id
    _no_txn = nipg.build()
    _no_txn["context"].pop("transaction_id", None)
    cases.append({
        "id": "N-TC006",
        "name": "Init Missing context.transaction_id",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401/400/NACK] Sends /init with transaction_id removed from context. Transaction ID is required for correlating init with on_init callbacks. Gateway may return 4xx or HTTP 200 NACK.",
        "method": "POST",
        "url": f"{neg_host}/init",
        "payload": _no_txn,
        "raw_body": None, "raw_content_type": None,
        "expected_status": [400, 401],
        "auth_mode": "valid", "custom_headers": None, "ttl": None, "sleep_before": None,
        "nack_ok": True,
    })

    # N-TC007 — Missing context.timestamp
    _no_ts = nipg.build()
    _no_ts["context"].pop("timestamp", None)
    cases.append({
        "id": "N-TC007",
        "name": "Init Missing context.timestamp",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401/400/NACK] Sends /init with context.timestamp removed. Timestamp is required for replay-attack prevention. Gateway may return 4xx or HTTP 200 NACK.",
        "method": "POST",
        "url": f"{neg_host}/init",
        "payload": _no_ts,
        "raw_body": None, "raw_content_type": None,
        "expected_status": [400, 401],
        "auth_mode": "valid", "custom_headers": None, "ttl": None, "sleep_before": None,
        "nack_ok": True,
    })

    # N-TC008 — Missing context.action
    _wrong_action = nipg.build()
    _wrong_action["context"]["action"] = "search"
    cases.append({
        "id": "N-TC008",
        "name": "Init Wrong action Value (search on /init endpoint)",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401/400/NACK] Sends a POST to /init but with context.action='search' instead of 'init'. Gateway must validate the action field. May return 4xx or HTTP 200 NACK.",
        "method": "POST",
        "url": f"{neg_host}/init",
        "payload": _wrong_action,
        "raw_body": None, "raw_content_type": None,
        "expected_status": [400, 401],
        "auth_mode": "valid", "custom_headers": None, "ttl": None, "sleep_before": None,
        "nack_ok": True,
    })

    # N-TC009 — Invalid JSON syntax (raw string)
    cases.append({
        "id": "N-TC009",
        "name": "Init Invalid JSON Syntax (raw string)",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401/400] Sends POST /init with Content-Type application/json but body is '{not valid json'. Gateway must reject unparseable JSON.",
        "method": "POST",
        "url": f"{neg_host}/init",
        "payload": None,
        "raw_body": "{not valid json",
        "raw_content_type": "application/json",
        "expected_status": [400, 401],
        "auth_mode": "custom",
        "custom_headers": {"Content-Type": "application/json"},
        "ttl": None, "sleep_before": None,
    })

    # N-TC010 — Empty JSON payload {}
    cases.append({
        "id": "N-TC010",
        "name": "Init Empty JSON Payload ({})",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401/400] Sends POST /init with an empty JSON body {}. Without context or message, the Gateway must reject as missing mandatory ONDC fields.",
        "method": "POST",
        "url": f"{neg_host}/init",
        "payload": {},
        "raw_body": None, "raw_content_type": None,
        "expected_status": [400, 401],
        "auth_mode": "custom",
        "custom_headers": {"Content-Type": "application/json"},
        "ttl": None, "sleep_before": None,
    })

    # N-TC011 — Wrong HTTP method (GET)
    cases.append({
        "id": "N-TC011",
        "name": "Init Wrong HTTP Method (GET)",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 404/405] Sends the /init request as GET instead of POST. ONDC Gateway endpoints only accept POST — other methods should return 404 or 405.",
        "method": "GET",
        "url": f"{neg_host}/init",
        "payload": None,
        "raw_body": None, "raw_content_type": None,
        "expected_status": [404, 405],
        "auth_mode": "no_auth", "custom_headers": None, "ttl": None, "sleep_before": None,
    })

    # N-TC012 — Wrong Content-Type (text/plain)
    cases.append({
        "id": "N-TC012",
        "name": "Init Wrong Content-Type (text/plain)",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401/400/415] Sends /init with Content-Type: text/plain instead of application/json. Gateway should reject requests with incorrect content type.",
        "method": "POST",
        "url": f"{neg_host}/init",
        "payload": None,
        "raw_body": "plain text body",
        "raw_content_type": "text/plain",
        "expected_status": [400, 401, 415],
        "auth_mode": "custom",
        "custom_headers": {"Content-Type": "text/plain"},
        "ttl": None, "sleep_before": None,
    })

    # N-TC013 — Invalid Authorization header format
    cases.append({
        "id": "N-TC013",
        "name": "Init Invalid Authorization Header Format",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401] Sends /init with Authorization: Bearer token_xyz instead of ONDC Signature format. Gateway must reject non-ONDC auth schemes.",
        "method": "POST",
        "url": f"{neg_host}/init",
        "payload": nipg.build(),
        "raw_body": None, "raw_content_type": None,
        "expected_status": [401, 400],
        "auth_mode": "custom",
        "custom_headers": {
            "Authorization": "Bearer invalid_token_here",
            "Content-Type": "application/json; charset=utf-8",
        },
        "ttl": None, "sleep_before": None,
    })

    # N-TC014 — Expired signature (TTL=10s)
    cases.append({
        "id": "N-TC014",
        "name": "Init Expired Signature (TTL = 10s)",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401] Generates an /init signature with TTL=10s then waits 12 seconds before sending. The signature will be expired at send time.",
        "method": "POST",
        "url": f"{neg_host}/init",
        "payload": nipg.build(),
        "raw_body": None, "raw_content_type": None,
        "expected_status": [401, 400],
        "auth_mode": "expired", "custom_headers": None,
        "ttl": 10, "sleep_before": 12,
    })

    # N-TC015 — Invalid domain
    _bad_domain = nipg.build()
    _bad_domain["context"]["domain"] = "INVALID:DOMAIN999"
    cases.append({
        "id": "N-TC015",
        "name": "Init Invalid Domain (INVALID:DOMAIN999)",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401/400] Sends /init with an unrecognised domain code 'INVALID:DOMAIN999'. Gateway must reject requests for unsupported ONDC domains.",
        "method": "POST",
        "url": f"{neg_host}/init",
        "payload": _bad_domain,
        "raw_body": None, "raw_content_type": None,
        "expected_status": [400, 401],
        "auth_mode": "valid", "custom_headers": None, "ttl": None, "sleep_before": None,
    })

    # N-TC016 — Invalid city code
    _bad_city = nipg.build()
    _bad_city["context"]["city"] = "invalid:city:format"
    cases.append({
        "id": "N-TC016",
        "name": "Init Invalid City Code (invalid:city:format)",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401/400/NACK] Sends /init with a malformed city code. Gateway must validate city codes. May return 4xx or HTTP 200 NACK.",
        "method": "POST",
        "url": f"{neg_host}/init",
        "payload": _bad_city,
        "raw_body": None, "raw_content_type": None,
        "expected_status": [400, 401],
        "auth_mode": "valid", "custom_headers": None, "ttl": None, "sleep_before": None,
        "nack_ok": True,
    })

    # N-TC017 — Invalid country code
    _bad_country = nipg.build()
    _bad_country["context"]["country"] = "XYZZY"
    cases.append({
        "id": "N-TC017",
        "name": "Init Invalid Country Code (XYZZY)",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401/400/NACK] Sends /init with context.country='XYZZY'. Gateway must reject invalid country fields. May return 4xx or HTTP 200 NACK.",
        "method": "POST",
        "url": f"{neg_host}/init",
        "payload": _bad_country,
        "raw_body": None, "raw_content_type": None,
        "expected_status": [400, 401],
        "auth_mode": "valid", "custom_headers": None, "ttl": None, "sleep_before": None,
        "nack_ok": True,
    })

    # N-TC018 — Invalid core_version
    _bad_ver = nipg.build()
    _bad_ver["context"]["core_version"] = "99.abcd"
    cases.append({
        "id": "N-TC018",
        "name": "Init Invalid core_version (99.abcd)",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401/400] Sends /init with context.core_version='99.abcd'. Validates Gateway rejects requests referencing unsupported protocol versions.",
        "method": "POST",
        "url": f"{neg_host}/init",
        "payload": _bad_ver,
        "raw_body": None, "raw_content_type": None,
        "expected_status": [400, 401],
        "auth_mode": "valid", "custom_headers": None, "ttl": None, "sleep_before": None,
    })

    # N-TC019 — Malformed JSON structure (valid JSON, wrong ONDC shape)
    cases.append({
        "id": "N-TC019",
        "name": "Init Malformed JSON Structure",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401/400/NACK] Sends POST /init with valid JSON but entirely wrong shape (no context or message keys). Gateway must reject structurally invalid ONDC payloads.",
        "method": "POST",
        "url": f"{neg_host}/init",
        "payload": {"invalid_key": "test", "another": 123, "nested": {"wrong": "structure"}},
        "raw_body": None, "raw_content_type": None,
        "expected_status": [400, 401],
        "auth_mode": "valid", "custom_headers": None, "ttl": None, "sleep_before": None,
        "nack_ok": True,
    })

    # N-TC020 — Extremely large payload (ACK expected — no size limit enforced)
    _dos_payload = nipg.build()
    _dos_payload["message"]["order"]["items"] = [
        {"id": f"item-{i:05d}", "quantity": {"count": 1}, "fulfillment_id": "F1", "descriptor": {"name": "x" * 500}}
        for i in range(200)
    ]
    cases.append({
        "id": "N-TC020",
        "name": "Init Extremely Large Payload (DoS / Size Limit)",
        "category": "Negative",
        "description": "[PASS EXPECTED — ACK] Sends /init with 200 items each with 500-char names. Gateway returns ACK as no size limit is enforced at this layer.",
        "method": "POST",
        "url": f"{neg_host}/init",
        "payload": _dos_payload,
        "raw_body": None, "raw_content_type": None,
        "expected_status": [200, 202],
        "auth_mode": "valid", "custom_headers": None, "ttl": None, "sleep_before": None,
    })

    # ----- on_init negative tests (N-TC021 – N-TC026) -----------------------

    # N-TC021 — on_init missing Authorization header
    cases.append({
        "id": "N-TC021",
        "name": "on_init Missing Authorization Header",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401] Sends /on_init with no Authorization header. Even backward callbacks from BPPs must be authenticated.",
        "method": "POST",
        "url": f"{neg_host}/on_init",
        "payload": noipg.build(),
        "raw_body": None, "raw_content_type": None,
        "expected_status": [401, 400],
        "auth_mode": "no_auth", "custom_headers": None, "ttl": None, "sleep_before": None,
    })

    # N-TC022 — on_init tampered signature
    cases.append({
        "id": "N-TC022",
        "name": "on_init Tampered Signature",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401] Sends /on_init with a cryptographically invalid (tampered) signature. Gateway must verify the BPP's signature before accepting any backward callback.",
        "method": "POST",
        "url": f"{neg_host}/on_init",
        "payload": noipg.build(),
        "raw_body": None, "raw_content_type": None,
        "expected_status": [401, 400],
        "auth_mode": "tamper_sig", "custom_headers": None, "ttl": None, "sleep_before": None,
    })

    # N-TC023 — REMOVED (on_init missing context.bpp_id — Gateway accepts this)

    # N-TC024 — on_init missing context.bap_id
    cases.append({
        "id": "N-TC024",
        "name": "on_init Missing context.bap_id (Routing Failure)",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401/400/NACK] Sends /on_init without bap_id in context. Gateway cannot route the callback to the correct BAP. May return 4xx or HTTP 200 NACK.",
        "method": "POST",
        "url": f"{neg_host}/on_init",
        "payload": noipg.build(omit_bap_id=True),
        "raw_body": None, "raw_content_type": None,
        "expected_status": [400, 401],
        "auth_mode": "valid", "custom_headers": None, "ttl": None, "sleep_before": None,
        "nack_ok": True,
    })

    # N-TC025 — on_init missing context.domain
    cases.append({
        "id": "N-TC025",
        "name": "on_init Missing context.domain",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401/400/NACK] Sends /on_init with domain removed from context. Gateway uses domain to validate the callback. May return 4xx or HTTP 200 NACK.",
        "method": "POST",
        "url": f"{neg_host}/on_init",
        "payload": noipg.build(omit_domain=True),
        "raw_body": None, "raw_content_type": None,
        "expected_status": [400, 401],
        "auth_mode": "valid", "custom_headers": None, "ttl": None, "sleep_before": None,
        "nack_ok": True,
    })

    # N-TC026 — on_init wrong HTTP method (GET)
    cases.append({
        "id": "N-TC026",
        "name": "on_init Wrong HTTP Method (GET)",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 404/405] Sends the /on_init request as GET instead of POST. ONDC Gateway endpoints only accept POST — other methods should return 404 or 405.",
        "method": "GET",
        "url": f"{neg_host}/on_init",
        "payload": None,
        "raw_body": None, "raw_content_type": None,
        "expected_status": [404, 405],
        "auth_mode": "no_auth", "custom_headers": None, "ttl": None, "sleep_before": None,
    })

    # Apply filter
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
    catalogue_path = os.path.join(
        PROJECT_ROOT,
        "resources", "gateway", "ondc_gateway_error_codes.yml",
    )
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
    raw_tc_id = tc.get("id", "UNKNOWN-TC")
    raw_tc_id = str(raw_tc_id) if raw_tc_id is not None else "UNKNOWN-TC"
    safe_tc_id = "".join(ch for ch in raw_tc_id if ch.isalnum() or ch in ("-", "_"))[:64] or "UNKNOWN-TC"
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

    tc_id_raw = str(tc.get("id", "UNKNOWN"))
    safe_tc_id = "".join(ch for ch in tc_id_raw if ch.isalnum() or ch in ("_", "-")) or "UNKNOWN"
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

def _safe_dump(obj) -> str:
    """Convert obj to an HTML-safe string for embedding in the report."""
    import html as _html
    if obj is None:
        return ""
    if isinstance(obj, dict):
        return _html.escape(json.dumps(obj, indent=2, ensure_ascii=False, default=str))
    return _html.escape(str(obj))


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

        # Redact all request/response artifacts before persisting into HTML report
        req_headers_safe = _safe_dump(r.get("req_headers"))
        req_body_safe = _safe_dump(r.get("req_body"))
        resp_headers_safe = _safe_dump(r.get("resp_headers"))
        resp_body_safe = _safe_dump(r.get("resp_body"))
        error_safe = _safe_dump(r.get("error"))

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
<title>ONDC Gateway Init API Test Report</title>
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
.sc-2xx {{ background: rgba(34,197,94,.1); color: #22c55e; }}
.sc-4xx {{ background: rgba(239,68,68,.1); color: #ef4444; }}
.sc-5xx {{ background: rgba(239,68,68,.1); color: #ef4444; }}
.sc-none {{ background: rgba(245,158,11,.1); color: #f59e0b; }}
.chip-time {{ background: rgba(56,189,248,.08); color: #38bdf8; }}
.chip-ts {{ background: rgba(148,163,184,.06); color: #64748b; }}
.auth-chip {{
    font-size: .68rem; font-weight: 700; padding: 2px 8px; border-radius: 6px;
    background: rgba(245,158,11,.1); color: #f59e0b; flex-shrink: 0;
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
    <h1>ONDC <span>Gateway Init API</span> Test Report</h1>
    <p>
      <strong>Source:</strong> Gateway /init &amp; /on_init — Functional &amp; Negative
      &nbsp;|&nbsp;
      <strong>Generated:</strong> {_esc(run_ts)}
    </p>
  </div>

  <div class="summary">
    <div class="scard total"><div class="val">{total}</div><div class="lbl">Total</div></div>
    <div class="scard passed"><div class="val">{passed}</div><div class="lbl">Passed</div></div>
    <div class="scard failed"><div class="val">{failed}</div><div class="lbl">Failed</div></div>
    <div class="scard rate"><div class="val">{pass_pct}%</div><div class="lbl">Pass Rate</div></div>
    <div class="scard rsp"><div class="val">{avg_s}s</div><div class="lbl">Avg Response</div></div>
  </div>

  <div class="controls">
    <input id="search" class="search" type="text" placeholder="Search test ID or name ..." oninput="applyFilters()"/>
    <button class="fbtn active" data-f="all" onclick="setFilter(this,'all')">All</button>
    <button class="fbtn pass" data-f="pass" onclick="setFilter(this,'pass')">Passed</button>
    <button class="fbtn fail" data-f="fail" onclick="setFilter(this,'fail')">Failed</button>
    <button class="fbtn suite active" data-suite="all" onclick="setSuite(this,'all')">All Suites</button>
    {suite_btns}
    <span class="count" id="count"></span>
  </div>

  <div id="container">
    {cards_html}
  </div>

</div>
<script>
var activeFilter='all',activeSuite='all';
function toggle(i){{
  var b=document.getElementById('body-'+i),c=document.getElementById('chev-'+i),o=b.style.display==='block';
  b.style.display=o?'none':'block';c.classList.toggle('open',!o);
}}
function setFilter(btn,f){{
  activeFilter=f;
  document.querySelectorAll('.fbtn[data-f]').forEach(function(b){{b.classList.remove('active');}});
  btn.classList.add('active');applyFilters();
}}
function setSuite(btn,s){{
  activeSuite=s;
  document.querySelectorAll('.fbtn.suite').forEach(function(b){{b.classList.remove('active');}});
  btn.classList.add('active');applyFilters();
}}
function applyFilters(){{
  var q=(document.getElementById('search').value||'').toLowerCase();
  var cards=document.querySelectorAll('#container .card');
  var visible=0;
  cards.forEach(function(c){{
    var nm=!q||(c.dataset.name||'').toLowerCase().includes(q);
    var fm=activeFilter==='all'||
           (activeFilter==='pass'&&c.classList.contains('pass'))||
           (activeFilter==='fail'&&c.classList.contains('fail'));
    var sm=activeSuite==='all'||c.dataset.suite===activeSuite;
    var show=nm&&fm&&sm;
    c.style.display=show?'':'none';
    if(show)visible++;
  }});
  document.getElementById('count').textContent=visible+' of {total} shown';
}}
applyFilters();
</script>
</body>
</html>
"""

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    logger.info(f"HTML report saved -> {output_path}")


# ---------------------------------------------------------------------------
# Participant registration (embedded — reads creds from cfg dict)
# ---------------------------------------------------------------------------
_REG_ADMIN_API_URL  = os.environ.get("REG_ADMIN_API_URL", "")
_REG_ADMIN_AUTH_URL = os.environ.get("REG_ADMIN_AUTH_URL", "")
_REG_ADMIN_EMAIL    = os.environ.get("REG_ADMIN_EMAIL", "")
_REG_ADMIN_PASSWORD = os.environ.get("REG_ADMIN_PASSWORD", "")
_REG_LOC_ID         = "loc-gw-bap-001"
_REG_URI_ID         = "uri-gw-bap-001"
_REG_TIMEOUT        = 15


def _reg_get_admin_token() -> str:
    """Obtain a SUPER_ADMIN Bearer token via RegistryAuthClient dynamic login."""
    try:
        from tests.utils.registry_auth_client import RegistryAuthClient
        import urllib3 as _u3
        _u3.disable_warnings(_u3.exceptions.InsecureRequestWarning)
        client = RegistryAuthClient(
            base_url=_REG_ADMIN_API_URL,
            username=_REG_ADMIN_EMAIL,
            password=_REG_ADMIN_PASSWORD,
            auth_url=_REG_ADMIN_AUTH_URL,
            verify=False,
        )
        return client.get_token()
    except Exception as exc:
        raise RuntimeError(f"Admin login failed: {exc}") from exc


def _reg_derive_signing_pub(private_key_seed_raw: str) -> Optional[str]:
    if not _HAS_CRYPTO:
        return None
    seed = _decode_private_key(private_key_seed_raw)
    if not seed:
        return None
    try:
        priv = Ed25519PrivateKey.from_private_bytes(seed)
        return base64.b64encode(priv.public_key().public_bytes_raw()).decode()
    except Exception as exc:
        logger.warning(f"[register] Could not derive public key: {exc}")
        return None


def _reg_build_payload(cfg: dict, signing_pub: str, enc_pub: str) -> dict:
    participant_id = cfg.get("participant_id", "")
    uk_id = cfg.get("uk_id", "")
    bap_uri = cfg.get("bap_uri", "")
    domains = cfg.get("domains", ["ONDC:RET10"])
    cities = cfg.get("cities", ["std:080"])
    configs = [
        {"domain": d, "np_type": "BAP", "subscriber_id": participant_id,
         "location_id": _REG_LOC_ID, "uri_id": _REG_URI_ID, "key_id": uk_id}
        for d in domains
    ]
    return {
        "participant_id": participant_id,
        "action": "SUBSCRIBED",
        "credentials": [{"cred_id": "cred-gst-gw-bap-001", "type": "GST",
                         "cred_data": {"gstin": "29ABCDE1234F1Z5",
                                       "legal_name": "Gateway Test BAP Pvt Ltd"}},
                        {"cred_id": "cred-pan-gw-bap-001", "type": "PAN",
                         "cred_data": {"pan": "ABCDE1234F",
                                       "name": "Gateway Test BAP Pvt Ltd"}}],
        "contacts": [{"contact_id": "contact-auth-gw-bap-001", "type": "AUTHORISED_SIGNATORY",
                      "name": "GW Test Admin", "email": f"admin@{participant_id}",
                      "phone": "+919876543211"},
                     {"contact_id": "contact-biz-gw-bap-001", "type": "BUSINESS",
                      "name": "GW Test Biz", "email": f"business@{participant_id}",
                      "phone": "+919876543212"},
                     {"contact_id": "contact-tech-gw-bap-001", "type": "TECHNICAL",
                      "name": "GW Test Tech", "email": f"tech@{participant_id}",
                      "phone": "+919876543210"}],
        "key": [{"uk_id": uk_id, "signing_public_key": signing_pub,
                "encryption_public_key": enc_pub,
                "signed_algorithm": "ED25519", "encryption_algorithm": "X25519",
                "valid_from": "2024-01-01T00:00:00.000Z",
                "valid_until": "2026-12-31T23:59:59.000Z"}],
        "location": [{"location_id": _REG_LOC_ID, "type": "SERVICEABLE",
                     "country": "IND", "city": cities[:1]}],
        "uri": [{"uri_id": _REG_URI_ID, "type": "CALLBACK",
                 "url": f"https://{participant_id}/callback"}],
        "configs": configs,
        "dns_skip": True,
        "skip_ssl_verification": True,
    }


def _reg_already_registered(body: str) -> bool:
    try:
        data = json.loads(body)
        code = str(data.get("error", {}).get("code", ""))
        msg  = str(data.get("error", {}).get("message", "")).lower()
        return code in ("30004", "40900") or "already" in msg or "exists" in msg
    except Exception:
        return False


def register_bap_participant(cfg: dict) -> None:
    """Register the BAP participant using credentials from the loaded YAML config."""
    import os as _os

    participant_id = cfg.get("participant_id", "")
    uk_id = cfg.get("uk_id", "")
    if not participant_id:
        logger.warning("[register] participant_id not found in config — skipping registration.")
        return

    logger.info("--- BAP Participant Registration (UAT) ---")
    logger.info(f"Participant : {_sanitize_log(participant_id)}  UK: ***{_sanitize_log(uk_id[-4:]) if len(uk_id) > 4 else '****'}")

    # 1 — derive signing public key
    try:
        signing_pub = _reg_derive_signing_pub(str(cfg.get("private_key_seed", "")))
        if not signing_pub:
            logger.warning("[register] Could not derive signing public key — skipping registration.")
            return
        enc_pub = base64.b64encode(_os.urandom(32)).decode()
    except Exception as exc:
        logger.warning(f"[register] Key derivation failed: {_sanitize_log(exc)} — skipping registration.")
        return

    # 2 — get admin token
    try:
        token = _reg_get_admin_token()
    except Exception as exc:
        logger.warning(f"[register] Could not obtain admin token: {_sanitize_log(exc)} — skipping registration.")
        return

    # 3 — POST /admin/subscribe
    url = f"{_REG_ADMIN_API_URL.rstrip('/')}/admin/subscribe"
    payload = _reg_build_payload(cfg, signing_pub, enc_pub)
    wire = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    try:
        resp = requests.post(url, data=wire.encode(), headers=headers,
                             timeout=_REG_TIMEOUT, verify=_SSL_VERIFY)
        body = resp.text
    except Exception as exc:
        logger.warning(f"[register] HTTP request failed: {_sanitize_log(exc)} — skipping registration.")
        return

    if resp.status_code in (200, 202) and not _is_nack(body):
        logger.info(f"[register] Participant '{participant_id}' registered successfully.")
    elif _reg_already_registered(body):
        logger.info(f"[register] Participant already registered — skipping.")
    else:
        logger.warning(
            f"[register] Registration returned HTTP {resp.status_code}: {body[:200]} "
            "— tests will proceed (participant may already exist)."
        )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(
        description="ONDC Gateway Init API automated test runner — /init and /on_init endpoints."
    )
    parser.add_argument(
        "--func-config",
        default="resources/gateway/ondc_gateway_init_functional.yml",
        help="Path to functional test YAML config (default: resources/gateway/ondc_gateway_init_functional.yml)",
    )
    parser.add_argument(
        "--neg-config",
        default="resources/gateway/ondc_gateway_init_negative.yml",
        help="Path to negative test YAML config (default: resources/gateway/ondc_gateway_init_negative.yml)",
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
        help="Path for the HTML report (default: reports/Gateway-init-<timestamp>.html)",
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
            f"Gateway-init-{args.suite}-{ts_file}.html",
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
    logger.info(f"  ONDC Gateway Init API Test Suite")
    logger.info(f"  Endpoint: /init  and  /on_init")
    logger.info(f"  Test cases: {len(all_cases)}")
    logger.info(f"  Host (func): {_sanitize_log(func_cfg.get('host', 'N/A'))}")
    logger.info(f"  Timeout: {args.timeout}s")
    logger.info(f"{'='*60}\n")

    results = []
    for tc in all_cases:
        result = run_test_case(tc, func_auth, neg_auth, timeout=args.timeout)
        results.append(result)

    total = len(results)
    passed = sum(1 for r in results if r["passed"])
    failed = total - passed

    logger.info("=" * 60)
    logger.info(f"Results  Total={total}  PASS={passed}  FAIL={failed}  ({round(passed/total*100 if total else 0, 1)}%)")
    logger.info("=" * 60)

    generate_html_report(results, report_path, run_ts)
    logger.info(f"Report -> {report_path}")


if __name__ == "__main__":
    main()
