#!/usr/bin/env python3
"""
ONDC Gateway Confirm API - Automated Test Runner with HTML Report Generator

Runs all functional and negative test cases for the ONDC /confirm endpoint
and generates a comprehensive HTML report.

Usage:
    python func_test_scripts/run_confirm_api_tests.py
    python func_test_scripts/run_confirm_api_tests.py --output reports/custom_report.html
    python func_test_scripts/run_confirm_api_tests.py --suite functional
    python func_test_scripts/run_confirm_api_tests.py --suite negative
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
from typing import Any, Dict, List, Optional, Tuple

import requests
import yaml

# ---------------------------------------------------------------------------
# Path setup — allow project-level imports
# ---------------------------------------------------------------------------
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, PROJECT_ROOT)

logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")
logger = logging.getLogger(__name__)

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
        """Generate headers that expire in 1 second."""
        return self.generate_headers(payload, ttl=1)


# ---------------------------------------------------------------------------
# Config loader
# ---------------------------------------------------------------------------
def load_yaml_config(path: str, tenant: str = "ondcGW") -> dict:
    full_path = path if os.path.isabs(path) else os.path.join(PROJECT_ROOT, path)
    if not os.path.exists(full_path):
        logger.warning(f"Config not found: {full_path}")
        return {}
    with open(full_path, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    return data.get(tenant, {})


def _decode_private_key(raw: str) -> Optional[bytes]:
    """Accept 64-char hex OR base64-encoded PKCS#8; return 32-byte seed."""
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
        if len(pkcs8) >= 32:
            return pkcs8[-32:]
    except Exception:
        pass
    return None


# Required fields in each YAML config (under ondcGW tenant)
_REQUIRED_FIELDS = ["host", "private_key_seed", "participant_id", "uk_id", "bap_id", "bap_uri"]


def validate_config(cfg: dict, config_path: str, label: str) -> None:
    """Fail fast if any required field is missing or empty in the loaded config."""
    missing = [f for f in _REQUIRED_FIELDS if not cfg.get(f)]
    if missing:
        lines = [f"  - {f}" for f in missing]
        raise ValueError(
            f"\n\n[CONFIG ERROR] {label} config is missing required fields:\n"
            + "\n".join(lines)
            + f"\n\nFile  : {config_path}"
            + "\nMake sure these fields are present and NOT commented out under the"
            + " 'ondcGW:' key.\n"
        )
    logger.info(f"{label} config OK — all required fields present ({config_path})")


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
# Payload generator
# ---------------------------------------------------------------------------
class ConfirmPayloadGenerator:
    def __init__(self, cfg: dict):
        self.domains = cfg.get("domains", ["ONDC:FIS12"])
        self.cities = cfg.get("cities", ["std:080"])
        self.core_version = str(cfg.get("core_version", "1.2.0"))
        self.bap_id = str(cfg.get("bap_id", ""))
        self.bap_uri = str(cfg.get("bap_uri", ""))
        self.bpp_id = str(cfg.get("bpp_id", ""))
        self.bpp_uri = str(cfg.get("bpp_uri", ""))

        primary_domain = self.domains[0] if self.domains else ""

        # test_providers: may be domain-keyed dict {domain: [...]} or flat list
        raw_providers = cfg.get("test_providers", [])
        if isinstance(raw_providers, dict):
            self.test_providers = raw_providers.get(
                primary_domain,
                next(iter(raw_providers.values()), [{"id": "IGO_Seller_0001", "location_id": "store-location-001"}]),
            )
        else:
            self.test_providers = raw_providers or [{"id": "IGO_Seller_0001", "location_id": "store-location-001"}]

        # payment_types: may be domain-keyed dict {domain: [...]} or flat list
        raw_payment_types = cfg.get("payment_types", [])
        if isinstance(raw_payment_types, dict):
            self.payment_types = raw_payment_types.get(
                primary_domain,
                next(iter(raw_payment_types.values()), []),
            )
        else:
            self.payment_types = raw_payment_types

        # fulfillment_types: may be domain-keyed dict {domain: [{type, description}]} or flat list/strings
        raw_ft = cfg.get("fulfillment_types", ["Delivery"])
        if isinstance(raw_ft, dict):
            raw_ft = raw_ft.get(primary_domain, next(iter(raw_ft.values()), []))
        # Normalize each entry to a plain string (extract "type" key if entry is a dict)
        self.fulfillment_types = [
            ft["type"] if isinstance(ft, dict) else ft for ft in raw_ft
        ] or ["Delivery"]

        # test_items: now nested under test_data.{domain}.test_items; fall back to flat list
        raw_test_data = cfg.get("test_data", {})
        if isinstance(raw_test_data, dict) and raw_test_data:
            domain_data = raw_test_data.get(primary_domain, next(iter(raw_test_data.values()), {}))
            raw_items = (domain_data.get("test_items", []) if isinstance(domain_data, dict) else [])
        else:
            raw_items = cfg.get("test_items", [])
        self.test_items = raw_items or [{"id": "item-001", "price": "450.00", "name": "Test Item"}]

        self.test_locations = cfg.get(
            "test_locations", [{"gps": "12.9492953,77.7019878", "area_code": "560001"}]
        )
        self.settlement_details = cfg.get("settlement_details", [])
        self.country = str(cfg.get("country", "IND"))
        self.currency = str(cfg.get("currency", "INR"))
        self.request_ttl = str(cfg.get("request_ttl", "PT30S"))
        self.default_order_amount = str(cfg.get("default_order_amount", "500.00"))
        self.default_delivery_charge = str(cfg.get("default_delivery_charge", "50.00"))
        buyer = cfg.get("test_buyer", {})
        self.buyer_name = str(buyer.get("name", "Test Buyer"))
        self.buyer_phone = str(buyer.get("phone", "9876543210"))
        self.buyer_email = str(buyer.get("email", "buyer@example.com"))
        self.buyer_address_prefix = str(buyer.get("address_prefix", "123 Test Street, Bangalore"))
        self.buyer_gstin = str(buyer.get("gstin", "GSTIN123456789"))
        self.buyer_org_name = str(buyer.get("org_name", "Test Buyer Org"))
        self.seller_source_gps = str(cfg.get("seller_source_gps", "12.9063433,77.5856825"))
        self.seller_source_address = str(cfg.get("seller_source_address", "Seller Warehouse, Bangalore"))
        self.seller_agent_phone = str(cfg.get("seller_agent_phone", "8888888888"))
        self.delivery_agent_phone = str(cfg.get("delivery_agent_phone", "9999999999"))

    def build(
        self,
        domain: str = None,
        city: str = None,
        transaction_id: str = None,
        message_id: str = None,
        provider_id: str = None,
        item_id: str = None,
        item_quantity: int = 1,
        payment_type: dict = None,
        fulfillment_type: str = None,
        order_amount: str = None,
    ) -> dict:
        order_amount = order_amount or self.default_order_amount
        txn_id = transaction_id or f"txn-{uuid.uuid4().hex[:12]}"
        msg_id = message_id or f"msg-{uuid.uuid4().hex[:12]}"
        order_id = f"order-{uuid.uuid4().hex[:8]}"
        pay_txn = f"pay-{uuid.uuid4().hex[:8]}"

        sel_domain = domain or (self.domains[0] if self.domains else "")
        sel_city = city or (self.cities[0] if self.cities else "")

        prov = self.test_providers[0] if self.test_providers else {}
        pid = provider_id or prov.get("id", "")
        loc_id = prov.get("location_id", "")

        item = self.test_items[0] if self.test_items else {}
        iid = item_id or item.get("id", "")
        item_price = item.get("price", "0.00")
        item_name = item.get("name", "")

        ptype = payment_type or (
            self.payment_types[0] if self.payment_types else {}
        )
        ftype = fulfillment_type or (
            self.fulfillment_types[0] if self.fulfillment_types else ""
        )
        gps = (
            self.test_locations[0].get("gps", "")
            if self.test_locations
            else ""
        )
        area_code = (
            self.test_locations[0].get("area_code", "")
            if self.test_locations
            else ""
        )

        return {
            "context": {
                "domain": sel_domain,
                "action": "confirm",
                "country": self.country,
                "city": sel_city,
                "core_version": self.core_version,
                "bap_id": self.bap_id,
                "bap_uri": self.bap_uri,
                "bpp_id": self.bpp_id,
                "bpp_uri": self.bpp_uri,
                "transaction_id": txn_id,
                "message_id": msg_id,
                "timestamp": datetime.now(timezone.utc)
                .isoformat(timespec="milliseconds")
                .replace("+00:00", "Z"),
                "ttl": self.request_ttl,
            },
            "message": {
                "order": {
                    "id": order_id,
                    "provider": {"id": pid, "locations": [{"id": loc_id}]},
                    "items": [{"id": iid, "quantity": {"count": item_quantity}}],
                    "billing": {
                        "name": self.buyer_name,
                        "phone": self.buyer_phone,
                        "email": self.buyer_email,
                        "address": f"{self.buyer_address_prefix} {area_code}",
                    },
                    "fulfillments": [
                        {
                            "id": "1",
                            "type": ftype,
                            "end": {
                                "contact": {"phone": self.buyer_phone},
                                "location": {
                                    "gps": gps,
                                    "address": {"area_code": area_code},
                                },
                            },
                        }
                    ],
                    "payment": {
                        "params": {
                            "transaction_id": pay_txn,
                            "amount": order_amount,
                            "currency": self.currency,
                        },
                        "status": ptype.get("status", "PAID"),
                        "type": ptype.get("type", "ON-ORDER"),
                        "collected_by": ptype.get("collected_by", "BAP"),
                    },
                    "quote": {
                        "price": {"currency": self.currency, "value": order_amount},
                        "breakup": [
                            {
                                "@ondc/org/item_id": iid,
                                "@ondc/org/title_type": "item",
                                "title": item_name,
                                "price": {"currency": self.currency, "value": item_price},
                            },
                            {
                                "@ondc/org/item_id": "1",
                                "@ondc/org/title_type": "delivery",
                                "title": "Delivery Charges",
                                "price": {"currency": self.currency, "value": self.default_delivery_charge},
                            },
                        ],
                    },
                }
            },
        }


# ---------------------------------------------------------------------------
# on_confirm Payload generator (backward flow: BPP → Gateway → BAP)
# ---------------------------------------------------------------------------
class OnConfirmPayloadGenerator:
    """Builds on_confirm (backward-flow) payloads for the ONDC gateway."""

    def __init__(self, cfg: dict):
        self.domains = cfg.get("domains", ["ONDC:RET10"])
        self.cities = cfg.get("cities", ["std:080"])
        self.core_version = str(cfg.get("core_version", "1.2.0"))
        self.bap_id = str(cfg.get("bap_id", ""))
        self.bap_uri = str(cfg.get("bap_uri", ""))
        self.bpp_id = str(cfg.get("bpp_id", ""))
        self.bpp_uri = str(cfg.get("bpp_uri", ""))

        primary_domain = self.domains[0] if self.domains else ""

        # test_providers: may be domain-keyed dict {domain: [...]} or flat list
        raw_providers = cfg.get("test_providers", [])
        if isinstance(raw_providers, dict):
            self.test_providers = raw_providers.get(
                primary_domain,
                next(iter(raw_providers.values()), [{"id": "IGO_Seller_0001", "location_id": "store-location-001"}]),
            )
        else:
            self.test_providers = raw_providers or [{"id": "IGO_Seller_0001", "location_id": "store-location-001"}]

        # test_items: now nested under test_data.{domain}.test_items; fall back to flat list
        raw_test_data = cfg.get("test_data", {})
        if isinstance(raw_test_data, dict) and raw_test_data:
            domain_data = raw_test_data.get(primary_domain, next(iter(raw_test_data.values()), {}))
            raw_items = (domain_data.get("test_items", []) if isinstance(domain_data, dict) else [])
        else:
            raw_items = cfg.get("test_items", [])
        self.test_items = raw_items or [{"id": "item-001", "price": "450.00", "name": "Test Item"}]

        self.test_locations = cfg.get(
            "test_locations", [{"gps": "12.9492953,77.7019878", "area_code": "560001"}]
        )
        self.country = str(cfg.get("country", "IND"))
        self.currency = str(cfg.get("currency", "INR"))
        self.request_ttl = str(cfg.get("request_ttl", "PT30S"))
        self.default_order_amount = str(cfg.get("default_order_amount", "500.00"))
        self.default_delivery_charge = str(cfg.get("default_delivery_charge", "50.00"))
        buyer = cfg.get("test_buyer", {})
        self.buyer_name = str(buyer.get("name", "Test Buyer"))
        self.buyer_phone = str(buyer.get("phone", "9876543210"))
        self.buyer_email = str(buyer.get("email", "buyer@example.com"))
        self.buyer_address_prefix = str(buyer.get("address_prefix", "123 Test Street, Bangalore"))
        self.seller_source_gps = str(cfg.get("seller_source_gps", "12.9063433,77.5856825"))

    def build(
        self,
        domain: str = None,
        city: str = None,
        order_id: str = None,
        order_state: str = "Created",
        fulfillment_type: str = "Delivery",
        fulfillment_state_code: str = "Pending",
        tracking: bool = True,
        payment_type: str = "ON-ORDER",
        payment_status: str = "PAID",
        order_amount: str = None,
        include_error: dict = None,
        omit_order_state: bool = False,
        omit_order_id: bool = False,
        omit_billing: bool = False,
        omit_fulfillments: bool = False,
        omit_bap_id: bool = False,
    ) -> dict:
        order_amount = order_amount or self.default_order_amount
        txn_id = f"txn-oc-{uuid.uuid4().hex[:12]}"
        msg_id = f"msg-oc-{uuid.uuid4().hex[:12]}"
        oid = order_id or f"order-{uuid.uuid4().hex[:8]}"
        now = (
            datetime.now(timezone.utc)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z")
        )

        sel_domain = domain or (self.domains[0] if self.domains else "")
        sel_city = city or (self.cities[0] if self.cities else "")

        prov = self.test_providers[0] if self.test_providers else {}
        pid = prov.get("id", "")
        loc_id = prov.get("location_id", "")

        item = self.test_items[0] if self.test_items else {}
        iid = item.get("id", "")
        item_price = item.get("price", "0.00")
        item_name = item.get("name", "")

        gps = (
            self.test_locations[0].get("gps", "")
            if self.test_locations
            else ""
        )
        area_code = (
            self.test_locations[0].get("area_code", "")
            if self.test_locations
            else ""
        )

        ctx: dict = {
            "domain": sel_domain,
            "action": "on_confirm",
            "country": self.country,
            "city": sel_city,
            "core_version": self.core_version,
            "bap_id": "" if omit_bap_id else self.bap_id,
            "bap_uri": self.bap_uri,
            "bpp_id": self.bpp_id,
            "bpp_uri": self.bpp_uri,
            "transaction_id": txn_id,
            "message_id": msg_id,
            "timestamp": now,
            "ttl": self.request_ttl,
        }

        order: dict = {
            "id": oid,
            "state": order_state,
            "provider": {"id": pid, "locations": [{"id": loc_id}]},
            "items": [{"id": iid, "quantity": {"count": 1}}],
            "billing": {
                "name": self.buyer_name,
                "phone": self.buyer_phone,
                "email": self.buyer_email,
                "address": f"{self.buyer_address_prefix} {area_code}",
            },
            "fulfillments": [
                {
                    "id": "1",
                    "type": fulfillment_type,
                    "state": {"descriptor": {"code": fulfillment_state_code}},
                    "tracking": tracking,
                    "start": {
                        "location": {"id": loc_id, "gps": self.seller_source_gps}
                    },
                    "end": {
                        "contact": {"phone": self.buyer_phone},
                        "location": {
                            "gps": gps,
                            "address": f"{self.buyer_address_prefix} {area_code}",
                        },
                    },
                }
            ],
            "quote": {
                "price": {"currency": self.currency, "value": order_amount},
                "breakup": [
                    {
                        "@ondc/org/item_id": iid,
                        "@ondc/org/title_type": "item",
                        "title": item_name,
                        "price": {"currency": self.currency, "value": item_price},
                    },
                    {
                        "@ondc/org/item_id": "1",
                        "@ondc/org/title_type": "delivery",
                        "title": "Delivery Charges",
                        "price": {"currency": self.currency, "value": self.default_delivery_charge},
                    },
                ],
            },
            "payment": {"status": payment_status, "type": payment_type},
            "created_at": now,
            "updated_at": now,
        }

        # Apply field omissions for negative tests
        if omit_order_state:
            order.pop("state", None)
        if omit_order_id:
            order.pop("id", None)
        if omit_billing:
            order.pop("billing", None)
        if omit_fulfillments:
            order.pop("fulfillments", None)

        payload: dict = {"context": ctx, "message": {"order": order}}
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
) -> List[Dict[str, Any]]:
    """
    Build the complete list of test cases for functional and negative suites.

    Each test case dict:
        id, name, category, description, method, url,
        payload (dict | None), raw_body (str | None), raw_content_type (str | None),
        expected_status (list[int]),
        auth_mode: 'valid' | 'no_auth' | 'custom' | 'tamper_sig' |
                   'tamper_digest' | 'expired' | 'no_wait_expired',
        custom_headers (dict | None),
        ttl (int | None),           # for expired auth
        sleep_before (float | None) # seconds to sleep before sending (expired tests)
    """
    func_host = func_cfg.get("host", "http://localhost:8080").rstrip("/")
    neg_host = neg_cfg.get("host", "http://localhost:8080").rstrip("/")

    fpg = ConfirmPayloadGenerator(func_cfg)
    npg = ConfirmPayloadGenerator(neg_cfg)

    cases: List[Dict[str, Any]] = []

    # =========================================================================
    # FUNCTIONAL TEST CASES
    # =========================================================================

    # F-TC001 — Valid request with authentication
    cases.append({
        "id": "F-TC001",
        "name": "Confirm Valid Authenticated Request",
        "category": "Functional",
        "description": "[PASS EXPECTED] Sends a complete, correctly signed /confirm request. Validates that the Gateway accepts a well-formed order confirmation and forwards it to the BPP. This is the baseline happy-path scenario.",
        "method": "POST",
        "url": f"{func_host}/confirm",
        "payload": fpg.build(),
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [200, 202],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
    })

    # F-TC002 — Different ONDC domains
    for domain in fpg.domains:
        cases.append({
            "id": f"F-TC002-{domain}",
            "name": f"Confirm Different Domain: {domain}",
            "category": "Functional",
            "description": f"[PASS EXPECTED] Sends /confirm with context.domain='{domain}'. Verifies the Gateway correctly routes requests across different ONDC domain verticals (e.g., Grocery, Health, Financial Services).",
            "method": "POST",
            "url": f"{func_host}/confirm",
            "payload": fpg.build(domain=domain),
            "raw_body": None,
            "raw_content_type": None,
            "expected_status": [200, 202],
            "auth_mode": "valid",
            "custom_headers": None,
            "ttl": None,
            "sleep_before": None,
        })

    # F-TC003 — Different cities
    for city in fpg.cities:
        cases.append({
            "id": f"F-TC003-{city}",
            "name": f"Confirm Different City: {city}",
            "category": "Functional",
            "description": f"[PASS EXPECTED] Sends /confirm with context.city='{city}'. Validates the Gateway accepts confirm requests targeting different delivery city codes across India.",
            "method": "POST",
            "url": f"{func_host}/confirm",
            "payload": fpg.build(city=city),
            "raw_body": None,
            "raw_content_type": None,
            "expected_status": [200, 202],
            "auth_mode": "valid",
            "custom_headers": None,
            "ttl": None,
            "sleep_before": None,
        })

    # F-TC004 — Different payment types
    for pt in fpg.payment_types:
        label = pt.get("type", "UNKNOWN")
        cases.append({
            "id": f"F-TC004-{label}",
            "name": f"Confirm Payment Type: {label}",
            "category": "Functional",
            "description": f"[PASS EXPECTED] Sends /confirm with payment.type='{label}'. Validates Gateway accepts all supported ONDC payment modes: ON-ORDER (pre-payment), PRE-FULFILLMENT, ON-FULFILLMENT, and POST-FULFILLMENT (COD).",
            "method": "POST",
            "url": f"{func_host}/confirm",
            "payload": fpg.build(payment_type=pt),
            "raw_body": None,
            "raw_content_type": None,
            "expected_status": [200, 202],
            "auth_mode": "valid",
            "custom_headers": None,
            "ttl": None,
            "sleep_before": None,
        })

    # F-TC005 — Different fulfillment types
    for ftype in fpg.fulfillment_types:
        cases.append({
            "id": f"F-TC005-{ftype}",
            "name": f"Confirm Fulfillment Type: {ftype}",
            "category": "Functional",
            "description": f"[PASS EXPECTED] Sends /confirm with fulfillment.type='{ftype}'. Validates Gateway accepts all supported fulfillment modes: Delivery (home delivery), Pickup (buyer collects from store), Self-Pickup.",
            "method": "POST",
            "url": f"{func_host}/confirm",
            "payload": fpg.build(fulfillment_type=ftype),
            "raw_body": None,
            "raw_content_type": None,
            "expected_status": [200, 202],
            "auth_mode": "valid",
            "custom_headers": None,
            "ttl": None,
            "sleep_before": None,
        })

    # F-TC006 — Multiple items in order
    multi_item_payload = fpg.build()
    _item_quantities = [2, 1, 3]
    _all_items = fpg.test_items
    multi_item_payload["message"]["order"]["items"] = [
        {"id": _all_items[i % len(_all_items)]["id"], "quantity": {"count": _item_quantities[i % len(_item_quantities)]}}
        for i in range(min(3, len(_all_items)))
    ]
    multi_item_payload["message"]["order"]["quote"]["breakup"].extend([
        {
            "@ondc/org/item_id": _all_items[idx]["id"],
            "@ondc/org/title_type": "item",
            "title": _all_items[idx].get("name", f"Test Item {idx + 1}"),
            "price": {"currency": fpg.currency, "value": _all_items[idx].get("price", "200.00")},
        }
        for idx in range(1, min(3, len(_all_items)))
    ])
    cases.append({
        "id": "F-TC006",
        "name": "Confirm Multiple Items in Order",
        "category": "Functional",
        "description": "[PASS EXPECTED] Sends /confirm with 3 different items in the order (Basmati Rice x2, Sunflower Oil x1, Multivitamin x3). Validates Gateway handles multi-item basket confirmations correctly.",
        "method": "POST",
        "url": f"{func_host}/confirm",
        "payload": multi_item_payload,
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [200, 202],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
    })

    # F-TC007 — Minimal required fields only
    txn_id = f"txn-{uuid.uuid4().hex[:12]}"
    msg_id = f"msg-{uuid.uuid4().hex[:12]}"
    order_id = f"order-{uuid.uuid4().hex[:8]}"
    _prov007 = fpg.test_providers[0] if fpg.test_providers else {}
    _item007 = fpg.test_items[0] if fpg.test_items else {}
    _loc007 = fpg.test_locations[0] if fpg.test_locations else {}
    minimal_payload = {
        "context": {
            "domain": fpg.domains[0] if fpg.domains else "ONDC:RET10",
            "action": "confirm",
            "country": fpg.country,
            "city": fpg.cities[0] if fpg.cities else "std:080",
            "core_version": fpg.core_version,
            "bap_id": fpg.bap_id,
            "bap_uri": fpg.bap_uri,
            "bpp_id": fpg.bpp_id,
            "bpp_uri": fpg.bpp_uri,
            "transaction_id": txn_id,
            "message_id": msg_id,
            "timestamp": datetime.now(timezone.utc)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z"),
            "ttl": fpg.request_ttl,
        },
        "message": {
            "order": {
                "id": order_id,
                "provider": {
                    "id": _prov007.get("id", "IGO_Seller_0001"),
                    "locations": [{"id": _prov007.get("location_id", "store-location-001")}],
                },
                "items": [{"id": _item007.get("id", "item-001"), "quantity": {"count": 1}}],
                "billing": {
                    "name": fpg.buyer_name,
                    "phone": fpg.buyer_phone,
                    "address": f"{fpg.buyer_address_prefix} {_loc007.get('area_code', '560001')}",
                },
                "fulfillments": [{
                    "id": "1",
                    "type": fpg.fulfillment_types[0] if fpg.fulfillment_types else "Delivery",
                    "end": {
                        "contact": {"phone": fpg.buyer_phone},
                        "location": {"gps": _loc007.get("gps", "12.9492953,77.7019878")},
                    },
                }],
                "payment": {
                    "params": {
                        "transaction_id": f"pay-{uuid.uuid4().hex[:8]}",
                        "amount": fpg.default_order_amount,
                        "currency": fpg.currency,
                    },
                    "status": "PAID",
                    "type": "ON-ORDER",
                },
                "quote": {
                    "price": {"currency": fpg.currency, "value": fpg.default_order_amount},
                    "breakup": [
                        {
                            "@ondc/org/item_id": _item007.get("id", "item-001"),
                            "@ondc/org/title_type": "item",
                            "title": _item007.get("name", "Test Item"),
                            "price": {"currency": fpg.currency, "value": _item007.get("price", "450.00")},
                        },
                        {
                            "@ondc/org/item_id": "1",
                            "@ondc/org/title_type": "delivery",
                            "title": "Delivery Charges",
                            "price": {"currency": fpg.currency, "value": fpg.default_delivery_charge},
                        },
                    ],
                },
            }
        },
    }
    cases.append({
        "id": "F-TC007",
        "name": "Confirm Minimal Required Fields Only",
        "category": "Functional",
        "description": "[PASS EXPECTED] Sends /confirm with only the mandatory ONDC fields (context, order.id, provider, items, billing, fulfillments, payment). Validates Gateway does not reject valid but sparse payloads — tests resilience to minimal data.",
        "method": "POST",
        "url": f"{func_host}/confirm",
        "payload": minimal_payload,
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [200, 202],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
    })

    # F-TC008 — Complete payload (all optional fields)
    complete_payload = fpg.build()
    complete_payload["message"]["order"]["billing"].update({
        "created_at": datetime.now(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z"),
        "updated_at": datetime.now(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z"),
        "tax_number": fpg.buyer_gstin,
        "org": {"name": fpg.buyer_org_name},
    })
    complete_payload["message"]["order"]["fulfillments"][0].update({
        "tracking": True,
        "agent": {"name": "Delivery Partner", "phone": fpg.delivery_agent_phone},
        "start": {
            "location": {"gps": fpg.seller_source_gps, "address": fpg.seller_source_address},
            "contact": {"phone": fpg.seller_agent_phone},
        },
    })
    if fpg.settlement_details:
        complete_payload["message"]["order"]["payment"][
            "@ondc/org/settlement_details"
        ] = fpg.settlement_details
    cases.append({
        "id": "F-TC008",
        "name": "Confirm Complete Payload (All Optional Fields)",
        "category": "Functional",
        "description": "[PASS EXPECTED] Sends /confirm with all optional fields populated: extended billing address, settlement details (NEFT), finder fee. Validates Gateway correctly processes fully-enriched payloads without rejecting unknown optional fields.",
        "method": "POST",
        "url": f"{func_host}/confirm",
        "payload": complete_payload,
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [200, 202],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
    })

    # F-TC009 — Large order amount
    large_payload = fpg.build(order_amount="999999.99")
    large_payload["message"]["order"]["quote"]["price"]["value"] = "999999.99"
    large_payload["message"]["order"]["quote"]["breakup"][0]["price"]["value"] = "999949.99"
    large_payload["message"]["order"]["quote"]["breakup"][1]["price"]["value"] = fpg.default_delivery_charge
    cases.append({
        "id": "F-TC009",
        "name": "Confirm Large Order Amount (₹999999.99)",
        "category": "Functional",
        "description": "[PASS EXPECTED] Sends /confirm with order total ₹999999.99 (edge-case high value). Validates Gateway does not impose undocumented value limits and handles large numeric amounts in price fields correctly.",
        "method": "POST",
        "url": f"{func_host}/confirm",
        "payload": large_payload,
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [200, 202],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
    })

    # F-TC010 — Zero delivery charge (free delivery)
    _item010 = fpg.test_items[0] if fpg.test_items else {}
    _item010_price = _item010.get("price", "450.00")
    free_delivery_payload = fpg.build(order_amount=_item010_price)
    free_delivery_payload["message"]["order"]["quote"]["breakup"] = [
        {
            "@ondc/org/item_id": _item010.get("id", "item-001"),
            "@ondc/org/title_type": "item",
            "title": _item010.get("name", "Test Item"),
            "price": {"currency": fpg.currency, "value": _item010_price},
        },
        {
            "@ondc/org/item_id": "1",
            "@ondc/org/title_type": "delivery",
            "title": "Delivery Charges",
            "price": {"currency": fpg.currency, "value": "0.00"},
        },
    ]
    cases.append({
        "id": "F-TC010",
        "name": "Confirm Free Delivery (Zero Delivery Charge)",
        "category": "Functional",
        "description": "[PASS EXPECTED] Sends /confirm with delivery charge = ₹0.00 in the quote breakup. Validates Gateway correctly handles zero-value line items — a common scenario for free-delivery promotional orders.",
        "method": "POST",
        "url": f"{func_host}/confirm",
        "payload": free_delivery_payload,
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [200, 202],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
    })

    # F-TC011 — Same transaction ID, different message IDs (retry pattern)
    shared_txn = f"txn-{uuid.uuid4().hex[:12]}"
    for i in range(3):
        retry_payload = fpg.build(
            transaction_id=shared_txn,
            message_id=f"msg-retry-{uuid.uuid4().hex[:10]}",
        )
        cases.append({
            "id": f"F-TC011-Req{i + 1}",
            "name": f"Confirm Same TxnID / Different MsgID — Req {i + 1}",
            "category": "Functional",
            "description": f"[PASS EXPECTED] Retry scenario: reuses the same transaction_id ('{shared_txn}') but sends a fresh message_id. Request {i + 1} of 3. Validates Gateway idempotency — repeated confirms within the same transaction must be accepted.",
            "method": "POST",
            "url": f"{func_host}/confirm",
            "payload": retry_payload,
            "raw_body": None,
            "raw_content_type": None,
            "expected_status": [200, 202],
            "auth_mode": "valid",
            "custom_headers": None,
            "ttl": None,
            "sleep_before": None,
        })

    # F-TC012 — High item quantity (bulk order)
    cases.append({
        "id": "F-TC012",
        "name": "Confirm High Item Quantity (Bulk Order)",
        "category": "Functional",
        "description": "[PASS EXPECTED] Sends /confirm with item quantity=100 (bulk purchase). Validates Gateway accepts large quantity values in order items without imposing undocumented quantity caps.",
        "method": "POST",
        "url": f"{func_host}/confirm",
        "payload": fpg.build(item_quantity=100),
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [200, 202],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
    })

    # F-TC013 — Unicode characters in buyer name / address
    unicode_buyers = [
        {"name": "राम कुमार", "address": "१२३ परीक्षण सड़क, बेंगलुरु"},
        {"name": "ராம் குமார்", "address": "123 சோதனை தெரு, பெங்களூரு"},
        {"name": "ರಾಮ್ ಕುಮಾರ್", "address": "123 ಮೈಸೂರ್ ರಸ್ತೆ, ಬೆಂಗಳೂರು"},
    ]
    for idx, buyer in enumerate(unicode_buyers):
        u_payload = fpg.build()
        u_payload["message"]["order"]["billing"].update({
            "name": buyer["name"],
            "address": buyer["address"],
        })
        cases.append({
            "id": f"F-TC013-{idx}",
            "name": f"Confirm Unicode Buyer Info ({idx})",
            "category": "Functional",
            "description": f"[PASS EXPECTED] Sends /confirm with buyer name in non-ASCII script: '{buyer['name']}'. Validates Gateway correctly accepts and forwards Unicode characters in billing fields (Hindi, Arabic, Chinese).",
            "method": "POST",
            "url": f"{func_host}/confirm",
            "payload": u_payload,
            "raw_body": None,
            "raw_content_type": None,
            "expected_status": [200, 202],
            "auth_mode": "valid",
            "custom_headers": None,
            "ttl": None,
            "sleep_before": None,
        })

    # F-TC014 — Different providers
    for prov in fpg.test_providers:
        pid = prov.get("id", "IGO_Seller_0001")
        prov_payload = fpg.build(provider_id=pid)
        prov_payload["message"]["order"]["provider"]["locations"] = [
            {"id": prov.get("location_id", "store-location-001")}
        ]
        cases.append({
            "id": f"F-TC014-{pid}",
            "name": f"Confirm Different Provider: {pid}",
            "category": "Functional",
            "description": f"[PASS EXPECTED] Sends /confirm targeting seller provider ID='{pid}'. Validates Gateway routes the confirmation to the correct BPP based on the provider ID in the order payload.",
            "method": "POST",
            "url": f"{func_host}/confirm",
            "payload": prov_payload,
            "raw_body": None,
            "raw_content_type": None,
            "expected_status": [200, 202],
            "auth_mode": "valid",
            "custom_headers": None,
            "ttl": None,
            "sleep_before": None,
        })

    # F-TC015 — Payment NOT-PAID (cash-on-delivery)
    cod_payment = {"type": "ON-FULFILLMENT", "status": "NOT-PAID", "collected_by": "BPP"}
    cases.append({
        "id": "F-TC015",
        "name": "Confirm Payment Status NOT-PAID (COD)",
        "category": "Functional",
        "description": "[PASS EXPECTED] Sends /confirm with payment.status=NOT-PAID and type=ON-FULFILLMENT (COD). Validates Gateway accepts cash-on-delivery orders where payment is collected by the seller at the time of delivery.",
        "method": "POST",
        "url": f"{func_host}/confirm",
        "payload": fpg.build(payment_type=cod_payment),
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [200, 202],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
    })

    # F-TC016 — Health check
    cases.append({
        "id": "F-TC016",
        "name": "Gateway Health Check",
        "category": "Functional",
        "description": "[PASS EXPECTED] Sends HTTP GET /health. Verifies the Gateway service is up and responding. A failed result here indicates a connectivity or infrastructure issue, not an application bug.",
        "method": "GET",
        "url": f"{func_host}/health",
        "payload": None,
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [200],
        "auth_mode": "no_auth",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
    })

    # =========================================================================
    # on_confirm FUNCTIONAL TEST CASES  (backward flow: BPP → Gateway → BAP)
    # Baseline from Postman collection: Sync/Backward/on_confirm
    # =========================================================================

    ocpg = OnConfirmPayloadGenerator(func_cfg)
    on_confirm_url = f"{func_host}/on_confirm"

    # F-TC017 — Valid on_confirm: order state=Created (Postman baseline)
    cases.append({
        "id": "F-TC017",
        "name": "on_confirm Valid Callback — Order Created",
        "category": "Functional",
        "description": "[PASS EXPECTED] Sends a valid /on_confirm callback (BPP → Gateway → BAP) with order.state=Created. This is the primary backward-flow scenario matching the Postman collection baseline — seller confirms the order and notifies the buyer app.",
        "method": "POST",
        "url": on_confirm_url,
        "payload": ocpg.build(order_state="Created"),
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [200, 202],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
    })

    # F-TC018 — on_confirm order state=Accepted
    cases.append({
        "id": "F-TC018",
        "name": "on_confirm Order State — Accepted",
        "category": "Functional",
        "description": "[PASS EXPECTED] Sends /on_confirm with order.state=Accepted. Validates Gateway routes the acknowledgment back to the BAP when the seller's system transitions the order from Created to Accepted state.",
        "method": "POST",
        "url": on_confirm_url,
        "payload": ocpg.build(order_state="Accepted"),
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [200, 202],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
    })

    # F-TC019 — on_confirm order state=In-progress
    cases.append({
        "id": "F-TC019",
        "name": "on_confirm Order State — In-progress",
        "category": "Functional",
        "description": "[PASS EXPECTED] Sends /on_confirm with order.state=In-progress. Validates Gateway handles mid-lifecycle state callbacks where the seller notifies the buyer app that order preparation has started.",
        "method": "POST",
        "url": on_confirm_url,
        "payload": ocpg.build(order_state="In-progress"),
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [200, 202],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
    })

    # F-TC020 — on_confirm Pickup fulfillment type
    cases.append({
        "id": "F-TC020",
        "name": "on_confirm Fulfillment Type — Pickup",
        "category": "Functional",
        "description": "[PASS EXPECTED] Sends /on_confirm with fulfillment.type=Pickup (store pickup). Validates Gateway correctly processes confirmation callbacks for click-and-collect orders where the buyer collects from the seller's physical location.",
        "method": "POST",
        "url": on_confirm_url,
        "payload": ocpg.build(
            order_state="Created",
            fulfillment_type="Pickup",
            fulfillment_state_code="Pending",
        ),
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [200, 202],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
    })

    # F-TC021 — on_confirm PRE-FULFILLMENT payment
    cases.append({
        "id": "F-TC021",
        "name": "on_confirm Payment Type — PRE-FULFILLMENT",
        "category": "Functional",
        "description": "[PASS EXPECTED] Sends /on_confirm with payment.type=PRE-FULFILLMENT and status=PAID. Validates Gateway routes the confirmation callback for pre-paid orders — a common scenario in online payment flows.",
        "method": "POST",
        "url": on_confirm_url,
        "payload": ocpg.build(
            order_state="Created",
            payment_type="PRE-FULFILLMENT",
            payment_status="PAID",
        ),
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [200, 202],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
    })

    # F-TC022 — on_confirm POST-FULFILLMENT (COD / cash-on-delivery)
    cases.append({
        "id": "F-TC022",
        "name": "on_confirm Payment Type — POST-FULFILLMENT (COD)",
        "category": "Functional",
        "description": "[PASS EXPECTED] Sends /on_confirm with payment.type=POST-FULFILLMENT and status=NOT-PAID (COD). Validates Gateway routes confirmation callbacks for cash-on-delivery orders where payment is yet to be collected.",
        "method": "POST",
        "url": on_confirm_url,
        "payload": ocpg.build(
            order_state="Created",
            payment_type="POST-FULFILLMENT",
            payment_status="NOT-PAID",
        ),
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [200, 202],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
    })

    # F-TC023 — on_confirm with error object (order rejected / item unavailable)
    cases.append({
        "id": "F-TC023",
        "name": "on_confirm With Error — Order Rejected (Item Unavailable)",
        "category": "Functional",
        "description": "[PASS EXPECTED] Sends /on_confirm with order.state=Cancelled and an error block (code 20006 — item unavailable). Validates Gateway correctly routes seller rejection callbacks back to the BAP so it can inform the buyer.",
        "method": "POST",
        "url": on_confirm_url,
        "payload": ocpg.build(
            order_state="Cancelled",
            include_error={"type": "DOMAIN-ERROR", "code": "20006", "message": "Item not available"},
        ),
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [200, 202],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
    })

    # F-TC024 — on_confirm with tracking=false (no live tracking)
    cases.append({
        "id": "F-TC024",
        "name": "on_confirm Tracking Disabled",
        "category": "Functional",
        "description": "[PASS EXPECTED] Sends /on_confirm with fulfillment.tracking=false. Validates Gateway accepts confirmation payloads where the seller does not support live parcel tracking — a valid configuration for small sellers.",
        "method": "POST",
        "url": on_confirm_url,
        "payload": ocpg.build(order_state="Created", tracking=False),
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [200, 202],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
    })

    # =========================================================================
    # NEGATIVE TEST CASES
    # =========================================================================

    # N-TC001 — Missing Authorization header
    cases.append({
        "id": "N-TC001",
        "name": "Confirm Missing Authorization Header",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401] Sends /confirm without any Authorization header. The Gateway must reject unauthenticated requests with HTTP 401. A 200 response here would indicate a critical security vulnerability.",
        "method": "POST",
        "url": f"{neg_host}/confirm",
        "payload": npg.build(),
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [401, 400],
        "auth_mode": "custom",
        "custom_headers": {"Content-Type": "application/json; charset=utf-8"},
        "ttl": None,
        "sleep_before": None,
    })

    # N-TC002 — Invalid / tampered signature
    cases.append({
        "id": "N-TC002",
        "name": "Confirm Invalid / Tampered Signature",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401] Sends /confirm with a valid Authorization header structure but the signature bytes are altered. The Gateway must detect the tampered Ed25519 signature and reject the request, preventing request forgery.",
        "method": "POST",
        "url": f"{neg_host}/confirm",
        "payload": npg.build(),
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [401, 400],
        "auth_mode": "tamper_sig",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
    })

    # [N/A] # N-TC003 — Invalid Digest header
    # [N/A] cases.append({
    # [N/A] "id": "N-TC003",
    # [N/A] "name": "Confirm Invalid Digest Header",
    # [N/A] "category": "Negative",
    # [N/A] "description": "[FAIL EXPECTED — 401/400] Sends /confirm with the Digest header replaced by an invalid value. The Gateway must reject the request because the payload integrity check (BLAKE2b digest) fails, preventing payload tampering attacks.",
    # [N/A] "method": "POST",
    # [N/A] "url": f"{neg_host}/confirm",
    # [N/A] "payload": npg.build(),
    # [N/A] "raw_body": None,
    # [N/A] "raw_content_type": None,
    # [N/A] "expected_status": [412, 401, 400],
    # [N/A] "auth_mode": "tamper_digest",
    # [N/A] "custom_headers": None,
    # [N/A] "ttl": None,
    # [N/A] "sleep_before": None,
    # [N/A] })

    # N-TC004 — Missing context.domain
    no_domain = npg.build()
    del no_domain["context"]["domain"]
    cases.append({
        "id": "N-TC004",
        "name": "Confirm Missing context.domain",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 200 NACK / 400 / 422 / 401] Sends /confirm with context.domain omitted. The ONDC spec mandates domain for routing. The Gateway must reject the request — either via HTTP 200 with NACK+error (ONDC protocol pattern) or a 4xx status code.",
        "method": "POST",
        "url": f"{neg_host}/confirm",
        "payload": no_domain,
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [200, 400, 422, 401],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
        "expected_error_code": "10002",
    })

    # N-TC005 — Missing context.bpp_id
    no_bpp = npg.build()
    del no_bpp["context"]["bpp_id"]
    cases.append({
        "id": "N-TC005",
        "name": "Confirm Missing context.bpp_id",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 200 NACK / 400 / 422 / 401] Sends /confirm with context.bpp_id omitted. Without the BPP identifier the Gateway cannot route the request to a seller platform. The Gateway must reject via HTTP 200 NACK+error or a 4xx status code.",
        "method": "POST",
        "url": f"{neg_host}/confirm",
        "payload": no_bpp,
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [200, 400, 422, 401],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
        "expected_error_code": "10002",
    })

    # N-TC006 — Missing message.order.id
    no_order_id = npg.build()
    del no_order_id["message"]["order"]["id"]
    cases.append({
        "id": "N-TC006",
        "name": "Confirm Missing message.order.id",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 200 NACK / 400 / 422 / 401] Sends /confirm with message.order.id missing. Order ID is mandatory for the seller to associate the confirmation with an existing pending order. The Gateway must reject via HTTP 200 NACK+error or a 4xx status code.",
        "method": "POST",
        "url": f"{neg_host}/confirm",
        "payload": no_order_id,
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [200, 400, 422, 401],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
        "expected_error_code": "10006",
    })

    # N-TC007 — Missing message.order.billing
    no_billing = npg.build()
    del no_billing["message"]["order"]["billing"]
    cases.append({
        "id": "N-TC007",
        "name": "Confirm Missing message.order.billing",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 200 NACK / 400 / 422 / 401] Sends /confirm without the message.order.billing block. Billing information is required for invoice generation and KYC compliance. The Gateway must reject via HTTP 200 NACK+error or a 4xx status code.",
        "method": "POST",
        "url": f"{neg_host}/confirm",
        "payload": no_billing,
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [200, 400, 422, 401],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
        "expected_error_code": "10006",
    })

    # N-TC008 — Missing message.order.payment
    no_payment = npg.build()
    del no_payment["message"]["order"]["payment"]
    cases.append({
        "id": "N-TC008",
        "name": "Confirm Missing message.order.payment",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 200 NACK / 400 / 422 / 401] Sends /confirm without the message.order.payment block. Payment details are required to confirm an order's financial terms. The Gateway must reject via HTTP 200 NACK+error or a 4xx status code.",
        "method": "POST",
        "url": f"{neg_host}/confirm",
        "payload": no_payment,
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [200, 400, 422, 401],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
        "expected_error_code": "10006",
    })

    # N-TC009 — Missing message.order.fulfillments
    no_fulfill = npg.build()
    del no_fulfill["message"]["order"]["fulfillments"]
    cases.append({
        "id": "N-TC009",
        "name": "Confirm Missing message.order.fulfillments",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 200 NACK / 400 / 422 / 401] Sends /confirm without the message.order.fulfillments array. Fulfillment details (delivery address, type) are mandatory for order processing. The Gateway must reject via HTTP 200 NACK+error or a 4xx status code.",
        "method": "POST",
        "url": f"{neg_host}/confirm",
        "payload": no_fulfill,
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [200, 400, 422, 401],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
        "expected_error_code": "10006",
    })

    # N-TC010 — Expired signature (TTL elapsed)
    cases.append({
        "id": "N-TC010",
        "name": "Confirm Expired Signature (TTL = 1s)",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401] Generates a valid auth signature with TTL=1s, then waits 5 seconds before sending. The signature is now expired. The Gateway must reject replay attacks using stale credentials (signature replay protection).",
        "method": "POST",
        "url": f"{neg_host}/confirm",
        "payload": npg.build(),
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [401, 400],
        "auth_mode": "expired",
        "custom_headers": None,
        "ttl": 1,
        "sleep_before": 5.0,
    })

    # N-TC011 — Invalid core_version
    bad_version = npg.build()
    bad_version["context"]["core_version"] = "99.99.99"
    cases.append({
        "id": "N-TC011",
        "name": "Confirm Invalid core_version (99.99.99)",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 200 NACK / 400 / 422 / 401] Sends /confirm with context.core_version='99.99.99' (non-existent ONDC version). The Gateway must reject via HTTP 200 NACK+error or a 4xx status code.",
        "method": "POST",
        "url": f"{neg_host}/confirm",
        "payload": bad_version,
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [200, 400, 422, 401],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
        "expected_error_code": "10002",
    })

    # N-TC012 — Invalid domain
    bad_domain = npg.build()
    bad_domain["context"]["domain"] = "INVALID:DOMAIN999"
    cases.append({
        "id": "N-TC012",
        "name": "Confirm Invalid Domain (INVALID:DOMAIN999)",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 200 NACK / 400 / 422 / 401] Sends /confirm with context.domain='INVALID:DOMAIN999' (not a registered ONDC vertical). The Gateway must reject via HTTP 200 NACK+error or a 4xx status code.",
        "method": "POST",
        "url": f"{neg_host}/confirm",
        "payload": bad_domain,
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [200, 400, 422, 401],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
        "expected_error_code": "10001",
    })

    # N-TC013 — Invalid country code
    bad_country = npg.build()
    bad_country["context"]["country"] = "XYZZY"
    cases.append({
        "id": "N-TC013",
        "name": "Confirm Invalid Country Code (XYZZY)",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 200 NACK / 400 / 422 / 401] Sends /confirm with context.country='XYZZY' (invalid ISO-3166 country code). The Gateway must reject via HTTP 200 NACK+error or a 4xx status code.",
        "method": "POST",
        "url": f"{neg_host}/confirm",
        "payload": bad_country,
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [200, 400, 422, 401],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
        "expected_error_code": "10002",
    })

    # N-TC014 — Malformed JSON structure (valid JSON, wrong ONDC shape)
    cases.append({
        "id": "N-TC014",
        "name": "Confirm Malformed JSON Structure",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 200 NACK / 400 / 422 / 401] Sends a valid JSON payload that has no ONDC fields (e.g., {\"foo\": \"bar\"}). The Gateway must reject via HTTP 200 NACK+error or a 4xx status code.",
        "method": "POST",
        "url": f"{neg_host}/confirm",
        "payload": {"wrong_root": "not_ondc", "random_field": 12345, "nested": {"also_wrong": True}},
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [200, 400, 422, 401],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
        "expected_error_code": "10002",
    })

    # N-TC015 — Invalid JSON syntax (raw string that is not valid JSON)
    cases.append({
        "id": "N-TC015",
        "name": "Confirm Invalid JSON Syntax (raw string)",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 400] Sends a raw non-JSON string as the request body (Content-Type: application/json). The Gateway must return 400 Bad Request when the payload cannot be parsed as JSON, protecting against malformed-input attacks.",
        "method": "POST",
        "url": f"{neg_host}/confirm",
        "payload": None,
        "raw_body": "{invalid json content}",
        "raw_content_type": "application/json",
        "expected_status": [400, 422, 401],
        "auth_mode": "custom",
        "custom_headers": {"Content-Type": "application/json"},
        "ttl": None,
        "sleep_before": None,
    })

    # N-TC016 — Empty payload {}
    cases.append({
        "id": "N-TC016",
        "name": "Confirm Empty JSON Payload ({})",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401/400] Sends an empty JSON object {} as the body. The Gateway must reject the request since context and message are mandatory top-level fields in every ONDC request.",
        "method": "POST",
        "url": f"{neg_host}/confirm",
        "payload": None,
        "raw_body": "{}",
        "raw_content_type": "application/json",
        "expected_status": [400, 422, 401],
        "auth_mode": "custom",
        "custom_headers": {"Content-Type": "application/json"},
        "ttl": None,
        "sleep_before": None,
    })

    # N-TC017 — Wrong HTTP method (GET to /confirm)
    cases.append({
        "id": "N-TC017",
        "name": "Confirm Wrong HTTP Method (GET)",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 404/405] Sends HTTP GET to /confirm (which only accepts POST). The Gateway must reject unsupported HTTP methods with 405 Method Not Allowed (or 404), preventing accidental data exposure via GET.",
        "method": "GET",
        "url": f"{neg_host}/confirm",
        "payload": None,
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [405, 404, 400],
        "auth_mode": "no_auth",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
    })

    # N-TC018 — Wrong Content-Type (text/plain)
    wrong_ct_payload = npg.build()
    cases.append({
        "id": "N-TC018",
        "name": "Confirm Wrong Content-Type (text/plain)",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401/400] Sends /confirm with Content-Type: text/plain instead of application/json. The Gateway must enforce the correct media type and reject requests that do not declare JSON content.",
        "method": "POST",
        "url": f"{neg_host}/confirm",
        "payload": None,
        "raw_body": json.dumps(wrong_ct_payload, separators=(",", ":"), sort_keys=False),
        "raw_content_type": "text/plain",
        "expected_status": [400, 415, 422, 401],
        "auth_mode": "custom",
        "custom_headers": {"Content-Type": "text/plain"},
        "ttl": None,
        "sleep_before": None,
    })

    # N-TC019 — Invalid Authorization header format
    cases.append({
        "id": "N-TC019",
        "name": "Confirm Invalid Authorization Header Format",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401] Sends /confirm with 'Authorization: Bearer abc123' (JWT/OAuth style) instead of the ONDC Signature scheme. The Gateway must reject incorrectly formatted authorization headers and enforce the ONDC auth standard.",
        "method": "POST",
        "url": f"{neg_host}/confirm",
        "payload": npg.build(),
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [401, 400],
        "auth_mode": "custom",
        "custom_headers": {
            "Authorization": "Bearer invalid_token_value",
            "Content-Type": "application/json",
        },
        "ttl": None,
        "sleep_before": None,
    })

    # N-TC020 — Expired timestamp in context (30 min in the past)
    expired_ts_payload = npg.build()
    old_time = (datetime.now(timezone.utc) - timedelta(minutes=30)).isoformat(
        timespec="milliseconds"
    ).replace("+00:00", "Z")
    expired_ts_payload["context"]["timestamp"] = old_time
    cases.append({
        "id": "N-TC020",
        "name": "Confirm Expired Timestamp in Context (−30 min)",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 200 NACK / 400 / 401 / 408] Sends /confirm with context.timestamp set 30 minutes in the past (auth signature is still fresh). The Gateway must reject requests with stale context timestamps via HTTP 200 NACK+error or a 4xx status code.",
        "method": "POST",
        "url": f"{neg_host}/confirm",
        "payload": expired_ts_payload,
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [200, 400, 401, 408],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
        "expected_error_code": "10006",
    })

    # N-TC021 — Quote price mismatch (breakup ≠ total)
    mismatch_payload = npg.build()
    mismatch_payload["message"]["order"]["quote"]["breakup"][0]["price"]["value"] = "100.00"
    cases.append({
        "id": "N-TC021",
        "name": "Confirm Quote Price Mismatch (Breakup ≠ Total)",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 200 NACK / 400 / 422 / 401] Sends /confirm where quote.breakup items sum does not match quote.price.value. The Gateway must detect price inconsistencies via HTTP 200 NACK+error or a 4xx status code.",
        "method": "POST",
        "url": f"{neg_host}/confirm",
        "payload": mismatch_payload,
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [200, 400, 422, 401],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
        "expected_error_code": "10006",
    })

    # N-TC022 — Missing items array
    no_items = npg.build()
    del no_items["message"]["order"]["items"]
    cases.append({
        "id": "N-TC022",
        "name": "Confirm Missing Items Array",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 200 NACK / 400 / 422 / 401] Sends /confirm with message.order.items missing. The Gateway must reject via HTTP 200 NACK+error or a 4xx status code.",
        "method": "POST",
        "url": f"{neg_host}/confirm",
        "payload": no_items,
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [200, 400, 422, 401],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
        "expected_error_code": "10006",
    })

    # N-TC023 — Missing provider block
    no_provider = npg.build()
    del no_provider["message"]["order"]["provider"]
    cases.append({
        "id": "N-TC023",
        "name": "Confirm Missing Provider Block",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 200 NACK / 400 / 422 / 401] Sends /confirm with message.order.provider omitted. The Gateway must reject via HTTP 200 NACK+error or a 4xx status code.",
        "method": "POST",
        "url": f"{neg_host}/confirm",
        "payload": no_provider,
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [200, 400, 422, 401],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
        "expected_error_code": "10006",
    })

    # N-TC024 — Missing quote block
    no_quote = npg.build()
    del no_quote["message"]["order"]["quote"]
    cases.append({
        "id": "N-TC024",
        "name": "Confirm Missing Quote Block",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 200 NACK / 400 / 422 / 401] Sends /confirm without the message.order.quote block. The Gateway must reject via HTTP 200 NACK+error or a 4xx status code.",
        "method": "POST",
        "url": f"{neg_host}/confirm",
        "payload": no_quote,
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [200, 400, 422, 401],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
        "expected_error_code": "10006",
    })

    # N-TC025 — Extremely large payload (DoS / size limit)
    dos_payload = npg.build()
    dos_payload["message"]["order"]["items"] = [
        {
            "id": f"item-{i:04d}",
            "quantity": {"count": 1},
            "descriptor": {"name": "A" * 10000, "long_desc": "B" * 10000},
        }
        for i in range(50)
    ]
    cases.append({
        "id": "N-TC025",
        "name": "Confirm Extremely Large Payload (DoS / Size Limit)",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 200 NACK / 400 / 413 / 422 / 401] Sends /confirm with 50 items each padded with 20 000-byte descriptor strings (~1 MB total). The Gateway must enforce payload size limits — either via HTTP 200 NACK+error or a 4xx/413 status code.",
        "method": "POST",
        "url": f"{neg_host}/confirm",
        "payload": dos_payload,
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [200, 400, 413, 422, 401],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
        "expected_error_code": "10006",
    })

    # =========================================================================
    # on_confirm NEGATIVE TEST CASES  (N-TC026 – N-TC033)
    # =========================================================================


    nocpg = OnConfirmPayloadGenerator(neg_cfg)
    on_confirm_neg_url = f"{neg_host}/on_confirm"

    # N-TC026 — Missing Authorization header on on_confirm
    cases.append({
        "id": "N-TC026",
        "name": "on_confirm Missing Authorization Header",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401] Sends /on_confirm without any Authorization header. The Gateway must authenticate backward-flow callbacks just as it does forward-flow requests. An unauthenticated on_confirm must be rejected to prevent spoofed seller callbacks.",
        "method": "POST",
        "url": on_confirm_neg_url,
        "payload": nocpg.build(),
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [401, 400],
        "auth_mode": "custom",
        "custom_headers": {"Content-Type": "application/json; charset=utf-8"},
        "ttl": None,
        "sleep_before": None,
    })

    # N-TC027 — Tampered signature on on_confirm
    cases.append({
        "id": "N-TC027",
        "name": "on_confirm Tampered Signature",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401] Sends /on_confirm with an altered Ed25519 signature. The Gateway must verify the signature on backward-flow callbacks to ensure only legitimate BPPs can send on_confirm responses to buyer apps.",
        "method": "POST",
        "url": on_confirm_neg_url,
        "payload": nocpg.build(),
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [401, 400],
        "auth_mode": "tamper_sig",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
    })

    # N-TC028 — Missing order.state in on_confirm
    cases.append({
        "id": "N-TC028",
        "name": "on_confirm Missing message.order.state",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 200 NACK / 400 / 401] Sends /on_confirm without message.order.state. Order state is mandatory in the backward flow. The Gateway must reject via HTTP 200 NACK+error or a 4xx status code.",
        "method": "POST",
        "url": on_confirm_neg_url,
        "payload": nocpg.build(omit_order_state=True),
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [200, 400, 401],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
        "expected_error_code": "10006",
    })

    # N-TC029 — Invalid order.state value in on_confirm
    cases.append({
        "id": "N-TC029",
        "name": "on_confirm Invalid order.state Value",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 200 NACK / 400 / 401] Sends /on_confirm with order.state='INVALID_STATE' (not a valid ONDC order state). The Gateway must reject via HTTP 200 NACK+error or a 4xx status code.",
        "method": "POST",
        "url": on_confirm_neg_url,
        "payload": nocpg.build(order_state="INVALID_STATE"),
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [200, 400, 401],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
        "expected_error_code": "10006",
    })

    # N-TC030 — Missing order.id in on_confirm
    cases.append({
        "id": "N-TC030",
        "name": "on_confirm Missing message.order.id",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 200 NACK / 400 / 401] Sends /on_confirm without message.order.id. The Gateway must reject via HTTP 200 NACK+error or a 4xx status code.",
        "method": "POST",
        "url": on_confirm_neg_url,
        "payload": nocpg.build(omit_order_id=True),
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [200, 400, 401],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
        "expected_error_code": "10006",
    })

    # N-TC031 — Missing billing block in on_confirm
    cases.append({
        "id": "N-TC031",
        "name": "on_confirm Missing Billing Block",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 200 NACK / 400 / 401] Sends /on_confirm without the message.order.billing block. The Gateway must reject via HTTP 200 NACK+error or a 4xx status code.",
        "method": "POST",
        "url": on_confirm_neg_url,
        "payload": nocpg.build(omit_billing=True),
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [200, 400, 401],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
        "expected_error_code": "10006",
    })

    # N-TC032 — Missing fulfillments array in on_confirm
    cases.append({
        "id": "N-TC032",
        "name": "on_confirm Missing Fulfillments Array",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 200 NACK / 400 / 401] Sends /on_confirm missing message.order.fulfillments. The Gateway must reject via HTTP 200 NACK+error or a 4xx status code.",
        "method": "POST",
        "url": on_confirm_neg_url,
        "payload": nocpg.build(omit_fulfillments=True),
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [200, 400, 401],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
        "expected_error_code": "10006",
    })

    # N-TC033 — Missing bap_id in on_confirm context (routing failure)
    cases.append({
        "id": "N-TC033",
        "name": "on_confirm Missing context.bap_id (Routing Failure)",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 200 NACK / 400 / 401] Sends /on_confirm with an empty context.bap_id. Without the BAP identifier the Gateway cannot route the callback back to the buyer app. The Gateway must reject via HTTP 200 NACK+error or a 4xx status code.",
        "method": "POST",
        "url": on_confirm_neg_url,
        "payload": nocpg.build(omit_bap_id=True),
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [200, 400, 401],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
        "expected_error_code": None,
    })

    return cases


# ---------------------------------------------------------------------------
# ONDC response helpers
# ---------------------------------------------------------------------------
def _is_nack(body: str) -> bool:
    """Return True if the response body is an ONDC NACK (message.ack.status == NACK)."""
    try:
        data = json.loads(body)
        return str(data.get("message", {}).get("ack", {}).get("status", "")).upper() == "NACK"
    except Exception:
        return False


def _get_error_code(body: str) -> Optional[str]:
    """Extract error.code from an ONDC NACK response body, or None if not present."""
    try:
        data = json.loads(body)
        code = data.get("error", {}).get("code", "")
        return str(code) if code else None
    except Exception:
        return None


def _get_error_type(body: str) -> Optional[str]:
    """Extract error.type from an ONDC NACK response body, or None if not present."""
    try:
        data = json.loads(body)
        t = data.get("error", {}).get("type", "")
        return str(t) if t else None
    except Exception:
        return None


def _load_error_catalogue() -> dict:
    """Load ondc_gateway_error_codes.yml and return a code → entry dict."""
    catalogue_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "resources", "gateway", "ondc_gateway_error_codes.yml",
    )
    try:
        with open(catalogue_path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        return {str(k): v for k, v in data.get("error_codes", {}).items()}
    except Exception as exc:
        logger.warning(f"Could not load error catalogue: {exc}")
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
    """Execute a single test case and return a result dict."""

    auth = func_auth if tc["category"] == "Functional" else neg_auth

    # Resolve headers
    headers: Dict[str, str] = {}
    auth_note = ""

    if tc["auth_mode"] == "valid":
        if auth and tc["payload"] is not None:
            try:
                headers = auth.generate_headers(tc["payload"])
            except Exception as exc:
                headers = {"Content-Type": "application/json"}
                auth_note = f"Auth generation failed: {exc}"
        else:
            headers = {"Content-Type": "application/json"}
            auth_note = "No auth helper available"

    elif tc["auth_mode"] == "no_auth":
        headers = {}

    elif tc["auth_mode"] == "custom":
        headers = dict(tc.get("custom_headers") or {})
        auth_note = "Custom headers (no ONDC auth)"

    elif tc["auth_mode"] == "tamper_sig":
        if auth and tc["payload"] is not None:
            try:
                headers = auth.generate_tampered_sig_headers(tc["payload"])
                auth_note = "Signature deliberately tampered"
            except Exception as exc:
                headers = {"Content-Type": "application/json"}
                auth_note = f"Auth generation failed: {exc}"
        else:
            headers = {"Content-Type": "application/json"}
            auth_note = "No auth helper — cannot tamper"

    elif tc["auth_mode"] == "tamper_digest":
        if auth and tc["payload"] is not None:
            try:
                headers = auth.generate_tampered_digest_headers(tc["payload"])
                auth_note = "Digest header deliberately corrupted"
            except Exception as exc:
                headers = {"Content-Type": "application/json"}
                auth_note = f"Auth generation failed: {exc}"
        else:
            headers = {"Content-Type": "application/json"}
            auth_note = "No auth helper — cannot tamper digest"

    elif tc["auth_mode"] == "expired":
        ttl = tc.get("ttl") or 1
        if auth and tc["payload"] is not None:
            try:
                headers = auth.generate_headers(tc["payload"], ttl=ttl)
                auth_note = f"Auth generated with TTL={ttl}s (will expire)"
            except Exception as exc:
                headers = {"Content-Type": "application/json"}
                auth_note = f"Auth generation failed: {exc}"
        else:
            headers = {"Content-Type": "application/json"}
            auth_note = "No auth helper"

    # Remove internal serialized_body key (not a real header)
    headers.pop("serialized_body", None)

    # Optional pre-request sleep (for expired-signature tests) — capped at 15s
    _MAX_SLEEP_BEFORE = 15
    sleep_s = tc.get("sleep_before")
    if sleep_s:
        total = min(int(sleep_s), _MAX_SLEEP_BEFORE)
        logger.info(f"  [test-case] Sleeping {total}s for signature expiry …")
        for remaining in range(total, 0, -1):
            print(f"\r  [test-case] Sending in {remaining:3d}s ...   ", end="", flush=True)
            time.sleep(1)
        print(f"\r  [test-case] Wait complete — sending now.              ", flush=True)

    # Determine request body
    body_str: Optional[str] = None
    if tc.get("raw_body") is not None:
        body_str = str(tc["raw_body"])
    elif tc["payload"] is not None:
        body_str = json.dumps(tc["payload"], separators=(",", ":"), sort_keys=False, ensure_ascii=False)

    # Capture request details
    req_url = tc["url"]
    req_headers_display = dict(headers)
    req_body_display = None
    if tc["payload"] is not None:
        req_body_display = json.dumps(tc["payload"], indent=2, ensure_ascii=False)
    elif tc.get("raw_body") is not None:
        req_body_display = str(tc["raw_body"])

    # Execute request
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

    # Determine PASS / FAIL
    if error_msg:
        passed = False
        status_note = f"ERROR — {error_msg}"
    elif resp_status in tc["expected_status"]:
        # Functional tests: HTTP 2xx + NACK body = the Gateway rejected a valid request = FAIL.
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
                f"HTTP {resp_status} — NACK received for a valid request — "
                f"error.code={nack_code}{type_note}{msg_note}"
            )
        # Negative tests: HTTP 200 is only a pass when the body is a NACK.
        # An HTTP 200 ACK means the Gateway accepted a request it should have rejected.
        elif tc["category"] == "Negative" and resp_status == 200 and not _is_nack(resp_body):
            passed = False
            status_note = f"HTTP {resp_status} — received ACK (expected NACK or 4xx error response)"
        elif (
            tc["category"] == "Negative"
            and resp_status == 200
            and expected_error_code
            and actual_error_code != expected_error_code
        ):
            passed = False
            status_note = (
                f"HTTP {resp_status} — NACK received but error.code={actual_error_code!r} "
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
                f"HTTP {resp_status} — NACK received but error.type={actual_error_type!r} "
                f"(expected {expected_error_type!r} per catalogue)"
            )
        else:
            passed = True
            code_note = f", error.code={actual_error_code}" if actual_error_code else ""
            type_note = f", error.type={actual_error_type}" if actual_error_type else ""
            status_note = f"HTTP {resp_status} — expected one of {tc['expected_status']}{code_note}{type_note}"
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
                f"HTTP {resp_status} — expected one of {tc['expected_status']}"
                f"{code_note}{type_note}{msg_note} [NACK received but wrong HTTP status]"
            )
        else:
            status_note = f"HTTP {resp_status} — expected one of {tc['expected_status']}"

    logger.info(
        f"  [{tc['id']}] {'PASS' if passed else 'FAIL'}  "
        f"HTTP {resp_status}  {elapsed_ms}ms  {tc['name']}"
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
# HTML report generator  (dark theme — matches generate_gateway_confirm_combined reference)
# ---------------------------------------------------------------------------
def _esc(text: str) -> str:
    """HTML-escape a string."""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def generate_html_report(results: List[Dict[str, Any]], output_path: str, run_ts: str) -> None:
    total = len(results)
    total = len(results)
    passed = sum(1 for r in results if r["passed"])
    failed = total - passed
    func_total = sum(1 for r in results if r["category"] == "Functional")
    neg_total = total - func_total
    pass_pct = round((passed / total * 100) if total else 0, 1)
    avg_ms = round(
        sum(r["elapsed_ms"] for r in results) / total if total else 0, 0
    )
    avg_s = round(avg_ms / 1000, 3)

    # Unique suite names for filter buttons
    suite_ids = []
    seen = set()
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

        # HTTP status chip class
        sc = r["resp_status"]
        if sc is None:
            sc_cls = "sc-none"
            sc_display = "N/A"
        elif sc < 300:
            sc_cls = "sc-2xx"
            sc_display = f"HTTP {sc}"
        elif sc < 500:
            sc_cls = "sc-4xx"
            sc_display = f"HTTP {sc}"
        else:
            sc_cls = "sc-5xx"
            sc_display = f"HTTP {sc}"

        elapsed_s = round(r["elapsed_ms"] / 1000, 3)

        # Request body pretty JSON
        req_body_str = r.get("req_body") or ""
        if req_body_str:
            try:
                req_body_str = json.dumps(json.loads(req_body_str), indent=2, ensure_ascii=False)
            except (ValueError, TypeError):
                pass

        # Response body
        resp_body_str = r.get("resp_body") or ""

        # Request headers JSON block
        req_hdrs_json = json.dumps(r.get("req_headers", {}), indent=2, ensure_ascii=False)

        # Status details JSON block
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
    # ---- build suite filter buttons ----
    suite_btns = ""
    for sid, slabel in suite_ids:
        suite_btns += f'<button class="fbtn suite" data-suite="{_esc(sid)}" onclick="setSuite(this,\'{_esc(sid)}\')">{_esc(slabel)}</button>'

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>ONDC Gateway Confirm API Test Report</title>
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
.fbtn:hover {{ border-color: #818cf8; color: #e2e8f0; }}
.fbtn.active {{ background: #818cf8; border-color: #818cf8; color: #fff; }}
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
    background: rgba(129,140,248,.18);
    color: #c7d2fe;
    flex-shrink: 0;
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
.auth-chip {{
    font-size: .68rem;
    font-weight: 700;
    padding: 2px 8px;
    border-radius: 6px;
    background: rgba(245,158,11,.1);
    color: #f59e0b;
    flex-shrink: 0;
}}
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
.col {{ padding: 0 8px; }}
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
    font-family: Consolas, 'Cascadia Code', monospace;
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
    <h1>ONDC <span>Gateway Confirm API</span> Test Report</h1>
    <p>
      <strong>Source:</strong> Gateway Confirm Functional &amp; Negative
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
    <input id="search" class="search" type="text" placeholder="Search test ID or name &hellip;" oninput="applyFilters()"/>
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
var activeFilter = 'all';
var activeSuite  = 'all';

function toggle(i) {{
  var body = document.getElementById('body-' + i);
  var chev = document.getElementById('chev-' + i);
  var open = body.style.display === 'block';
  body.style.display = open ? 'none' : 'block';
  chev.classList.toggle('open', !open);
}}

function setFilter(btn, f) {{
  activeFilter = f;
  document.querySelectorAll('.fbtn[data-f]').forEach(function(b) {{ b.classList.remove('active'); }});
  btn.classList.add('active');
  applyFilters();
}}

function setSuite(btn, s) {{
  activeSuite = s;
  document.querySelectorAll('.fbtn.suite').forEach(function(b) {{ b.classList.remove('active'); }});
  btn.classList.add('active');
  applyFilters();
}}

function applyFilters() {{
  var q = (document.getElementById('search').value || '').toLowerCase();
  var cards = document.querySelectorAll('#container .card');
  var visible = 0;
  cards.forEach(function(c) {{
    var nameMatch   = !q || (c.dataset.name || '').toLowerCase().includes(q);
    var filterMatch = activeFilter === 'all' ||
                      (activeFilter === 'pass' && c.classList.contains('pass')) ||
                      (activeFilter === 'fail' && c.classList.contains('fail'));
    var suiteMatch  = activeSuite === 'all' || c.dataset.suite === activeSuite;
    var show = nameMatch && filterMatch && suiteMatch;
    c.style.display = show ? '' : 'none';
    if (show) visible++;
  }});
  document.getElementById('count').textContent = visible + ' of {total} shown';
}}

applyFilters();
</script>
</body>
</html>
"""

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    logger.info(f"HTML report saved → {output_path}")


# ---------------------------------------------------------------------------
# BAP Participant Registration (UAT one-time setup)
# Reads all values dynamically from the loaded YAML config.
# ---------------------------------------------------------------------------
_REG_LOC_ID  = "loc-gw-bap-001"
_REG_URI_ID  = "uri-gw-bap-001"
_REG_TIMEOUT = 15


def _reg_get_admin_token(cfg: dict) -> str:
    admin_api_url  = str(cfg.get("registry_url") or "")
    admin_auth_url = str(cfg.get("admin_auth_url") or "")
    admin_email    = str(cfg.get("admin_email") or "")
    admin_password = str(cfg.get("admin_password") or "")
    if not all([admin_api_url, admin_auth_url, admin_email, admin_password]):
        raise RuntimeError(
            "Registry admin credentials missing from YAML config. "
            "Ensure registry_url, admin_auth_url, admin_email, and admin_password are set."
        )
    try:
        from tests.utils.registry_auth_client import RegistryAuthClient
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        client = RegistryAuthClient(
            base_url=admin_api_url,
            username=admin_email,
            password=admin_password,
            auth_url=admin_auth_url,
            verify=False,
        )
        return client.get_token()
    except Exception as exc:
        raise RuntimeError(f"Admin login failed: {exc}") from exc


def _reg_derive_signing_pub(private_key_seed_b64: str) -> str:
    import base64 as _b64
    raw = _b64.b64decode(private_key_seed_b64)
    seed = raw[:32] if len(raw) == 64 else raw[-32:]
    if not _HAS_CRYPTO:
        raise RuntimeError("cryptography package required for key derivation.")
    priv = Ed25519PrivateKey.from_private_bytes(seed)
    return _b64.b64encode(priv.public_key().public_bytes_raw()).decode()


def _reg_build_payload(cfg: dict, signing_pub: str, enc_pub: str) -> dict:
    participant_id = str(cfg.get("participant_id", ""))
    uk_id          = str(cfg.get("uk_id", ""))
    bap_uri        = str(cfg.get("bap_uri", ""))
    domains        = cfg.get("domains", ["ONDC:RET10"])
    cities         = cfg.get("cities", ["std:080"])
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
                                       "legal_name": "Gateway Test BAP Pvt Ltd"}}],
        "contacts": [{"contact_id": "contact-tech-gw-bap-001", "type": "TECHNICAL",
                      "name": "GW Test Tech", "email": "gw-tech@participant.ondc",
                      "phone": "+919876543210", "is_primary": True}],
        "key": {"uk_id": uk_id, "signing_public_key": signing_pub,
                "encryption_public_key": enc_pub,
                "signed_algorithm": "ED25519", "encryption_algorithm": "X25519",
                "valid_from": "2024-01-01T00:00:00.000Z",
                "valid_until": "2026-12-31T23:59:59.000Z"},
        "location": {"location_id": _REG_LOC_ID, "type": "SERVICEABLE",
                     "country": "IND", "city": cities[:1]},
        "uri": {"uri_id": _REG_URI_ID, "type": "CALLBACK", "url": bap_uri},
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
    """
    Register the UAT test BAP participant in the Registry (one-time setup).
    All values are read from the loaded YAML config dict.
    Skips silently if already registered.
    """
    import base64 as _b64
    import os as _os

    participant_id      = str(cfg.get("participant_id", ""))
    uk_id               = str(cfg.get("uk_id", ""))
    private_key_seed    = str(cfg.get("private_key_seed", ""))
    registry_url        = str(cfg.get("registry_url", "https://registry-uat.kynondc.net"))

    logger.info("--- BAP Participant Registration (UAT) ---")
    logger.info(f"Participant : {participant_id}  UK: {uk_id}")

    try:
        signing_pub = _reg_derive_signing_pub(private_key_seed)
        enc_pub = _b64.b64encode(_os.urandom(32)).decode()
    except Exception as exc:
        logger.warning(f"[registration] Key derivation failed: {exc} — skipping.")
        return

    try:
        token = _reg_get_admin_token(cfg)
    except Exception as exc:
        logger.warning(f"[registration] Could not obtain admin token: {exc} — skipping.")
        return

    url     = f"{registry_url.rstrip('/')}/admin/subscribe"
    payload = _reg_build_payload(cfg, signing_pub, enc_pub)
    wire    = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    try:
        resp = requests.post(url, data=wire.encode(), headers=headers,
                             timeout=_REG_TIMEOUT, verify=_SSL_VERIFY)
        body = resp.text
    except Exception as exc:
        logger.warning(f"[registration] HTTP request failed: {exc} — skipping.")
        return

    if resp.status_code in (200, 202) and not _is_nack(body):
        logger.info(f"[registration] {participant_id} registered successfully.")
    elif _reg_already_registered(body):
        logger.info(f"[registration] Participant already registered — skipping.")
    else:
        logger.warning(f"[registration] Registration returned HTTP {resp.status_code}. "
                       "Tests will proceed — participant may already exist.")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(
        description="ONDC Gateway Confirm API Test Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--output",
        default=None,
        help=(
            "Output HTML report path. "
            "If omitted, auto-generated as reports/Gateway-confirm-<suite>-<timestamp>.html"
        ),
    )
    parser.add_argument(
        "--suite",
        choices=["all", "functional", "negative"],
        default="all",
        help="Which test suite to run (default: all)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="HTTP request timeout in seconds (default: 10)",
    )
    parser.add_argument(
        "--func-config",
        default="resources/gateway/ondc_gateway_confirm_functional.yml",
        help="Path to functional test YAML config (relative to project root or absolute)",
    )
    parser.add_argument(
        "--neg-config",
        default="resources/gateway/ondc_gateway_confirm_negative.yml",
        help="Path to negative test YAML config (relative to project root or absolute)",
    )
    parser.add_argument(
        "--filter",
        default=None,
        help="Run only the test case(s) whose ID starts with this string (e.g. N-TC003)",
    )
    parser.add_argument(
        "--skip-register",
        action="store_true",
        help="Skip the BAP participant registration step",
    )
    args = parser.parse_args()

    if not args.skip_register:
        pass  # registration moved after config loading

    run_ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    # File-safe timestamp: 2026-03-13_15-42-52
    ts_file = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H-%M-%S")

    # Auto-generate output filename if not provided
    if args.output:
        output_path = (
            args.output
            if os.path.isabs(args.output)
            else os.path.join(PROJECT_ROOT, args.output)
        )
    else:
        output_path = os.path.join(
            PROJECT_ROOT, "reports",
            f"Gateway-confirm-{args.suite}-{ts_file}.html",
        )

    logger.info("=" * 60)
    logger.info("ONDC Gateway Confirm API Test Runner")
    logger.info(f"Run timestamp : {run_ts}")
    logger.info(f"Suite         : {args.suite}")
    logger.info(f"Timeout       : {args.timeout}s")
    logger.info(f"Func config   : {args.func_config}")
    logger.info(f"Neg config    : {args.neg_config}")
    logger.info(f"Output        : {output_path}")
    logger.info("=" * 60)

    # Load configs (absolute path, project-relative path, or bare filename all supported)
    func_cfg = load_yaml_config(args.func_config)
    neg_cfg = load_yaml_config(args.neg_config)

    # Fail fast if required fields are missing / commented out
    validate_config(func_cfg, args.func_config, "Functional")
    validate_config(neg_cfg,  args.neg_config,  "Negative")

    # Registration uses func_cfg (loaded from YAML) — no hardcoded values
    if not args.skip_register:
        register_bap_participant(func_cfg)

    logger.info(f"Functional host : {func_cfg.get('host', 'NOT SET')}")
    logger.info(f"Negative host   : {neg_cfg.get('host', 'NOT SET')}")

    # Build auth helpers
    func_auth = build_auth_helper(func_cfg, label="Functional")
    neg_auth  = build_auth_helper(neg_cfg,  label="Negative")
    logger.info(f"Functional auth : {'enabled' if func_auth else 'disabled'}")
    logger.info(f"Negative auth   : {'enabled' if neg_auth else 'disabled'}")

    # Build test cases
    logger.info("\nBuilding test cases ...")
    all_cases = build_test_cases(func_cfg, neg_cfg, func_auth, neg_auth)

    if args.suite == "functional":
        cases = [c for c in all_cases if c["category"] == "Functional"]
    elif args.suite == "negative":
        cases = [c for c in all_cases if c["category"] == "Negative"]
    else:
        cases = all_cases

    if args.filter:
        _filters = [f.strip() for f in args.filter.split(",")]
        cases = [c for c in cases if any(c["id"].startswith(f) for f in _filters)]

    logger.info(f"Total test cases : {len(cases)}")

    # Execute all test cases
    logger.info("\nExecuting test cases ...")
    results = []
    for tc in cases:
        result = run_test_case(tc, func_auth, neg_auth, timeout=args.timeout)
        results.append(result)

    # Summary
    total = len(results)
    passed = sum(1 for r in results if r["passed"])
    failed = total - passed
    logger.info("=" * 60)
    logger.info(f"Results  Total={total}  PASS={passed}  FAIL={failed}  ({round(passed/total*100 if total else 0, 1)}%)")
    logger.info("=" * 60)

    # Generate report
    generate_html_report(results, output_path, run_ts)
    print(f"\nReport -> {output_path}")


if __name__ == "__main__":
    main()
