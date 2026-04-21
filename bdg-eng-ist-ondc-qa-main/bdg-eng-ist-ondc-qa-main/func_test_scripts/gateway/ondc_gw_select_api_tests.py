#!/usr/bin/env python3
"""
ONDC Gateway Select API - Automated Test Runner with HTML Report Generator

Runs all functional and negative test cases for the ONDC /select and /on_select
endpoints and generates a comprehensive dark-theme HTML report.

Usage:
    python func_test_scripts/gateway/ondc_gw_select_api_tests.py
    python func_test_scripts/gateway/ondc_gw_select_api_tests.py --suite functional
    python func_test_scripts/gateway/ondc_gw_select_api_tests.py --suite negative
    python func_test_scripts/gateway/ondc_gw_select_api_tests.py --timeout 30
    python func_test_scripts/gateway/ondc_gw_select_api_tests.py --output reports/my_report.html
    python func_test_scripts/gateway/ondc_gw_select_api_tests.py --func-config resources/gateway/ondc_gateway_select_functional.yml
    python func_test_scripts/gateway/ondc_gw_select_api_tests.py --neg-config  resources/gateway/ondc_gateway_select_negative.yml
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
def load_yaml_config(path: str, tenant: str = "ondcGW") -> dict:
    full_path = path if os.path.isabs(path) else os.path.join(PROJECT_ROOT, path)
    if not os.path.exists(full_path):
        logger.warning(f"Config not found: {full_path}")
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
            + f"\n\nFile: {config_path}"
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
# Select Payload Generator  (/select — forward flow)
# ---------------------------------------------------------------------------
class SelectPayloadGenerator:
    """Builds /select (forward-flow) payloads for the ONDC gateway.

    The /select request is sent by a BAP to the Gateway to request a quote
    for specific items from a particular BPP provider.  Unlike /search which
    can be broadcast, /select is always unicast (includes bpp_id in context).
    """

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

        # test_providers: may be domain-keyed dict or flat list
        raw_providers = cfg.get("test_providers", [])
        if isinstance(raw_providers, dict):
            self.test_providers = raw_providers.get(
                primary_domain,
                next(iter(raw_providers.values()), [{"id": "IGO_Seller_0001", "location_id": "store-location-001"}]),
            )
        else:
            self.test_providers = raw_providers or [{"id": "IGO_Seller_0001", "location_id": "store-location-001"}]

        # fulfillment_types: may be domain-keyed dict or flat list
        raw_ft = cfg.get("fulfillment_types", ["Delivery"])
        if isinstance(raw_ft, dict):
            raw_ft = raw_ft.get(primary_domain, next(iter(raw_ft.values()), []))
        self.fulfillment_types = [
            ft["type"] if isinstance(ft, dict) else ft for ft in raw_ft
        ] or ["Delivery"]

        # test_items: nested under test_data.{domain}.test_items; fall back to flat test_items
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

    def build(
        self,
        domain: str = None,
        city: str = None,
        transaction_id: str = None,
        message_id: str = None,
        provider_id: str = None,
        item_id: str = None,
        item_quantity: int = 1,
        fulfillment_type: str = None,
        items_list: list = None,
        omit_bpp: bool = False,
    ) -> dict:
        txn_id = transaction_id or f"txn-{uuid.uuid4().hex[:12]}"
        msg_id = message_id or f"msg-{uuid.uuid4().hex[:12]}"

        sel_domain = domain or (self.domains[0] if self.domains else "")
        sel_city = city or (self.cities[0] if self.cities else "")

        prov = self.test_providers[0] if self.test_providers else {}
        pid = provider_id or prov.get("id", "")
        loc_id = prov.get("location_id", "")

        item = self.test_items[0] if self.test_items else {}
        iid = item_id or item.get("id", "")

        ftype = fulfillment_type or (
            self.fulfillment_types[0] if self.fulfillment_types else "Delivery"
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

        ctx: dict = {
            "domain": sel_domain,
            "action": "select",
            "country": self.country,
            "city": sel_city,
            "core_version": self.core_version,
            "bap_id": self.bap_id,
            "bap_uri": self.bap_uri,
            "transaction_id": txn_id,
            "message_id": msg_id,
            "timestamp": datetime.now(timezone.utc)
                .isoformat(timespec="milliseconds")
                .replace("+00:00", "Z"),
            "ttl": self.request_ttl,
        }
        # /select is unicast — always includes bpp_id/bpp_uri
        if not omit_bpp and self.bpp_id:
            ctx["bpp_id"] = self.bpp_id
            ctx["bpp_uri"] = self.bpp_uri

        # Build items list
        if items_list:
            order_items = items_list
        else:
            order_items = [{"id": iid, "quantity": {"count": item_quantity}}]

        return {
            "context": ctx,
            "message": {
                "order": {
                    "provider": {"id": pid, "locations": [{"id": loc_id}]},
                    "items": order_items,
                    "fulfillments": [
                        {
                            "id": "1",
                            "type": ftype,
                            "end": {
                                "location": {
                                    "gps": gps,
                                    "address": {"area_code": area_code},
                                },
                            },
                        }
                    ],
                }
            },
        }


# ---------------------------------------------------------------------------
# OnSelect Payload Generator  (/on_select — backward callback from BPP)
# ---------------------------------------------------------------------------
class OnSelectPayloadGenerator:
    """Builds /on_select (backward-flow) payloads for the ONDC gateway.

    The /on_select response is sent by a BPP back through the Gateway to the BAP
    containing the quote (prices, breakup) for the items requested in /select.
    """

    def __init__(self, cfg: dict):
        self.domains = cfg.get("domains", ["ONDC:RET10"])
        self.cities = cfg.get("cities", ["std:080"])
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
            self.test_providers = raw_providers.get(
                primary_domain,
                next(iter(raw_providers.values()), [{"id": "IGO_Seller_0001", "location_id": "store-location-001"}]),
            )
        else:
            self.test_providers = raw_providers or [{"id": "IGO_Seller_0001", "location_id": "store-location-001"}]

        # test_items
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
        self.default_order_amount = str(cfg.get("default_order_amount", "500.00"))
        self.default_delivery_charge = str(cfg.get("default_delivery_charge", "50.00"))

        # fulfillment_types
        raw_ft = cfg.get("fulfillment_types", ["Delivery"])
        if isinstance(raw_ft, dict):
            raw_ft = raw_ft.get(primary_domain, next(iter(raw_ft.values()), []))
        self.fulfillment_types = [
            ft["type"] if isinstance(ft, dict) else ft for ft in raw_ft
        ] or ["Delivery"]

    def build(
        self,
        domain: str = None,
        city: str = None,
        transaction_id: str = None,
        message_id: str = None,
        include_error: dict = None,
        empty_quote: bool = False,
        omit_bpp_id: bool = False,
        omit_bap_id: bool = False,
        omit_domain: bool = False,
        omit_quote: bool = False,
        omit_provider: bool = False,
    ) -> dict:
        txn_id = transaction_id or f"txn-os-{uuid.uuid4().hex[:12]}"
        msg_id = message_id or f"msg-os-{uuid.uuid4().hex[:12]}"
        now = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")

        sel_domain = domain or (self.domains[0] if self.domains else "")
        sel_city = city or (self.cities[0] if self.cities else "")

        ctx: dict = {
            "domain": sel_domain,
            "action": "on_select",
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

        prov = self.test_providers[0] if self.test_providers else {}
        item = self.test_items[0] if self.test_items else {}
        item_price = item.get("price") or self.default_order_amount
        item_name = item.get("name", "")
        iid = item.get("id", "")
        loc_id = prov.get("location_id", "")

        ftype = self.fulfillment_types[0] if self.fulfillment_types else "Delivery"
        gps = self.test_locations[0].get("gps", "") if self.test_locations else ""
        area_code = self.test_locations[0].get("area_code", "") if self.test_locations else ""

        if omit_quote:
            order: dict = {
                "provider": {"id": prov.get("id", ""), "locations": [{"id": loc_id}]},
                "items": [{"id": iid, "quantity": {"count": 1}}],
                "fulfillments": [
                    {
                        "id": "1",
                        "type": ftype,
                        "state": {"descriptor": {"code": "Serviceable"}},
                        "end": {
                            "location": {
                                "gps": gps,
                                "address": {"area_code": area_code},
                            },
                        },
                    }
                ],
            }
        elif empty_quote:
            order = {
                "provider": {"id": prov.get("id", ""), "locations": [{"id": loc_id}]},
                "items": [],
                "fulfillments": [
                    {
                        "id": "1",
                        "type": ftype,
                        "state": {"descriptor": {"code": "Non-serviceable"}},
                    }
                ],
                "quote": {
                    "price": {"currency": self.currency, "value": "0.00"},
                    "breakup": [],
                },
            }
        else:
            order = {
                "provider": {"id": prov.get("id", ""), "locations": [{"id": loc_id}]},
                "items": [
                    {
                        "id": iid,
                        "quantity": {"available": {"count": 100}, "maximum": {"count": 10}},
                        "price": {"currency": self.currency, "value": item_price},
                        "fulfillment_id": "1",
                    }
                ],
                "fulfillments": [
                    {
                        "id": "1",
                        "type": ftype,
                        "state": {"descriptor": {"code": "Serviceable"}},
                        "@ondc/org/TAT": "P2D",
                        "end": {
                            "location": {
                                "gps": gps,
                                "address": {"area_code": area_code},
                            },
                        },
                    }
                ],
                "quote": {
                    "price": {"currency": self.currency, "value": self.default_order_amount},
                    "breakup": [
                        {
                            "@ondc/org/item_id": iid,
                            "@ondc/org/title_type": "item",
                            "title": item_name,
                            "price": {"currency": self.currency, "value": item_price},
                            "item": {"quantity": {"count": 1}},
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

        if omit_provider:
            order.pop("provider", None)

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
    func_host = func_cfg.get("host", "http://localhost:8080").rstrip("/")
    neg_host = neg_cfg.get("host", "http://localhost:8080").rstrip("/")

    spg = SelectPayloadGenerator(func_cfg)
    ospg = OnSelectPayloadGenerator(func_cfg)
    nspg = SelectPayloadGenerator(neg_cfg)
    nospg = OnSelectPayloadGenerator(neg_cfg)

    cases: List[Dict[str, Any]] = []

    # =========================================================================
    # FUNCTIONAL TEST CASES  (/select forward + /on_select backward)
    # =========================================================================

    # F-TC001 — Valid /select with authentication
    cases.append({
        "id": "F-TC001",
        "name": "Select Valid Authenticated Request",
        "category": "Functional",
        "description": "[PASS EXPECTED] Sends a complete, correctly signed /select request with provider, items and fulfillment. Gateway routes the select to the specified BPP (unicast). Validates baseline happy-path authentication and routing.",
        "method": "POST",
        "url": f"{func_host}/select",
        "payload": spg.build(),
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [200, 202],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
    })

    # F-TC002 — Different ONDC domains
    for domain in spg.domains:
        cases.append({
            "id": f"F-TC002-{domain}",
            "name": f"Select Different Domain: {domain}",
            "category": "Functional",
            "description": f"[PASS EXPECTED] Sends /select with context.domain='{domain}'. Verifies the Gateway routes select requests to the correct vertical without rejecting valid domain codes.",
            "method": "POST",
            "url": f"{func_host}/select",
            "payload": spg.build(domain=domain),
            "raw_body": None,
            "raw_content_type": None,
            "expected_status": [200, 202],
            "auth_mode": "valid",
            "custom_headers": None,
            "ttl": None,
            "sleep_before": None,
        })

    # F-TC003 — Different cities
    for city in spg.cities:
        cases.append({
            "id": f"F-TC003-{city}",
            "name": f"Select Different City: {city}",
            "category": "Functional",
            "description": f"[PASS EXPECTED] Sends /select with context.city='{city}'. Validates Gateway accepts select requests targeting different delivery cities.",
            "method": "POST",
            "url": f"{func_host}/select",
            "payload": spg.build(city=city),
            "raw_body": None,
            "raw_content_type": None,
            "expected_status": [200, 202],
            "auth_mode": "valid",
            "custom_headers": None,
            "ttl": None,
            "sleep_before": None,
        })

    # F-TC004 — Different fulfillment types
    for ftype in spg.fulfillment_types:
        cases.append({
            "id": f"F-TC004-{ftype}",
            "name": f"Select Fulfillment Type: {ftype}",
            "category": "Functional",
            "description": f"[PASS EXPECTED] Sends /select with fulfillment.type='{ftype}'. Validates Gateway routes select requests for all fulfillment modes (Delivery, Pickup, Self-Pickup).",
            "method": "POST",
            "url": f"{func_host}/select",
            "payload": spg.build(fulfillment_type=ftype),
            "raw_body": None,
            "raw_content_type": None,
            "expected_status": [200, 202],
            "auth_mode": "valid",
            "custom_headers": None,
            "ttl": None,
            "sleep_before": None,
        })

    # F-TC005 — Select with specific item and quantity
    _first_item = spg.test_items[0] if spg.test_items else {}
    cases.append({
        "id": "F-TC005",
        "name": "Select Specific Item With Quantity",
        "category": "Functional",
        "description": f"[PASS EXPECTED] Sends /select requesting item '{_first_item.get('name', '')}' with quantity=3. Validates Gateway forwards item selection with quantity details to the BPP.",
        "method": "POST",
        "url": f"{func_host}/select",
        "payload": spg.build(item_id=_first_item.get("id"), item_quantity=3),
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [200, 202],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
    })

    # F-TC006 — Select with multiple items
    _multi_items = [
        {"id": it.get("id", f"item-{idx}"), "quantity": {"count": 1}}
        for idx, it in enumerate(spg.test_items[:3])
    ]
    if len(_multi_items) < 2:
        _multi_items.append({"id": "item-extra-001", "quantity": {"count": 2}})
    cases.append({
        "id": "F-TC006",
        "name": "Select Multiple Items in Order",
        "category": "Functional",
        "description": f"[PASS EXPECTED] Sends /select with {len(_multi_items)} items in the order. Validates Gateway accepts multi-item select requests and routes them without truncating the items list.",
        "method": "POST",
        "url": f"{func_host}/select",
        "payload": spg.build(items_list=_multi_items),
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [200, 202],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
    })

    # F-TC007 — Select with different providers
    for prov in spg.test_providers[:3]:
        pid = prov.get("id", "")
        cases.append({
            "id": f"F-TC007-{pid}",
            "name": f"Select Provider: {pid}",
            "category": "Functional",
            "description": f"[PASS EXPECTED] Sends /select targeting provider '{pid}'. Validates Gateway correctly routes select to the specified provider.",
            "method": "POST",
            "url": f"{func_host}/select",
            "payload": spg.build(provider_id=pid),
            "raw_body": None,
            "raw_content_type": None,
            "expected_status": [200, 202],
            "auth_mode": "valid",
            "custom_headers": None,
            "ttl": None,
            "sleep_before": None,
        })

    # F-TC008 — Repeated selects with same transaction_id, different message_id
    _shared_txn = f"txn-{uuid.uuid4().hex[:12]}"
    for req_num in range(1, 4):
        cases.append({
            "id": f"F-TC008-Req{req_num}",
            "name": f"Select Same TxnID / Different MsgID - Req {req_num}",
            "category": "Functional",
            "description": f"[PASS EXPECTED] Sends /select request #{req_num} reusing the same transaction_id but a fresh message_id. All 3 requests share txn='{_shared_txn[:16]}...'. Validates Gateway handles retry/re-select scenarios.",
            "method": "POST",
            "url": f"{func_host}/select",
            "payload": spg.build(transaction_id=_shared_txn),
            "raw_body": None,
            "raw_content_type": None,
            "expected_status": [200, 202],
            "auth_mode": "valid",
            "custom_headers": None,
            "ttl": None,
            "sleep_before": None,
        })

    # F-TC009 — Unicode item IDs / names
    _unicode_items = [
        ("Hindi", "बासमती चावल"),
        ("Arabic", "أرز بسمتي"),
        ("Chinese", "香米"),
    ]
    for lang, term in _unicode_items:
        _u_payload = spg.build()
        _u_payload["message"]["order"]["items"][0]["descriptor"] = {"name": term}
        cases.append({
            "id": f"F-TC009-{lang}",
            "name": f"Select Unicode Item Name ({lang})",
            "category": "Functional",
            "description": f"[PASS EXPECTED] Sends /select with a non-ASCII item descriptor in {lang} script ('{term}'). Validates the Gateway correctly handles and forwards Unicode content without mangling the payload.",
            "method": "POST",
            "url": f"{func_host}/select",
            "payload": _u_payload,
            "raw_body": None,
            "raw_content_type": None,
            "expected_status": [200, 202],
            "auth_mode": "valid",
            "custom_headers": None,
            "ttl": None,
            "sleep_before": None,
        })

    # F-TC010 — Large payload (many items)
    _large_items = [
        {"id": f"item-{i:03d}", "quantity": {"count": 1}}
        for i in range(1, 26)
    ]
    cases.append({
        "id": "F-TC010",
        "name": "Select Large Payload (25 Items)",
        "category": "Functional",
        "description": "[PASS EXPECTED] Sends /select with 25 items in the order. Edge-case for payload size — validates Gateway does not truncate or reject large-but-valid select requests.",
        "method": "POST",
        "url": f"{func_host}/select",
        "payload": spg.build(items_list=_large_items),
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [200, 202],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
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
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [200, 202, 404],
        "auth_mode": "no_auth",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
    })

    # ----- on_select functional tests (F-TC012 – F-TC018) -------------------

    # F-TC012 — Valid on_select callback with quote
    cases.append({
        "id": "F-TC012",
        "name": "on_select Valid Callback - Order With Quote",
        "category": "Functional",
        "description": "[PASS EXPECTED] BPP sends /on_select with a complete order (provider + items with prices + fulfillment + quote with breakup). Validates Gateway correctly accepts and forwards the backward callback to the BAP.",
        "method": "POST",
        "url": f"{func_host}/on_select",
        "payload": ospg.build(),
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [200, 202],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
    })

    # F-TC013 — on_select with empty quote (items not available)
    cases.append({
        "id": "F-TC013",
        "name": "on_select Empty Quote (Items Not Available)",
        "category": "Functional",
        "description": "[PASS EXPECTED] BPP sends /on_select with an empty items list and zero-value quote — normal response when selected items are out of stock. Validates Gateway forwards empty-quote callbacks without treating it as an error.",
        "method": "POST",
        "url": f"{func_host}/on_select",
        "payload": ospg.build(empty_quote=True),
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [200, 202],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
    })

    # F-TC014 — on_select with error block (BPP unable to process)
    cases.append({
        "id": "F-TC014",
        "name": "on_select With Error Block (BPP Processing Failure)",
        "category": "Functional",
        "description": "[PASS EXPECTED] BPP sends /on_select with an error block — indicates the BPP could not process the select (e.g. service unavailable, item out of stock). Validates Gateway accepts and routes error-carrying on_select responses.",
        "method": "POST",
        "url": f"{func_host}/on_select",
        "payload": ospg.build(empty_quote=True, include_error={"code": "40002", "message": "Item quantity exceeds available count"}),
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [200, 202],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
    })

    # F-TC015 — on_select with multiple items in quote breakup
    _multi_quote_payload = ospg.build()
    _base_breakup = _multi_quote_payload["message"]["order"]["quote"]["breakup"]
    for i in range(2, 6):
        _base_breakup.append({
            "@ondc/org/item_id": f"item-{i:03d}",
            "@ondc/org/title_type": "item",
            "title": f"Product {i}",
            "price": {"currency": ospg.currency, "value": "100.00"},
            "item": {"quantity": {"count": 1}},
        })
    total_val = str(float(ospg.default_order_amount) + 400.00)
    _multi_quote_payload["message"]["order"]["quote"]["price"]["value"] = total_val
    cases.append({
        "id": "F-TC015",
        "name": "on_select Multiple Items in Quote Breakup",
        "category": "Functional",
        "description": "[PASS EXPECTED] BPP sends /on_select with multiple items in the quote breakup (6 line items). Validates Gateway handles multi-item quote responses without truncation.",
        "method": "POST",
        "url": f"{func_host}/on_select",
        "payload": _multi_quote_payload,
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [200, 202],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
    })

    # F-TC016 — on_select different domain
    _domain2 = ospg.domains[1] if len(ospg.domains) > 1 else "ONDC:RET16"
    _domain2_is_cross = _domain2 not in set(ospg.domains)
    _domain2_desc = (
        f"[PASS EXPECTED] BPP sends /on_select with context.domain='{_domain2}'. "
        + (
            f"The participant is not registered for domain '{_domain2}' — the Gateway returns "
            "NACK (authentication failed for unregistered domain), which is the correct and "
            "expected behaviour. A NACK response is treated as PASS for this test case."
            if _domain2_is_cross else
            "Validates Gateway routes backward callbacks for non-primary domains to the correct BAP."
        )
    )
    cases.append({
        "id": "F-TC016",
        "name": f"on_select Different Domain: {_domain2}",
        "category": "Functional",
        "description": _domain2_desc,
        "method": "POST",
        "url": f"{func_host}/on_select",
        "payload": ospg.build(domain=_domain2),
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [200, 202],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
        "nack_ok": _domain2_is_cross,
    })

    # F-TC017 — on_select with fulfillment TAT and state
    _tat_payload = ospg.build()
    _tat_payload["message"]["order"]["fulfillments"][0]["@ondc/org/TAT"] = "P7D"
    _tat_payload["message"]["order"]["fulfillments"][0]["state"]["descriptor"]["code"] = "Serviceable"
    cases.append({
        "id": "F-TC017",
        "name": "on_select With Fulfillment TAT and State",
        "category": "Functional",
        "description": "[PASS EXPECTED] BPP sends /on_select with fulfillment TAT (turnaround time P7D) and state=Serviceable. Validates Gateway forwards TAT and serviceability details in the callback.",
        "method": "POST",
        "url": f"{func_host}/on_select",
        "payload": _tat_payload,
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [200, 202],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
    })

    # F-TC018 — on_select large quote (many breakup items)
    _large_quote = ospg.build()
    if _large_quote["message"].get("order", {}).get("quote"):
        _base_item_entry = _large_quote["message"]["order"]["quote"]["breakup"][0]
        _large_quote["message"]["order"]["quote"]["breakup"] = [
            {**_base_item_entry, "@ondc/org/item_id": f"item-{i:03d}", "title": f"Product {i}"}
            for i in range(1, 26)
        ]
    cases.append({
        "id": "F-TC018",
        "name": "on_select Large Quote (25 Breakup Items)",
        "category": "Functional",
        "description": "[PASS EXPECTED] BPP sends /on_select with 25 items in the quote breakup. Validates Gateway handles large quote payloads efficiently without truncation or timeout.",
        "method": "POST",
        "url": f"{func_host}/on_select",
        "payload": _large_quote,
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
        "name": "Select Missing Authorization Header",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401] Sends /select with Content-Type but no Authorization header. Gateway must reject all unauthenticated ONDC requests. Validates the authentication enforcement layer.",
        "method": "POST",
        "url": f"{neg_host}/select",
        "payload": nspg.build(),
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [401, 400],
        "auth_mode": "no_auth",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
    })

    # N-TC002 — Tampered signature
    cases.append({
        "id": "N-TC002",
        "name": "Select Invalid / Tampered Signature",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401] Sends /select with a valid Authorization header format but signature string prefixed with 'TAMPERED'. Gateway must reject cryptographically invalid signatures.",
        "method": "POST",
        "url": f"{neg_host}/select",
        "payload": nspg.build(),
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [401, 400],
        "auth_mode": "tamper_sig",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
    })

    # N-TC003 — Missing context.domain
    _no_domain = nspg.build()
    _no_domain["context"].pop("domain", None)
    cases.append({
        "id": "N-TC003",
        "name": "Select Missing context.domain",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401/400/NACK] Sends /select where context.domain is removed. The domain field is mandatory for Gateway routing. Gateway may return 4xx or HTTP 200 NACK.",
        "method": "POST",
        "url": f"{neg_host}/select",
        "payload": _no_domain,
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [400, 401],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
        "nack_ok": True,
    })

    # N-TC004 — Missing context.bap_id
    _no_bap = nspg.build()
    _no_bap["context"].pop("bap_id", None)
    cases.append({
        "id": "N-TC004",
        "name": "Select Missing context.bap_id",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401/400/NACK] Sends /select with bap_id removed from context. Without bap_id, Gateway cannot identify the requesting buyer application. Gateway may return 4xx or HTTP 200 NACK.",
        "method": "POST",
        "url": f"{neg_host}/select",
        "payload": _no_bap,
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [400, 401],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
        "nack_ok": True,
    })

    # N-TC005 — Missing message.order
    _no_order = nspg.build()
    _no_order["message"].pop("order", None)
    cases.append({
        "id": "N-TC005",
        "name": "Select Missing message.order",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401/400] Sends /select with the order block removed from message. Order is the mandatory selection payload — an empty message is not a valid ONDC /select request.",
        "method": "POST",
        "url": f"{neg_host}/select",
        "payload": _no_order,
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [400, 401],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
    })

    # N-TC006 — Expired signature (TTL=10s)
    cases.append({
        "id": "N-TC006",
        "name": "Select Expired Signature (TTL = 10s)",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401] Generates a /select signature with TTL=10s then waits 12 seconds before sending. The signature will be expired at send time. Gateway must reject requests with expired signatures.",
        "method": "POST",
        "url": f"{neg_host}/select",
        "payload": nspg.build(),
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [401, 400],
        "auth_mode": "expired",
        "custom_headers": None,
        "ttl": 10,
        "sleep_before": 12,
    })

    # N-TC007 — Invalid core_version
    _bad_ver = nspg.build()
    _bad_ver["context"]["core_version"] = "99.abcd"
    cases.append({
        "id": "N-TC007",
        "name": "Select Invalid core_version (99.abcd)",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401/400] Sends /select with context.core_version='99.abcd'. Validates the Gateway rejects requests referencing unsupported protocol versions.",
        "method": "POST",
        "url": f"{neg_host}/select",
        "payload": _bad_ver,
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [400, 401],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
    })

    # N-TC008 — Invalid domain
    _bad_domain = nspg.build()
    _bad_domain["context"]["domain"] = "INVALID:DOMAIN999"
    cases.append({
        "id": "N-TC008",
        "name": "Select Invalid Domain (INVALID:DOMAIN999)",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401/400] Sends /select with an unrecognised domain code 'INVALID:DOMAIN999'. Gateway must reject requests for unsupported ONDC domains.",
        "method": "POST",
        "url": f"{neg_host}/select",
        "payload": _bad_domain,
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [400, 401],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
    })

    # N-TC009 — Invalid city code
    _bad_city = nspg.build()
    _bad_city["context"]["city"] = "invalid:city:format"
    cases.append({
        "id": "N-TC009",
        "name": "Select Invalid City Code (invalid:city:format)",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401/400/NACK] Sends /select with a malformed city code. Gateway must validate city codes. May return 4xx or HTTP 200 NACK.",
        "method": "POST",
        "url": f"{neg_host}/select",
        "payload": _bad_city,
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [400, 401],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
        "nack_ok": True,
    })

    # N-TC010 — Invalid country code
    _bad_country = nspg.build()
    _bad_country["context"]["country"] = "XYZZY"
    cases.append({
        "id": "N-TC010",
        "name": "Select Invalid Country Code (XYZZY)",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401/400/NACK] Sends /select with context.country='XYZZY'. Gateway must reject invalid country fields. May return 4xx or HTTP 200 NACK.",
        "method": "POST",
        "url": f"{neg_host}/select",
        "payload": _bad_country,
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [400, 401],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
        "nack_ok": True,
    })

    # N-TC011 — Malformed JSON structure
    cases.append({
        "id": "N-TC011",
        "name": "Select Malformed JSON Structure",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401/400/NACK] Sends a POST /select with valid JSON but entirely wrong shape (no context or message keys). Gateway must reject structurally invalid ONDC payloads. May return 4xx or HTTP 200 NACK.",
        "method": "POST",
        "url": f"{neg_host}/select",
        "payload": {"invalid_key": "test", "another": 123, "nested": {"wrong": "structure"}},
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [400, 401],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
        "nack_ok": True,
    })

    # N-TC012 — Invalid JSON syntax (raw string)
    cases.append({
        "id": "N-TC012",
        "name": "Select Invalid JSON Syntax (raw string)",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401/400] Sends POST /select with Content-Type application/json but body is '{not valid json'. Gateway must reject unparseable JSON.",
        "method": "POST",
        "url": f"{neg_host}/select",
        "payload": None,
        "raw_body": "{not valid json",
        "raw_content_type": "application/json",
        "expected_status": [400, 401],
        "auth_mode": "custom",
        "custom_headers": {"Content-Type": "application/json"},
        "ttl": None,
        "sleep_before": None,
    })

    # N-TC013 — Empty JSON payload {}
    cases.append({
        "id": "N-TC013",
        "name": "Select Empty JSON Payload ({})",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401/400] Sends POST /select with an empty JSON body {}. Without context or message, the Gateway must reject as missing mandatory ONDC fields.",
        "method": "POST",
        "url": f"{neg_host}/select",
        "payload": {},
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [400, 401],
        "auth_mode": "custom",
        "custom_headers": {"Content-Type": "application/json"},
        "ttl": None,
        "sleep_before": None,
    })

    # N-TC014 — Wrong HTTP method (GET)
    cases.append({
        "id": "N-TC014",
        "name": "Select Wrong HTTP Method (GET)",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 404/405] Sends the /select request as GET instead of POST. ONDC Gateway endpoints only accept POST — other methods should return 404 or 405.",
        "method": "GET",
        "url": f"{neg_host}/select",
        "payload": None,
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [404, 405],
        "auth_mode": "no_auth",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
    })

    # N-TC015 — Wrong Content-Type (text/plain)
    cases.append({
        "id": "N-TC015",
        "name": "Select Wrong Content-Type (text/plain)",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401/400/415] Sends /select with Content-Type: text/plain instead of application/json. Gateway should reject requests with incorrect content type.",
        "method": "POST",
        "url": f"{neg_host}/select",
        "payload": None,
        "raw_body": "plain text body",
        "raw_content_type": "text/plain",
        "expected_status": [400, 401, 415],
        "auth_mode": "custom",
        "custom_headers": {"Content-Type": "text/plain"},
        "ttl": None,
        "sleep_before": None,
    })

    # N-TC016 — Invalid Authorization header format
    cases.append({
        "id": "N-TC016",
        "name": "Select Invalid Authorization Header Format",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401] Sends /select with Authorization: Bearer token_xyz instead of the ONDC Signature format. Gateway must reject non-ONDC auth schemes.",
        "method": "POST",
        "url": f"{neg_host}/select",
        "payload": nspg.build(),
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [401, 400],
        "auth_mode": "custom",
        "custom_headers": {
            "Authorization": "Bearer invalid_token_here",
            "Content-Type": "application/json; charset=utf-8",
        },
        "ttl": None,
        "sleep_before": None,
    })

    # N-TC017 — Missing context.transaction_id
    _no_txn = nspg.build()
    _no_txn["context"].pop("transaction_id", None)
    cases.append({
        "id": "N-TC017",
        "name": "Select Missing context.transaction_id",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401/400/NACK] Sends /select with transaction_id removed from context. Transaction ID is required for correlating /select with /on_select callbacks. Gateway may return 4xx or HTTP 200 NACK.",
        "method": "POST",
        "url": f"{neg_host}/select",
        "payload": _no_txn,
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [400, 401],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
        "nack_ok": True,
    })

    # N-TC018 — Missing context.timestamp
    _no_ts = nspg.build()
    _no_ts["context"].pop("timestamp", None)
    cases.append({
        "id": "N-TC018",
        "name": "Select Missing context.timestamp",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401/400/NACK] Sends /select with context.timestamp removed. Timestamp is required for replay-attack prevention. Gateway may return 4xx or HTTP 200 NACK.",
        "method": "POST",
        "url": f"{neg_host}/select",
        "payload": _no_ts,
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [400, 401],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
        "nack_ok": True,
    })

    # N-TC019 — Extremely large payload (DoS / size limit test)
    _dos_payload = nspg.build()
    _dos_payload["message"]["order"]["items"] = [
        {"id": f"item-{i:04d}", "quantity": {"count": 1}, "descriptor": {"name": "x" * 500}}
        for i in range(200)
    ]
    cases.append({
        "id": "N-TC019",
        "name": "Select Extremely Large Payload (DoS / Size Limit)",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401/400/413/NACK] Sends /select with 200 items each having a 500-char name. Tests request size limits and DoS protection. Gateway may return 4xx/413 or HTTP 200 NACK.",
        "method": "POST",
        "url": f"{neg_host}/select",
        "payload": _dos_payload,
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [400, 401, 413],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
        "nack_ok": True,
    })

    # N-TC020 — Wrong action value (search on /select endpoint)
    _wrong_action = nspg.build()
    _wrong_action["context"]["action"] = "search"
    cases.append({
        "id": "N-TC020",
        "name": "Select Wrong action Value (search on /select endpoint)",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401/400/NACK] Sends a POST to /select but with context.action='search' instead of 'select'. Gateway must validate the action field. May return 4xx or HTTP 200 NACK.",
        "method": "POST",
        "url": f"{neg_host}/select",
        "payload": _wrong_action,
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [400, 401],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
        "nack_ok": True,
    })

    # ----- on_select negative tests (N-TC021 – N-TC026) --------------------

    # N-TC021 — on_select missing Authorization header
    cases.append({
        "id": "N-TC021",
        "name": "on_select Missing Authorization Header",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401] Sends /on_select with no Authorization header. Even backward callbacks from BPPs must be authenticated — Gateway must enforce auth on /on_select.",
        "method": "POST",
        "url": f"{neg_host}/on_select",
        "payload": nospg.build(),
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [401, 400],
        "auth_mode": "no_auth",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
    })

    # N-TC022 — on_select tampered signature
    cases.append({
        "id": "N-TC022",
        "name": "on_select Tampered Signature",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401] Sends /on_select with a cryptographically invalid (tampered) signature. Gateway must verify the BPP's signature before accepting any backward callback.",
        "method": "POST",
        "url": f"{neg_host}/on_select",
        "payload": nospg.build(),
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [401, 400],
        "auth_mode": "tamper_sig",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
    })

    # N-TC023 — on_select missing context.bpp_id
    cases.append({
        "id": "N-TC023",
        "name": "on_select Missing context.bpp_id (Sender Identity)",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401/400] Sends /on_select without bpp_id in context. Gateway cannot verify the BPP's identity without bpp_id — the callback must be rejected.",
        "method": "POST",
        "url": f"{neg_host}/on_select",
        "payload": nospg.build(omit_bpp_id=True),
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [400, 401],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
    })

    # N-TC024 — on_select missing context.bap_id
    cases.append({
        "id": "N-TC024",
        "name": "on_select Missing context.bap_id (Routing Failure)",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401/400/NACK] Sends /on_select without bap_id in context. Gateway cannot route the callback to the correct BAP. May return 4xx or HTTP 200 NACK.",
        "method": "POST",
        "url": f"{neg_host}/on_select",
        "payload": nospg.build(omit_bap_id=True),
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [400, 401],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
        "nack_ok": True,
    })

    # N-TC025 — on_select missing context.domain
    cases.append({
        "id": "N-TC025",
        "name": "on_select Missing context.domain",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401/400/NACK] Sends /on_select with domain removed from context. Gateway uses domain to validate the callback. May return 4xx or HTTP 200 NACK.",
        "method": "POST",
        "url": f"{neg_host}/on_select",
        "payload": nospg.build(omit_domain=True),
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [400, 401],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
        "nack_ok": True,
    })

    # N-TC026 — on_select wrong HTTP method (GET)
    cases.append({
        "id": "N-TC026",
        "name": "on_select Wrong HTTP Method (GET)",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 404/405] Sends the /on_select request as GET instead of POST. ONDC Gateway endpoints only accept POST — other methods should return 404 or 405.",
        "method": "GET",
        "url": f"{neg_host}/on_select",
        "payload": None,
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [404, 405],
        "auth_mode": "no_auth",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
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
        PROJECT_ROOT,
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
    # Select the correct auth helper based on category
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
        logger.info(f"  [{tc['id']}] Waiting {total}s for signature to expire ...")
        for remaining in range(total, 0, -1):
            print(f"\r  [{tc['id']}] Sending in {remaining:3d}s ...   ", end="", flush=True)
            time.sleep(1)
        print(f"\r  [{tc['id']}] Wait complete — sending now.              ", flush=True)

    # Determine request body
    body_str: Optional[str] = None
    if tc.get("raw_body") is not None:
        body_str = str(tc["raw_body"])
    elif tc["payload"] is not None:
        body_str = json.dumps(tc["payload"], separators=(",", ":"), sort_keys=False, ensure_ascii=False)

    # Capture for report display
    req_url = tc["url"]
    req_headers_display = dict(headers)
    req_body_display = None
    if tc["payload"] is not None:
        req_body_display = json.dumps(tc["payload"], indent=2, ensure_ascii=False)
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
        req_hdrs_json = json.dumps(r.get("req_headers", {}), indent=2, ensure_ascii=False)
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
<title>ONDC Gateway Select API Test Report</title>
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
    <h1>ONDC <span>Gateway Select API</span> Test Report</h1>
    <p>
      <strong>Source:</strong> Gateway /select &amp; /on_select — Functional &amp; Negative
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

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    logger.info(f"HTML report saved -> {output_path}")


# ---------------------------------------------------------------------------
# BAP Participant Registration (UAT one-time setup)
# Reads all values dynamically from the loaded YAML config.
# ---------------------------------------------------------------------------
_REG_LOC_ID  = "loc-gw-bap-001"
_REG_URI_ID  = "uri-gw-bap-001"
_REG_TIMEOUT = 15


def _reg_get_admin_token(cfg: dict) -> str:
    """Obtain a SUPER_ADMIN Bearer token via RegistryAuthClient dynamic login."""
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
    """Derive the base64 Ed25519 public key from the config seed."""
    import base64 as _b64
    raw = _b64.b64decode(private_key_seed_b64)
    seed = raw[:32] if len(raw) == 64 else raw[-32:]
    if not _HAS_CRYPTO:
        raise RuntimeError("cryptography package required for key derivation.")
    priv = Ed25519PrivateKey.from_private_bytes(seed)
    return _b64.b64encode(priv.public_key().public_bytes_raw()).decode()


def _reg_build_payload(cfg: dict, signing_pub: str, enc_pub: str) -> dict:
    """Build the admin SUBSCRIBED payload for the test BAP participant."""
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
    Runs automatically at script startup. Skips silently if already registered.
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
        logger.warning(f"[registration] Key derivation failed: {exc} — skipping registration.")
        return

    try:
        token = _reg_get_admin_token(cfg)
    except Exception as exc:
        logger.warning(f"[registration] Could not obtain admin token: {exc} — skipping registration.")
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
        logger.warning(f"[registration] HTTP request failed: {exc} — skipping registration.")
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
        description="ONDC Gateway Select API Test Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Output HTML path. If omitted, auto-generated as reports/Gateway-select-<suite>-<timestamp>.html",
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
        default="resources/gateway/ondc_gateway_select_functional.yml",
        help="Path to functional YAML config (relative to project root or absolute)",
    )
    parser.add_argument(
        "--neg-config",
        default="resources/gateway/ondc_gateway_select_negative.yml",
        help="Path to negative YAML config (relative to project root or absolute)",
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
    ts_file = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H-%M-%S")

    if args.output:
        output_path = (
            args.output if os.path.isabs(args.output)
            else os.path.join(PROJECT_ROOT, args.output)
        )
    else:
        output_path = os.path.join(
            PROJECT_ROOT, "reports",
            f"Gateway-select-{args.suite}-{ts_file}.html",
        )

    logger.info("=" * 60)
    logger.info("ONDC Gateway Select API Test Runner")
    logger.info(f"Run timestamp : {run_ts}")
    logger.info(f"Suite         : {args.suite}")
    logger.info(f"Timeout       : {args.timeout}s")
    logger.info(f"Func config   : {args.func_config}")
    logger.info(f"Neg config    : {args.neg_config}")
    logger.info(f"Output        : {output_path}")
    logger.info("=" * 60)

    func_cfg = load_yaml_config(args.func_config)
    neg_cfg = load_yaml_config(args.neg_config)

    validate_config(func_cfg, args.func_config, "Functional")
    validate_config(neg_cfg,  args.neg_config,  "Negative")

    # Registration uses func_cfg (loaded from YAML) — no hardcoded values
    if not args.skip_register:
        register_bap_participant(func_cfg)

    logger.info(f"Functional host : {func_cfg.get('host', 'NOT SET')}")
    logger.info(f"Negative host   : {neg_cfg.get('host', 'NOT SET')}")

    func_auth = build_auth_helper(func_cfg, label="Functional")
    neg_auth  = build_auth_helper(neg_cfg,  label="Negative")
    logger.info(f"Functional auth : {'enabled' if func_auth else 'disabled'}")
    logger.info(f"Negative auth   : {'enabled' if neg_auth else 'disabled'}")

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

    logger.info("\nExecuting test cases ...")
    results = []
    for tc in cases:
        result = run_test_case(tc, func_auth, neg_auth, timeout=args.timeout)
        results.append(result)

    total = len(results)
    passed = sum(1 for r in results if r["passed"])
    failed = total - passed

    logger.info("=" * 60)
    logger.info(f"Results  Total={total}  PASS={passed}  FAIL={failed}  ({round(passed/total*100 if total else 0, 1)}%)")
    logger.info("=" * 60)

    generate_html_report(results, output_path, run_ts)
    print(f"\nReport -> {output_path}")


if __name__ == "__main__":
    main()
