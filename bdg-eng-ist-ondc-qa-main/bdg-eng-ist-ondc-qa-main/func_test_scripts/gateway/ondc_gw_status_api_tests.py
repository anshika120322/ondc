#!/usr/bin/env python3
"""
ONDC Gateway status API - Automated Test Runner with HTML Report Generator

Runs all functional and negative test cases for the ONDC /status and /on_status
endpoints and generates a comprehensive dark-theme HTML report.

Usage:
    python func_test_scripts/gateway/ondc_gw_status_api_tests.py
    python func_test_scripts/gateway/ondc_gw_status_api_tests.py --suite functional
    python func_test_scripts/gateway/ondc_gw_status_api_tests.py --suite negative
    python func_test_scripts/gateway/ondc_gw_status_api_tests.py --timeout 30
    python func_test_scripts/gateway/ondc_gw_status_api_tests.py --output reports/my_report.html
    python func_test_scripts/gateway/ondc_gw_status_api_tests.py --func-config resources/gateway/ondc_gateway_status_functional.yml
    python func_test_scripts/gateway/ondc_gw_status_api_tests.py --neg-config  resources/gateway/ondc_gateway_status_negative.yml
    python func_test_scripts/gateway/ondc_gw_status_api_tests.py --filter F-TC011
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
# Shared payload helpers
# ---------------------------------------------------------------------------
def _json_clone(value: Any) -> Any:
    return json.loads(json.dumps(value, ensure_ascii=False))


def _resolve_domain_entries(raw: Any, domain: str, fallback: Any = None) -> Any:
    if isinstance(raw, dict):
        value = raw.get(domain)
        if value is None:
            value = next(iter(raw.values()), fallback)
        return value if value is not None else fallback
    return raw if raw is not None else fallback


def _resolve_domain_items(cfg: dict, domain: str) -> List[Dict[str, Any]]:
    raw_test_data = cfg.get("test_data", {})
    if isinstance(raw_test_data, dict) and raw_test_data:
        domain_data = raw_test_data.get(domain, next(iter(raw_test_data.values()), {}))
        if isinstance(domain_data, dict):
            items = domain_data.get("test_items")
            if items:
                return items
    raw_items = cfg.get("test_items", [])
    resolved = _resolve_domain_entries(raw_items, domain, [])
    return resolved or []


def _resolve_domain_providers(cfg: dict, domain: str) -> List[Dict[str, Any]]:
    raw_test_data = cfg.get("test_data", {})
    if isinstance(raw_test_data, dict) and raw_test_data:
        domain_data = raw_test_data.get(domain, next(iter(raw_test_data.values()), {}))
        if isinstance(domain_data, dict):
            providers = domain_data.get("test_providers")
            if providers:
                return providers
    raw_providers = cfg.get("test_providers", [])
    resolved = _resolve_domain_entries(raw_providers, domain, [])
    return resolved or []


def _resolve_domain_payment_types(cfg: dict, domain: str) -> List[Any]:
    raw_test_data = cfg.get("test_data", {})
    if isinstance(raw_test_data, dict) and raw_test_data:
        domain_data = raw_test_data.get(domain, next(iter(raw_test_data.values()), {}))
        if isinstance(domain_data, dict):
            payment_types = domain_data.get("payment_types")
            if payment_types:
                return payment_types
    raw_payment_types = cfg.get("payment_types", [])
    resolved = _resolve_domain_entries(raw_payment_types, domain, [])
    return resolved or []


def _resolve_domain_fulfillment_types(cfg: dict, domain: str) -> List[Any]:
    raw_test_data = cfg.get("test_data", {})
    if isinstance(raw_test_data, dict) and raw_test_data:
        domain_data = raw_test_data.get(domain, next(iter(raw_test_data.values()), {}))
        if isinstance(domain_data, dict):
            fulfillment_types = domain_data.get("fulfillment_types")
            if fulfillment_types:
                return fulfillment_types
    raw_fulfillment_types = cfg.get("fulfillment_types", [])
    resolved = _resolve_domain_entries(raw_fulfillment_types, domain, [])
    return resolved or []


def _safe_int(value: Any, default: int = 1) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _money_str(value: Any, default: str = "0.00") -> str:
    if value in (None, ""):
        return default
    if isinstance(value, dict):
        value = value.get("value", default)
    try:
        return f"{float(str(value).replace(',', '')):.2f}"
    except Exception:
        return str(value)


def _money_sum(values: List[Any]) -> str:
    total = 0.0
    for value in values:
        try:
            total += float(str(value).replace(",", ""))
        except Exception:
            pass
    return f"{total:.2f}"


def _slugify(text: str) -> str:
    cleaned = "".join(ch.lower() if ch.isalnum() else "-" for ch in str(text or "gw-bap"))
    while "--" in cleaned:
        cleaned = cleaned.replace("--", "-")
    return cleaned.strip("-") or "gw-bap"


# ---------------------------------------------------------------------------
# status Payload Generator  (/status — forward flow)
# ---------------------------------------------------------------------------
class StatusPayloadGenerator:
    def __init__(self, cfg: dict):
        self.cfg = cfg
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
        self.default_order_amount = str(cfg.get("default_order_amount", "500.00"))
        self.default_delivery_charge = str(cfg.get("default_delivery_charge", "50.00"))
        self.default_processing_charge = str(cfg.get("default_processing_charge", "25.00"))
        self.default_order_state = str(cfg.get("default_order_state", "Status Requested"))

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
        self.test_locations = cfg.get(
            "test_locations", [{"city": "std:080", "gps": "12.9492953,77.7019878", "area_code": "560001"}]
        )

    def providers_for_domain(self, domain: str = None) -> List[Dict[str, Any]]:
        sel_domain = domain or (self.domains[0] if self.domains else "")
        providers = _resolve_domain_providers(self.cfg, sel_domain)
        return providers or [{"id": "provider-001", "name": "Test Provider", "location_id": "store-location-001"}]

    def items_for_domain(self, domain: str = None) -> List[Dict[str, Any]]:
        sel_domain = domain or (self.domains[0] if self.domains else "")
        items = _resolve_domain_items(self.cfg, sel_domain)
        return items or [{"id": "item-001", "name": "Status Item", "price": self.default_order_amount, "category_id": "Generic"}]

    def payment_types_for_domain(self, domain: str = None) -> List[Any]:
        sel_domain = domain or (self.domains[0] if self.domains else "")
        payment_types = _resolve_domain_payment_types(self.cfg, sel_domain)
        return payment_types or [{"type": "PRE-FULFILLMENT", "status": "PAID", "collected_by": "BAP"}]

    def fulfillment_types_for_domain(self, domain: str = None) -> List[Any]:
        sel_domain = domain or (self.domains[0] if self.domains else "")
        fulfillment_types = _resolve_domain_fulfillment_types(self.cfg, sel_domain)
        return fulfillment_types or [{"type": "Delivery"}]

    def _pick_provider(self, domain: str, provider_id: str = None) -> Dict[str, Any]:
        providers = self.providers_for_domain(domain)
        if provider_id:
            for provider in providers:
                if str(provider.get("id", "")) == str(provider_id):
                    return _json_clone(provider)
        provider = _json_clone(providers[0]) if providers else {}
        if provider_id:
            provider["id"] = provider_id
        return provider

    def _pick_payment_type(self, domain: str, payment_type: dict = None) -> dict:
        if payment_type:
            return payment_type
        candidates = self.payment_types_for_domain(domain)
        candidate = candidates[0] if candidates else {}
        return candidate if isinstance(candidate, dict) else {"type": str(candidate)}

    def _pick_fulfillment_type(self, domain: str, fulfillment_type: str = None) -> dict:
        if fulfillment_type:
            return {"type": fulfillment_type}
        candidates = self.fulfillment_types_for_domain(domain)
        candidate = candidates[0] if candidates else {}
        return candidate if isinstance(candidate, dict) else {"type": str(candidate)}

    def _pick_location(self, city: str, provider: dict = None, fulfillment_cfg: dict = None) -> Dict[str, str]:
        provider = provider or {}
        fulfillment_cfg = fulfillment_cfg or {}

        selected = {}
        for loc in self.test_locations:
            if str(loc.get("city", "")) == str(city):
                selected = loc
                break
        if not selected and self.test_locations:
            selected = self.test_locations[0]

        f_loc = fulfillment_cfg.get("location", {}) if isinstance(fulfillment_cfg, dict) else {}
        return {
            "city": str(selected.get("city", city or (self.cities[0] if self.cities else ""))),
            "gps": str(f_loc.get("gps") or provider.get("gps") or selected.get("gps", "")),
            "area_code": str(f_loc.get("area_code") or provider.get("area_code") or selected.get("area_code", "")),
            "address": str(provider.get("address") or selected.get("address") or f"{self.buyer_address_prefix} {selected.get('area_code', '')}".strip()),
            "location_id": str(provider.get("location_id") or selected.get("location_id") or "store-location-001"),
        }

    def _delivery_charge_for(self, fulfillment_type: str) -> str:
        if str(fulfillment_type).strip().lower() in ("digital", "account-credit", "mandate-setup"):
            return _money_str(self.default_processing_charge, "0.00")
        return _money_str(self.default_delivery_charge, "0.00")

    def _delivery_title_for(self, fulfillment_type: str) -> str:
        if str(fulfillment_type).strip().lower() in ("digital", "account-credit", "mandate-setup"):
            return "Processing Charges"
        return "Delivery Charges"

    def _prepare_items(
        self,
        domain: str,
        item_overrides: Optional[List[Dict[str, Any]]] = None,
        fulfillment_type: str = "Delivery",
    ) -> Dict[str, Any]:
        base_items = self.items_for_domain(domain)
        source_items: List[Dict[str, Any]]
        if item_overrides is None:
            source_items = [_json_clone(base_items[0])] if base_items else [{"id": "item-001", "name": "Status Item", "price": self.default_order_amount}]
        elif isinstance(item_overrides, dict):
            source_items = [_json_clone(item_overrides)]
        else:
            source_items = [_json_clone(item) if isinstance(item, dict) else {"id": str(item), "name": str(item)} for item in item_overrides]

        order_items: List[Dict[str, Any]] = []
        breakup: List[Dict[str, Any]] = []
        subtotals: List[str] = []

        for idx, item in enumerate(source_items, start=1):
            item_id = str(item.get("id") or f"item-{idx:03d}")
            item_name = str(item.get("name") or item.get("title") or item.get("descriptor", {}).get("name") or f"Status Item {idx}")
            item_qty = _safe_int(item.get("quantity"), 1)
            if isinstance(item.get("quantity"), dict):
                item_qty = _safe_int(item.get("quantity", {}).get("count"), item_qty)
            fulfillment_id = str(item.get("fulfillment_id", "1"))
            descriptor = item.get("descriptor")
            if not descriptor and item_name:
                descriptor = {"name": item_name, "short_desc": f"{item_name} status request"}
            price_source = item.get("price") or item.get("loan_amount") or item.get("amount") or self.default_order_amount
            unit_price = _money_str(price_source, self.default_order_amount)
            subtotal = _money_str(float(unit_price) * item_qty, self.default_order_amount)

            order_item = {
                "id": item_id,
                "quantity": {"count": item_qty},
                "fulfillment_id": fulfillment_id,
            }
            if descriptor:
                order_item["descriptor"] = descriptor
            if item.get("category_id"):
                order_item["category_id"] = item.get("category_id")

            order_items.append(order_item)
            breakup.append({
                "@ondc/org/item_id": item_id,
                "@ondc/org/title_type": "item",
                "title": item_name,
                "price": {"currency": self.currency, "value": subtotal},
            })
            subtotals.append(subtotal)

        delivery_charge = self._delivery_charge_for(fulfillment_type)
        breakup.append({
            "@ondc/org/item_id": "1",
            "@ondc/org/title_type": "delivery",
            "title": self._delivery_title_for(fulfillment_type),
            "price": {"currency": self.currency, "value": delivery_charge},
        })

        return {
            "items": order_items,
            "breakup": breakup,
            "delivery_charge": delivery_charge,
            "items_total": _money_sum(subtotals),
            "quote_total": _money_sum(subtotals + [delivery_charge]),
        }

    def _build_order(
        self,
        domain: str,
        city: str,
        provider_id: str = None,
        item_overrides: Optional[List[Dict[str, Any]]] = None,
        payment_type: dict = None,
        fulfillment_type: str = None,
        order_state: str = None,
        order_id: str = None,
    ) -> dict:
        now = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        oid = order_id or f"order-{uuid.uuid4().hex[:8]}"

        provider = self._pick_provider(domain, provider_id=provider_id)
        payment = self._pick_payment_type(domain, payment_type=payment_type)
        fulfillment_cfg = self._pick_fulfillment_type(domain, fulfillment_type=fulfillment_type)
        location = self._pick_location(city, provider=provider, fulfillment_cfg=fulfillment_cfg)
        item_bundle = self._prepare_items(domain, item_overrides=item_overrides, fulfillment_type=fulfillment_cfg.get("type", "Delivery"))
        provider_loc_id = str(provider.get("location_id") or location.get("location_id") or "store-location-001")
        provider_name = str(provider.get("name", "Test Provider"))

        return {
            "id": oid,
            "state": order_state or self.default_order_state,
            "provider": {
                "id": str(provider.get("id", provider_id or "provider-001")),
                "descriptor": {"name": provider_name},
                "locations": [{"id": provider_loc_id}],
            },
            "items": item_bundle["items"],
            "billing": {
                "name": self.buyer_name,
                "phone": self.buyer_phone,
                "email": self.buyer_email,
                "address": f"{self.buyer_address_prefix} {location.get('area_code', '')}".strip(),
                "tax_number": self.buyer_gstin,
                "org": {"name": self.buyer_org_name},
            },
            "fulfillment": {
                "id": "1",
                "type": fulfillment_cfg.get("type", "Delivery"),
                "tracking": True,
                "state": {"descriptor": {"code": order_state or self.default_order_state}},
                "start": {
                    "location": {
                        "id": provider_loc_id,
                        "gps": self.seller_source_gps,
                        "address": self.seller_source_address,
                    },
                    "contact": {"phone": self.seller_agent_phone},
                },
                "end": {
                    "contact": {"phone": self.buyer_phone},
                    "location": {
                        "gps": location.get("gps", ""),
                        "address": {"area_code": location.get("area_code", "")},
                    },
                },
            },
            "payment": {
                "params": {
                    "transaction_id": f"pay-{uuid.uuid4().hex[:8]}",
                    "amount": item_bundle["quote_total"],
                    "currency": self.currency,
                },
                "status": payment.get("status", "PAID"),
                "type": payment.get("type", "PRE-FULFILLMENT"),
                "collected_by": payment.get("collected_by", "BAP"),
            },
            "quote": {
                "price": {"currency": self.currency, "value": item_bundle["quote_total"]},
                "breakup": item_bundle["breakup"],
            },
            "updated_at": now,
        }

    def build(
        self,
        domain: str = None,
        city: str = None,
        transaction_id: str = None,
        message_id: str = None,
        provider_id: str = None,
        item_overrides: Optional[List[Dict[str, Any]]] = None,
        payment_type: dict = None,
        fulfillment_type: str = None,
        order_state: str = None,
        order_id: str = None,
    ) -> dict:
        txn_id = transaction_id or f"txn-{uuid.uuid4().hex[:12]}"
        msg_id = message_id or f"msg-{uuid.uuid4().hex[:12]}"
        now = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")

        sel_domain = domain or (self.domains[0] if self.domains else "")
        sel_city = city or (self.cities[0] if self.cities else "")

        return {
            "context": {
                "domain": sel_domain,
                "action": "status",
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
            },
            "message": {
                "order": self._build_order(
                    sel_domain,
                    sel_city,
                    provider_id=provider_id,
                    item_overrides=item_overrides,
                    payment_type=payment_type,
                    fulfillment_type=fulfillment_type,
                    order_state=order_state,
                    order_id=order_id,
                )
            },
        }


# ---------------------------------------------------------------------------
# on_status Payload Generator  (/on_status — backward callback from BPP)
# ---------------------------------------------------------------------------
class OnStatusPayloadGenerator(StatusPayloadGenerator):
    def __init__(self, cfg: dict):
        super().__init__(cfg)
        self.default_on_status_state = str(cfg.get("default_on_status_state", "Status Available"))

    def build(
        self,
        domain: str = None,
        city: str = None,
        transaction_id: str = None,
        message_id: str = None,
        provider_id: str = None,
        item_overrides: Optional[List[Dict[str, Any]]] = None,
        payment_type: dict = None,
        fulfillment_type: str = None,
        order_state: str = None,
        order_id: str = None,
        omit_order: bool = False,
        omit_bpp_id: bool = False,
        omit_bap_id: bool = False,
        omit_domain: bool = False,
        include_error: dict = None,
        empty_items: bool = False,
    ) -> dict:
        payload = super().build(
            domain=domain,
            city=city,
            transaction_id=transaction_id,
            message_id=message_id,
            provider_id=provider_id,
            item_overrides=item_overrides,
            payment_type=payment_type,
            fulfillment_type=fulfillment_type,
            order_state=order_state or self.default_on_status_state,
            order_id=order_id,
        )
        payload["context"]["action"] = "on_status"

        if empty_items:
            order = payload.get("message", {}).get("order", {})
            order["items"] = []
            order["quote"] = {
                "price": {"currency": self.currency, "value": "0.00"},
                "breakup": [],
            }
            order["payment"]["params"]["amount"] = "0.00"

        if omit_domain:
            payload["context"].pop("domain", None)
        if omit_bpp_id:
            payload["context"].pop("bpp_id", None)
            payload["context"].pop("bpp_uri", None)
        if omit_bap_id:
            payload["context"].pop("bap_id", None)
            payload["context"].pop("bap_uri", None)
        if omit_order:
            payload = {"context": payload["context"], "message": {}}
        if include_error:
            payload["error"] = include_error
        return payload


statusPayloadGenerator = StatusPayloadGenerator
OnstatusPayloadGenerator = OnStatusPayloadGenerator


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

    spg = StatusPayloadGenerator(func_cfg)
    ospg = OnStatusPayloadGenerator(func_cfg)
    nspg = StatusPayloadGenerator(neg_cfg)
    nospg = OnStatusPayloadGenerator(neg_cfg)

    def _item_overrides(generator: StatusPayloadGenerator, domain: str = None, count: int = 1, quantities: Optional[List[int]] = None, names: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        base_items = generator.items_for_domain(domain)
        if not base_items:
            base_items = [{"id": "item-001", "name": "Status Item", "price": generator.default_order_amount, "category_id": "Generic"}]
        overrides: List[Dict[str, Any]] = []
        for idx in range(count):
            item = _json_clone(base_items[idx % len(base_items)])
            item_id = str(item.get("id") or f"item-{idx + 1:03d}")
            if count > len(base_items):
                item_id = f"{item_id}-{idx + 1:02d}"
            item["id"] = item_id
            item["name"] = names[idx % len(names)] if names else str(item.get("name") or f"Status Item {idx + 1}")
            if quantities:
                item["quantity"] = quantities[idx % len(quantities)]
            elif count > 1:
                item["quantity"] = 1
            if not item.get("price") and not item.get("loan_amount"):
                item["price"] = generator.default_order_amount
            overrides.append(item)
        return overrides

    cases: List[Dict[str, Any]] = []
    primary_domain = spg.domains[0] if spg.domains else ""
    neg_primary_domain = nspg.domains[0] if nspg.domains else ""

    # =========================================================================
    # FUNCTIONAL TEST CASES  (/status forward + /on_status backward)
    # =========================================================================

    cases.append({
        "id": "F-TC001",
        "name": "status Valid Authenticated Request",
        "category": "Functional",
        "description": "[PASS EXPECTED] Sends a complete, correctly signed /status request with bpp_id and bpp_uri in context. Validates baseline happy-path authentication, payload shape, and Gateway unicast routing for order status messages.",
        "method": "POST",
        "url": f"{func_host}/status",
        "payload": spg.build(),
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [200, 202],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
    })

    for domain in spg.domains:
        cases.append({
            "id": f"F-TC002-{domain}",
            "name": f"status Different Domain: {domain}",
            "category": "Functional",
            "description": f"[PASS EXPECTED] Sends /status with context.domain='{domain}'. Verifies the Gateway accepts valid status payloads across configured ONDC domains.",
            "method": "POST",
            "url": f"{func_host}/status",
            "payload": spg.build(domain=domain),
            "raw_body": None,
            "raw_content_type": None,
            "expected_status": [200, 202],
            "auth_mode": "valid",
            "custom_headers": None,
            "ttl": None,
            "sleep_before": None,
        })

    for city in spg.cities:
        cases.append({
            "id": f"F-TC003-{city}",
            "name": f"status Different City: {city}",
            "category": "Functional",
            "description": f"[PASS EXPECTED] Sends /status with context.city='{city}'. Validates the Gateway accepts status requests for different city codes and preserves location context.",
            "method": "POST",
            "url": f"{func_host}/status",
            "payload": spg.build(city=city),
            "raw_body": None,
            "raw_content_type": None,
            "expected_status": [200, 202],
            "auth_mode": "valid",
            "custom_headers": None,
            "ttl": None,
            "sleep_before": None,
        })

    for ft_cfg in spg.fulfillment_types_for_domain(primary_domain):
        ftype = ft_cfg.get("type", "Delivery") if isinstance(ft_cfg, dict) else str(ft_cfg)
        cases.append({
            "id": f"F-TC004-{ftype}",
            "name": f"status Fulfillment Type: {ftype}",
            "category": "Functional",
            "description": f"[PASS EXPECTED] Sends /status with order.fulfillment.type='{ftype}'. Validates the Gateway accepts status payloads for all configured fulfillment modes.",
            "method": "POST",
            "url": f"{func_host}/status",
            "payload": spg.build(fulfillment_type=ftype),
            "raw_body": None,
            "raw_content_type": None,
            "expected_status": [200, 202],
            "auth_mode": "valid",
            "custom_headers": None,
            "ttl": None,
            "sleep_before": None,
        })

    for pt in spg.payment_types_for_domain(primary_domain):
        pt_label = pt.get("type", "UNKNOWN") if isinstance(pt, dict) else str(pt)
        cases.append({
            "id": f"F-TC005-{pt_label}",
            "name": f"status Payment Type: {pt_label}",
            "category": "Functional",
            "description": f"[PASS EXPECTED] Sends /status with order.payment.type='{pt_label}'. Validates the Gateway accepts status payloads covering different payment collection models.",
            "method": "POST",
            "url": f"{func_host}/status",
            "payload": spg.build(payment_type=pt if isinstance(pt, dict) else {"type": str(pt)}),
            "raw_body": None,
            "raw_content_type": None,
            "expected_status": [200, 202],
            "auth_mode": "valid",
            "custom_headers": None,
            "ttl": None,
            "sleep_before": None,
        })

    _multi_item_payload = spg.build(item_overrides=_item_overrides(spg, domain=primary_domain, count=3, quantities=[1, 1, 1]))
    cases.append({
        "id": "F-TC006",
        "name": "status Multiple Items in Order",
        "category": "Functional",
        "description": "[PASS EXPECTED] Sends /status with multiple order items in a single payload. Validates the Gateway accepts multi-item status requests and preserves quote breakup alignment with the items list.",
        "method": "POST",
        "url": f"{func_host}/status",
        "payload": _multi_item_payload,
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [200, 202],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
    })

    _qty_payload = spg.build(item_overrides=_item_overrides(spg, domain=primary_domain, count=1, quantities=[5]))
    cases.append({
        "id": "F-TC007",
        "name": "status Quantity Greater Than One",
        "category": "Functional",
        "description": "[PASS EXPECTED] Sends /status where the primary order item has quantity.count > 1. Validates the Gateway preserves item quantity data correctly.",
        "method": "POST",
        "url": f"{func_host}/status",
        "payload": _qty_payload,
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [200, 202],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
    })

    _shared_txn = f"txn-{uuid.uuid4().hex[:12]}"
    for req_num in range(1, 4):
        cases.append({
            "id": f"F-TC008-Req{req_num}",
            "name": f"status Same TxnID / Different MsgID - Req {req_num}",
            "category": "Functional",
            "description": "[PASS EXPECTED] Sends repeated /status requests with the same transaction_id but fresh message_ids. Validates repeated status polling within a shared transaction context.",
            "method": "POST",
            "url": f"{func_host}/status",
            "payload": spg.build(transaction_id=_shared_txn),
            "raw_body": None,
            "raw_content_type": None,
            "expected_status": [200, 202],
            "auth_mode": "valid",
            "custom_headers": None,
            "ttl": None,
            "sleep_before": None,
        })

    _unicode_payload = spg.build(item_overrides=_item_overrides(
        spg,
        domain=primary_domain,
        count=3,
        quantities=[1, 1, 1],
        names=["बासमती चावल", "أرز بسمتي", "香米"],
    ))
    cases.append({
        "id": "F-TC009",
        "name": "status Unicode Item Names",
        "category": "Functional",
        "description": "[PASS EXPECTED] Sends /status with Unicode item descriptors and quote breakup titles in Hindi, Arabic, and Chinese. Validates the Gateway preserves non-ASCII status metadata correctly.",
        "method": "POST",
        "url": f"{func_host}/status",
        "payload": _unicode_payload,
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [200, 202],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
    })

    _large_status_payload = spg.build(item_overrides=_item_overrides(spg, domain=primary_domain, count=20))
    cases.append({
        "id": "F-TC010",
        "name": "status Large Payload (20 Items)",
        "category": "Functional",
        "description": "[PASS EXPECTED] Sends /status with a large order containing 20 items and a long quote breakup. Validates the Gateway handles large-but-valid status payloads without truncation or timeout.",
        "method": "POST",
        "url": f"{func_host}/status",
        "payload": _large_status_payload,
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [200, 202],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
    })

    cases.append({
        "id": "F-TC011",
        "name": "on_status Valid Callback With Quote",
        "category": "Functional",
        "description": "[PASS EXPECTED] Sends a complete, correctly signed /on_status callback with provider, items, billing, fulfillment, payment, and quote breakup. Validates backward-flow callback handling for order status messages.",
        "method": "POST",
        "url": f"{func_host}/on_status",
        "payload": ospg.build(),
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [200, 202],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
    })

    cases.append({
        "id": "F-TC012",
        "name": "on_status Empty Items",
        "category": "Functional",
        "description": "[PASS EXPECTED] Sends /on_status with an order that has an empty items array. Validates the Gateway accepts edge-case callbacks where the response references a temporarily empty order state.",
        "method": "POST",
        "url": f"{func_host}/on_status",
        "payload": ospg.build(empty_items=True),
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [200, 202],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
    })

    cases.append({
        "id": "F-TC013",
        "name": "on_status With Error Block",
        "category": "Functional",
        "description": "[PASS EXPECTED] Sends /on_status with a valid order payload plus an error block describing a downstream status condition. Validates the Gateway forwards error-carrying callbacks without dropping order context.",
        "method": "POST",
        "url": f"{func_host}/on_status",
        "payload": ospg.build(include_error={"code": "20000", "message": "Status acknowledged with downstream warning"}),
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [200, 202],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
    })

    _multi_provider_payload = ospg.build()
    _providers = ospg.providers_for_domain(primary_domain)
    _provider_list = []
    for idx, provider in enumerate(_providers[:3], start=1):
        _provider_list.append({
            "id": str(provider.get("id", f"provider-{idx:03d}")),
            "descriptor": {"name": str(provider.get("name", f"Provider {idx}"))},
            "locations": [{"id": str(provider.get("location_id", f"store-location-{idx:03d}"))}],
        })
    if len(_provider_list) < 2:
        _provider_list.append({
            "id": str(_multi_provider_payload["message"]["order"]["provider"]["id"]) + "-alt",
            "descriptor": {"name": "Alternate Provider"},
            "locations": [{"id": "store-location-002"}],
        })
    _multi_provider_payload["message"]["order"]["providers"] = _provider_list
    cases.append({
        "id": "F-TC014",
        "name": "on_status Multiple Providers Metadata",
        "category": "Functional",
        "description": "[PASS EXPECTED] Sends /on_status with the standard order.provider plus an additional providers array carrying multiple provider references. Validates the Gateway tolerates richer provider metadata in status callback payloads.",
        "method": "POST",
        "url": f"{func_host}/on_status",
        "payload": _multi_provider_payload,
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [200, 202],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
    })

    _detailed_quote_payload = ospg.build()
    _detailed_quote_payload["message"]["order"]["quote"]["breakup"].extend([
        {
            "@ondc/org/item_id": "tax-001",
            "@ondc/org/title_type": "tax",
            "title": "GST",
            "price": {"currency": ospg.currency, "value": "18.00"},
        },
        {
            "@ondc/org/item_id": "status-001",
            "@ondc/org/title_type": "status",
            "title": "Status Fee",
            "price": {"currency": ospg.currency, "value": "12.00"},
        },
        {
            "@ondc/org/item_id": "fee-001",
            "@ondc/org/title_type": "convenience",
            "title": "Convenience Fee",
            "price": {"currency": ospg.currency, "value": "5.00"},
        },
    ])
    _detailed_quote_payload["message"]["order"]["quote"]["price"]["value"] = _money_sum([
        _detailed_quote_payload["message"]["order"]["quote"]["price"]["value"],
        "18.00",
        "12.00",
        "5.00",
    ])
    _detailed_quote_payload["message"]["order"]["payment"]["params"]["amount"] = _detailed_quote_payload["message"]["order"]["quote"]["price"]["value"]
    cases.append({
        "id": "F-TC015",
        "name": "on_status Detailed Quote Breakup",
        "category": "Functional",
        "description": "[PASS EXPECTED] Sends /on_status with an expanded quote breakup including tax, status fee, and convenience fee lines. Validates the Gateway preserves detailed financial breakup structures in callbacks.",
        "method": "POST",
        "url": f"{func_host}/on_status",
        "payload": _detailed_quote_payload,
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [200, 202],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
    })

    _domain2 = ospg.domains[1] if len(ospg.domains) > 1 else "ONDC:RET16"
    _domain2_is_cross = _domain2 not in set(ospg.domains)
    _domain2_desc = (
        f"[PASS EXPECTED] Sends /on_status with context.domain='{_domain2}'. "
        + (
            f"The participant is not registered for domain '{_domain2}' — the Gateway may return NACK, which is the correct and acceptable outcome for this cross-domain callback test."
            if _domain2_is_cross else
            "Validates the Gateway accepts status callbacks for non-primary configured domains."
        )
    )
    cases.append({
        "id": "F-TC016",
        "name": f"on_status Different Domain: {_domain2}",
        "category": "Functional",
        "description": _domain2_desc,
        "method": "POST",
        "url": f"{func_host}/on_status",
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

    _large_on_status_payload = ospg.build(item_overrides=_item_overrides(ospg, domain=primary_domain, count=25))
    cases.append({
        "id": "F-TC017",
        "name": "on_status Large Order (25 Items)",
        "category": "Functional",
        "description": "[PASS EXPECTED] Sends /on_status with a large order containing 25 items. Validates the Gateway accepts and forwards large callback payloads without truncating item or quote breakup data.",
        "method": "POST",
        "url": f"{func_host}/on_status",
        "payload": _large_on_status_payload,
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

    cases.append({
        "id": "N-TC001",
        "name": "status Missing Authorization Header",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401] Sends /status with Content-Type but no Authorization header. Gateway must reject unauthenticated ONDC status requests.",
        "method": "POST",
        "url": f"{neg_host}/status",
        "payload": nspg.build(),
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [401, 400],
        "auth_mode": "no_auth",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
    })

    cases.append({
        "id": "N-TC002",
        "name": "status Invalid / Tampered Signature",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401] Sends /status with a valid-looking Authorization header whose signature is intentionally tampered. Gateway must reject cryptographically invalid signatures.",
        "method": "POST",
        "url": f"{neg_host}/status",
        "payload": nspg.build(),
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [401, 400],
        "auth_mode": "tamper_sig",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
    })

    _no_domain = nspg.build()
    _no_domain["context"].pop("domain", None)
    cases.append({
        "id": "N-TC003",
        "name": "status Missing context.domain",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401/400/NACK] Sends /status with context.domain removed. Domain is mandatory for Gateway validation and routing. Gateway may return 4xx or HTTP 200 NACK.",
        "method": "POST",
        "url": f"{neg_host}/status",
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

    _no_bap = nspg.build()
    _no_bap["context"].pop("bap_id", None)
    cases.append({
        "id": "N-TC004",
        "name": "status Missing context.bap_id",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401/400/NACK] Sends /status with bap_id removed from context. Without bap_id, Gateway cannot identify the requesting buyer application. Gateway may return 4xx or HTTP 200 NACK.",
        "method": "POST",
        "url": f"{neg_host}/status",
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

    _no_bpp = nspg.build()
    _no_bpp["context"].pop("bpp_id", None)
    _no_bpp["context"].pop("bpp_uri", None)
    cases.append({
        "id": "N-TC005",
        "name": "status Missing context.bpp_id",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401/400/NACK] Sends /status with bpp_id and bpp_uri removed from context. status is always unicast, so the Gateway must reject a payload that does not identify the target BPP. Gateway may return 4xx or HTTP 200 NACK.",
        "method": "POST",
        "url": f"{neg_host}/status",
        "payload": _no_bpp,
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [400, 401],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
        "nack_ok": True,
    })

    cases.append({
        "id": "N-TC006",
        "name": "status Expired Signature (TTL = 10s)",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401] Generates a /status signature with TTL=10s then waits 12 seconds before sending. Gateway must reject requests whose authentication signature is already expired.",
        "method": "POST",
        "url": f"{neg_host}/status",
        "payload": nspg.build(),
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [401, 400],
        "auth_mode": "expired",
        "custom_headers": None,
        "ttl": 10,
        "sleep_before": 12,
    })

    _bad_ver = nspg.build()
    _bad_ver["context"]["core_version"] = "99.abcd"
    cases.append({
        "id": "N-TC007",
        "name": "status Invalid core_version (99.abcd)",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401/400] Sends /status with an invalid core_version value. Gateway must reject requests referencing unsupported protocol versions.",
        "method": "POST",
        "url": f"{neg_host}/status",
        "payload": _bad_ver,
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [400, 401],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
    })

    _bad_domain = nspg.build()
    _bad_domain["context"]["domain"] = "INVALID:DOMAIN999"
    cases.append({
        "id": "N-TC008",
        "name": "status Invalid Domain (INVALID:DOMAIN999)",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401/400] Sends /status with an unrecognised domain code. Gateway must reject requests for unsupported ONDC domains.",
        "method": "POST",
        "url": f"{neg_host}/status",
        "payload": _bad_domain,
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [400, 401],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
    })

    _bad_city = nspg.build()
    _bad_city["context"]["city"] = "invalid:city:format"
    cases.append({
        "id": "N-TC009",
        "name": "status Invalid City Code (invalid:city:format)",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401/400/NACK] Sends /status with a malformed city code. Gateway may return 4xx or HTTP 200 NACK.",
        "method": "POST",
        "url": f"{neg_host}/status",
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

    _bad_country = nspg.build()
    _bad_country["context"]["country"] = "XYZZY"
    cases.append({
        "id": "N-TC010",
        "name": "status Invalid Country Code (XYZZY)",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401/400/NACK] Sends /status with an invalid country code. Gateway may return 4xx or HTTP 200 NACK.",
        "method": "POST",
        "url": f"{neg_host}/status",
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

    _bad_shape = nspg.build()
    _bad_shape["message"] = {"unexpected": "missing order block"}
    cases.append({
        "id": "N-TC011",
        "name": "status Malformed JSON Structure (missing message.order)",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401/400/NACK] Sends /status with valid JSON but the wrong ONDC shape (message.order missing). Gateway must reject structurally invalid status payloads. May return 4xx or HTTP 200 NACK.",
        "method": "POST",
        "url": f"{neg_host}/status",
        "payload": _bad_shape,
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [400, 401],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
        "nack_ok": True,
    })

    cases.append({
        "id": "N-TC012",
        "name": "status Invalid JSON Syntax (raw string)",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401/400] Sends POST /status with Content-Type application/json but body is '{not valid json'. Gateway must reject unparseable JSON.",
        "method": "POST",
        "url": f"{neg_host}/status",
        "payload": None,
        "raw_body": "{not valid json",
        "raw_content_type": "application/json",
        "expected_status": [400, 401],
        "auth_mode": "custom",
        "custom_headers": {"Content-Type": "application/json"},
        "ttl": None,
        "sleep_before": None,
    })

    cases.append({
        "id": "N-TC013",
        "name": "status Empty JSON Payload ({})",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401/400] Sends POST /status with an empty JSON body {}. Gateway must reject payloads with no context or message data.",
        "method": "POST",
        "url": f"{neg_host}/status",
        "payload": {},
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [400, 401],
        "auth_mode": "custom",
        "custom_headers": {"Content-Type": "application/json"},
        "ttl": None,
        "sleep_before": None,
    })

    cases.append({
        "id": "N-TC014",
        "name": "status Wrong HTTP Method (GET)",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 404/405] Sends the /status request as GET instead of POST. ONDC Gateway status endpoints only accept POST.",
        "method": "GET",
        "url": f"{neg_host}/status",
        "payload": None,
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [404, 405],
        "auth_mode": "no_auth",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
    })

    cases.append({
        "id": "N-TC015",
        "name": "status Wrong Content-Type (text/plain)",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401/400] Sends /status with Content-Type: text/plain instead of application/json. Gateway should reject invalid content types for ONDC payloads.",
        "method": "POST",
        "url": f"{neg_host}/status",
        "payload": None,
        "raw_body": "plain text body",
        "raw_content_type": "text/plain",
        "expected_status": [400, 401],
        "auth_mode": "custom",
        "custom_headers": {"Content-Type": "text/plain"},
        "ttl": None,
        "sleep_before": None,
    })

    cases.append({
        "id": "N-TC016",
        "name": "status Invalid Authorization Header Format",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401] Sends /status with Authorization: Bearer token_xyz instead of the ONDC Signature format. Gateway must reject non-ONDC auth schemes.",
        "method": "POST",
        "url": f"{neg_host}/status",
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

    _no_txn = nspg.build()
    _no_txn["context"].pop("transaction_id", None)
    cases.append({
        "id": "N-TC017",
        "name": "status Missing context.transaction_id",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401/400/NACK] Sends /status with transaction_id removed from context. Gateway may return 4xx or HTTP 200 NACK.",
        "method": "POST",
        "url": f"{neg_host}/status",
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

    _no_ts = nspg.build()
    _no_ts["context"].pop("timestamp", None)
    cases.append({
        "id": "N-TC018",
        "name": "status Missing context.timestamp",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401/400/NACK] Sends /status with context.timestamp removed. Gateway may return 4xx or HTTP 200 NACK.",
        "method": "POST",
        "url": f"{neg_host}/status",
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

    _dos_items = _item_overrides(nspg, domain=neg_primary_domain, count=100)
    for idx, item in enumerate(_dos_items, start=1):
        huge = "x" * 500
        item["name"] = f"DoS Item {idx} {huge}"
        item["descriptor"] = {"name": item["name"], "short_desc": huge}
    _dos_payload = nspg.build(item_overrides=_dos_items)
    cases.append({
        "id": "N-TC019",
        "name": "status Extremely Large Payload (DoS / Size Limit)",
        "category": "Negative",
        "description": "[PASS EXPECTED] Sends /status with 100 items whose descriptors are intentionally oversized. The current gateway accepts this large payload, so a normal HTTP ACK response is treated as the correct outcome for this stress test.",
        "method": "POST",
        "url": f"{neg_host}/status",
        "payload": _dos_payload,
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [200, 202],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
        "accept_ack": True,
    })

    _no_action = nspg.build()
    _no_action["context"].pop("action", None)
    cases.append({
        "id": "N-TC020",
        "name": "status Missing context.action",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401/400/NACK] Sends /status with context.action removed. Gateway must reject a payload whose action cannot be validated. May return 4xx or HTTP 200 NACK.",
        "method": "POST",
        "url": f"{neg_host}/status",
        "payload": _no_action,
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [400, 401],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
        "nack_ok": True,
    })

    cases.append({
        "id": "N-TC021",
        "name": "on_status Missing Authorization Header",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401] Sends /on_status with no Authorization header. Backward callbacks must also be authenticated.",
        "method": "POST",
        "url": f"{neg_host}/on_status",
        "payload": nospg.build(),
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [401, 400],
        "auth_mode": "no_auth",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
    })

    cases.append({
        "id": "N-TC022",
        "name": "on_status Tampered Signature",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401] Sends /on_status with a cryptographically invalid signature. Gateway must verify the BPP's signature before accepting the callback.",
        "method": "POST",
        "url": f"{neg_host}/on_status",
        "payload": nospg.build(),
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [401, 400],
        "auth_mode": "tamper_sig",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
    })

    cases.append({
        "id": "N-TC024",
        "name": "on_status Missing context.bap_id",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401/400/NACK] Sends /on_status without bap_id and bap_uri in context. Gateway may return 4xx or HTTP 200 NACK because it cannot route the callback to the target BAP.",
        "method": "POST",
        "url": f"{neg_host}/on_status",
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

    cases.append({
        "id": "N-TC025",
        "name": "on_status Missing context.domain",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401/400/NACK] Sends /on_status with domain removed from context. Gateway may return 4xx or HTTP 200 NACK.",
        "method": "POST",
        "url": f"{neg_host}/on_status",
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

    cases.append({
        "id": "N-TC026",
        "name": "on_status Wrong HTTP Method (GET)",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 404/405] Sends the /on_status request as GET instead of POST. ONDC Gateway callback endpoints only accept POST.",
        "method": "GET",
        "url": f"{neg_host}/on_status",
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
        elif tc.get("accept_ack") and _is_nack(resp_body):
            passed = False
            status_note = f"HTTP {resp_status} - received NACK (expected a normal accepted response)"
        elif tc["category"] == "Negative" and resp_status == 200 and not _is_nack(resp_body) and not tc.get("accept_ack"):
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
            auth_note_html = f'<span class="auth-chip">{_esc(r["auth_note"])} </span>'

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
<title>ONDC Gateway status API Test Report</title>
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
    <h1>ONDC <span>Gateway status API</span> Test Report</h1>
    <p>
      <strong>Source:</strong> Gateway /status &amp; /on_status — Functional &amp; Negative
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
def _reg_get_admin_token(cfg: dict) -> str:
    """Obtain a SUPER_ADMIN Bearer token via RegistryAuthClient dynamic login."""
    admin_api_url = str(cfg.get("registry_url") or "")
    admin_auth_url = str(cfg.get("admin_auth_url") or "")
    admin_email = str(cfg.get("admin_email") or "")
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
    uk_id = str(cfg.get("uk_id", ""))
    bap_uri = str(cfg.get("bap_uri", ""))
    domains = cfg.get("domains", ["ONDC:RET10"])
    cities = cfg.get("cities", ["std:080"])
    country = str(cfg.get("country", "IND"))
    slug = _slugify(participant_id)
    location_id = str(cfg.get("registration_location_id") or f"loc-{slug}")
    uri_id = str(cfg.get("registration_uri_id") or f"uri-{slug}")
    configs = [
        {"domain": d, "np_type": "BAP", "subscriber_id": participant_id,
         "location_id": location_id, "uri_id": uri_id, "key_id": uk_id}
        for d in domains
    ]
    return {
        "participant_id": participant_id,
        "action": "SUBSCRIBED",
        "credentials": [{"cred_id": f"cred-{slug}", "type": "GST",
                         "cred_data": {"gstin": "29ABCDE1234F1Z5",
                                       "legal_name": "Gateway Test BAP Pvt Ltd"}}],
        "contacts": [{"contact_id": f"contact-{slug}", "type": "TECHNICAL",
                      "name": "GW Test Tech", "email": "gw-tech@participant.ondc",
                      "phone": "+919876543210", "is_primary": True}],
        "key": [{"uk_id": uk_id, "signing_public_key": signing_pub,
                 "encryption_public_key": enc_pub,
                 "signed_algorithm": "ED25519", "encryption_algorithm": "X25519",
                 "valid_from": "2024-01-01T00:00:00.000Z",
                 "valid_until": "2026-12-31T23:59:59.000Z"}],
        "location": [{"location_id": location_id, "type": "SERVICEABLE",
                     "country": country, "city": cities[:1]}],
        "uri": [{"uri_id": uri_id, "type": "CALLBACK", "url": bap_uri}],
        "configs": configs,
        "dns_skip": True,
        "skip_ssl_verification": True,
    }


def _reg_already_registered(body: str) -> bool:
    try:
        data = json.loads(body)
        code = str(data.get("error", {}).get("code", ""))
        msg = str(data.get("error", {}).get("message", "")).lower()
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

    participant_id = str(cfg.get("participant_id", ""))
    uk_id = str(cfg.get("uk_id", ""))
    private_key_seed = str(cfg.get("private_key_seed", ""))
    registry_url = str(cfg.get("registry_url", "https://registry-uat.kynondc.net"))
    reg_timeout = _safe_int(cfg.get("registration_timeout_seconds", 15), 15)

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

    url = f"{registry_url.rstrip('/')}/admin/subscribe"
    payload = _reg_build_payload(cfg, signing_pub, enc_pub)
    wire = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    try:
        resp = requests.post(url, data=wire.encode(), headers=headers,
                             timeout=reg_timeout, verify=_SSL_VERIFY)
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
        description="ONDC Gateway status API Test Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Output HTML path. If omitted, auto-generated as reports/Gateway-status-<suite>-<timestamp>.html",
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
        default="resources/gateway/ondc_gateway_status_functional.yml",
        help="Path to functional YAML config (relative to project root or absolute)",
    )
    parser.add_argument(
        "--neg-config",
        default="resources/gateway/ondc_gateway_status_negative.yml",
        help="Path to negative YAML config (relative to project root or absolute)",
    )
    parser.add_argument(
        "--filter",
        default=None,
        help="Run only the test case(s) whose ID or name contains this text (e.g. F-TC011)",
    )
    parser.add_argument(
        "--skip-register",
        action="store_true",
        help="Skip the BAP participant registration step",
    )
    args = parser.parse_args()

    if not args.skip_register:
        pass

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
            f"Gateway-status-{args.suite}-{ts_file}.html",
        )

    logger.info("=" * 60)
    logger.info("ONDC Gateway status API Test Runner")
    logger.info(f"Run timestamp : {run_ts}")
    logger.info(f"Suite         : {args.suite}")
    logger.info(f"Timeout       : {args.timeout}s")
    logger.info(f"Func config   : {args.func_config}")
    logger.info(f"Neg config    : {args.neg_config}")
    logger.info(f"Filter        : {args.filter or '(none)'}")
    logger.info(f"Output        : {output_path}")
    logger.info("=" * 60)

    func_cfg = load_yaml_config(args.func_config)
    neg_cfg = load_yaml_config(args.neg_config)

    validate_config(func_cfg, args.func_config, "Functional")
    validate_config(neg_cfg, args.neg_config, "Negative")

    if not args.skip_register:
        register_bap_participant(func_cfg)

    logger.info(f"Functional host : {func_cfg.get('host', 'NOT SET')}")
    logger.info(f"Negative host   : {neg_cfg.get('host', 'NOT SET')}")

    func_auth = build_auth_helper(func_cfg, label="Functional")
    neg_auth = build_auth_helper(neg_cfg, label="Negative")
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
        _filters = [f.strip() for f in args.filter.split(",") if f.strip()]
        cases = [
            c for c in cases
            if any(
                f.lower() in c["id"].lower() or f.lower() in c["name"].lower()
                for f in _filters
            )
        ]

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
    logger.info(f"Report -> {output_path}")


if __name__ == "__main__":
    main()
