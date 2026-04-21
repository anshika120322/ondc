#!/usr/bin/env python3
"""
ONDC Gateway Search API - Automated Test Runner with HTML Report Generator

Runs all functional and negative test cases for the ONDC /search and /on_search
endpoints and generates a comprehensive dark-theme HTML report.

Usage:
    python func_test_scripts/run_search_api_tests.py
    python func_test_scripts/run_search_api_tests.py --suite functional
    python func_test_scripts/run_search_api_tests.py --suite negative
    python func_test_scripts/run_search_api_tests.py --timeout 30
    python func_test_scripts/run_search_api_tests.py --output reports/my_report.html
    python func_test_scripts/run_search_api_tests.py --func-config resources/gateway/ondc_gateway_search_functional.yml
    python func_test_scripts/run_search_api_tests.py --neg-config  resources/gateway/ondc_gateway_search_negative.yml
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
def load_yaml_config(path: str, tenant: str = "ondcGatewaySearch") -> dict:
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
            # NaCl 64-byte key: seed is first 32 bytes
            return pkcs8[:32]
        if len(pkcs8) >= 32:
            # PKCS#8 DER: 32-byte seed is at the end
            return pkcs8[-32:]
    except Exception:
        pass
    return None


# Required fields in each YAML config (under ondcGatewaySearch tenant)
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
            + " 'ondcGatewaySearch:' key.\n"
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
# Search Payload Generator  (/search — forward flow)
# ---------------------------------------------------------------------------
class SearchPayloadGenerator:
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
        self.finder_fee_type = str(cfg.get("finder_fee_type", "percent"))
        self.finder_fee_amount = str(cfg.get("finder_fee_amount", "3.0"))

        primary_domain = self.domains[0] if self.domains else ""

        # test_providers: may be domain-keyed dict or flat list
        raw_providers = cfg.get("test_providers", [])
        if isinstance(raw_providers, dict):
            self.test_providers = raw_providers.get(primary_domain, next(iter(raw_providers.values()), []))
        else:
            self.test_providers = raw_providers or []

        # payment_types: may be domain-keyed dict or flat list
        raw_payment_types = cfg.get("payment_types", [])
        if isinstance(raw_payment_types, dict):
            self.payment_types = raw_payment_types.get(primary_domain, next(iter(raw_payment_types.values()), []))
        else:
            self.payment_types = raw_payment_types or []

        # fulfillment_types: may be domain-keyed dict or flat list
        raw_ft = cfg.get("fulfillment_types", [])
        if isinstance(raw_ft, dict):
            raw_ft = raw_ft.get(primary_domain, next(iter(raw_ft.values()), []))
        self.fulfillment_types = raw_ft or []

        # test_items: nested under test_data.{domain}.test_items; fall back to flat test_items
        raw_test_data = cfg.get("test_data", {})
        if isinstance(raw_test_data, dict) and raw_test_data:
            domain_data = raw_test_data.get(primary_domain, next(iter(raw_test_data.values()), {}))
            raw_items_from_data = domain_data.get("test_items", []) if isinstance(domain_data, dict) else []
        else:
            raw_items_from_data = []
        self.test_items = raw_items_from_data or cfg.get("test_items", [])

        # search_items: use test_items names when search_items not in YAML
        raw_search = cfg.get("search_items", None)
        self.search_items: List[Dict] = []
        if raw_search:
            for it in raw_search:
                if isinstance(it, dict):
                    self.search_items.append(it)
                else:
                    _cat = self.test_items[0].get("category_id", "") if self.test_items else ""
                    self.search_items.append(
                        {"name": str(it), "category_id": _cat, "code": str(it).upper()[:10]}
                    )
        else:
            # Derive search items from test_items
            for it in self.test_items:
                self.search_items.append({
                    "name": it.get("name", ""),
                    "category_id": it.get("category_id", ""),
                    "code": it.get("id", "").upper(),
                })

        self.item_categories = cfg.get("item_categories", [])
        self.domain_tags = cfg.get("domain_tags", [])
        self.test_locations = cfg.get("test_locations", [])
        self.multiple_items = cfg.get("multiple_items", [])

    def _resolve_domain_intent(
        self,
        domain: str,
        item_name: str = None,
        item_category_id: str = None,
    ):
        """Return (category_dict, item_dict, tags_list) derived from domain_tags for *domain*.

        Logic:
          1. Look up domain_tags[domain] (dict keyed by domain code).
          2. Take the first tag group's first list value as the canonical item value
             (e.g. loan_type → personal_loan for ONDC:FIS12).
          3. Build a human-friendly item name (snake_case → Title Case) and a short
             code abbreviation (initials + '001', e.g. PL001).
          4. Falls back to search_items[0] when no domain_tags entry exists.
        """
        domain_tag_list = None
        if isinstance(self.domain_tags, dict):
            domain_tag_list = self.domain_tags.get(domain)

        if not domain_tag_list:
            # Fallback — use first search_item or first test_item from YAML
            _si = self.search_items[0] if self.search_items else (self.test_items[0] if self.test_items else {})
            name = item_name or _si.get("name", "")
            cat_id = item_category_id or _si.get("category_id", "")
            category = {"descriptor": {"name": name}, "id": cat_id}
            item = {
                "descriptor": {"name": name.replace("_", " ").title(), "code": name.upper()[:8] + "001"},
                "category_id": cat_id,
            }
            return category, item, []

        # Derive names from first tag group's first value
        first_tag = domain_tag_list[0]
        first_list = first_tag.get("list", [])
        first_value = first_list[0].get("value", "item") if first_list else "item"

        cat_name = item_name or first_value
        cat_id = item_category_id or cat_name.upper()

        words = cat_name.replace("-", "_").split("_")
        abbrev = "".join(w[0].upper() for w in words if w) + "001"
        human_name = " ".join(w.capitalize() for w in words if w)

        category = {"descriptor": {"name": cat_name}, "id": cat_id}
        item = {"descriptor": {"name": human_name, "code": abbrev}, "category_id": cat_id}
        return category, item, domain_tag_list

    def build(
        self,
        domain: str = None,
        city: str = None,
        transaction_id: str = None,
        message_id: str = None,
        item_name: str = None,
        item_category_id: str = None,
        fulfillment_type: str = None,
        fulfillment_gps: str = None,
        fulfillment_area_code: str = None,
        payment_type: dict = None,
        include_bpp_id: bool = False,
    ) -> dict:
        txn_id = transaction_id or f"txn-{uuid.uuid4().hex[:12]}"
        msg_id = message_id or f"msg-{uuid.uuid4().hex[:12]}"

        sel_domain = domain or (self.domains[0] if self.domains else "")
        sel_city = city or (self.cities[0] if self.cities else "")

        # Determine fulfillment details — defaults from YAML test_locations[0] and fulfillment_types[0]
        _def_loc = self.test_locations[0] if self.test_locations else {}
        gps = _def_loc.get("gps", "")
        area_code = _def_loc.get("area_code", "")
        ftype = ""
        if self.fulfillment_types and not fulfillment_type:
            ft_cfg = self.fulfillment_types[0]
            ftype = ft_cfg.get("type", "") if isinstance(ft_cfg, dict) else str(ft_cfg)
            loc = ft_cfg.get("location", {}) if isinstance(ft_cfg, dict) else {}
            gps = loc.get("gps", gps)
            area_code = loc.get("area_code", area_code)
        elif fulfillment_type:
            ftype = fulfillment_type
        if fulfillment_gps:
            gps = fulfillment_gps
        if fulfillment_area_code:
            area_code = fulfillment_area_code

        # Domain-aware category, item and tags derived from domain_tags YAML config
        domain_category, domain_item, domain_intent_tags = self._resolve_domain_intent(
            sel_domain, item_name, item_category_id
        )

        # Payment — default from YAML payment_types[0]
        pt = payment_type or (self.payment_types[0] if self.payment_types else {})

        ctx: dict = {
            "domain": sel_domain,
            "action": "search",
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
        if include_bpp_id and self.bpp_id:
            ctx["bpp_id"] = self.bpp_id
            ctx["bpp_uri"] = self.bpp_uri

        intent: dict = {
            "fulfillment": {
                "type": ftype,
                "end": {
                    "location": {
                        "gps": gps,
                        "area_code": area_code,
                    }
                },
            },
            "payment": {
                "@ondc/org/buyer_app_finder_fee_type": self.finder_fee_type,
                "@ondc/org/buyer_app_finder_fee_amount": self.finder_fee_amount,
                "type": pt.get("type", "PRE-FULFILLMENT") if isinstance(pt, dict) else "PRE-FULFILLMENT",
                "collected_by": pt.get("collected_by", "BAP") if isinstance(pt, dict) else "BAP",
            },
            "category": domain_category,
            "item": domain_item,
        }
        if domain_intent_tags:
            intent["tags"] = domain_intent_tags

        return {
            "context": ctx,
            "message": {"intent": intent},
        }


# ---------------------------------------------------------------------------
# OnSearch Payload Generator  (/on_search — backward callback from BPP)
# ---------------------------------------------------------------------------
class OnSearchPayloadGenerator:
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
            self.test_providers = raw_providers.get(primary_domain, next(iter(raw_providers.values()), []))
        else:
            self.test_providers = raw_providers or []

        self.test_locations = cfg.get("test_locations", [])
        self.default_item_price = str(cfg.get("default_order_amount", ""))

        # test_items: nested under test_data.{domain}.test_items; fall back to flat test_items
        raw_test_data = cfg.get("test_data", {})
        if isinstance(raw_test_data, dict) and raw_test_data:
            domain_data = raw_test_data.get(primary_domain, next(iter(raw_test_data.values()), {}))
            raw_items = domain_data.get("test_items", []) if isinstance(domain_data, dict) else []
        else:
            raw_items = cfg.get("test_items", [])
        self.test_items = raw_items or []

    def build(
        self,
        domain: str = None,
        city: str = None,
        transaction_id: str = None,
        message_id: str = None,
        omit_catalog: bool = False,
        omit_bpp_id: bool = False,
        omit_bap_id: bool = False,
        omit_domain: bool = False,
        include_error: dict = None,
        empty_catalog: bool = False,
    ) -> dict:
        txn_id = transaction_id or f"txn-{uuid.uuid4().hex[:12]}"
        msg_id = message_id or f"msg-{uuid.uuid4().hex[:12]}"
        now = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")

        sel_domain = domain or (self.domains[0] if self.domains else "")
        sel_city = city or (self.cities[0] if self.cities else "")

        ctx: dict = {
            "domain": sel_domain,
            "action": "on_search",
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

        if omit_catalog:
            payload: dict = {"context": ctx, "message": {}}
            if include_error:
                payload["error"] = include_error
            return payload

        prov = self.test_providers[0] if self.test_providers else {}
        item = self.test_items[0] if self.test_items else {}
        _def_gps = self.test_locations[0].get("gps", "") if self.test_locations else ""
        _item_price = item.get("price") or item.get("loan_amount") or self.default_item_price

        if empty_catalog:
            catalog = {
                "bpp/descriptor": {"name": prov.get("name", ""), "short_desc": "No items available"},
                "bpp/providers": [],
            }
        else:
            catalog = {
                "bpp/descriptor": {
                    "name": prov.get("name", ""),
                    "short_desc": "Your local store",
                },
                "bpp/providers": [
                    {
                        "id": prov.get("id", ""),
                        "descriptor": {
                            "name": prov.get("name", ""),
                            "short_desc": prov.get("name", "") + " - available",
                        },
                        "locations": [
                            {
                                "id": prov.get("location_id", ""),
                                "gps": prov.get("gps", _def_gps),
                                "address": prov.get("address", ""),
                            }
                        ],
                        "items": [
                            {
                                "id": item.get("id", ""),
                                "descriptor": {
                                    "name": item.get("name", ""),
                                    "short_desc": f"{item.get('name', '')} - available now",
                                },
                                "price": {
                                    "currency": self.currency,
                                    "value": _item_price,
                                },
                                "quantity": {"available": {"count": 100}},
                                "category_id": item.get("category_id", ""),
                            }
                        ],
                    }
                ],
            }

        payload = {"context": ctx, "message": {"catalog": catalog}}
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

    spg = SearchPayloadGenerator(func_cfg)
    ospg = OnSearchPayloadGenerator(func_cfg)
    nspg = SearchPayloadGenerator(neg_cfg)
    nospg = OnSearchPayloadGenerator(neg_cfg)

    cases: List[Dict[str, Any]] = []

    # =========================================================================
    # FUNCTIONAL TEST CASES  (/search forward + /on_search backward)
    # =========================================================================

    # F-TC001 — Valid broadcast /search with authentication
    cases.append({
        "id": "F-TC001",
        "name": "Search Valid Authenticated Request (Broadcast)",
        "category": "Functional",
        "description": "[PASS EXPECTED] Sends a complete, correctly signed broadcast /search request. No bpp_id in context — Gateway is expected to fanout the search to all registered BPPs for the domain+city. Validates baseline happy-path authentication and routing.",
        "method": "POST",
        "url": f"{func_host}/search",
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
            "name": f"Search Different Domain: {domain}",
            "category": "Functional",
            "description": f"[PASS EXPECTED] Sends /search with context.domain='{domain}'. Verifies the Gateway routes search requests to the correct vertical (Grocery/Health/Financial Services) without rejecting valid domain codes.",
            "method": "POST",
            "url": f"{func_host}/search",
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
            "name": f"Search Different City: {city}",
            "category": "Functional",
            "description": f"[PASS EXPECTED] Sends /search with context.city='{city}'. Validates Gateway accepts search requests targeting different delivery cities across India and routes them to sellers in the correct geography.",
            "method": "POST",
            "url": f"{func_host}/search",
            "payload": spg.build(city=city),
            "raw_body": None,
            "raw_content_type": None,
            "expected_status": [200, 202],
            "auth_mode": "valid",
            "custom_headers": None,
            "ttl": None,
            "sleep_before": None,
        })

    # F-TC004 — Different fulfillment types in search intent
    for ft_cfg in spg.fulfillment_types:
        if isinstance(ft_cfg, dict):
            ftype = ft_cfg.get("type", "Delivery")
            loc = ft_cfg.get("location", {})
            gps = loc.get("gps")
            area = loc.get("area_code")
        else:
            ftype = str(ft_cfg)
            gps = None
            area = None
        cases.append({
            "id": f"F-TC004-{ftype}",
            "name": f"Search Fulfillment Type: {ftype}",
            "category": "Functional",
            "description": f"[PASS EXPECTED] Sends /search with intent.fulfillment.type='{ftype}'. Validates Gateway routes searches for all fulfillment modes: Delivery (home), Pickup (store), Self-Pickup.",
            "method": "POST",
            "url": f"{func_host}/search",
            "payload": spg.build(fulfillment_type=ftype, fulfillment_gps=gps, fulfillment_area_code=area),
            "raw_body": None,
            "raw_content_type": None,
            "expected_status": [200, 202],
            "auth_mode": "valid",
            "custom_headers": None,
            "ttl": None,
            "sleep_before": None,
        })

    # F-TC005 — Different payment preferences in search intent
    for pt in spg.payment_types:
        pt_label = pt.get("type", "UNKNOWN") if isinstance(pt, dict) else str(pt)
        cases.append({
            "id": f"F-TC005-{pt_label}",
            "name": f"Search Payment Preference: {pt_label}",
            "category": "Functional",
            "description": f"[PASS EXPECTED] Sends /search with intent.payment.type='{pt_label}'. Validates Gateway accepts searches filtered by different buyer payment preferences (PRE-FULFILLMENT, ON-FULFILLMENT, POST-FULFILLMENT).",
            "method": "POST",
            "url": f"{func_host}/search",
            "payload": spg.build(payment_type=pt),
            "raw_body": None,
            "raw_content_type": None,
            "expected_status": [200, 202],
            "auth_mode": "valid",
            "custom_headers": None,
            "ttl": None,
            "sleep_before": None,
        })

    # F-TC006 — Search with item category and code details
    _first_item = spg.test_items[0] if spg.test_items else {}
    _cat = spg.item_categories[0] if spg.item_categories else {
        "category_id": _first_item.get("category_id", ""),
        "name": _first_item.get("name", ""),
        "code": _first_item.get("id", "").upper(),
    }
    _cat6 = spg.build(item_name=_cat.get("name", "rice"), item_category_id=_cat.get("category_id", "Grocery"))
    _cat6["message"]["intent"]["item"] = {
        "descriptor": {"name": _cat.get("name", "rice"), "code": _cat.get("code", "RICE001")},
        "category_id": _cat.get("category_id", "Grocery"),
    }
    cases.append({
        "id": "F-TC006",
        "name": "Search With Item Category and Code",
        "category": "Functional",
        "description": "[PASS EXPECTED] Sends /search with a fully-specified item descriptor (name + code) and category_id in the intent. Verifies Gateway accepts structured item-level search criteria as part of the intent.",
        "method": "POST",
        "url": f"{func_host}/search",
        "payload": _cat6,
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [200, 202],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
    })

    # F-TC007 — Search with domain-specific tags (ONDC:RET10 grocery tags)
    _tag_payload = spg.build(domain=spg.domains[0])
    # domain_tags may be a dict keyed by domain name or a list — handle both
    if isinstance(spg.domain_tags, dict):
        _first_domain_tags = next(iter(spg.domain_tags.values()), [])
        _tag_list = (_first_domain_tags[:2] if isinstance(_first_domain_tags, list) else [_first_domain_tags])
    elif isinstance(spg.domain_tags, list):
        _tag_list = spg.domain_tags[:2]
    else:
        _tag_list = []
    # Derive fallback tag from first test_item when no domain_tags configured
    if not _tag_list and spg.test_items:
        _fi = spg.test_items[0]
        _tag_list = [{"code": _fi.get("category_id", "item_type"), "list": [{"code": "type", "value": _fi.get("name", "")}]}]
    _tag_payload["message"]["intent"]["tags"] = _tag_list
    cases.append({
        "id": "F-TC007",
        "name": "Search With Domain-Specific Tags",
        "category": "Functional",
        "description": "[PASS EXPECTED] Sends /search with ONDC domain-specific tags in the intent (e.g. product_category=staples, dietary=organic). Validates Gateway correctly passes through domain-specific search filters to BPPs.",
        "method": "POST",
        "url": f"{func_host}/search",
        "payload": _tag_payload,
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [200, 202],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
    })

    # F-TC008 — Search with location radius (circle-based search)
    _loc_cfg = spg.test_locations[0] if spg.test_locations else {"city": "std:080", "gps": "12.9716,77.5946", "area_code": "560001", "radius_km": 5}
    _radius_payload = spg.build(city=_loc_cfg.get("city", "std:080"), fulfillment_gps=_loc_cfg.get("gps"), fulfillment_area_code=_loc_cfg.get("area_code"))
    _radius_payload["message"]["intent"]["fulfillment"]["end"]["location"]["circle"] = {
        "gps": _loc_cfg.get("gps", "12.9716,77.5946"),
        "radius": {"value": str(_loc_cfg.get("radius_km", 5)), "unit": "km"},
    }
    cases.append({
        "id": "F-TC008",
        "name": "Search With Location Radius (Circle Search)",
        "category": "Functional",
        "description": "[PASS EXPECTED] Sends /search with a fulfillment circle (GPS + radius in km) to restrict results to sellers within a geographic radius. Validates Gateway accepts and passes radius-constrained location searches.",
        "method": "POST",
        "url": f"{func_host}/search",
        "payload": _radius_payload,
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [200, 202],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
    })

    # F-TC009 — Search with multiple items in intent
    _multi_payload = spg.build()
    _multi_items = spg.multiple_items or [
        {"descriptor": {"name": s["name"]}, "category_id": s.get("category_id", "Grocery")}
        for s in spg.search_items[:3]
    ]
    _multi_payload["message"]["intent"]["items"] = _multi_items
    cases.append({
        "id": "F-TC009",
        "name": "Search Multiple Items in Intent",
        "category": "Functional",
        "description": "[PASS EXPECTED] Sends /search with an intent containing multiple item descriptors (e.g. Rice, Oil, Vitamins). Validates Gateway accepts multi-item search requests and routes them without truncating the items list.",
        "method": "POST",
        "url": f"{func_host}/search",
        "payload": _multi_payload,
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [200, 202],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
    })

    # F-TC010 — Category-only search (no item name — browse by category)
    _cat_only_payload = spg.build()
    _cat_only_payload["message"]["intent"].pop("category", None)
    _cat_only_payload["message"]["intent"]["provider"] = {"descriptor": {"name": ""}}
    cases.append({
        "id": "F-TC010",
        "name": "Search Category-Only (No Item Name)",
        "category": "Functional",
        "description": "[PASS EXPECTED] Sends /search with minimal intent — fulfillment and payment only, no item/category descriptor. Validates Gateway accepts open/browse searches without a specific item keyword.",
        "method": "POST",
        "url": f"{func_host}/search",
        "payload": _cat_only_payload,
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [200, 202],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
    })

    # F-TC011 — Unicast/sync search (with bpp_id in context)
    _unicast_payload = spg.build(include_bpp_id=True)
    cases.append({
        "id": "F-TC011",
        "name": "Search Unicast Mode (bpp_id in Context)",
        "category": "Functional",
        "description": "[PASS EXPECTED] Sends /search with bpp_id and bpp_uri in context — Gateway routes directly to the specified BPP (synchronous unicast mode) instead of broadcasting. Validates that targeted single-BPP search routing is supported.",
        "method": "POST",
        "url": f"{func_host}/search",
        "payload": _unicast_payload,
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [200, 202],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
    })

    # F-TC012 — Repeated searches with same transaction_id, different message_id
    _shared_txn = f"txn-{uuid.uuid4().hex[:12]}"
    for req_num in range(1, 4):
        cases.append({
            "id": f"F-TC012-Req{req_num}",
            "name": f"Search Same TxnID / Different MsgID - Req {req_num}",
            "category": "Functional",
            "description": f"[PASS EXPECTED] Sends /search request #{req_num} reusing the same transaction_id but a fresh message_id. All 3 requests share txn='{_shared_txn[:16]}...'. Validates Gateway handles polling/retry scenarios where a buyer re-issues search in the same session.",
            "method": "POST",
            "url": f"{func_host}/search",
            "payload": spg.build(transaction_id=_shared_txn),
            "raw_body": None,
            "raw_content_type": None,
            "expected_status": [200, 202],
            "auth_mode": "valid",
            "custom_headers": None,
            "ttl": None,
            "sleep_before": None,
        })

    # F-TC013 — Unicode search terms (Hindi, Arabic, Chinese)
    _unicode_items = [
        ("Hindi", "बासमती चावल"),
        ("Arabic", "أرز بسمتي"),
        ("Chinese", "香米"),
    ]
    for lang, term in _unicode_items:
        _u_payload = spg.build(item_name=term)
        cases.append({
            "id": f"F-TC013-{lang}",
            "name": f"Search Unicode Item Name ({lang})",
            "category": "Functional",
            "description": f"[PASS EXPECTED] Sends /search with a non-ASCII item name in {lang} script ('{term}'). Validates the Gateway correctly handles and forwards Unicode search terms without mangling the payload.",
            "method": "POST",
            "url": f"{func_host}/search",
            "payload": _u_payload,
            "raw_body": None,
            "raw_content_type": None,
            "expected_status": [200, 202],
            "auth_mode": "valid",
            "custom_headers": None,
            "ttl": None,
            "sleep_before": None,
        })

    # F-TC014 — Large payload (many tags injected into intent)
    _large_payload = spg.build()
    _large_payload["message"]["intent"]["tags"] = [
        {"code": f"tag_{i}", "list": [{"code": f"attr_{j}", "value": f"value_{j}"} for j in range(10)]}
        for i in range(20)
    ]
    cases.append({
        "id": "F-TC014",
        "name": "Search Large Payload (20 Tag Groups)",
        "category": "Functional",
        "description": "[PASS EXPECTED] Sends /search with 20 tag groups (200 total attributes) in the intent. Edge-case for payload size — validates Gateway does not truncate or reject large-but-valid search requests.",
        "method": "POST",
        "url": f"{func_host}/search",
        "payload": _large_payload,
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [200, 202],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
    })

    # F-TC015 — Gateway health check
    cases.append({
        "id": "F-TC015",
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

    # ----- on_search functional tests (F-TC016 – F-TC023) -------------------

    # F-TC016 — Valid on_search callback with catalog
    cases.append({
        "id": "F-TC016",
        "name": "on_search Valid Callback - Catalog With Items",
        "category": "Functional",
        "description": "[PASS EXPECTED] BPP sends /on_search with a complete catalog (provider + items + location). Validates Gateway correctly accepts and forwards the backward callback to the BAP.",
        "method": "POST",
        "url": f"{func_host}/on_search",
        "payload": ospg.build(),
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [200, 202],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
    })

    # F-TC017 — on_search with empty catalog (no results found)
    cases.append({
        "id": "F-TC017",
        "name": "on_search Empty Catalog (No Results)",
        "category": "Functional",
        "description": "[PASS EXPECTED] BPP sends /on_search with an empty providers list — normal response when no items match the search. Validates Gateway forwards empty-catalog callbacks without treating it as an error.",
        "method": "POST",
        "url": f"{func_host}/on_search",
        "payload": ospg.build(empty_catalog=True),
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [200, 202],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
    })

    # F-TC018 — on_search with error block (BPP unable to process)
    cases.append({
        "id": "F-TC018",
        "name": "on_search With Error Block (BPP Processing Failure)",
        "category": "Functional",
        "description": "[PASS EXPECTED] BPP sends /on_search with an error block and empty catalog — indicates the BPP could not process the search (e.g. service unavailable). Validates Gateway accepts and routes error-carrying on_search responses.",
        "method": "POST",
        "url": f"{func_host}/on_search",
        "payload": ospg.build(empty_catalog=True, include_error={"code": "20000", "message": "BPP service temporarily unavailable"}),
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [200, 202],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
    })

    # F-TC019 — on_search multiple providers in catalog
    _multi_prov_payload = ospg.build()
    _provs = ospg.test_providers
    if len(_provs) > 1:
        _extra_items = [
            {
                "id": _provs[idx].get("id", f"prov-{idx}"),
                "descriptor": {"name": _provs[idx].get("name", f"Provider {idx}"), "short_desc": "Store"},
                "locations": [{"id": _provs[idx].get("location_id", f"loc-{idx}"), "gps": _provs[idx].get("gps", "12.9716,77.5946"), "address": _provs[idx].get("address", "Bangalore")}],
                "items": [],
            }
            for idx in range(1, len(_provs))
        ]
        _multi_prov_payload["message"]["catalog"]["bpp/providers"].extend(_extra_items)
    cases.append({
        "id": "F-TC019",
        "name": "on_search Multiple Providers in Catalog",
        "category": "Functional",
        "description": "[PASS EXPECTED] BPP sends /on_search with multiple seller providers in the catalog. Validates Gateway handles multi-provider catalog responses — common when a marketplace aggregates multiple stores.",
        "method": "POST",
        "url": f"{func_host}/on_search",
        "payload": _multi_prov_payload,
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [200, 202],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
    })

    # F-TC020 — on_search with location info on items
    _loc_items_payload = ospg.build()
    if _loc_items_payload["message"].get("catalog", {}).get("bpp/providers"):
        _loc_items_payload["message"]["catalog"]["bpp/providers"][0]["items"][0]["location_id"] = ospg.test_providers[0].get("location_id", "store-location-001")
    cases.append({
        "id": "F-TC020",
        "name": "on_search Item With Location Reference",
        "category": "Functional",
        "description": "[PASS EXPECTED] BPP sends /on_search where catalog items include location_id references linking items to specific store locations. Validates Gateway forwards location-linked item data in callbacks.",
        "method": "POST",
        "url": f"{func_host}/on_search",
        "payload": _loc_items_payload,
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [200, 202],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
    })

    # F-TC021 — on_search with product tags on items
    _tags_items_payload = ospg.build()
    if _tags_items_payload["message"].get("catalog", {}).get("bpp/providers"):
        _tags_items_payload["message"]["catalog"]["bpp/providers"][0]["items"][0]["tags"] = [
            {"code": "product_category", "value": "staples"},
            {"code": "dietary", "value": "organic"},
        ]
    cases.append({
        "id": "F-TC021",
        "name": "on_search With Product Tags on Items",
        "category": "Functional",
        "description": "[PASS EXPECTED] BPP sends /on_search where catalog items include ONDC-specific tags (product_category, dietary preferences). Validates Gateway forwards enriched item metadata without stripping tags.",
        "method": "POST",
        "url": f"{func_host}/on_search",
        "payload": _tags_items_payload,
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [200, 202],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
    })

    # F-TC022 — on_search different domain (second configured domain, or cross-domain fallback)
    # When the YAML has only one domain, the participant is not registered for the fallback domain.
    # The Gateway will return NACK (authentication failed) — which is correct and expected.
    # nack_ok=True tells the runner to treat any NACK response as PASS for this test case.
    _domain2 = ospg.domains[1] if len(ospg.domains) > 1 else "ONDC:RET16"
    _domain2_is_cross = _domain2 not in set(ospg.domains)
    _domain2_desc = (
        f"[PASS EXPECTED] BPP sends /on_search with context.domain='{_domain2}'. "
        + (
            f"The participant is not registered for domain '{_domain2}' — the Gateway returns "
            "NACK (authentication failed for unregistered domain), which is the correct and "
            "expected behaviour. A NACK response is treated as PASS for this test case."
            if _domain2_is_cross else
            "Validates Gateway routes backward callbacks for non-primary domains to the correct BAP."
        )
    )
    cases.append({
        "id": "F-TC022",
        "name": f"on_search Different Domain: {_domain2}",
        "category": "Functional",
        "description": _domain2_desc,
        "method": "POST",
        "url": f"{func_host}/on_search",
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

    # F-TC023 — on_search large catalog (many items)
    _large_catalog = ospg.build()
    if _large_catalog["message"].get("catalog", {}).get("bpp/providers"):
        _base_item = _large_catalog["message"]["catalog"]["bpp/providers"][0]["items"][0]
        _large_catalog["message"]["catalog"]["bpp/providers"][0]["items"] = [
            {**_base_item, "id": f"item-{i:03d}", "descriptor": {"name": f"Product {i}", "short_desc": "Available"}}
            for i in range(1, 26)
        ]
    cases.append({
        "id": "F-TC023",
        "name": "on_search Large Catalog (25 Items)",
        "category": "Functional",
        "description": "[PASS EXPECTED] BPP sends /on_search with 25 items in the catalog. Validates Gateway handles large catalog payloads efficiently without truncation or timeout — important for full-catalog search responses.",
        "method": "POST",
        "url": f"{func_host}/on_search",
        "payload": _large_catalog,
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
        "name": "Search Missing Authorization Header",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401] Sends /search with Content-Type but no Authorization header. Gateway must reject all unauthenticated ONDC requests. Validates the authentication enforcement layer.",
        "method": "POST",
        "url": f"{neg_host}/search",
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
        "name": "Search Invalid / Tampered Signature",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401] Sends /search with a valid Authorization header format but signature string prefixed with 'TAMPERED'. Gateway must reject cryptographically invalid signatures.",
        "method": "POST",
        "url": f"{neg_host}/search",
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
        "name": "Search Missing context.domain",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401/400/NACK] Sends /search where context.domain is removed. The domain field is mandatory for Gateway routing — without it the Gateway cannot identify the vertical. Gateway may return 4xx or HTTP 200 NACK.",
        "method": "POST",
        "url": f"{neg_host}/search",
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
        "name": "Search Missing context.bap_id",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401/400/NACK] Sends /search with bap_id removed from context. Without bap_id, Gateway cannot identify the requesting buyer application. Gateway may return 4xx or HTTP 200 NACK.",
        "method": "POST",
        "url": f"{neg_host}/search",
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

    # N-TC005 — Missing message.intent
    _no_intent = nspg.build()
    _no_intent["message"].pop("intent", None)
    cases.append({
        "id": "N-TC005",
        "name": "Search Missing message.intent",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401/400] Sends /search with the intent block removed from message. Intent is the mandatory search criteria field — an empty message is not a valid ONDC /search request.",
        "method": "POST",
        "url": f"{neg_host}/search",
        "payload": _no_intent,
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
        "name": "Search Expired Signature (TTL = 10s)",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401] Generates a /search signature with TTL=10s then waits 12 seconds before sending. The signature will be expired at send time. Gateway must reject requests with expired signatures.",
        "method": "POST",
        "url": f"{neg_host}/search",
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
        "name": "Search Invalid core_version (99.abcd)",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401/400] Sends /search with context.core_version='99.abcd' — a version the Gateway does not support. Validates the Gateway rejects requests referencing unsupported protocol versions.",
        "method": "POST",
        "url": f"{neg_host}/search",
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
        "name": "Search Invalid Domain (INVALID:DOMAIN999)",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401/400] Sends /search with an unrecognised domain code 'INVALID:DOMAIN999'. Gateway must reject requests for unsupported ONDC domains to prevent routing to unknown verticals.",
        "method": "POST",
        "url": f"{neg_host}/search",
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
        "name": "Search Invalid City Code (invalid:city:format)",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401/400/NACK] Sends /search with a malformed city code (not 'std:XXX' format). Gateway must validate city codes. May return 4xx or HTTP 200 NACK.",
        "method": "POST",
        "url": f"{neg_host}/search",
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
        "name": "Search Invalid Country Code (XYZZY)",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401/400/NACK] Sends /search with context.country='XYZZY' — not a valid ISO 3166-1 alpha-3 code. Gateway must reject invalid country fields. May return 4xx or HTTP 200 NACK.",
        "method": "POST",
        "url": f"{neg_host}/search",
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

    # N-TC011 — Malformed JSON structure (valid JSON, wrong ONDC shape)
    cases.append({
        "id": "N-TC011",
        "name": "Search Malformed JSON Structure",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401/400/NACK] Sends a POST /search with valid JSON but entirely wrong shape (no context or message keys). Gateway must reject structurally invalid ONDC payloads. May return 4xx or HTTP 200 NACK (e.g. 'context not found in payload').",
        "method": "POST",
        "url": f"{neg_host}/search",
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
        "name": "Search Invalid JSON Syntax (raw string)",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401/400] Sends POST /search with Content-Type application/json but body is '{not valid json'. Gateway must reject unparseable JSON at the protocol layer.",
        "method": "POST",
        "url": f"{neg_host}/search",
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
        "name": "Search Empty JSON Payload ({})",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401/400] Sends POST /search with an empty JSON body {}. Without context or message, the Gateway must reject as missing mandatory ONDC fields.",
        "method": "POST",
        "url": f"{neg_host}/search",
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
        "name": "Search Wrong HTTP Method (GET)",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 404/405] Sends the /search request as GET instead of POST. ONDC Gateway endpoints only accept POST — other methods should return 404 or 405.",
        "method": "GET",
        "url": f"{neg_host}/search",
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
        "name": "Search Wrong Content-Type (text/plain)",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401/400/415] Sends /search with Content-Type: text/plain instead of application/json. Gateway should reject requests with incorrect content type for the ONDC protocol.",
        "method": "POST",
        "url": f"{neg_host}/search",
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
        "name": "Search Invalid Authorization Header Format",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401] Sends /search with Authorization: Bearer token_xyz instead of the ONDC Signature format. Gateway must reject non-ONDC auth schemes.",
        "method": "POST",
        "url": f"{neg_host}/search",
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

    # -----------------------------------------------------------------------
    # TEMPORARILY DISABLED — N-TC018 (original numbering)
    # Reason: not applicable in current test environment.
    # To re-enable: uncomment the block below and renumber to fit the
    # then-current active sequence (insert after current N-TC016).
    # -----------------------------------------------------------------------
    # _old_ts = nspg.build()
    # _old_ts["context"]["timestamp"] = (
    #     datetime.now(timezone.utc) - timedelta(minutes=30)
    # ).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    # cases.append({
    #     "id": "N-TC018",   # renumber as needed when re-enabling
    #     "name": "Search Expired Timestamp in Context (-30 min)",
    #     "category": "Negative",
    #     "description": "[FAIL EXPECTED — 401/400] Sends /search where context.timestamp is set 30 minutes in the past. Gateway must reject stale requests to prevent replay attacks using old signed messages.",
    #     "method": "POST",
    #     "url": f"{neg_host}/search",
    #     "payload": _old_ts,
    #     "raw_body": None,
    #     "raw_content_type": None,
    #     "expected_status": [400, 401],
    #     "auth_mode": "valid",
    #     "custom_headers": None,
    #     "ttl": None,
    #     "sleep_before": None,
    # })

    # N-TC017 — Missing context.transaction_id
    _no_txn = nspg.build()
    _no_txn["context"].pop("transaction_id", None)
    cases.append({
        "id": "N-TC017",
        "name": "Search Missing context.transaction_id",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401/400/NACK] Sends /search with transaction_id removed from context. Transaction ID is required for correlating /search with /on_search callbacks. Gateway may return 4xx or HTTP 200 NACK.",
        "method": "POST",
        "url": f"{neg_host}/search",
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

    # -----------------------------------------------------------------------
    # TEMPORARILY DISABLED — N-TC020 (original numbering)
    # Reason: not applicable in current test environment.
    # To re-enable: uncomment the block below and renumber to fit the
    # then-current active sequence (insert after current N-TC017).
    # -----------------------------------------------------------------------
    # _no_ff = nspg.build()
    # _no_ff["message"]["intent"].pop("fulfillment", None)
    # cases.append({
    #     "id": "N-TC020",   # renumber as needed when re-enabling
    #     "name": "Search Missing intent.fulfillment Block",
    #     "category": "Negative",
    #     "description": "[FAIL EXPECTED — 401/400] Sends /search with the fulfillment block removed from the intent. Fulfillment contains the delivery location which is mandatory for routing search to the correct geography.",
    #     "method": "POST",
    #     "url": f"{neg_host}/search",
    #     "payload": _no_ff,
    #     "raw_body": None,
    #     "raw_content_type": None,
    #     "expected_status": [400, 401],
    #     "auth_mode": "valid",
    #     "custom_headers": None,
    #     "ttl": None,
    #     "sleep_before": None,
    # })

    # N-TC018 — Missing context.timestamp
    _no_ts = nspg.build()
    _no_ts["context"].pop("timestamp", None)
    cases.append({
        "id": "N-TC018",
        "name": "Search Missing context.timestamp",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401/400/NACK] Sends /search with context.timestamp removed. Timestamp is required for replay-attack prevention and signature expiry validation. Gateway may return 4xx or HTTP 200 NACK.",
        "method": "POST",
        "url": f"{neg_host}/search",
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
    _dos_payload["message"]["intent"]["tags"] = [
        {"code": f"tag_{i}", "list": [{"code": f"attr_{j}", "value": "x" * 500} for j in range(50)]}
        for i in range(100)
    ]
    cases.append({
        "id": "N-TC019",
        "name": "Search Extremely Large Payload (DoS / Size Limit)",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401/400/413/NACK] Sends /search with 100 tag groups each containing 50 attributes of 500 chars. Tests request size limits and DoS protection. Gateway may return 4xx/413 or HTTP 200 NACK.",
        "method": "POST",
        "url": f"{neg_host}/search",
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

    # N-TC020 — Missing context.action (or wrong action value)
    _wrong_action = nspg.build()
    _wrong_action["context"]["action"] = "confirm"
    cases.append({
        "id": "N-TC020",
        "name": "Search Wrong action Value (confirm on /search endpoint)",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401/400/NACK] Sends a POST to /search but with context.action='confirm' instead of 'search'. Gateway must validate the action field. May return 4xx or HTTP 200 NACK.",
        "method": "POST",
        "url": f"{neg_host}/search",
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

    # ----- on_search negative tests (N-TC021 – N-TC026) --------------------

    # N-TC021 — on_search missing Authorization header
    cases.append({
        "id": "N-TC021",
        "name": "on_search Missing Authorization Header",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401] Sends /on_search with no Authorization header. Even backward callbacks from BPPs must be authenticated — Gateway must enforce auth on /on_search.",
        "method": "POST",
        "url": f"{neg_host}/on_search",
        "payload": nospg.build(),
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [401, 400],
        "auth_mode": "no_auth",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
    })

    # N-TC022 — on_search tampered signature
    cases.append({
        "id": "N-TC022",
        "name": "on_search Tampered Signature",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401] Sends /on_search with a cryptographically invalid (tampered) signature. Gateway must verify the BPP's signature before accepting any backward callback.",
        "method": "POST",
        "url": f"{neg_host}/on_search",
        "payload": nospg.build(),
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [401, 400],
        "auth_mode": "tamper_sig",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
    })

    # -----------------------------------------------------------------------
    # TEMPORARILY DISABLED — N-TC026 (original numbering)
    # Reason: not applicable in current test environment.
    # To re-enable: uncomment the block below and renumber to fit the
    # then-current active sequence (insert after current N-TC022).
    # -----------------------------------------------------------------------
    # cases.append({
    #     "id": "N-TC026",   # renumber as needed when re-enabling
    #     "name": "on_search Missing message.catalog",
    #     "category": "Negative",
    #     "description": "[FAIL EXPECTED — 401/400] Sends /on_search with the catalog block missing entirely from message. The catalog field is the payload of a search response — without it the callback is malformed.",
    #     "method": "POST",
    #     "url": f"{neg_host}/on_search",
    #     "payload": nospg.build(omit_catalog=True),
    #     "raw_body": None,
    #     "raw_content_type": None,
    #     "expected_status": [400, 401],
    #     "auth_mode": "valid",
    #     "custom_headers": None,
    #     "ttl": None,
    #     "sleep_before": None,
    # })

    # N-TC023 — on_search missing context.bpp_id (cannot identify sender)
    cases.append({
        "id": "N-TC023",
        "name": "on_search Missing context.bpp_id (Sender Identity)",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401/400] Sends /on_search without bpp_id in context. Gateway cannot verify the BPP's identity without bpp_id — the callback must be rejected as the sender is unknown.",
        "method": "POST",
        "url": f"{neg_host}/on_search",
        "payload": nospg.build(omit_bpp_id=True),
        "raw_body": None,
        "raw_content_type": None,
        "expected_status": [400, 401],
        "auth_mode": "valid",
        "custom_headers": None,
        "ttl": None,
        "sleep_before": None,
    })

    # N-TC024 — on_search missing context.bap_id (routing failure)
    cases.append({
        "id": "N-TC024",
        "name": "on_search Missing context.bap_id (Routing Failure)",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401/400/NACK] Sends /on_search without bap_id in context. Gateway cannot route the callback to the correct BAP. May return 4xx or HTTP 200 NACK.",
        "method": "POST",
        "url": f"{neg_host}/on_search",
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

    # -----------------------------------------------------------------------
    # TEMPORARILY DISABLED — N-TC029 (original numbering)
    # Reason: not applicable in current test environment.
    # To re-enable: uncomment the block below and renumber to fit the
    # then-current active sequence (insert after current N-TC024).
    # -----------------------------------------------------------------------
    # _on_old_ts = nospg.build()
    # _on_old_ts["context"]["timestamp"] = (
    #     datetime.now(timezone.utc) - timedelta(minutes=30)
    # ).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    # cases.append({
    #     "id": "N-TC029",   # renumber as needed when re-enabling
    #     "name": "on_search Expired Context Timestamp (-30 min)",
    #     "category": "Negative",
    #     "description": "[FAIL EXPECTED — 401/400] Sends /on_search where context.timestamp is 30 minutes in the past. Stale callbacks could be replay attacks — Gateway must enforce timestamp freshness on backward flow too.",
    #     "method": "POST",
    #     "url": f"{neg_host}/on_search",
    #     "payload": _on_old_ts,
    #     "raw_body": None,
    #     "raw_content_type": None,
    #     "expected_status": [400, 401],
    #     "auth_mode": "valid",
    #     "custom_headers": None,
    #     "ttl": None,
    #     "sleep_before": None,
    # })

    # -----------------------------------------------------------------------
    # TEMPORARILY DISABLED — N-TC030 (original numbering)
    # Reason: not applicable in current test environment.
    # To re-enable: uncomment the block below and renumber to fit the
    # then-current active sequence (insert after N-TC029 or current N-TC024).
    # -----------------------------------------------------------------------
    # _bad_catalog = nospg.build()
    # _bad_catalog["message"]["catalog"] = {"invalid_structure": "test", "missing_required": True}
    # cases.append({
    #     "id": "N-TC030",   # renumber as needed when re-enabling
    #     "name": "on_search Malformed Catalog Structure",
    #     "category": "Negative",
    #     "description": "[FAIL EXPECTED — 401/400] Sends /on_search with a catalog object that has wrong keys (no bpp/providers, no bpp/descriptor). Gateway must validate catalog schema before forwarding to the BAP.",
    #     "method": "POST",
    #     "url": f"{neg_host}/on_search",
    #     "payload": _bad_catalog,
    #     "raw_body": None,
    #     "raw_content_type": None,
    #     "expected_status": [400, 401],
    #     "auth_mode": "valid",
    #     "custom_headers": None,
    #     "ttl": None,
    #     "sleep_before": None,
    # })

    # N-TC025 — on_search missing context.domain
    cases.append({
        "id": "N-TC025",
        "name": "on_search Missing context.domain",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 401/400/NACK] Sends /on_search with domain removed from context. Gateway uses domain to validate the callback — missing it makes routing impossible. May return 4xx or HTTP 200 NACK.",
        "method": "POST",
        "url": f"{neg_host}/on_search",
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

    # N-TC026 — on_search wrong HTTP method (GET)
    cases.append({
        "id": "N-TC026",
        "name": "on_search Wrong HTTP Method (GET)",
        "category": "Negative",
        "description": "[FAIL EXPECTED — 404/405] Sends the /on_search request as GET instead of POST. ONDC Gateway endpoints only accept POST — other methods should return 404 or 405.",
        "method": "GET",
        "url": f"{neg_host}/on_search",
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
        # nack_ok=True: a NACK response is an acceptable/expected outcome for this test.
        # Validate error.code and error.type if specified.
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
                f"HTTP {resp_status} - NACK received for a valid request - "
                f"error.code={nack_code}{type_note}{msg_note}"
            )
        # Negative tests: HTTP 200 is only a pass when the body is a NACK.
        # An HTTP 200 ACK means the Gateway accepted a request it should have rejected.
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
<title>ONDC Gateway Search API Test Report</title>
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
    <h1>ONDC <span>Gateway Search API</span> Test Report</h1>
    <p>
      <strong>Source:</strong> Gateway /search &amp; /on_search — Functional &amp; Negative
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

    # 1 — derive signing public key
    try:
        signing_pub = _reg_derive_signing_pub(private_key_seed)
        enc_pub = _b64.b64encode(_os.urandom(32)).decode()
    except Exception as exc:
        logger.warning(f"[registration] Key derivation failed: {exc} — skipping registration.")
        return

    # 2 — get admin token
    try:
        token = _reg_get_admin_token(cfg)
    except Exception as exc:
        logger.warning(f"[registration] Could not obtain admin token: {exc} — skipping registration.")
        return

    # 3 — POST /admin/subscribe
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
        description="ONDC Gateway Search API Test Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Output HTML path. If omitted, auto-generated as reports/Gateway-search-<suite>-<timestamp>.html",
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
        default="resources/gateway/ondc_gateway_search_functional.yml",
        help="Path to functional YAML config (relative to project root or absolute)",
    )
    parser.add_argument(
        "--neg-config",
        default="resources/gateway/ondc_gateway_search_negative.yml",
        help="Path to negative YAML config (relative to project root or absolute)",
    )
    parser.add_argument(
        "--func-tenant",
        default="ondcGatewaySearch",
        help="Top-level YAML key (tenant) in functional config (default: ondcGatewaySearch)",
    )
    parser.add_argument(
        "--neg-tenant",
        default="ondcGatewaySearch",
        help="Top-level YAML key (tenant) in negative config (default: ondcGatewaySearch)",
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
            f"Gateway-search-{args.suite}-{ts_file}.html",
        )

    logger.info("=" * 60)
    logger.info("ONDC Gateway Search API Test Runner")
    logger.info(f"Run timestamp : {run_ts}")
    logger.info(f"Suite         : {args.suite}")
    logger.info(f"Timeout       : {args.timeout}s")
    logger.info(f"Func config   : {args.func_config}")
    logger.info(f"Func tenant   : {args.func_tenant}")
    logger.info(f"Neg config    : {args.neg_config}")
    logger.info(f"Neg tenant    : {args.neg_tenant}")
    logger.info(f"Output        : {output_path}")
    logger.info("=" * 60)

    func_cfg = load_yaml_config(args.func_config, tenant=args.func_tenant)
    neg_cfg = load_yaml_config(args.neg_config, tenant=args.neg_tenant)

    # Fail fast if required fields are missing / commented out
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
