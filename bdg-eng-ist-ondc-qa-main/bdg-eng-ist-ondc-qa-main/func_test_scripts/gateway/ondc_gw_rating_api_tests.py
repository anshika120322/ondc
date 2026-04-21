#!/usr/bin/env python3
"""
ONDC Gateway Rating API - Automated Test Runner with HTML Report Generator

Runs all functional and negative test cases for the ONDC /rating and /on_rating
endpoints and generates a comprehensive dark-theme HTML report.

Usage:
    python func_test_scripts/gateway/ondc_gw_rating_api_tests.py
    python func_test_scripts/gateway/ondc_gw_rating_api_tests.py --suite functional
    python func_test_scripts/gateway/ondc_gw_rating_api_tests.py --suite negative
    python func_test_scripts/gateway/ondc_gw_rating_api_tests.py --timeout 30
    python func_test_scripts/gateway/ondc_gw_rating_api_tests.py --output results/gateway/my_report.html
    python func_test_scripts/gateway/ondc_gw_rating_api_tests.py --func-config resources/gateway/ondc_gateway_rating_functional.yml
    python func_test_scripts/gateway/ondc_gw_rating_api_tests.py --neg-config  resources/gateway/ondc_gateway_rating_negative.yml
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
_TENANT_KEY = "ondcGatewaySearch"


def load_yaml_config(path: str, tenant: str = _TENANT_KEY) -> dict:
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
            + f"\nMake sure these fields are present and NOT commented out under the"
            + f" '{_TENANT_KEY}:' key.\n"
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
# Rating Payload Generator  (/rating — forward flow: BAP → Gateway → BPP)
# ---------------------------------------------------------------------------
class RatingPayloadGenerator:
    def __init__(self, cfg: dict):
        self.domains = cfg.get("domains", ["ONDC:FIS12"])
        self.cities = cfg.get("cities", ["std:080"])
        self.core_version = str(cfg.get("core_version", "1.2.0"))
        self.bap_id = str(cfg.get("bap_id", ""))
        self.bap_uri = str(cfg.get("bap_uri", ""))
        self.bpp_id = str(cfg.get("bpp_id", ""))
        self.bpp_uri = str(cfg.get("bpp_uri", ""))
        self.country = str(cfg.get("country", "IND"))
        self.request_ttl = str(cfg.get("request_ttl", "PT30S"))

    def build(
        self,
        domain: str = None,
        city: str = None,
        transaction_id: str = None,
        message_id: str = None,
        rating_category: str = "Order",
        rating_value: str = "5",
        include_bpp: bool = True,
        rating_id: str = None,
    ) -> dict:
        txn_id = transaction_id or f"txn-{uuid.uuid4().hex[:12]}"
        msg_id = message_id or f"msg-{uuid.uuid4().hex[:12]}"
        sel_domain = domain or (self.domains[0] if self.domains else "ONDC:FIS12")
        sel_city = city or (self.cities[0] if self.cities else "std:080")
        r_id = rating_id or f"rating-{uuid.uuid4().hex[:8]}"

        ctx: dict = {
            "domain": sel_domain,
            "action": "rating",
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
        if include_bpp and self.bpp_id:
            ctx["bpp_id"] = self.bpp_id
            ctx["bpp_uri"] = self.bpp_uri

        return {
            "context": ctx,
            "message": {
                "ratings": [
                    {
                        "id": r_id,
                        "rating_category": rating_category,
                        "value": rating_value,
                    }
                ]
            },
        }


# ---------------------------------------------------------------------------
# OnRating Payload Generator  (/on_rating — backward flow: BPP → Gateway → BAP)
# ---------------------------------------------------------------------------
class OnRatingPayloadGenerator:
    def __init__(self, cfg: dict):
        self.domains = cfg.get("domains", ["ONDC:FIS12"])
        self.cities = cfg.get("cities", ["std:080"])
        self.core_version = str(cfg.get("core_version", "1.2.0"))
        self.bap_id = str(cfg.get("bap_id", ""))
        self.bap_uri = str(cfg.get("bap_uri", ""))
        self.bpp_id = str(cfg.get("bpp_id", ""))
        self.bpp_uri = str(cfg.get("bpp_uri", ""))
        self.country = str(cfg.get("country", "IND"))
        self.request_ttl = str(cfg.get("request_ttl", "PT30S"))
        self.feedback_questions = cfg.get("feedback_questions_text", [])

    def build(
        self,
        domain: str = None,
        city: str = None,
        transaction_id: str = None,
        message_id: str = None,
        feedback_form: list = None,
        empty_feedback: bool = False,
        include_error: dict = None,
        omit_bpp_id: bool = False,
        omit_bap_id: bool = False,
        omit_domain: bool = False,
    ) -> dict:
        txn_id = transaction_id or f"txn-{uuid.uuid4().hex[:12]}"
        msg_id = message_id or f"msg-{uuid.uuid4().hex[:12]}"
        sel_domain = domain or (self.domains[0] if self.domains else "ONDC:FIS12")
        sel_city = city or (self.cities[0] if self.cities else "std:080")

        ctx: dict = {
            "domain": sel_domain,
            "action": "on_rating",
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
        }
        if omit_bpp_id:
            ctx.pop("bpp_id", None)
            ctx.pop("bpp_uri", None)
        if omit_bap_id:
            ctx.pop("bap_id", None)
        if omit_domain:
            ctx.pop("domain", None)

        if empty_feedback:
            form = []
        elif feedback_form is not None:
            form = feedback_form
        else:
            form = list(self.feedback_questions) if self.feedback_questions else [
                {"id": "fq-default-001", "question": "How was your experience?",
                 "answer": "Good", "answer_type": "text"}
            ]

        payload: dict = {
            "context": ctx,
            "message": {
                "feedback_form": form,
            },
        }
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

    fspg = RatingPayloadGenerator(func_cfg)
    fospg = OnRatingPayloadGenerator(func_cfg)
    nspg = RatingPayloadGenerator(neg_cfg)
    nospg = OnRatingPayloadGenerator(neg_cfg)

    cases: List[Dict[str, Any]] = []

    def tc(tc_id, name, category, description, method, url, payload,
           expected_status, auth_mode, **kw):
        cases.append({
            "id": tc_id, "name": name, "category": category,
            "description": description, "method": method, "url": url,
            "payload": payload, "expected_status": expected_status,
            "auth_mode": auth_mode,
            "raw_body": kw.get("raw_body"), "raw_content_type": kw.get("raw_content_type"),
            "custom_headers": kw.get("custom_headers"),
            "ttl": kw.get("ttl"), "sleep_before": kw.get("sleep_before"),
            "nack_ok": kw.get("nack_ok", False),
        })

    # ======================================================================
    # FUNCTIONAL TEST CASES  — /rating (forward flow: BAP → Gateway → BPP)
    # ======================================================================

    # F-TC001 — Valid rating request
    p = fspg.build(rating_category="Order", rating_value="5")
    tc("F-TC001", "Valid Rating Request (Order, value=5)", "Functional",
       "[PASS EXPECTED — 200/202] Sends a complete, correctly signed POST /rating with "
       "rating_category='Order' and value='5'. Validates the Gateway accepts and routes "
       "a standard rating request to the BPP.",
       "POST", f"{func_host}/rating", p, [200, 202], "valid")

    # F-TC002 — Rating per domain
    for domain in fspg.domains:
        p = fspg.build(rating_category="Order", rating_value="5", domain=domain)
        tc(f"F-TC002-{domain}", f"Rating for Domain {domain}", "Functional",
           f"[PASS EXPECTED — 200/202] Sends /rating with context.domain='{domain}'. "
           "Validates Gateway routes rating requests for different ONDC verticals.",
           "POST", f"{func_host}/rating", p, [200, 202], "valid")

    # F-TC003 — Rating per city
    for city in fspg.cities:
        p = fspg.build(rating_category="Order", rating_value="5", city=city)
        tc(f"F-TC003-{city}", f"Rating for City {city}", "Functional",
           f"[PASS EXPECTED — 200/202] Sends /rating with context.city='{city}'. "
           "Validates Gateway accepts rating requests for different delivery cities.",
           "POST", f"{func_host}/rating", p, [200, 202], "valid")

    # F-TC004 — Rating category: Provider
    p = fspg.build(rating_category="Provider", rating_value="4")
    tc("F-TC004", "Rating Category: Provider", "Functional",
       "[PASS EXPECTED — 200/202] Sends /rating with rating_category='Provider'. "
       "Validates the Gateway accepts provider-level ratings.",
       "POST", f"{func_host}/rating", p, [200, 202], "valid")

    # F-TC005 — Rating category: Fulfillment
    p = fspg.build(rating_category="Fulfillment", rating_value="3")
    tc("F-TC005", "Rating Category: Fulfillment", "Functional",
       "[PASS EXPECTED — 200/202] Sends /rating with rating_category='Fulfillment'. "
       "Validates the Gateway accepts fulfillment-level ratings.",
       "POST", f"{func_host}/rating", p, [200, 202], "valid")

    # F-TC006 — Rating value boundary: minimum (1)
    p = fspg.build(rating_category="Order", rating_value="1")
    tc("F-TC006", "Rating Value Boundary: Minimum (1)", "Functional",
       "[PASS EXPECTED — 200/202] Sends /rating with the minimum valid value '1'. "
       "Validates boundary handling at the low end of the rating scale.",
       "POST", f"{func_host}/rating", p, [200, 202], "valid")

    # F-TC007 — Rating value boundary: maximum (5)
    p = fspg.build(rating_category="Order", rating_value="5")
    tc("F-TC007", "Rating Value Boundary: Maximum (5)", "Functional",
       "[PASS EXPECTED — 200/202] Sends /rating with the maximum valid value '5'. "
       "Validates boundary handling at the high end of the rating scale.",
       "POST", f"{func_host}/rating", p, [200, 202], "valid")

    # F-TC008 — Decimal rating value (3.5)
    p = fspg.build(rating_category="Order", rating_value="3.5")
    tc("F-TC008", "Rating Value: Decimal (3.5)", "Functional",
       "[PASS EXPECTED — 200/202] Sends /rating with a decimal value '3.5'. "
       "Validates Gateway accepts fractional rating values.",
       "POST", f"{func_host}/rating", p, [200, 202], "valid")

    # F-TC009 — Multiple ratings in a single request
    p = fspg.build(rating_category="Order", rating_value="5")
    p["message"]["ratings"].append({
        "id": f"rating-{uuid.uuid4().hex[:8]}",
        "rating_category": "Provider",
        "value": "4",
    })
    p["message"]["ratings"].append({
        "id": f"rating-{uuid.uuid4().hex[:8]}",
        "rating_category": "Fulfillment",
        "value": "3",
    })
    tc("F-TC009", "Multiple Ratings in Single Request", "Functional",
       "[PASS EXPECTED — 200/202] Sends /rating with three rating entries (Order, Provider, "
       "Fulfillment) in a single request. Validates the Gateway handles batch ratings.",
       "POST", f"{func_host}/rating", p, [200, 202], "valid")

    # F-TC010 — Same transaction_id, different message_ids (retry pattern)
    _shared_txn = f"txn-{uuid.uuid4().hex[:12]}"
    for req_num in range(1, 4):
        p = fspg.build(rating_category="Order", rating_value="5",
                        transaction_id=_shared_txn)
        tc(f"F-TC010-Req{req_num}",
           f"Same TxnID, Different MsgID (Request {req_num})", "Functional",
           f"[PASS EXPECTED — 200/202] Sends /rating request #{req_num} reusing transaction_id "
           f"'{_shared_txn[:16]}...' but with a fresh message_id. Validates the Gateway handles "
           "retry patterns correctly.",
           "POST", f"{func_host}/rating", p, [200, 202], "valid")

    # F-TC011 — Without bpp_id (broadcast mode)
    p = fspg.build(rating_category="Order", rating_value="4", include_bpp=False)
    tc("F-TC011", "Rating Without bpp_id (Broadcast)", "Functional",
       "[PASS EXPECTED — 200/202] Sends a /rating without bpp_id/bpp_uri in context. "
       "Validates that the Gateway can route a rating in broadcast mode.",
       "POST", f"{func_host}/rating", p, [200, 202], "valid")

    # ======================================================================
    # FUNCTIONAL TEST CASES  — /on_rating (backward flow: BPP → Gateway → BAP)
    # ======================================================================

    # F-TC012 — Valid /on_rating with feedback form
    p = fospg.build()
    tc("F-TC012", "Valid on_rating with Feedback Form", "Functional",
       "[PASS EXPECTED — 200/202] Sends a valid authenticated POST /on_rating with a feedback "
       "form (questions + answers). Validates that the Gateway accepts the BPP-to-BAP callback.",
       "POST", f"{func_host}/on_rating", p, [200, 202], "valid")

    # F-TC013 — on_rating per-domain
    for domain in fospg.domains:
        p = fospg.build(domain=domain)
        tc(f"F-TC013-{domain}", f"on_rating for Domain {domain}", "Functional",
           f"[PASS EXPECTED — 200/202] Sends a valid /on_rating for domain {domain}. "
           "Validates correct domain-based routing of on_rating callbacks.",
           "POST", f"{func_host}/on_rating", p, [200, 202], "valid")

    # F-TC014 — on_rating with empty feedback form
    p = fospg.build(empty_feedback=True)
    tc("F-TC014", "on_rating with Empty Feedback Form", "Functional",
       "[PASS EXPECTED — 200/202] Sends /on_rating with an empty feedback_form array. "
       "Validates that the Gateway accepts on_rating even without feedback questions.",
       "POST", f"{func_host}/on_rating", p, [200, 202], "valid")

    # F-TC015 — on_rating with error object (BPP returning an error)
    p = fospg.build(include_error={"type": "DOMAIN-ERROR", "code": "40002",
                                   "message": "Rating not applicable for this order"})
    tc("F-TC015", "on_rating with Error Object", "Functional",
       "[PASS EXPECTED — 200/202] Sends /on_rating with an error object indicating the BPP "
       "cannot process the rating. Validates that the Gateway forwards the error to the BAP.",
       "POST", f"{func_host}/on_rating", p, [200, 202], "valid", nack_ok=True)

    # F-TC016 — Tampered digest accepted (Gateway does not validate BLAKE2b-512 digest)
    p = fspg.build(rating_category="Order", rating_value="5")
    tc("F-TC016", "Tampered Digest Header Accepted", "Functional",
       "[PASS EXPECTED — 200/202] Sends a POST /rating with a valid Authorization but an "
       "invalid Digest header. The UAT Gateway does not verify the BLAKE2b-512 digest and "
       "accepts the request. Validates observed Gateway behavior.",
       "POST", f"{func_host}/rating", p, [200, 202], "tamper_digest")

    # F-TC017 — on_rating without bpp_id (bpp_id not required for on_rating)
    p = fospg.build(omit_bpp_id=True)
    tc("F-TC017", "on_rating Without bpp_id", "Functional",
       "[PASS EXPECTED — 200/202] Sends /on_rating without bpp_id in context. "
       "The Gateway accepts on_rating callbacks without bpp_id. "
       "Validates that bpp_id is not mandatory for the on_rating flow.",
       "POST", f"{func_host}/on_rating", p, [200, 202], "valid")

    # ======================================================================
    # NEGATIVE TEST CASES  — /rating
    # ======================================================================

    # N-TC001 — Missing auth header
    p = nspg.build(rating_category="Order", rating_value="5")
    tc("N-TC001", "Missing Auth Header", "Negative",
       "[FAIL EXPECTED — 401/400] Sends a POST /rating with no Authorization header. "
       "The ONDC protocol mandates Ed25519 BLAKE2b-512 signed headers on every request. "
       "The Gateway must reject with HTTP 401 or 400.",
       "POST", f"{func_host}/rating", p, [401, 400], "custom",
       custom_headers={"Content-Type": "application/json"})

    # N-TC002 — Tampered signature
    p = nspg.build(rating_category="Order", rating_value="5")
    tc("N-TC002", "Tampered Signature", "Negative",
       "[FAIL EXPECTED — 401/400] Sends a POST /rating with a tampered Authorization signature. "
       "The Gateway must verify the signature cryptographically and reject when it does not match.",
       "POST", f"{func_host}/rating", p, [401, 400], "tamper_sig")

    # N-TC003 — Missing context.domain
    p = nspg.build(rating_category="Order", rating_value="5")
    p["context"].pop("domain", None)
    tc("N-TC003", "Missing context.domain", "Negative",
       "[FAIL EXPECTED — 400/200+NACK] Sends a /rating without the required context.domain field. "
       "The Gateway must reject requests with incomplete context.",
       "POST", f"{func_host}/rating", p, [400, 200], "valid", nack_ok=True)

    # N-TC004 — Missing context.action
    p = nspg.build(rating_category="Order", rating_value="5")
    p["context"].pop("action", None)
    tc("N-TC004", "Missing context.action", "Negative",
       "[FAIL EXPECTED — 400/200+NACK] Sends a /rating without context.action. "
       "The Gateway must reject requests without an action field.",
       "POST", f"{func_host}/rating", p, [400, 200], "valid", nack_ok=True)

    # N-TC005 — Missing context.bap_id
    p = nspg.build(rating_category="Order", rating_value="5")
    p["context"].pop("bap_id", None)
    tc("N-TC005", "Missing context.bap_id", "Negative",
       "[FAIL EXPECTED — 401/400/200+NACK] Sends a /rating without context.bap_id. "
       "The Gateway must reject when the calling BAP cannot be identified.",
       "POST", f"{func_host}/rating", p, [401, 400, 200], "valid", nack_ok=True)

    # N-TC006 — Invalid domain value
    p = nspg.build(rating_category="Order", rating_value="5")
    p["context"]["domain"] = "INVALID:DOMAIN:999"
    tc("N-TC006", "Invalid Domain Value", "Negative",
       "[FAIL EXPECTED — 400/200+NACK] Sends a /rating with an invalid domain code. "
       "The Gateway must reject requests with unrecognized domains.",
       "POST", f"{func_host}/rating", p, [400, 200], "valid", nack_ok=True)

    # N-TC007 — Invalid city code
    p = nspg.build(rating_category="Order", rating_value="5")
    p["context"]["city"] = "INVALID_CITY"
    tc("N-TC007", "Invalid City Code", "Negative",
       "[FAIL EXPECTED — 400/200+NACK] Sends a /rating with an invalid city code. "
       "The Gateway must validate the city format.",
       "POST", f"{func_host}/rating", p, [400, 200], "valid", nack_ok=True)

    # F-TC018 — Empty ratings array accepted (Gateway forwards without validating)
    p = fspg.build(rating_category="Order", rating_value="5")
    p["message"]["ratings"] = []
    tc("F-TC018", "Empty Ratings Array Accepted", "Functional",
       "[PASS EXPECTED — 200/202] Sends a /rating with an empty ratings array. "
       "The UAT Gateway does not validate rating payload fields and forwards to BPP. "
       "Validates observed Gateway behavior.",
       "POST", f"{func_host}/rating", p, [200, 202], "valid")

    # F-TC019 — Missing rating_category accepted
    p = fspg.build(rating_category="Order", rating_value="5")
    for r in p["message"]["ratings"]:
        r.pop("rating_category", None)
    tc("F-TC019", "Missing rating_category Accepted", "Functional",
       "[PASS EXPECTED — 200/202] Sends a /rating where the rating entry has no "
       "rating_category field. The UAT Gateway does not validate rating payload fields. "
       "Validates observed Gateway behavior.",
       "POST", f"{func_host}/rating", p, [200, 202], "valid")

    # F-TC020 — Missing value field accepted
    p = fspg.build(rating_category="Order", rating_value="5")
    for r in p["message"]["ratings"]:
        r.pop("value", None)
    tc("F-TC020", "Missing Rating Value Accepted", "Functional",
       "[PASS EXPECTED — 200/202] Sends a /rating where the rating entry has no "
       "value field. The UAT Gateway does not validate rating payload fields. "
       "Validates observed Gateway behavior.",
       "POST", f"{func_host}/rating", p, [200, 202], "valid")

    # F-TC021 — Rating value 0 accepted (out of typical range)
    p = fspg.build(rating_category="Order", rating_value="0")
    tc("F-TC021", "Rating Value 0 Accepted", "Functional",
       "[PASS EXPECTED — 200/202] Sends a /rating with value '0'. "
       "The UAT Gateway does not validate rating value ranges and forwards to BPP. "
       "Validates observed Gateway behavior.",
       "POST", f"{func_host}/rating", p, [200, 202], "valid")

    # F-TC022 — Rating value 6 accepted (out of typical range)
    p = fspg.build(rating_category="Order", rating_value="6")
    tc("F-TC022", "Rating Value 6 Accepted", "Functional",
       "[PASS EXPECTED — 200/202] Sends a /rating with value '6'. "
       "The UAT Gateway does not validate rating value ranges and forwards to BPP. "
       "Validates observed Gateway behavior.",
       "POST", f"{func_host}/rating", p, [200, 202], "valid")

    # F-TC023 — Missing rating id accepted
    p = fspg.build(rating_category="Order", rating_value="5")
    for r in p["message"]["ratings"]:
        r.pop("id", None)
    tc("F-TC023", "Missing Rating ID Accepted", "Functional",
       "[PASS EXPECTED — 200/202] Sends a /rating where the rating entry has no 'id' field. "
       "The UAT Gateway does not validate rating entry IDs and forwards to BPP. "
       "Validates observed Gateway behavior.",
       "POST", f"{func_host}/rating", p, [200, 202], "valid")

    # N-TC008 — Malformed JSON body (valid auth, invalid JSON payload)
    p_sign = nspg.build(rating_category="Order", rating_value="5")
    tc("N-TC008", "Malformed JSON Body", "Negative",
       "[FAIL EXPECTED — 400/200+NACK] Sends a POST /rating with valid ONDC auth headers "
       "but a syntactically invalid JSON body. The Gateway must reject unparseable bodies.",
       "POST", f"{func_host}/rating", p_sign, [400, 200], "valid",
       raw_body='{"context": {"action": "rating"}, INVALID JSON}',
       nack_ok=True)

    # N-TC009 — Empty body
    tc("N-TC009", "Empty Request Body", "Negative",
       "[FAIL EXPECTED — 400/401] Sends a POST /rating with a completely empty body. "
       "The Gateway must reject requests without a body.",
       "POST", f"{func_host}/rating", None, [400, 401], "custom",
       custom_headers={"Content-Type": "application/json"},
       raw_body="")

    # N-TC010 — Wrong HTTP method (GET instead of POST)
    p = nspg.build(rating_category="Order", rating_value="5")
    tc("N-TC010", "Wrong HTTP Method (GET /rating)", "Negative",
       "[FAIL EXPECTED — 405/404/400] Sends a GET request to /rating which only accepts POST. "
       "The Gateway must return Method Not Allowed or similar error.",
       "GET", f"{func_host}/rating", p, [405, 404, 400], "no_auth")

    # N-TC011 — Wrong content-type
    p = nspg.build(rating_category="Order", rating_value="5")
    tc("N-TC011", "Wrong Content-Type (text/plain)", "Negative",
       "[FAIL EXPECTED — 400/415/401] Sends a POST /rating with Content-Type: text/plain. "
       "The Gateway must validate the content type is application/json.",
       "POST", f"{func_host}/rating", p, [400, 415, 401], "custom",
       custom_headers={"Content-Type": "text/plain"},
       raw_content_type="text/plain")

    # N-TC012 — Wrong context.action (search instead of rating)
    p = nspg.build(rating_category="Order", rating_value="5")
    p["context"]["action"] = "search"
    tc("N-TC012", "Wrong context.action (search instead of rating)", "Negative",
       "[FAIL EXPECTED — 400/200+NACK] Sends a /rating request but with context.action='search'. "
       "The Gateway must reject mismatched action fields.",
       "POST", f"{func_host}/rating", p, [400, 200], "valid", nack_ok=True)

    # N-TC013 — Missing transaction_id
    p = nspg.build(rating_category="Order", rating_value="5")
    p["context"].pop("transaction_id", None)
    tc("N-TC013", "Missing transaction_id", "Negative",
       "[FAIL EXPECTED — 400/200+NACK] Sends a /rating without context.transaction_id. "
       "The Gateway must reject requests missing the mandatory transaction identifier.",
       "POST", f"{func_host}/rating", p, [400, 200], "valid", nack_ok=True)

    # ======================================================================
    # NEGATIVE TEST CASES  — /on_rating
    # ======================================================================

    # N-TC014 — on_rating missing auth
    p = fospg.build()
    tc("N-TC014", "on_rating Missing Auth Header", "Negative",
       "[FAIL EXPECTED — 401/400] Sends a POST /on_rating with no Authorization header. "
       "The Gateway must reject unauthenticated callback requests.",
       "POST", f"{func_host}/on_rating", p, [401, 400], "custom",
       custom_headers={"Content-Type": "application/json"})

    # N-TC015 — on_rating tampered signature
    p = fospg.build()
    tc("N-TC015", "on_rating Tampered Signature", "Negative",
       "[FAIL EXPECTED — 401/400] Sends a POST /on_rating with a tampered signature. "
       "The Gateway must verify BPP callback signatures.",
       "POST", f"{func_host}/on_rating", p, [401, 400], "tamper_sig")

    # N-TC016 — on_rating missing bap_id
    p = fospg.build(omit_bap_id=True)
    tc("N-TC016", "on_rating Missing bap_id", "Negative",
       "[FAIL EXPECTED — 400/200+NACK] Sends /on_rating without bap_id in context. "
       "The Gateway must know the target BAP for callback delivery.",
       "POST", f"{func_host}/on_rating", p, [400, 200], "valid", nack_ok=True)

    # N-TC017 — on_rating missing domain
    p = fospg.build(omit_domain=True)
    tc("N-TC017", "on_rating Missing Domain", "Negative",
       "[FAIL EXPECTED — 400/200+NACK] Sends /on_rating without context.domain. "
       "The Gateway must validate domain presence for callback routing.",
       "POST", f"{func_host}/on_rating", p, [400, 200], "valid", nack_ok=True)

    # N-TC018 — on_rating wrong HTTP method
    p = fospg.build()
    tc("N-TC018", "on_rating Wrong HTTP Method (GET)", "Negative",
       "[FAIL EXPECTED — 405/404/400] Sends a GET request to /on_rating. "
       "The endpoint only accepts POST requests.",
       "GET", f"{func_host}/on_rating", p, [405, 404, 400], "no_auth")

    return cases


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


def _load_error_catalogue() -> dict:
    catalogue_path = os.path.join(
        PROJECT_ROOT, "resources", "gateway", "ondc_gateway_error_codes.yml",
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
<title>ONDC Gateway Rating API Test Report</title>
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
    <h1>ONDC <span>Gateway Rating API</span> Test Report</h1>
    <p>
      <strong>Source:</strong> Gateway /rating &amp; /on_rating — Functional &amp; Negative
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
# ---------------------------------------------------------------------------
_REG_PARTICIPANT_ID       = os.environ.get("REG_PARTICIPANT_ID", "")
_REG_UK_ID                = os.environ.get("REG_UK_ID", "")
_REG_PRIVATE_KEY_SEED_B64 = os.environ.get("REG_PRIVATE_KEY_SEED", "")
_REG_BAP_URI              = os.environ.get("REG_BAP_URI", "")
_REG_ADMIN_API_URL        = os.environ.get("REG_ADMIN_API_URL", "")
_REG_ADMIN_AUTH_URL       = os.environ.get("REG_ADMIN_AUTH_URL", "")
_REG_ADMIN_EMAIL          = os.environ.get("REG_ADMIN_EMAIL", "")
_REG_ADMIN_PASSWORD       = os.environ.get("REG_ADMIN_PASSWORD", "")
_REG_REGISTRY_URL         = os.environ.get("REG_ADMIN_API_URL", "")
_REG_DOMAINS              = ["ONDC:RET10", "ONDC:RET16"]
_REG_LOC_ID               = "loc-gw-bap-001"
_REG_URI_ID               = "uri-gw-bap-001"
_REG_TIMEOUT              = 15


def _reg_get_admin_token() -> str:
    try:
        from tests.utils.registry_auth_client import RegistryAuthClient
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
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


def _reg_derive_signing_pub() -> str:
    import base64 as _b64
    raw = _b64.b64decode(_REG_PRIVATE_KEY_SEED_B64)
    seed = raw[:32] if len(raw) == 64 else raw[-32:]
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    priv = Ed25519PrivateKey.from_private_bytes(seed)
    pub_bytes = priv.public_key().public_bytes(
        encoding=__import__("cryptography.hazmat.primitives.serialization", fromlist=["Encoding"]).Encoding.Raw,
        format=__import__("cryptography.hazmat.primitives.serialization", fromlist=["PublicFormat"]).PublicFormat.Raw,
    )
    return _b64.b64encode(pub_bytes).decode()


def _reg_build_payload() -> dict:
    signing_pub = _reg_derive_signing_pub()
    return {
        "subscriber_id": _REG_PARTICIPANT_ID,
        "subscriber_url": _REG_BAP_URI,
        "signing_public_key": signing_pub,
        "valid_from": "2024-01-01T00:00:00.000Z",
        "valid_until": "2030-12-31T23:59:59.000Z",
        "type": "BAP",
        "domain": _REG_DOMAINS,
        "pub_key_id": _REG_UK_ID,
        "country": "IND",
        "city": ["std:080"],
        "unique_key_id": _REG_UK_ID,
        "nw_participant": [
            {
                "subscriber_url": _REG_BAP_URI,
                "domain": _REG_DOMAINS[0] if _REG_DOMAINS else "ONDC:RET10",
                "type": "buyerApp",
                "msn": False,
                "city_code": ["std:080"],
            }
        ],
    }


def _reg_already_registered(body: str) -> bool:
    try:
        data = json.loads(body)
        code = str(data.get("error", {}).get("code", ""))
        msg = str(data.get("error", {}).get("message", "")).lower()
        return code in ("30004", "40900") or "already" in msg or "exists" in msg
    except Exception:
        return False


def register_bap_participant() -> None:
    logger.info("[registration] Registering BAP participant for rating tests ...")
    try:
        token = _reg_get_admin_token()
    except Exception as exc:
        logger.warning(f"[registration] Could not obtain admin token: {_sanitize_log(exc)} — skipping.")
        return

    payload = _reg_build_payload()
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json; charset=utf-8",
    }
    url = f"{_REG_ADMIN_API_URL}/api/admin/subscriber"
    try:
        resp = requests.post(url, json=payload, headers=headers,
                             timeout=_REG_TIMEOUT, verify=_SSL_VERIFY)
        body = resp.text
    except Exception as exc:
        logger.warning(f"[registration] HTTP request failed: {_sanitize_log(exc)} — skipping registration.")
        return

    if resp.status_code in (200, 202) and not _is_nack(body):
        logger.info(f"[registration] {_REG_PARTICIPANT_ID} registered successfully.")
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
        description="ONDC Gateway Rating API Test Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--output", default=None,
        help="Output HTML path. If omitted, auto-generated under results/gateway/.",
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
        default="resources/gateway/ondc_gateway_rating_functional.yml",
        help="Path to functional YAML config",
    )
    parser.add_argument(
        "--neg-config",
        default="resources/gateway/ondc_gateway_rating_negative.yml",
        help="Path to negative YAML config",
    )
    parser.add_argument(
        "--func-tenant", default=_TENANT_KEY,
        help=f"YAML tenant key for functional config (default: {_TENANT_KEY})",
    )
    parser.add_argument(
        "--neg-tenant", default=_TENANT_KEY,
        help=f"YAML tenant key for negative config (default: {_TENANT_KEY})",
    )
    parser.add_argument(
        "--skip-register", action="store_true",
        help="Skip the BAP participant registration step",
    )
    args = parser.parse_args()

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
            f"Gateway-rating-{args.suite}-{ts_file}.html",
        )

    logger.info("=" * 60)
    logger.info("ONDC Gateway Rating API Test Runner")
    logger.info(f"Run timestamp : {run_ts}")
    logger.info(f"Suite         : {args.suite}")
    logger.info(f"Timeout       : {args.timeout}s")
    logger.info(f"Func config   : {_sanitize_log(args.func_config)}")
    logger.info(f"Func tenant   : {_sanitize_log(args.func_tenant)}")
    logger.info(f"Neg config    : {_sanitize_log(args.neg_config)}")
    logger.info(f"Neg tenant    : {_sanitize_log(args.neg_tenant)}")
    logger.info(f"Output        : {_sanitize_log(output_path)}")
    logger.info("=" * 60)

    func_cfg = load_yaml_config(args.func_config, tenant=args.func_tenant)
    neg_cfg = load_yaml_config(args.neg_config, tenant=args.neg_tenant)

    if not func_cfg:
        logger.error(f"Functional config empty or missing: {_sanitize_log(args.func_config)}")
        sys.exit(1)
    if not neg_cfg:
        logger.warning(f"Negative config empty or missing: {_sanitize_log(args.neg_config)} — using functional config as fallback.")
        neg_cfg = func_cfg

    if not args.skip_register:
        register_bap_participant()
    else:
        logger.info("[register] Skipping participant registration (--skip-register).")

    validate_config(func_cfg, args.func_config, "Functional")
    validate_config(neg_cfg,  args.neg_config,  "Negative")

    logger.info(f"Functional host : {_sanitize_log(func_cfg.get('host', 'NOT SET'))}")
    logger.info(f"Negative host   : {_sanitize_log(neg_cfg.get('host', 'NOT SET'))}")

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
    for tc_item in cases:
        result = run_test_case(tc_item, func_auth, neg_auth, timeout=args.timeout)
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
