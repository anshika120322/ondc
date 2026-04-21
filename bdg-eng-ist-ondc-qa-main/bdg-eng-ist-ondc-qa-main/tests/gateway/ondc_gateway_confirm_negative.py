import json
import re
import time
import uuid
from datetime import datetime, timezone, timedelta
from locust import task, between
from tests.gateway.gateway_confirm_base import GatewayConfirmBase

"""
ONDC Gateway Confirm API - Negative Tests (Unhappy-Path / Error Scenarios)
All tests use @task(1) for equal distribution during validation.
Run with low user count: --users 1 --iterations 5
"""


class ONDCGatewayConfirmNegative(GatewayConfirmBase):
    """Negative test scenarios for /confirm error-handling validation"""

    wait_time = between(1, 3)

    config_file = 'resources/gateway/ondc_gateway_confirm_negative.yml'
    tenant_name = 'ondcGW'

    # -------------------------------------------------------------------------
    # TC-001: Confirm API - Missing Authorization Header
    # -------------------------------------------------------------------------
    @task(1)
    def tc001_confirm_missing_auth(self):
        """Gateway must reject confirm requests that carry no Authorization header."""
        self.step_name = 'TC001_Confirm_Missing_Auth'
        payload = self._generate_confirm_payload()
        self._send_confirm_request(
            self.step_name,
            payload,
            headers={"Content-Type": "application/json; charset=utf-8"},
            expected_status=[401, 400]
        )

    # -------------------------------------------------------------------------
    # TC-002: Confirm API - Invalid / Tampered Signature
    # -------------------------------------------------------------------------
    @task(1)
    def tc002_confirm_invalid_signature(self):
        """Tamper the Authorization signature after generation; Gateway must reject."""
        self.step_name = 'TC002_Confirm_Invalid_Signature'
        payload = self._generate_confirm_payload()
        headers = self.auth_helper.generate_headers(payload)
        headers.pop('serialized_body', None)
        headers['Authorization'] = headers['Authorization'].replace('signature="', 'signature="INVALID')
        self._send_confirm_request(self.step_name, payload, headers=headers, expected_status=[401, 400])

    # -------------------------------------------------------------------------
    # TC-003: Confirm API - Invalid Digest Header
    # -------------------------------------------------------------------------
    @task(1)
    def tc003_confirm_invalid_digest(self):
        """Replace Digest header with garbage; Gateway must return 412 / 401 / 400."""
        self.step_name = 'TC003_Confirm_Invalid_Digest'
        payload = self._generate_confirm_payload()
        headers = self.auth_helper.generate_headers(payload)
        headers.pop('serialized_body', None)
        headers['Digest'] = 'BLAKE-512=INVALID_DIGEST_VALUE=='
        self._send_confirm_request(self.step_name, payload, headers=headers, expected_status=[412, 401, 400])

    # -------------------------------------------------------------------------
    # TC-004: Confirm API - Missing context.domain
    # -------------------------------------------------------------------------
    @task(1)
    def tc004_confirm_missing_domain(self):
        """Confirm payload without 'domain' in context must be rejected."""
        self.step_name = 'TC004_Confirm_Missing_Domain'
        payload = self._generate_confirm_payload()
        del payload['context']['domain']
        self._send_confirm_request(self.step_name, payload, expected_status=[200, 400, 422, 401], test_type='negative', expected_error_code="10002")

    # -------------------------------------------------------------------------
    # TC-005: Confirm API - Missing context.bpp_id
    # -------------------------------------------------------------------------
    @task(1)
    def tc005_confirm_missing_bpp_id(self):
        """Confirm payload without 'bpp_id' must be rejected (cannot route)."""
        self.step_name = 'TC005_Confirm_Missing_BPP_ID'
        payload = self._generate_confirm_payload()
        del payload['context']['bpp_id']
        self._send_confirm_request(self.step_name, payload, expected_status=[200, 400, 422, 401], test_type='negative', expected_error_code="10002")

    # -------------------------------------------------------------------------
    # TC-006: Confirm API - Missing message.order.id
    # -------------------------------------------------------------------------
    @task(1)
    def tc006_confirm_missing_order_id(self):
        """Confirm payload without an order ID must be rejected."""
        self.step_name = 'TC006_Confirm_Missing_Order_ID'
        payload = self._generate_confirm_payload()
        del payload['message']['order']['id']
        self._send_confirm_request(self.step_name, payload, expected_status=[200, 400, 422, 401], test_type='negative', expected_error_code="10006")

    # -------------------------------------------------------------------------
    # TC-007: Confirm API - Missing message.order.billing
    # -------------------------------------------------------------------------
    @task(1)
    def tc007_confirm_missing_billing(self):
        """Confirm order without billing details must be rejected."""
        self.step_name = 'TC007_Confirm_Missing_Billing'
        payload = self._generate_confirm_payload()
        del payload['message']['order']['billing']
        self._send_confirm_request(self.step_name, payload, expected_status=[200, 400, 422, 401], test_type='negative', expected_error_code="10006")

    # -------------------------------------------------------------------------
    # TC-008: Confirm API - Missing message.order.payment
    # -------------------------------------------------------------------------
    @task(1)
    def tc008_confirm_missing_payment(self):
        """Confirm order without payment block must be rejected."""
        self.step_name = 'TC008_Confirm_Missing_Payment'
        payload = self._generate_confirm_payload()
        del payload['message']['order']['payment']
        self._send_confirm_request(self.step_name, payload, expected_status=[200, 400, 422, 401], test_type='negative', expected_error_code="10006")

    # -------------------------------------------------------------------------
    # TC-009: Confirm API - Missing message.order.fulfillments
    # -------------------------------------------------------------------------
    @task(1)
    def tc009_confirm_missing_fulfillments(self):
        """Confirm order without fulfillment array must be rejected."""
        self.step_name = 'TC009_Confirm_Missing_Fulfillments'
        payload = self._generate_confirm_payload()
        del payload['message']['order']['fulfillments']
        self._send_confirm_request(self.step_name, payload, expected_status=[200, 400, 422, 401], test_type='negative', expected_error_code="10006")

    # -------------------------------------------------------------------------
    # TC-010: Confirm API - Expired Signature (TTL Elapsed)
    # -------------------------------------------------------------------------
    @task(1)
    def tc010_confirm_expired_signature(self):
        """Generate auth with TTL=1 s, wait for expiry, then confirm; must be rejected."""
        self.step_name = 'TC010_Confirm_Expired_Signature'
        payload = self._generate_confirm_payload()
        headers = self.auth_helper.generate_headers(payload, ttl=1)
        time.sleep(2)
        self._send_confirm_request(self.step_name, payload, headers=headers, expected_status=[401, 400])

    # -------------------------------------------------------------------------
    # TC-011: Confirm API - Invalid core_version
    # -------------------------------------------------------------------------
    @task(1)
    def tc011_confirm_invalid_core_version(self):
        """Confirm with an unsupported/future core_version must be rejected."""
        self.step_name = 'TC011_Confirm_Invalid_Version'
        payload = self._generate_confirm_payload()
        payload['context']['core_version'] = "99.99.99"
        self._send_confirm_request(self.step_name, payload, expected_status=[200, 400, 422, 401], test_type='negative', expected_error_code="10002")

    # -------------------------------------------------------------------------
    # TC-012: Confirm API - Invalid Domain
    # -------------------------------------------------------------------------
    @task(1)
    def tc012_confirm_invalid_domain(self):
        """Confirm with an unrecognized ONDC domain must be rejected."""
        self.step_name = 'TC012_Confirm_Invalid_Domain'
        payload = self._generate_confirm_payload()
        payload['context']['domain'] = "INVALID:DOMAIN999"
        self._send_confirm_request(self.step_name, payload, expected_status=[200, 400, 422, 401], test_type='negative', expected_error_code="10001")

    # -------------------------------------------------------------------------
    # TC-013: Confirm API - Invalid Country Code
    # -------------------------------------------------------------------------
    @task(1)
    def tc013_confirm_invalid_country(self):
        """Confirm with an invalid country code (non-ISO-3166) must be rejected."""
        self.step_name = 'TC013_Confirm_Invalid_Country'
        payload = self._generate_confirm_payload()
        payload['context']['country'] = "XYZZY"
        self._send_confirm_request(self.step_name, payload, expected_status=[200, 400, 422, 401], test_type='negative', expected_error_code="10002")

    # -------------------------------------------------------------------------
    # TC-014: Confirm API - Malformed JSON Structure
    # -------------------------------------------------------------------------
    @task(1)
    def tc014_confirm_malformed_json_structure(self):
        """Syntactically valid JSON but completely wrong ONDC structure."""
        self.step_name = 'TC014_Confirm_Malformed_Structure'
        bad_payload = {
            "wrong_root": "not_ondc",
            "random_field": 12345,
            "nested": {"also_wrong": True}
        }
        self._send_confirm_request(self.step_name, bad_payload, expected_status=[200, 400, 422, 401], test_type='negative')

    # -------------------------------------------------------------------------
    # TC-015: Confirm API - Invalid JSON Syntax (raw string)
    # -------------------------------------------------------------------------
    @task(1)
    def tc015_confirm_invalid_json_syntax(self):
        """Send a plain string that is not valid JSON."""
        self.step_name = 'TC015_Confirm_Invalid_JSON_Syntax'
        with self.client.post(
            name=self.step_name,
            url="/confirm",
            data="{invalid json content}",
            headers={"Content-Type": "application/json"},
            catch_response=True
        ) as response:
            if response.status_code not in [400, 422, 401]:
                response.failure(f"TC-015 Failed: Expected [400, 422, 401], got {response.status_code}")
                return
            response.success()

    # -------------------------------------------------------------------------
    # TC-016: Confirm API - Empty Payload
    # -------------------------------------------------------------------------
    @task(1)
    def tc016_confirm_empty_payload(self):
        """Send an empty JSON body {}; Gateway must reject as invalid."""
        self.step_name = 'TC016_Confirm_Empty_Payload'
        with self.client.post(
            name=self.step_name,
            url="/confirm",
            data=json.dumps({}, separators=(',', ':')),
            headers={"Content-Type": "application/json"},
            catch_response=True
        ) as response:
            if response.status_code not in [400, 422, 401]:
                response.failure(f"TC-016 Failed: Expected [400, 422, 401], got {response.status_code}")
                return
            response.success()

    # -------------------------------------------------------------------------
    # TC-017: Confirm API - Wrong HTTP Method (GET instead of POST)
    # -------------------------------------------------------------------------
    @task(1)
    def tc017_confirm_wrong_http_method(self):
        """HTTP GET to /confirm should return 405 Method Not Allowed or 404."""
        self.step_name = 'TC017_Confirm_Wrong_Method'
        with self.client.get(
            name=self.step_name,
            url="/confirm",
            catch_response=True
        ) as response:
            if response.status_code not in [405, 404, 400]:
                response.failure(f"TC-017 Failed: Expected [405, 404, 400], got {response.status_code}")
                return
            response.success()

    # -------------------------------------------------------------------------
    # TC-018: Confirm API - Wrong Content-Type Header
    # -------------------------------------------------------------------------
    @task(1)
    def tc018_confirm_wrong_content_type(self):
        """Sending confirm payload with Content-Type: text/plain must be rejected."""
        self.step_name = 'TC018_Confirm_Wrong_Content_Type'
        payload = self._generate_confirm_payload()
        payload_json = json.dumps(payload, separators=(',', ':'), sort_keys=False)
        with self.client.post(
            name=self.step_name,
            url="/confirm",
            data=payload_json,
            headers={"Content-Type": "text/plain"},
            catch_response=True
        ) as response:
            if response.status_code not in [400, 415, 422, 401]:
                response.failure(f"TC-018 Failed: Expected [400, 415, 422, 401], got {response.status_code}")
                return
            response.success()

    # -------------------------------------------------------------------------
    # TC-019: Confirm API - Invalid Authorization Header Format
    # -------------------------------------------------------------------------
    @task(1)
    def tc019_confirm_invalid_auth_format(self):
        """Malformed Authorization header (no ONDC signature) must be rejected."""
        self.step_name = 'TC019_Confirm_Invalid_Auth_Format'
        payload = self._generate_confirm_payload()
        self._send_confirm_request(
            self.step_name,
            payload,
            headers={"Authorization": "Bearer invalid_token", "Content-Type": "application/json"},
            expected_status=[401, 400]
        )

    # -------------------------------------------------------------------------
    # TC-020: Confirm API - Expired Timestamp in Context
    # -------------------------------------------------------------------------
    @task(1)
    def tc020_confirm_expired_timestamp(self):
        """Confirm payload where context.timestamp is 30 minutes in the past."""
        self.step_name = 'TC020_Confirm_Expired_Timestamp'
        payload = self._generate_confirm_payload()
        old_time = (datetime.now(timezone.utc) - timedelta(minutes=30)).isoformat(
            timespec='milliseconds'
        ).replace('+00:00', 'Z')
        payload['context']['timestamp'] = old_time
        self._send_confirm_request(self.step_name, payload, expected_status=[200, 400, 401, 408], test_type='negative')

    # -------------------------------------------------------------------------
    # TC-021: Confirm API - Quote Price Mismatch (Breakup ≠ Total)
    # -------------------------------------------------------------------------
    @task(1)
    def tc021_confirm_price_mismatch(self):
        """Quote breakup sum does not equal quoted total price; Gateway must reject."""
        self.step_name = 'TC021_Confirm_Price_Mismatch'
        payload = self._generate_confirm_payload(order_amount="500.00")
        # Deliberately set wrong item price so breakup total != 500
        payload['message']['order']['quote']['breakup'][0]['price']['value'] = "100.00"  # was 450.00
        self._send_confirm_request(self.step_name, payload, expected_status=[200, 400, 422, 401], test_type='negative', expected_error_code="10006")

    # -------------------------------------------------------------------------
    # TC-022: Confirm API - Missing Items Array
    # -------------------------------------------------------------------------
    @task(1)
    def tc022_confirm_missing_items(self):
        """Confirm order payload with no items array must be rejected."""
        self.step_name = 'TC022_Confirm_Missing_Items'
        payload = self._generate_confirm_payload()
        del payload['message']['order']['items']
        self._send_confirm_request(self.step_name, payload, expected_status=[200, 400, 422, 401], test_type='negative', expected_error_code="10006")

    # -------------------------------------------------------------------------
    # TC-023: Confirm API - Missing Provider ID
    # -------------------------------------------------------------------------
    @task(1)
    def tc023_confirm_missing_provider(self):
        """Confirm order with provider block but empty 'id' field."""
        self.step_name = 'TC023_Confirm_Missing_Provider'
        payload = self._generate_confirm_payload()
        del payload['message']['order']['provider']
        self._send_confirm_request(self.step_name, payload, expected_status=[200, 400, 422, 401], test_type='negative', expected_error_code="10006")

    # -------------------------------------------------------------------------
    # TC-024: Confirm API - Missing Quote Block
    # -------------------------------------------------------------------------
    @task(1)
    def tc024_confirm_missing_quote(self):
        """Confirm order without the quote object must be rejected."""
        self.step_name = 'TC024_Confirm_Missing_Quote'
        payload = self._generate_confirm_payload()
        del payload['message']['order']['quote']
        self._send_confirm_request(self.step_name, payload, expected_status=[200, 400, 422, 401], test_type='negative', expected_error_code="10006")

    # -------------------------------------------------------------------------
    # TC-025: Confirm API - Extremely Large Payload (DoS / Size Limit)
    # -------------------------------------------------------------------------
    @task(1)
    def tc025_confirm_large_payload_dos(self):
        """Extremely large confirm payload should be rejected by Gateway size limit."""
        self.step_name = 'TC025_Confirm_Large_Payload_DoS'
        payload = self._generate_confirm_payload()
        # Pad items to balloon payload size
        payload['message']['order']['items'] = [
            {
                "id": f"item-{i:04d}",
                "descriptor": {"name": f"item_{i}" * 500},
                "quantity": {"count": 1},
                "tags": [{"code": f"tag_{j}", "value": "x" * 5000} for j in range(50)]
            }
            for i in range(100)
        ]
        self._send_confirm_request(
            self.step_name,
            payload,
            expected_status=[413, 400, 401, 422, 500]
        )

    # -------------------------------------------------------------------------
    # TC-026: Confirm API - SQL Injection in Buyer Name
    # -------------------------------------------------------------------------
    @task(1)
    def tc026_confirm_sql_injection(self):
        """SQL injection attempt in billing name; Gateway must sanitize or reject."""
        self.step_name = 'TC026_Confirm_SQL_Injection'
        sql_payloads = [
            "'; DROP TABLE orders; --",
            "1' OR '1'='1",
            "admin'--"
        ]
        for i, sql_val in enumerate(sql_payloads):
            payload = self._generate_confirm_payload()
            payload['message']['order']['billing']['name'] = sql_val
            self._send_confirm_request(
                f"{self.step_name}_{i}",
                payload,
                expected_status=[200, 202, 400, 401, 422]
            )

    # -------------------------------------------------------------------------
    # TC-027: Confirm API - XSS Attempt in Address Field
    # -------------------------------------------------------------------------
    @task(1)
    def tc027_confirm_xss_attack(self):
        """XSS injection in billing address; Gateway must sanitize or reject."""
        self.step_name = 'TC027_Confirm_XSS'
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')"
        ]
        for i, xss_val in enumerate(xss_payloads):
            payload = self._generate_confirm_payload()
            payload['message']['order']['billing']['address'] = xss_val
            self._send_confirm_request(
                f"{self.step_name}_{i}",
                payload,
                expected_status=[200, 202, 400, 401, 422]
            )

    # -------------------------------------------------------------------------
    # TC-028: Confirm API - Negative Item Quantity
    # -------------------------------------------------------------------------
    @task(1)
    def tc028_confirm_negative_quantity(self):
        """Confirm with negative item quantity; Gateway must reject."""
        self.step_name = 'TC028_Confirm_Negative_Qty'
        payload = self._generate_confirm_payload()
        payload['message']['order']['items'][0]['quantity']['count'] = -1
        self._send_confirm_request(self.step_name, payload, expected_status=[200, 400, 422, 401], test_type='negative', expected_error_code="10006")

    # -------------------------------------------------------------------------
    # TC-029: Confirm API - Zero Item Quantity
    # -------------------------------------------------------------------------
    @task(1)
    def tc029_confirm_zero_quantity(self):
        """Confirm with zero item quantity; Gateway must reject."""
        self.step_name = 'TC029_Confirm_Zero_Qty'
        payload = self._generate_confirm_payload()
        payload['message']['order']['items'][0]['quantity']['count'] = 0
        self._send_confirm_request(self.step_name, payload, expected_status=[200, 400, 422, 401], test_type='negative', expected_error_code="10006")

    # -------------------------------------------------------------------------
    # TC-030: Confirm API - Invalid Payment Currency
    # -------------------------------------------------------------------------
    @task(1)
    def tc030_confirm_invalid_currency(self):
        """Confirm with non-INR currency in payment params; Gateway must reject."""
        self.step_name = 'TC030_Confirm_Invalid_Currency'
        payload = self._generate_confirm_payload()
        payload['message']['order']['payment']['params']['currency'] = "USD"
        payload['message']['order']['quote']['price']['currency'] = "USD"
        self._send_confirm_request(self.step_name, payload, expected_status=[200, 400, 422, 401], test_type='negative', expected_error_code="10006")

    # -------------------------------------------------------------------------
    # TC-031: Confirm API - Invalid bpp_id (not registered) (TC-C-102)
    # Gateway cannot route the confirm to an unknown BPP; must reject with 401/400.
    # -------------------------------------------------------------------------
    @task(1)
    def tc031_confirm_invalid_bpp_id(self):
        """TC-C-102: /confirm with unregistered bpp_id — subscriber not found → 401/400."""
        self.step_name = 'TC031_Confirm_Invalid_BPP_ID'
        payload = self._generate_confirm_payload()
        payload['context']['bpp_id'] = 'unknown.bpp.ondc.network'
        payload['context']['bpp_uri'] = 'https://unknown.bpp.ondc.network/v1'
        self._send_confirm_request(self.step_name, payload, expected_status=[200, 401, 400, 422], test_type='negative', expected_error_code="10006")

    # -------------------------------------------------------------------------
    # TC-032: Confirm API - Missing message.order (TC-C-103)
    # The complete 'order' object is mandatory in /confirm; must be rejected.
    # -------------------------------------------------------------------------
    @task(1)
    def tc032_confirm_missing_order(self):
        """TC-C-103: /confirm with message.order entirely absent → 400/422."""
        self.step_name = 'TC032_Confirm_Missing_Order'
        payload = self._generate_confirm_payload()
        payload['message'] = {}  # Remove the entire 'order' block
        self._send_confirm_request(self.step_name, payload, expected_status=[200, 400, 422, 401], test_type='negative', expected_error_code="10006")

    # -------------------------------------------------------------------------
    # TC-033: on_confirm - Missing context.bap_id (TC-OC-101)
    # Gateway cannot route on_confirm to unknown BAP; must reject with 400/401.
    # -------------------------------------------------------------------------
    @task(1)
    def tc033_on_confirm_missing_bap_id(self):
        """TC-OC-101: on_confirm without context.bap_id — routing target unknown → 400/401."""
        self.step_name = 'TC033_On_Confirm_Missing_BAP_ID'
        payload = self._generate_on_confirm_payload()
        del payload['context']['bap_id']
        headers = self.auth_helper.generate_headers(payload)
        serialized_body = headers.pop('serialized_body', None) or json.dumps(
            payload, separators=(',', ':'), sort_keys=False, ensure_ascii=False
        )
        with self.client.post(
            name=self.step_name,
            url="/on_confirm",
            data=serialized_body.encode('utf-8'),
            headers={**headers, "Content-Type": "application/json; charset=utf-8"},
            catch_response=True
        ) as response:
            if response.status_code not in [400, 422, 401]:
                response.failure(f"TC-033 Failed: Expected [400, 422, 401], got {response.status_code}")
                return
            response.success()

    # -------------------------------------------------------------------------
    # TC-034: on_confirm - Invalid bap_uri (TC-OC-102)
    # on_confirm with a non-routable bap_uri (TEST-NET-1).
    # Gateway may accept (async delivery failure, 200 ACK) or reject (URI validation, 400).
    # -------------------------------------------------------------------------
    @task(1)
    def tc034_on_confirm_invalid_bap_uri(self):
        """TC-OC-102: on_confirm with unreachable bap_uri — async delivery fails or 400."""
        self.step_name = 'TC034_On_Confirm_Invalid_BAP_URI'
        payload = self._generate_on_confirm_payload()
        payload['context']['bap_uri'] = 'http://192.0.2.1:9999'  # TEST-NET-1 (RFC 5737)
        headers = self.auth_helper.generate_headers(payload)
        serialized_body = headers.pop('serialized_body', None) or json.dumps(
            payload, separators=(',', ':'), sort_keys=False, ensure_ascii=False
        )
        with self.client.post(
            name=self.step_name,
            url="/on_confirm",
            data=serialized_body.encode('utf-8'),
            headers={**headers, "Content-Type": "application/json; charset=utf-8"},
            catch_response=True
        ) as response:
            # 200/202: Gateway accepts (async routing) — delivery to BAP will fail
            # 400/422/401: Gateway rejects due to URI validation
            if response.status_code not in [200, 202, 400, 422, 401]:
                response.failure(
                    f"TC-034 Failed: Expected [200, 202, 400, 422, 401], got {response.status_code}"
                )
                return
            response.success()

    # -------------------------------------------------------------------------
    # TC-035: on_confirm - Missing context.transaction_id (TC-OC-103)
    # transaction_id is mandatory for Gateway routing; absence must be rejected.
    # -------------------------------------------------------------------------
    @task(1)
    def tc035_on_confirm_missing_transaction_id(self):
        """TC-OC-103: on_confirm without context.transaction_id → 400/422."""
        self.step_name = 'TC035_On_Confirm_Missing_Txn_ID'
        payload = self._generate_on_confirm_payload()
        del payload['context']['transaction_id']
        headers = self.auth_helper.generate_headers(payload)
        serialized_body = headers.pop('serialized_body', None) or json.dumps(
            payload, separators=(',', ':'), sort_keys=False, ensure_ascii=False
        )
        with self.client.post(
            name=self.step_name,
            url="/on_confirm",
            data=serialized_body.encode('utf-8'),
            headers={**headers, "Content-Type": "application/json; charset=utf-8"},
            catch_response=True
        ) as response:
            if response.status_code not in [400, 422, 401]:
                response.failure(
                    f"TC-035 Failed: Expected [400, 422, 401], got {response.status_code}"
                )
                return
            response.success()

    # -------------------------------------------------------------------------
    # TC-036: on_confirm - Invalid / Tampered Signature (TC-OC-104)
    # on_confirm callback with the Authorization signature tampered.
    # Gateway must reject invalid signatures with 401.
    # -------------------------------------------------------------------------
    @task(1)
    def tc036_on_confirm_invalid_signature(self):
        """TC-OC-104: on_confirm with tampered Authorization signature → 401."""
        self.step_name = 'TC036_On_Confirm_Invalid_Signature'
        payload = self._generate_on_confirm_payload()
        headers = self.auth_helper.generate_headers(payload)
        headers.pop('serialized_body', None)
        if 'Authorization' in headers:
            headers['Authorization'] = headers['Authorization'].replace(
                'signature="', 'signature="INVALID'
            )
        with self.client.post(
            name=self.step_name,
            url="/on_confirm",
            data=json.dumps(
                payload, separators=(',', ':'), sort_keys=False, ensure_ascii=False
            ).encode('utf-8'),
            headers={**headers, "Content-Type": "application/json; charset=utf-8"},
            catch_response=True
        ) as response:
            if response.status_code not in [401, 400]:
                response.failure(f"TC-036 Failed: Expected [401, 400], got {response.status_code}")
                return
            response.success()

    # =========================================================================
    # AUTHORIZATION HEADER VALIDATION TESTS (TC-031 to TC-037)
    # =========================================================================

    # -------------------------------------------------------------------------
    # TC-031: Invalid Algorithm Value "banaa"
    # -------------------------------------------------------------------------
    @task(1)
    def tc031_confirm_invalid_algorithm_banaa(self):
        """Confirm with invalid algorithm 'banaa' in Authorization header; Gateway must reject with 401."""
        self.step_name = 'TC031_Confirm_Invalid_Algorithm_Banaa'
        payload = self._generate_confirm_payload()
        
        # Generate valid headers first
        headers = self.auth_helper.generate_headers(payload, include_digest=True)
        
        # Modify the algorithm field in Authorization header
        if "Authorization" in headers:
            headers["Authorization"] = re.sub(
                r'algorithm="[^"]*"',
                'algorithm="banaa"',
                headers["Authorization"]
            )
        
        self._send_confirm_request(self.step_name, payload, headers=headers, expected_status=[401, 400])

    # -------------------------------------------------------------------------
    # TC-032: Invalid Algorithm Value "mango"
    # -------------------------------------------------------------------------
    @task(1)
    def tc032_confirm_invalid_algorithm_mango(self):
        """Confirm with invalid algorithm 'mango' in Authorization header; Gateway must reject with 401."""
        self.step_name = 'TC032_Confirm_Invalid_Algorithm_Mango'
        payload = self._generate_confirm_payload()
        
        headers = self.auth_helper.generate_headers(payload, include_digest=True)
        
        if "Authorization" in headers:
            headers["Authorization"] = re.sub(
                r'algorithm="[^"]*"',
                'algorithm="mango"',
                headers["Authorization"]
            )
        
        self._send_confirm_request(self.step_name, payload, headers=headers, expected_status=[401, 400])

    # -------------------------------------------------------------------------
    # TC-033: Invalid Algorithm Value "banana"
    # -------------------------------------------------------------------------
    @task(1)
    def tc033_confirm_invalid_algorithm_banana(self):
        """Confirm with invalid algorithm 'banana' in Authorization header; Gateway must reject with 401."""
        self.step_name = 'TC033_Confirm_Invalid_Algorithm_Banana'
        payload = self._generate_confirm_payload()
        
        headers = self.auth_helper.generate_headers(payload, include_digest=True)
        
        if "Authorization" in headers:
            headers["Authorization"] = re.sub(
                r'algorithm="[^"]*"',
                'algorithm="banana"',
                headers["Authorization"]
            )
        
        self._send_confirm_request(self.step_name, payload, headers=headers, expected_status=[401, 400])

    # -------------------------------------------------------------------------
    # TC-034: Headers Field Missing Digest
    # -------------------------------------------------------------------------
    @task(1)
    def tc034_confirm_headers_field_missing_digest(self):
        """Confirm with 'headers' field missing 'digest' in Authorization; Gateway must reject with 401."""
        self.step_name = 'TC034_Confirm_Headers_Missing_Digest'
        payload = self._generate_confirm_payload()
        
        headers = self.auth_helper.generate_headers(payload, include_digest=True)
        
        if "Authorization" in headers:
            headers["Authorization"] = re.sub(
                r'headers="[^"]*"',
                'headers="(created) (expires)"',
                headers["Authorization"]
            )
        
        self._send_confirm_request(self.step_name, payload, headers=headers, expected_status=[401, 400])

    # -------------------------------------------------------------------------
    # TC-035: Headers Field Wrong Order
    # -------------------------------------------------------------------------
    @task(1)
    def tc035_confirm_headers_field_wrong_order(self):
        """Confirm with 'headers' field in wrong order in Authorization; Gateway must reject with 401."""
        self.step_name = 'TC035_Confirm_Headers_Wrong_Order'
        payload = self._generate_confirm_payload()
        
        headers = self.auth_helper.generate_headers(payload, include_digest=True)
        
        if "Authorization" in headers:
            headers["Authorization"] = re.sub(
                r'headers="[^"]*"',
                'headers="digest (created) (expires)"',
                headers["Authorization"]
            )
        
        self._send_confirm_request(self.step_name, payload, headers=headers, expected_status=[401, 400])

    # -------------------------------------------------------------------------
    # TC-036: Headers Field With Extra Fields
    # -------------------------------------------------------------------------
    @task(1)
    def tc036_confirm_headers_field_extra_fields(self):
        """Confirm with extra fields in 'headers' field in Authorization; Gateway must reject with 401."""
        self.step_name = 'TC036_Confirm_Headers_Extra_Fields'
        payload = self._generate_confirm_payload()
        
        headers = self.auth_helper.generate_headers(payload, include_digest=True)
        
        if "Authorization" in headers:
            headers["Authorization"] = re.sub(
                r'headers="[^"]*"',
                'headers="(created) (expires) digest (invalid)"',
                headers["Authorization"]
            )
        
        self._send_confirm_request(self.step_name, payload, headers=headers, expected_status=[401, 400])

    # -------------------------------------------------------------------------
    # TC-037: Headers Field Empty
    # -------------------------------------------------------------------------
    @task(1)
    def tc037_confirm_headers_field_empty(self):
        """Confirm with empty 'headers' field in Authorization; Gateway must reject with 401."""
        self.step_name = 'TC037_Confirm_Headers_Empty'
        payload = self._generate_confirm_payload()
        
        headers = self.auth_helper.generate_headers(payload, include_digest=True)
        
        if "Authorization" in headers:
            headers["Authorization"] = re.sub(
                r'headers="[^"]*"',
                'headers=""',
                headers["Authorization"]
            )
        
        self._send_confirm_request(self.step_name, payload, headers=headers, expected_status=[401, 400])


tasks = [ONDCGatewayConfirmNegative]
