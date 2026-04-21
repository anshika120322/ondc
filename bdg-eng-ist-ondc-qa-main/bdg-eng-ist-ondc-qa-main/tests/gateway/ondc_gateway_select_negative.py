import json
import uuid
from datetime import datetime, timezone, timedelta
from locust import task, between
from tests.gateway.gateway_select_base import GatewaySelectBase

"""
ONDC Gateway Select API - Negative Tests (Unhappy-Path / Error Scenarios)
All tests use @task(1) for equal distribution during validation.
Run with low user count: --users 1 --iterations 5

32 test cases covering:
  - Authentication failures (TC-001 to TC-003)
  - Missing/invalid context fields (TC-004 to TC-016)
  - Invalid payload structure (TC-017 to TC-024)
  - on_select-specific failures (TC-025 to TC-032)
"""


class ONDCGatewaySelectNegative(GatewaySelectBase):
    """Negative test scenarios for /select and /on_select error-handling validation"""

    wait_time = between(1, 3)

    config_file = 'resources/gateway/ondc_gateway_select_negative.yml'
    tenant_name = 'ondcGW'

    # -------------------------------------------------------------------------
    # TC-001: Select API - Missing Authorization Header
    # -------------------------------------------------------------------------
    @task(1)
    def tc001_select_missing_auth(self):
        """Gateway must reject /select requests that carry no Authorization header."""
        self.step_name = 'TC001_Select_Missing_Auth'
        payload = self._generate_select_payload()
        self._send_select_request(
            self.step_name,
            payload,
            headers={"Content-Type": "application/json; charset=utf-8"},
            expected_status=[401, 400]
        )

    # -------------------------------------------------------------------------
    # TC-002: Select API - Invalid / Tampered Signature
    # -------------------------------------------------------------------------
    @task(1)
    def tc002_select_invalid_signature(self):
        """Tamper the Authorization signature after generation; Gateway must reject."""
        self.step_name = 'TC002_Select_Invalid_Signature'
        payload = self._generate_select_payload()
        headers = self.auth_helper.generate_headers(payload)
        headers.pop('serialized_body', None)
        headers['Authorization'] = headers['Authorization'].replace('signature="', 'signature="INVALID')
        self._send_select_request(self.step_name, payload, headers=headers, expected_status=[401, 400])

    # -------------------------------------------------------------------------
    # TC-003: Select API - Invalid Digest Header
    # -------------------------------------------------------------------------
    @task(1)
    def tc003_select_invalid_digest(self):
        """Replace Digest header with garbage; Gateway must return 412 / 401 / 400."""
        self.step_name = 'TC003_Select_Invalid_Digest'
        payload = self._generate_select_payload()
        headers = self.auth_helper.generate_headers(payload)
        headers.pop('serialized_body', None)
        headers['Digest'] = 'BLAKE-512=INVALID_DIGEST_VALUE=='
        self._send_select_request(self.step_name, payload, headers=headers, expected_status=[412, 401, 400])

    # -------------------------------------------------------------------------
    # TC-004: Select API - Missing context.domain
    # -------------------------------------------------------------------------
    @task(1)
    def tc004_select_missing_domain(self):
        """Select payload without 'domain' in context must be rejected."""
        self.step_name = 'TC004_Select_Missing_Domain'
        payload = self._generate_select_payload()
        del payload['context']['domain']
        self._send_select_request(self.step_name, payload, expected_status=[400, 422, 401])

    # -------------------------------------------------------------------------
    # TC-005: Select API - Missing context.bpp_id
    # -------------------------------------------------------------------------
    @task(1)
    def tc005_select_missing_bpp_id(self):
        """Select payload without 'bpp_id' is INVALID — bpp_id is required for /select."""
        self.step_name = 'TC005_Select_Missing_BPP_ID'
        payload = self._generate_select_payload()
        del payload['context']['bpp_id']
        self._send_select_request(self.step_name, payload, expected_status=[400, 422, 401])

    # -------------------------------------------------------------------------
    # TC-006: Select API - Missing context.bpp_uri
    # -------------------------------------------------------------------------
    @task(1)
    def tc006_select_missing_bpp_uri(self):
        """Select payload without 'bpp_uri' is INVALID — bpp_uri is required for /select."""
        self.step_name = 'TC006_Select_Missing_BPP_URI'
        payload = self._generate_select_payload()
        del payload['context']['bpp_uri']
        self._send_select_request(self.step_name, payload, expected_status=[400, 422, 401])

    # -------------------------------------------------------------------------
    # TC-007: Select API - Missing context.transaction_id
    # -------------------------------------------------------------------------
    @task(1)
    def tc007_select_missing_transaction_id(self):
        """Select payload without 'transaction_id' must be rejected."""
        self.step_name = 'TC007_Select_Missing_TxnID'
        payload = self._generate_select_payload()
        del payload['context']['transaction_id']
        self._send_select_request(self.step_name, payload, expected_status=[400, 422, 401])

    # -------------------------------------------------------------------------
    # TC-008: Select API - Missing context.message_id
    # -------------------------------------------------------------------------
    @task(1)
    def tc008_select_missing_message_id(self):
        """Select payload without 'message_id' must be rejected."""
        self.step_name = 'TC008_Select_Missing_MsgID'
        payload = self._generate_select_payload()
        del payload['context']['message_id']
        self._send_select_request(self.step_name, payload, expected_status=[400, 422, 401])

    # -------------------------------------------------------------------------
    # TC-009: Select API - Missing context.bap_id
    # -------------------------------------------------------------------------
    @task(1)
    def tc009_select_missing_bap_id(self):
        """Select payload without 'bap_id' must be rejected (auth subscriber not found)."""
        self.step_name = 'TC009_Select_Missing_BAP_ID'
        payload = self._generate_select_payload()
        del payload['context']['bap_id']
        self._send_select_request(self.step_name, payload, expected_status=[400, 401, 422])

    # -------------------------------------------------------------------------
    # TC-010: Select API - Missing message.order.provider
    # -------------------------------------------------------------------------
    @task(1)
    def tc010_select_missing_provider(self):
        """Select payload without provider in message.order must be rejected."""
        self.step_name = 'TC010_Select_Missing_Provider'
        payload = self._generate_select_payload()
        del payload['message']['order']['provider']
        self._send_select_request(self.step_name, payload, expected_status=[400, 422])

    # -------------------------------------------------------------------------
    # TC-011: Select API - Missing message.order.items
    # -------------------------------------------------------------------------
    @task(1)
    def tc011_select_missing_items(self):
        """Select payload without items in message.order must be rejected."""
        self.step_name = 'TC011_Select_Missing_Items'
        payload = self._generate_select_payload()
        del payload['message']['order']['items']
        self._send_select_request(self.step_name, payload, expected_status=[400, 422])

    # -------------------------------------------------------------------------
    # TC-012: Select API - Empty Items Array
    # -------------------------------------------------------------------------
    @task(1)
    def tc012_select_empty_items(self):
        """Select with an empty items list — no items to select is invalid."""
        self.step_name = 'TC012_Select_Empty_Items'
        payload = self._generate_select_payload()
        payload['message']['order']['items'] = []
        self._send_select_request(self.step_name, payload, expected_status=[400, 422])

    # -------------------------------------------------------------------------
    # TC-013: Select API - Missing message.order.fulfillments
    # -------------------------------------------------------------------------
    @task(1)
    def tc013_select_missing_fulfillments(self):
        """Select payload without fulfillments (no delivery destination) must be rejected."""
        self.step_name = 'TC013_Select_Missing_Fulfillments'
        payload = self._generate_select_payload()
        del payload['message']['order']['fulfillments']
        self._send_select_request(self.step_name, payload, expected_status=[400, 422])

    # -------------------------------------------------------------------------
    # TC-014: Select API - Invalid Domain Value
    # -------------------------------------------------------------------------
    @task(1)
    def tc014_select_invalid_domain(self):
        """Select with an unrecognized/invalid context.domain value."""
        self.step_name = 'TC014_Select_Invalid_Domain'
        payload = self._generate_select_payload()
        payload['context']['domain'] = 'INVALID:DOMAIN99'
        self._send_select_request(self.step_name, payload, expected_status=[400, 422])

    # -------------------------------------------------------------------------
    # TC-015: Select API - Empty Request Body
    # -------------------------------------------------------------------------
    @task(1)
    def tc015_select_empty_body(self):
        """Completely empty POST body must be rejected (no JSON to parse)."""
        self.step_name = 'TC015_Select_Empty_Body'
        headers = self.auth_helper.generate_headers({})
        headers.pop('serialized_body', None)
        self._send_select_request(
            self.step_name,
            {},
            headers={"Content-Type": "application/json; charset=utf-8"},
            expected_status=[400, 401]
        )

    # -------------------------------------------------------------------------
    # TC-016: Select API - Missing context.action
    # -------------------------------------------------------------------------
    @task(1)
    def tc016_select_missing_action(self):
        """Select payload without the 'action' field in context must be rejected."""
        self.step_name = 'TC016_Select_Missing_Action'
        payload = self._generate_select_payload()
        del payload['context']['action']
        self._send_select_request(self.step_name, payload, expected_status=[400, 422, 401])

    # -------------------------------------------------------------------------
    # TC-017: Select API - Expired Timestamp (Stale Request)
    # -------------------------------------------------------------------------
    @task(1)
    def tc017_select_expired_timestamp(self):
        """Context timestamp more than 30s in the past — gateway should reject stale request."""
        self.step_name = 'TC017_Select_Expired_Timestamp'
        payload = self._generate_select_payload()
        stale_ts = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat(timespec='milliseconds').replace('+00:00', 'Z')
        payload['context']['timestamp'] = stale_ts
        self._send_select_request(self.step_name, payload, expected_status=[400, 401, 422])

    # -------------------------------------------------------------------------
    # TC-018: Select API - Future Timestamp
    # -------------------------------------------------------------------------
    @task(1)
    def tc018_select_future_timestamp(self):
        """Context timestamp far in the future — gateway should reject."""
        self.step_name = 'TC018_Select_Future_Timestamp'
        payload = self._generate_select_payload()
        future_ts = (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat(timespec='milliseconds').replace('+00:00', 'Z')
        payload['context']['timestamp'] = future_ts
        self._send_select_request(self.step_name, payload, expected_status=[400, 401, 422])

    # -------------------------------------------------------------------------
    # TC-019: Select API - Invalid bap_id (Not Registered)
    # -------------------------------------------------------------------------
    @task(1)
    def tc019_select_invalid_bap_id(self):
        """Select with an unknown/unregistered bap_id — subscriber lookup fails."""
        self.step_name = 'TC019_Select_Invalid_BAP_ID'
        payload = self._generate_select_payload()
        payload['context']['bap_id'] = 'unknown.bap.notregistered.ondc'
        self._send_select_request(self.step_name, payload, expected_status=[401, 400])

    # -------------------------------------------------------------------------
    # TC-020: Select API - Wrong HTTP Method (GET)
    # -------------------------------------------------------------------------
    @task(1)
    def tc020_select_wrong_http_method(self):
        """GET /select should be rejected — only POST is supported."""
        self.step_name = 'TC020_Select_Wrong_HTTP_Method'
        with self.client.get(
            name=self.step_name,
            url="/select",
            catch_response=True
        ) as response:
            if response.status_code not in [404, 405]:
                response.failure(f"{self.step_name} Failed: Expected 404/405, got {response.status_code}")
            else:
                response.success()

    # -------------------------------------------------------------------------
    # TC-021: Select API - Missing context.city
    # -------------------------------------------------------------------------
    @task(1)
    def tc021_select_missing_city(self):
        """Select payload without the 'city' field in context must be rejected."""
        self.step_name = 'TC021_Select_Missing_City'
        payload = self._generate_select_payload()
        del payload['context']['city']
        self._send_select_request(self.step_name, payload, expected_status=[400, 422, 401])

    # -------------------------------------------------------------------------
    # TC-022: Select API - Missing context.core_version
    # -------------------------------------------------------------------------
    @task(1)
    def tc022_select_missing_core_version(self):
        """Select payload without the 'core_version' field in context must be rejected."""
        self.step_name = 'TC022_Select_Missing_Core_Version'
        payload = self._generate_select_payload()
        del payload['context']['core_version']
        self._send_select_request(self.step_name, payload, expected_status=[400, 422, 401])

    # -------------------------------------------------------------------------
    # TC-023: Select API - Negative Item Quantity
    # -------------------------------------------------------------------------
    @task(1)
    def tc023_select_negative_quantity(self):
        """Item with a negative quantity count is semantically invalid."""
        self.step_name = 'TC023_Select_Negative_Quantity'
        payload = self._generate_select_payload()
        payload['message']['order']['items'] = [{"id": "item-001", "quantity": {"count": -1}}]
        self._send_select_request(self.step_name, payload, expected_status=[400, 422])

    # -------------------------------------------------------------------------
    # TC-024: Select API - Duplicate message_id (Replay Attack)
    # -------------------------------------------------------------------------
    @task(1)
    def tc024_select_duplicate_message_id(self):
        """Replaying the same message_id should be detected/rejected (idempotency / replay prevention)."""
        self.step_name = 'TC024_Select_Duplicate_MsgID'
        fixed_msg_id = f"msg-replay-{uuid.uuid4().hex[:8]}"
        payload = self._generate_select_payload(message_id=fixed_msg_id)
        # First request — expected to succeed
        self._send_select_request(f"{self.step_name}_First", payload, expected_status=[200, 202, 400, 422, 401])
        # Second request with identical message_id — may be rejected as replay
        self._send_select_request(f"{self.step_name}_Replay", payload, expected_status=[200, 202, 400, 409, 401, 422])

    # -------------------------------------------------------------------------
    # TC-025: Select API - Wrong action in context (action mismatch)
    # -------------------------------------------------------------------------
    @task(1)
    def tc025_select_wrong_action_value(self):
        """Using a different action value (e.g. 'confirm') in /select context is invalid."""
        self.step_name = 'TC025_Select_Wrong_Action'
        payload = self._generate_select_payload()
        payload['context']['action'] = 'confirm'   # wrong action for /select endpoint
        self._send_select_request(self.step_name, payload, expected_status=[400, 422, 401])

    # -------------------------------------------------------------------------
    # TC-026: Select API - Oversized Item List (DoS Prevention)
    # -------------------------------------------------------------------------
    @task(1)
    def tc026_select_oversized_item_list(self):
        """Send /select with an excessively large item count to test DoS guardrails."""
        self.step_name = 'TC026_Select_Oversized_Items'
        items = [{"id": f"item-{i:04d}", "quantity": {"count": 1}} for i in range(500)]
        payload = self._generate_select_payload(items=items)
        self._send_select_request(self.step_name, payload, expected_status=[200, 202, 400, 413, 422])

    # =========================================================================
    # on_select negative tests
    # =========================================================================

    # -------------------------------------------------------------------------
    # TC-027: on_select API - Missing Authorization Header
    # -------------------------------------------------------------------------
    @task(1)
    def tc027_on_select_missing_auth(self):
        """Gateway must reject /on_select requests with no Authorization header."""
        self.step_name = 'TC027_OnSelect_Missing_Auth'
        payload = self._generate_on_select_payload()
        self._send_on_select_request(
            self.step_name,
            payload,
            headers={"Content-Type": "application/json; charset=utf-8"},
            expected_status=[401, 400]
        )

    # -------------------------------------------------------------------------
    # TC-028: on_select API - Invalid Signature
    # -------------------------------------------------------------------------
    @task(1)
    def tc028_on_select_invalid_signature(self):
        """Tampered /on_select Authorization signature must be rejected."""
        self.step_name = 'TC028_OnSelect_Invalid_Signature'
        payload = self._generate_on_select_payload()
        headers = self.auth_helper.generate_headers(payload)
        headers.pop('serialized_body', None)
        headers['Authorization'] = headers['Authorization'].replace('signature="', 'signature="TAMPERED')
        self._send_on_select_request(self.step_name, payload, headers=headers, expected_status=[401, 400])

    # -------------------------------------------------------------------------
    # TC-029: on_select API - Missing context.bap_id
    # -------------------------------------------------------------------------
    @task(1)
    def tc029_on_select_missing_bap_id(self):
        """on_select payload without bap_id — gateway cannot route response to BAP."""
        self.step_name = 'TC029_OnSelect_Missing_BAP_ID'
        payload = self._generate_on_select_payload()
        del payload['context']['bap_id']
        self._send_on_select_request(self.step_name, payload, expected_status=[400, 422, 401])

    # -------------------------------------------------------------------------
    # TC-030: on_select API - Missing context.transaction_id
    # -------------------------------------------------------------------------
    @task(1)
    def tc030_on_select_missing_transaction_id(self):
        """on_select without transaction_id cannot be correlated to original select."""
        self.step_name = 'TC030_OnSelect_Missing_TxnID'
        payload = self._generate_on_select_payload()
        del payload['context']['transaction_id']
        self._send_on_select_request(self.step_name, payload, expected_status=[400, 422, 401])

    # -------------------------------------------------------------------------
    # TC-031: on_select API - Missing message.order.quote
    # -------------------------------------------------------------------------
    @task(1)
    def tc031_on_select_missing_quote(self):
        """on_select payload without a quote is invalid — quote is the purpose of on_select."""
        self.step_name = 'TC031_OnSelect_Missing_Quote'
        payload = self._generate_on_select_payload()
        del payload['message']['order']['quote']
        self._send_on_select_request(self.step_name, payload, expected_status=[400, 422])

    # -------------------------------------------------------------------------
    # TC-032: on_select API - Missing message Object
    # -------------------------------------------------------------------------
    @task(1)
    def tc032_on_select_missing_message(self):
        """on_select payload with 'message' key entirely absent must be rejected."""
        self.step_name = 'TC032_OnSelect_Missing_Message'
        payload = self._generate_on_select_payload()
        del payload['message']
        self._send_on_select_request(self.step_name, payload, expected_status=[400, 422, 401])


tasks = [ONDCGatewaySelectNegative]
