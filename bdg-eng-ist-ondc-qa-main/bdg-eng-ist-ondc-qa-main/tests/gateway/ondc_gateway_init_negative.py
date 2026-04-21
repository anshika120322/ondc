import json
import re
import time
import uuid
from datetime import datetime, timezone, timedelta
from locust import task, between
from tests.gateway.gateway_init_base import GatewayInitBase

"""
ONDC Gateway Init API - Negative Tests (Unhappy-Path / Error Scenarios)
All tests use @task(1) for equal distribution during validation.
Run with low user count: --users 1 --iterations 5
"""


class ONDCGatewayInitNegative(GatewayInitBase):
    """Negative test scenarios for /init and /on_init error-handling validation"""

    wait_time = between(1, 3)

    config_file = 'resources/gateway/ondc_gateway_init_negative.yml'
    tenant_name = 'ondcGW'

    # -------------------------------------------------------------------------
    # TC-001: Init API - Missing Authorization Header
    # -------------------------------------------------------------------------
    @task(1)
    def tc001_init_missing_auth(self):
        """Gateway must reject /init requests that carry no Authorization header."""
        self.step_name = 'TC001_Init_Missing_Auth'
        payload = self._generate_init_payload()
        self._send_init_request(
            self.step_name,
            payload,
            headers={"Content-Type": "application/json; charset=utf-8"},
            expected_status=[401, 400]
        )

    # -------------------------------------------------------------------------
    # TC-002: Init API - Invalid / Tampered Signature
    # -------------------------------------------------------------------------
    @task(1)
    def tc002_init_invalid_signature(self):
        """Tamper the Authorization signature after generation; Gateway must reject."""
        self.step_name = 'TC002_Init_Invalid_Signature'
        payload = self._generate_init_payload()
        headers = self.auth_helper.generate_headers(payload)
        headers.pop('serialized_body', None)
        headers['Authorization'] = headers['Authorization'].replace('signature="', 'signature="INVALID')
        self._send_init_request(self.step_name, payload, headers=headers, expected_status=[401, 400])

    # -------------------------------------------------------------------------
    # TC-003: Init API - Invalid Digest Header
    # -------------------------------------------------------------------------
    @task(1)
    def tc003_init_invalid_digest(self):
        """Replace Digest header with garbage; Gateway must return 412 / 401 / 400."""
        self.step_name = 'TC003_Init_Invalid_Digest'
        payload = self._generate_init_payload()
        headers = self.auth_helper.generate_headers(payload)
        headers.pop('serialized_body', None)
        headers['Digest'] = 'BLAKE-512=INVALID_DIGEST_VALUE=='
        self._send_init_request(self.step_name, payload, headers=headers, expected_status=[412, 401, 400])

    # -------------------------------------------------------------------------
    # TC-004: Init API - Missing context.domain
    # -------------------------------------------------------------------------
    @task(1)
    def tc004_init_missing_domain(self):
        """Init payload without 'domain' in context must be rejected."""
        self.step_name = 'TC004_Init_Missing_Domain'
        payload = self._generate_init_payload()
        del payload['context']['domain']
        self._send_init_request(self.step_name, payload, expected_status=[400, 422, 401])

    # -------------------------------------------------------------------------
    # TC-005: Init API - Missing context.bpp_id
    # -------------------------------------------------------------------------
    @task(1)
    def tc005_init_missing_bpp_id(self):
        """Init payload without 'bpp_id' is INVALID — bpp_id is required for /init."""
        self.step_name = 'TC005_Init_Missing_BPP_ID'
        payload = self._generate_init_payload()
        del payload['context']['bpp_id']
        self._send_init_request(self.step_name, payload, expected_status=[400, 422, 401])

    # -------------------------------------------------------------------------
    # TC-006: Init API - Missing context.bpp_uri
    # -------------------------------------------------------------------------
    @task(1)
    def tc006_init_missing_bpp_uri(self):
        """Init payload without 'bpp_uri' is INVALID — bpp_uri is required for /init."""
        self.step_name = 'TC006_Init_Missing_BPP_URI'
        payload = self._generate_init_payload()
        del payload['context']['bpp_uri']
        self._send_init_request(self.step_name, payload, expected_status=[400, 422, 401])

    # -------------------------------------------------------------------------
    # TC-007: Init API - Missing message.order.provider
    # -------------------------------------------------------------------------
    @task(1)
    def tc007_init_missing_provider(self):
        """Init without order.provider must be rejected."""
        self.step_name = 'TC007_Init_Missing_Provider'
        payload = self._generate_init_payload()
        del payload['message']['order']['provider']
        self._send_init_request(self.step_name, payload, expected_status=[400, 422, 401])

    # -------------------------------------------------------------------------
    # TC-008: Init API - Missing message.order.billing
    # -------------------------------------------------------------------------
    @task(1)
    def tc008_init_missing_billing(self):
        """Init without billing details must be rejected."""
        self.step_name = 'TC008_Init_Missing_Billing'
        payload = self._generate_init_payload()
        del payload['message']['order']['billing']
        self._send_init_request(self.step_name, payload, expected_status=[400, 422, 401])

    # -------------------------------------------------------------------------
    # TC-009: Init API - Missing billing.name (required field)
    # -------------------------------------------------------------------------
    @task(1)
    def tc009_init_missing_billing_name(self):
        """Init billing block without 'name' (required) must be rejected."""
        self.step_name = 'TC009_Init_Missing_Billing_Name'
        payload = self._generate_init_payload()
        del payload['message']['order']['billing']['name']
        self._send_init_request(self.step_name, payload, expected_status=[400, 422, 401])

    # -------------------------------------------------------------------------
    # TC-010: Init API - Missing message.order.fulfillments
    # -------------------------------------------------------------------------
    @task(1)
    def tc010_init_missing_fulfillments(self):
        """Init without fulfillments must be rejected."""
        self.step_name = 'TC010_Init_Missing_Fulfillments'
        payload = self._generate_init_payload()
        del payload['message']['order']['fulfillments']
        self._send_init_request(self.step_name, payload, expected_status=[400, 422, 401])

    # -------------------------------------------------------------------------
    # TC-011: Init API - Missing message.order.payments
    # -------------------------------------------------------------------------
    @task(1)
    def tc011_init_missing_payments(self):
        """Init without payments array must be rejected."""
        self.step_name = 'TC011_Init_Missing_Payments'
        payload = self._generate_init_payload()
        del payload['message']['order']['payments']
        self._send_init_request(self.step_name, payload, expected_status=[400, 422, 401])

    # -------------------------------------------------------------------------
    # TC-012: Init API - Invalid Payment Type (ON-ORDER not allowed in /init)
    # -------------------------------------------------------------------------
    @task(1)
    def tc012_init_invalid_payment_type_on_order(self):
        """Init with payments[].type = 'ON-ORDER' must be rejected —
        valid types for /init are PRE-ORDER, ON-FULFILLMENT, POST-FULFILLMENT only."""
        self.step_name = 'TC012_Init_Invalid_Payment_ON_ORDER'
        payload = self._generate_init_payload()
        payload['message']['order']['payments'][0]['type'] = 'ON-ORDER'
        self._send_init_request(self.step_name, payload, expected_status=[400, 422, 401])

    # -------------------------------------------------------------------------
    # TC-013: Init API - Missing payments.tags
    # -------------------------------------------------------------------------
    @task(1)
    def tc013_init_missing_payment_tags(self):
        """Init payment entry without 'tags' block must be rejected."""
        self.step_name = 'TC013_Init_Missing_Payment_Tags'
        payload = self._generate_init_payload()
        del payload['message']['order']['payments'][0]['tags']
        self._send_init_request(self.step_name, payload, expected_status=[400, 422, 401])

    # -------------------------------------------------------------------------
    # TC-014: Init API - Invalid payments.collected_by Value
    # -------------------------------------------------------------------------
    @task(1)
    def tc014_init_invalid_collected_by(self):
        """Init with payments[].collected_by = 'INVALID' must be rejected."""
        self.step_name = 'TC014_Init_Invalid_Collected_By'
        payload = self._generate_init_payload()
        payload['message']['order']['payments'][0]['collected_by'] = 'INVALID_PARTY'
        self._send_init_request(self.step_name, payload, expected_status=[400, 422, 401])

    # -------------------------------------------------------------------------
    # TC-015: Init API - Missing context.transaction_id
    # -------------------------------------------------------------------------
    @task(1)
    def tc015_init_missing_transaction_id(self):
        """Init payload without 'transaction_id' must be rejected."""
        self.step_name = 'TC015_Init_Missing_Txn_ID'
        payload = self._generate_init_payload()
        del payload['context']['transaction_id']
        self._send_init_request(self.step_name, payload, expected_status=[400, 422, 401])

    # -------------------------------------------------------------------------
    # TC-016: Init API - Missing context.message_id
    # -------------------------------------------------------------------------
    @task(1)
    def tc016_init_missing_message_id(self):
        """Init payload without 'message_id' must be rejected."""
        self.step_name = 'TC016_Init_Missing_Msg_ID'
        payload = self._generate_init_payload()
        del payload['context']['message_id']
        self._send_init_request(self.step_name, payload, expected_status=[400, 422, 401])

    # -------------------------------------------------------------------------
    # TC-017: Init API - Expired Timestamp (1 hour in the past)
    # -------------------------------------------------------------------------
    @task(1)
    def tc017_init_expired_timestamp(self):
        """Init with a timestamp 1 hour in the past should be rejected (TTL violation)."""
        self.step_name = 'TC017_Init_Expired_Timestamp'
        payload = self._generate_init_payload()
        expired_ts = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(timespec='milliseconds').replace('+00:00', 'Z')
        payload['context']['timestamp'] = expired_ts
        self._send_init_request(self.step_name, payload, expected_status=[400, 401, 422])

    # -------------------------------------------------------------------------
    # TC-018: Init API - Future Timestamp (1 hour ahead)
    # -------------------------------------------------------------------------
    @task(1)
    def tc018_init_future_timestamp(self):
        """Init with a timestamp 1 hour in the future should be rejected."""
        self.step_name = 'TC018_Init_Future_Timestamp'
        payload = self._generate_init_payload()
        future_ts = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(timespec='milliseconds').replace('+00:00', 'Z')
        payload['context']['timestamp'] = future_ts
        self._send_init_request(self.step_name, payload, expected_status=[400, 401, 422])

    # -------------------------------------------------------------------------
    # TC-019: Init API - Invalid context.action (wrong action name)
    # -------------------------------------------------------------------------
    @task(1)
    def tc019_init_wrong_action(self):
        """Init payload with context.action='confirm' (wrong action) must be rejected."""
        self.step_name = 'TC019_Init_Wrong_Action'
        payload = self._generate_init_payload()
        payload['context']['action'] = 'confirm'
        self._send_init_request(self.step_name, payload, expected_status=[400, 422, 401])

    # -------------------------------------------------------------------------
    # TC-020: Init API - Invalid domain value
    # -------------------------------------------------------------------------
    @task(1)
    def tc020_init_invalid_domain(self):
        """Init payload with a non-existent ONDC domain must be rejected."""
        self.step_name = 'TC020_Init_Invalid_Domain'
        payload = self._generate_init_payload(domain="ONDC:INVALID99")
        self._send_init_request(self.step_name, payload, expected_status=[400, 422, 404, 401])

    # -------------------------------------------------------------------------
    # TC-021: Init API - Empty payload body
    # -------------------------------------------------------------------------
    @task(1)
    def tc021_init_empty_payload(self):
        """Empty JSON body {} must be rejected by the Gateway."""
        self.step_name = 'TC021_Init_Empty_Payload'
        payload = {}
        headers = {"Content-Type": "application/json; charset=utf-8"}
        with self.client.post(
            name=self.step_name,
            url="/init",
            data=json.dumps(payload, separators=(',', ':')).encode('utf-8'),
            headers=headers,
            catch_response=True
        ) as response:
            if response.status_code not in [400, 401, 422]:
                response.failure(f"TC-021 Failed: Expected 400/401/422, got {response.status_code}")
                return
            response.success()

    # -------------------------------------------------------------------------
    # TC-022: Init API - Malformed JSON (not valid JSON)
    # -------------------------------------------------------------------------
    @task(1)
    def tc022_init_malformed_json(self):
        """Malformed JSON body must be rejected with 400."""
        self.step_name = 'TC022_Init_Malformed_JSON'
        malformed = b'{"context": {"domain": "ONDC:RET10", "action": "init"'  # unclosed
        with self.client.post(
            name=self.step_name,
            url="/init",
            data=malformed,
            headers={"Content-Type": "application/json; charset=utf-8"},
            catch_response=True
        ) as response:
            if response.status_code not in [400, 401, 422]:
                response.failure(f"TC-022 Failed: Expected 400/401/422, got {response.status_code}")
                return
            response.success()

    # -------------------------------------------------------------------------
    # TC-023: Init API - Empty items array
    # -------------------------------------------------------------------------
    @task(1)
    def tc023_init_empty_items(self):
        """Init with an empty items array must be rejected."""
        self.step_name = 'TC023_Init_Empty_Items'
        payload = self._generate_init_payload()
        payload['message']['order']['items'] = []
        self._send_init_request(self.step_name, payload, expected_status=[400, 422, 401])

    # -------------------------------------------------------------------------
    # TC-024: Init API - Missing context.core_version
    # -------------------------------------------------------------------------
    @task(1)
    def tc024_init_missing_core_version(self):
        """Init without context.core_version must be rejected."""
        self.step_name = 'TC024_Init_Missing_Core_Version'
        payload = self._generate_init_payload()
        del payload['context']['core_version']
        self._send_init_request(self.step_name, payload, expected_status=[400, 422, 401])

    # -------------------------------------------------------------------------
    # TC-025: Init API - Empty fulfillments array
    # -------------------------------------------------------------------------
    @task(1)
    def tc025_init_empty_fulfillments(self):
        """Init with an empty fulfillments array must be rejected."""
        self.step_name = 'TC025_Init_Empty_Fulfillments'
        payload = self._generate_init_payload()
        payload['message']['order']['fulfillments'] = []
        self._send_init_request(self.step_name, payload, expected_status=[400, 422, 401])

    # -------------------------------------------------------------------------
    # TC-026: on_init Callback - Missing quote
    # -------------------------------------------------------------------------
    @task(1)
    def tc026_on_init_missing_quote(self):
        """on_init without quote block must be rejected (quote is required)."""
        self.step_name = 'TC026_On_Init_Missing_Quote'
        payload = self._generate_on_init_payload()
        del payload['message']['order']['quote']
        self._send_on_init_request(self.step_name, payload, expected_status=[400, 422, 401])

    # -------------------------------------------------------------------------
    # TC-027: on_init Callback - Missing quote.breakup BASE_FARE
    # -------------------------------------------------------------------------
    @task(1)
    def tc027_on_init_missing_base_fare(self):
        """on_init quote breakup without BASE_FARE title must be rejected."""
        self.step_name = 'TC027_On_Init_Missing_BASE_FARE'
        payload = self._generate_on_init_payload()
        # Remove BASE_FARE, keep only DISTANCE_FARE
        payload['message']['order']['quote']['breakup'] = [
            {"title": "DISTANCE_FARE", "price": {"currency": "INR", "value": "50.00"}},
            {"title": "TAX", "price": {"currency": "INR", "value": "30.00"}}
        ]
        self._send_on_init_request(self.step_name, payload, expected_status=[400, 422, 401])

    # -------------------------------------------------------------------------
    # TC-028: on_init Callback - Missing cancellation_terms
    # -------------------------------------------------------------------------
    @task(1)
    def tc028_on_init_missing_cancellation_terms(self):
        """on_init without cancellation_terms must be rejected."""
        self.step_name = 'TC028_On_Init_Missing_Cancellation_Terms'
        payload = self._generate_on_init_payload()
        del payload['message']['order']['cancellation_terms']
        self._send_on_init_request(self.step_name, payload, expected_status=[400, 422, 401])

    # -------------------------------------------------------------------------
    # TC-029: on_init Callback - Invalid fulfillment type (lowercase)
    # -------------------------------------------------------------------------
    @task(1)
    def tc029_on_init_invalid_fulfillment_type(self):
        """on_init fulfillments[].type = 'Delivery' (not uppercase 'DELIVERY') must be rejected."""
        self.step_name = 'TC029_On_Init_Invalid_Fulfillment_Type'
        payload = self._generate_on_init_payload()
        payload['message']['order']['fulfillments'][0]['type'] = 'Delivery'  # should be 'DELIVERY'
        self._send_on_init_request(self.step_name, payload, expected_status=[400, 422, 401])

    # -------------------------------------------------------------------------
    # TC-030: on_init Callback - Item missing fulfillment_ids
    # -------------------------------------------------------------------------
    @task(1)
    def tc030_on_init_missing_fulfillment_ids(self):
        """on_init items without fulfillment_ids must be rejected."""
        self.step_name = 'TC030_On_Init_Missing_Fulfillment_IDs'
        payload = self._generate_on_init_payload()
        del payload['message']['order']['items'][0]['fulfillment_ids']
        self._send_on_init_request(self.step_name, payload, expected_status=[400, 422, 401])

    # -------------------------------------------------------------------------
    # TC-031: on_init Callback - Item missing location_ids
    # -------------------------------------------------------------------------
    @task(1)
    def tc031_on_init_missing_location_ids(self):
        """on_init items without location_ids must be rejected."""
        self.step_name = 'TC031_On_Init_Missing_Location_IDs'
        payload = self._generate_on_init_payload()
        del payload['message']['order']['items'][0]['location_ids']
        self._send_on_init_request(self.step_name, payload, expected_status=[400, 422, 401])

    # -------------------------------------------------------------------------
    # TC-032: on_init Callback - Invalid cancellation_terms fulfillment_state code
    # -------------------------------------------------------------------------
    @task(1)
    def tc032_on_init_invalid_cancellation_state(self):
        """on_init cancellation_terms with invalid fulfillment_state code must be rejected.
        Valid codes: RIDE_ASSIGNED, RIDE_ENROUTE_PICKUP, RIDE_ARRIVED_PICKUP, RIDE_STARTED."""
        self.step_name = 'TC032_On_Init_Invalid_Cancel_State'
        payload = self._generate_on_init_payload()
        payload['message']['order']['cancellation_terms'][0]['fulfillment_state']['descriptor']['code'] = 'INVALID_STATE'
        self._send_on_init_request(self.step_name, payload, expected_status=[400, 422, 401])

    # =========================================================================
    # AUTHORIZATION HEADER VALIDATION TESTS (TC-033 to TC-039)
    # =========================================================================

    # -------------------------------------------------------------------------
    # TC-033: Invalid Algorithm Value "banaa"
    # -------------------------------------------------------------------------
    @task(1)
    def tc033_init_invalid_algorithm_banaa(self):
        """Init with invalid algorithm 'banaa' in Authorization header; Gateway must reject with 401."""
        self.step_name = 'TC033_Init_Invalid_Algorithm_Banaa'
        payload = self._generate_init_payload()
        
        # Generate valid headers first
        headers = self.auth_helper.generate_headers(payload, include_digest=True)
        
        # Modify the algorithm field in Authorization header
        if "Authorization" in headers:
            headers["Authorization"] = re.sub(
                r'algorithm="[^"]*"',
                'algorithm="banaa"',
                headers["Authorization"]
            )
        
        self._send_init_request(self.step_name, payload, headers=headers, expected_status=[401, 400])

    # -------------------------------------------------------------------------
    # TC-034: Invalid Algorithm Value "mango"
    # -------------------------------------------------------------------------
    @task(1)
    def tc034_init_invalid_algorithm_mango(self):
        """Init with invalid algorithm 'mango' in Authorization header; Gateway must reject with 401."""
        self.step_name = 'TC034_Init_Invalid_Algorithm_Mango'
        payload = self._generate_init_payload()
        
        headers = self.auth_helper.generate_headers(payload, include_digest=True)
        
        if "Authorization" in headers:
            headers["Authorization"] = re.sub(
                r'algorithm="[^"]*"',
                'algorithm="mango"',
                headers["Authorization"]
            )
        
        self._send_init_request(self.step_name, payload, headers=headers, expected_status=[401, 400])

    # -------------------------------------------------------------------------
    # TC-035: Invalid Algorithm Value "banana"
    # -------------------------------------------------------------------------
    @task(1)
    def tc035_init_invalid_algorithm_banana(self):
        """Init with invalid algorithm 'banana' in Authorization header; Gateway must reject with 401."""
        self.step_name = 'TC035_Init_Invalid_Algorithm_Banana'
        payload = self._generate_init_payload()
        
        headers = self.auth_helper.generate_headers(payload, include_digest=True)
        
        if "Authorization" in headers:
            headers["Authorization"] = re.sub(
                r'algorithm="[^"]*"',
                'algorithm="banana"',
                headers["Authorization"]
            )
        
        self._send_init_request(self.step_name, payload, headers=headers, expected_status=[401, 400])

    # -------------------------------------------------------------------------
    # TC-036: Headers Field Missing Digest
    # -------------------------------------------------------------------------
    @task(1)
    def tc036_init_headers_field_missing_digest(self):
        """Init with 'headers' field missing 'digest' in Authorization; Gateway must reject with 401."""
        self.step_name = 'TC036_Init_Headers_Missing_Digest'
        payload = self._generate_init_payload()
        
        headers = self.auth_helper.generate_headers(payload, include_digest=True)
        
        if "Authorization" in headers:
            headers["Authorization"] = re.sub(
                r'headers="[^"]*"',
                'headers="(created) (expires)"',
                headers["Authorization"]
            )
        
        self._send_init_request(self.step_name, payload, headers=headers, expected_status=[401, 400])

    # -------------------------------------------------------------------------
    # TC-037: Headers Field Wrong Order
    # -------------------------------------------------------------------------
    @task(1)
    def tc037_init_headers_field_wrong_order(self):
        """Init with 'headers' field in wrong order in Authorization; Gateway must reject with 401."""
        self.step_name = 'TC037_Init_Headers_Wrong_Order'
        payload = self._generate_init_payload()
        
        headers = self.auth_helper.generate_headers(payload, include_digest=True)
        
        if "Authorization" in headers:
            headers["Authorization"] = re.sub(
                r'headers="[^"]*"',
                'headers="digest (created) (expires)"',
                headers["Authorization"]
            )
        
        self._send_init_request(self.step_name, payload, headers=headers, expected_status=[401, 400])

    # -------------------------------------------------------------------------
    # TC-038: Headers Field With Extra Fields
    # -------------------------------------------------------------------------
    @task(1)
    def tc038_init_headers_field_extra_fields(self):
        """Init with extra fields in 'headers' field in Authorization; Gateway must reject with 401."""
        self.step_name = 'TC038_Init_Headers_Extra_Fields'
        payload = self._generate_init_payload()
        
        headers = self.auth_helper.generate_headers(payload, include_digest=True)
        
        if "Authorization" in headers:
            headers["Authorization"] = re.sub(
                r'headers="[^"]*"',
                'headers="(created) (expires) digest (invalid)"',
                headers["Authorization"]
            )
        
        self._send_init_request(self.step_name, payload, headers=headers, expected_status=[401, 400])

    # -------------------------------------------------------------------------
    # TC-039: Headers Field Empty
    # -------------------------------------------------------------------------
    @task(1)
    def tc039_init_headers_field_empty(self):
        """Init with empty 'headers' field in Authorization; Gateway must reject with 401."""
        self.step_name = 'TC039_Init_Headers_Empty'
        payload = self._generate_init_payload()
        
        headers = self.auth_helper.generate_headers(payload, include_digest=True)
        
        if "Authorization" in headers:
            headers["Authorization"] = re.sub(
                r'headers="[^"]*"',
                'headers=""',
                headers["Authorization"]
            )
        
        self._send_init_request(self.step_name, payload, headers=headers, expected_status=[401, 400])


tasks = [ONDCGatewayInitNegative]
