import json
import time
import uuid
from datetime import datetime, timezone
from locust import task, between
from tests.gateway.gateway_init_base import GatewayInitBase

"""
ONDC Gateway Init API - Functional Tests (Positive / Happy-Path Scenarios)
All tests use @task(1) for equal distribution during functional validation.
Run with low user count: --users 1 --iterations 5

Key schema rules for /init (differs from /confirm):
  - bpp_id and bpp_uri are REQUIRED in context
  - message.order.payments is an ARRAY
  - payments[].type enum: PRE-ORDER, ON-FULFILLMENT, POST-FULFILLMENT (NOT ON-ORDER)
  - payments[].tags must include SETTLEMENT_TERMS + BUYER_FINDER_FEES codes

Key schema rules for /on_init:
  - items must include fulfillment_ids and location_ids
  - fulfillments[].type must be "DELIVERY" (uppercase)
  - quote is required with breakup containing BASE_FARE and DISTANCE_FARE
  - cancellation_terms required with valid fulfillment_state codes
"""


class ONDCGatewayInitFunctional(GatewayInitBase):
    """Positive test scenarios for /init and /on_init functional validation"""

    wait_time = between(1, 3)

    config_file = 'resources/gateway/ondc_gateway_init_functional.yml'
    tenant_name = 'ondcGW'

    # -------------------------------------------------------------------------
    # TC-001: Init API - Valid Request with Authentication
    # -------------------------------------------------------------------------
    @task(1)
    def tc001_init_valid_authenticated(self):
        """Submit a fully-valid /init payload with proper ONDC auth."""
        self.step_name = 'TC001_Init_Valid_Auth'
        payload = self._generate_init_payload()
        self._send_init_request(self.step_name, payload)

    # -------------------------------------------------------------------------
    # TC-002: Init API - Different ONDC Domains
    # -------------------------------------------------------------------------
    @task(1)
    def tc002_init_different_domains(self):
        """Send /init across each configured ONDC domain."""
        self.step_name = 'TC002_Init_Different_Domains'
        for domain in self.init_domains:
            payload = self._generate_init_payload(domain=domain)
            self._send_init_request(
                f"{self.step_name}_{domain}",
                payload,
                expected_status=[200, 202]
            )

    # -------------------------------------------------------------------------
    # TC-003: Init API - Different Cities
    # -------------------------------------------------------------------------
    @task(1)
    def tc003_init_different_cities(self):
        """Send /init for each configured delivery city."""
        self.step_name = 'TC003_Init_Different_Cities'
        for city in self.cities:
            payload = self._generate_init_payload(city=city)
            self._send_init_request(
                f"{self.step_name}_{city}",
                payload,
                expected_status=[200, 202]
            )

    # -------------------------------------------------------------------------
    # TC-004: Init API - Payment Type PRE-ORDER
    # -------------------------------------------------------------------------
    @task(1)
    def tc004_init_payment_pre_order(self):
        """Send /init with PRE-ORDER payment type (pay before fulfillment starts)."""
        self.step_name = 'TC004_Init_Payment_PRE_ORDER'
        payment = {"type": "PRE-ORDER", "status": "PAID", "collected_by": "BAP"}
        payload = self._generate_init_payload(payment_type=payment)
        self._send_init_request(self.step_name, payload)

    # -------------------------------------------------------------------------
    # TC-005: Init API - Payment Type ON-FULFILLMENT (COD)
    # -------------------------------------------------------------------------
    @task(1)
    def tc005_init_payment_on_fulfillment(self):
        """Send /init with ON-FULFILLMENT payment type (cash on delivery)."""
        self.step_name = 'TC005_Init_Payment_ON_FULFILLMENT'
        payment = {"type": "ON-FULFILLMENT", "status": "NOT-PAID", "collected_by": "BPP"}
        payload = self._generate_init_payload(payment_type=payment)
        self._send_init_request(self.step_name, payload)

    # -------------------------------------------------------------------------
    # TC-006: Init API - Payment Type POST-FULFILLMENT
    # -------------------------------------------------------------------------
    @task(1)
    def tc006_init_payment_post_fulfillment(self):
        """Send /init with POST-FULFILLMENT payment type (pay after delivery)."""
        self.step_name = 'TC006_Init_Payment_POST_FULFILLMENT'
        payment = {"type": "POST-FULFILLMENT", "status": "NOT-PAID", "collected_by": "BPP"}
        payload = self._generate_init_payload(payment_type=payment)
        self._send_init_request(self.step_name, payload)

    # -------------------------------------------------------------------------
    # TC-007: Init API - All Three Payment Types in Sequence
    # -------------------------------------------------------------------------
    @task(1)
    def tc007_init_all_payment_types(self):
        """Send /init for each configured payment type sequentially."""
        self.step_name = 'TC007_Init_All_Payment_Types'
        payment_types = self.payment_types or [
            {"type": "PRE-ORDER", "status": "PAID", "collected_by": "BAP"},
            {"type": "ON-FULFILLMENT", "status": "NOT-PAID", "collected_by": "BPP"},
            {"type": "POST-FULFILLMENT", "status": "NOT-PAID", "collected_by": "BPP"},
        ]
        for payment in payment_types:
            payload = self._generate_init_payload(payment_type=payment)
            self._send_init_request(
                f"{self.step_name}_{payment.get('type')}",
                payload,
                expected_status=[200, 202]
            )

    # -------------------------------------------------------------------------
    # TC-008: Init API - Different Fulfillment Types
    # -------------------------------------------------------------------------
    @task(1)
    def tc008_init_fulfillment_types(self):
        """Send /init with Delivery, Pickup, and Self-Pickup fulfillment types."""
        self.step_name = 'TC008_Init_Fulfillment_Types'
        fulfillment_types = self.fulfillment_types or ["Delivery", "Pickup", "Self-Pickup"]
        for ftype in fulfillment_types:
            payload = self._generate_init_payload(fulfillment_type=ftype)
            self._send_init_request(
                f"{self.step_name}_{ftype}",
                payload,
                expected_status=[200, 202]
            )

    # -------------------------------------------------------------------------
    # TC-009: Init API - Multiple Items in Order
    # -------------------------------------------------------------------------
    @task(1)
    def tc009_init_multiple_items(self):
        """Send /init with multiple line items in the order."""
        self.step_name = 'TC009_Init_Multiple_Items'
        payload = self._generate_init_payload()
        payload['message']['order']['items'] = [
            {"id": "item-001", "quantity": {"count": 2}},
            {"id": "item-002", "quantity": {"count": 1}},
            {"id": "item-003", "quantity": {"count": 3}},
        ]
        self._send_init_request(self.step_name, payload)

    # -------------------------------------------------------------------------
    # TC-010: Init API - Minimal Required Fields Only
    # -------------------------------------------------------------------------
    @task(1)
    def tc010_init_minimal_payload(self):
        """Send /init with only the minimum required ONDC fields."""
        self.step_name = 'TC010_Init_Minimal_Payload'
        txn_id = f"txn-{uuid.uuid4().hex[:12]}"
        msg_id = f"msg-{uuid.uuid4().hex[:12]}"
        payload = {
            "context": {
                "domain": "ONDC:RET10",
                "action": "init",
                "country": "IND",
                "city": "std:080",
                "core_version": self.core_version,
                "bap_id": self.bap_id,
                "bap_uri": self.bap_uri,
                "bpp_id": self.bpp_id,
                "bpp_uri": self.bpp_uri,
                "transaction_id": txn_id,
                "message_id": msg_id,
                "timestamp": datetime.now(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z'),
                "ttl": "PT30S"
            },
            "message": {
                "order": {
                    "provider": {"id": "IGO_Seller_0001"},
                    "items": [{"id": "item-001", "quantity": {"count": 1}}],
                    "billing": {"name": "Test Buyer"},
                    "fulfillments": [{"id": "F1", "type": "Delivery"}],
                    "payments": [
                        {
                            "type": "PRE-ORDER",
                            "status": "PAID",
                            "collected_by": "BAP",
                            "tags": [
                                {
                                    "descriptor": {"code": "SETTLEMENT_TERMS"},
                                    "list": [
                                        {"descriptor": {"code": "settlement_counterparty"}, "value": "seller-app"},
                                        {"descriptor": {"code": "settlement_type"}, "value": "neft"}
                                    ]
                                },
                                {
                                    "descriptor": {"code": "BUYER_FINDER_FEES"},
                                    "list": [
                                        {"descriptor": {"code": "buyer_finder_fee_type"}, "value": "percent"},
                                        {"descriptor": {"code": "buyer_finder_fee_amount"}, "value": "3.0"}
                                    ]
                                }
                            ]
                        }
                    ]
                }
            }
        }
        self._send_init_request(self.step_name, payload)

    # -------------------------------------------------------------------------
    # TC-011: Init API - Different Providers
    # -------------------------------------------------------------------------
    @task(1)
    def tc011_init_different_providers(self):
        """Send /init against each configured test provider."""
        self.step_name = 'TC011_Init_Different_Providers'
        providers = self.test_providers or [{"id": "IGO_Seller_0001", "location_id": "store-location-001"}]
        for provider in providers:
            payload = self._generate_init_payload(provider_id=provider['id'])
            payload['message']['order']['provider']['locations'] = [
                {"id": provider.get('location_id', 'store-location-001')}
            ]
            self._send_init_request(
                f"{self.step_name}_{provider['id']}",
                payload,
                expected_status=[200, 202]
            )

    # -------------------------------------------------------------------------
    # TC-012: Init API - Same Transaction ID, Different Message IDs (Retry)
    # -------------------------------------------------------------------------
    @task(1)
    def tc012_init_same_txn_different_msg_ids(self):
        """Send /init retries under the same transaction with distinct message IDs."""
        self.step_name = 'TC012_Init_Same_Txn_Diff_Msg'
        txn_id = f"txn-{uuid.uuid4().hex[:12]}"
        for i in range(3):
            payload = self._generate_init_payload(
                transaction_id=txn_id,
                message_id=f"msg-{uuid.uuid4().hex[:12]}"
            )
            self._send_init_request(
                f"{self.step_name}_Req_{i + 1}",
                payload,
                expected_status=[200, 202]
            )
            if i < 2:
                time.sleep(0.1)

    # -------------------------------------------------------------------------
    # TC-013: Init API - Unicode Characters in Buyer Name / Address
    # -------------------------------------------------------------------------
    @task(1)
    def tc013_init_unicode_buyer_info(self):
        """Send /init with multilingual buyer name and address in billing."""
        self.step_name = 'TC013_Init_Unicode'
        unicode_buyers = [
            {"name": "राम कुमार", "address": "१२३ परीक्षण सड़क, बेंगलुरु"},
            {"name": "ராம் குமார்", "address": "123 சோதனை தெரு, பெங்களூரு"},
            {"name": "ರಾಮ್ ಕುಮಾರ್", "address": "123 ಮೈಸೂರ್ ರಸ್ತೆ, ಬೆಂಗಳೂರು"},
        ]
        for i, buyer in enumerate(unicode_buyers):
            payload = self._generate_init_payload()
            payload['message']['order']['billing'].update({
                "name": buyer["name"],
                "address": buyer["address"]
            })
            self._send_init_request(
                f"{self.step_name}_{i}",
                payload,
                expected_status=[200, 202]
            )

    # -------------------------------------------------------------------------
    # TC-014: Init API - Collected By BAP
    # -------------------------------------------------------------------------
    @task(1)
    def tc014_init_collected_by_bap(self):
        """Send /init where payment is collected by BAP (buyer app)."""
        self.step_name = 'TC014_Init_Collected_BAP'
        payment = {"type": "PRE-ORDER", "status": "PAID", "collected_by": "BAP"}
        payload = self._generate_init_payload(payment_type=payment)
        self._send_init_request(self.step_name, payload)

    # -------------------------------------------------------------------------
    # TC-015: Init API - Collected By BPP
    # -------------------------------------------------------------------------
    @task(1)
    def tc015_init_collected_by_bpp(self):
        """Send /init where payment is to be collected by BPP (seller app)."""
        self.step_name = 'TC015_Init_Collected_BPP'
        payment = {"type": "ON-FULFILLMENT", "status": "NOT-PAID", "collected_by": "BPP"}
        payload = self._generate_init_payload(payment_type=payment)
        self._send_init_request(self.step_name, payload)

    # -------------------------------------------------------------------------
    # TC-016: Init API - High Item Quantity
    # -------------------------------------------------------------------------
    @task(1)
    def tc016_init_high_quantity(self):
        """Send /init with a high item quantity (bulk order)."""
        self.step_name = 'TC016_Init_High_Quantity'
        payload = self._generate_init_payload(item_quantity=100)
        self._send_init_request(self.step_name, payload)

    # -------------------------------------------------------------------------
    # TC-017: Init API - Concurrent Requests (Burst)
    # -------------------------------------------------------------------------
    @task(1)
    def tc017_init_concurrent_requests(self):
        """Fire multiple independent /init requests in quick succession."""
        self.step_name = 'TC017_Init_Concurrent'
        for i in range(5):
            payload = self._generate_init_payload()
            self._send_init_request(
                f"{self.step_name}_Req_{i + 1}",
                payload,
                expected_status=[200, 202]
            )
            if i < 4:
                time.sleep(0.05)

    # -------------------------------------------------------------------------
    # TC-018: Health Check
    # -------------------------------------------------------------------------
    @task(1)
    def tc018_health_check(self):
        """Verify Gateway health endpoint is reachable."""
        self.step_name = 'TC018_Health_Check'
        with self.client.get(
            name=self.step_name,
            url="/health",
            catch_response=True
        ) as response:
            if response.status_code != 200:
                response.failure(f"TC-018 Failed: Expected 200, got {response.status_code}")
                return
            response.success()

    # -------------------------------------------------------------------------
    # TC-019: Metrics Endpoint Accessible
    # -------------------------------------------------------------------------
    @task(1)
    def tc019_metrics_endpoint(self):
        """Verify Gateway metrics endpoint is reachable."""
        self.step_name = 'TC019_Metrics'
        with self.client.get(
            name=self.step_name,
            url="/metrics",
            catch_response=True
        ) as response:
            if response.status_code != 200:
                response.failure(f"TC-019 Failed: Expected 200, got {response.status_code}")
                return
            response.success()

    # -------------------------------------------------------------------------
    # TC-020: on_init Callback - Valid BPP Acknowledgement
    # -------------------------------------------------------------------------
    @task(1)
    def tc020_on_init_valid_callback(self):
        """Simulate BPP sending a valid /on_init callback to the Gateway."""
        self.step_name = 'TC020_On_Init_Valid_Callback'
        payload = self._generate_on_init_payload()
        self._send_on_init_request(self.step_name, payload)

    # -------------------------------------------------------------------------
    # TC-021: on_init Callback - Full Quote with All Breakup Items
    # -------------------------------------------------------------------------
    @task(1)
    def tc021_on_init_full_quote(self):
        """Send /on_init with all 5 quote breakup items: BASE_FARE, DISTANCE_FARE,
        TAX, DISCOUNT, WAITING_CHARGE."""
        self.step_name = 'TC021_On_Init_Full_Quote'
        payload = self._generate_on_init_payload()
        payload['message']['order']['quote'] = {
            "price": {"currency": "INR", "value": "600.00"},
            "breakup": [
                {"title": "BASE_FARE", "price": {"currency": "INR", "value": "350.00"}},
                {"title": "DISTANCE_FARE", "price": {"currency": "INR", "value": "100.00"}},
                {"title": "TAX", "price": {"currency": "INR", "value": "90.00"}},
                {"title": "DISCOUNT", "price": {"currency": "INR", "value": "-20.00"}},
                {"title": "WAITING_CHARGE", "price": {"currency": "INR", "value": "80.00"}}
            ]
        }
        self._send_on_init_request(self.step_name, payload)

    # -------------------------------------------------------------------------
    # TC-022: on_init Callback - All Cancellation Term States
    # -------------------------------------------------------------------------
    @task(1)
    def tc022_on_init_all_cancellation_states(self):
        """Send /on_init with all 4 valid cancellation fulfillment states:
        RIDE_ASSIGNED, RIDE_ENROUTE_PICKUP, RIDE_ARRIVED_PICKUP, RIDE_STARTED."""
        self.step_name = 'TC022_On_Init_Cancellation_States'
        payload = self._generate_on_init_payload()
        payload['message']['order']['cancellation_terms'] = [
            {
                "fulfillment_state": {"descriptor": {"code": "RIDE_ASSIGNED"}},
                "cancellation_fee": {"amount": {"currency": "INR", "value": "0.00"}}
            },
            {
                "fulfillment_state": {"descriptor": {"code": "RIDE_ENROUTE_PICKUP"}},
                "cancellation_fee": {"amount": {"currency": "INR", "value": "50.00"}}
            },
            {
                "fulfillment_state": {"descriptor": {"code": "RIDE_ARRIVED_PICKUP"}},
                "cancellation_fee": {"amount": {"currency": "INR", "value": "100.00"}}
            },
            {
                "fulfillment_state": {"descriptor": {"code": "RIDE_STARTED"}},
                "cancellation_fee": {"percentage": "20"}
            }
        ]
        self._send_on_init_request(self.step_name, payload)

    # -------------------------------------------------------------------------
    # TC-023: on_init Callback - Linked Transaction (Linked Init → on_init)
    # -------------------------------------------------------------------------
    @task(1)
    def tc023_on_init_linked_transaction(self):
        """Send /init first to obtain a transaction_id, then send /on_init
        sharing the same transaction_id (simulates real BAP→BPP→BAP flow)."""
        self.step_name = 'TC023_On_Init_Linked_Txn'

        # Step 1: Send /init to establish transaction
        init_payload = self._generate_init_payload()
        txn_id = init_payload['context']['transaction_id']
        self._send_init_request(
            f"{self.step_name}_Setup_LinkedInit",
            init_payload,
            expected_status=[200, 202]
        )

        # Step 2: Send /on_init with the same transaction_id but new message_id
        on_init_payload = self._generate_on_init_payload(
            transaction_id=txn_id,
            message_id=f"msg-{uuid.uuid4().hex[:12]}"
        )
        self._send_on_init_request(self.step_name, on_init_payload)

    # -------------------------------------------------------------------------
    # TC-024: on_init Callback - Multiple Items with fulfillment_ids/location_ids
    # -------------------------------------------------------------------------
    @task(1)
    def tc024_on_init_multiple_items_with_ids(self):
        """Send /on_init with multiple items each having fulfillment_ids and location_ids."""
        self.step_name = 'TC024_On_Init_Multi_Items'
        payload = self._generate_on_init_payload()
        payload['message']['order']['items'] = [
            {
                "id": "item-001",
                "quantity": {"count": 2},
                "fulfillment_ids": ["F1"],
                "location_ids": ["L1"]
            },
            {
                "id": "item-002",
                "quantity": {"count": 1},
                "fulfillment_ids": ["F1"],
                "location_ids": ["L1"]
            }
        ]
        self._send_on_init_request(self.step_name, payload)


tasks = [ONDCGatewayInitFunctional]
