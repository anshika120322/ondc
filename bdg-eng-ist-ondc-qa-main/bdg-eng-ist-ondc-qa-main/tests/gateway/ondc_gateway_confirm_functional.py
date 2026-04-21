import json
import time
import uuid
from datetime import datetime, timezone
from locust import task, between
from tests.gateway.gateway_confirm_base import GatewayConfirmBase

"""
ONDC Gateway Confirm API - Functional Tests (Positive / Happy-Path Scenarios)
All tests use @task(1) for equal distribution during functional validation.
Run with low user count: --users 1 --iterations 5
"""


class ONDCGatewayConfirmFunctional(GatewayConfirmBase):
    """Positive test scenarios for /confirm functional validation"""

    wait_time = between(1, 3)

    config_file = 'resources/gateway/ondc_gateway_confirm_functional.yml'
    tenant_name = 'ondcGW'

    # -------------------------------------------------------------------------
    # TC-001: Confirm API - Valid Request with Authentication
    # -------------------------------------------------------------------------
    @task(1)
    def tc001_confirm_valid_authenticated(self):
        """Submit a fully-valid confirm order payload with proper ONDC auth."""
        self.step_name = 'TC001_Confirm_Valid_Auth'
        payload = self._generate_confirm_payload()
        success, data, status = self._send_confirm_request(self.step_name, payload)
        if success and data:
            pass  # ACK validation can be extended here

    # -------------------------------------------------------------------------
    # TC-002: Confirm API - Different ONDC Domains
    # -------------------------------------------------------------------------
    @task(1)
    def tc002_confirm_different_domains(self):
        """Confirm order across each configured ONDC domain."""
        self.step_name = 'TC002_Confirm_Different_Domains'
        for domain in self.confirm_domains:
            payload = self._generate_confirm_payload(domain=domain)
            self._send_confirm_request(
                f"{self.step_name}_{domain}",
                payload,
                expected_status=[200, 202]
            )

    # -------------------------------------------------------------------------
    # TC-003: Confirm API - Different Cities
    # -------------------------------------------------------------------------
    @task(1)
    def tc003_confirm_different_cities(self):
        """Confirm order for each configured delivery city."""
        self.step_name = 'TC003_Confirm_Different_Cities'
        for city in self.cities:
            payload = self._generate_confirm_payload(city=city)
            self._send_confirm_request(
                f"{self.step_name}_{city}",
                payload,
                expected_status=[200, 202]
            )

    # -------------------------------------------------------------------------
    # TC-004: Confirm API - Different Payment Types
    # -------------------------------------------------------------------------
    @task(1)
    def tc004_confirm_payment_types(self):
        """Send confirm for each configured payment type (PRE/ON/POST-FULFILLMENT)."""
        self.step_name = 'TC004_Confirm_Payment_Types'
        payment_types = self.payment_types or [
            {"type": "ON-ORDER", "status": "PAID", "collected_by": "BAP"},
            {"type": "PRE-FULFILLMENT", "status": "PAID", "collected_by": "BAP"},
            {"type": "ON-FULFILLMENT", "status": "NOT-PAID", "collected_by": "BPP"},
            {"type": "POST-FULFILLMENT", "status": "NOT-PAID", "collected_by": "BPP"},
        ]
        for payment in payment_types:
            payload = self._generate_confirm_payload(payment_type=payment)
            self._send_confirm_request(
                f"{self.step_name}_{payment.get('type')}",
                payload,
                expected_status=[200, 202]
            )

    # -------------------------------------------------------------------------
    # TC-005: Confirm API - Different Fulfillment Types
    # -------------------------------------------------------------------------
    @task(1)
    def tc005_confirm_fulfillment_types(self):
        """Confirm order with Delivery and Pickup fulfillment types."""
        self.step_name = 'TC005_Confirm_Fulfillment_Types'
        fulfillment_types = self.fulfillment_types or ["Delivery", "Pickup", "Self-Pickup"]
        for ftype in fulfillment_types:
            payload = self._generate_confirm_payload(fulfillment_type=ftype)
            self._send_confirm_request(
                f"{self.step_name}_{ftype}",
                payload,
                expected_status=[200, 202]
            )

    # -------------------------------------------------------------------------
    # TC-006: Confirm API - Multiple Items in Order
    # -------------------------------------------------------------------------
    @task(1)
    def tc006_confirm_multiple_items(self):
        """Confirm an order that contains multiple line items."""
        self.step_name = 'TC006_Confirm_Multiple_Items'
        payload = self._generate_confirm_payload()
        payload['message']['order']['items'] = [
            {"id": "item-001", "quantity": {"count": 2}},
            {"id": "item-002", "quantity": {"count": 1}},
            {"id": "item-003", "quantity": {"count": 3}},
        ]
        payload['message']['order']['quote']['breakup'].extend([
            {
                "@ondc/org/item_id": "item-002",
                "@ondc/org/title_type": "item",
                "title": "Test Item 2",
                "price": {"currency": "INR", "value": "200.00"}
            },
            {
                "@ondc/org/item_id": "item-003",
                "@ondc/org/title_type": "item",
                "title": "Test Item 3",
                "price": {"currency": "INR", "value": "150.00"}
            }
        ])
        self._send_confirm_request(self.step_name, payload, expected_status=[200, 202])

    # -------------------------------------------------------------------------
    # TC-007: Confirm API - Minimal Required Fields Only
    # -------------------------------------------------------------------------
    @task(1)
    def tc007_confirm_minimal_payload(self):
        """Confirm order with only the minimum required ONDC fields present."""
        self.step_name = 'TC007_Confirm_Minimal'
        txn_id = f"txn-{uuid.uuid4().hex[:12]}"
        msg_id = f"msg-{uuid.uuid4().hex[:12]}"
        order_id = f"order-{uuid.uuid4().hex[:8]}"

        payload = {
            "context": {
                "domain": self.confirm_domains[0] if self.confirm_domains else "ONDC:RET10",
                "action": "confirm",
                "country": "IND",
                "city": self.cities[0] if self.cities else "std:080",
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
                    "id": order_id,
                    "provider": {"id": "IGO_Seller_0001", "locations": [{"id": "store-location-001"}]},
                    "items": [{"id": "item-001", "quantity": {"count": 1}}],
                    "billing": {
                        "name": "Test Buyer",
                        "phone": "9876543210",
                        "address": "123 Test Street, Bangalore 560001"
                    },
                    "fulfillments": [
                        {
                            "id": "1",
                            "type": "Delivery",
                            "end": {
                                "contact": {"phone": "9876543210"},
                                "location": {"gps": "12.9492953,77.7019878"}
                            }
                        }
                    ],
                    "payment": {
                        "params": {"transaction_id": f"pay-{uuid.uuid4().hex[:8]}", "amount": "500.00", "currency": "INR"},
                        "status": "PAID",
                        "type": "ON-ORDER"
                    },
                    "quote": {
                        "price": {"currency": "INR", "value": "500.00"},
                        "breakup": [
                            {
                                "@ondc/org/item_id": "item-001",
                                "@ondc/org/title_type": "item",
                                "title": "Test Item",
                                "price": {"currency": "INR", "value": "450.00"}
                            },
                            {
                                "@ondc/org/item_id": "1",
                                "@ondc/org/title_type": "delivery",
                                "title": "Delivery Charges",
                                "price": {"currency": "INR", "value": "50.00"}
                            }
                        ]
                    }
                }
            }
        }
        self._send_confirm_request(self.step_name, payload, expected_status=[200, 202])

    # -------------------------------------------------------------------------
    # TC-008: Confirm API - Complete Payload (All Optional Fields)
    # -------------------------------------------------------------------------
    @task(1)
    def tc008_confirm_complete_payload(self):
        """Confirm order with all optional ONDC fields populated."""
        self.step_name = 'TC008_Confirm_Complete_Payload'
        payload = self._generate_confirm_payload()

        # Enrich billing with optional fields
        payload['message']['order']['billing'].update({
            "created_at": datetime.now(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z'),
            "updated_at": datetime.now(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z'),
            "tax_number": "GSTIN123456789",
            "org": {"name": "Test Buyer Org"}
        })

        # Enrich fulfillment with tracking and agent details
        payload['message']['order']['fulfillments'][0].update({
            "tracking": True,
            "agent": {"name": "Delivery Partner", "phone": "9999999999"},
            "start": {
                "location": {"gps": "12.9716,77.5946", "address": "Seller Warehouse, Bangalore"},
                "contact": {"phone": "8888888888"}
            }
        })

        # Add tags to payment
        payload['message']['order']['payment']['@ondc/org/settlement_details'] = [
            {
                "settlement_counterparty": "seller-app",
                "settlement_phase": "sale-amount",
                "settlement_type": "neft",
                "beneficiary_name": "Seller Account",
                "settlement_bank_account_no": "1234567890",
                "settlement_ifsc_code": "HDFC0001234",
                "bank_name": "HDFC Bank"
            }
        ]

        self._send_confirm_request(self.step_name, payload, expected_status=[200, 202])

    # -------------------------------------------------------------------------
    # TC-009: Confirm API - Large Order Amount
    # -------------------------------------------------------------------------
    @task(1)
    def tc009_confirm_large_order_amount(self):
        """Confirm order with a high-value amount (e.g. luxury goods)."""
        self.step_name = 'TC009_Confirm_Large_Amount'
        payload = self._generate_confirm_payload(order_amount="999999.99")
        payload['message']['order']['quote']['price']['value'] = "999999.99"
        payload['message']['order']['quote']['breakup'][0]['price']['value'] = "999949.99"
        payload['message']['order']['quote']['breakup'][1]['price']['value'] = "50.00"
        self._send_confirm_request(self.step_name, payload, expected_status=[200, 202])

    # -------------------------------------------------------------------------
    # TC-010: Confirm API - Zero Delivery Charge (Seller Offers Free Delivery)
    # -------------------------------------------------------------------------
    @task(1)
    def tc010_confirm_free_delivery(self):
        """Confirm order where delivery charge is zero (free delivery)."""
        self.step_name = 'TC010_Confirm_Free_Delivery'
        payload = self._generate_confirm_payload(order_amount="450.00")
        payload['message']['order']['quote']['breakup'] = [
            {
                "@ondc/org/item_id": "item-001",
                "@ondc/org/title_type": "item",
                "title": "Test Item",
                "price": {"currency": "INR", "value": "450.00"}
            },
            {
                "@ondc/org/item_id": "1",
                "@ondc/org/title_type": "delivery",
                "title": "Delivery Charges",
                "price": {"currency": "INR", "value": "0.00"}
            }
        ]
        self._send_confirm_request(self.step_name, payload, expected_status=[200, 202])

    # -------------------------------------------------------------------------
    # TC-011: Confirm API - Same Transaction ID, Different Message IDs
    # -------------------------------------------------------------------------
    @task(1)
    def tc011_confirm_same_txn_different_msg_ids(self):
        """Confirm re-sent under the same transaction with distinct message IDs (retry pattern)."""
        self.step_name = 'TC011_Confirm_Same_Txn_Diff_Msg'
        txn_id = f"txn-{uuid.uuid4().hex[:12]}"

        for i in range(3):
            payload = self._generate_confirm_payload(
                transaction_id=txn_id,
                message_id=f"msg-{uuid.uuid4().hex[:12]}"
            )
            self._send_confirm_request(
                f"{self.step_name}_Req_{i+1}",
                payload,
                expected_status=[200, 202]
            )
            if i < 2:
                time.sleep(0.1)

    # -------------------------------------------------------------------------
    # TC-012: Confirm API - High Item Quantity
    # -------------------------------------------------------------------------
    @task(1)
    def tc012_confirm_high_quantity(self):
        """Confirm order with a high item quantity (bulk order)."""
        self.step_name = 'TC012_Confirm_High_Quantity'
        payload = self._generate_confirm_payload(item_quantity=100)
        self._send_confirm_request(self.step_name, payload, expected_status=[200, 202])

    # -------------------------------------------------------------------------
    # TC-013: Confirm API - Concurrent Requests (Burst)
    # -------------------------------------------------------------------------
    @task(1)
    def tc013_confirm_concurrent_requests(self):
        """Fire multiple independent confirm requests in quick succession."""
        self.step_name = 'TC013_Confirm_Concurrent'
        for i in range(5):
            payload = self._generate_confirm_payload()
            self._send_confirm_request(
                f"{self.step_name}_Req_{i+1}",
                payload,
                expected_status=[200, 202]
            )
            if i < 4:
                time.sleep(0.05)

    # -------------------------------------------------------------------------
    # TC-014: Confirm API - Unicode Characters in Buyer Name / Address
    # -------------------------------------------------------------------------
    @task(1)
    def tc014_confirm_unicode_buyer_info(self):
        """Confirm order with multilingual buyer name and address."""
        self.step_name = 'TC014_Confirm_Unicode'
        unicode_buyers = [
            {"name": "राम कुमार", "address": "१२३ परीक्षण सड़क, बेंगलुरु"},
            {"name": "ராம் குமார்", "address": "123 சோதனை தெரு, பெங்களூரு"},
            {"name": "ರಾಮ್ ಕುಮಾರ್", "address": "123 ಮೈಸೂರ್ ರಸ್ತೆ, ಬೆಂಗಳೂರು"},
        ]
        for buyer in unicode_buyers:
            payload = self._generate_confirm_payload()
            payload['message']['order']['billing'].update({
                "name": buyer["name"],
                "address": buyer["address"]
            })
            self._send_confirm_request(
                f"{self.step_name}_{unicode_buyers.index(buyer)}",
                payload,
                expected_status=[200, 202]
            )

    # -------------------------------------------------------------------------
    # TC-015: Confirm API - Different Providers
    # -------------------------------------------------------------------------
    @task(1)
    def tc015_confirm_different_providers(self):
        """Confirm order against each configured test provider."""
        self.step_name = 'TC015_Confirm_Different_Providers'
        providers = self.test_providers or [
            {"id": "IGO_Seller_0001", "location_id": "store-location-001"},
            {"id": "IGO_Seller_0002", "location_id": "store-location-002"},
        ]
        for provider in providers:
            payload = self._generate_confirm_payload(provider_id=provider['id'])
            payload['message']['order']['provider']['locations'] = [{"id": provider.get('location_id', 'store-location-001')}]
            self._send_confirm_request(
                f"{self.step_name}_{provider['id']}",
                payload,
                expected_status=[200, 202]
            )

    # -------------------------------------------------------------------------
    # TC-016: Confirm API - Payment Status NOT-PAID (COD / Pay on Delivery)
    # -------------------------------------------------------------------------
    @task(1)
    def tc016_confirm_payment_not_paid(self):
        """Confirm order where payment has NOT-PAID status (cash-on-delivery flow)."""
        self.step_name = 'TC016_Confirm_Not_Paid'
        cod_payment = {"type": "ON-FULFILLMENT", "status": "NOT-PAID", "collected_by": "BPP"}
        payload = self._generate_confirm_payload(payment_type=cod_payment)
        self._send_confirm_request(self.step_name, payload, expected_status=[200, 202])

    # -------------------------------------------------------------------------
    # TC-017: Confirm API - Health Check
    # -------------------------------------------------------------------------
    @task(1)
    def tc017_health_check(self):
        """Verify Gateway health endpoint is reachable."""
        self.step_name = 'TC017_Health_Check'
        with self.client.get(
            name=self.step_name,
            url="/health",
            catch_response=True
        ) as response:
            if response.status_code != 200:
                response.failure(f"TC-017 Failed: Expected 200, got {response.status_code}")
                return
            response.success()

    # -------------------------------------------------------------------------
    # TC-018: Confirm API - Metrics Endpoint Accessible
    # -------------------------------------------------------------------------
    @task(1)
    def tc018_metrics_endpoint(self):
        """Verify Gateway metrics endpoint is reachable."""
        self.step_name = 'TC018_Metrics'
        with self.client.get(
            name=self.step_name,
            url="/metrics",
            catch_response=True
        ) as response:
            if response.status_code != 200:
                response.failure(f"TC-018 Failed: Expected 200, got {response.status_code}")
                return
            response.success()

    # -------------------------------------------------------------------------
    # TC-019: on_confirm Callback - Valid Seller Acknowledgement
    # -------------------------------------------------------------------------
    @task(1)
    def tc019_on_confirm_valid_callback(self):
        """Simulate BPP sending a valid on_confirm callback to the Gateway."""
        self.step_name = 'TC019_On_Confirm_Valid_Callback'
        payload = self._generate_on_confirm_payload(order_status="Accepted")
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
            if response.status_code not in [200, 202]:
                response.failure(f"TC-019 Failed: Expected 200/202, got {response.status_code}")
                return
            response.success()

    # -------------------------------------------------------------------------
    # TC-020: on_confirm Callback - Order Created State
    # -------------------------------------------------------------------------
    @task(1)
    def tc020_on_confirm_order_created(self):
        """Simulate BPP sending on_confirm with 'Created' order state."""
        self.step_name = 'TC020_On_Confirm_Created'
        payload = self._generate_on_confirm_payload(order_status="Created")
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
            if response.status_code not in [200, 202]:
                response.failure(f"TC-020 Failed: Expected 200/202, got {response.status_code}")
                return
            response.success()

    # -------------------------------------------------------------------------
    # TC-021: E2E - Confirm → On_confirm Linked Transaction Flow (TC-E2E-002)
    # Step 1: BAP sends /confirm to register a transaction with the Gateway.
    # Step 2: BPP sends /on_confirm with the same transaction_id.
    # Both steps must return 200/202 ACK.
    # -------------------------------------------------------------------------
    @task(1)
    def tc021_on_confirm_e2e_linked_flow(self):
        """TC-E2E-002: Full confirm → on_confirm E2E flow linked by transaction_id."""
        self.step_name = 'TC021_E2E_Confirm_OnConfirm'

        # Step 1: BAP sends /confirm
        confirm_payload = self._generate_confirm_payload()
        txn_id = confirm_payload['context']['transaction_id']
        success, _, status = self._send_confirm_request(
            f"{self.step_name}_Step1_Confirm",
            confirm_payload,
            expected_status=[200, 202]
        )
        if not success:
            import logging
            logging.getLogger(__name__).warning(
                f"TC021 Step 1 (confirm) did not succeed (status={status}); skipping on_confirm."
            )
            return

        # Step 2: BPP sends /on_confirm with the same transaction_id
        on_confirm_payload = self._generate_on_confirm_payload(
            transaction_id=txn_id,
            order_status="Accepted"
        )
        headers = self.auth_helper.generate_headers(on_confirm_payload)
        serialized_body = headers.pop('serialized_body', None) or json.dumps(
            on_confirm_payload, separators=(',', ':'), sort_keys=False, ensure_ascii=False
        )
        with self.client.post(
            name=f"{self.step_name}_Step2_OnConfirm",
            url="/on_confirm",
            data=serialized_body.encode('utf-8'),
            headers={**headers, "Content-Type": "application/json; charset=utf-8"},
            catch_response=True
        ) as response:
            if response.status_code not in [200, 202]:
                response.failure(
                    f"TC021 Step 2 (on_confirm) Failed: Expected 200/202, got {response.status_code}"
                )
                return
            response.success()


tasks = [ONDCGatewayConfirmFunctional]
