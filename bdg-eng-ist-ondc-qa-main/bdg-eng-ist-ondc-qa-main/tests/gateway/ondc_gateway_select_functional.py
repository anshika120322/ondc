import json
import uuid
from datetime import datetime, timezone
from locust import task, between
from tests.gateway.gateway_select_base import GatewaySelectBase

"""
ONDC Gateway Select API - Functional Tests (Positive / Happy-Path Scenarios)
All tests use @task(1) for equal distribution during functional validation.
Run with low user count: --users 1 --iterations 5

/select sits between /search and /init in the ONDC order flow:
  search → on_search → SELECT → on_select → init → on_init → confirm → on_confirm

Key schema rules for /select:
  - bpp_id and bpp_uri are REQUIRED in context (routing the request to BPP)
  - message.order.provider: id + locations[].id
  - message.order.items: id + quantity.count
  - message.order.fulfillments: end.location.gps (delivery destination)
  - NO billing, payment, or quote at this stage

Key schema rules for /on_select:
  - message.order.provider.id
  - message.order.items: id + quantity
  - message.order.quote: price (total) + breakup array + ttl
  - message.order.fulfillments: type + tracking flag
"""


class ONDCGatewaySelectFunctional(GatewaySelectBase):
    """Positive test scenarios for /select and /on_select functional validation"""

    wait_time = between(1, 3)

    config_file = 'resources/gateway/ondc_gateway_select_functional.yml'
    tenant_name = 'ondcGW'

    # -------------------------------------------------------------------------
    # TC-001: Select API - Valid Request with Authentication
    # -------------------------------------------------------------------------
    @task(1)
    def tc001_select_valid_authenticated(self):
        """Submit a fully-valid /select payload with proper ONDC auth."""
        self.step_name = 'TC001_Select_Valid_Auth'
        payload = self._generate_select_payload()
        self._send_select_request(self.step_name, payload)

    # -------------------------------------------------------------------------
    # TC-002: Select API - Different ONDC Domains
    # -------------------------------------------------------------------------
    @task(1)
    def tc002_select_different_domains(self):
        """Send /select across each configured ONDC domain."""
        self.step_name = 'TC002_Select_Different_Domains'
        for domain in self.select_domains:
            payload = self._generate_select_payload(domain=domain)
            self._send_select_request(
                f"{self.step_name}_{domain}",
                payload,
                expected_status=[200, 202]
            )

    # -------------------------------------------------------------------------
    # TC-003: Select API - Different Cities
    # -------------------------------------------------------------------------
    @task(1)
    def tc003_select_different_cities(self):
        """Send /select for each configured delivery city."""
        self.step_name = 'TC003_Select_Different_Cities'
        for city in self.cities:
            payload = self._generate_select_payload(city=city)
            self._send_select_request(
                f"{self.step_name}_{city}",
                payload,
                expected_status=[200, 202]
            )

    # -------------------------------------------------------------------------
    # TC-004: Select API - Multiple Items (Cart)
    # -------------------------------------------------------------------------
    @task(1)
    def tc004_select_multiple_items(self):
        """Send /select with multiple items in the cart."""
        self.step_name = 'TC004_Select_Multiple_Items'
        items = [
            {"id": "item-001", "quantity": {"count": 2}},
            {"id": "item-002", "quantity": {"count": 1}},
            {"id": "item-003", "quantity": {"count": 3}},
        ]
        payload = self._generate_select_payload(items=items)
        self._send_select_request(self.step_name, payload)

    # -------------------------------------------------------------------------
    # TC-005: Select API - Different Providers
    # -------------------------------------------------------------------------
    @task(1)
    def tc005_select_different_providers(self):
        """Send /select for each configured provider."""
        self.step_name = 'TC005_Select_Different_Providers'
        for provider in self.test_providers:
            payload = self._generate_select_payload(provider_id=provider.get('id'))
            self._send_select_request(
                f"{self.step_name}_{provider.get('id')}",
                payload,
                expected_status=[200, 202]
            )

    # -------------------------------------------------------------------------
    # TC-006: Select API - Different Delivery Locations
    # -------------------------------------------------------------------------
    @task(1)
    def tc006_select_different_locations(self):
        """Send /select with delivery GPS from each configured location."""
        self.step_name = 'TC006_Select_Different_Locations'
        for location in self.test_locations:
            gps = location.get('gps')
            city = location.get('city', 'std:080')
            payload = self._generate_select_payload(city=city, delivery_gps=gps)
            self._send_select_request(
                f"{self.step_name}_{city}",
                payload,
                expected_status=[200, 202]
            )

    # -------------------------------------------------------------------------
    # TC-007: Select API - Single Item, Quantity 1
    # -------------------------------------------------------------------------
    @task(1)
    def tc007_select_single_item_qty1(self):
        """Send /select with a single item, quantity 1 (simplest valid cart)."""
        self.step_name = 'TC007_Select_Single_Item_Qty1'
        payload = self._generate_select_payload(item_quantity=1)
        self._send_select_request(self.step_name, payload)

    # -------------------------------------------------------------------------
    # TC-008: Select API - High Quantity
    # -------------------------------------------------------------------------
    @task(1)
    def tc008_select_high_quantity(self):
        """Send /select with a high item quantity (bulk order)."""
        self.step_name = 'TC008_Select_High_Quantity'
        payload = self._generate_select_payload(item_quantity=50)
        self._send_select_request(self.step_name, payload)

    # -------------------------------------------------------------------------
    # TC-009: Select API - Minimal Required Fields Only
    # -------------------------------------------------------------------------
    @task(1)
    def tc009_select_minimal_payload(self):
        """Send /select with only the minimum required ONDC fields."""
        self.step_name = 'TC009_Select_Minimal_Payload'
        txn_id = f"txn-{uuid.uuid4().hex[:12]}"
        msg_id = f"msg-{uuid.uuid4().hex[:12]}"
        payload = {
            "context": {
                "domain": "ONDC:RET10",
                "action": "select",
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
                    "fulfillments": [
                        {"id": "F1", "end": {"location": {"gps": "12.9492953,77.7019878"}}}
                    ]
                }
            }
        }
        self._send_select_request(self.step_name, payload)

    # -------------------------------------------------------------------------
    # TC-010: Select API - Different Fulfillment Types
    # -------------------------------------------------------------------------
    @task(1)
    def tc010_select_fulfillment_types(self):
        """Send /select with Delivery, Pickup, and Self-Pickup fulfillment types."""
        self.step_name = 'TC010_Select_Fulfillment_Types'
        fulfillment_types = self.fulfillment_types or ["Delivery", "Pickup", "Self-Pickup"]
        for ftype in fulfillment_types:
            payload = self._generate_select_payload(fulfillment_type=ftype)
            self._send_select_request(
                f"{self.step_name}_{ftype}",
                payload,
                expected_status=[200, 202]
            )

    # -------------------------------------------------------------------------
    # TC-011: Select API - Linked to Previous Search (Shared Transaction ID)
    # -------------------------------------------------------------------------
    @task(1)
    def tc011_select_shared_transaction_id(self):
        """Send two calls sharing a transaction_id — models search→select flow."""
        self.step_name = 'TC011_Select_Shared_TxnID'
        txn_id = f"txn-{uuid.uuid4().hex[:12]}"
        # First call simulates selecting the first item from search results
        payload_a = self._generate_select_payload(
            transaction_id=txn_id,
            item_id="item-001"
        )
        self._send_select_request(f"{self.step_name}_A", payload_a, expected_status=[200, 202])

        # Second call in the same transaction selects a different item
        payload_b = self._generate_select_payload(
            transaction_id=txn_id,
            item_id="item-002"
        )
        self._send_select_request(f"{self.step_name}_B", payload_b, expected_status=[200, 202])

    # -------------------------------------------------------------------------
    # TC-012: Select API - Items from Multiple Categories
    # -------------------------------------------------------------------------
    @task(1)
    def tc012_select_multi_category_items(self):
        """Send /select with items spanning multiple product categories."""
        self.step_name = 'TC012_Select_Multi_Category'
        # Mix grocery + health items
        items = [
            {"id": "item-001", "quantity": {"count": 1}},   # Grocery
            {"id": "item-003", "quantity": {"count": 2}},   # Health
        ]
        payload = self._generate_select_payload(items=items)
        self._send_select_request(self.step_name, payload)

    # -------------------------------------------------------------------------
    # TC-013: on_select API - Valid Callback with Quote
    # -------------------------------------------------------------------------
    @task(1)
    def tc013_on_select_valid_quote(self):
        """Send a fully-valid /on_select callback with a well-formed quote."""
        self.step_name = 'TC013_OnSelect_Valid_Quote'
        payload = self._generate_on_select_payload()
        self._send_on_select_request(self.step_name, payload)

    # -------------------------------------------------------------------------
    # TC-014: on_select API - Multi-Item Quote Breakup
    # -------------------------------------------------------------------------
    @task(1)
    def tc014_on_select_multi_item_quote(self):
        """Send /on_select with a quote breakup covering multiple items."""
        self.step_name = 'TC014_OnSelect_Multi_Item_Quote'
        txn_id = f"txn-{uuid.uuid4().hex[:12]}"
        msg_id = f"msg-{uuid.uuid4().hex[:12]}"

        provider_id = self.test_providers[0].get('id') if self.test_providers else 'IGO_Seller_0001'
        items = self.test_items[:2] if len(self.test_items) >= 2 else self.test_items

        breakup = []
        total = 0.0
        for item in items:
            item_id = item.get('id', 'item-001')
            item_name = item.get('name', 'Test Item')
            item_price_str = item.get('price', '450.00')
            item_price = float(item_price_str)
            total += item_price
            breakup.append({
                "@ondc/org/item_id": item_id,
                "@ondc/org/item_quantity": {"count": 1},
                "title": item_name,
                "@ondc/org/title_type": "item",
                "price": {"currency": "INR", "value": item_price_str},
                "item": {"price": {"currency": "INR", "value": item_price_str}}
            })

        # Add delivery charge
        delivery = 50.00
        total += delivery
        if items:
            breakup.append({
                "@ondc/org/item_id": items[0].get('id', 'item-001'),
                "title": "Delivery charges",
                "@ondc/org/title_type": "delivery",
                "price": {"currency": "INR", "value": "50.00"}
            })

        import random
        payload = {
            "context": {
                "domain": random.choice(self.select_domains) if self.select_domains else "ONDC:RET10",
                "action": "on_select",
                "country": "IND",
                "city": random.choice(self.cities) if self.cities else "std:080",
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
                    "provider": {"id": provider_id},
                    "items": [{"id": item.get('id', 'item-001'), "quantity": {"count": 1}} for item in items],
                    "quote": {
                        "price": {"currency": "INR", "value": f"{total:.2f}"},
                        "breakup": breakup,
                        "ttl": "P1D"
                    },
                    "fulfillments": [{"id": "F1", "type": "Delivery", "tracking": False}]
                }
            }
        }
        self._send_on_select_request(self.step_name, payload)

    # -------------------------------------------------------------------------
    # TC-015: on_select API - Different Providers
    # -------------------------------------------------------------------------
    @task(1)
    def tc015_on_select_different_providers(self):
        """Send /on_select from each configured provider."""
        self.step_name = 'TC015_OnSelect_Different_Providers'
        for provider in self.test_providers:
            txn_id = f"txn-{uuid.uuid4().hex[:12]}"
            msg_id = f"msg-{uuid.uuid4().hex[:12]}"

            item = self.test_items[0] if self.test_items else {"id": "item-001", "name": "Test Item", "price": "450.00"}

            import random
            payload = {
                "context": {
                    "domain": random.choice(self.select_domains) if self.select_domains else "ONDC:RET10",
                    "action": "on_select",
                    "country": "IND",
                    "city": random.choice(self.cities) if self.cities else "std:080",
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
                        "provider": {"id": provider.get('id', 'IGO_Seller_0001')},
                        "items": [{"id": item.get('id', 'item-001'), "quantity": {"count": 1}}],
                        "quote": {
                            "price": {"currency": "INR", "value": "500.00"},
                            "breakup": [
                                {
                                    "@ondc/org/item_id": item.get('id', 'item-001'),
                                    "@ondc/org/item_quantity": {"count": 1},
                                    "title": item.get('name', 'Test Item'),
                                    "@ondc/org/title_type": "item",
                                    "price": {"currency": "INR", "value": item.get('price', '450.00')},
                                    "item": {"price": {"currency": "INR", "value": item.get('price', '450.00')}}
                                },
                                {
                                    "@ondc/org/item_id": item.get('id', 'item-001'),
                                    "title": "Delivery charges",
                                    "@ondc/org/title_type": "delivery",
                                    "price": {"currency": "INR", "value": "50.00"}
                                }
                            ],
                            "ttl": "P1D"
                        },
                        "fulfillments": [{"id": "F1", "type": "Delivery", "tracking": False}]
                    }
                }
            }
            self._send_on_select_request(
                f"{self.step_name}_{provider.get('id')}",
                payload,
                expected_status=[200, 202]
            )


tasks = [ONDCGatewaySelectFunctional]
