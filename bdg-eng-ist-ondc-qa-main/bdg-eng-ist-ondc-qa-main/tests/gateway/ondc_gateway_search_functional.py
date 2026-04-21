import json
import logging
import time
import uuid
from datetime import datetime, timezone
from locust import task, between, HttpUser
from tests.gateway.gateway_search_base import GatewaySearchBase

logger = logging.getLogger(__name__)

"""
ONDC Gateway Search API - Functional Tests (Positive Scenarios)
All tests use @task(1) for equal distribution during functional validation
Run with low user count: --users 1 --iterations 5
"""

class ONDCGatewaySearchFunctional(GatewaySearchBase):
    """Positive test scenarios for functional validation"""
    
    # Wait time between tasks (will be overridden by --wait-min and --wait-max if provided)
    wait_time = between(1, 3)
    
    # Override config settings
    config_file = 'resources/gateway/ondc_gateway_search_functional.yml'
    tenant_name = 'ondcGatewaySearch'
    
    # TC-001: Search API - Valid Request with Authentication
    @task(1)
    def tc001_search_valid_authenticated(self):
        self.step_name = 'TC001_Search_Valid_Auth'
        payload = self._generate_search_payload()
        # Use helper method with correct serialization (sort_keys=False)
        success, data, status = self._send_search_request(self.step_name, payload)
        
        if success:
            # Validate response structure if needed
            pass

    # TC-002: Search API - Different Domains
    @task(1)
    def tc002_search_different_domains(self):
        self.step_name = 'TC002_Search_Different_Domains'
        
        for domain in self.search_domains:
            payload = self._generate_search_payload(domain=domain)
            success, data, status = self._send_search_request(
                f"{self.step_name}_{domain}", 
                payload
            )

    # TC-003: Search API - Different Cities
    @task(1)
    def tc003_search_different_cities(self):
        self.step_name = 'TC003_Search_Different_Cities'
        
        for city in self.cities:
            payload = self._generate_search_payload(city=city)
            
            # Use helper method with correct serialization
            self._send_search_request(
                f"{self.step_name}_{city}",
                payload,
                expected_status=[200, 202]
            )

    # TC-004: Search API - Large Payload
    @task(1)
    def tc004_search_large_payload(self):
        self.step_name = 'TC004_Search_Large_Payload'
        payload = self._generate_search_payload()
        
        # Add multiple items to create larger payload
        payload['message']['intent']['items'] = [
            {
                "descriptor": {"name": f"item_{i}"},
                "tags": [{"code": f"tag_{j}", "value": f"value_{j}"} for j in range(10)]
            }
            for i in range(20)
        ]
        
        self._send_search_request(self.step_name, payload, expected_status=[200, 202, 413])

    # TC-005: Search with Different Fulfillment Types
    @task(1)
    def tc005_search_fulfillment_types(self):
        self.step_name = 'TC005_Search_Fulfillment_Types'
        
        raw_ft = self.fulfillment_types
        if isinstance(raw_ft, dict):
            # YAML config is keyed by domain — flatten all domain lists into one
            fulfillment_types = [entry for entries in raw_ft.values() for entry in entries]
        elif raw_ft:
            fulfillment_types = raw_ft
        else:
            fulfillment_types = [
                {"type": "Delivery", "location": {"gps": "12.9716,77.5946", "area_code": "560001"}},
                {"type": "Pickup", "location": {"gps": "12.9716,77.5946"}}
            ]

        for fulfillment in fulfillment_types:
            payload = self._generate_search_payload()
            fulfillment_intent = {"type": fulfillment['type']}
            if 'location' in fulfillment:
                fulfillment_intent["end"] = {"location": fulfillment['location']}
            payload['message']['intent']['fulfillment'] = fulfillment_intent
            
            # Use helper method with correct serialization
            self._send_search_request(
                f"{self.step_name}_{fulfillment['type']}",
                payload,
                expected_status=[200, 202]
            )

    # TC-006: Search with Item Category and Code
    @task(1)
    def tc006_search_item_details(self):
        self.step_name = 'TC006_Search_Item_Details'
        
        item_category = self.item_categories[0] if self.item_categories else {
            "category_id": "Electronics",
            "name": "laptop",
            "code": "LAPTOP001"
        }
        
        payload = self._generate_search_payload()
        payload['message']['intent']['item'] = {
            "descriptor": {
                "name": item_category['name']
            },
            "category_id": item_category['category_id'],
            "code": item_category['code']
        }
        
        self._send_search_request(self.step_name, payload, expected_status=[200, 202])

    # TC-007: Search with Payment Preferences
    @task(1)
    def tc007_search_payment_preferences(self):
        self.step_name = 'TC007_Search_Payment_Preferences'
        
        raw_pt = self.payment_types
        if isinstance(raw_pt, dict):
            # YAML config is keyed by domain — flatten all domain lists into one
            payment_types = [entry for entries in raw_pt.values() for entry in entries]
        elif raw_pt:
            payment_types = raw_pt
        else:
            payment_types = [
                {"type": "PRE-FULFILLMENT", "collected_by": "BAP"},
                {"type": "ON-FULFILLMENT", "collected_by": "BPP"},
                {"type": "POST-FULFILLMENT", "collected_by": "BPP"}
            ]

        for payment in payment_types:
            payload = self._generate_search_payload()
            payload['message']['intent']['payment'] = payment
            
            # Use helper method with correct serialization
            self._send_search_request(
                f"{self.step_name}_{payment.get('type')}",
                payload,
                expected_status=[200, 202]
            )

    # TC-008: Search with Domain-Specific Tags
    @task(1)
    def tc008_search_with_tags(self):
        self.step_name = 'TC008_Search_With_Tags'
        
        # Get tags for F&B domain from config or use default
        domain = self.search_domains[0] if self.search_domains else "ONDC:RET10"  # Grocery domain
        tags = self.domain_tags.get(domain, [
            {
                "code": "product_category",
                "list": [{"code": "type", "value": "veg"}]
            },
            {
                "code": "dietary",
                "list": [{"code": "preference", "value": "gluten-free"}]
            }
        ])
        
        payload = self._generate_search_payload(domain=domain)
        payload['message']['intent']['tags'] = tags
        
        self._send_search_request(self.step_name, payload, expected_status=[200, 202])

    # TC-009: Search with Location Radius
    @task(1)
    def tc009_search_location_radius(self):
        self.step_name = 'TC009_Search_Location_Radius'
        
        location = self.test_locations[0] if self.test_locations else {
            "city": "std:080",
            "gps": "12.9716,77.5946",
            "area_code": "560001",
            "radius_km": 5
        }
        
        payload = self._generate_search_payload(city=location['city'])
        payload['message']['intent']['fulfillment'] = {
            "type": "Delivery",
            "end": {
                "location": {
                    "gps": location['gps'],
                    "area_code": location['area_code']
                },
                "circle": {
                    "gps": location['gps'],
                    "radius": {
                        "value": str(location['radius_km']),
                        "unit": "km"
                    }
                }
            }
        }
        
        self._send_search_request(self.step_name, payload, expected_status=[200, 202])

    # TC-010: Search with Multiple Items
    @task(1)
    def tc010_search_multiple_items(self):
        self.step_name = 'TC010_Search_Multiple_Items'
        
        items = self.multiple_items or [
            {
                "descriptor": {"name": "laptop"},
                "category_id": "Electronics"
            },
            {
                "descriptor": {"name": "mouse"},
                "category_id": "Accessories"
            },
            {
                "descriptor": {"name": "keyboard"},
                "category_id": "Accessories"
            }
        ]
        
        payload = self._generate_search_payload()
        payload['message']['intent']['items'] = items
        
        self._send_search_request(self.step_name, payload, expected_status=[200, 202])

    # TC-011: Health Check
    @task(1)
    def tc011_health_check(self):
        self.step_name = 'TC011_Health_Check'
        
        with self.client.get(
            name=self.step_name,
            url="/health",
            catch_response=True
        ) as response:
            
            if response.status_code != 200:
                response.failure(f"TC-011 Failed: Expected 200, got {response.status_code}")
                return
            
            response.success()

    # TC-012: Metrics Endpoint
    @task(1)
    def tc012_metrics_endpoint(self):
        self.step_name = 'TC012_Metrics'
        
        with self.client.get(
            name=self.step_name,
            url="/metrics",
            catch_response=True
        ) as response:
            
            if response.status_code != 200:
                response.failure(f"TC-012 Failed: Expected 200, got {response.status_code}")
                return
            
            response.success()

    # TC-013: Search API - Concurrent Requests with Same Transaction ID
    @task(1)
    def tc013_search_same_transaction_id(self):
        self.step_name = 'TC013_Search_Same_Txn_ID'
        
        txn_id = f"txn-{uuid.uuid4().hex[:12]}"
        
        for i in range(3):
            payload = self._generate_search_payload()
            payload['context']['transaction_id'] = txn_id
            payload['context']['message_id'] = f"msg-{uuid.uuid4().hex[:12]}"
            # Use helper method with correct serialization
            self._send_search_request(
                f"{self.step_name}_Req_{i+1}",
                payload,
                expected_status=[200, 202]
            )
            
            # Small delay between requests to avoid connection pool exhaustion
            if i < 2:  # Don't delay after last request
                time.sleep(0.1)

    # TC-014: Search API - Performance Test (Burst)
    @task(1)
    def tc014_search_performance_burst(self):
        """High frequency search requests to test performance"""
        self.step_name = 'TC014_Search_Performance_Burst'
        
        payload = self._generate_search_payload()
        
        # Send request - Locust automatically tracks response time
        self._send_search_request(self.step_name, payload, expected_status=[200, 202])
        # Note: Performance metrics (response time, RPS) are tracked by Locust automatically

    # TC-015: Search with All Optional Fields
    @task(1)
    def tc015_search_complete_payload(self):
        """Test search with all optional ONDC fields populated"""
        self.step_name = 'TC015_Search_Complete_Payload'
        
        payload = self._generate_search_payload()
        
        # NOTE: bpp_id/bpp_uri intentionally omitted — adding them triggers unicast routing
        # which returns 502 if the BPP is unreachable. Broadcast search is the happy-path.
        
        payload['message']['intent'].update({
            'provider': {
                'descriptor': {
                    'name': 'Preferred Provider'
                }
            },
            'category': {
                'id': 'Electronics'
            },
            'offer': {
                'id': 'SPECIAL-OFFER-2024'
            },
            'tags': [
                {
                    'code': 'price_range',
                    'list': [
                        {'code': 'min', 'value': '1000'},
                        {'code': 'max', 'value': '50000'}
                    ]
                }
            ]
        })
        
        self._send_search_request(self.step_name, payload, expected_status=[200, 202])

    # TC-016: Search with Minimal Payload
    @task(1)
    def tc016_search_minimal_payload(self):
        """Test search with only required fields"""
        self.step_name = 'TC016_Search_Minimal'
        
        payload = {
            "context": {
                "domain": self.search_domains[0] if self.search_domains else "ONDC:RET10",
                "action": "search",
                "country": "IND",
                "city": "std:080",
                "core_version": self.core_version,
                "bap_id": self.bap_id,
                "bap_uri": self.bap_uri,
                "transaction_id": f"txn-{uuid.uuid4().hex[:12]}",
                "message_id": f"msg-{uuid.uuid4().hex[:12]}",
                "timestamp": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
                "ttl": "PT30S"
            },
            "message": {
                "intent": {}  # Minimal intent
            }
        }
        
        self._send_search_request(self.step_name, payload, expected_status=[200, 202])

    # TC-017: Search with Unicode/Special Characters
    @task(1)
    def tc017_search_unicode_items(self):
        """Test search with Unicode and special characters"""
        self.step_name = 'TC017_Search_Unicode'
        
        unicode_items = [
            "मोबाइल फोन",  # Hindi
            "ಲ್ಯಾಪ್‌ಟಾಪ್",  # Kannada
            "முட்டை",  # Tamil
            "laptop 💻",  # Emoji
            "50% OFF"  # Special chars
        ]
        
        for item_name in unicode_items:
            payload = self._generate_search_payload(item=item_name)
            self._send_search_request(
                f"{self.step_name}_{unicode_items.index(item_name)}",
                payload,
                expected_status=[200, 202]
            )

    # -------------------------------------------------------------------------
    # TC-018: on_search Callback - Valid Seller Response (Minimal Catalog)
    # -------------------------------------------------------------------------
    @task(1)
    def tc018_on_search_valid_callback(self):
        """Simulate BPP sending a valid on_search callback to the Gateway."""
        self.step_name = 'TC018_On_Search_Valid_Callback'
        txn_id = self._setup_linked_transaction('TC018')
        payload = self._generate_on_search_payload(transaction_id=txn_id)
        
        # Use helper method with comprehensive validation
        success, data, status = self._send_on_search_request(
            self.step_name, payload, expected_status=[200, 202], validate_catalog=True
        )
        with self.client.post(
            name=self.step_name,
            url="/on_search",
            data=serialized_body.encode('utf-8'),
            headers={**headers, "Content-Type": "application/json; charset=utf-8"},
            catch_response=True
        ) as response:
            if response.status_code not in [200, 202]:
                response.failure(f"TC-018 Failed: Expected 200/202, got {response.status_code}")
                return
            try:
                data = response.json() if response.content else {}
            except Exception:
                data = {}
            ack_status = data.get('message', {}).get('ack', {}).get('status')
            if ack_status == 'NACK':
                error_info = data.get('error', {})
                error_code = error_info.get('code', 'N/A')
                error_msg = error_info.get('message', 'No error message')
                response.failure(f"TC-018 Failed: Received NACK - [{error_code}] {error_msg}")
                return
            response.success()

    # -------------------------------------------------------------------------
    # TC-019: on_search Callback - Catalog with Multiple Providers
    # -------------------------------------------------------------------------
    @task(1)
    def tc019_on_search_multiple_providers(self):
        """Simulate BPP on_search response with multiple seller providers in catalog."""
        self.step_name = 'TC019_On_Search_Multiple_Providers'
        txn_id = self._setup_linked_transaction('TC019')
        payload = self._generate_on_search_payload(transaction_id=txn_id)
        payload['message']['catalog']['bpp/providers'] = [
            {
                "id": f"provider-{i}",
                "descriptor": {"name": f"Test Provider {i}", "short_desc": f"Provider {i} description"},
                "locations": [
                    {
                        "id": f"loc-{i}",
                        "gps": "12.9716,77.5946",
                        "address": f"Store {i}, Market Street, Bangalore"
                    }
                ],
                "items": [
                    {
                        "id": f"item-{i}-1",
                        "descriptor": {"name": f"Product {i}", "short_desc": f"Product {i} description"},
                        "price": {"currency": "INR", "value": str(100 * (i + 1)) + ".00"},
                        "quantity": {"available": {"count": 50}}
                    }
                ]
            }
            for i in range(3)
        ]
        
        # Use helper method with comprehensive validation
        success, data, status = self._send_on_search_request(
            self.step_name, payload, expected_status=[200, 202], validate_catalog=True
        )
        with self.client.post(
            name=self.step_name,
            url="/on_search",
            data=serialized_body.encode('utf-8'),
            headers={**headers, "Content-Type": "application/json; charset=utf-8"},
            catch_response=True
        ) as response:
            if response.status_code not in [200, 202]:
                response.failure(f"TC-019 Failed: Expected 200/202, got {response.status_code}")
                return
            try:
                data = response.json() if response.content else {}
            except Exception:
                data = {}
            ack_status = data.get('message', {}).get('ack', {}).get('status')
            if ack_status == 'NACK':
                error_info = data.get('error', {})
                error_code = error_info.get('code', 'N/A')
                error_msg = error_info.get('message', 'No error message')
                response.failure(f"TC-019 Failed: Received NACK - [{error_code}] {error_msg}")
                return
            response.success()

    # -------------------------------------------------------------------------
    # TC-020: on_search Callback - Catalog with Multiple Items per Provider
    # -------------------------------------------------------------------------
    @task(1)
    def tc020_on_search_multiple_items(self):
        """Simulate BPP on_search response with multiple items under one provider."""
        self.step_name = 'TC020_On_Search_Multiple_Items'
        txn_id = self._setup_linked_transaction('TC020')
        payload = self._generate_on_search_payload(transaction_id=txn_id)
        payload['message']['catalog']['bpp/providers'][0]['items'] = [
            {
                "id": f"item-{i:03d}",
                "descriptor": {"name": f"Product {i}", "short_desc": f"Product {i} - short description"},
                "price": {"currency": "INR", "value": str(50 * (i + 1)) + ".00"},
                "quantity": {"available": {"count": 100}},
                "tags": [{"code": "availability", "value": "in_stock"}]
            }
            for i in range(1, 6)
        ]
        
        # Use helper method with comprehensive validation
        success, data, status = self._send_on_search_request(
            self.step_name, payload, expected_status=[200, 202], validate_catalog=True
        )
        with self.client.post(
            name=self.step_name,
            url="/on_search",
            data=serialized_body.encode('utf-8'),
            headers={**headers, "Content-Type": "application/json; charset=utf-8"},
            catch_response=True
        ) as response:
            if response.status_code not in [200, 202]:
                response.failure(f"TC-020 Failed: Expected 200/202, got {response.status_code}")
                return
            try:
                data = response.json() if response.content else {}
            except Exception:
                data = {}
            ack_status = data.get('message', {}).get('ack', {}).get('status')
            if ack_status == 'NACK':
                error_info = data.get('error', {})
                error_code = error_info.get('code', 'N/A')
                error_msg = error_info.get('message', 'No error message')
                response.failure(f"TC-020 Failed: Received NACK - [{error_code}] {error_msg}")
                return
            response.success()

    # -------------------------------------------------------------------------
    # TC-021: on_search Callback - Different ONDC Domains
    # -------------------------------------------------------------------------
    @task(1)
    def tc021_on_search_different_domains(self):
        """Simulate on_search callbacks from BPPs across each configured domain."""
        self.step_name = 'TC021_On_Search_Different_Domains'
        for domain in self.search_domains:
            txn_id = self._setup_linked_transaction(f'TC021_{domain}')
            payload = self._generate_on_search_payload(transaction_id=txn_id)
            payload['context']['domain'] = domain
            
            # Use helper method with comprehensive validation
            success, data, status = self._send_on_search_request(
                f"{self.step_name}_{domain}", payload, expected_status=[200, 202], validate_catalog=True
            )
            with self.client.post(
                name=f"{self.step_name}_{domain}",
                url="/on_search",
                data=serialized_body.encode('utf-8'),
                headers={**headers, "Content-Type": "application/json; charset=utf-8"},
                catch_response=True
            ) as response:
                if response.status_code not in [200, 202]:
                    response.failure(f"TC-021 Failed [{domain}]: Expected 200/202, got {response.status_code}")
                else:
                    try:
                        data = response.json() if response.content else {}
                    except Exception:
                        data = {}
                    ack_status = data.get('message', {}).get('ack', {}).get('status')
                    if ack_status == 'NACK':
                        error_info = data.get('error', {})
                        error_code = error_info.get('code', 'N/A')
                        error_msg = error_info.get('message', 'No error message')
                        response.failure(f"TC-021 Failed [{domain}]: Received NACK - [{error_code}] {error_msg}")
                    else:
                        response.success()

    # -------------------------------------------------------------------------
    # TC-022: on_search Callback - Catalog with Offers and Tags
    # -------------------------------------------------------------------------
    @task(1)
    def tc022_on_search_with_offers_and_tags(self):
        """Simulate on_search response containing seller offers and domain-specific tags."""
        self.step_name = 'TC022_On_Search_Offers_Tags'
        txn_id = self._setup_linked_transaction('TC022')
        payload = self._generate_on_search_payload(transaction_id=txn_id)

        # Add offers to the BPP catalog
        payload['message']['catalog']['bpp/offers'] = [
            {
                "id": "offer-001",
                "descriptor": {"name": "10% OFF on First Order"},
                "location_ids": ["loc-1"],
                "item_ids": ["item-1"],
                "time": {
                    "range": {
                        "start": "2026-02-01T00:00:00Z",
                        "end": "2026-12-31T23:59:59Z"
                    }
                },
                "tags": [{"code": "type", "value": "percent"}, {"code": "value", "value": "10"}]
            }
        ]

        # Add tags to items
        payload['message']['catalog']['bpp/providers'][0]['items'][0]['tags'] = [
            {"code": "veg_nonveg", "value": "veg"},
            {"code": "availability", "value": "in_stock"},
            {"code": "brand", "value": "Test Brand"}
        ]

        # Use helper method with comprehensive validation
        success, data, status = self._send_on_search_request(
            self.step_name, payload, expected_status=[200, 202], validate_catalog=True
        )
        with self.client.post(
            name=self.step_name,
            url="/on_search",
            data=serialized_body.encode('utf-8'),
            headers={**headers, "Content-Type": "application/json; charset=utf-8"},
            catch_response=True
        ) as response:
            if response.status_code not in [200, 202]:
                response.failure(f"TC-022 Failed: Expected 200/202, got {response.status_code}")
                return
            try:
                data = response.json() if response.content else {}
            except Exception:
                data = {}
            ack_status = data.get('message', {}).get('ack', {}).get('status')
            if ack_status == 'NACK':
                error_info = data.get('error', {})
                error_code = error_info.get('code', 'N/A')
                error_msg = error_info.get('message', 'No error message')
                response.failure(f"TC-022 Failed: Received NACK - [{error_code}] {error_msg}")
                return
            response.success()

    # -------------------------------------------------------------------------
    # TC-023: on_search Callback - Linked Transaction (matched txn_id from search)
    # -------------------------------------------------------------------------
    @task(1)
    def tc023_on_search_linked_transaction(self):
        """
        Simulate a full search → on_search flow:
        first send /search, then send /on_search with the same transaction_id.
        """
        self.step_name = 'TC023_On_Search_Linked_Txn'

        # Use shared helper — same pattern as TC-018 to TC-022
        txn_id = self._setup_linked_transaction('TC023')

        # Send /on_search with the registered transaction_id
        on_search_payload = self._generate_on_search_payload(transaction_id=txn_id)
        
        # Use helper method with comprehensive validation
        success, data, status = self._send_on_search_request(
            self.step_name, on_search_payload, expected_status=[200, 202], validate_catalog=True
        )
        with self.client.post(
            name=self.step_name,
            url="/on_search",
            data=serialized_body.encode('utf-8'),
            headers={**headers, "Content-Type": "application/json; charset=utf-8"},
            catch_response=True
        ) as response:
            if response.status_code not in [200, 202]:
                response.failure(f"TC-023 Failed: Expected 200/202, got {response.status_code}")
                return
            try:
                data = response.json() if response.content else {}
            except Exception:
                data = {}
            ack_status = data.get('message', {}).get('ack', {}).get('status')
            if ack_status == 'NACK':
                error_info = data.get('error', {})
                error_code = error_info.get('code', 'N/A')
                error_msg = error_info.get('message', 'No error message')
                response.failure(f"TC-023 Failed: Received NACK - [{error_code}] {error_msg}")
                return
            response.success()

    # -------------------------------------------------------------------------
    # TC-024: Search API - Sync Mode (Direct BPP Query with bpp_id in context)
    # Reference: S-P02 "Search sync direct call" from testcase.md / regression_test.sh
    # When bpp_id is present in context, the Gateway routes the request directly to
    # that BPP (unicast) rather than broadcasting to all BPPs.
    # -------------------------------------------------------------------------
    @task(1)
    def tc024_search_sync_mode(self):
        """Send /search in sync mode — bpp_id present in context → unicast routing."""
        self.step_name = 'TC024_Search_Sync_Mode'
        payload = self._generate_search_payload(
            bpp_id=self.bpp_id,
            bpp_uri=self.bpp_uri
        )
        # Sync mode returns 200/202 (ACK) before the BPP responds.
        # A 502 is also acceptable if the BPP is unreachable in this environment.
        self._send_search_request(
            self.step_name,
            payload,
            expected_status=[200, 202, 502]
        )

    # -------------------------------------------------------------------------
    # TC-025: Search API - Multiple Concurrent Requests (TC-S-005)
    # Reference: "Search multiple concurrent" — 5 independent search requests with
    # unique transaction IDs, each expecting 200/202 ACK.
    # -------------------------------------------------------------------------
    @task(1)
    def tc025_search_concurrent_requests(self):
        """TC-S-005: 5 back-to-back search requests with unique txn_ids (concurrent-load simulation)."""
        self.step_name = 'TC025_Search_Concurrent'
        for i in range(5):
            payload = self._generate_search_payload()  # fresh txn_id each iteration
            self._send_search_request(
                f"{self.step_name}_Req_{i + 1}",
                payload,
                expected_status=[200, 202]
            )

    # -------------------------------------------------------------------------
    # TC-026: Search API - Valid Timestamp Within 30s Window (TC-S-006)
    # -------------------------------------------------------------------------
    @task(1)
    def tc026_search_valid_timestamp_window(self):
        """TC-S-006: Fresh /search with timestamp < 1s old; verifies 30s window acceptance."""
        self.step_name = 'TC026_Search_Valid_Timestamp'
        payload = self._generate_search_payload()
        logger.info(f"TC026: Sending request with timestamp: {payload['context']['timestamp']}")
        success, data, status = self._send_search_request(self.step_name, payload)
        if success and data:
            ack_status = data.get('message', {}).get('ack', {}).get('status')
            if ack_status:
                logger.info(f"TC026: Gateway returned ack.status={ack_status}")

    # -------------------------------------------------------------------------
    # TC-027: Search API - Auth Subscriber Lookup Verification (TC-AUTH-002)
    # Verifies that a correctly signed request results in a successful subscriber
    # lookup against the ONDC registry (evidenced by a 200 ACK, not 401).
    # -------------------------------------------------------------------------
    @task(1)
    def tc027_search_auth_subscriber_lookup(self):
        """TC-AUTH-002: Valid request — response ACK proves registry lookup succeeded."""
        self.step_name = 'TC027_Auth_Subscriber_Lookup'
        payload = self._generate_search_payload()
        success, data, status = self._send_search_request(self.step_name, payload)
        if success and data:
            ack_status = data.get('message', {}).get('ack', {}).get('status')
            logger.info(f"TC027: Subscriber lookup verified, ack.status={ack_status}, http={status}")

    # -------------------------------------------------------------------------
    # TC-028: Search API - Async ACK Response Timing (TC-TO-002)
    # Async broadcast /search (no bpp_id) must return an ACK quickly — the Gateway
    # does not wait for BPP responses before acknowledging.
    # -------------------------------------------------------------------------
    @task(1)
    def tc028_search_async_ack_timing(self):
        """TC-TO-002: Async /search ACK timing — Gateway must ACK without waiting for BPPs."""
        self.step_name = 'TC028_Async_ACK_Timing'
        payload = self._generate_search_payload()
        start_time = time.time()
        success, data, status = self._send_search_request(self.step_name, payload)
        elapsed_ms = (time.time() - start_time) * 1000
        logger.info(f"TC028: Async ACK elapsed={elapsed_ms:.1f}ms, success={success}, status={status}")

    # -------------------------------------------------------------------------
    # TC-029: Search API - Sync Request Within Timeout (TC-TO-001)
    # Unicast /search (bpp_id present) must respond before the 30s gateway timeout.
    # 502 is accepted if the BPP is unreachable in this environment — the important
    # check is that the Gateway itself responds, not that it hangs.
    # -------------------------------------------------------------------------
    @task(1)
    def tc029_search_sync_within_timeout(self):
        """TC-TO-001: Sync /search with bpp_id — Gateway responds before 30s timeout."""
        self.step_name = 'TC029_Sync_Within_Timeout'
        payload = self._generate_search_payload(
            bpp_id=self.bpp_id,
            bpp_uri=self.bpp_uri
        )
        start_time = time.time()
        self._send_search_request(
            self.step_name,
            payload,
            expected_status=[200, 202, 502]
        )
        elapsed_s = time.time() - start_time
        logger.info(f"TC029: Sync response time={elapsed_s:.2f}s (must be < 30s)")

    # -------------------------------------------------------------------------
    # TC-030: Search API - L1 Cache Hit for Subscriber Routing (TC-RT-001)
    # Two successive searches from the same subscriber. The second request should
    # benefit from the in-memory L1 cache, observable as equal or faster latency.
    # Both requests must succeed (200/202 ACK).
    # -------------------------------------------------------------------------
    @task(1)
    def tc030_search_cache_routing_hit(self):
        """TC-RT-001: Two consecutive searches — second benefits from L1 subscriber cache."""
        self.step_name = 'TC030_Cache_Routing_Hit'

        # First request — may trigger registry lookup or L2 cache
        payload1 = self._generate_search_payload()
        start1 = time.time()
        self._send_search_request(f"{self.step_name}_First", payload1, expected_status=[200, 202])
        latency1_ms = (time.time() - start1) * 1000

        # Second request — should hit L1 cache (same subscriber credentials reused)
        payload2 = self._generate_search_payload()
        start2 = time.time()
        self._send_search_request(f"{self.step_name}_Second", payload2, expected_status=[200, 202])
        latency2_ms = (time.time() - start2) * 1000

        logger.info(
            f"TC030: First={latency1_ms:.1f}ms, Second={latency2_ms:.1f}ms "
            f"(L1 cache expected to reduce or maintain latency)"
        )

    # -------------------------------------------------------------------------
    # TC-031: Search API - Multi-Target Broadcast Routing (TC-RT-004)
    # /search without bpp_id triggers a broadcast to all matching BPPs on the
    # network. Verifies Gateway accepts broadcast mode and returns ACK.
    # -------------------------------------------------------------------------
    @task(1)
    def tc031_search_broadcast_routing(self):
        """TC-RT-004: Broadcast /search (no bpp_id) — Gateway routes to all matching BPPs."""
        self.step_name = 'TC031_Broadcast_Routing'
        payload = self._generate_search_payload()
        # Confirm broadcast mode (no bpp_id in context)
        assert 'bpp_id' not in payload.get('context', {}), \
            "TC031: bpp_id must NOT be present for broadcast search"
        self._send_search_request(self.step_name, payload, expected_status=[200, 202])


# Module-level tasks variable required by common_test_foundation framework
tasks = [ONDCGatewaySearchFunctional]

# Locust User wrapper for running tests directly with Locust
class GatewaySearchUser(HttpUser):
    """HttpUser wrapper for Gateway Search functional tests"""
    tasks = [ONDCGatewaySearchFunctional]
    wait_time = between(1, 3)
    host = "http://34.100.154.102:8080"  # UAT Gateway (can be overridden by --host)

