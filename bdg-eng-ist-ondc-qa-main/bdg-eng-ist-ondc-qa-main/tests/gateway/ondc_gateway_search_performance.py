import json
import uuid
import random
import logging
import threading
from locust import task, between
from tests.gateway.gateway_search_base import GatewaySearchBase

logger = logging.getLogger(__name__)

"""
ONDC Gateway Search API - Performance Tests (Load Testing)
Uses optimized task weights to simulate realistic user behavior
Run with higher user counts: --users 10-50 for load testing
"""

class ONDCGatewaySearchPerformance(GatewaySearchBase):
    """Performance test scenarios with realistic load distribution"""
    
    # Wait time between tasks - very short for high throughput performance testing
    wait_time = between(0.1, 0.5)
    
    # Override config settings
    config_file = 'resources/gateway/ondc_gateway_search_performance.yml'
    tenant_name = 'ondcGatewaySearch'
    
    # TC-001: Search API - Valid Request with Authentication (Primary scenario - 20%)
    @task(1)
    def tc001_search_valid_authenticated(self):
        try:
            logger.info(f"TC-001 STARTED by thread {threading.current_thread().name}")
            self.step_name = 'TC001_Search_Valid_Auth'
            
            logger.info("TC-001: Generating payload...")
            payload = self._generate_search_payload()
            logger.info(f"TC-001: Payload generated successfully")
            
            # Check for 500 errors (infrastructure issues)
            logger.info("TC-001: Generating auth headers...")
            # /search no longer uses digest — omit it from the signing string and headers
            headers = self.auth_helper.generate_headers(payload, include_digest=False)
            logger.info("TC-001: Headers generated successfully")
            payload_json = headers.pop('serialized_body', json.dumps(payload, separators=(',', ':'), sort_keys=False))
            
            logger.info("TC-001: Sending POST request...")
            with self.client.post(
                name=self.step_name,
                url="/search",
                data=payload_json,
                headers={**headers, "Content-Type": "application/json"},
                catch_response=True
            ) as response:
                
                # Handle infrastructure/server errors (5xx)
                if response.status_code >= 500:
                    try:
                        data = response.json()
                        error_msg = data.get('error', {}).get('message', 'unknown error')
                        response.failure(f"TC-001 Failed: Server error {response.status_code} - {error_msg}")
                    except:
                        response.failure(f"TC-001 Failed: Server error {response.status_code} - {response.text[:200]}")
                    return
                
                if response.status_code not in [200, 202]:
                    response.failure(f"TC-001 Failed: Expected 200/202, got {response.status_code} - {response.text[:200]}")
                    return
                
                try:
                    data = response.json()
                    # Validate ACK response
                    if not self._validate_ack_response(response, data, "TC-001"):
                        return
                    response.success()
                except Exception as e:
                    response.failure(f"TC-001 Failed: Error parsing response: {str(e)}")
        except Exception as e:
            logger.error(f"TC-001 Exception: {str(e)}", exc_info=True)

    # TC-002: Search API - Different Domains (15%)
    @task(1)
    def tc002_search_different_domains(self):
        self.step_name = 'TC002_Search_Different_Domains'
        
        # Guard against empty domains list
        if not self.search_domains:
            logger.error("TC-002: search_domains is empty - check config")
            return
        
        # Pick one random domain per task execution
        domain = random.choice(self.search_domains)
        payload = self._generate_search_payload(domain=domain)
        # /search no longer uses digest — omit it from the signing string and headers
        headers = self.auth_helper.generate_headers(payload, include_digest=False)
        payload_json = headers.pop('serialized_body', json.dumps(payload, separators=(',', ':'), sort_keys=False))

        with self.client.post(
            name=self.step_name,  # Use stable name to avoid stats explosion
            url="/search",
            data=payload_json,
            headers={**headers, "Content-Type": "application/json"},
            catch_response=True
        ) as response:
            
            if response.status_code not in [200, 202]:
                response.failure(f"TC-002 Failed for {domain}: Status {response.status_code} - {response.text[:200]}")
                return
            
            try:
                data = response.json()
                ack_status = data.get('message', {}).get('ack', {}).get('status')
                if ack_status != 'ACK':
                    response.failure(f"TC-002 Failed for {domain}: Expected ACK, got {ack_status}")
                    return
                
                response.success()
            except Exception as e:
                response.failure(f"TC-002 Failed for {domain}: {str(e)} - {response.text[:200]}")

    # TC-003: Search API - Different Cities (15%)
    @task(1)
    def tc003_search_different_cities(self):
        self.step_name = 'TC003_Search_Different_Cities'
        
        # Guard against empty cities list
        if not self.cities:
            logger.error("TC-003: cities is empty - check config")
            return
        
        # Pick one random city per task execution
        city = random.choice(self.cities)
        payload = self._generate_search_payload(city=city)
        # /search no longer uses digest — omit it from the signing string and headers
        headers = self.auth_helper.generate_headers(payload, include_digest=False)
        payload_json = headers.pop('serialized_body', json.dumps(payload, separators=(',', ':'), sort_keys=False))

        with self.client.post(
            name=self.step_name,  # Use stable name to avoid stats explosion
            url="/search",
            data=payload_json,
            headers={**headers, "Content-Type": "application/json"},
            catch_response=True
        ) as response:
            
            if response.status_code not in [200, 202]:
                response.failure(f"TC-003 Failed for {city}: Status {response.status_code} - {response.text[:200]}")
                return
            
            try:
                data = response.json()
                ack_status = data.get('message', {}).get('ack', {}).get('status')
                if ack_status != 'ACK':
                    response.failure(f"TC-003 Failed for {city}: Expected ACK, got {ack_status}")
                    return
                
                response.success()
            except Exception as e:
                response.failure(f"TC-003 Failed for {city}: {str(e)} - {response.text[:200]}")

    # TC-004: Search API - Large Payload (10%)
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

    # TC-005: Health Check (5%)
    @task(1)
    def tc005_health_check(self):
        self.step_name = 'TC005_Health_Check'
        
        with self.client.get(
            name=self.step_name,
            url="/health",
            catch_response=True
        ) as response:
            
            if response.status_code != 200:
                response.failure(f"TC-005 Failed: Expected 200, got {response.status_code} - {response.text[:200]}")
                return
            
            response.success()

    # TC-006: Metrics Endpoint (5%)
    @task(1)
    def tc006_metrics_endpoint(self):
        self.step_name = 'TC006_Metrics'
        
        with self.client.get(
            name=self.step_name,
            url="/metrics",
            catch_response=True
        ) as response:
            
            if response.status_code != 200:
                response.failure(f"TC-006 Failed: Expected 200, got {response.status_code} - {response.text[:200]}")
                return
            
            response.success()

    # TC-007: Search API - Same Transaction ID (8%)
    @task(1)
    def tc007_search_same_transaction_id(self):
        """Test with same transaction ID (simulates retry behavior)"""
        self.step_name = 'TC007_Search_Same_Txn_ID'
        
        # Generate one request per task execution
        # In real scenarios, same txn_id would be used across retries
        # but for load testing, we test the behavior with single requests
        txn_id = f"txn-{uuid.uuid4().hex[:12]}"
        
        payload = self._generate_search_payload()
        payload['context']['transaction_id'] = txn_id
        payload['context']['message_id'] = f"msg-{uuid.uuid4().hex[:12]}"
        
        # /search no longer uses digest — omit it from the signing string and headers
        headers = self.auth_helper.generate_headers(payload, include_digest=False)
        payload_json = headers.pop('serialized_body', json.dumps(payload, separators=(',', ':'), sort_keys=False))

        with self.client.post(
            name=self.step_name,
            url="/search",
            data=payload_json,
            headers={**headers, "Content-Type": "application/json"},
            catch_response=True
        ) as response:
            
            if response.status_code not in [200, 202]:
                response.failure(f"TC-007 Failed: Status {response.status_code} - {response.text[:200]}")
                return
            
            response.success()

    # TC-008: Search API - Performance Test (Burst) (10%)
    @task(1)
    def tc008_search_performance_burst(self):
        """High frequency search requests to test performance"""
        self.step_name = 'TC008_Search_Performance_Burst'
        
        payload = self._generate_search_payload()
        
        # Send request - Locust automatically tracks response time
        self._send_search_request(self.step_name, payload, expected_status=[200, 202])
        # Note: Performance metrics (response time, RPS) are tracked by Locust automatically

    # TC-009: Search with Fulfillment Types (5%)
    @task(1)
    def tc009_search_fulfillment_types(self):
        self.step_name = 'TC009_Search_Fulfillment_Types'
        
        fulfillment_type = random.choice(self.fulfillment_types) if self.fulfillment_types else "Delivery"
        
        payload = self._generate_search_payload()
        payload['message']['intent']['fulfillment'] = {
            "type": fulfillment_type
        }
        
        self._send_search_request(self.step_name, payload, expected_status=[200, 202])

    # TC-010: Search with Item Details (5%)
    @task(1)
    def tc010_search_item_details(self):
        self.step_name = 'TC010_Search_Item_Details'
        
        category = random.choice(self.item_categories) if self.item_categories else {
            "category_name": "Grocery",
            "item_name": "rice"
        }
        
        payload = self._generate_search_payload()
        payload['message']['intent']['item'] = {
            "descriptor": {
                "name": category.get('item_name', 'product')
            }
        }
        if 'category_name' in category:
            payload['message']['intent']['category'] = {
                "descriptor": {
                    "name": category['category_name']
                }
            }
        
        self._send_search_request(self.step_name, payload, expected_status=[200, 202])

    # TC-011: Search with Payment Preferences (5%)
    @task(1)
    def tc011_search_payment_preferences(self):
        self.step_name = 'TC011_Search_Payment_Preferences'
        
        payment_type = random.choice(self.payment_types) if self.payment_types else "ON-ORDER"
        
        payload = self._generate_search_payload()
        payload['message']['intent']['payment'] = {
            "@ondc/org/buyer_app_finder_fee_type": "percent",
            "@ondc/org/buyer_app_finder_fee_amount": "3",
            "type": payment_type
        }
        
        self._send_search_request(self.step_name, payload, expected_status=[200, 202])

    # TC-012: Search with Tags (5%)
    @task(1)
    def tc012_search_with_tags(self):
        self.step_name = 'TC012_Search_With_Tags'
        
        if self.domain_tags:
            tag = random.choice(self.domain_tags)
            domain = tag.get('domain', 'ONDC:RET10')
            tags = tag.get('tags', [])
        else:
            domain = 'ONDC:RET11'
            tags = [
                {
                    "code": "catalog_inc",
                    "list": [{"code": "start_time", "value": "2024-01-01T00:00:00Z"}]
                }
            ]
        
        payload = self._generate_search_payload(domain=domain)
        payload['message']['intent']['tags'] = tags
        
        self._send_search_request(self.step_name, payload, expected_status=[200, 202])

    # TC-013: Search with Location Radius (5%)
    @task(1)
    def tc013_search_location_radius(self):
        self.step_name = 'TC013_Search_Location_Radius'
        
        location = random.choice(self.test_locations) if self.test_locations else {
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

    # TC-014: Search with Multiple Items (5%)
    @task(1)
    def tc014_search_multiple_items(self):
        self.step_name = 'TC014_Search_Multiple_Items'
        
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

    # TC-015: on_search Callback - Valid Request (2%)
    @task(2)
    def tc015_on_search_valid_callback(self):
        """Test POST /v3.0/on_search with valid seller callback"""
        self.step_name = 'TC015_On_Search_Valid_Callback'
        
        payload = self._generate_on_search_payload()
        headers = self.auth_helper.generate_headers(payload)
        serialized_body = headers.pop('serialized_body', None) or json.dumps(
            payload, separators=(',', ':'), sort_keys=False, ensure_ascii=False
        )
        
        with self.client.post(
            name=self.step_name,
            url="/on_search",
            data=serialized_body,
            headers={**headers, "Content-Type": "application/json"},
            catch_response=True
        ) as response:
            if response.status_code not in [200, 202]:
                response.failure(f"TC-015 Failed: Expected 200/202, got {response.status_code}")
                return
            response.success()

    # TC-016: Search with Complete Payload (3%)
    @task(3)
    def tc016_search_complete_payload(self):
        """Test search with all optional ONDC fields populated"""
        self.step_name = 'TC016_Search_Complete_Payload'
        
        payload = self._generate_search_payload()
        
        # Add all optional fields
        payload['context']['bpp_id'] = 'target-seller.bpp.ondc'
        payload['context']['bpp_uri'] = 'https://target-seller.bpp.ondc.example.com'
        
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

    # TC-017: Search with Minimal Payload (5%)
    @task(5)
    def tc017_search_minimal_payload(self):
        """Test search with only required fields"""
        self.step_name = 'TC017_Search_Minimal'
        
        payload = {
            "context": {
                "domain": "ONDC:RET10",
                "action": "search",
                "country": "IND",
                "city": "std:080",
                "core_version": self.core_version,
                "bap_id": self.bap_id,
                "bap_uri": self.bap_uri,
                "transaction_id": f"txn-{uuid.uuid4().hex[:12]}",
                "message_id": f"msg-{uuid.uuid4().hex[:12]}",
                "timestamp": self.auth_helper.generate_headers({})['serialized_body'] if hasattr(self, 'auth_helper') else "",
                "ttl": "PT30S"
            },
            "message": {
                "intent": {}  # Minimal intent
            }
        }
        
        # Fix timestamp
        from datetime import datetime, timezone
        payload['context']['timestamp'] = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
        
        self._send_search_request(self.step_name, payload, expected_status=[200, 202])

    # TC-018: Search with Unicode/Special Characters (2%)
    @task(2)
    def tc018_search_unicode_items(self):
        """Test search with Unicode and special characters"""
        self.step_name = 'TC018_Search_Unicode'
        
        unicode_items = [
            "मोबाइल फोन",  # Hindi
            "ಲ್ಯಾಪ್‌ಟಾಪ್",  # Kannada
            "முட்டை",  # Tamil
            "laptop 💻",  # Emoji
            "50% OFF"  # Special chars
        ]
        
        item_name = random.choice(unicode_items)
        payload = self._generate_search_payload(item=item_name)
        self._send_search_request(
            self.step_name,
            payload,
            expected_status=[200, 202]
        )


tasks = [ONDCGatewaySearchPerformance]
