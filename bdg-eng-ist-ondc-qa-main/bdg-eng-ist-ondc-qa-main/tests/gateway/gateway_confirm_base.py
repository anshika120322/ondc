import json
import uuid
import yaml
import os
import logging
from datetime import datetime, timezone
from locust import TaskSet
from common_test_foundation.lib.proxy.proxy_server import ProxyServer
from common_test_foundation.helpers.taskset_handler import RESCHEDULE_TASK, taskset_handler
from tests.utils.ondc_auth_helper import ONDCAuthHelper
from tests.utils.ondc_lookup_helper import ONDCLookupHelper
from tests.utils.ondc_error_catalogue import validate_nack_error

logger = logging.getLogger(__name__)

"""
Base class for ONDC Gateway Confirm API tests
Contains shared functionality: config loading, auth setup, confirm payload generation
Models structure after gateway_search_base.py
"""

@taskset_handler(RESCHEDULE_TASK)
class GatewayConfirmBase(TaskSet):
    """Base class with shared setup and helper methods for Gateway Confirm tests"""

    def on_start(self):
        """Initialize proxy, load config, setup authentication"""
        self.step_name = 'ON_START'

        if getattr(self, 'enable_proxy', False):
            self.proxy = ProxyServer()
            self.proxy.start_capture(trx_id=self.step_name)
            self.client.verify = self.proxy.get_certificate()
            self.client.proxies = self.proxy.get_http_proxy_config()
        else:
            self.proxy = None

        config_file = getattr(self, 'config_file', 'resources/gateway/ondc_gateway_confirm_functional.yml')
        tenant_name = getattr(self, 'tenant_name', 'ondcGW')

        config = self._load_config(config_file, tenant_name)

        participant_id, uk_id, private_key_seed = self._setup_auth(config)

        self.auth_helper = ONDCAuthHelper(
            participant_id=participant_id,
            uk_id=uk_id,
            private_key_seed=private_key_seed
        )

        # Core config — all values loaded from YAML; no environment-specific defaults
        self.confirm_domains = config.get('domains', ["ONDC:RET10", "ONDC:RET16"])
        self.cities = config.get('cities', ["std:080", "std:022", "std:011"])
        self.core_version = config.get('core_version', '1.2.0')
        self.bap_id = config.get('bap_id')
        self.bap_uri = config.get('bap_uri')
        self.bpp_id = config.get('bpp_id')
        self.bpp_uri = config.get('bpp_uri')

        # Confirm-specific config data
        self.payment_types = config.get('payment_types', [])
        self.fulfillment_types = config.get('fulfillment_types', [])
        self.test_providers = config.get('test_providers', [])
        self.test_items = config.get('test_items', [])
        self.test_locations = config.get('test_locations', [])
        self.settlement_details = config.get('settlement_details', [])

        logger.info(f"ON_START completed successfully for Confirm tests. wait_time={getattr(self, 'wait_time', 'NOT SET')}")

    def _load_config(self, config_file, tenant_name):
        """Load tenant configuration from YAML file"""
        config = {}
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                yaml_content = yaml.safe_load(f)
                if not yaml_content:
                    logger.warning(f"Config file is empty: {config_file}")
                    return config
                config = yaml_content.get(tenant_name, {})
                logger.info(f"Loaded config from {config_file}")
        else:
            logger.warning(f"Config file not found: {config_file}")
        return config

    def _setup_auth(self, config):
        """Setup authentication credentials from lookup or config"""
        lookup_url = config.get('lookup_host', '')
        participant_id = None
        uk_id = None
        private_key_seed = None

        if lookup_url:
            lookup_helper = ONDCLookupHelper(lookup_url)
            lookup_domain = config.get('lookup_domain', 'ONDC:RET10')
            lookup_city = config.get('lookup_city', 'std:080')

            logger.info(f"Calling lookup for BPP in {lookup_domain}, {lookup_city}")
            lookup_result = lookup_helper.lookup(
                domain=lookup_domain,
                participant_type="BPP",
                city=lookup_city
            )

            if lookup_result.get("success") and lookup_result.get("data"):
                bpp_list = lookup_result["data"]
                if isinstance(bpp_list, list) and len(bpp_list) > 0:
                    bpp = bpp_list[0]
                    participant_id = bpp.get("subscriber_id")
                    keys = bpp.get("keys", [])
                    if keys and len(keys) > 0:
                        uk_id = keys[0].get("uk_id")
                    logger.info(f"Using BPP from lookup: {participant_id}, uk_id: {uk_id}")
            else:
                logger.warning("Lookup failed or returned no results")
        else:
            logger.info("Lookup disabled, using credentials from config")

        if not participant_id:
            participant_id = config.get('participant_id', 'participant-1.participant.ondc')
            logger.info(f"Using participant_id from config: {participant_id}")
        if not uk_id:
            uk_id = config.get('uk_id', 'buyer-key-001')
            logger.info(f"Using uk_id from config: {uk_id}")

        private_key_hex = config.get('private_key_seed')
        if not private_key_hex:
            raise ValueError("private_key_seed is required in config. Do not use hardcoded keys.")

        private_key_seed = None
        if isinstance(private_key_hex, str):
            if len(private_key_hex) == 64:
                try:
                    private_key_seed = bytes.fromhex(private_key_hex)
                    logger.info("Using private key from config (hex format)")
                except ValueError:
                    pass

            if private_key_seed is None:
                try:
                    import base64
                    pkcs8_bytes = base64.b64decode(private_key_hex)
                    if len(pkcs8_bytes) >= 32:
                        private_key_seed = pkcs8_bytes[-32:]
                        logger.info("Using private key from config (base64 PKCS#8 format)")
                except Exception:
                    pass

        if private_key_seed is None:
            raise ValueError(
                f"Invalid private_key_seed in config. Expected a 64-char hex string or "
                f"base64-encoded PKCS#8 key, got {len(private_key_hex) if private_key_hex else 0} chars"
            )

        return participant_id, uk_id, private_key_seed

    def _generate_confirm_payload(
        self,
        domain=None,
        city=None,
        transaction_id=None,
        message_id=None,
        provider_id=None,
        item_id=None,
        item_quantity=1,
        payment_type=None,
        fulfillment_type=None,
        order_amount="500.00",
    ):
        """
        Generate a confirm payload (BAP confirms an order).

        Args:
            domain: ONDC domain (e.g. 'ONDC:RET10'). Defaults to first in config list.
            city: City std code (e.g. 'std:080'). Defaults to first in config list.
            transaction_id: Override transaction ID. Auto-generated if None.
            message_id: Override message ID. Auto-generated if None.
            provider_id: Seller/provider ID. Defaults to first test_provider in config.
            item_id: Item ID being ordered. Defaults to first item in config.
            item_quantity: Quantity of item.
            payment_type: Payment type dict from config. Defaults to first payment_type.
            fulfillment_type: Fulfillment type string (e.g. 'Delivery').
            order_amount: Order total in INR string.

        Returns:
            dict: Confirm payload
        """
        import random

        txn_id = transaction_id or f"txn-{uuid.uuid4().hex[:12]}"
        msg_id = message_id or f"msg-{uuid.uuid4().hex[:12]}"
        order_id = f"order-{uuid.uuid4().hex[:8]}"
        payment_txn_id = f"payment-txn-{uuid.uuid4().hex[:8]}"

        selected_domain = domain or (random.choice(self.confirm_domains) if self.confirm_domains else "ONDC:RET10")
        selected_city = city or (random.choice(self.cities) if self.cities else "std:080")

        # Provider resolution — look up store_location_id even when provider_id is passed as arg
        if provider_id is None:
            if self.test_providers:
                provider = self.test_providers[0]
                provider_id = provider.get('id', 'IGO_Seller_0001')
                store_location_id = provider.get('location_id', 'store-location-001')
            else:
                provider_id = 'IGO_Seller_0001'
                store_location_id = 'store-location-001'
        else:
            # provider_id supplied as arg — find matching location_id from config
            matched = next((p for p in self.test_providers if p.get('id') == provider_id), None)
            store_location_id = matched.get('location_id', 'store-location-001') if matched else 'store-location-001'

        # Item resolution — look up price and name even when item_id is passed as arg
        if item_id is None:
            if self.test_items:
                item = self.test_items[0]
                item_id = item.get('id', 'item-001')
                item_price = item.get('price', '450.00')
                item_name = item.get('name', 'Test Item')
            else:
                item_id = 'item-001'
                item_price = '450.00'
                item_name = 'Test Item'
        else:
            # item_id supplied as arg — find matching price and name from config
            matched_item = next((i for i in self.test_items if i.get('id') == item_id), None)
            item_price = matched_item.get('price', '450.00') if matched_item else '450.00'
            item_name = matched_item.get('name', 'Test Item') if matched_item else 'Test Item'

        delivery_charge = "50.00"

        # Payment resolution
        if payment_type is None:
            payment_type = self.payment_types[0] if self.payment_types else {
                "type": "ON-ORDER",
                "collected_by": "BAP",
                "status": "PAID"
            }

        # Fulfillment type — use first from config, fall back to spec default
        selected_fulfillment_type = fulfillment_type or (self.fulfillment_types[0] if self.fulfillment_types else "Delivery")

        # Settlement details
        settlement = self.settlement_details[0] if self.settlement_details else {
            "settlement_counterparty": "seller-app",
            "settlement_phase": "sale-amount",
            "settlement_type": "neft",
            "beneficiary_name": "Seller Account",
            "settlement_bank_account_no": "1234567890",
            "settlement_ifsc_code": "HDFC0001234",
            "bank_name": "HDFC Bank"
        }

        # GPS from test_locations or fallback
        gps = "12.9492953,77.7019878"
        if self.test_locations:
            gps = self.test_locations[0].get('gps', gps)

        return {
            "context": {
                "domain": selected_domain,
                "action": "confirm",
                "country": "IND",
                "city": selected_city,
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
                    "provider": {
                        "id": provider_id,
                        "locations": [{"id": store_location_id}]
                    },
                    "items": [
                        {
                            "id": item_id,
                            "quantity": {"count": item_quantity}
                        }
                    ],
                    "billing": {
                        "name": "Test Buyer",
                        "phone": "9876543210",
                        "email": "buyer@example.com",
                        "address": "123 Test Street, Bangalore 560001"
                    },
                    "fulfillments": [
                        {
                            "id": "1",
                            "type": selected_fulfillment_type,
                            "end": {
                                "contact": {
                                    "phone": "9876543210"
                                },
                                "location": {
                                    "gps": gps,
                                    "address": "123 Test Street, Bangalore 560001"
                                }
                            }
                        }
                    ],
                    "payment": {
                        "uri": "https://payment.gateway.com/pay",
                        "tl_method": "http/get",
                        "params": {
                            "transaction_id": payment_txn_id,
                            "amount": order_amount,
                            "currency": "INR"
                        },
                        "status": payment_type.get("status", "PAID"),
                        "type": payment_type.get("type", "ON-ORDER"),
                        "@ondc/org/buyer_app_finder_fee_type": "percent",
                        "@ondc/org/buyer_app_finder_fee_amount": "3.0",
                        "@ondc/org/settlement_details": [settlement]
                    },
                    "quote": {
                        "price": {"currency": "INR", "value": order_amount},
                        "breakup": [
                            {
                                "@ondc/org/item_id": item_id,
                                "@ondc/org/title_type": "item",
                                "title": item_name,
                                "price": {"currency": "INR", "value": item_price}
                            },
                            {
                                "@ondc/org/item_id": "1",
                                "@ondc/org/title_type": "delivery",
                                "title": "Delivery Charges",
                                "price": {"currency": "INR", "value": delivery_charge}
                            }
                        ]
                    }
                }
            }
        }

    def _generate_on_confirm_payload(self, transaction_id=None, message_id=None, order_status="Accepted"):
        """
        Generate an on_confirm callback payload (BPP acknowledges the confirmed order).

        Args:
            transaction_id: Override transaction ID. Auto-generated if None.
            message_id: Override message ID. Auto-generated if None.
            order_status: Order status string (e.g. 'Accepted', 'Created').

        Returns:
            dict: on_confirm callback payload
        """
        import random

        txn_id = transaction_id or f"txn-{uuid.uuid4().hex[:12]}"
        msg_id = message_id or f"msg-{uuid.uuid4().hex[:12]}"
        order_id = f"order-{uuid.uuid4().hex[:8]}"
        payment_txn_id = f"payment-txn-{uuid.uuid4().hex[:8]}"

        # Provider resolution from config
        provider = self.test_providers[0] if self.test_providers else {}
        provider_id = provider.get('id', 'IGO_Seller_0001')
        store_location_id = provider.get('location_id', 'store-location-001')

        # Item resolution from config
        item = self.test_items[0] if self.test_items else {}
        item_id = item.get('id', 'item-001')
        item_price = item.get('price', '450.00')
        item_name = item.get('name', 'Test Item')

        # GPS from config
        gps = self.test_locations[0].get('gps', '12.9492953,77.7019878') if self.test_locations else '12.9492953,77.7019878'

        # Payment from config
        payment_type = self.payment_types[0] if self.payment_types else {"type": "ON-ORDER", "status": "PAID", "collected_by": "BAP"}

        # Fulfillment type from config
        fulfillment_type = self.fulfillment_types[0] if self.fulfillment_types else "Delivery"

        return {
            "context": {
                "domain": random.choice(self.confirm_domains),
                "action": "on_confirm",
                "country": "IND",
                "city": random.choice(self.cities),
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
                    "state": order_status,
                    "provider": {
                        "id": provider_id,
                        "locations": [{"id": store_location_id}]
                    },
                    "items": [
                        {
                            "id": item_id,
                            "quantity": {"count": 1}
                        }
                    ],
                    "billing": {
                        "name": "Test Buyer",
                        "phone": "9876543210",
                        "email": "buyer@example.com",
                        "address": "123 Test Street, Bangalore 560001"
                    },
                    "fulfillments": [
                        {
                            "id": "1",
                            "type": fulfillment_type,
                            "state": {
                                "descriptor": {
                                    "code": "Pending"
                                }
                            },
                            "end": {
                                "contact": {"phone": "9876543210"},
                                "location": {
                                    "gps": gps,
                                    "address": "123 Test Street, Bangalore 560001"
                                }
                            },
                            "tracking": False
                        }
                    ],
                    "payment": {
                        "uri": "https://payment.gateway.com/pay",
                        "tl_method": "http/get",
                        "params": {
                            "transaction_id": payment_txn_id,
                            "amount": "500.00",
                            "currency": "INR"
                        },
                        "status": payment_type.get("status", "PAID"),
                        "type": payment_type.get("type", "ON-ORDER"),
                        "@ondc/org/buyer_app_finder_fee_type": "percent",
                        "@ondc/org/buyer_app_finder_fee_amount": "3.0"
                    },
                    "quote": {
                        "price": {"currency": "INR", "value": "500.00"},
                        "breakup": [
                            {
                                "@ondc/org/item_id": item_id,
                                "@ondc/org/title_type": "item",
                                "title": item_name,
                                "price": {"currency": "INR", "value": item_price}
                            },
                            {
                                "@ondc/org/item_id": "1",
                                "@ondc/org/title_type": "delivery",
                                "title": "Delivery Charges",
                                "price": {"currency": "INR", "value": "50.00"}
                            }
                        ]
                    },
                    "created_at": datetime.now(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z'),
                    "updated_at": datetime.now(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')
                }
            }
        }

    def _send_confirm_request(self, step_name, payload, headers=None, expected_status=None, test_type='functional', expected_error_code=None):
        """
        Helper method to send confirm requests with consistent error handling.
        Mirrors _send_search_request from GatewaySearchBase.

        Args:
            step_name: Name for the test step
            payload: Request payload (dict)
            headers: Optional headers (will generate auth if not provided)
            expected_status: List of expected status codes (default: [200, 202])
            test_type: 'functional' (default) or 'negative'.
                - 'functional': HTTP status checked first; NACK body = FAIL even at HTTP 200.
                - 'negative': NACK in response body = PASS (error details captured);
                  ACK = FAIL; HTTP 4xx/5xx with no ACK/NACK body = PASS (auth-level rejection).
            expected_error_code: When test_type='negative' and a NACK is received, validate
                that error.code matches this value (string). None = no code validation.

        Returns:
            tuple: (success: bool, response_data: dict, status_code: int)
        """
        if headers is None:
            headers = self.auth_helper.generate_headers(payload)

        if expected_status is None:
            expected_status = [200, 202]

        # Use pre-serialized body from auth_helper to ensure digest matches exactly
        serialized_body = headers.pop('serialized_body', None)
        if not serialized_body:
            serialized_body = json.dumps(payload, separators=(',', ':'), sort_keys=False, ensure_ascii=False)

        with self.client.post(
            name=step_name,
            url="/confirm",
            data=serialized_body.encode('utf-8'),
            headers={**headers, "Content-Type": "application/json; charset=utf-8"},
            catch_response=True
        ) as response:

            if test_type == 'negative':
                # --- Negative test validation ---
                try:
                    data = response.json() if response.content else {}
                except Exception:
                    data = {}

                ack_status = data.get('message', {}).get('ack', {}).get('status')

                if ack_status == 'ACK':
                    # Gateway accepted a request it should have rejected → test FAILS
                    response.failure(f"{step_name} Failed: Expected NACK/rejection but received ACK")
                    return False, data, response.status_code

                if ack_status == 'NACK':
                    # Gateway correctly rejected → validate code and type against catalogue
                    error_info = data.get('error', {})
                    actual_code = str(error_info.get('code', '')) or 'N/A'
                    actual_type = error_info.get('type', '')
                    error_msg = error_info.get('message', 'No error message')
                    ok, note = validate_nack_error(actual_code, actual_type, expected_error_code)
                    if not ok:
                        response.failure(f"{step_name} Failed: NACK received but {note}")
                        return False, data, response.status_code
                    logger.info(f"{step_name} NACK received (expected for negative test): {note} — {error_msg}")
                    response.success()
                    return True, data, response.status_code

                # No ACK/NACK in body (e.g. plain HTTP 401 auth rejection) — treat any
                # 4xx/5xx status as a correct rejection
                if response.status_code >= 400:
                    response.success()
                    return True, data, response.status_code

                # HTTP 2xx but no NACK — unexpected for a negative test
                response.failure(
                    f"{step_name} Failed: Expected NACK/rejection, got HTTP {response.status_code} with no NACK"
                )
                return False, data, response.status_code

            else:
                # --- Functional test validation (default) ---
                if response.status_code not in expected_status:
                    response.failure(f"{step_name} Failed: Expected {expected_status}, got {response.status_code}")
                    return False, None, response.status_code

                try:
                    data = response.json() if response.content else {}
                except Exception as e:
                    response.failure(f"{step_name} Failed: Error parsing response: {str(e)}")
                    return False, None, response.status_code

                # Check ACK/NACK — NACK means the gateway rejected the payload even
                # though HTTP 200 was returned; this is a functional failure
                ack_status = data.get('message', {}).get('ack', {}).get('status')
                if ack_status == 'NACK':
                    error_info = data.get('error', {})
                    error_code = error_info.get('code', 'N/A')
                    error_type = error_info.get('type', '')
                    error_msg = error_info.get('message', 'No error message')
                    type_note = f", error.type={error_type}" if error_type else ""
                    response.failure(
                        f"{step_name} Failed: NACK received for a valid request — "
                        f"error.code={error_code}{type_note} ({error_msg})"
                    )
                    return False, data, response.status_code

                response.success()
                return True, data, response.status_code

    def _validate_ack_response(self, response_obj, data, test_name):
        """
        Validate ACK/NACK response from Gateway.

        Args:
            response_obj: Locust response object
            data: Parsed JSON response
            test_name: Test case name for error messages

        Returns:
            bool: True if valid ACK, False otherwise
        """
        ack_status = data.get('message', {}).get('ack', {}).get('status')

        if ack_status == 'NACK':
            error_msg = data.get('error', {}).get('message', 'unknown')
            response_obj.failure(f"{test_name} Failed: Received NACK - {error_msg}")
            return False
        elif ack_status != 'ACK':
            response_obj.failure(f"{test_name} Failed: Expected ACK, got {data}")
            return False

        return True

    def on_stop(self):
        """Cleanup proxy after test ends"""
        if self.proxy:
            self.proxy.stop_capture()
            self.proxy.quit()
