import json
import logging
import os
import uuid
from datetime import datetime, timezone

import yaml
from locust import TaskSet
from common_test_foundation.lib.proxy.proxy_server import ProxyServer
from common_test_foundation.helpers.taskset_handler import RESCHEDULE_TASK, taskset_handler
from tests.utils.ondc_auth_helper import ONDCAuthHelper

logger = logging.getLogger(__name__)

"""
Base class for ONDC Gateway Init API tests
Contains shared functionality: config loading, auth setup, init payload generation.
Models structure after gateway_confirm_base.py
"""


@taskset_handler(RESCHEDULE_TASK)
class GatewayInitBase(TaskSet):
    """Base class with shared setup and helper methods for Gateway Init tests"""

    def on_start(self):
        """Initialize proxy, load config, setup authentication."""
        self.step_name = 'ON_START'

        if getattr(self, 'enable_proxy', False):
            self.proxy = ProxyServer()
            self.proxy.start_capture(trx_id=self.step_name)
            self.client.verify = self.proxy.get_certificate()
            self.client.proxies = self.proxy.get_http_proxy_config()
        else:
            self.proxy = None

        config_file = getattr(self, 'config_file', 'resources/gateway/ondc_gateway_init_functional.yml')
        tenant_name = getattr(self, 'tenant_name', 'ondcGW')
        config = self._load_config(config_file, tenant_name)

        participant_id, uk_id, private_key_seed = self._setup_auth(config)

        self.auth_helper = ONDCAuthHelper(
            participant_id=participant_id,
            uk_id=uk_id,
            private_key_seed=private_key_seed
        )

        # Core config — all values loaded from YAML; no environment-specific defaults
        self.init_domains = config.get('domains', ["ONDC:RET10", "ONDC:RET16"])
        self.cities = config.get('cities', ["std:080"])
        self.core_version = config.get('core_version', '1.2.0')
        self.bap_id = config.get('bap_id')
        self.bap_uri = config.get('bap_uri')
        self.bpp_id = config.get('bpp_id')
        self.bpp_uri = config.get('bpp_uri')

        # Init-specific config data
        self.payment_types = config.get('payment_types', [])
        self.fulfillment_types = config.get('fulfillment_types', [])
        self.test_providers = config.get('test_providers', [])
        self.test_items = config.get('test_items', [])
        self.test_locations = config.get('test_locations', [])
        self.settlement_details = config.get('settlement_details', [])

        logger.info(f"ON_START completed successfully for Init tests. wait_time={getattr(self, 'wait_time', 'NOT SET')}")

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
        """Extract and validate auth credentials from config."""
        participant_id = config.get('participant_id')
        if not participant_id:
            participant_id = config.get('bap_id', 'participant-1.participant.ondc')
            logger.info(f"Using bap_id as participant_id: {participant_id}")

        uk_id = config.get('uk_id', 'buyer-key-001')
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

    def _generate_init_payload(
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
        Generate an /init payload (BAP initiates order checkout).

        Key differences from /confirm:
        - `bpp_id` and `bpp_uri` are REQUIRED in context (cannot be omitted)
        - `message.order.payments` is an ARRAY (not a single `payment` object)
        - `payments[].type` enum: PRE-ORDER, ON-FULFILLMENT, POST-FULFILLMENT
          (NOTE: ON-ORDER is NOT valid for /init)
        - Each payment entry must include `type`, `status`, `collected_by`, and `tags`
          with SETTLEMENT_TERMS + BUYER_FINDER_FEES descriptor codes

        Args:
            domain: ONDC domain. Defaults to first in config list.
            city: City std code. Defaults to first in config list.
            transaction_id: Override transaction ID. Auto-generated if None.
            message_id: Override message ID. Auto-generated if None.
            provider_id: Seller/provider ID. Defaults to first test_provider.
            item_id: Item ID. Defaults to first item in config.
            item_quantity: Quantity.
            payment_type: Payment type dict. Defaults to first payment_type in config.
            fulfillment_type: Fulfillment type string (e.g. 'Delivery').
            order_amount: Order total in INR string.

        Returns:
            dict: Init payload
        """
        import random

        txn_id = transaction_id or f"txn-{uuid.uuid4().hex[:12]}"
        msg_id = message_id or f"msg-{uuid.uuid4().hex[:12]}"

        selected_domain = domain or (random.choice(self.init_domains) if self.init_domains else "ONDC:RET10")
        selected_city = city or (random.choice(self.cities) if self.cities else "std:080")

        # Provider resolution
        if provider_id is None:
            if self.test_providers:
                provider = self.test_providers[0]
                provider_id = provider.get('id', 'IGO_Seller_0001')
                store_location_id = provider.get('location_id', 'store-location-001')
            else:
                provider_id = 'IGO_Seller_0001'
                store_location_id = 'store-location-001'
        else:
            store_location_id = 'store-location-001'

        # Item resolution
        if item_id is None:
            if self.test_items:
                item = self.test_items[0]
                item_id = item.get('id', 'item-001')
                item_price = item.get('price', '450.00')
                fulfillment_id = item.get('fulfillment_id', 'F1')
                location_id = item.get('location_id', 'L1')
            else:
                item_id = 'item-001'
                item_price = '450.00'
                fulfillment_id = 'F1'
                location_id = 'L1'
        else:
            item_price = '450.00'
            fulfillment_id = 'F1'
            location_id = 'L1'

        # Payment resolution
        if payment_type is None:
            payment_type = self.payment_types[0] if self.payment_types else {
                "type": "PRE-ORDER",
                "collected_by": "BAP",
                "status": "PAID"
            }

        selected_fulfillment_type = fulfillment_type or "Delivery"

        # GPS from test_locations or fallback
        gps = "12.9492953,77.7019878"
        if self.test_locations:
            gps = self.test_locations[0].get('gps', gps)

        # Settlement details for SETTLEMENT_TERMS tag
        settlement = self.settlement_details[0] if self.settlement_details else {
            "settlement_counterparty": "seller-app",
            "settlement_phase": "sale-amount",
            "settlement_type": "neft",
            "beneficiary_name": "Seller Account",
            "settlement_bank_account_no": "1234567890",
            "settlement_ifsc_code": "HDFC0001234",
            "bank_name": "HDFC Bank"
        }

        return {
            "context": {
                "domain": selected_domain,
                "action": "init",
                "country": "IND",
                "city": selected_city,
                "core_version": self.core_version,
                "bap_id": self.bap_id,
                "bap_uri": self.bap_uri,
                "bpp_id": self.bpp_id,       # REQUIRED for /init (unlike /search)
                "bpp_uri": self.bpp_uri,     # REQUIRED for /init
                "transaction_id": txn_id,
                "message_id": msg_id,
                "timestamp": datetime.now(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z'),
                "ttl": "PT30S"
            },
            "message": {
                "order": {
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
                            "id": "F1",
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
                    "payments": [
                        {
                            "type": payment_type.get("type", "PRE-ORDER"),
                            "status": payment_type.get("status", "PAID"),
                            "collected_by": payment_type.get("collected_by", "BAP"),
                            "tags": [
                                {
                                    "descriptor": {
                                        "code": "SETTLEMENT_TERMS"
                                    },
                                    "list": [
                                        {"descriptor": {"code": "settlement_counterparty"}, "value": settlement.get("settlement_counterparty", "seller-app")},
                                        {"descriptor": {"code": "settlement_phase"}, "value": settlement.get("settlement_phase", "sale-amount")},
                                        {"descriptor": {"code": "settlement_type"}, "value": settlement.get("settlement_type", "neft")},
                                        {"descriptor": {"code": "settlement_bank_account_no"}, "value": settlement.get("settlement_bank_account_no", "1234567890")},
                                        {"descriptor": {"code": "settlement_ifsc_code"}, "value": settlement.get("settlement_ifsc_code", "HDFC0001234")}
                                    ]
                                },
                                {
                                    "descriptor": {
                                        "code": "BUYER_FINDER_FEES"
                                    },
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

    def _generate_on_init_payload(self, transaction_id=None, message_id=None):
        """
        Generate an /on_init callback payload (BPP responds with quote for init).

        Key additions vs /init:
        - `items` must include `fulfillment_ids` (minItems: 1) and `location_ids` (minItems: 1)
        - `fulfillments[].type` must be "DELIVERY" (uppercase enum)
        - `quote` with `price` + `breakup` (must include BASE_FARE and DISTANCE_FARE titles)
        - `cancellation_terms` with valid `fulfillment_state.descriptor.code` values:
          RIDE_ASSIGNED, RIDE_ENROUTE_PICKUP, RIDE_ARRIVED_PICKUP, RIDE_STARTED

        Args:
            transaction_id: Override transaction ID. Auto-generated if None.
            message_id: Override message ID. Auto-generated if None.

        Returns:
            dict: on_init callback payload
        """
        import random

        txn_id = transaction_id or f"txn-{uuid.uuid4().hex[:12]}"
        msg_id = message_id or f"msg-{uuid.uuid4().hex[:12]}"

        # Provider resolution from config
        provider_id = self.test_providers[0].get('id') if self.test_providers else 'IGO_Seller_0001'
        store_location_id = self.test_providers[0].get('location_id') if self.test_providers else 'store-location-001'

        # Item resolution from config
        item = self.test_items[0] if self.test_items else {}
        item_id = item.get('id', 'item-001')
        fulfillment_id = item.get('fulfillment_id', 'F1')
        location_id = item.get('location_id', 'L1')

        # GPS from config
        gps = self.test_locations[0].get('gps', '12.9492953,77.7019878') if self.test_locations else '12.9492953,77.7019878'
        delivery_address = self.test_locations[0].get('address', '123 Test Street, Bangalore 560001') if self.test_locations else '123 Test Street, Bangalore 560001'

        # Payment from config
        payment_type = self.payment_types[0] if self.payment_types else {"type": "PRE-ORDER", "status": "PAID", "collected_by": "BAP"}

        # Settlement details from config
        settlement = self.settlement_details[0] if self.settlement_details else {
            "settlement_counterparty": "seller-app",
            "settlement_phase": "sale-amount",
            "settlement_type": "neft",
            "settlement_bank_account_no": "1234567890",
            "settlement_ifsc_code": "HDFC0001234"
        }

        return {
            "context": {
                "domain": random.choice(self.init_domains),
                "action": "on_init",
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
                    "provider": {
                        "id": provider_id,
                        "locations": [{"id": store_location_id}]
                    },
                    "items": [
                        {
                            "id": item_id,
                            "quantity": {"count": 1},
                            "fulfillment_ids": [fulfillment_id],   # required: minItems 1
                            "location_ids": [location_id]          # required: minItems 1
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
                            "id": fulfillment_id,
                            "type": "DELIVERY",          # uppercase enum required by on_init schema
                            "state": {
                                "descriptor": {
                                    "code": "Pending"
                                }
                            },
                            "end": {
                                "contact": {"phone": "9876543210"},
                                "location": {
                                    "gps": gps,
                                    "address": delivery_address
                                }
                            },
                            "tracking": False
                        }
                    ],
                    "payments": [
                        {
                            "type": payment_type.get("type", "PRE-ORDER"),
                            "status": payment_type.get("status", "PAID"),
                            "collected_by": payment_type.get("collected_by", "BAP"),
                            "tags": [
                                {
                                    "descriptor": {"code": "SETTLEMENT_TERMS"},
                                    "list": [
                                        {"descriptor": {"code": "settlement_counterparty"}, "value": settlement.get("settlement_counterparty", "seller-app")},
                                        {"descriptor": {"code": "settlement_phase"}, "value": settlement.get("settlement_phase", "sale-amount")},
                                        {"descriptor": {"code": "settlement_type"}, "value": settlement.get("settlement_type", "neft")},
                                        {"descriptor": {"code": "settlement_bank_account_no"}, "value": settlement.get("settlement_bank_account_no", "1234567890")},
                                        {"descriptor": {"code": "settlement_ifsc_code"}, "value": settlement.get("settlement_ifsc_code", "HDFC0001234")}
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
                    ],
                    "quote": {
                        "price": {"currency": "INR", "value": "500.00"},
                        "breakup": [
                            {
                                "title": "BASE_FARE",
                                "price": {"currency": "INR", "value": "400.00"}
                            },
                            {
                                "title": "DISTANCE_FARE",
                                "price": {"currency": "INR", "value": "50.00"}
                            },
                            {
                                "title": "TAX",
                                "price": {"currency": "INR", "value": "30.00"}
                            },
                            {
                                "title": "DISCOUNT",
                                "price": {"currency": "INR", "value": "-10.00"}
                            },
                            {
                                "title": "WAITING_CHARGE",
                                "price": {"currency": "INR", "value": "30.00"}
                            }
                        ]
                    },
                    "cancellation_terms": [
                        {
                            "fulfillment_state": {
                                "descriptor": {
                                    "code": "RIDE_ASSIGNED"
                                }
                            },
                            "cancellation_fee": {
                                "amount": {"currency": "INR", "value": "0.00"}
                            }
                        },
                        {
                            "fulfillment_state": {
                                "descriptor": {
                                    "code": "RIDE_ENROUTE_PICKUP"
                                }
                            },
                            "cancellation_fee": {
                                "amount": {"currency": "INR", "value": "50.00"}
                            }
                        },
                        {
                            "fulfillment_state": {
                                "descriptor": {
                                    "code": "RIDE_ARRIVED_PICKUP"
                                }
                            },
                            "cancellation_fee": {
                                "amount": {"currency": "INR", "value": "100.00"}
                            }
                        },
                        {
                            "fulfillment_state": {
                                "descriptor": {
                                    "code": "RIDE_STARTED"
                                }
                            },
                            "cancellation_fee": {
                                "percentage": "20"
                            }
                        }
                    ]
                }
            }
        }

    def _send_init_request(self, step_name, payload, headers=None, expected_status=None):
        """
        Helper to send /init requests with consistent auth and error handling.

        Args:
            step_name: Locust step name (appears in reports).
            payload: Request payload dict.
            headers: Optional pre-built headers (auth generated if None).
            expected_status: List of acceptable status codes (default: [200, 202]).

        Returns:
            tuple: (success: bool, response_data: dict, status_code: int)
        """
        if headers is None:
            headers = self.auth_helper.generate_headers(payload)

        if expected_status is None:
            expected_status = [200, 202]

        serialized_body = headers.pop('serialized_body', None)
        if not serialized_body:
            serialized_body = json.dumps(payload, separators=(',', ':'), sort_keys=False, ensure_ascii=False)

        with self.client.post(
            name=step_name,
            url="/init",
            data=serialized_body.encode('utf-8'),
            headers={**headers, "Content-Type": "application/json; charset=utf-8"},
            catch_response=True
        ) as response:

            if response.status_code not in expected_status:
                response.failure(f"{step_name} Failed: Expected {expected_status}, got {response.status_code}")
                return False, None, response.status_code

            try:
                data = response.json() if response.content else {}
                response.success()
                return True, data, response.status_code
            except Exception as e:
                response.failure(f"{step_name} Failed: Error parsing response: {str(e)}")
                return False, None, response.status_code

    def _send_on_init_request(self, step_name, payload, headers=None, expected_status=None):
        """
        Helper to send /on_init callback requests with consistent auth and error handling.

        Args:
            step_name: Locust step name.
            payload: on_init callback payload dict.
            headers: Optional pre-built headers (auth generated if None).
            expected_status: List of acceptable status codes (default: [200, 202]).

        Returns:
            tuple: (success: bool, response_data: dict, status_code: int)
        """
        if headers is None:
            headers = self.auth_helper.generate_headers(payload)

        if expected_status is None:
            expected_status = [200, 202]

        serialized_body = headers.pop('serialized_body', None)
        if not serialized_body:
            serialized_body = json.dumps(payload, separators=(',', ':'), sort_keys=False, ensure_ascii=False)

        with self.client.post(
            name=step_name,
            url="/on_init",
            data=serialized_body.encode('utf-8'),
            headers={**headers, "Content-Type": "application/json; charset=utf-8"},
            catch_response=True
        ) as response:

            if response.status_code not in expected_status:
                response.failure(f"{step_name} Failed: Expected {expected_status}, got {response.status_code}")
                return False, None, response.status_code

            try:
                data = response.json() if response.content else {}
                response.success()
                return True, data, response.status_code
            except Exception as e:
                response.failure(f"{step_name} Failed: Error parsing response: {str(e)}")
                return False, None, response.status_code

    def _validate_ack_response(self, response_obj, data, test_name):
        """
        Validate ACK/NACK response from Gateway.

        Args:
            response_obj: Locust response object.
            data: Parsed JSON response.
            test_name: Test case name for error messages.

        Returns:
            bool: True if valid ACK, False otherwise.
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
        """Cleanup proxy after test ends."""
        if self.proxy:
            self.proxy.stop_capture()
