#!/usr/bin/env python3
"""
Test UAT Gateway connectivity with proper ONDC authentication
"""
import sys
import os
import json
import time
import uuid
import base64
import requests
from datetime import datetime, timezone

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from tests.utils.ondc_auth_helper import ONDCAuthHelper

# UAT Gateway configuration
GATEWAY_URL = "http://34.100.154.102:8080"
PARTICIPANT_ID = "participant-1.participant.ondc"
UK_ID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa1"
PRIVATE_KEY_SEED_B64 = "MC4CAQAwBQYDK2VwBCIEIPGt7Hv6vy2haK04ipiBbgU0omo/IGjs+hmuGE+jXkbf"
BAP_URI = "http://34.93.83.227:8081"

def decode_private_key(b64_key):
    """Decode base64 private key to 32-byte seed"""
    decoded_bytes = base64.b64decode(b64_key)
    if len(decoded_bytes) == 64:
        # NaCl-style 64-byte signing key: seed = first 32 bytes
        return decoded_bytes[:32]
    elif len(decoded_bytes) >= 32:
        # PKCS#8 DER format: the 32-byte seed is at the end
        return decoded_bytes[-32:]
    else:
        raise ValueError(f"Invalid key length: {len(decoded_bytes)}")

PRIVATE_KEY_SEED = decode_private_key(PRIVATE_KEY_SEED_B64)

def create_search_payload():
    """Create a minimal /search payload"""
    txn_id = f"txn-{uuid.uuid4().hex[:12]}"
    msg_id = f"msg-{uuid.uuid4().hex[:12]}"
    timestamp = datetime.now(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')
    
    payload = {
        "context": {
            "domain": "ONDC:RET10",
            "action": "search",
            "country": "IND",
            "city": "std:080",
            "core_version": "1.2.0",
            "bap_id": PARTICIPANT_ID,
            "bap_uri": BAP_URI,
            "transaction_id": txn_id,
            "message_id": msg_id,
            "timestamp": timestamp,
            "ttl": "PT30S"
        },
        "message": {
            "intent": {
                "fulfillment": {
                    "type": "Delivery",
                    "end": {
                        "location": {
                            "gps": "12.9716,77.5946"
                        }
                    }
                },
                "payment": {
                    "@ondc/org/buyer_app_finder_fee_type": "percent",
                    "@ondc/org/buyer_app_finder_fee_amount": "3.0"
                },
                "category": {
                    "descriptor": {
                        "name": "laptop"
                    }
                }
            }
        }
    }
    
    return payload

def test_gateway_search():
    """Test Gateway /search endpoint with proper authentication"""
    print("\n" + "="*80)
    print("Testing UAT Gateway /search endpoint")
    print("="*80)
    
    # Setup authentication
    auth_helper = ONDCAuthHelper(
        participant_id=PARTICIPANT_ID,
        uk_id=UK_ID,
        private_key_seed=PRIVATE_KEY_SEED
    )
    
    # Create payload
    payload = create_search_payload()
    print(f"\n📝 Payload created:")
    print(f"   Transaction ID: {payload['context']['transaction_id']}")
    print(f"   Message ID: {payload['context']['message_id']}")
    print(f"   BAP ID: {payload['context']['bap_id']}")
    print(f"   BAP URI: {payload['context']['bap_uri']}")
    print(f"   Domain: {payload['context']['domain']}")
    print(f"   City: {payload['context']['city']}")
    
    # Generate headers WITH digest (Gateway requires it)
    headers = auth_helper.generate_headers(payload, include_digest=True)
    serialized_body = headers.pop('serialized_body', None)
    
    if not serialized_body:
        serialized_body = json.dumps(payload, separators=(',', ':'), sort_keys=False, ensure_ascii=False)
    
    print(f"\n🔐 Full Authorization Header:")
    print(f"   {headers['Authorization']}")
    
    print(f"\n📝 Other Headers:")
    for key, value in headers.items():
        if key != 'Authorization':
            print(f"   {key}: {value}")
    
    print(f"\n📤 Sending request to: {GATEWAY_URL}/search")
    print(f"   Payload size: {len(serialized_body)} bytes")
    
    # Send request
    try:
        response = requests.post(
            f"{GATEWAY_URL}/search",
            data=serialized_body.encode('utf-8'),
            headers={
                **headers,
                "Content-Type": "application/json; charset=utf-8"
            },
            timeout=10
        )
        
        print(f"\n✅ Response received:")
        print(f"   Status Code: {response.status_code}")
        print(f"   Headers: {dict(response.headers)}")
        
        try:
            response_data = response.json()
            print(f"\n📥 Response Body:")
            print(json.dumps(response_data, indent=2))
            
            # Check if ACK or NACK
            ack_status = response_data.get('message', {}).get('ack', {}).get('status')
            if ack_status == 'ACK':
                print(f"\n✅ SUCCESS: Gateway accepted the request (ACK)")
                return True
            elif ack_status == 'NACK':
                error = response_data.get('error', {})
                print(f"\n❌ FAILURE: Gateway rejected the request (NACK)")
                print(f"   Error Code: {error.get('code')}")
                print(f"   Error Type: {error.get('type')}")
                print(f"   Error Message: {error.get('message')}")
                return False
            else:
                print(f"\n⚠️  UNEXPECTED: Unknown response format")
                return False
                
        except ValueError:
            print(f"\n❌ Non-JSON response:")
            print(response.text[:500])
            return False
            
    except requests.exceptions.RequestException as e:
        print(f"\n❌ Request failed: {str(e)}")
        return False

if __name__ == "__main__":
    success = test_gateway_search()
    sys.exit(0 if success else 1)
