#!/usr/bin/env python3
"""
Complete Gateway functionality test - UAT Environment
Tests /search endpoint with different scenarios
"""
import sys
import os
import json
import uuid
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from tests.utils.ondc_auth_helper import ONDCAuthHelper
import requests

# UAT Gateway configuration
GATEWAY_URL = "http://34.100.154.102:8080"
PARTICIPANT_ID = "participant-1.participant.ondc"
UK_ID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa1"
PRIVATE_KEY_SEED_B64 = "MC4CAQAwBQYDK2VwBCIEIPGt7Hv6vy2haK04ipiBbgU0omo/IGjs+hmuGE+jXkbf"
BAP_URI = "http://34.93.83.227:8081"

def decode_private_key(b64_key):
    """Decode base64 private key to 32-byte seed"""
    import base64
    decoded_bytes = base64.b64decode(b64_key)
    if len(decoded_bytes) >= 32:
        return decoded_bytes[-32:]
    else:
        raise ValueError(f"Invalid key length: {len(decoded_bytes)}")

PRIVATE_KEY_SEED = decode_private_key(PRIVATE_KEY_SEED_B64)

def create_search_payload(domain="ONDC:RET10", city="std:080", search_term="laptop"):
    """Create a /search payload"""
    txn_id = f"txn-{uuid.uuid4().hex[:12]}"
    msg_id = f"msg-{uuid.uuid4().hex[:12]}"
    timestamp = datetime.now(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')
    
    return {
        "context": {
            "domain": domain,
            "action": "search",
            "country": "IND",
            "city": city,
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
                        "name": search_term
                    }
                }
            }
        }
    }

def test_search(test_name, payload):
    """Test Gateway /search endpoint"""
    auth_helper = ONDCAuthHelper(
        participant_id=PARTICIPANT_ID,
        uk_id=UK_ID,
        private_key_seed=PRIVATE_KEY_SEED
    )
    
    # Generate headers WITH digest (required by Gateway)
    headers = auth_helper.generate_headers(payload, include_digest=True)
    serialized_body = headers.pop('serialized_body', None)
    
    if not serialized_body:
        serialized_body = json.dumps(payload, separators=(',', ':'), sort_keys=False, ensure_ascii=False)
    
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
        
        if response.status_code == 200:
            try:
                response_data = response.json()
                ack_status = response_data.get('message', {}).get('ack', {}).get('status')
                if ack_status == 'ACK':
                    print(f"✅ {test_name}: PASS (ACK)")
                    return True
                else:
                    print(f"❌ {test_name}: FAIL (NACK)")
                    return False
            except:
                print(f"✅ {test_name}: PASS (Status 200)")
                return True
        else:
            print(f"❌ {test_name}: FAIL (Status {response.status_code})")
            try:
                error = response.json()
                print(f"   Error: {error}")
            except:
                pass
            return False
            
    except Exception as e:
        print(f"❌ {test_name}: FAIL (Exception: {str(e)})")
        return False

def main():
    """Run comprehensive Gateway tests"""
    print("="*80)
    print("UAT GATEWAY FUNCTIONAL TESTS")
    print(f"Gateway: {GATEWAY_URL}")
    print(f"Participant: {PARTICIPANT_ID}")
    print("="*80)
    
    tests = [
        ("TC-001: Basic Search - Grocery Domain", 
         create_search_payload("ONDC:RET10", "std:080", "laptop")),
        
        ("TC-002: Search - Health & Wellness Domain", 
         create_search_payload("ONDC:RET16", "std:080", "medicine")),
        
        ("TC-003: Search - Different City (Mumbai)", 
         create_search_payload("ONDC:RET10", "std:022", "mobile")),
        
        ("TC-004: Search - Different City (Delhi)", 
         create_search_payload("ONDC:RET10", "std:011", "shirt")),
        
        ("TC-005: Search - Bangalore Grocery", 
         create_search_payload("ONDC:RET10", "std:080", "rice")),
    ]
    
    total = len(tests)
    passed = 0
    
    print(f"\nRunning {total} test cases...\n")
    
    for test_name, payload in tests:
        if test_search(test_name, payload):
            passed += 1
        print()
    
    print("="*80)
    print(f"RESULTS: {passed}/{total} tests passed ({100*passed//total}%)")
    print("="*80)
    
    return 0 if passed == total else 1

if __name__ == "__main__":
    sys.exit(main())
