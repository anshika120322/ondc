#!/usr/bin/env python3
"""
Test if UAT Gateway expects signature in context instead of HTTP headers
"""
import sys
import os
import json
import uuid
import requests
from datetime import datetime, timezone

# UAT Gateway configuration  
GATEWAY_URL = "http://34.100.154.102:8080"
PARTICIPANT_ID = "participant-1.participant.ondc"
BAP_URI = "http://34.93.83.227:8081"

def test_no_auth_header():
    """Test Gateway with NO Authorization header (signature in context)"""
    print("\n" + "="*80)
    print("Test 1: Sending WITHOUT Authorization Header")
    print("="*80)
    
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
    
    print(f"📤 Sending request with NO auth header")
    
    try:
        response = requests.post(
            f"{GATEWAY_URL}/search",
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        
        print(f"✅ Response: {response.status_code}")
        print(json.dumps(response.json(), indent=2))
        
        return response.status_code, response.json()
    except Exception as e:
        print(f"❌ Error: {e}")
        return None, None

def test_with_x_gateway_authorization():
    """Test if Gateway uses X-Gateway-Authorization instead of Authorization"""
    print("\n" + "="*80)
    print("Test 2: Using X-Gateway-Authorization Header")
    print("="*80)
    
    # Simplified test - just testing header name
    payload = {"test": "data"}
    
    headers = {
        "Content-Type": "application/json",
        "X-Gateway-Authorization": "test"
    }
    
    print(f"📤 Sending with X-Gateway-Authorization header")
    
    try:
        response = requests.post(
            f"{GATEWAY_URL}/search",
            json=payload,
            headers=headers,
            timeout=10
        )
        
        print(f"✅ Response: {response.status_code}")
        print(json.dumps(response.json(), indent=2))
        
        return response.status_code
    except Exception as e:
        print(f"❌ Error: {e}")
        return None

if __name__ == "__main__":
    # Test 1: No auth header (should get 401)
    status1, data1 = test_no_auth_header()
    
    # Test 2: Different header name
    status2 = test_with_x_gateway_authorization()
    
    print("\n" + "="*80)
    print("Summary:")
    print("="*80)
    print(f"Test 1 (No auth): {status1}")
    print(f"Test 2 (X-Gateway-Authorization): {status2}")
    
    if status1 == 401:
        print("\n✅ Gateway requires authentication (401 without auth)")
    elif status1 == 200 or status1 == 202:
        print("\n⚠️  Gateway accepted request without authentication!")
