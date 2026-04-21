#!/usr/bin/env python3
"""
Register participant-1.participant.ondc as a BAP in UAT for Gateway testing
"""
import sys
import os
import json
import base64
import requests
from nacl.signing import SigningKey

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# UAT Admin API configuration
ADMIN_URL = "http://34.93.208.52"
ADMIN_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI2MjFlZTZiYi0zMDc1LTQ2MTQtODMyNC1lMzJjZTUxYjZjMzkiLCJlbWFpbCI6InVhdC1hZG1pbkBvbmRjLnRlc3QiLCJyb2xlIjoiU1VQRVJfQURNSU4iLCJyb2xlSWQiOiJkYjJlNDYxOS0wNDQ2LTQ0YzItOTNlNi1mYWJkNGIxOTlmNDciLCJpYXQiOjE3NzMxOTc5OTgsImV4cCI6MTc3NTc4OTk5OH0.7I314fWUstN_xFdBGeI79CDpv3OOhHFXn723O2Tjl8E"

# Gateway participant credentials from config
PARTICIPANT_ID = "participant-1.participant.ondc"
UK_ID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa1"
PRIVATE_KEY_SEED_B64 = "MC4CAQAwBQYDK2VwBCIEIPGt7Hv6vy2haK04ipiBbgU0omo/IGjs+hmuGE+jXkbf"
BAP_URI = "http://34.93.83.227:8081"

def decode_and_get_public_key(b64_key):
    """Decode base64 private key and extract public key"""
    decoded_bytes = base64.b64decode(b64_key)
    
    # Extract 32-byte seed
    if len(decoded_bytes) == 64:
        # NaCl-style 64-byte signing key: seed = first 32 bytes
        private_key_seed = decoded_bytes[:32]
    elif len(decoded_bytes) >= 32:
        # PKCS#8 DER format: the 32-byte seed is at the end
        private_key_seed = decoded_bytes[-32:]
    else:
        raise ValueError(f"Invalid key length: {len(decoded_bytes)}")
    
    # Generate SigningKey from seed
    signing_key = SigningKey(private_key_seed)
    
    # Get public key
    public_key_bytes = bytes(signing_key.verify_key)
    public_key_b64 = base64.b64encode(public_key_bytes).decode('utf-8')
    
    return public_key_b64, private_key_seed.hex()

def register_bap_participant():
    """Register participant-1.participant.ondc as BAP using Admin API"""
    print("\n" + "="*80)
    print("Registering Gateway BAP Participant in UAT")
    print("="*80)
    
    # Get public key from private key
    print("\n🔑 Generating public key from private key...")
    public_key_b64, private_key_hex = decode_and_get_public_key(PRIVATE_KEY_SEED_B64)
    print(f"   Public Key (base64): {public_key_b64}")
    print(f"   Private Key (hex): {private_key_hex[:32]}...{private_key_hex[-32:]}")
    
    # Create registration payload
    payload = {
        "participant_id": PARTICIPANT_ID,
        "action": "SUBSCRIBED",  # Register directly as SUBSCRIBED for immediate use
        "credentials": [
            {
                "cred_id": "cred_gst_001",
                "type": "GST",
                "cred_data": {
                    "gstin": "29ABCDE1234F1Z5",
                    "legal_name": "Gateway Test BAP Pvt Ltd"
                }
            },
            {
                "cred_id": "cred_pan_001",
                "type": "PAN",
                "cred_data": {
                    "pan": "ABCDE1234F",
                    "legal_name": "Gateway Test BAP Pvt Ltd"
                }
            }
        ],
        "contacts": [
            {
                "contact_id": "contact_tech_001",
                "type": "TECHNICAL",
                "name": "Tech Support",
                "email": "tech@gateway-test.ondc",
                "phone": "+919876543210",
                "designation": "Technical Lead"
            },
            {
                "contact_id": "contact_auth_001",
                "type": "AUTHORISED_SIGNATORY",
                "name": "Authorized Signatory",
                "email": "signatory@gateway-test.ondc",
                "phone": "+919876543211",
                "designation": "Authorized Signatory"
            },
            {
                "contact_id": "contact_business_001",
                "type": "BUSINESS",
                "name": "Business Contact",
                "email": "business@gateway-test.ondc",
                "phone": "+919876543212",
                "designation": "Business Manager"
            }
        ],
        "location": {
            "location_id": "loc001",
            "type": "SERVICEABLE",
            "country": "IND",
            "city": ["std:080", "std:022"]
        },
        "key": {
            "uk_id": UK_ID,
            "signing_public_key": public_key_b64,
            "encryption_public_key": public_key_b64,  # Same key for both
            "signed_algorithm": "ED25519",
            "encryption_algorithm": "X25519",
            "valid_from": "2026-03-01T00:00:00.000Z",
            "valid_until": "2030-12-31T23:59:59.000Z"
        },
        "uri": {
            "uri_id": "uri_callback_001",
            "type": "CALLBACK",
            "url": "https://httpbin.org/anything",  # Use HTTPS as required
            "description": "BAP Gateway callback endpoint"
        },
        "configs": [
            {
                "domain": "ONDC:RET10",
                "np_type": "BAP",
                "subscriber_id": PARTICIPANT_ID,
                "location_id": "loc001",
                "uri_id": "uri_callback_001",
                "key_id": UK_ID
            },
            {
                "domain": "ONDC:RET16",
                "np_type": "BAP",
                "subscriber_id": PARTICIPANT_ID,
                "location_id": "loc001",
                "uri_id": "uri_callback_001",
                "key_id": UK_ID
            }
        ]
    }
    
    print(f"\n📝 Registration Payload:")
    print(f"   Participant ID: {PARTICIPANT_ID}")
    print(f"   UK ID: {UK_ID}")
    print(f"   Type: BAP (Buyer App)")
    print(f"   Status: SUBSCRIBED")
    print(f"   Callback URL: https://httpbin.org/anything")
    print(f"   Domains: ONDC:RET10, ONDC:RET16")
    print(f"   Location: std:080, std:022")
    
    # Send registration request
    print(f"\n📤 Sending request to: {ADMIN_URL}/admin/subscribe")
    
    try:
        response = requests.post(
            f"{ADMIN_URL}/admin/subscribe",
            json=payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {ADMIN_TOKEN}"
            },
            timeout=15
        )
        
        print(f"\n✅ Response received:")
        print(f"   Status Code: {response.status_code}")
        
        try:
            response_data = response.json()
            print(f"\n📥 Response Body:")
            print(json.dumps(response_data, indent=2))
            
            # Check response
            if response.status_code == 200:
                ack_status = response_data.get('message', {}).get('ack', {}).get('status')
                if ack_status == 'ACK':
                    print(f"\n✅ SUCCESS: Participant registered successfully!")
                    print(f"\n🎉 participant-1.participant.ondc is now registered as BAP in UAT")
                    print(f"\nNext steps:")
                    print(f"  1. Gateway can now authenticate with this participant")
                    print(f"  2. Run gateway tests: python driver.py --test ondc_gateway_search_functional --environment ondcGatewaySearch")
                    return True
                else:
                    error = response_data.get('error', {})
                    print(f"\n❌ FAILURE: Registration rejected (NACK)")
                    print(f"   Error Code: {error.get('code')}")
                    print(f"   Error Type: {error.get('type')}")
                    print(f"   Error Message: {error.get('message')}")
                    return False
            else:
                print(f"\n❌ FAILURE: Unexpected status code {response.status_code}")
                return False
                
        except ValueError:
            print(f"\n❌ Non-JSON response:")
            print(response.text[:500])
            return False
            
    except requests.exceptions.RequestException as e:
        print(f"\n❌ Request failed: {str(e)}")
        return False

def verify_registration():
    """Verify the participant is now in the registry"""
    print("\n" + "="*80)
    print("Verifying Registration in Registry")
    print("="*80)
    
    try:
        response = requests.post(
            "http://35.200.145.160:8080/lookup",
            json={
                "country": "IND",
                "type": "BAP",
                "domain": "ONDC:RET10",
                "city": "*"
            },
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        
        if response.status_code == 200:
            participants = response.json()
            found = [p for p in participants if p.get('subscriber_id') == PARTICIPANT_ID]
            
            if found:
                print(f"\n✅ Verification SUCCESS!")
                print(f"\nParticipant found in UAT Registry:")
                print(json.dumps(found[0], indent=2))
                return True
            else:
                print(f"\n⚠️  Participant not found in lookup yet (may take a few seconds to sync)")
                print(f"   Total BAP participants found: {len(participants)}")
                return False
        else:
            print(f"\n⚠️  Lookup returned status {response.status_code}")
            return False
            
    except Exception as e:
        print(f"\n⚠️  Verification failed: {str(e)}")
        return False

if __name__ == "__main__":
    success = register_bap_participant()
    
    if success:
        print("\n" + "="*80)
        print("Waiting 3 seconds for registry sync...")
        print("="*80)
        import time
        time.sleep(3)
        verify_registration()
    
    sys.exit(0 if success else 1)
