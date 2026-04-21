#!/usr/bin/env python3
"""
Create a fresh test participant with unique credentials
Uses a publicly accessible URL to pass validation
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import requests
import json
import uuid
from nacl.signing import SigningKey
from nacl.encoding import Base64Encoder
from tests.utils.registry_auth_client import RegistryAuthClient

def create_and_register_participant():
    """Create a new participant with fresh credentials and register it"""
    
    # Subscribe server (has admin API)
    subscribe_host = "http://34.14.152.92"
    admin_username = "<admin-user>"
    admin_password = "admin"
    
    # Generate fresh Ed25519 keypair
    print("\n" + "="*60)
    print("CREATING FRESH TEST PARTICIPANT")
    print("="*60)
    
    print("\n[1/4] Generating Ed25519 keypair...")
    signing_key = SigningKey.generate()
    signing_key_bytes = bytes(signing_key)  # 32-byte seed
    verify_key = signing_key.verify_key
    
    # Convert to base64
    private_key_seed = signing_key_bytes.hex()
    public_key_b64 = verify_key.encode(Base64Encoder).decode('utf-8')
    
    # Generate unique participant ID
    session_suffix = str(uuid.uuid4())[:8]
    participant_id = f"test-qa-{session_suffix}.participant.ondc"
    uk_id = str(uuid.uuid4())
    
    print(f"✅ Generated keypair")
    print(f"   Participant ID: {participant_id}")
    print(f"   UK ID: {uk_id}")
    print(f"   Private Key Seed: {private_key_seed}")
    print(f"   Public Key: {public_key_b64}")
    
    # Get admin token
    print(f"\n[2/4] Getting admin token...")
    auth_client = RegistryAuthClient(subscribe_host, admin_username, admin_password)
    
    try:
        token = auth_client.get_token()
        print(f"✅ Token obtained")
    except Exception as e:
        print(f"❌ Failed to get token: {e}")
        return None
    
    # Generate IDs for references
    key_id = uk_id
    location_id = f"loc_{uk_id[:8]}"
    uri_id = f"uri_{uk_id[:8]}"
    cred_gst_id = f"cred_{uk_id[:8]}_gst"
    cred_pan_id = f"cred_{uk_id[:8]}_pan"
    contact_tech_id = f"contact_{uk_id[:8]}_tech"
    contact_auth_id = f"contact_{uk_id[:8]}_auth"
    contact_biz_id = f"contact_{uk_id[:8]}_biz"
    
    # Use a known reachable URL for validation (google.com for testing)
    # In production, this would be the actual participant's callback endpoint
    test_url = "https://www.google.com"
    
    print(f"\n[3/4] Preparing registration payload...")
    print(f"   Using test URL: {test_url}")
    print(f"   (Note: This passes validation but won't receive callbacks)")
    
    # Admin API payload
    payload = {
        "participant_id": participant_id,
        "action": "SUBSCRIBED",
        "credentials": [
            {
                "cred_id": cred_gst_id,
                "type": "GST",
                "cred_data": {
                    "pan": "ABCDE1234F",
                    "gstin": "22ABCDE1234F1Z5",
                    "business_name": f"Test QA Participant {session_suffix}"
                }
            },
            {
                "cred_id": cred_pan_id,
                "type": "PAN",
                "cred_data": {
                    "pan": "ABCDE1234F",
                    "name": "Test Business Owner"
                }
            }
        ],
        "contacts": [
            {
                "contact_id": contact_tech_id,
                "type": "TECHNICAL",
                "name": "Tech Admin",
                "email": f"tech-{session_suffix}@testqa.ondc.org",
                "phone": "+919876543210",
                "address": "123 Test Street, Bangalore",
                "designation": "Technical Lead",
                "is_primary": True
            },
            {
                "contact_id": contact_auth_id,
                "type": "AUTHORISED_SIGNATORY",
                "name": "Authorized Signatory",
                "email": f"auth-{session_suffix}@testqa.ondc.org",
                "phone": "+919876543211",
                "designation": "Authorized Signatory",
                "is_primary": False
            },
            {
                "contact_id": contact_biz_id,
                "type": "BUSINESS",
                "name": "Business Manager",
                "email": f"biz-{session_suffix}@testqa.ondc.org",
                "phone": "+919876543212",
                "designation": "Business Head",
                "is_primary": False
            }
        ],
        "key": {
            "uk_id": key_id,
            "signing_public_key": public_key_b64,
            "encryption_public_key": public_key_b64,  # Using same key for both
            "signed_algorithm": "ED25519",
            "encryption_algorithm": "X25519",
            "valid_from": "2026-02-01T00:00:00.000Z",
            "valid_until": "2030-12-31T23:59:59.000Z"
        },
        "location": {
            "location_id": location_id,
            "country": "IND",
            "city": ["std:080"],
            "type": "SERVICEABLE"
        },
        "uri": {
            "uri_id": uri_id,
            "type": "CALLBACK",
            "url": test_url
        },
        "configs": [
            {
                "domain": "ONDC:RET10",
                "np_type": "BPP",
                "subscriber_id": participant_id,
                "location_id": location_id,
                "uri_id": uri_id,
                "key_id": key_id
            }
        ]
    }
    
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }
    
    print(f"\n[4/4] Registering participant...")
    
    try:
        response = requests.post(
            f"{subscribe_host}/admin/subscribe",
            json=payload,
            headers=headers,
            timeout=30
        )
        
        print(f"\nResponse Status: {response.status_code}")
        
        if response.status_code in [200, 201]:
            print(f"✅ SUCCESS: Participant registered!")
            
            # Save credentials to file
            creds = {
                "participant_id": participant_id,
                "uk_id": uk_id,
                "private_key_seed": private_key_seed,
                "signing_public_key": public_key_b64,
                "encryption_public_key": public_key_b64
            }
            
            # Print credentials for manual update
            print("\n" + "="*60)
            print("PARTICIPANT CREDENTIALS (Save these!)")
            print("="*60)
            print(f"\nAdd this to your test config YAML:\n")
            print(f"  participant_id: \"{participant_id}\"")
            print(f"  uk_id: \"{uk_id}\"")
            print(f"  private_key_seed: \"{private_key_seed}\"")
            print(f"  signing_public_key: \"{public_key_b64}\"")
            print(f"  encryption_public_key: \"{public_key_b64}\"")
            print("\n" + "="*60)
            
            return creds
            
        elif response.status_code == 400:
            error_data = response.json()
            print(f"Response: {json.dumps(error_data, indent=2)}")
            
            if "already exists" in str(error_data).lower():
                print(f"⚠️  Participant already exists")
                return None
            else:
                error_msg = error_data.get('error', {}).get('message', 'Unknown error')
                print(f"❌ Registration failed: {error_msg}")
                return None
        else:
            print(f"❌ Unexpected status {response.status_code}")
            print(f"Response: {response.text}")
            return None
            
    except Exception as e:
        print(f"❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
        return None

if __name__ == '__main__':
    creds = create_and_register_participant()
    sys.exit(0 if creds else 1)
