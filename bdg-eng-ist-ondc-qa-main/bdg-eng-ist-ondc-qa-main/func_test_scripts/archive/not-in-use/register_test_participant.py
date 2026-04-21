#!/usr/bin/env python3
"""
Register test participant for V3 lookup tests
Registers on subscribe server (34.14.152.92) so it's available on lookup server (35.200.190.239:8080)
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import requests
import yaml
from tests.utils.registry_auth_client import RegistryAuthClient

def register_participant():
    """Register test participant via admin API"""
    
    # Load config
    config_file = 'resources/registry/lookup/v3/test_lookup_functional.yml'
    with open(config_file, 'r') as f:
        config_data = yaml.safe_load(f)
        config = config_data.get('ondcRegistry', {})
    
    # Subscribe server (has admin API)
    subscribe_host = "http://34.14.152.92"
    
    # Get credentials
    participant_id = config.get('participant_id')
    uk_id = config.get('uk_id')
    signing_public_key = config.get('signing_public_key')
    encryption_public_key = config.get('encryption_public_key')
    admin_username = config.get('admin_username')
    admin_password = config.get('admin_password')
    
    print(f"\n========================================")
    print(f"Registering Test Participant")
    print(f"========================================")
    print(f"Participant ID: {participant_id}")
    print(f"UK ID: {uk_id}")
    print(f"Subscribe Server: {subscribe_host}")
    print(f"========================================\n")
    
    # Get admin token
    print("[1/2] Getting admin token...")
    auth_client = RegistryAuthClient(subscribe_host, admin_username, admin_password)
    
    try:
        token = auth_client.get_token()
        print(f"✅ Token obtained: {token[:30]}...")
    except Exception as e:
        print(f"❌ Failed to get token: {e}")
        return False
    
    # Register participant
    print(f"\n[2/2] Registering participant...")
    
    # Generate IDs for references
    key_id = uk_id
    location_id = f"loc_{uk_id[:8]}"
    uri_id = f"uri_{uk_id[:8]}"
    cred_gst_id = f"cred_{uk_id[:8]}_gst"
    cred_pan_id = f"cred_{uk_id[:8]}_pan"
    contact_tech_id = f"contact_{uk_id[:8]}_tech"
    contact_auth_id = f"contact_{uk_id[:8]}_auth"
    contact_biz_id = f"contact_{uk_id[:8]}_biz"
    
    # Admin API V3 requires proper schema with credentials, contacts, location, uri, configs
    payload = {
        "participant_id": participant_id,
        "action": "SUBSCRIBED",  # Admin API action
        "credentials": [
            {
                "cred_id": cred_gst_id,
                "type": "GST",
                "cred_data": {
                    "pan": "ABCDE1234F",
                    "gstin": "22ABCDE1234F1Z5",
                    "business_name": "Test Lookup Business Ltd"
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
                "email": "tech@testlookup.example.com",
                "phone": "+919876543210",
                "address": "123 Tech Street, Bangalore",
                "designation": "Technical Lead",
                "is_primary": True
            },
            {
                "contact_id": contact_auth_id,
                "type": "AUTHORISED_SIGNATORY",
                "name": "Authorized Signatory",
                "email": "auth@testlookup.example.com",
                "phone": "+919876543211",
                "designation": "Authorized Signatory",
                "is_primary": False
            },
            {
                "contact_id": contact_biz_id,
                "type": "BUSINESS",
                "name": "Business Manager",
                "email": "business@testlookup.example.com",
                "phone": "+919876543212",
                "designation": "Business Head",
                "is_primary": False
            }
        ],
        "key": {
            "uk_id": key_id,
            "signing_public_key": signing_public_key,
            "encryption_public_key": encryption_public_key,
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
            "url": f"https://{participant_id.split('.')[0]}.example.com/ondc"
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
    
    try:
        response = requests.post(
            f"{subscribe_host}/admin/subscribe",
            json=payload,
            headers=headers,
            timeout=30
        )
        
        print(f"\nResponse Status: {response.status_code}")
        print(f"Response Body: {response.text}")
        
        if response.status_code in [200, 201]:
            print(f"\n✅ SUCCESS: Participant registered as SUBSCRIBED")
            print(f"\n📝 Next steps:")
            print(f"   1. Participant is now in the database")
            print(f"   2. V3 lookup tests on 35.200.190.239:8080 will find this participant")
            print(f"   3. Run: python driver.py --test ondc_reg_lookup_functional")
            return True
        elif response.status_code == 400:
            try:
                error = response.json()
                if "already exists" in str(error).lower():
                    print(f"\n✅ ALREADY EXISTS: Participant already registered")
                    print(f"   This is OK - we can use it for lookup tests")
                    return True
                else:
                    print(f"\n⚠️  Registration error: {error}")
                    return False
            except:
                print(f"\n⚠️  Registration error (status 400)")
                return False
        else:
            print(f"\n❌ FAILED: Unexpected status {response.status_code}")
            return False
            
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == '__main__':
    success = register_participant()
    sys.exit(0 if success else 1)
