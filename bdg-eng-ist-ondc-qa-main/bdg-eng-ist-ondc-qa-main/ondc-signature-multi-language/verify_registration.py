#!/usr/bin/env python3
"""
Verify participant registration and run full test with lookup verification
"""

import json
import requests
import urllib3
from datetime import datetime

urllib3.disable_warnings()

def check_participant():
    """Check if participant is properly registered"""
    print("=" * 80)
    print("VERIFYING PARTICIPANT REGISTRATION")
    print("=" * 80)
    
    # Load credentials
    with open('shared/test-credentials.json') as f:
        creds = json.load(f)['uat']
    
    subscriber_id = creds['subscriber_id']
    
    print(f"\nParticipant: {subscriber_id}")
    print(f"Domain: ONDC:RET10")
    print(f"\nChecking registration status...")
    
    # Check lookup
    try:
        response = requests.post(
            "https://registry-uat.kynondc.net/v3.0/lookup",
            json={"subscriber_id": subscriber_id, "domain": "ONDC:RET10"},
            headers={'Content-Type': 'application/json'},
            timeout=10
        )
        
        print(f"\nStatus Code: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"\n✅ SUCCESS! Participant is registered and active!")
            print(f"\nParticipant Details:")
            if isinstance(data, list) and len(data) > 0:
                participant = data[0]
                print(f"  Participant ID: {participant.get('participant_id')}")
                print(f"  Subscriber ID: {participant.get('subscriber_id')}")
                print(f"  NP Type: {participant.get('np_type')}")
                print(f"  Created: {participant.get('created_at')}")
                print(f"  Updated: {participant.get('updated_at')}")
            print("\n" + "=" * 80)
            print("✅ Ready to run full tests with 200 responses!")
            print("=" * 80)
            return True
        elif response.status_code == 404:
            print(f"\n⚠️  Participant not found (404)")
            print(f"Response: {response.text}")
            print(f"\n" + "=" * 80)
            print("MANUAL REGISTRATION REQUIRED")
            print("=" * 80)
            print(f"\nPlease register the participant manually:")
            print(f"\n1. Visit ONDC UAT Portal")
            print(f"2. Register participant: {subscriber_id}")
            print(f"3. Domain: ONDC:RET10")
            print(f"4. Public Key: Use the key from shared/test-credentials.json")
            print(f"\nOnce registered, run this script again to verify.")
            print("=" * 80)
            return False
        else:
            print(f"\n⚠️  Unexpected response: {response.status_code}")
            print(f"Response: {response.text}")
            return False
            
    except Exception as e:
        print(f"\n❌ Error checking registration: {e}")
        return False

if __name__ == "__main__":
    if check_participant():
        print("\n✅ You can now run ./run-tests.sh to get 200 responses!")
    else:
        print("\n⚠️  Please complete manual registration first")
