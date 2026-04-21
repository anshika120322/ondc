#!/usr/bin/env python3
"""
Ensure test participant exists before running tests
Can be run standalone or imported by test scripts
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import requests
import json
from scripts.register_test_participant import register_participant

def check_participant_exists(participant_id="test-v3-feb2026-fresh.participant.ondc"):
    """
    Check if participant exists in V1 lookup API
    Returns: (exists: bool, count: int)
    """
    lookup_url = "http://35.200.190.239:8080/lookup"
    
    payload = {
        "subscriber_id": participant_id,
        "country": "IND"
    }
    
    try:
        response = requests.post(
            lookup_url,
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            found = any(
                participant_id.lower() in str(item.get('subscriber_id', '')).lower()
                for item in data
            )
            return found, len(data)
        else:
            return False, 0
            
    except Exception as e:
        print(f"⚠️  Warning: Could not check participant status: {e}")
        return False, 0


def ensure_participant_registered(force_register=False):
    """
    Ensure test participant is registered
    If not found, registers it automatically
    
    Args:
        force_register: If True, always register (even if exists)
    
    Returns:
        bool: True if participant is available, False otherwise
    """
    participant_id = "test-v3-feb2026-fresh.participant.ondc"
    
    print("\n" + "="*60)
    print("ENSURING TEST PARTICIPANT IS AVAILABLE")
    print("="*60)
    
    if not force_register:
        print(f"\n[1/2] Checking if participant exists: {participant_id}")
        exists, total = check_participant_exists(participant_id)
        
        if exists:
            print(f"✅ Participant found in lookup database ({total} total participants)")
            print("="*60 + "\n")
            return True
        else:
            print(f"❌ Participant not found ({total} participants in DB)")
            print("⚠️  Will attempt to register participant...\n")
    else:
        print("🔄 Force registration requested\n")
    
    # Register participant
    print("[2/2] Registering participant via admin API...")
    success = register_participant()
    
    if success:
        print("\n✅ Registration completed!")
        print("⏳ Waiting 5 seconds for cache refresh...")
        import time
        time.sleep(5)
        
        # Verify registration
        exists, total = check_participant_exists(participant_id)
        if exists:
            print(f"✅ Participant verified in lookup database")
            print("="*60 + "\n")
            return True
        else:
            print(f"⚠️  Participant registered but not yet visible in lookup")
            print(f"   This may be a cache delay. Tests may still work.")
            print("="*60 + "\n")
            return True  # Return True anyway, might just be cache delay
    else:
        print("\n❌ Failed to register participant")
        print("="*60 + "\n")
        return False


if __name__ == "__main__":
    """Run as standalone script"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Ensure test participant is registered for V3 lookup tests"
    )
    parser.add_argument(
        '--force',
        action='store_true',
        help='Force re-registration even if participant exists'
    )
    parser.add_argument(
        '--check-only',
        action='store_true',
        help='Only check if participant exists, do not register'
    )
    
    args = parser.parse_args()
    
    if args.check_only:
        print("\n" + "="*60)
        print("CHECKING TEST PARTICIPANT STATUS")
        print("="*60)
        participant_id = "test-v3-feb2026-fresh.participant.ondc"
        exists, total = check_participant_exists(participant_id)
        print(f"\nParticipant: {participant_id}")
        print(f"Status: {'✅ FOUND' if exists else '❌ NOT FOUND'}")
        print(f"Total participants in DB: {total}")
        print("="*60 + "\n")
        sys.exit(0 if exists else 1)
    
    success = ensure_participant_registered(force_register=args.force)
    sys.exit(0 if success else 1)
