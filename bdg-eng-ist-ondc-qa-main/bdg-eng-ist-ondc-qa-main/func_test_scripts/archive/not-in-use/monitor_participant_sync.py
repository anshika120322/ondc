#!/usr/bin/env python3
"""
Monitor participant sync between subscribe and lookup servers
Checks every 30 seconds to see when participant appears in lookup database
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import time
import requests
import yaml
from datetime import datetime

# Load config
with open('resources/registry/ondc_reg_lookup_functional.yml', 'r') as f:
    config = yaml.safe_load(f)['ondcRegistry']

participant_id = config['participant_id']
lookup_server = "http://35.200.190.239:8080"
check_interval = 30  # seconds

def check_participant_exists():
    """Check if participant exists in V1 lookup"""
    try:
        response = requests.post(
            f"{lookup_server}/lookup",
            json={
                "subscriber_id": participant_id,
                "country": "IND"
            },
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            if isinstance(data, list):
                for item in data:
                    if participant_id.lower() in str(item.get('subscriber_id', '')).lower():
                        return True, item
        return False, None
    except Exception as e:
        return False, f"Error: {e}"

def format_duration(seconds):
    """Format duration in human readable format"""
    if seconds < 60:
        return f"{seconds}s"
    elif seconds < 3600:
        return f"{seconds//60}m {seconds%60}s"
    else:
        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        return f"{hours}h {minutes}m"

print("\n" + "="*80)
print("MONITORING PARTICIPANT SYNC STATUS")
print("="*80)
print(f"Participant: {participant_id}")
print(f"Lookup Server: {lookup_server}")
print(f"Check Interval: {check_interval} seconds")
print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print("="*80)
print("\nPress Ctrl+C to stop monitoring\n")

start_time = time.time()
check_count = 0

try:
    while True:
        check_count += 1
        elapsed = int(time.time() - start_time)
        timestamp = datetime.now().strftime('%H:%M:%S')
        
        print(f"[{timestamp}] Check #{check_count} (elapsed: {format_duration(elapsed)})...", end=' ', flush=True)
        
        exists, data = check_participant_exists()
        
        if exists:
            print("✅ FOUND!")
            print("\n" + "="*80)
            print("PARTICIPANT SYNCED TO LOOKUP SERVER")
            print("="*80)
            print(f"Time taken: {format_duration(elapsed)}")
            print(f"Total checks: {check_count}")
            print(f"\nParticipant Details:")
            if isinstance(data, dict):
                print(f"  Subscriber ID: {data.get('subscriber_id')}")
                print(f"  Status: {data.get('status')}")
                print(f"  UK ID: {data.get('ukId')}")
                print(f"  Domain: {data.get('domain')}")
                print(f"  Type: {data.get('type')}")
                print(f"  Created: {data.get('created')}")
                print(f"  Updated: {data.get('updated')}")
            print("\n✅ You can now run negative tests!")
            print(f"   python driver.py --test ondc_reg_lookup_negative --iterations 2")
            print("="*80 + "\n")
            sys.exit(0)
        else:
            print("❌ Not found")
        
        # Wait before next check
        if check_count < 10:
            # Check more frequently in first 5 minutes
            time.sleep(check_interval)
        else:
            # After 5 minutes, check every minute
            time.sleep(60)
            
except KeyboardInterrupt:
    print("\n\n" + "="*80)
    print("MONITORING STOPPED")
    print("="*80)
    print(f"Total time: {format_duration(int(time.time() - start_time))}")
    print(f"Total checks: {check_count}")
    print(f"Status: Participant not yet synced")
    print("="*80 + "\n")
    sys.exit(0)
