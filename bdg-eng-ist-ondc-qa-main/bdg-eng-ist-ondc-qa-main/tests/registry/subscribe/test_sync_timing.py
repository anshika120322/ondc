from locust import task, HttpUser, events
from tests.registry.subscribe.common.base_subscribe_test import RegistrySubscribeBase
import time
import uuid
import json
from datetime import datetime, timedelta

"""
DB Synchronization Timing Test
Tests how long it takes for a subscribed participant to appear in lookup database

PREREQUISITES:
- Admin authentication service must be running and accessible
- If /admin/auth/login returns 404, you need to:
  1. Start the admin service locally, OR
  2. Update 'host' in resources/registry/subscribe/test_sync_timing.yml to point to admin service

ALTERNATIVE: Use pre-registered participants (skip registration step)

Run with:
driver.py --test ondc_reg_sync_timing --environment ondcRegistry --iterations 5 -u 1 --autostart --autoquit 1
"""

class SyncTimingResults:
    """Store results from all sync timing tests"""
    participants = []
    
    @classmethod
    def add_result(cls, participant_id, registration_time, sync_duration, status):
        cls.participants.append({
            'participant_id': participant_id,
            'registration_time': registration_time,
            'sync_duration': sync_duration,
            'status': status
        })
    
    @classmethod
    def print_summary(cls):
        if not cls.participants:
            return
        
        print("\n" + "="*100)
        print("DB SYNCHRONIZATION TIMING TEST - SUMMARY REPORT")
        print("="*100)
        print(f"Total Participants Tested: {len(cls.participants)}")
        print("-"*100)
        
        successful = [p for p in cls.participants if p['status'] == 'SUCCESS']
        failed = [p for p in cls.participants if p['status'] != 'SUCCESS']
        
        if successful:
            avg_sync = sum(p['sync_duration'] for p in successful) / len(successful)
            min_sync = min(p['sync_duration'] for p in successful)
            max_sync = max(p['sync_duration'] for p in successful)
            
            print(f"\n Successful Syncs: {len(successful)}/{len(cls.participants)}")
            print(f"   Average Sync Time: {avg_sync:.1f} seconds ({avg_sync/60:.1f} minutes)")
            print(f"   Minimum Sync Time: {min_sync} seconds ({min_sync/60:.1f} minutes)")
            print(f"   Maximum Sync Time: {max_sync} seconds ({max_sync/60:.1f} minutes)")
        
        if failed:
            print(f"\n Failed Syncs: {len(failed)}/{len(cls.participants)}")
        
        print("\n" + "-"*100)
        print(f"{'#':<3} {'Participant ID':<50} {'Sync Duration':<20} {'Status':<10}")
        print("-"*100)
        
        for idx, p in enumerate(cls.participants, 1):
            duration_str = f"{p['sync_duration']}s ({p['sync_duration']/60:.1f}m)" if p['sync_duration'] else "N/A"
            print(f"{idx:<3} {p['participant_id']:<50} {duration_str:<20} {p['status']:<10}")
        
        print("="*100 + "\n")


@events.test_stop.add_listener
def on_test_stop(environment, **kwargs):
    """Print summary when all tests complete"""
    SyncTimingResults.print_summary()


class ONDCRegSyncTiming(RegistrySubscribeBase):
    """Test DB synchronization timing for subscribe -> lookup"""
    
    config_file = 'resources/registry/subscribe/test_sync_timing.yml'
    tenant_name = 'ondcRegistry'
    
    def on_start(self):
        """Initialize test - parent handles config and auth"""
        super().on_start()
        
        # Load test-specific configuration from YAML
        config = self._load_config(self.config_file, self.tenant_name)
        
        # Configuration for sync timing test
        self.SUBSCRIBE_SERVER = config.get('subscribe_host', 'http://34.14.152.92')
        self.LOOKUP_SERVER = config.get('lookup_host', 'http://35.200.190.239:8080')
        self.MAX_WAIT_TIME = config.get('max_wait_time', 600)  # 10 minutes max wait per participant
        self.CHECK_INTERVAL = config.get('check_interval', 10)  # Check every 10 seconds
        
        print(f"[SYNC-TEST] Subscribe: {self.SUBSCRIBE_SERVER}, Lookup: {self.LOOKUP_SERVER}")
        print(f"[SYNC-TEST] Max wait: {self.MAX_WAIT_TIME}s, Check interval: {self.CHECK_INTERVAL}s")
    
    def _register_participant(self, participant_id):
        """
        Register a new participant via subscribe API
        Returns: (success, registration_time)
        """
        uk_id = str(uuid.uuid4())
        test_id = participant_id.split('.')[0]
        
        payload = {
            "dns_skip": True,
            "skip_ssl_verification": True,
            "participant_id": participant_id,
            "action": "SUBSCRIBED",
            "credentials": [
                {
                    "cred_id": f"cred_gst_{uk_id[:8]}",
                    "type": "GST",
                    "cred_data": {
                        "gstin": "29ABCDE1234F1Z5",
                        "legal_name": f"Sync Test {test_id}"
                    }
                }
            ],
            "contacts": [
                {
                    "contact_id": f"contact_{uk_id[:8]}",
                    "type": "AUTHORISED_SIGNATORY",
                    "name": "Test Admin",
                    "email": f"{test_id}@synctest.ondc.org",
                    "phone": "+919876543210"
                }
            ],
            "key": {
                "uk_id": uk_id,
                "signing_public_key": "MCowBQYDK2VwAyEAVXtuKQMPh485BxBcV1jbqNHRuuyyJnbe1QIQoQYjLBg=",
                "encryption_public_key": "MCowBQYDK2VuAyEABQ3Mrz0aCgQzKEMgs7T8BrZPx4nzCOFJyNdARxxRc3E=",
                "signed_algorithm": "ED25519",
                "encryption_algorithm": "X25519",
                "valid_from": datetime.now().isoformat() + "Z",
                "valid_until": "2030-12-31T23:59:59.000Z"
            },
            "location": {
                "location_id": f"loc_{uk_id[:8]}",
                "type": "SERVICEABLE",
                "country": "IND",
                "city": ["std:080"]
            },
            "uri": {
                "uri_id": f"uri_{uk_id[:8]}",
                "type": "CALLBACK",
                "url": f"https://{test_id}.synctest.ondc.org/callback"
            },
            "configs": [
                {
                    "domain": "ONDC:RET10",
                    "np_type": "BPP",
                    "subscriber_id": participant_id,
                    "location_id": f"loc_{uk_id[:8]}",
                    "uri_id": f"uri_{uk_id[:8]}",
                    "key_id": uk_id
                }
            ]
        }
        
        try:
            # Use auth_client from base class for token management
            try:
                admin_token = self.auth_client.get_token()
            except Exception as auth_error:
                error_msg = str(auth_error)
                if "404" in error_msg or "ENDPOINT_NOT_FOUND" in error_msg:
                    print(f"\n{'='*100}")
                    print(f" ADMIN AUTHENTICATION SERVICE NOT AVAILABLE")
                    print(f"{'='*100}")
                    print(f"The /admin/auth/login endpoint returned 404.")
                    print(f"This test requires the admin service to be running.")
                    print(f"\nPossible solutions:")
                    print(f"1. Update 'host' in resources/registry/subscribe/test_sync_timing.yml")
                    print(f"   to point to a server with admin endpoints available")
                    print(f"2. Start the admin service locally (if available)")
                    print(f"3. Use an alternative testing approach without registration")
                    print(f"{'='*100}\n")
                    raise
                else:
                    raise
            
            with self.client.post(
                f"{self.SUBSCRIBE_SERVER}/admin/subscribe",
                json=payload,
                headers={
                    "Authorization": f"Bearer {admin_token}",
                    "Content-Type": "application/json"
                },
                catch_response=True,
                name="[STEP 1] Register Participant"
            ) as response:
                registration_time = datetime.now()
                
                if response.status_code in [200, 201]:
                    response.success()
                    print(f"[{participant_id}] ✅ Registered at {registration_time.strftime('%H:%M:%S')}")
                    return True, registration_time
                else:
                    response.failure(f"Registration failed: {response.status_code}")
                    print(f"[{participant_id}] ⚠️  Registration returned {response.status_code}, will still monitor...")
                    return True, registration_time  # Continue monitoring anyway
                
        except Exception as e:
            print(f"[{participant_id}] ❌ Error during registration: {e}")
            return False, None
    
    def _check_participant_in_lookup(self, participant_id):
        """
        Check if participant exists in lookup database using V3 API
        Returns: True if found, False otherwise
        """
        try:
            with self.client.post(
                f"{self.LOOKUP_SERVER}/v3.0/lookup",
                json={
                    "participant_id": participant_id,
                    "country": "IND",
                    "type": "BPP"  # V3 requires type field
                },
                headers={"Content-Type": "application/json"},
                catch_response=True,
                name="[STEP 2] Check Lookup V3"
            ) as response:
                if response.status_code == 200:
                    data = response.json()
                    if data and len(data) > 0:
                        response.success()
                        return True
                    else:
                        response.success()  # Not an error, just not found yet
                        return False
                else:
                    response.success()  # Treat as not found
                    return False
                
        except Exception as e:
            print(f"[{participant_id}] ⚠️  Lookup error: {e}")
            return False
    
    def _monitor_sync(self, participant_id, registration_time):
        """
        Monitor lookup database until participant appears or timeout
        Returns: (found, sync_duration_seconds)
        
        NOTE: Timing starts AFTER registration completes
        """
        # Start timing AFTER registration completed
        start_monitoring = time.time()
        check_count = 0
        found = False
        max_checks = self.MAX_WAIT_TIME // self.CHECK_INTERVAL
        
        print(f"[{participant_id}] 🔍 Starting monitoring (max {self.MAX_WAIT_TIME}s)...")
        
        while not found and check_count < max_checks:
            check_count += 1
            elapsed = int(time.time() - start_monitoring)
            
            # Format elapsed time
            if elapsed < 60:
                elapsed_str = f"{elapsed}s"
            else:
                elapsed_str = f"{elapsed//60}m {elapsed%60}s"
            
            print(f"[{participant_id}] Check #{check_count:2d} (elapsed: {elapsed_str:>6s})...", end=' ', flush=True)
            
            found = self._check_participant_in_lookup(participant_id)
            
            if found:
                sync_duration = int(time.time() - start_monitoring)
                print(f" FOUND! (sync time: {sync_duration}s)")
                return True, sync_duration
            else:
                print("Not found yet")
            
            if not found:
                time.sleep(self.CHECK_INTERVAL)
        
        # Timeout
        final_elapsed = int(time.time() - start_monitoring)
        print(f"[{participant_id}] ⏱️  Timeout after {final_elapsed}s ({check_count} checks)")
        return False, final_elapsed
    
    @task(1)
    def test_sync_timing_full_flow(self):
        """
        Full test: Register participant -> Monitor sync -> Record timing
        Each task iteration creates ONE participant
        """
        # Generate unique participant ID for this test iteration
        test_id = f"sync-test-{datetime.now().strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"
        participant_id = f"{test_id}.participant.ondc"
        
        self.step_name = f"SyncTest_{participant_id}"
        
        print(f"\n{'='*100}")
        print(f"SYNC TIMING TEST - Participant: {participant_id}")
        print(f"{'='*100}")
        
        # Step 1: Register participant
        success, registration_time = self._register_participant(participant_id)
        
        if not success:
            SyncTimingResults.add_result(participant_id, None, None, "REGISTRATION_FAILED")
            return
        
        # Small delay to ensure registration completes
        time.sleep(2)
        
        # Step 2: Monitor for sync (timing starts here, AFTER registration)
        found, sync_duration = self._monitor_sync(participant_id, registration_time)
        
        # Step 3: Record results
        if found:
            status = "SUCCESS"
            print(f"[{participant_id}]  Sync completed in {sync_duration} seconds ({sync_duration/60:.1f} minutes)")
        else:
            status = "TIMEOUT"
            print(f"[{participant_id}]  Sync timeout after {sync_duration} seconds")
        
        SyncTimingResults.add_result(
            participant_id=participant_id,
            registration_time=registration_time.strftime('%Y-%m-%d %H:%M:%S') if registration_time else None,
            sync_duration=sync_duration,
            status=status
        )
        
        print(f"{'='*100}\n")


# Required by Locust
tasks = [ONDCRegSyncTiming]
