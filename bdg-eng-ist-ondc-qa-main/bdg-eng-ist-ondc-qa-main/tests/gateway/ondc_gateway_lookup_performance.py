import random
import logging
from locust import task
from tests.gateway.gateway_lookup_base import GatewayLookupBase

logger = logging.getLogger(__name__)

"""
ONDC Gateway Lookup API - Performance Tests (Load Testing)
Uses optimized task weights to simulate realistic user behavior
Run with higher user counts: --users 10-50 for load testing
"""

class ONDCGatewayLookupPerformance(GatewayLookupBase):
    """Performance test scenarios with realistic load distribution"""
    
    # Override config settings
    config_file = 'resources/gateway/ondc_gateway_lookup_performance.yml'
    tenant_name = 'ondcGatewayLookup'
    
    # TC-001: Lookup - Valid BPP Request (Primary scenario - 25%)
    @task(25)
    def tc001_lookup_bpp_valid(self):
        self.step_name = 'TC001_Lookup_BPP_Valid'
        
        # Guard against empty lists
        if not self.domains or not self.cities:
            logger.error("TC-001: domains or cities is empty - check config")
            return
        
        domain = random.choice(self.domains)
        city = random.choice(self.cities)
        
        with self.client.post(
            name=self.step_name,
            url="/lookup",
            json={
                "domain": domain,
                "type": "BPP",
                "city": city,
                "country": "IND",
                "core_version": self.core_version
            },
            catch_response=True
        ) as response:
            
            if response.status_code != 200:
                response.failure(f"TC-001 Failed: Expected 200, got {response.status_code} - {response.text[:200]}")
                return
            
            try:
                data = response.json()
                
                # Validate response is list or dict with expected structure
                if isinstance(data, list):
                    response.success()
                elif isinstance(data, dict) and ('participant_id' in data or 'subscriber_id' in data):
                    response.success()
                else:
                    response.failure(f"TC-001 Failed: Unexpected response format - {type(data).__name__}")
                    
            except Exception as e:
                response.failure(f"TC-001 Failed: Error parsing response: {str(e)}")

    # TC-002: Lookup - Valid BAP Request (20%)
    @task(20)
    def tc002_lookup_bap_valid(self):
        self.step_name = 'TC002_Lookup_BAP_Valid'
        
        # Guard against empty lists
        if not self.domains or not self.cities:
            logger.error("TC-002: domains or cities is empty - check config")
            return
        
        domain = random.choice(self.domains)
        city = random.choice(self.cities)
        
        success, data, status = self._send_lookup_request(
            self.step_name,
            domain,
            "BAP",
            city
        )

    # TC-003: Lookup - Multiple Domains (15%)
    @task(15)
    def tc003_lookup_multiple_domains(self):
        self.step_name = 'TC003_Lookup_Multiple_Domains'
        
        city = "std:080"
        
        # Pick one random domain per task execution
        domain = random.choice(self.domains) if self.domains else "ONDC:RET10"
        
        with self.client.post(
            name=self.step_name,  # Use stable name
            url="/lookup",
            json={
                "domain": domain,
                "type": "BPP",
                "city": city,
                "country": "IND",
                "core_version": self.core_version
            },
            catch_response=True
        ) as response:
            
            if response.status_code != 200:
                response.failure(f"TC-003 Failed for {domain}: Status {response.status_code} - {response.text[:200]}")
                return
            
            response.success()

    # TC-004: Lookup - Multiple Cities (15%)
    @task(15)
    def tc004_lookup_multiple_cities(self):
        self.step_name = 'TC004_Lookup_Multiple_Cities'
        
        # Guard against empty cities list
        if not self.cities:
            logger.error("TC-004: cities is empty - check config")
            return
        
        domain = "ONDC:RET10"
        
        # Pick one random city per task execution
        city = random.choice(self.cities)
        
        with self.client.post(
            name=self.step_name,  # Use stable name
            url="/lookup",
            json={
                "domain": domain,
                "type": "BPP",
                "city": city,
                "country": "IND",
                "core_version": self.core_version
            },
            catch_response=True
        ) as response:
            
            if response.status_code != 200:
                response.failure(f"TC-004 Failed for {city}: Status {response.status_code} - {response.text[:200]}")
                return
            
            response.success()

    # TC-005: Lookup - Performance Test (Burst) (25%)
    @task(25)
    def tc005_lookup_performance(self):
        """High frequency lookup requests to test performance"""
        self.step_name = 'TC005_Lookup_Performance'
        
        # Guard against empty lists
        if not self.domains or not self.cities:
            logger.error("TC-005: domains or cities is empty - check config")
            return
        
        domain = random.choice(self.domains)
        city = random.choice(self.cities)
        
        # Locust automatically tracks response time
        success, data, status = self._send_lookup_request(
            self.step_name,
            domain,
            "BPP",
            city
        )

    # TC-006: Lookup by Subscriber ID - Specific (5%)
    @task(5)
    def tc006_lookup_subscriber_id_specific(self):
        self.step_name = 'TC006_Lookup_Subscriber_ID_Specific'
        
        subscriber_id = self.test_subscriber_id or "example-bpp.com"
        
        with self.client.post(
            name=self.step_name,
            url="/lookup",
            json={
                "subscriber_id": subscriber_id,
                "country": "IND",
                "core_version": self.core_version
            },
            catch_response=True
        ) as response:
            
            if response.status_code != 200:
                response.failure(f"TC-006 Failed: Status {response.status_code} - {response.text[:200]}")
                return
            
            response.success()

    # TC-007: Lookup by Subscriber ID - Random (5%)
    @task(5)
    def tc007_lookup_subscriber_id_multiple(self):
        self.step_name = 'TC007_Lookup_Subscriber_ID_Multiple'
        
        subscriber_ids = self.test_subscriber_ids or ["example1.com", "example2.com", "example3.com"]
        
        # Pick one random subscriber ID per task execution
        sub_id = random.choice(subscriber_ids)
        
        with self.client.post(
            name=self.step_name,  # Use stable name
            url="/lookup",
            json={
                "subscriber_id": sub_id,
                "country": "IND",
                "core_version": self.core_version
            },
            catch_response=True
        ) as response:
            
            if response.status_code != 200:
                response.failure(f"TC-007 Failed for {sub_id}: Status {response.status_code} - {response.text[:200]}")
                return
            
            response.success()

    # TC-008: Lookup by Participant ID - Specific (5%)
    @task(5)
    def tc008_lookup_participant_id_specific(self):
        self.step_name = 'TC008_Lookup_Participant_ID_Specific'
        
        participant_id = self.test_participant_id or "example-participant-id"
        
        with self.client.post(
            name=self.step_name,
            url="/lookup",
            json={
                "participant_id": participant_id,
                "country": "IND",
                "core_version": self.core_version
            },
            catch_response=True
        ) as response:
            
            if response.status_code != 200:
                response.failure(f"TC-008 Failed: Status {response.status_code} - {response.text[:200]}")
                return
            
            response.success()

    # TC-009: Lookup by Participant ID - Multiple (5%)
    @task(5)
    def tc009_lookup_participant_id_multiple(self):
        self.step_name = 'TC009_Lookup_Participant_ID_Multiple'
        
        participant_ids = self.test_participant_ids or ["part-id-1", "part-id-2", "part-id-3"]
        
        # Pick one random participant ID per task execution
        part_id = random.choice(participant_ids)
        
        with self.client.post(
            name=self.step_name,  # Use stable name
            url="/lookup",
            json={
                "participant_id": part_id,
                "country": "IND",
                "core_version": self.core_version
            },
            catch_response=True
        ) as response:
            
            if response.status_code != 200:
                response.failure(f"TC-009 Failed for {part_id}: Status {response.status_code} - {response.text[:200]}")
                return
            
            response.success()

    # TC-010: Lookup Combined - Subscriber ID + Domain (5%)
    @task(5)
    def tc010_lookup_combined_subscriber_domain(self):
        self.step_name = 'TC010_Lookup_Combined_Subscriber_Domain'
        
        subscriber_id = self.test_subscriber_id or "example-bpp.com"
        domain = random.choice(self.domains)
        
        with self.client.post(
            name=self.step_name,
            url="/lookup",
            json={
                "subscriber_id": subscriber_id,
                "domain": domain,
                "country": "IND",
                "core_version": self.core_version
            },
            catch_response=True
        ) as response:
            
            if response.status_code != 200:
                response.failure(f"TC-010 Failed: Status {response.status_code} - {response.text[:200]}")
                return
            
            response.success()


tasks = [ONDCGatewayLookupPerformance]
