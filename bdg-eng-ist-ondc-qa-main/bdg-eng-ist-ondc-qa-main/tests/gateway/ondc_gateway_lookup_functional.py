import random
from locust import task
from tests.gateway.gateway_lookup_base import GatewayLookupBase

"""
ONDC Gateway Lookup API - Functional Tests (Positive Scenarios)
All tests use @task(1) for equal distribution during functional validation
Run with low user count: --users 1 --iterations 5
"""

class ONDCGatewayLookupFunctional(GatewayLookupBase):
    """Positive test scenarios for functional validation"""
    
    # Override config settings
    config_file = 'resources/gateway/ondc_gateway_lookup_functional.yml'
    tenant_name = 'ondcGatewayLookup'
    
    # TC-001: Lookup - Valid BPP Request
    @task(1)
    def tc001_lookup_bpp_valid(self):
        self.step_name = 'TC001_Lookup_BPP_Valid'
        
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
                response.failure(f"TC-001 Failed: Expected 200, got {response.status_code}")
                return
            
            try:
                data = response.json()
                
                # Response can be an array or object
                if isinstance(data, (list, dict)):
                    response.success()
                else:
                    response.failure(f"TC-001 Failed: Unexpected response format")
                    
            except Exception as e:
                response.failure(f"TC-001 Failed: Error parsing response: {str(e)}")

    # TC-002: Lookup - Valid BAP Request
    @task(1)
    def tc002_lookup_bap_valid(self):
        self.step_name = 'TC002_Lookup_BAP_Valid'
        
        domain = random.choice(self.domains)
        city = random.choice(self.cities)
        
        success, data, status = self._send_lookup_request(
            self.step_name,
            domain,
            "BAP",
            city
        )

    # TC-003: Lookup - Multiple Domains
    @task(1)
    def tc003_lookup_multiple_domains(self):
        self.step_name = 'TC003_Lookup_Multiple_Domains'
        
        city = "std:080"
        
        for domain in self.domains:
            with self.client.post(
                name=f"{self.step_name}_{domain}",
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
                    response.failure(f"TC-003 Failed for {domain}: Status {response.status_code}")
                    continue
                
                response.success()

    # TC-004: Lookup - Multiple Cities
    @task(1)
    def tc004_lookup_multiple_cities(self):
        self.step_name = 'TC004_Lookup_Multiple_Cities'
        
        domain = "ONDC:RET10"
        
        for city in self.cities:
            with self.client.post(
                name=f"{self.step_name}_{city}",
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
                    response.failure(f"TC-004 Failed for {city}: Status {response.status_code}")
                    continue
                
                response.success()

    # TC-005: Lookup - Empty Results
    @task(1)
    def tc005_lookup_empty_results(self):
        self.step_name = 'TC005_Lookup_Empty_Results'
        
        # Use unlikely combination to get empty results
        with self.client.post(
            name=self.step_name,
            url="/lookup",
            json={
                "domain": "ONDC:RET99",
                "type": "BPP",
                "city": "std:999",
                "country": "IND",
                "core_version": self.core_version
            },
            catch_response=True
        ) as response:
            
            if response.status_code not in [200, 404]:
                response.failure(f"TC-005 Failed: Expected 200/404, got {response.status_code}")
                return
            
            try:
                data = response.json()
                
                # Empty results should be [] or empty dict
                if isinstance(data, (list, dict)):
                    response.success()
                else:
                    response.success()  # Any valid response is ok
                    
            except Exception as e:
                response.failure(f"TC-005 Failed: Error: {str(e)}")

    # TC-006: Lookup - By Subscriber ID
    @task(1)
    def tc006_lookup_by_subscriber_id(self):
        self.step_name = 'TC006_Lookup_By_SubscriberID'
        
        # Lookup by subscriber_id (common participant identifier)
        with self.client.post(
            name=self.step_name,
            url="/lookup",
            json={
                "subscriber_id": "example-bpp.ondc.org",
                "country": "IND",
                "core_version": self.core_version
            },
            catch_response=True
        ) as response:
            
            if response.status_code not in [200, 404]:
                response.failure(f"TC-006 Failed: Expected 200/404, got {response.status_code}")
                return
            
            try:
                data = response.json()
                
                # Valid response could be participant data or empty
                if response.status_code == 200:
                    if isinstance(data, (list, dict)):
                        response.success()
                    else:
                        response.failure(f"TC-006 Failed: Invalid response format")
                else:
                    response.success()  # 404 is valid for non-existent subscriber
                    
            except Exception as e:
                response.failure(f"TC-006 Failed: Error: {str(e)}")

    # TC-007: Lookup - By Participant ID (Payload from Sujit)
    @task(1)
    def tc007_lookup_by_participant_id(self):
        self.step_name = 'TC007_Lookup_By_ParticipantID'
        
        # Lookup by participant_id as provided by Sujit/Satya
        with self.client.post(
            name=self.step_name,
            url="/lookup",
            json={
                "participant_id": "participant-0.participant.ondc",
                "type": "BPP"
            },
            catch_response=True
        ) as response:
            
            if response.status_code not in [200, 404]:
                response.failure(f"TC-007 Failed: Expected 200/404, got {response.status_code}")
                return
            
            try:
                data = response.json()
                
                # Valid response could be participant data or empty
                if response.status_code == 200:
                    if isinstance(data, (list, dict)):
                        response.success()
                    else:
                        response.failure(f"TC-007 Failed: Invalid response format")
                else:
                    response.success()  # 404 is valid for non-existent participant
                    
            except Exception as e:
                response.failure(f"TC-007 Failed: Error: {str(e)}")

    # TC-008: Lookup - Subscriber ID only
    @task(1)
    def tc008_lookup_subscriber_id_only(self):
        self.step_name = 'TC008_Lookup_SubscriberID_Only'
        
        with self.client.post(
            name=self.step_name,
            url="/lookup",
            json={
                "subscriber_id": "example-bpp.ondc.org"
            },
            catch_response=True
        ) as response:
            
            if response.status_code not in [200, 404, 400]:
                response.failure(f"TC-008 Failed: Unexpected status {response.status_code}")
                return
            
            response.success()

    # TC-009: Lookup - Subscriber ID + Type
    @task(1)
    def tc009_lookup_subscriber_id_type(self):
        self.step_name = 'TC009_Lookup_SubscriberID_Type'
        
        with self.client.post(
            name=self.step_name,
            url="/lookup",
            json={
                "subscriber_id": "example-bpp.ondc.org",
                "type": "BPP"
            },
            catch_response=True
        ) as response:
            
            if response.status_code not in [200, 404]:
                response.failure(f"TC-009 Failed: Unexpected status {response.status_code}")
                return
            
            response.success()

    # TC-010: Lookup - Subscriber ID + Domain
    @task(1)
    def tc010_lookup_subscriber_id_domain(self):
        self.step_name = 'TC010_Lookup_SubscriberID_Domain'
        
        with self.client.post(
            name=self.step_name,
            url="/lookup",
            json={
                "subscriber_id": "example-bpp.ondc.org",
                "domain": "ONDC:RET10"
            },
            catch_response=True
        ) as response:
            
            if response.status_code not in [200, 404]:
                response.failure(f"TC-010 Failed: Unexpected status {response.status_code}")
                return
            
            response.success()

    # TC-011: Lookup - Subscriber ID + City
    @task(1)
    def tc011_lookup_subscriber_id_city(self):
        self.step_name = 'TC011_Lookup_SubscriberID_City'
        
        with self.client.post(
            name=self.step_name,
            url="/lookup",
            json={
                "subscriber_id": "example-bpp.ondc.org",
                "city": "std:080"
            },
            catch_response=True
        ) as response:
            
            if response.status_code not in [200, 404]:
                response.failure(f"TC-011 Failed: Unexpected status {response.status_code}")
                return
            
            response.success()

    # TC-012: Lookup - Participant ID only
    @task(1)
    def tc012_lookup_participant_id_only(self):
        self.step_name = 'TC012_Lookup_ParticipantID_Only'
        
        with self.client.post(
            name=self.step_name,
            url="/lookup",
            json={
                "participant_id": "participant-0.participant.ondc"
            },
            catch_response=True
        ) as response:
            
            if response.status_code not in [200, 404, 400]:
                response.failure(f"TC-012 Failed: Unexpected status {response.status_code}")
                return
            
            response.success()

    # TC-013: Lookup - Participant ID + Domain
    @task(1)
    def tc013_lookup_participant_id_domain(self):
        self.step_name = 'TC013_Lookup_ParticipantID_Domain'
        
        with self.client.post(
            name=self.step_name,
            url="/lookup",
            json={
                "participant_id": "participant-0.participant.ondc",
                "domain": "ONDC:RET10"
            },
            catch_response=True
        ) as response:
            
            if response.status_code not in [200, 404]:
                response.failure(f"TC-013 Failed: Unexpected status {response.status_code}")
                return
            
            response.success()

    # TC-014: Lookup - Participant ID + City
    @task(1)
    def tc014_lookup_participant_id_city(self):
        self.step_name = 'TC014_Lookup_ParticipantID_City'
        
        with self.client.post(
            name=self.step_name,
            url="/lookup",
            json={
                "participant_id": "participant-0.participant.ondc",
                "city": "std:080"
            },
            catch_response=True
        ) as response:
            
            if response.status_code not in [200, 404]:
                response.failure(f"TC-014 Failed: Unexpected status {response.status_code}")
                return
            
            response.success()

    # TC-015: Lookup - Participant ID + Country
    @task(1)
    def tc015_lookup_participant_id_country(self):
        self.step_name = 'TC015_Lookup_ParticipantID_Country'
        
        with self.client.post(
            name=self.step_name,
            url="/lookup",
            json={
                "participant_id": "participant-0.participant.ondc",
                "country": "IND"
            },
            catch_response=True
        ) as response:
            
            if response.status_code not in [200, 404]:
                response.failure(f"TC-015 Failed: Unexpected status {response.status_code}")
                return
            
            response.success()


tasks = [ONDCGatewayLookupFunctional]

