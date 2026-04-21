from locust import task
from tests.gateway.gateway_lookup_base import GatewayLookupBase

"""
ONDC Gateway Lookup API - Negative Tests (Error Scenarios)
All tests use @task(1) for equal distribution during functional validation
Run with low user count: --users 1 --iterations 5
"""

class ONDCGatewayLookupNegative(GatewayLookupBase):
    """Negative test scenarios for error handling validation"""
    
    # Override config settings
    config_file = 'resources/gateway/ondc_gateway_lookup_negative.yml'
    tenant_name = 'ondcGatewayLookup'
    
    # TC-001: Lookup - Missing Required Field
    @task(1)
    def tc001_lookup_missing_field(self):
        self.step_name = 'TC001_Lookup_Missing_Field'
        
        with self.client.post(
            name=self.step_name,
            url="/lookup",
            json={
                "domain": "ONDC:RET10",
                "type": "BPP",
                # Missing city field
                "country": "IND",
                "core_version": self.core_version
            },
            catch_response=True
        ) as response:
            
            # NEGATIVE TEST: Should reject missing required field with error
            if response.status_code not in [400, 422]:
                response.failure(f"TC-001 Failed: Expected 400/422, got {response.status_code} - {response.text[:200]}")
                return
            
            response.success()

    # TC-002: Lookup - Invalid Participant Type
    @task(1)
    def tc002_lookup_invalid_type(self):
        self.step_name = 'TC002_Lookup_Invalid_Type'
        
        with self.client.post(
            name=self.step_name,
            url="/lookup",
            json={
                "domain": "ONDC:RET10",
                "type": "INVALID_TYPE",
                "city": "std:080",
                "country": "IND",
                "core_version": self.core_version
            },
            catch_response=True
        ) as response:
            
            # NEGATIVE TEST: Should reject invalid participant type with error
            if response.status_code not in [400, 422]:
                response.failure(f"TC-002 Failed: Expected 400/422, got {response.status_code} - {response.text[:200]}")
                return
            
            response.success()

    # TC-003: Lookup - Invalid Domain
    @task(1)
    def tc003_lookup_invalid_domain(self):
        self.step_name = 'TC003_Lookup_Invalid_Domain'
        
        with self.client.post(
            name=self.step_name,
            url="/lookup",
            json={
                "domain": "INVALID:DOMAIN",
                "type": "BPP",
                "city": "std:080",
                "country": "IND",
                "core_version": self.core_version
            },
            catch_response=True
        ) as response:
            
            # NEGATIVE TEST: Should reject invalid domain with error
            if response.status_code not in [400, 422]:
                response.failure(f"TC-003 Failed: Expected 400/422, got {response.status_code} - {response.text[:200]}")
                return
            
            response.success()

    # TC-004: Lookup - Malformed JSON
    @task(1)
    def tc004_lookup_malformed_json(self):
        self.step_name = 'TC004_Lookup_Malformed_JSON'
        
        with self.client.post(
            name=self.step_name,
            url="/lookup",
            data="{invalid json}",
            headers={"Content-Type": "application/json"},
            catch_response=True
        ) as response:
            
            if response.status_code not in [400, 422]:
                response.failure(f"TC-004 Failed: Expected 400/422, got {response.status_code} - {response.text[:200]}")
                return
            
            response.success()


tasks = [ONDCGatewayLookupNegative]
