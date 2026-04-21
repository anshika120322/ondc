import json
import time
import uuid
from locust import task
from tests.gateway.gateway_search_base import GatewaySearchBase

"""
ONDC Gateway Search API - Large Payload Test
TC-004: Search API with Large Payload
Run with: --test ondc_gateway_search_large_payload
"""

class ONDCGatewaySearchLargePayload(GatewaySearchBase):
    """Test large payload handling for Gateway Search API"""
    
    # Override config settings
    config_file = 'resources/gateway/ondc_gateway_search_functional.yml'
    tenant_name = 'ondcGatewaySearch'
    
    # TC-004: Search API - Large Payload
    @task(1)
    def tc004_search_large_payload(self):
        """
        Test Case: TC-004 - Search API with Large Payload
        Purpose: Validate Gateway's ability to handle large payloads
        Expected: Accept large payloads or return proper error (413)
        """
        self.step_name = 'TC004_Search_Large_Payload'
        payload = self._generate_search_payload()
        
        # Add multiple items to create larger payload
        payload['message']['intent']['items'] = [
            {
                "descriptor": {"name": f"item_{i}"},
                "tags": [{"code": f"tag_{j}", "value": f"value_{j}"} for j in range(10)]
            }
            for i in range(20)
        ]
        
        self._send_search_request(
            self.step_name, 
            payload, 
            expected_status=[200, 202, 413]  # Accept success or payload too large
        )


tasks = [ONDCGatewaySearchLargePayload]
