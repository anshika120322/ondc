import json
import yaml
import os
from locust import TaskSet
from common_test_foundation.lib.proxy.proxy_server import ProxyServer
from common_test_foundation.helpers.taskset_handler import RESCHEDULE_TASK, taskset_handler
from tests.utils.ondc_lookup_helper import ONDCLookupHelper

"""
Base class for ONDC Gateway Lookup API tests
Contains shared functionality: config loading, helper setup, common methods
"""

@taskset_handler(RESCHEDULE_TASK)
class GatewayLookupBase(TaskSet):
    """Base class with shared setup and helper methods for Gateway Lookup tests"""
    
    def on_start(self):
        """Initialize proxy, load config, setup lookup helper"""
        self.step_name = 'ON_START'
        self.proxy = ProxyServer()
        self.proxy.start_capture(trx_id=self.step_name)
        self.client.verify = self.proxy.get_certificate()
        self.client.proxies = self.proxy.get_http_proxy_config()
        
        # Load configuration - child classes can override config_file_name
        config_file = getattr(self, 'config_file', 'resources/gateway/ondc_gateway_lookup.yml')
        tenant_name = getattr(self, 'tenant_name', 'ondcGatewayLookup')
        
        config = self._load_config(config_file, tenant_name)
        
        # Setup lookup helper
        lookup_url = config.get('lookup_host', config.get('host', 'http://localhost:8080'))
        if not lookup_url.endswith('/lookup'):
            lookup_url = lookup_url + '/lookup'
        
        self.lookup_helper = ONDCLookupHelper(lookup_url)
        
        # Store test data
        self.domains = config.get('domains', ["ONDC:RET10", "ONDC:RET11"])
        self.cities = config.get('cities', ["std:080", "std:022"])
        self.core_version = config.get('core_version', '1.2.0')
    
    def _load_config(self, config_file, tenant_name):
        """Load tenant configuration from YAML file"""
        config = {}
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                yaml_content = yaml.safe_load(f)
                config = yaml_content.get(tenant_name, {})
                print(f"[ON_START] Loaded config from {config_file}")
        else:
            print(f"[ON_START] WARNING: Config file not found: {config_file}")
        return config
    
    def _send_lookup_request(self, step_name, domain, participant_type, city, expected_status=None):
        """
        Helper method to send lookup requests with consistent error handling
        
        Args:
            step_name: Name for the test step
            domain: ONDC domain (e.g., "ONDC:RET10")
            participant_type: "BPP" or "BAP"
            city: City code (e.g., "std:080")
            expected_status: List of expected status codes (default: [200])
        
        Returns:
            tuple: (success: bool, response_data: dict/list, status_code: int)
        """
        if expected_status is None:
            expected_status = [200]
        
        with self.client.post(
            name=step_name,
            url="/lookup",
            json={
                "domain": domain,
                "type": participant_type,
                "city": city,
                "country": "IND",
                "core_version": self.core_version
            },
            catch_response=True
        ) as response:
            
            # Check for expected status codes
            if response.status_code not in expected_status:
                response.failure(f"{step_name} Failed: Expected {expected_status}, got {response.status_code}")
                return False, None, response.status_code
            
            # Try to parse response
            try:
                data = response.json() if response.content else {}
                response.success()
                return True, data, response.status_code
            except Exception as e:
                response.failure(f"{step_name} Failed: Error parsing response: {str(e)}")
                return False, None, response.status_code
    
    def on_stop(self):
        """Cleanup resources after test ends"""
        # Close lookup helper session
        if hasattr(self, 'lookup_helper') and self.lookup_helper:
            self.lookup_helper.close()
        
        # Stop proxy
        self.proxy.stop_capture()
        self.proxy.quit()
