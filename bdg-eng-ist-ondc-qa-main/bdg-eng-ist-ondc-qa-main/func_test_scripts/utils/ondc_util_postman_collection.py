#!/usr/bin/env python3
"""
Generate Postman Collections for ONDC Registry Lookup Tests (V1, V2, V3)

This script generates Postman collections from test YAML configurations
to enable manual testing of lookup APIs in Postman.

Usage:
    python func_test_scripts/utils/ondc_util_postman_collection.py
    
Output:
    - postman_collections/ONDC_Registry_Lookup_V1.postman_collection.json
    - postman_collections/ONDC_Registry_Lookup_V2.postman_collection.json
    - postman_collections/ONDC_Registry_Lookup_V3.postman_collection.json
"""

import json
import os
import yaml
import uuid
import time
import base64
import hashlib
from pathlib import Path
from typing import Dict, List, Any


class PostmanCollectionGenerator:
    """Generate Postman collections from YAML test configurations"""
    
    POSTMAN_VERSION = "2.1.0"
    
    def __init__(self, output_dir: str = "postman_collections"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
    def load_yaml_config(self, yaml_path: str) -> dict:
        """Load YAML configuration file"""
        with open(yaml_path, 'r') as f:
            return yaml.safe_load(f)
    
    def generate_blake2b_digest(self, payload_str: str) -> str:
        """Generate BLAKE2b-512 digest for payload"""
        h = hashlib.blake2b(payload_str.encode('utf-8'), digest_size=64)
        return base64.b64encode(h.digest()).decode('utf-8')
    
    def create_v1_collection(self) -> dict:
        """Generate Postman collection for V1 Lookup API"""
        
        # Load V1 configs
        functional_config = self.load_yaml_config('resources/registry/lookup/v1/test_lookup_v1.yml')
        qa_config = functional_config['ondcRegistryV1Lookup']
        prod_config = functional_config.get('ondcRegistryV1LookupProd', {})
        
        collection = {
            "info": {
                "name": "ONDC Registry Lookup V1 - Complete Test Suite",
                "description": "V1 Lookup API - Complete test coverage\n\n"
                              f"QA Host: {qa_config['host']}\n"
                              f"PROD Host: {prod_config.get('host', 'N/A')}\n"
                              f"Endpoint: /lookup\n\n"
                              "Includes: Functional, Filter Combinations, Negative, and Boundary tests",
                "schema": f"https://schema.getpostman.com/json/collection/v{self.POSTMAN_VERSION}/collection.json"
            },
            "item": [],
            "variable": [
                {"key": "qa_host", "value": qa_config['host'], "type": "string"},
                {"key": "prod_host", "value": prod_config.get('host', ''), "type": "string"}
            ]
        }
        
        # 1. FUNCTIONAL TESTS
        functional_folder = {
            "name": "Functional Tests",
            "description": "V1 Lookup functional tests on QA environment",
            "item": []
        }
        
        for lookup_type in qa_config['lookup_types']:
            for country in qa_config['countries']:
                request = {
                    "name": f"Lookup - {lookup_type} in {country}",
                    "request": {
                        "method": "POST",
                        "header": [{"key": "Content-Type", "value": "application/json"}],
                        "body": {
                            "mode": "raw",
                            "raw": json.dumps({"country": country, "type": lookup_type}, indent=2)
                        },
                        "url": {
                            "raw": "{{qa_host}}/lookup",
                            "host": ["{{qa_host}}"],
                            "path": ["lookup"]
                        },
                        "description": f"Lookup {lookup_type} participants in {country}"
                    }
                }
                functional_folder['item'].append(request)
        
        # 2. FILTER COMBINATIONS (read from filter combinations config)
        filter_config = self.load_yaml_config('resources/registry/lookup/v1/test_lookup_filter_combinations_v1.yml')
        filter_folder = {
            "name": "Filter Combinations",
            "description": "V1 Lookup with various type/country combinations",
            "item": []
        }
        
        # Add all type combinations
        for lookup_type in qa_config['lookup_types']:
            filter_folder['item'].append({
                "name": f"Type Only - {lookup_type}",
                "request": {
                    "method": "POST",
                    "header": [{"key": "Content-Type", "value": "application/json"}],
                    "body": {"mode": "raw", "raw": json.dumps({"type": lookup_type}, indent=2)},
                    "url": {"raw": "{{qa_host}}/lookup", "host": ["{{qa_host}}"], "path": ["lookup"]},
                    "description": f"Lookup with only type={lookup_type}"
                }
            })
        
        # Country only
        filter_folder['item'].append({
            "name": "Country Only - IND",
            "request": {
                "method": "POST",
                "header": [{"key": "Content-Type", "value": "application/json"}],
                "body": {"mode": "raw", "raw": json.dumps({"country": "IND"}, indent=2)},
                "url": {"raw": "{{qa_host}}/lookup", "host": ["{{qa_host}}"], "path": ["lookup"]},
                "description": "Lookup with only country=IND"
            }
        })
        
        # 3. NEGATIVE TESTS
        negative_folder = {
            "name": "Negative Tests",
            "description": "V1 Lookup comprehensive negative test scenarios",
            "item": []
        }
        
        negative_scenarios = [
            {"name": "Empty Payload", "payload": {}, "desc": "Empty JSON object"},
            {"name": "Invalid Country", "payload": {"country": "INVALID", "type": "BPP"}, "desc": "Invalid country code"},
            {"name": "Invalid Type", "payload": {"country": "IND", "type": "INVALID_TYPE"}, "desc": "Invalid participant type"},
            {"name": "Numeric Country", "payload": {"country": 123, "type": "BPP"}, "desc": "Country as number"},
            {"name": "Numeric Type", "payload": {"country": "IND", "type": 123}, "desc": "Type as number"},
            {"name": "Null Country", "payload": {"country": None, "type": "BPP"}, "desc": "Null country value"},
            {"name": "Null Type", "payload": {"country": "IND", "type": None}, "desc": "Null type value"},
            {"name": "Array Payload", "payload": [], "desc": "Array instead of object"},
            {"name": "String Payload", "payload": "string", "desc": "String instead of JSON"},
            {"name": "Extra Fields", "payload": {"country": "IND", "type": "BPP", "extra": "field"}, "desc": "Extra unknown fields"},
            {"name": "Case Sensitive Type Lower", "payload": {"country": "IND", "type": "bpp"}, "desc": "Lowercase type"},
            {"name": "Case Sensitive Country Lower", "payload": {"country": "ind", "type": "BPP"}, "desc": "Lowercase country"},
            {"name": "Special Characters in Country", "payload": {"country": "IN@D", "type": "BPP"}, "desc": "Special chars in country"},
            {"name": "Special Characters in Type", "payload": {"country": "IND", "type": "BP@P"}, "desc": "Special chars in type"},
            {"name": "Very Long Country", "payload": {"country": "A" * 100, "type": "BPP"}, "desc": "Country > 100 chars"},
            {"name": "Very Long Type", "payload": {"country": "IND", "type": "B" * 100}, "desc": "Type > 100 chars"},
            {"name": "Empty String Country", "payload": {"country": "", "type": "BPP"}, "desc": "Empty string country"},
            {"name": "Empty String Type", "payload": {"country": "IND", "type": ""}, "desc": "Empty string type"},
            {"name": "Whitespace Country", "payload": {"country": "   ", "type": "BPP"}, "desc": "Whitespace-only country"},
            {"name": "Whitespace Type", "payload": {"country": "IND", "type": "   "}, "desc": "Whitespace-only type"},
        ]
        
        for scenario in negative_scenarios:
            payload = scenario['payload']
            # Handle non-dict payloads
            raw_body = json.dumps(payload, indent=2) if isinstance(payload, (dict, list)) else f'"{payload}"'
            
            negative_folder['item'].append({
                "name": scenario['name'],
                "request": {
                    "method": "POST",
                    "header": [{"key": "Content-Type", "value": "application/json"}],
                    "body": {"mode": "raw", "raw": raw_body},
                    "url": {"raw": "{{qa_host}}/lookup", "host": ["{{qa_host}}"], "path": ["lookup"]},
                    "description": f"{scenario['desc']}\n\nExpected: 400 Bad Request or validation error"
                }
            })
        
        # 4. BOUNDARY TESTS
        boundary_folder = {
            "name": "Boundary & Edge Cases",
            "description": "V1 Lookup boundary value and edge case tests",
            "item": []
        }
        
        boundary_scenarios = [
            {"name": "Max Length Country (3 chars)", "payload": {"country": "IND", "type": "BPP"}, "desc": "Standard 3-char country"},
            {"name": "Min Payload - Type Only", "payload": {"type": "BPP"}, "desc": "Minimum viable - type only"},
            {"name": "Min Payload - Country Only", "payload": {"country": "IND"}, "desc": "Minimum viable - country only"},
            {"name": "Unicode in Country", "payload": {"country": "😀😀😀", "type": "BPP"}, "desc": "Unicode characters in country"},
            {"name": "Unicode in Type", "payload": {"country": "IND", "type": "😀😀😀"}, "desc": "Unicode characters in type"},
            {"name": "SQL Injection - Country", "payload": {"country": "IND'; DROP TABLE--", "type": "BPP"}, "desc": "SQL injection attempt in country"},
            {"name": "SQL Injection - Type", "payload": {"country": "IND", "type": "BPP'; DROP TABLE--"}, "desc": "SQL injection attempt in type"},
            {"name": "XSS - Country", "payload": {"country": "<script>alert('xss')</script>", "type": "BPP"}, "desc": "XSS attempt in country"},
            {"name": "XSS - Type", "payload": {"country": "IND", "type": "<script>alert('xss')</script>"}, "desc": "XSS attempt in type"},
            {"name": "Path Traversal - Country", "payload": {"country": "../../etc/passwd", "type": "BPP"}, "desc": "Path traversal in country"},
            {"name": "Null Bytes", "payload": {"country": "IND\x00NULL", "type": "BPP"}, "desc": "Null byte injection"},
            {"name": "Multiple Spaces", "payload": {"country": "I  N  D", "type": "B  P  P"}, "desc": "Multiple spaces in values"},
        ]
        
        for scenario in boundary_scenarios:
            boundary_folder['item'].append({
                "name": scenario['name'],
                "request": {
                    "method": "POST",
                    "header": [{"key": "Content-Type", "value": "application/json"}],
                    "body": {"mode": "raw", "raw": json.dumps(scenario['payload'], indent=2)},
                    "url": {"raw": "{{qa_host}}/lookup", "host": ["{{qa_host}}"], "path": ["lookup"]},
                    "description": f"{scenario['desc']}\n\nTest for proper input validation and sanitization"
                }
            })
        
        collection['item'] = [functional_folder, filter_folder, negative_folder, boundary_folder]
        return collection
    
    def create_v2_collection(self) -> dict:
        """Generate Postman collection for V2 Lookup API"""
        
        # Load V2 configs
        functional_config = self.load_yaml_config('resources/registry/lookup/v2/test_lookup_v2.yml')
        negative_config = self.load_yaml_config('resources/registry/lookup/v2/test_lookup_negative_v2.yml')
        filter_config = self.load_yaml_config('resources/registry/lookup/v2/test_lookup_filter_combinations_v2.yml')
        
        qa_config = functional_config['ondcRegistryV2Lookup']
        neg_config = negative_config['ondcRegistry']
        
        collection = {
            "info": {
                "name": "ONDC Registry Lookup V2 - Complete Test Suite",
                "description": "V2 Lookup API with ED25519 Signature Authentication\n\n"
                              f"QA Host: {qa_config['host']}\n"
                              f"Endpoint: /v2.0/lookup\n\n"
                              "⚠️ V2 requires ED25519 signature authentication.\n"
                              "Use func_test_scripts/utils/ondc_util_auth_signature.py to create signatures.\n\n"
                              "Includes: Functional, Filter Combinations, Negative, and Boundary tests",
                "schema": f"https://schema.getpostman.com/json/collection/v{self.POSTMAN_VERSION}/collection.json"
            },
            "item": [],
            "variable": [
                {"key": "qa_host", "value": qa_config['host'], "type": "string"},
                {"key": "participant_id", "value": qa_config['participant_id'], "type": "string"},
                {"key": "uk_id", "value": qa_config['uk_id'], "type": "string"},
                {"key": "private_key_seed", "value": qa_config['private_key_seed'], "type": "string"},
            ]
        }
        
        # 1. FUNCTIONAL TESTS
        functional_folder = {"name": "Functional Tests", "description": "V2 Lookup with valid authentication", "item": []}
        
        default_payload = qa_config.get('default_lookup_payload', {})
        functional_folder['item'].append({
            "name": "Basic Lookup - Country + Type",
            "request": {
                "method": "POST",
                "header": [
                    {"key": "Content-Type", "value": "application/json"},
                    {"key": "Authorization", "value": "{{v2_auth_signature}}", "description": "Generate using func_test_scripts/utils/ondc_util_auth_signature.py"},
                    {"key": "Digest", "value": "BLAKE-512={{v2_digest}}", "description": "BLAKE2b-512 digest"}
                ],
                "body": {"mode": "raw", "raw": json.dumps(default_payload, indent=2)},
                "url": {"raw": "{{qa_host}}/v2.0/lookup", "host": ["{{qa_host}}"], "path": ["v2.0", "lookup"]},
                "description": "Basic V2 lookup with country and type"
            }
        })
        
        # 2. FILTER COMBINATIONS
        filter_folder = {"name": "Filter Combinations", "description": "V2 Lookup with various filter combinations", "item": []}
        
        filter_tests = filter_config.get('test', {})
        domains = filter_tests.get('default_domains', ["ONDC:RET10"])
        cities = filter_tests.get('default_cities', ["std:080"])
        
        # Domain-based filters
        for domain in domains[:3]:
            filter_folder['item'].append({
                "name": f"Filter by Domain - {domain}",
                "request": {
                    "method": "POST",
                    "header": [
                        {"key": "Content-Type", "value": "application/json"},
                        {"key": "Authorization", "value": "{{v2_auth_signature}}"},
                        {"key": "Digest", "value": "BLAKE-512={{v2_digest}}"}
                   ],
                    "body": {"mode": "raw", "raw": json.dumps({"country": "IND", "domain": domain}, indent=2)},
                    "url": {"raw": "{{qa_host}}/v2.0/lookup", "host": ["{{qa_host}}"], "path": ["v2.0", "lookup"]},
                    "description": f"Lookup participants by domain {domain}"
                }
            })
        
        # City-based filters
        for city in cities[:3]:
            filter_folder['item'].append({
                "name": f"Filter by City - {city}",
                "request": {
                    "method": "POST",
                    "header": [
                        {"key": "Content-Type", "value": "application/json"},
                        {"key": "Authorization", "value": "{{v2_auth_signature}}"},
                        {"key": "Digest", "value": "BLAKE-512={{v2_digest}}"}
                    ],
                    "body": {"mode": "raw", "raw": json.dumps({"country": "IND", "city": city}, indent=2)},
                    "url": {"raw": "{{qa_host}}/v2.0/lookup", "host": ["{{qa_host}}"], "path": ["v2.0", "lookup"]},
                    "description": f"Lookup participants by city {city}"
                }
            })
        
        # Combined filters
        filter_folder['item'].append({
            "name": "Combined - Domain + City + Type",
            "request": {
                "method": "POST",
                "header": [
                    {"key": "Content-Type", "value": "application/json"},
                    {"key": "Authorization", "value": "{{v2_auth_signature}}"},
                    {"key": "Digest", "value": "BLAKE-512={{v2_digest}}"}
                ],
                "body": {"mode": "raw", "raw": json.dumps({
                    "country": "IND",
                    "type": "BPP",
                    "domain": domains[0],
                    "city": cities[0]
                }, indent=2)},
                "url": {"raw": "{{qa_host}}/v2.0/lookup", "host": ["{{qa_host}}"], "path": ["v2.0", "lookup"]},
                "description": "Lookup with multiple filters"
            }
        })
        
        # 3. NEGATIVE TESTS
        negative_folder = {"name": "Negative Tests", "description": "V2 Lookup with invalid/missing authentication and invalid inputs", "item": []}
        
        invalid_auth = qa_config.get('invalid_auth', {})
        
        # Auth-related negative tests
        negative_folder['item'].append({
            "name": "Missing Authorization Header",
            "request": {
                "method": "POST",
                "header": [{"key": "Content-Type", "value": "application/json"}],
                "body": {"mode": "raw", "raw": json.dumps(default_payload, indent=2)},
                "url": {"raw": "{{qa_host}}/v2.0/lookup", "host": ["{{qa_host}}"], "path": ["v2.0", "lookup"]},
                "description": "Expected: 401 Unauthorized - Missing auth header"
            }
        })
        
        if 'invalid_signature' in invalid_auth:
            negative_folder['item'].append({
                "name": "Invalid Signature",
                "request": {
                    "method": "POST",
                    "header": [
                        {"key": "Content-Type", "value": "application/json"},
                        {"key": "Authorization", "value": invalid_auth['invalid_signature']}
                    ],
                    "body": {"mode": "raw", "raw": json.dumps(default_payload, indent=2)},
                    "url": {"raw": "{{qa_host}}/v2.0/lookup", "host": ["{{qa_host}}"], "path": ["v2.0", "lookup"]},
                    "description": "Expected: 401 Invalid signature"
                }
            })
        
        if 'expired_signature' in invalid_auth:
            negative_folder['item'].append({
                "name": "Expired Signature",
                "request": {
                    "method": "POST",
                    "header": [
                        {"key": "Content-Type", "value": "application/json"},
                        {"key": "Authorization", "value": invalid_auth['expired_signature']}
                    ],
                    "body": {"mode": "raw", "raw": json.dumps(default_payload, indent=2)},
                    "url": {"raw": "{{qa_host}}/v2.0/lookup", "host": ["{{qa_host}}"], "path": ["v2.0", "lookup"]},
                    "description": "Expected: 401 Signature expired"
                }
            })
        
        # Payload validation negative tests
        payload_negative_tests = [
            {"name": "Empty Payload", "payload": {}, "desc": "Empty JSON - Expected: 400"},
            {"name": "Invalid Country", "payload": {"country": "INVALID"}, "desc": "Invalid country code"},
            {"name": "Invalid Type", "payload": {"country": "IND", "type": "INVALID"}, "desc": "Invalid participant type"},
            {"name": "Invalid Domain", "payload": {"country": "IND", "domain": "INVALID:DOMAIN"}, "desc": "Invalid domain format"},
            {"name": "Invalid City", "payload": {"country": "IND", "city": "invalid_city"}, "desc": "Invalid city code"},
            {"name": "Malformed JSON", "payload": "not-json", "desc": "String instead of JSON object"},
            {"name": "Array Payload", "payload": [], "desc": "Array instead of object"},
        ]
        
        for test in payload_negative_tests:
            raw_body = json.dumps(test['payload'], indent=2) if isinstance(test['payload'], (dict, list)) else f'"{test["payload"]}"'
            negative_folder['item'].append({
                "name": test['name'],
                "request": {
                    "method": "POST",
                    "header": [
                        {"key": "Content-Type", "value": "application/json"},
                        {"key": "Authorization", "value": "{{v2_auth_signature}}"},
                        {"key": "Digest", "value": "BLAKE-512={{v2_digest}}"}
                    ],
                    "body": {"mode": "raw", "raw": raw_body},
                    "url": {"raw": "{{qa_host}}/v2.0/lookup", "host": ["{{qa_host}}"], "path": ["v2.0", "lookup"]},
                    "description": test['desc']
                }
            })
        
        # 4. BOUNDARY TESTS
        boundary_folder = {"name": "Boundary & Edge Cases", "description": "V2 Lookup boundary value tests", "item": []}
        
        boundary_tests = [
            {"name": "Very Long Country", "payload": {"country": "A" * 100, "type": "BPP"}, "desc": "Country > 100 chars"},
            {"name": "Very Long Domain", "payload": {"country": "IND", "domain": "ONDC:" + "X" * 100}, "desc": "Domain > 100 chars"},
            {"name": "Special Characters in Domain", "payload": {"country": "IND", "domain": "ONDC:RET@#$%"}, "desc": "Special chars in domain"},
            {"name": "Unicode in City", "payload": {"country": "IND", "city": "😀😀😀"}, "desc": "Unicode in city"},
            {"name": "SQL Injection", "payload": {"country": "IND'; DROP TABLE--", "type": "BPP"}, "desc": "SQL injection attempt"},
            {"name": "XSS Attempt", "payload": {"country": "IND", "domain": "<script>alert('xss')</script>"}, "desc": "XSS in domain"},
        ]
        
        for test in boundary_tests:
            boundary_folder['item'].append({
                "name": test['name'],
                "request": {
                    "method": "POST",
                    "header": [
                        {"key": "Content-Type", "value": "application/json"},
                        {"key": "Authorization", "value": "{{v2_auth_signature}}"},
                        {"key": "Digest", "value": "BLAKE-512={{v2_digest}}"}
                    ],
                    "body": {"mode": "raw", "raw": json.dumps(test['payload'], indent=2)},
                    "url": {"raw": "{{qa_host}}/v2.0/lookup", "host": ["{{qa_host}}"], "path": ["v2.0", "lookup"]},
                    "description": test['desc']
                }
            })
        
        collection['item'] = [functional_folder, filter_folder, negative_folder, boundary_folder]
        return collection
    
    def create_v3_collection(self) -> dict:
        """Generate Postman collection for V3 Lookup API"""
        
        # Load V3 configs
        functional_config = self.load_yaml_config('resources/registry/lookup/v3/test_lookup_functional.yml')
        negative_config = self.load_yaml_config('resources/registry/lookup/v3/test_lookup_negative.yml')
        filter_config = self.load_yaml_config('resources/registry/lookup/v3/test_lookup_filter_combinations.yml')
        
        qa_config = functional_config['ondcRegistry']
        filter_test = filter_config.get('test', {})
        
        collection = {
            "info": {
                "name": "ONDC Registry Lookup V3 - Complete Test Suite",
                "description": "V3 Lookup API with ED25519 Signature Authentication\n\n"
                              f"QA Host: {qa_config['host']}\n"
                              f"Endpoint: /v3.0/lookup\n\n"
                              "⚠️ V3 requires ED25519 signature authentication.\n"
                              "Use func_test_scripts/utils/ondc_util_auth_signature.py to create signatures.\n\n"
                              "Includes: Functional, Filter Combinations, Negative, and Boundary tests",
                "schema": f"https://schema.getpostman.com/json/collection/v{self.POSTMAN_VERSION}/collection.json"
            },
            "item": [],
            "variable": [
                {"key": "qa_host", "value": qa_config['host'], "type": "string"},
                {"key": "participant_id", "value": qa_config['participant_id'], "type": "string"},
                {"key": "uk_id", "value": qa_config['uk_id'], "type": "string"},
                {"key": "private_key_seed", "value": qa_config['private_key_seed'], "type": "string"},
            ]
        }
        
        # 1. FUNCTIONAL TESTS
        functional_folder = {"name": "Functional Tests", "description": "V3 Lookup positive test cases", "item": []}
        
        default_payload = qa_config.get('default_lookup_payload', {})
        functional_folder['item'].append({
            "name": "Basic Lookup - Country + Type",
            "request": {
                "method": "POST",
                "header": [
                    {"key": "Content-Type", "value": "application/json"},
                    {"key": "Authorization", "value": "{{v3_auth_signature}}", "description": "Generate using func_test_scripts/utils/ondc_util_auth_signature.py"},
                    {"key": "Digest", "value": "BLAKE-512={{v3_digest}}", "description": "BLAKE2b-512 digest"}
                ],
                "body": {"mode": "raw", "raw": json.dumps(default_payload, indent=2)},
                "url": {"raw": "{{qa_host}}/v3.0/lookup", "host": ["{{qa_host}}"], "path": ["v3.0", "lookup"]},
                "description": "Basic V3 lookup with country and type"
            }
        })
        
        # 2. FILTER COMBINATIONS
        filter_folder = {"name": "Filter Combinations", "description": "V3 Lookup with various filter combinations", "item": []}
        
        domains = filter_test.get('default_domains', ["ONDC:RET10", "ONDC:RET11"])
        cities = filter_test.get('default_cities', ["std:080", "std:011"])
        types = filter_test.get('default_types', ["BPP", "BAP"])
        
        # Domain filters
        for domain in domains[:5]:
            filter_folder['item'].append({
                "name": f"Filter by Domain - {domain}",
                "request": {
                    "method": "POST",
                    "header": [
                        {"key": "Content-Type", "value": "application/json"},
                        {"key": "Authorization", "value": "{{v3_auth_signature}}"},
                        {"key": "Digest", "value": "BLAKE-512={{v3_digest}}"}
                    ],
                    "body": {"mode": "raw", "raw": json.dumps({"country": "IND", "domain": domain}, indent=2)},
                    "url": {"raw": "{{qa_host}}/v3.0/lookup", "host": ["{{qa_host}}"], "path": ["v3.0", "lookup"]},
                    "description": f"Lookup participants in domain {domain}"
                }
            })
        
        # City filters
        for city in cities[:5]:
            filter_folder['item'].append({
                "name": f"Filter by City - {city}",
                "request": {
                    "method": "POST",
                    "header": [
                        {"key": "Content-Type", "value": "application/json"},
                        {"key": "Authorization", "value": "{{v3_auth_signature}}"},
                        {"key": "Digest", "value": "BLAKE-512={{v3_digest}}"}
                    ],
                    "body": {"mode": "raw", "raw": json.dumps({"country": "IND", "city": city}, indent=2)},
                    "url": {"raw": "{{qa_host}}/v3.0/lookup", "host": ["{{qa_host}}"], "path": ["v3.0", "lookup"]},
                    "description": f"Lookup participants in city {city}"
                }
            })
        
        # Type filters
        for ptype in types:
            filter_folder['item'].append({
                "name": f"Filter by Type - {ptype}",
                "request": {
                    "method": "POST",
                    "header": [
                        {"key": "Content-Type", "value": "application/json"},
                        {"key": "Authorization", "value": "{{v3_auth_signature}}"},
                        {"key": "Digest", "value": "BLAKE-512={{v3_digest}}"}
                    ],
                    "body": {"mode": "raw", "raw": json.dumps({"country": "IND", "type": ptype}, indent=2)},
                    "url": {"raw": "{{qa_host}}/v3.0/lookup", "host": ["{{qa_host}}"], "path": ["v3.0", "lookup"]},
                    "description": f"Lookup {ptype} participants"
                }
            })
        
        # Combined filters
        filter_folder['item'].append({
            "name": "Combined - Domain + City + Type",
            "request": {
                "method": "POST",
                "header": [
                    {"key": "Content-Type", "value": "application/json"},
                    {"key": "Authorization", "value": "{{v3_auth_signature}}"},
                    {"key": "Digest", "value": "BLAKE-512={{v3_digest}}"}
                ],
                "body": {"mode": "raw", "raw": json.dumps({
                    "country": "IND",
                    "type": "BPP",
                    "domain": domains[0] if domains else "ONDC:RET10",
                    "city": cities[0] if cities else "std:080"
                }, indent=2)},
                "url": {"raw": "{{qa_host}}/v3.0/lookup", "host": ["{{qa_host}}"], "path": ["v3.0", "lookup"]},
                "description": "Lookup with multiple combined filters"
            }
        })
        
        # 3. NEGATIVE TESTS
        negative_folder = {"name": "Negative Tests", "description": "V3 Lookup with invalid inputs and authentication", "item": []}
        
        invalid_auth = qa_config.get('invalid_auth', {})
        
        # Auth negative tests
        negative_folder['item'].append({
            "name": "Missing Authorization Header",
            "request": {
                "method": "POST",
                "header": [{"key": "Content-Type", "value": "application/json"}],
                "body": {"mode": "raw", "raw": json.dumps(default_payload, indent=2)},
                "url": {"raw": "{{qa_host}}/v3.0/lookup", "host": ["{{qa_host}}"], "path": ["v3.0", "lookup"]},
                "description": "Expected: 401 Unauthorized"
            }
        })
        
        if 'invalid_signature' in invalid_auth:
            negative_folder['item'].append({
                "name": "Invalid Signature",
                "request": {
                    "method": "POST",
                    "header": [
                        {"key": "Content-Type", "value": "application/json"},
                        {"key": "Authorization", "value": invalid_auth['invalid_signature']}
                    ],
                    "body": {"mode": "raw", "raw": json.dumps(default_payload, indent=2)},
                    "url": {"raw": "{{qa_host}}/v3.0/lookup", "host": ["{{qa_host}}"], "path": ["v3.0", "lookup"]},
                    "description": "Expected: 401 Invalid Signature"
                }
            })
        
        if 'expired_signature' in invalid_auth:
            negative_folder['item'].append({
                "name": "Expired Signature",
                "request": {
                    "method": "POST",
                    "header": [
                        {"key": "Content-Type", "value": "application/json"},
                        {"key": "Authorization", "value": invalid_auth['expired_signature']}
                    ],
                    "body": {"mode": "raw", "raw": json.dumps(default_payload, indent=2)},
                    "url": {"raw": "{{qa_host}}/v3.0/lookup", "host": ["{{qa_host}}"], "path": ["v3.0", "lookup"]},
                    "description": "Expected: 401 Signature Expired"
                }
            })
        
        # Payload negative tests
        payload_negative_tests = [
            {"name": "Empty Payload", "payload": {}, "desc": "Empty JSON object - Expected: 400"},
            {"name": "Invalid Country Code", "payload": {"country": "INVALID", "type": "BPP"}, "desc": "Invalid country code"},
            {"name": "Invalid Type", "payload": {"country": "IND", "type": "INVALID_TYPE"}, "desc": "Invalid participant type"},
            {"name": "Invalid Domain Format", "payload": {"country": "IND", "domain": "INVALID"}, "desc": "Domain without colon"},
            {"name": "Invalid City Format", "payload": {"country": "IND", "city": "invalid"}, "desc": "City without std: prefix"},
            {"name": "Null Country", "payload": {"country": None, "type": "BPP"}, "desc": "Null country value"},
            {"name": "Numeric Country", "payload": {"country": 123, "type": "BPP"}, "desc": "Country as number"},
            {"name": "Array Payload", "payload": [], "desc": "Array instead of object"},
            {"name": "String Payload", "payload": "string", "desc": "String instead of JSON"},
            {"name": "Missing Country", "payload": {"type": "BPP", "domain": "ONDC:RET10"}, "desc": "Missing required country field"},
        ]
        
        for test in payload_negative_tests:
            raw_body = json.dumps(test['payload'], indent=2) if isinstance(test['payload'], (dict, list)) else f'"{test["payload"]}"'
            negative_folder['item'].append({
                "name": test['name'],
                "request": {
                    "method": "POST",
                    "header": [
                        {"key": "Content-Type", "value": "application/json"},
                        {"key": "Authorization", "value": "{{v3_auth_signature}}"},
                        {"key": "Digest", "value": "BLAKE-512={{v3_digest}}"}
                    ],
                    "body": {"mode": "raw", "raw": raw_body},
                    "url": {"raw": "{{qa_host}}/v3.0/lookup", "host": ["{{qa_host}}"], "path": ["v3.0", "lookup"]},
                    "description": test['desc']
                }
            })
        
        # 4. BOUNDARY TESTS
        boundary_folder = {"name": "Boundary & Edge Cases", "description": "V3 Lookup boundary value and security tests", "item": []}
        
        boundary_tests = [
            {"name": "Very Long Country (100 chars)", "payload": {"country": "A" * 100, "type": "BPP"}, "desc": "Boundary: 100-char country"},
            {"name": "Very Long Domain", "payload": {"country": "IND", "domain": "ONDC:" + "X" * 200}, "desc": "Domain > 200 chars"},
            {"name": "Very Long City", "payload": {"country": "IND", "city": "std:" + "X" * 200}, "desc": "City > 200 chars"},
            {"name": "SQL Injection - Country", "payload": {"country": "IND'; DROP TABLE--", "type": "BPP"}, "desc": "SQL injection in country"},
            {"name": "SQL Injection - Domain", "payload": {"country": "IND", "domain": "ONDC:RET10'; DROP--"}, "desc": "SQL injection in domain"},
            {"name": "XSS - Country", "payload": {"country": "<script>alert('xss')</script>", "type": "BPP"}, "desc": "XSS in country"},
            {"name": "XSS - Domain", "payload": {"country": "IND", "domain": "ONDC:<script>alert()</script>"}, "desc": "XSS in domain"},
            {"name": "Path Traversal", "payload": {"country": "../../etc/passwd", "type": "BPP"}, "desc": "Path traversal attempt"},
            {"name": "Null Bytes", "payload": {"country": "IND\x00NULL", "type": "BPP"}, "desc": "Null byte injection"},
            {"name": "Unicode Characters", "payload": {"country": "IND", "domain": "😀ONDC:RET10"}, "desc": "Unicode in domain"},
            {"name": "LDAP Injection", "payload": {"country": "IND", "type": "BPP)(cn=*"}, "desc": "LDAP injection attempt"},
            {"name": "Command Injection", "payload": {"country": "IND; ls -la", "type": "BPP"}, "desc": "Command injection"},
        ]
        
        for test in boundary_tests:
            boundary_folder['item'].append({
                "name": test['name'],
                "request": {
                    "method": "POST",
                    "header": [
                        {"key": "Content-Type", "value": "application/json"},
                        {"key": "Authorization", "value": "{{v3_auth_signature}}"},
                        {"key": "Digest", "value": "BLAKE-512={{v3_digest}}"}
                    ],
                    "body": {"mode": "raw", "raw": json.dumps(test['payload'], indent=2)},
                    "url": {"raw": "{{qa_host}}/v3.0/lookup", "host": ["{{qa_host}}"], "path": ["v3.0", "lookup"]},
                    "description": f"{test['desc']}\n\nTest for proper input validation, sanitization, and security"
                }
            })
        
        collection['item'] = [functional_folder, filter_folder, negative_folder, boundary_folder]
        return collection
    
    def save_collection(self, collection: dict, filename: str):
        """Save collection to JSON file"""
        output_path = self.output_dir / filename
        with open(output_path, 'w') as f:
            json.dump(collection, f, indent=2)
        print(f"✅ Generated: {output_path}")
        return output_path
    
    def generate_all_collections(self):
        """Generate all lookup collections"""
        print("🔨 Generating Postman Collections for ONDC Registry Lookup APIs...\n")
        
        collections = []
        
        # V1 Collection
        print("📦 Generating V1 Collection...")
        v1_collection = self.create_v1_collection()
        v1_path = self.save_collection(v1_collection, "ONDC_Registry_Lookup_V1.postman_collection.json")
        collections.append(v1_path)
        
        # V2 Collection
        print("\n📦 Generating V2 Collection...")
        v2_collection = self.create_v2_collection()
        v2_path = self.save_collection(v2_collection, "ONDC_Registry_Lookup_V2.postman_collection.json")
        collections.append(v2_path)
        
        # V3 Collection
        print("\n📦 Generating V3 Collection...")
        v3_collection = self.create_v3_collection()
        v3_path = self.save_collection(v3_collection, "ONDC_Registry_Lookup_V3.postman_collection.json")
        collections.append(v3_path)
        
        print("\n" + "="*60)
        print("✨ All Collections Generated Successfully!")
        print("="*60)
        print("\n📂 Output Directory:", self.output_dir.absolute())
        print("\n📝 Import these files into Postman:")
        for path in collections:
            print(f"   - {path.name}")
        
        print("\n⚠️  Authentication Notes:")
        print("   • V1: No authentication required")
        print("   • V2/V3: Requires ED25519 signature")
        print("   • Use func_test_scripts/utils/ondc_util_auth_signature.py to create signatures")
        
        return collections


def main():
    """Main entry point"""
    # Change to project root
    script_dir = Path(__file__).parent
    project_root = script_dir.parent
    os.chdir(project_root)
    
    generator = PostmanCollectionGenerator()
    generator.generate_all_collections()


if __name__ == "__main__":
    main()
