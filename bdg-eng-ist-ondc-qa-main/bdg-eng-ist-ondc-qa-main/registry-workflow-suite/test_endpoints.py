#!/usr/bin/env python3
"""Quick test for domain/enum endpoints"""
import requests
import yaml

# Load config to get auth
with open('config/test_suite.yaml') as f:
    config = yaml.safe_load(f)

auth_url = config['config']['auth_url']
admin_user = config['config'].get('admin_username', 'admin')
admin_pass = config['config'].get('admin_password', 'admin123')

# Get token
auth_resp = requests.post(auth_url, json={'username': admin_user, 'password': admin_pass})
token = auth_resp.json().get('access_token')
headers = {'Authorization': f'Bearer {token}', 'Accept': 'application/json'}

base_url = 'https://registry-preprod.ondc.org'

# Test endpoints
endpoints = [
    '/admin/domains',
    '/admin/domains/name/ONDC:RET1A',
    '/admin/domains/name/NON_EXISTENT_DOMAIN_CODE_12345',
    '/admin/enums/category/NP_TYPE',
    '/admin/enums/category/NON_EXISTENT_CATEGORY_12345',
]

print("Testing domain/enum endpoints:")
print("=" * 60)
for ep in endpoints:
    try:
        resp = requests.get(f'{base_url}{ep}', headers=headers, timeout=10)
        print(f'\n{ep}')
        print(f'  Status: {resp.status_code}')
        if resp.status_code < 300:
            print(f'  ✓ Success!')
        elif resp.status_code == 403:
            print(f'  ✗ Blocked (403)')
        elif resp.status_code == 404:
            print(f'  ✓ Not found (404) - as expected!')
        
        if len(resp.text) < 500:
            print(f'  Response: {resp.text[:200]}')
    except Exception as e:
        print(f'\n{ep}')
        print(f'  Error: {e}')
