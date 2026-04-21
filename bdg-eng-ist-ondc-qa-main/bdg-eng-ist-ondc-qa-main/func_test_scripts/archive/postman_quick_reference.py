#!/usr/bin/env python3
"""
ONDC Postman Collection Quick Reference

Quick commands to generate Postman collections and signatures
"""

import sys

def print_help():
    print("""
╔══════════════════════════════════════════════════════════════════════════════╗
║                  ONDC Postman Collection - Quick Reference                   ║
╚══════════════════════════════════════════════════════════════════════════════╝

📦 GENERATE POSTMAN COLLECTIONS
───────────────────────────────────────────────────────────────────────────────
  Generate all V1, V2, V3 lookup collections:
  
    python func_test_scripts/generate_postman_collection.py
  
  Output: postman_collections/*.postman_collection.json


🔐 GENERATE AUTHENTICATION SIGNATURES (V2/V3)
───────────────────────────────────────────────────────────────────────────────
  V3 with default config:
  
    python func_test_scripts/generate_signature.py --version v3
  
  
  V2 with default config:
  
    python func_test_scripts/generate_signature.py --version v2
  
  
  V3 with custom payload:
  
    python func_test_scripts/generate_signature.py --version v3 \\
      --payload '{"country": "IND", "type": "BPP", "domain": "ONDC:RET10"}'
  
  
  Custom credentials:
  
    python func_test_scripts/generate_signature.py \\
      --participant-id "your-participant.id" \\
      --uk-id "your-unique-key-id" \\
      --private-key-seed "your-32-byte-hex-seed" \\
      --payload '{"country": "IND", "type": "BPP"}'
  
  
  Extended TTL (10 minutes):
  
    python func_test_scripts/generate_signature.py --version v3 --ttl 600


🚀 QUICK START WORKFLOW
───────────────────────────────────────────────────────────────────────────────
  1. Generate collections:
     python func_test_scripts/generate_postman_collection.py
  
  2. Import into Postman:
     - Open Postman → Import
     - Select files from postman_collections/
  
  3. For V1 (no auth):
     - Just click Send on any request
  
  4. For V2/V3 (requires auth):
     a) Generate signature:
        python func_test_scripts/generate_signature.py --version v3
     
     b) Copy headers from output into Postman
     
     c) Send request


📖 COLLECTION FILES
───────────────────────────────────────────────────────────────────────────────
  postman_collections/
  ├── ONDC_Registry_Lookup_V1.postman_collection.json  (V1 - no auth)
  ├── ONDC_Registry_Lookup_V2.postman_collection.json  (V2 - ED25519 auth)
  ├── ONDC_Registry_Lookup_V3.postman_collection.json  (V3 - ED25519 auth)
  └── README.md                                         (Detailed docs)


🌐 API ENDPOINTS
───────────────────────────────────────────────────────────────────────────────
  QA Environment: http://35.200.190.239:8080
  
  V1: POST /lookup
  V2: POST /v2.0/lookup
  V3: POST /v3.0/lookup


📋 EXAMPLE PAYLOADS
───────────────────────────────────────────────────────────────────────────────
  V1 (simple):
    {"country": "IND", "type": "BPP"}
  
  V2/V3 (basic):
    {"country": "IND", "type": "BPP"}
  
  V3 (with filters):
    {
      "country": "IND",
      "type": "BPP",
      "domain": "ONDC:RET10",
      "city": "std:080"
    }


⚠️  IMPORTANT NOTES
───────────────────────────────────────────────────────────────────────────────
  • V2/V3 signatures expire after 5 minutes (default)
  • Regenerate signature for each new request or after expiration
  • The payload you sign MUST exactly match what you send
  • V1 doesn't require any authentication


🔗 MORE HELP
───────────────────────────────────────────────────────────────────────────────
  Detailed documentation:
    cat postman_collections/README.md
  
  Script help:
    python func_test_scripts/generate_signature.py --help
    python func_test_scripts/generate_postman_collection.py --help


╚══════════════════════════════════════════════════════════════════════════════╝
""")

if __name__ == '__main__':
    print_help()
