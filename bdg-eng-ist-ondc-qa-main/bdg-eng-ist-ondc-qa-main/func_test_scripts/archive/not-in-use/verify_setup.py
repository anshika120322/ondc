#!/usr/bin/env python3
"""
ONDC Gateway Testing - Setup Verification Script
Checks prerequisites and configuration before running tests
"""

import sys
import os
from pathlib import Path

def print_header(text):
    print("\n" + "="*70)
    print(f"  {text}")
    print("="*70)

def print_success(text):
    print(f"[OK] {text}")

def print_error(text):
    print(f"[ERROR] {text}")

def print_warning(text):
    print(f"[WARNING] {text}")

def check_python_version():
    """Check Python version"""
    version = sys.version_info
    if version.major >= 3 and version.minor >= 8:
        print_success(f"Python version: {version.major}.{version.minor}.{version.micro}")
        return True
    else:
        print_error(f"Python version {version.major}.{version.minor} is too old (need 3.8+)")
        return False

def check_dependencies():
    """Check required Python packages"""
    required_packages = {
        'locust': 'Locust (load testing framework)',
        'common_test_foundation': 'Common Test Foundation framework',
        'cryptography': 'Cryptography library for Ed25519 signatures',
        'requests': 'HTTP client library',
        'yaml': 'PyYAML (config parsing)',
        'pymongo': 'PyMongo (BSON support)'
    }
    
    all_installed = True
    for package, description in required_packages.items():
        try:
            __import__(package)
            print_success(f"{package}: installed")
        except ImportError:
            print_error(f"{package}: NOT INSTALLED ({description})")
            all_installed = False
    
    # Check for problematic standalone bson package
    try:
        import bson
        if hasattr(bson, '__version__'):
            print_warning("Standalone 'bson' package detected - this conflicts with pymongo!")
            print("         Run: pip uninstall bson -y")
            all_installed = False
    except ImportError:
        pass  # This is fine, pymongo provides bson
    
    return all_installed

def check_file_structure():
    """Check required files and directories exist"""
    base_dir = Path(__file__).parent.parent
    
    required_files = [
        'tests/ondc_gateway_search.py',
        'tests/ondc_gateway_lookup.py',
        'tests/utils/ondc_auth_helper.py',
        'tests/utils/ondc_lookup_helper.py',
        'resources/ondc_gateway_search.yml',
        'config.yml',
        'driver.py',
        'requirements.txt'
    ]
    
    all_exist = True
    for file_path in required_files:
        full_path = base_dir / file_path
        if full_path.exists():
            print_success(f"{file_path}")
        else:
            print_error(f"{file_path}: NOT FOUND")
            all_exist = False
    
    return all_exist

def check_configuration():
    """Check configuration file"""
    base_dir = Path(__file__).parent.parent
    config_file = base_dir / 'resources' / 'ondc_gateway_search.yml'
    
    if not config_file.exists():
        print_error("Configuration file not found")
        return False
    
    try:
        with open(config_file, 'r') as f:
            content = f.read()
            
        checks = {
            'ondcGatewaySearch': 'Environment configuration',
            'host:': 'Gateway host URL',
            'lookup_host:': 'Lookup host URL',
            'participant_id:': 'Participant ID',
            'private_key_seed:': 'Private key seed'
        }
        
        all_present = True
        for key, description in checks.items():
            if key in content:
                print_success(f"{description}")
            else:
                print_error(f"{description}: NOT FOUND in config")
                all_present = False
        
        return all_present
        
    except Exception as e:
        print_error(f"Error reading config file: {e}")
        return False

def test_auth_helper():
    """Test the authentication helper"""
    try:
        sys.path.insert(0, str(Path(__file__).parent.parent))
        from tests.utils.ondc_auth_helper import ONDCAuthHelper
        
        helper = ONDCAuthHelper(
            participant_id="test-participant",
            uk_id="test-key"
        )
        
        test_payload = {
            "context": {
                "domain": "ONDC:RET10",
                "action": "search"
            },
            "message": {
                "intent": {}
            }
        }
        
        headers = helper.generate_headers(test_payload)
        
        required_headers = ['Authorization', 'Digest', 'Content-Type']
        all_present = True
        
        for header in required_headers:
            if header in headers:
                print_success(f"Generated {header} header")
            else:
                print_error(f"{header} header not generated")
                all_present = False
        
        return all_present
        
    except Exception as e:
        print_error(f"Auth helper test failed: {e}")
        return False

def check_gateway_connectivity():
    """Check if Gateway API is reachable"""
    try:
        import requests
        import yaml
        
        base_dir = Path(__file__).parent.parent
        config_file = base_dir / 'resources' / 'ondc_gateway_search.yml'
        
        with open(config_file, 'r') as f:
            config = yaml.safe_load(f)
        
        gateway_url = config['ondcGatewaySearch']['host']
        health_url = f"{gateway_url}/health"
        
        print(f"Testing connectivity to: {health_url}")
        
        response = requests.get(health_url, timeout=5)
        
        if response.status_code == 200:
            print_success(f"Gateway is reachable (HTTP {response.status_code})")
            return True
        else:
            print_warning(f"Gateway returned HTTP {response.status_code}")
            return False
            
    except requests.exceptions.RequestException as e:
        print_warning(f"Could not connect to Gateway: {e}")
        print_warning("This is OK if Gateway is not running locally")
        return False
    except Exception as e:
        print_warning(f"Connectivity check failed: {e}")
        return False

def print_next_steps(all_checks_passed):
    """Print next steps for the user"""
    print("\n" + "="*70)
    
    if all_checks_passed:
        print("  [SUCCESS] Setup Verification: PASSED")
        print("="*70)
        print("\nYou are ready to run tests!")
        print("\nQuick Start:")
        print("  ./func_test_scripts/run_gateway_tests.sh")
        print("\nOr run individual tests:")
        print("  python driver.py ondc_gateway_search_functional \\")
        print("    --environment ondcGatewaySearch \\")
        print("    --iterations 5 \\")
        print("    --html results/functional_report.html")
        print("\nDocumentation:")
        print("  docs/ONDC_GATEWAY_TESTING.md")
        print("  docs/TESTING_APPROACH.md")
    else:
        print("  [FAILED] Setup Verification: FAILED")
        print("="*70)
        print("\nPlease fix the issues above before running tests.")
        print("\nTo install missing dependencies:")
        print("  pip install -r requirements.txt")
        print("\nFor more help, see:")
        print("  docs/ONDC_GATEWAY_TESTING.md")

def main():
    """Main verification function"""
    print_header("ONDC Gateway Testing - Setup Verification")
    
    results = []
    
    # Check Python version
    print_header("1. Python Environment")
    results.append(check_python_version())
    
    # Check dependencies
    print_header("2. Python Dependencies")
    results.append(check_dependencies())
    
    # Check file structure
    print_header("3. File Structure")
    results.append(check_file_structure())
    
    # Check configuration
    print_header("4. Configuration")
    results.append(check_configuration())
    
    # Test auth helper
    print_header("5. Authentication Helper")
    results.append(test_auth_helper())
    
    # Check Gateway connectivity (optional)
    print_header("6. Gateway Connectivity (Optional)")
    check_gateway_connectivity()  # Don't fail if Gateway is not reachable
    
    # Print summary
    all_passed = all(results)
    print_next_steps(all_passed)
    
    return 0 if all_passed else 1

if __name__ == "__main__":
    sys.exit(main())
