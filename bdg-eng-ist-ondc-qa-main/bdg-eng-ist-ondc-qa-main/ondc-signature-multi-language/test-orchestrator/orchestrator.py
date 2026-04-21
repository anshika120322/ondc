"""
ONDC Multi-Language Test Orchestrator

Runs all language implementations and generates comprehensive compatibility report.
"""

import json
import os
import subprocess
import time
from datetime import datetime
from report_generator import generate_html_report


def run_language_test(language, container_name):
    """Run test for a specific language"""
    print(f"\n{'='*80}")
    print(f"Running {language} tests...")
    print('='*80)
    
    start_time = time.time()
    
    try:
        # Run the container
        result = subprocess.run(
            ['docker-compose', 'run', '--rm', f'{language.lower()}-signature'],
            cwd='/app',
            capture_output=True,
            text=True,
            timeout=120
        )
        
        elapsed_time = time.time() - start_time
        
        print(result.stdout)
        if result.stderr:
            print(f"Errors: {result.stderr}")
        
        success = result.returncode == 0
        
        return {
            'language': language,
            'status': 'PASS' if success else 'FAIL',
            'elapsed_time': round(elapsed_time, 2),
            'stdout': result.stdout,
            'stderr': result.stderr
        }
        
    except subprocess.TimeoutExpired:
        elapsed_time = time.time() - start_time
        print(f"❌ {language} tests timed out after 120 seconds")
        return {
            'language': language,
            'status': 'TIMEOUT',
            'elapsed_time': round(elapsed_time, 2),
            'stdout': '',
            'stderr': 'Test execution timed out'
        }
    except Exception as e:
        elapsed_time = time.time() - start_time
        print(f"❌ {language} tests failed: {e}")
        return {
            'language': language,
            'status': 'ERROR',
            'elapsed_time': round(elapsed_time, 2),
            'stdout': '',
            'stderr': str(e)
        }


def load_test_results():
    """Load all test results from reports directory"""
    results = {}
    languages = ['python', 'java', 'nodejs', 'golang', 'php', 'ruby']
    
    for lang in languages:
        lang_results = {
            'keys': None,
            'digests': None,
            'signatures': None,
            'api_test': None
        }
        
        # Load keys
        keys_file = f'/reports/{lang}-keys.json'
        if os.path.exists(keys_file):
            with open(keys_file, 'r') as f:
                lang_results['keys'] = json.load(f)
        
        # Load digests
        digests_file = f'/reports/{lang}-digests.json'
        if os.path.exists(digests_file):
            with open(digests_file, 'r') as f:
                lang_results['digests'] = json.load(f)
        
        # Load signatures
        signatures_file = f'/reports/{lang}-signatures.json'
        if os.path.exists(signatures_file):
            with open(signatures_file, 'r') as f:
                lang_results['signatures'] = json.load(f)
        
        # Load API test
        api_file = f'/reports/{lang}-api-test.json'
        if os.path.exists(api_file):
            with open(api_file, 'r') as f:
                lang_results['api_test'] = json.load(f)
        
        results[lang] = lang_results
    
    return results


def verify_cross_language_consistency(results):
    """Verify that all languages produce identical outputs"""
    print(f"\n{'='*80}")
    print("CROSS-LANGUAGE CONSISTENCY VERIFICATION")
    print('='*80)
    
    consistency_report = {
        'public_keys_match': True,
        'digests_match': {},
        'signatures_match': {},
        'all_api_tests_passed': True
    }
    
    # Get Python results as reference (baseline)
    python_results = results.get('python', {})
    reference_public_key = python_results.get('keys', {}).get('public_key')
    
    # Check public key consistency
    print("\n1. Public Key Consistency:")
    for lang, lang_results in results.items():
        if lang_results.get('keys'):
            pub_key = lang_results['keys'].get('public_key')
            matches = pub_key == reference_public_key
            consistency_report['public_keys_match'] &= matches
            
            status = "✅ MATCH" if matches else "❌ MISMATCH"
            print(f"   {lang.capitalize()}: {status}")
    
    # Check digest consistency
    print("\n2. Digest Consistency (per test case):")
    if python_results.get('digests'):
        for test_digest in python_results['digests'].get('digests', []):
            test_name = test_digest['test_name']
            reference_digest = test_digest['digest']
            
            all_match = True
            for lang, lang_results in results.items():
                if lang == 'python':
                    continue
                if lang_results.get('digests'):
                    lang_digest = next(
                        (d['digest'] for d in lang_results['digests'].get('digests', []) 
                         if d['test_name'] == test_name),
                        None
                    )
                    if lang_digest != reference_digest:
                        all_match = False
                        break
            
            consistency_report['digests_match'][test_name] = all_match
            status = "✅ ALL MATCH" if all_match else "❌ MISMATCH"
            print(f"   {test_name}: {status}")
    
    # Check signature consistency
    print("\n3. Signature Consistency (per test case):")
    if python_results.get('signatures'):
        for test_sig in python_results['signatures'].get('signatures', []):
            test_name = test_sig['test_name']
            reference_auth = test_sig['authorization']
            
            all_match = True
            for lang, lang_results in results.items():
                if lang == 'python':
                    continue
                if lang_results.get('signatures'):
                    lang_auth = next(
                        (s['authorization'] for s in lang_results['signatures'].get('signatures', []) 
                         if s['test_name'] == test_name),
                        None
                    )
                    if lang_auth != reference_auth:
                        all_match = False
                        break
            
            consistency_report['signatures_match'][test_name] = all_match
            status = "✅ ALL MATCH" if all_match else "❌ MISMATCH"
            print(f"   {test_name}: {status}")
    
    # Check API test results
    print("\n4. Live API Test Results:")
    for lang, lang_results in results.items():
        if lang_results.get('api_test'):
            api_result = lang_results['api_test'].get('result', {})
            status_val = api_result.get('status', 'UNKNOWN')
            code = api_result.get('code', 'N/A')
            
            passed = status_val == 'PASS'
            consistency_report['all_api_tests_passed'] &= passed
            
            status = f"✅ {status_val} (Code: {code})" if passed else f"❌ {status_val} (Code: {code})"
            print(f"   {lang.capitalize()}: {status}")
    
    return consistency_report


def main():
    """Main orchestrator function"""
    print("╔" + "="*78 + "╗")
    print("║" + " ONDC MULTI-LANGUAGE SIGNATURE TEST ORCHESTRATOR ".center(78) + "║")
    print("╚" + "="*78 + "╝")
    
    start_time = datetime.now()
    
    # Define languages to test
    languages = [
        ('Python', 'ondc-python'),
        ('Java', 'ondc-java'),
        ('Node.js', 'ondc-nodejs'),
        ('Go', 'ondc-golang'),
        ('PHP', 'ondc-php'),
        ('Ruby', 'ondc-ruby')
    ]
    
    # Run tests for each language
    test_results = []
    for lang_name, container in languages:
        result = run_language_test(lang_name, container)
        test_results.append(result)
    
    # Load all test results from JSON files
    detailed_results = load_test_results()
    
    # Verify cross-language consistency
    consistency = verify_cross_language_consistency(detailed_results)
    
    # Generate HTML report
    print(f"\n{'='*80}")
    print("Generating HTML report...")
    print('='*80)
    
    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()
    
    report_data = {
        'test_date': start_time.strftime('%Y-%m-%d %H:%M:%S'),
        'duration': round(duration, 2),
        'test_results': test_results,
        'detailed_results': detailed_results,
        'consistency': consistency,
        'summary': {
            'total_languages': len(languages),
            'passed': sum(1 for r in test_results if r['status'] == 'PASS'),
            'failed': sum(1 for r in test_results if r['status'] in ['FAIL', 'ERROR', 'TIMEOUT'])
        }
    }
    
    html_report = generate_html_report(report_data)
    
    with open('/reports/compatibility-report.html', 'w') as f:
        f.write(html_report)
    
    print(f"✅ HTML report generated: /reports/compatibility-report.html")
    
    # Final summary
    print(f"\n{'='*80}")
    print("TEST ORCHESTRATION COMPLETE")
    print('='*80)
    print(f"Total Duration: {duration:.2f} seconds")
    print(f"Languages Tested: {report_data['summary']['total_languages']}")
    print(f"Passed: {report_data['summary']['passed']}")
    print(f"Failed: {report_data['summary']['failed']}")
    print(f"Public Keys Consistent: {'✅ YES' if consistency['public_keys_match'] else '❌ NO'}")
    print(f"All API Tests Passed: {'✅ YES' if consistency['all_api_tests_passed'] else '❌ NO'}")
    print('='*80)


if __name__ == '__main__':
    main()
