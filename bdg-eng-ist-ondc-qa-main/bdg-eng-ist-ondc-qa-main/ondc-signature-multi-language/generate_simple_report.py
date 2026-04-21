#!/usr/bin/env python3
"""
Generate comprehensive summary report from all language test results
"""

import json
import os
from datetime import datetime


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
        keys_file = f'reports/{lang}-keys.json'
        if os.path.exists(keys_file):
            with open(keys_file, 'r') as f:
                lang_results['keys'] = json.load(f)
        
        # Load digests
        digests_file = f'reports/{lang}-digests.json'
        if os.path.exists(digests_file):
            with open(digests_file, 'r') as f:
                lang_results['digests'] = json.load(f)
        
        # Load signatures
        signatures_file = f'reports/{lang}-signatures.json'
        if os.path.exists(signatures_file):
            with open(signatures_file, 'r') as f:
                lang_results['signatures'] = json.load(f)
        
        # Load API test
        api_file = f'reports/{lang}-api-test.json'
        if os.path.exists(api_file):
            with open(api_file, 'r') as f:
                lang_results['api_test'] = json.load(f)
        
        results[lang] = lang_results
    
    return results


def verify_cross_language_consistency(results):
    """Verify that all languages produce identical outputs"""
    report = {
        'public_keys_match': True,
        'public_key_value': None,
        'digests_match': {},
        'signatures_match': {},
        'api_tests': {}
    }
    
    # Get Python results as reference (baseline)
    python_results = results.get('python', {})
    reference_public_key = python_results.get('keys', {}).get('public_key')
    report['public_key_value'] = reference_public_key
    
    # Check public key consistency
    for lang, lang_results in results.items():
        if lang_results.get('keys'):
            pub_key = lang_results['keys'].get('public_key')
            matches = pub_key == reference_public_key
            report['public_keys_match'] &= matches
    
    # Check digest consistency
    if python_results.get('digests'):
        for test_digest in python_results['digests'].get('digests', []):
            test_name = test_digest['test_name']
            reference_digest = test_digest['digest']
            
            test_results = {'reference': reference_digest, 'matches': {}}
            for lang, lang_results in results.items():
                if lang_results.get('digests'):
                    lang_digest = next(
                        (d['digest'] for d in lang_results['digests'].get('digests', []) 
                         if d['test_name'] == test_name),
                        None
                    )
                    test_results['matches'][lang] = (lang_digest == reference_digest, lang_digest)
            
            report['digests_match'][test_name] = test_results
    
    # Check signature consistency
    if python_results.get('signatures'):
        for test_sig in python_results['signatures'].get('signatures', []):
            test_name = test_sig['test_name']
            reference_auth = test_sig['authorization']
            
            test_results = {'reference': reference_auth[:80] + '...', 'matches': {}}
            for lang, lang_results in results.items():
                if lang_results.get('signatures'):
                    lang_auth = next(
                        (s['authorization'] for s in lang_results['signatures'].get('signatures', []) 
                         if s['test_name'] == test_name),
                        None
                    )
                    test_results['matches'][lang] = (lang_auth == reference_auth, lang_auth[:80] + '...' if lang_auth else None)
            
            report['signatures_match'][test_name] = test_results
    
    # Collect API test results
    for lang, lang_results in results.items():
        if lang_results.get('api_test'):
            api_result = lang_results['api_test'].get('result', {})
            report['api_tests'][lang] = {
                'status': api_result.get('status', 'UNKNOWN'),
                'code': api_result.get('code', 'N/A'),
                'message': api_result.get('message', '')
            }
    
    return report


def generate_text_report(results, consistency_report):
    """Generate text-based summary report"""
    
    report_lines = []
    report_lines.append("="*100)
    report_lines.append("ONDC MULTI-LANGUAGE SIGNATURE COMPATIBILITY TEST REPORT")
    report_lines.append("="*100)
    report_lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report_lines.append(f"Languages Tested: Python, Java, Node.js, Go, PHP, Ruby")
    report_lines.append("="*100)
    report_lines.append("")
    
    # Summary
    report_lines.append("SUMMARY")
    report_lines.append("-"*100)
    all_pass = all(all(match[0] for match in test['matches'].values()) 
                   for test in consistency_report['digests_match'].values())
    report_lines.append(f"Public Keys Match: {'✅ YES' if consistency_report['public_keys_match'] else '❌ NO'}")
    report_lines.append(f"All Digests Match: {'✅ YES' if all_pass else '❌ NO'}")
    report_lines.append(f"All Signatures Match: {'✅ YES' if all(all(match[0] for match in test['matches'].values()) for test in consistency_report['signatures_match'].values()) else '❌ NO'}")
    report_lines.append("")
    
    # Public Key
    report_lines.append("PUBLIC KEY CONSISTENCY")
    report_lines.append("-"*100)
    ref_key = consistency_report['public_key_value']
    if ref_key:
        report_lines.append(f"Reference Public Key (Python): {ref_key[:60]}...")
        for lang in ['python', 'java', 'nodejs', 'golang', 'php', 'ruby']:
            if results[lang].get('keys'):
                lang_key = results[lang]['keys'].get('public_key')
                match = "✅ MATCH" if lang_key == ref_key else "❌ MISMATCH"
                report_lines.append(f"  {lang.upper():10s}: {match}")
    report_lines.append("")
    
    # Digests
    report_lines.append("DIGEST CONSISTENCY (by test case)")
    report_lines.append("-"*100)
    for test_name, test_data in consistency_report['digests_match'].items():
        all_match = all(match[0] for match in test_data['matches'].values())
        status = "✅ ALL MATCH" if all_match else "❌ MISMATCH DETECTED"
        report_lines.append(f"\nTest: {test_name} - {status}")
        report_lines.append(f"  Reference: {test_data['reference'][:60]}...")
        for lang, (matches, digest) in test_data['matches'].items():
            match_str = "✅" if matches else "❌"
            report_lines.append(f"  {lang.upper():10s}: {match_str} {digest[:60] if digest else 'N/A'}...")
    report_lines.append("")
    
    # Signatures
    report_lines.append("SIGNATURE CONSISTENCY (by test case)")
    report_lines.append("-"*100)
    for test_name, test_data in consistency_report['signatures_match'].items():
        all_match = all(match[0] for match in test_data['matches'].values())
        status = "✅ ALL MATCH" if all_match else "❌ MISMATCH DETECTED"
        report_lines.append(f"\nTest: {test_name} - {status}")
        for lang, (matches, auth) in test_data['matches'].items():
            match_str = "✅" if matches else "❌"
            report_lines.append(f"  {lang.upper():10s}: {match_str}")
    report_lines.append("")
    
    # API Tests
    report_lines.append("LIVE API LOOKUP TEST RESULTS")
    report_lines.append("-"*100)
    for lang, api_data in consistency_report['api_tests'].items():
        status_emoji = "✅" if api_data['status'] == 'PASS' else "❌"
        report_lines.append(f"{lang.upper():10s}: {status_emoji} Status={api_data['status']}, Code={api_data['code']}, Message={api_data['message']}")
    report_lines.append("")
    
    report_lines.append("="*100)
    report_lines.append("END OF REPORT")
    report_lines.append("="*100)
    
    return '\n'.join(report_lines)


def main():
    print("Loading test results...")
    results = load_test_results()
    
    print("Analyzing cross-language consistency...")
    consistency_report = verify_cross_language_consistency(results)
    
    print("Generating report...")
    report_text = generate_text_report(results, consistency_report)
    
    # Print to console
    print("\n" + report_text)
    
    # Save to file
    report_file = 'reports/COMPATIBILITY_REPORT.txt'
    with open(report_file, 'w') as f:
        f.write(report_text)
    
    print(f"\n✅ Report saved to: {report_file}")
    
    # Also save detailed JSON report
    json_report_file = 'reports/compatibility-report.json'
    with open(json_report_file, 'w') as f:
        json.dump({
            'generated_at': datetime.now().isoformat(),
            'results': results,
            'consistency': consistency_report
        }, f, indent=2)
    
    print(f"✅ Detailed JSON report saved to: {json_report_file}")


if __name__ == '__main__':
    main()
