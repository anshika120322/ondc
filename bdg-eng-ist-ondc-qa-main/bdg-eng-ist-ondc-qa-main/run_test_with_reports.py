#!/usr/bin/env python3
"""
Enhanced Test Runner for ONDC Registry Tests
Generates custom HTML and JSON reports (similar to test-suite-v2) instead of default Locust reports.

Usage:
    python run_test_with_reports.py --test ondc_reg_v3_lookup_functional --env ondcRegistry --users 1 --run-time 60s
"""

import sys
import json
import os
from datetime import datetime
from argparse import ArgumentParser
from pathlib import Path
from typing import List, Dict, Any
from locust import events
from common_test_foundation.main import main, add_custom_arguments, parse_arguments

# Import HTMLReporter from test-suite-v2
test_suite_v2_path = Path(__file__).parent / "test-suite-v2 3"
if test_suite_v2_path.exists():
    sys.path.insert(0, str(test_suite_v2_path))
    try:
        from src.utils.html_reporter import HTMLReporter
    except ImportError:
        print("[WARNING] Could not import HTMLReporter from test-suite-v2 3. HTML report generation may fail.")
        HTMLReporter = None
else:
    print("[WARNING] test-suite-v2 3 not found. HTML report generation may fail.")
    HTMLReporter = None


class TestResultCollector:
    """Collects test results from Locust events and generates custom reports."""
    
    _instance = None  # Singleton instance
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        # Only initialize once
        if hasattr(self, '_initialized'):
            return
        self._initialized = True
        
        self.results: List[Dict[str, Any]] = []
        self.test_start_time = datetime.now()
        self.request_counter = {}
        
        # Register event listeners
        events.request.add_listener(self.on_request)
        events.test_stop.add_listener(self.on_test_stop)
        
    def on_request(self, request_type, name, response_time, response_length, 
                   response=None, context=None, exception=None, **kwargs):
        """Capture each request/response for reporting."""
        
        try:
            # Track unique test executions
            if name not in self.request_counter:
                self.request_counter[name] = 1
            else:
                self.request_counter[name] += 1
            
            test_id = name
            passed = exception is None
            
            # Extract request/response details if available
            request_data = {}
            response_data = {}
            error_message = None
            
            if hasattr(response, 'request'):
                req = response.request
                body = req.body if hasattr(req, 'body') else None
                if body is not None:
                    if isinstance(body, bytes):
                        body = body.decode('utf-8')
                request_data = {
                    'method': req.method,
                    'url': req.url,
                    'headers': dict(req.headers) if hasattr(req, 'headers') else {},
                    'body': body
                }
                
            if response is not None:
                response_data = {
                    'status_code': getattr(response, 'status_code', None),
                    'headers': dict(getattr(response, 'headers', {})),
                    'body': None
                }
                try:
                    response_data['body'] = response.json() if hasattr(response, 'json') else response.text
                except:
                    response_data['body'] = getattr(response, 'text', str(response))
            
            if exception:
                error_message = str(exception)
                # Try to extract error from response if available
                if response is not None:
                    try:
                        if hasattr(response, 'json'):
                            error_data = response.json()
                            if isinstance(error_data, dict):
                                error_message = json.dumps(error_data, indent=2)
                    except:
                        pass
            
            # Format data for HTMLReporter compatibility
            result = {
                'test_id': test_id,
                'name': test_id,
                'test_name': test_id,
                'passed': passed,
                'execution_time_ms': int(response_time),
                'timestamp': datetime.now().isoformat(),
                'response_time_ms': int(response_time),
                'response_length': response_length,
                'status_code': response_data.get('status_code') if response_data else None,
                'error_message': error_message,
                # Format request/response for HTMLReporter (expects lists for multi-step workflows)
                'request_details': [{
                    'method': request_data.get('method', 'POST'),
                    'url': request_data.get('url', ''),
                    'endpoint': request_data.get('url', ''),
                    'headers': request_data.get('headers', {}),
                    'body': request_data.get('body'),
                    'step_name': test_id
                }] if request_data else [],
                'response_details': [{
                    'status_code': response_data.get('status_code'),
                    'headers': response_data.get('headers', {}),
                    'body': response_data.get('body'),
                    'step_name': test_id
                }] if response_data else [],
                # Keep original format for JSON export
                'request': request_data,
                'response': response_data,
                'error': error_message,
            }
            
            self.results.append(result)
        except Exception as e:
            print(f"[ERROR] Failed to capture request '{name}': {e}")
    
    def on_test_stop(self, **kwargs):
        """Generate reports when test execution stops."""
        self.generate_reports()
    
    def generate_reports(self):
        """Generate both HTML and JSON reports."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = Path("output")
        output_dir.mkdir(exist_ok=True)
        
        # Determine test name from results
        test_name = "registry_lookup_tests"
        if self.results:
            first_test = self.results[0].get('test_id', '')
            if 'lookup' in first_test.lower():
                test_name = "registry_lookup_tests"
            elif 'subscribe' in first_test.lower():
                test_name = "registry_subscribe_tests"
        
        # Generate JSON report
        json_file = output_dir / f"{test_name}_{timestamp}.json"
        self._generate_json_report(json_file)
        
        # Generate HTML report
        html_file = output_dir / f"{test_name}_{timestamp}.html"
        self._generate_html_report(html_file)
        
        print(f"\n{'='*80}")
        print(f"📊 CUSTOM REPORTS GENERATED:")
        print(f"{'='*80}")
        print(f"📄 HTML Report: {html_file}")
        print(f"📄 JSON Report: {json_file}")
        print(f"{'='*80}\n")
    
    def _generate_json_report(self, output_file: Path):
        """Generate JSON report with test results."""
        report_data = {
            'test_suite': 'ONDC Registry Tests',
            'timestamp': datetime.now().isoformat(),
            'start_time': self.test_start_time.isoformat(),
            'total_tests': len(set(r['test_id'] for r in self.results)),
            'total_requests': len(self.results),
            'passed': sum(1 for r in self.results if r.get('passed')),
            'failed': sum(1 for r in self.results if not r.get('passed')),
            'results': self.results
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
    
    def _generate_html_report(self, output_file: Path):
        """Generate HTML report using test-suite-v2 HTMLReporter."""
        if HTMLReporter is None:
            print("[WARNING] HTMLReporter not available. Skipping HTML generation.")
            return
        
        try:
            # Deduplicate results - keep only unique test IDs with latest execution
            unique_results = {}
            for result in self.results:
                test_id = result['test_id']
                # Keep the result, preferring failures over passes for better visibility
                if test_id not in unique_results or not result['passed']:
                    unique_results[test_id] = result
            
            results_list = list(unique_results.values())
            
            test_suite_name = "ONDC Registry Lookup Tests - V3 API"
            if results_list and 'subscribe' in results_list[0].get('test_id', '').lower():
                test_suite_name = "ONDC Registry Subscribe Tests"
            
            HTMLReporter.generate_report(
                results=results_list,
                output_file=str(output_file),
                test_suite_name=test_suite_name
            )
        except Exception as e:
            print(f"[ERROR] Failed to generate HTML report: {e}")
            import traceback
            traceback.print_exc()


def setup_parser_arguments(parser: ArgumentParser):
    """Define custom arguments."""
    custom_group = parser.add_argument_group("Custom Report Options")
    custom_group.add_argument(
        '--skip-locust-html',
        action='store_true',
        help="Skip generating Locust HTML report (custom reports will still be generated)"
    )
    custom_group.add_argument(
        '--output-dir',
        type=str,
        default='output',
        help="Directory for output reports (default: output)"
    )


def process_html_argument():
    """Process --html argument to handle datetime placeholder."""
    for i, arg in enumerate(sys.argv):
        if arg == "--html" and i + 1 < len(sys.argv):
            report_path = sys.argv[i + 1]
            if "{datetime}" in report_path:
                now = datetime.now().strftime("%Y%m%d_%H%M%S")
                sys.argv[i + 1] = report_path.replace("{datetime}", now)
        
        # Remove --html argument if --skip-locust-html is present
        if arg == "--skip-locust-html":
            # Find and remove --html and its value
            new_argv = []
            skip_next = False
            for j, a in enumerate(sys.argv):
                if skip_next:
                    skip_next = False
                    continue
                if a == "--html":
                    skip_next = True  # Skip the next arg (the html file path)
                    continue
                new_argv.append(a)
            sys.argv = new_argv
            break


if __name__ == "__main__":
    """Main entry point - initialize result collector and start test framework."""
    
    # Initialize result collector (registers event listeners)
    collector = TestResultCollector()
    
    # Process arguments
    process_html_argument()
    add_custom_arguments(function=setup_parser_arguments)
    parse_arguments()
    
    # Run the test framework
    main()
