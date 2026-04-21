"""
HTML Report Generator for ONDC Multi-Language Signature Tests
"""

from jinja2 import Environment, select_autoescape


HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ONDC Multi-Language Signature Compatibility Report</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto,  'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
            padding: 20px;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        
        header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }
        
        header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        
        header p {
            font-size: 1.2em;
            opacity: 0.9;
        }
        
        .meta-info {
            background: #f8f9fa;
            padding: 20px 40px;
            border-bottom: 1px solid #dee2e6;
            display: flex;
            justify-content: space-between;
            flex-wrap: wrap;
            gap: 20px;
        }
        
        .meta-item {
            flex: 1;
            min-width: 200px;
        }
        
        .meta-label {
            font-size: 0.9em;
            color: #6c757d;
            margin-bottom: 5px;
        }
        
        .meta-value {
            font-size: 1.3em;
            font-weight: 600;
            color: #495057;
        }
        
        .content {
            padding: 40px;
        }
        
        .section {
            margin-bottom: 40px;
        }
        
        .section-title {
            font-size: 1.8em;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 3px solid #667eea;
            color: #495057;
        }
        
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .summary-card {
            background: #f8f9fa;
            border-left: 4px solid #667eea;
            padding: 20px;
            border-radius: 4px;
        }
        
        .summary-card.pass {
            border-left-color: #28a745;
        }
        
        .summary-card.fail {
            border-left-color: #dc3545;
        }
        
        .summary-card h3 {
            font-size: 0.9em;
            color: #6c757d;
            margin-bottom: 10px;
        }
        
        .summary-card .value {
            font-size: 2.5em;
            font-weight: 700;
            color: #495057;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            background: white;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        
        thead {
            background: #495057;
            color: white;
        }
        
        th, td {
            padding: 15px;
            text-align: left;
            border-bottom: 1px solid #dee2e6;
        }
        
        th {
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.85em;
            letter-spacing: 0.5px;
        }
        
        tbody tr:hover {
            background: #f8f9fa;
        }
        
        .badge {
            display: inline-block;
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 600;
            text-transform: uppercase;
        }
        
        .badge-pass {
            background: #d4edda;
            color: #155724;
        }
        
        .badge-fail {
            background: #f8d7da;
            color: #721c24;
        }
        
        .badge-warn {
            background: #fff3cd;
            color: #856404;
        }
        
        .code-block {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 4px;
            padding: 15px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            overflow-x: auto;
            margin: 10px 0;
        }
        
        .check-icon {
            color: #28a745;
            font-weight: bold;
        }
        
        .cross-icon {
            color: #dc3545;
            font-weight: bold;
        }
        
        .consistency-item {
            padding: 15px;
            margin: 10px 0;
            background: #f8f9fa;
            border-radius: 4px;
            border-left: 4px solid #6c757d;
        }
        
        .consistency-item.pass {
            border-left-color: #28a745;
        }
        
        .consistency-item.fail {
            border-left-color: #dc3545;
        }
        
        footer {
            background: #343a40;
            color: white;
            padding: 20px 40px;
            text-align: center;
            font-size: 0.9em;
        }
        
        @media print {
            body {
                background: white;
                padding: 0;
            }
            
            .container {
                box-shadow: none;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔐 ONDC Multi-Language Signature</h1>
            <p>Cross-Platform Compatibility Test Report</p>
        </header>
        
        <div class="meta-info">
            <div class="meta-item">
                <div class="meta-label">Test Date</div>
                <div class="meta-value">{{ test_date }}</div>
            </div>
            <div class="meta-item">
                <div class="meta-label">Duration</div>
                <div class="meta-value">{{ duration }}s</div>
            </div>
            <div class="meta-item">
                <div class="meta-label">Languages Tested</div>
                <div class="meta-value">{{ summary.total_languages }}</div>
            </div>
            <div class="meta-item">
                <div class="meta-label">Success Rate</div>
                <div class="meta-value">{{ "%.1f"|format((summary.passed / summary.total_languages * 100)) }}%</div>
            </div>
        </div>
        
        <div class="content">
            <!-- Executive Summary -->
            <section class="section">
                <h2 class="section-title">📊 Executive Summary</h2>
                <div class="summary-grid">
                    <div class="summary-card pass">
                        <h3>Tests Passed</h3>
                        <div class="value">{{ summary.passed }}</div>
                    </div>
                    <div class="summary-card {% if summary.failed > 0 %}fail{% else %}pass{% endif %}">
                        <h3>Tests Failed</h3>
                        <div class="value">{{ summary.failed }}</div>
                    </div>
                    <div class="summary-card {% if consistency.public_keys_match %}pass{% else %}fail{% endif %}">
                        <h3>Public Key Consistency</h3>
                        <div class="value">{{ '✓' if consistency.public_keys_match else '✗' }}</div>
                    </div>
                    <div class="summary-card {% if consistency.all_api_tests_passed %}pass{% else %}fail{% endif %}">
                        <h3>API Tests Passed</h3>
                        <div class="value">{{ '✓' if consistency.all_api_tests_passed else '✗' }}</div>
                    </div>
                </div>
            </section>
            
            <!-- Language Test Results -->
            <section class="section">
                <h2 class="section-title">🔬 Language Implementation Results</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Language</th>
                            <th>Status</th>
                            <th>Execution Time</th>
                            <th>Details</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for result in test_results %}
                        <tr>
                            <td><strong>{{ result.language }}</strong></td>
                            <td>
                                <span class="badge badge-{{ 'pass' if result.status == 'PASS' else 'fail' }}">
                                    {{ result.status }}
                                </span>
                            </td>
                            <td>{{ result.elapsed_time }}s</td>
                            <td>{{ 'All tests completed successfully' if result.status == 'PASS' else 'See errors below' }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </section>
            
            <!-- Cross-Language Consistency -->
            <section class="section">
                <h2 class="section-title">🔄 Cross-Language Consistency Verification</h2>
                
                <h3 style="margin: 20px 0 15px 0; font-size: 1.3em; color: #495057;">Public Key Generation</h3>
                <div class="consistency-item {{ 'pass' if consistency.public_keys_match else 'fail' }}">
                    <strong>{{ '✓ PASS' if consistency.public_keys_match else '✗ FAIL' }}:</strong>
                    All languages generate {{ 'identical' if consistency.public_keys_match else 'different' }} public keys from the same seed
                </div>
                
                <h3 style="margin: 20px 0 15px 0; font-size: 1.3em; color: #495057;">BLAKE2b-512 Digest Consistency</h3>
                {% for test_name, matches in consistency.digests_match.items() %}
                <div class="consistency-item {{ 'pass' if matches else 'fail' }}">
                    <strong>{{ test_name }}:</strong> {{ '✓ All languages produce identical digests' if matches else '✗ Digest mismatch detected' }}
                </div>
                {% endfor %}
                
                <h3 style="margin: 20px 0 15px 0; font-size: 1.3em; color: #495057;">Ed25519 Signature Consistency</h3>
                {% for test_name, matches in consistency.signatures_match.items() %}
                <div class="consistency-item {{ 'pass' if matches else 'fail' }}">
                    <strong>{{ test_name }}:</strong> {{ '✓ All languages produce identical signatures' if matches else '✗ Signature mismatch detected' }}
                </div>
                {% endfor %}
            </section>
            
            <!-- Live API Test Results -->
            <section class="section">
                <h2 class="section-title">🌐 Live UAT API Test Results</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Language</th>
                            <th>Status</th>
                            <th>HTTP Code</th>
                            <th>Message</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for lang, results in detailed_results.items() %}
                        {% if results.api_test %}
                        <tr>
                            <td><strong>{{ lang.capitalize() }}</strong></td>
                            <td>
                                <span class="badge badge-{{ 'pass' if results.api_test.result.status == 'PASS' else 'fail' }}">
                                    {{ results.api_test.result.status }}
                                </span>
                            </td>
                            <td>{{ results.api_test.result.code if results.api_test.result.code else 'N/A' }}</td>
                            <td>{{ results.api_test.result.message if results.api_test.result.message else 'Request successful' }}</td>
                        </tr>
                        {% endif %}
                        {% endfor %}
                    </tbody>
                </table>
            </section>
            
            <!-- Verification Statement -->
            <section class="section">
                <h2 class="section-title">✅ Verification Statement</h2>
                <div class="code-block">
                    <p><strong>Test Summary:</strong></p>
                    <ul style="margin-left: 20px; margin-top: 10px;">
                        <li>{{ '✓' if consistency.public_keys_match else '✗' }} All implementations generate identical Ed25519 key pairs from the same seed</li>
                        <li>{{ '✓' if all(consistency.digests_match.values()) else '✗' }} All implementations produce identical BLAKE2b-512 digests for the same input</li>
                        <li>{{ '✓' if all(consistency.signatures_match.values()) else '✗' }} All implementations generate identical Ed25519 signatures for the same data</li>
                        <li>{{ '✓' if consistency.all_api_tests_passed else '✗' }} All signatures successfully authenticate with ONDC UAT API</li>
                    </ul>
                    <p style="margin-top: 20px;"><strong>Conclusion:</strong></p>
                    <p style="margin-left: 20px;">
                        {% if consistency.public_keys_match and all(consistency.signatures_match.values()) and consistency.all_api_tests_passed %}
                        <span style="color: #28a745; font-weight: bold;">✓ FULL COMPATIBILITY VERIFIED</span><br>
                        All {{ summary.total_languages }} language implementations are fully compatible and interchangeable.
                        Signatures generated by any language will be accepted by the ONDC platform.
                        {% else %}
                        <span style="color: #dc3545; font-weight: bold;">✗ COMPATIBILITY ISSUES DETECTED</span><br>
                        Review the detailed results above to identify and resolve inconsistencies.
                        {% endif %}
                    </p>
                </div>
            </section>
        </div>
        
        <footer>
            <p>Generated on {{ test_date }} | ONDC Multi-Language Signature Implementation</p>
            <p style="margin-top: 10px; opacity: 0.8;">
                Python {{ summary.total_languages }} · Java · Node.js · Go · PHP · Ruby
            </p>
        </footer>
    </div>
</body>
</html>
"""


def generate_html_report(data):
    """Generate HTML report from test data"""
    env = Environment(autoescape=select_autoescape(['html', 'xml']))
    template = env.from_string(HTML_TEMPLATE)
    return template.render(**data)
