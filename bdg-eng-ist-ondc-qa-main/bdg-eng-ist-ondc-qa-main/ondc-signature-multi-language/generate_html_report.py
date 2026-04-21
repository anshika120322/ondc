#!/usr/bin/env python3
"""
Generate comprehensive HTML report for ONDC Signature Multi-Language Testing
"""

import subprocess
import json
import re
from datetime import datetime
from pathlib import Path

def run_command(cmd):
    """Run shell command and capture output"""
    try:
        result = subprocess.run(
            cmd, 
            shell=True, 
            capture_output=True, 
            text=True, 
            timeout=120
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Timeout"

def extract_test_results(output, language):
    """Extract test results from command output"""
    result = {
        "language": language,
        "status": "UNKNOWN",
        "http_status": None,
        "message": "",
        "signature_match": False,
        "api_test": False,
        "lookup_signature": {},
        "request": {},
        "response": ""
    }
    
    # Extract TEST 4 lookup signature (the one actually used for API call)
    # Look for the signature right before the API request
    test4_section = re.search(
        r"TEST 4: LIVE API CALL.*?📡 Endpoint: (.*?)$.*?📦 Payload: (.*?)$.*?🔑 Authorization: (.*?)$.*?🔐 Digest: (.*?)$",
        output,
        re.MULTILINE | re.DOTALL
    )
    
    if test4_section:
        result["request"]["endpoint"] = test4_section.group(1).strip()
        result["request"]["payload"] = test4_section.group(2).strip()
        result["lookup_signature"]["authorization"] = test4_section.group(3).strip()
        result["lookup_signature"]["digest"] = test4_section.group(4).strip()
    
    # Extract response (now capturing full response without truncation)
    response_match = re.search(r"Response: (\[.*?\{.*?\"participant_id\".*?)(?:\n|$)", output, re.MULTILINE | re.DOTALL)
    if response_match:
        result["response"] = response_match.group(1).strip()
    else:
        # Try to find error response
        error_match = re.search(r"Response: (\{.*?\"message\".*?\})", output, re.DOTALL)
        if error_match:
            result["response"] = error_match.group(1).strip()
    
    # Check for TEST 4 (Live API) results
    if "✅ SUCCESS: Signature verified! Participant found in registry!" in output:
        result["status"] = "PASS"
        result["http_status"] = 200
        result["message"] = "Signature verified! Participant found in registry"
        result["signature_match"] = True
        result["api_test"] = True
    elif "Response Status: 200" in output:
        result["status"] = "PASS"
        result["http_status"] = 200
        result["signature_match"] = True
        result["api_test"] = True
    elif "401 Unauthorized" in output:
        result["status"] = "FAIL"
        result["http_status"] = 401
        result["message"] = "Signature verification failed"
    elif "✅ SUCCESS: Signature accepted (404 means participant not found, but auth worked)" in output:
        result["status"] = "FAIL"
        result["http_status"] = 404
        result["message"] = "Participant not found (404)"
        result["signature_match"] = True
    elif "404" in output and "Response Status: 404" in output:
        result["status"] = "FAIL"
        result["http_status"] = 404
        result["message"] = "Participant not found (404)"
        result["signature_match"] = True
    
    # Check if all 5 test cases passed in signature generation (for cross-language compatibility)
    if output.count("✅ empty_body:") > 0 and \
       output.count("✅ simple_json:") > 0 and \
       output.count("✅ complex_json:") > 0 and \
       output.count("✅ special_characters:") > 0 and \
       output.count("✅ large_payload:") > 0:
        result["signature_match"] = True
    
    return result

def generate_html_report(results):
    """Generate HTML report from test results"""
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ONDC Multi-Language Signature Test Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            min-height: 100vh;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 16px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}
        
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.2);
        }}
        
        .header .subtitle {{
            font-size: 1.2em;
            opacity: 0.9;
        }}
        
        .header .timestamp {{
            margin-top: 15px;
            font-size: 0.9em;
            opacity: 0.8;
        }}
        
        .summary {{
            padding: 40px;
            background: #f8f9fa;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
        }}
        
        .summary-card {{
            background: white;
            padding: 25px;
            border-radius: 12px;
            text-align: center;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            transition: transform 0.2s;
        }}
        
        .summary-card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 6px 12px rgba(0,0,0,0.15);
        }}
        
        .summary-card .number {{
            font-size: 3em;
            font-weight: bold;
            margin-bottom: 10px;
        }}
        
        .summary-card.pass .number {{ color: #10b981; }}
        .summary-card.fail .number {{ color: #ef4444; }}
        .summary-card.total .number {{ color: #667eea; }}
        
        .summary-card .label {{
            font-size: 1.1em;
            color: #666;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        
        .results {{
            padding: 40px;
        }}
        
        .results h2 {{
            font-size: 2em;
            margin-bottom: 30px;
            color: #333;
        }}
        
        .test-card {{
            background: white;
            border: 2px solid #e5e7eb;
            border-radius: 12px;
            padding: 25px;
            margin-bottom: 20px;
            transition: all 0.3s;
        }}
        
        .test-card:hover {{
            border-color: #667eea;
            box-shadow: 0 4px 12px rgba(102, 126, 234, 0.15);
        }}
        
        .test-card.pass {{
            border-left: 5px solid #10b981;
        }}
        
        .test-card.fail {{
            border-left: 5px solid #ef4444;
        }}
        
        .test-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }}
        
        .test-language {{
            font-size: 1.5em;
            font-weight: bold;
            color: #333;
        }}
        
        .test-status {{
            padding: 8px 20px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        
        .test-status.pass {{
            background: #d1fae5;
            color: #065f46;
        }}
        
        .test-status.fail {{
            background: #fee2e2;
            color: #991b1b;
        }}
        
        .test-status.unknown {{
            background: #e5e7eb;
            color: #374151;
        }}
        
        .test-details {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 20px;
        }}
        
        .detail-item {{
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        
        .detail-icon {{
            font-size: 1.5em;
        }}
        
        .detail-text {{
            font-size: 0.95em;
            color: #666;
        }}
        
        .detail-value {{
            font-weight: bold;
            color: #333;
        }}
        
        .message {{
            margin-top: 15px;
            padding: 15px;
            background: #f9fafb;
            border-radius: 8px;
            font-size: 0.95em;
            color: #555;
        }}        
        .expandable {{
            margin-top: 20px;
            border: 1px solid #e5e7eb;
            border-radius: 8px;
            overflow: hidden;
        }}
        
        .expandable-header {{
            background: #f9fafb;
            padding: 15px;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-weight: 600;
            transition: background 0.2s;
            user-select: none;
        }}
        
        .expandable-header:hover {{
            background: #f3f4f6;
        }}
        
        .expandable-header .icon {{
            font-size: 1.2em;
            transition: transform 0.3s;
            display: inline-block;
        }}
        
        .expandable.open .icon {{
            transform: rotate(90deg);
        }}
        
        .expandable-content {{
            max-height: 0;
            overflow: hidden;
            transition: max-height 0.4s ease-out;
            background: white;
        }}
        
        .expandable.open .expandable-content {{
            max-height: 5000px;
            transition: max-height 0.6s ease-in;
        }}
        
        .expandable-inner {{
            padding: 20px;
        }}
        
        .code-block {{
            background: #1e293b;
            color: #e2e8f0;
            padding: 15px;
            border-radius: 6px;
            font-family: 'Monaco', 'Consolas', monospace;
            font-size: 0.85em;
            overflow-x: auto;
            margin: 10px 0;
            line-height: 1.6;
            white-space: pre-wrap;
            word-break: break-word;
        }}
        
        .headers-table {{
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
            background: white;
            border: 1px solid #e5e7eb;
            border-radius: 6px;
            overflow: hidden;
        }}
        
        .headers-table th {{
            background: #f9fafb;
            padding: 12px;
            text-align: left;
            font-weight: 600;
            color: #374151;
            border-bottom: 1px solid #e5e7eb;
            font-size: 0.9em;
        }}
        
        .headers-table td {{
            padding: 12px;
            border-bottom: 1px solid #f3f4f6;
            font-size: 0.85em;
        }}
        
        .headers-table tr:last-child td {{
            border-bottom: none;
        }}
        
        .headers-table td:first-child {{
            font-weight: 600;
            color: #6b7280;
            width: 180px;
            font-family: monospace;
        }}
        
        .headers-table td:last-child {{
            color: #1f2937;
            font-family: 'Monaco', 'Consolas', monospace;
            word-break: break-all;
        }}
        
        .request-container {{
            background: #f8fafc;
            border-radius: 8px;
            padding: 20px;
            margin: 15px 0;
        }}
        
        .response-container {{
            background: #f8fafc;
            border-radius: 8px;
            padding: 20px;
            margin: 15px 0;
        }}
        
        .status-badge {{
            display: inline-block;
            padding: 6px 16px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 1.1em;
            margin-left: 10px;
        }}
        
        .status-badge.success {{
            background: #d1fae5;
            color: #065f46;
        }}
        
        .status-badge.error {{
            background: #fee2e2;
            color: #991b1b;
        }}
        
        .json-viewer {{
            background: #1e293b;
            color: #e2e8f0;
            padding: 15px;
            border-radius: 6px;
            font-family: 'Monaco', 'Consolas', monospace;
            font-size: 0.85em;
            overflow-x: auto;
            margin: 10px 0;
            line-height: 1.8;
        }}
        
        .json-key {{
            color: #60a5fa;
        }}
        
        .json-string {{
            color: #86efac;
        }}
        
        .json-number {{
            color: #fbbf24;
        }}
        
        .signature-list {{
            display: grid;
            gap: 15px;
        }}
        
        .signature-item {{
            background: #f9fafb;
            padding: 15px;
            border-radius: 6px;
            border-left: 3px solid #667eea;
        }}
        
        .signature-name {{
            font-weight: bold;
            color: #667eea;
            margin-bottom: 8px;
            text-transform: uppercase;
            font-size: 0.9em;
            letter-spacing: 0.5px;
        }}
        
        .signature-detail {{
            margin: 5px 0;
            font-size: 0.85em;
        }}
        
        .signature-label {{
            color: #666;
            font-weight: 600;
            display: inline-block;
            width: 100px;
        }}
        
        .signature-value {{
            color: #333;
            font-family: monospace;
            word-break: break-all;
        }}
        
        .request-response {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
        }}
        
        @media (max-width: 768px) {{
            .request-response {{
                grid-template-columns: 1fr;
            }}
        }}
        
        .section-title {{
            font-size: 1.1em;
            font-weight: bold;
            color: #333;
            margin-bottom: 10px;
            border-bottom: 2px solid #667eea;
            padding-bottom: 5px;
        }}        
        .footer {{
            background: #f8f9fa;
            padding: 30px;
            text-align: center;
            color: #666;
            border-top: 1px solid #e5e7eb;
        }}
        
        .footer p {{
            margin: 5px 0;
        }}
        
        .badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: 600;
            margin-left: 10px;
        }}
        
        .badge.success {{
            background: #d1fae5;
            color: #065f46;
        }}
        
        .badge.error {{
            background: #fee2e2;
            color: #991b1b;
        }}
        
        /* JSON Viewer Component Styling */
        andypf-json-viewer {{
            display: block;
            max-height: 600px;
            overflow: auto;
            border-radius: 6px;
            font-size: 0.88em;
            border: 1px solid #e5e7eb;
            background: #1e293b;
        }}
    </style>
    <script src="https://cdn.jsdelivr.net/npm/@andypf/json-viewer@2/dist/iife/index.js"></script>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 ONDC Multi-Language Signature Test Report</h1>
            <div class="subtitle">Cross-Platform Signature Compatibility & API Integration Testing</div>
            <div class="timestamp">Generated: {timestamp}</div>
        </div>
        
        <div class="summary">
"""
    
    passed = sum(1 for r in results if r["status"] == "PASS")
    failed = sum(1 for r in results if r["status"] == "FAIL")
    total = len(results)
    
    html += f"""
            <div class="summary-card pass">
                <div class="number">{passed}</div>
                <div class="label">Passed</div>
            </div>
            <div class="summary-card fail">
                <div class="number">{failed}</div>
                <div class="label">Failed</div>
            </div>
            <div class="summary-card total">
                <div class="number">{total}</div>
                <div class="label">Total Tests</div>
            </div>
            <div class="summary-card">
                <div class="number" style="color: #f59e0b;">{int((passed/total)*100)}%</div>
                <div class="label">Success Rate</div>
            </div>
        </div>
        
        <div class="results">
            <h2>📊 Detailed Test Results</h2>
"""
    
    for result in results:
        status_class = result["status"].lower()
        status_icon = "✅" if result["status"] == "PASS" else "❌" if result["status"] == "FAIL" else "⚠️"
        
        html += f"""
            <div class="test-card {status_class}">
                <div class="test-header">
                    <div class="test-language">{status_icon} {result['language']}</div>
                    <div class="test-status {status_class}">{result['status']}</div>
                </div>
                
                <div class="test-details">
                    <div class="detail-item">
                        <span class="detail-icon">🔑</span>
                        <div>
                            <div class="detail-text">Signature Generation</div>
                            <div class="detail-value">{'✅ Match' if result['signature_match'] else '❌ Mismatch'}</div>
                        </div>
                    </div>
                    
                    <div class="detail-item">
                        <span class="detail-icon">🌐</span>
                        <div>
                            <div class="detail-text">API Integration</div>
                            <div class="detail-value">{'✅ Success' if result['api_test'] else '❌ Failed'}</div>
                        </div>
                    </div>
                    
                    <div class="detail-item">
                        <span class="detail-icon">📡</span>
                        <div>
                            <div class="detail-text">HTTP Status</div>
                            <div class="detail-value">{result['http_status'] if result['http_status'] else 'N/A'}</div>
                        </div>
                    </div>
                </div>
"""
        
        if result["message"]:
            html += f"""
                <div class="message">
                    <strong>📝 Details:</strong> {result['message']}
                </div>
"""
        
        # Add expandable section for lookup signature and request/response
        if result["lookup_signature"] or result["request"] or result["response"]:
            html += """
                <div class="expandable" onclick="this.classList.toggle('open')">
                    <div class="expandable-header">
                        <span>🔐 API Request & Response Details</span>
                        <span class="icon">▶</span>
                    </div>
                    <div class="expandable-content">
                        <div class="expandable-inner">
"""
            
            # REQUEST SECTION
            html += """
                            <div class="request-container">
                                <h3 style="color: #2563eb; margin-bottom: 15px; font-size: 1.2em;">
                                    📤 REQUEST
                                </h3>
"""
            
            if result["request"].get("endpoint"):
                html += f"""
                                <div style="margin-bottom: 20px;">
                                    <div style="font-weight: 600; color: #4b5563; margin-bottom: 8px;">Endpoint</div>
                                    <div style="background: white; padding: 12px; border-radius: 6px; border: 1px solid #e5e7eb;">
                                        <span style="color: #2563eb; font-weight: bold;">POST</span>
                                        <span style="font-family: monospace; margin-left: 10px;">{result['request']['endpoint']}</span>
                                    </div>
                                </div>
"""
            
            # Headers table
            if result["lookup_signature"] or result["request"]:
                html += """
                                <div style="margin-bottom: 20px;">
                                    <div style="font-weight: 600; color: #4b5563; margin-bottom: 8px;">Headers</div>
                                    <table class="headers-table">
                                        <thead>
                                            <tr>
                                                <th>Header Name</th>
                                                <th>Value</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <tr>
                                                <td>Content-Type</td>
                                                <td>application/json</td>
                                            </tr>
"""
                
                if result["lookup_signature"].get("authorization"):
                    auth_value = result["lookup_signature"]["authorization"]
                    html += f"""
                                            <tr>
                                                <td>Authorization</td>
                                                <td style="max-width: 600px;">{auth_value}</td>
                                            </tr>
"""
                
                if result["lookup_signature"].get("digest"):
                    html += f"""
                                            <tr>
                                                <td>Digest</td>
                                                <td>{result["lookup_signature"]["digest"]}</td>
                                            </tr>
"""
                
                html += """
                                        </tbody>
                                    </table>
                                </div>
"""
            
            # Request body
            if result["request"].get("payload"):
                try:
                    # Try to parse and format JSON
                    import json as json_lib
                    import html as html_lib
                    payload_obj = json_lib.loads(result["request"]["payload"])
                    payload_json = json_lib.dumps(payload_obj, indent=2, ensure_ascii=False)
                    payload_escaped = html_lib.escape(payload_json)
                    payload_json_compact = json_lib.dumps(payload_obj, ensure_ascii=False)
                    viewer_id = f"req-body-{result['language'].lower().replace(' ', '-')}"
                except:
                    payload_json = result["request"]["payload"]
                    payload_escaped = result["request"]["payload"]
                    payload_json_compact = result["request"]["payload"]
                    viewer_id = f"req-body-{result['language'].lower().replace(' ', '-')}"
                
                html += f"""
                                <div style="margin-bottom: 20px;">
                                    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
                                        <div style="font-weight: 600; color: #4b5563;">Body</div>
                                        <button class="copy-btn" onclick="copyJSON('{viewer_id}')" style="background:#667eea;color:white;border:none;padding:6px 12px;border-radius:4px;cursor:pointer;font-size:0.85em;">📋 Copy</button>
                                    </div>
                                    <script type="application/json" id="{viewer_id}">{payload_json_compact}</script>
                                    <andypf-json-viewer 
                                        indent="2" 
                                        expanded="true" 
                                        theme="default-dark"
                                        show-data-types="false" 
                                        show-toolbar="false"
                                        expand-icon-type="arrow"
                                        data="{payload_escaped.replace('"', '&quot;')}">
                                    </andypf-json-viewer>
                                </div>
"""
            
            html += """
                            </div>
"""
            
            # RESPONSE SECTION
            if result["response"]:
                status_class = "success" if result["http_status"] == 200 else "error"
                status_text = f"{result['http_status']}" if result["http_status"] else "N/A"
                
                html += f"""
                            <div class="response-container">
                                <h3 style="color: #dc2626; margin-bottom: 15px; font-size: 1.2em;">
                                    📥 RESPONSE
                                    <span class="status-badge {status_class}">{status_text}</span>
                                </h3>
"""
                
                # Format response JSON
                try:
                    import json as json_lib
                    import html as html_lib
                    if result["response"].startswith('[') or result["response"].startswith('{'):
                        response_obj = json_lib.loads(result["response"])
                        response_json = json_lib.dumps(response_obj, indent=2, ensure_ascii=False)
                        response_escaped = html_lib.escape(response_json)
                        response_json_compact = json_lib.dumps(response_obj, ensure_ascii=False)
                    else:
                        response_json = result["response"]
                        response_escaped = result["response"]
                        response_json_compact = result["response"]
                    viewer_id = f"resp-body-{result['language'].lower().replace(' ', '-')}"
                except:
                    response_json = result["response"]
                    response_escaped = result["response"]
                    response_json_compact = result["response"]
                    viewer_id = f"resp-body-{result['language'].lower().replace(' ', '-')}"
                
                html += f"""
                                <div style="margin-bottom: 20px;">
                                    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
                                        <div style="font-weight: 600; color: #4b5563;">Body</div>
                                        <button class="copy-btn" onclick="copyJSON('{viewer_id}')" style="background:#667eea;color:white;border:none;padding:6px 12px;border-radius:4px;cursor:pointer;font-size:0.85em;">📋 Copy</button>
                                    </div>
                                    <script type="application/json" id="{viewer_id}">{response_json_compact}</script>
                                    <andypf-json-viewer 
                                        indent="2" 
                                        expanded="true" 
                                        theme="default-dark"
                                        show-data-types="false" 
                                        show-toolbar="false"
                                        expand-icon-type="arrow"
                                        data="{response_escaped.replace('"', '&quot;')}">
                                    </andypf-json-viewer>
                                </div>
                            </div>
"""
            
            html += """
                        </div>
                    </div>
                </div>
"""
        
        html += """
            </div>
"""
    
    html += f"""
        </div>
        
        <div class="footer">
            <p><strong>ONDC Registry UAT Environment</strong></p>
            <p>Participant: ctf-admin-c86cad.participant.ondc</p>
            <p>Domain: ONDC:RET10</p>
            <p>Registry: registry-uat.kynondc.net</p>
            <p style="margin-top: 20px; font-size: 0.9em;">
                Test Coverage: Python, Java, Node.js, Go, PHP, Ruby
            </p>
        </div>
    </div>
    
    <script>
        // Toggle expandable sections
        function toggleExpandable(element) {{
            element.classList.toggle('open');
        }}
        
        // Copy JSON from script tag
        function copyJSON(scriptId) {{
            const scriptElement = document.getElementById(scriptId);
            if (!scriptElement) {{
                console.error('Script element not found:', scriptId);
                return;
            }}
            
            try {{
                const jsonData = JSON.parse(scriptElement.textContent);
                const formattedJSON = JSON.stringify(jsonData, null, 2);
                
                navigator.clipboard.writeText(formattedJSON).then(() => {{
                    // Find the button that triggered this
                    const button = event.target;
                    const originalText = button.innerHTML;
                    button.innerHTML = '✓ Copied!';
                    button.style.background = '#10b981';
                    
                    setTimeout(() => {{
                        button.innerHTML = originalText;
                        button.style.background = '#667eea';
                    }}, 2000);
                }}).catch(err => {{
                    console.error('Copy failed:', err);
                    alert('Failed to copy to clipboard');
                }});
            }} catch(e) {{
                // If not valid JSON, copy as-is
                navigator.clipboard.writeText(scriptElement.textContent);
            }}
        }}
    </script>
</body>
</html>
"""
    
    return html

def main():
    print("🚀 Starting ONDC Multi-Language Test Suite...")
    print("="*80)
    
    languages = [
        ("Python", "docker-compose run --rm python-signature"),
        ("Node.js", "docker-compose run --rm nodejs-signature"),
        ("Java", "docker-compose run --rm java-signature"),
        ("Go", "docker-compose run --rm golang-signature"),
        ("PHP", "docker-compose run --rm php-signature"),
        ("Ruby", "docker-compose run --rm ruby-signature"),
    ]
    
    results = []
    
    for lang_name, cmd in languages:
        print(f"\n📦 Testing {lang_name}...")
        returncode, stdout, stderr = run_command(cmd)
        
        result = extract_test_results(stdout + stderr, lang_name)
        results.append(result)
        
        status_emoji = "✅" if result["status"] == "PASS" else "❌"
        print(f"   {status_emoji} {lang_name}: {result['status']}")
    
    print("\n" + "="*80)
    print("📄 Generating HTML report...")
    
    html_content = generate_html_report(results)
    
    # Save to main report file
    report_path = Path("reports") / "compatibility-report.html"
    report_path.parent.mkdir(exist_ok=True)
    report_path.write_text(html_content)
    
    # Also save timestamped copy
    timestamp_filename = datetime.now().strftime("%Y%m%d_%H%M%S")
    timestamped_report = Path("reports") / f"ondc_signature_results_{timestamp_filename}.html"
    timestamped_report.write_text(html_content)
    
    print(f"✅ Report generated: {report_path.absolute()}")
    print(f"   Timestamped copy: {timestamped_report.name}")
    print("\n📊 Summary:")
    passed = sum(1 for r in results if r["status"] == "PASS")
    total = len(results)
    print(f"   Passed: {passed}/{total}")
    print(f"   Success Rate: {int((passed/total)*100)}%")
    print("\n" + "="*80)
    
    # Optionally open the report in browser
    import webbrowser
    import sys
    if '--open' in sys.argv or '-o' in sys.argv:
        print(f"\n🌐 Opening report in browser...")
        webbrowser.open(f"file://{report_path.absolute()}")
    else:
        print(f"\n💡 Tip: Run with --open flag to automatically open the report in your browser")

if __name__ == "__main__":
    main()
