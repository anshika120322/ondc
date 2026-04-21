#!/usr/bin/env python3
"""
Generate Combined V2 HTML Report
=================================
Combines all V2 Locust HTML reports into a single styled HTML report
similar to the format in generate_v2_combined.html

Usage:
    python func_test_scripts/generate_v2_combined_report.py
    
Optional:
    python func_test_scripts/generate_v2_combined_report.py --input-dir results/registry/v2 --output combined_v2_report.html
"""

import os
import sys
import glob
import argparse
import re
from datetime import datetime
from pathlib import Path
from bs4 import BeautifulSoup

def parse_locust_html(html_file):
    """Parse Locust HTML report and extract test case data"""
    try:
        with open(html_file, 'r', encoding='utf-8') as f:
            soup = BeautifulSoup(f.read(), 'html.parser')
        
        test_cases = []
        test_suite = Path(html_file).stem  # Get filename without extension
        
        # Extract from Locust statistics table
        tables = soup.find_all('table')
        
        for table in tables:
            # Look for the class or caption that indicates it's the stats table
            rows = table.find_all('tr')
            
            for row in rows[1:]:  # Skip header
                cols = row.find_all('td')
                if len(cols) >= 10:  # Locust stats table has many columns
                    name = cols[1].get_text(strip=True) if len(cols) > 1 else ""
                    
                    # Skip aggregated row and empty rows
                    if not name or name in ['Aggregated', 'Total', '']:
                        continue
                    
                    # Extract request/response data
                    num_requests = cols[2].get_text(strip=True) if len(cols) > 2 else "0"
                    num_failures = cols[3].get_text(strip=True) if len(cols) > 3 else "0"
                    median_response = cols[4].get_text(strip=True) if len(cols) > 4 else "0"
                    avg_response = cols[5].get_text(strip=True) if len(cols) > 5 else "0"
                    
                    # Determine status
                    try:
                        failures = int(num_failures.split('(')[0].strip())
                        status = "FAIL" if failures > 0 else "PASS"
                    except:
                        status = "UNKNOWN"
                    
                    test_cases.append({
                        'suite': test_suite,
                        'name': name,
                        'status': status,
                        'requests': num_requests,
                        'failures': num_failures,
                        'median_response': median_response,
                        'avg_response': avg_response,
                        'http_status': "HTTP N/A",  # Will be extracted if available
                        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        'response_time': avg_response
                    })
        
        return test_cases
    
    except Exception as e:
        print(f"❌ Error parsing {html_file}: {e}")
        return []


def generate_combined_html(test_cases, output_file):
    """Generate combined styled HTML report"""
    
    # Count statistics
    total = len(test_cases)
    passed = sum(1 for tc in test_cases if tc['status'] == 'PASS')
    failed = sum(1 for tc in test_cases if tc['status'] == 'FAIL')
    pass_rate = (passed / total * 100) if total > 0 else 0
    
    # Calculate average response time
    try:
        response_times = [float(tc['avg_response']) for tc in test_cases if tc['avg_response'].replace('.', '').isdigit()]
        avg_rsp = sum(response_times) / len(response_times) if response_times else 0
    except:
        avg_rsp = 0
    
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>ONDC V2 Combined - API Test Report</title>
<style>
*, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{
    font-family: 'Segoe UI', system-ui, Arial, sans-serif;
    background: #0d1117;
    color: #e2e8f0;
    line-height: 1.65;
    min-height: 100vh;
}}
::-webkit-scrollbar {{ width: 7px; height: 7px; }}
::-webkit-scrollbar-track {{ background: #0d1117; }}
::-webkit-scrollbar-thumb {{ background: #30363d; border-radius: 4px; }}

.page {{ max-width: 1280px; margin: 0 auto; padding: 32px 20px 80px; }}

.hero {{
    background: linear-gradient(135deg, #1e1b4b 0%, #312e81 50%, #1d4ed8 100%);
    border: 1px solid #3730a3;
    border-radius: 12px;
    padding: 36px 40px;
    margin-bottom: 32px;
    box-shadow: 0 8px 32px rgba(0,0,0,.5);
}}
.hero h1 {{
    font-size: 1.9rem;
    font-weight: 800;
    letter-spacing: -0.5px;
    margin-bottom: 6px;
}}
.hero h1 span {{ color: #a5b4fc; }}
.hero p {{ color: #94a3b8; font-size: .9rem; }}
.hero p strong {{ color: #c7d2fe; }}

.summary {{
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(170px, 1fr));
    gap: 16px;
    margin-bottom: 32px;
}}
.scard {{
    background: #161b22;
    border: 1px solid #21262d;
    border-radius: 10px;
    padding: 22px 20px;
    text-align: center;
    box-shadow: 0 2px 8px rgba(0,0,0,.3);
}}
.scard .val {{
    font-size: 2.4rem;
    font-weight: 900;
    line-height: 1;
    margin-bottom: 6px;
}}
.scard .lbl {{
    font-size: .72rem;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: #64748b;
}}
.scard.total  .val {{ color: #818cf8; }}
.scard.passed .val {{ color: #22c55e; }}
.scard.failed .val {{ color: #ef4444; }}
.scard.rate   .val {{ color: #38bdf8; }}
.scard.rsp    .val {{ color: #34d399; }}

.controls {{
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
    align-items: center;
    margin-bottom: 24px;
}}
.search {{
    flex: 1;
    min-width: 220px;
    padding: 9px 14px;
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    color: #e2e8f0;
    font-size: .88rem;
    outline: none;
}}
.search:focus {{ border-color: #818cf8; }}
.fbtn {{
    padding: 8px 18px;
    border-radius: 8px;
    border: 1px solid #30363d;
    background: #161b22;
    color: #8b949e;
    cursor: pointer;
    font-size: .82rem;
    font-weight: 700;
    transition: all .15s;
}}
.fbtn:hover {{ background: #21262d; color: #e2e8f0; border-color: #818cf8; }}
.fbtn.active {{ background: #312e81; border-color: #6366f1; color: #e0e7ff; }}

.card {{
    background: #161b22;
    border: 1px solid #21262d;
    border-radius: 10px;
    margin-bottom: 16px;
    overflow: hidden;
    transition: all .2s;
}}
.card:hover {{ border-color: #30363d; box-shadow: 0 4px 12px rgba(0,0,0,.3); }}
.card.pass {{ border-left: 3px solid #22c55e; }}
.card.fail {{ border-left: 3px solid #ef4444; }}

.card-header {{
    padding: 16px 20px;
    display: flex;
    align-items: center;
    gap: 10px;
    cursor: pointer;
    user-select: none;
}}
.card-header:hover {{ background: #1c2128; }}

.suite-chip {{
    background: #1e293b;
    padding: 4px 10px;
    border-radius: 6px;
    font-size: .72rem;
    font-weight: 700;
    color: #94a3b8;
    text-transform: uppercase;
}}

.badge {{
    padding: 5px 11px;
    border-radius: 6px;
    font-size: .75rem;
    font-weight: 800;
    text-transform: uppercase;
}}
.badge-pass {{ background: #064e3b; color: #6ee7b7; }}
.badge-fail {{ background: #7f1d1d; color: #fca5a5; }}

.tc-name {{
    flex: 1;
    font-weight: 700;
    font-size: .95rem;
    color: #e2e8f0;
}}

.chip {{
    background: #1e293b;
    padding: 4px 10px;
    border-radius: 6px;
    font-size: .72rem;
    font-weight: 600;
    color: #cbd5e1;
}}
.chip.sc-2xx {{ background: #064e3b; color: #6ee7b7; }}
.chip.sc-4xx {{ background: #7c2d12; color: #fdba74; }}
.chip.sc-5xx {{ background: #7f1d1d; color: #fca5a5; }}
.chip.sc-none {{ background: #334155; color: #94a3b8; }}
.chip-time {{ color: #a5b4fc; }}
.chip-ts {{ color: #94a3b8; font-size: .70rem; }}

.chevron {{
    font-size: 1.4rem;
    color: #64748b;
    transition: transform .2s;
    font-weight: 700;
}}
.chevron.open {{ transform: rotate(90deg); }}

.card-body {{
    padding: 24px 20px;
    background: #0d1117;
    border-top: 1px solid #21262d;
    display: none;
}}

.section-title {{
    font-size: .85rem;
    font-weight: 800;
    text-transform: uppercase;
    letter-spacing: 1.3px;
    color: #64748b;
    margin-bottom: 16px;
    padding-bottom: 8px;
    border-bottom: 1px solid #21262d;
}}
.req-title {{ color: #818cf8; border-color: #312e81; }}
.res-title {{ color: #34d399; border-color: #064e3b; }}

.two-col {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    gap: 20px;
    margin-bottom: 24px;
}}

.col-label {{
    font-size: .75rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: .8px;
    color: #94a3b8;
    margin-bottom: 10px;
}}

.json-block {{
    background: #0d1117;
    border: 1px solid #30363d;
    padding: 14px 16px;
    border-radius: 8px;
    font-family: 'Consolas', 'Monaco', monospace;
    font-size: .82rem;
    line-height: 1.6;
    color: #e2e8f0;
    overflow-x: auto;
    white-space: pre-wrap;
    word-wrap: break-word;
}}

.meta-row {{
    display: flex;
    flex-wrap: wrap;
    gap: 24px;
    padding: 14px 18px;
    background: #0d1117;
    border: 1px solid #21262d;
    border-radius: 8px;
    margin-bottom: 24px;
    font-size: .85rem;
}}
.meta-row strong {{ color: #a5b4fc; margin-right: 8px; }}
</style>
</head>
<body>
<div class="page">

<div class="hero">
    <h1>ONDC V2 Combined <span>→ API Test Report</span></h1>
    <p><strong>Generated:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} | <strong>Environment:</strong> UAT Registry | <strong>Version:</strong> V2.0</p>
</div>

<div class="summary">
    <div class="scard total">
        <div class="val">{total}</div>
        <div class="lbl">Total Tests</div>
    </div>
    <div class="scard passed">
        <div class="val">{passed}</div>
        <div class="lbl">Passed</div>
    </div>
    <div class="scard failed">
        <div class="val">{failed}</div>
        <div class="lbl">Failed</div>
    </div>
    <div class="scard rate">
        <div class="val">{pass_rate:.1f}%</div>
        <div class="lbl">Pass Rate</div>
    </div>
    <div class="scard rsp">
        <div class="val">{avg_rsp:.0f} ms</div>
        <div class="lbl">Avg Response</div>
    </div>
</div>

<div class="controls">
    <input type="text" class="search" id="searchInput" placeholder="🔍 Search test cases..." onkeyup="filterTests()">
    <button class="fbtn" onclick="filterStatus('all')">All</button>
    <button class="fbtn" onclick="filterStatus('pass')">✅ Passed</button>
    <button class="fbtn" onclick="filterStatus('fail')">❌ Failed</button>
    <button class="fbtn" onclick="expandAll()">Expand All</button>
    <button class="fbtn" onclick="collapseAll()">Collapse All</button>
</div>

"""
    
    # Add test cases
    for idx, tc in enumerate(test_cases):
        status_class = tc['status'].lower()
        http_class = 'sc-none'
        
        html_content += f"""
<div class="card {status_class}" data-name="{tc['name'].lower()}" data-suite="{tc['suite'].lower()}">
    <div class="card-header" onclick="toggle({idx})">
        <span class="suite-chip">{tc['suite'].replace('_', ' ').title()}</span>
        <span class="badge badge-{status_class}">{tc['status']}</span>
        <span class="tc-name">{tc['name']}</span>
        <span class="chip {http_class}">{tc['http_status']}</span>
        <span class="chip chip-time">{tc['response_time']} s</span>
        <span class="chip chip-ts">{tc['timestamp']}</span>
        <span class="chevron" id="chev-{idx}">></span>
    </div>

    <div class="card-body" id="body-{idx}">
        <div class="section-title req-title">Request</div>
        <div class="meta-row">
            <div><strong>Requests:</strong> {tc['requests']}</div>
            <div><strong>Failures:</strong> {tc['failures']}</div>
            <div><strong>Median Response:</strong> {tc['median_response']} ms</div>
            <div><strong>Average Response:</strong> {tc['avg_response']} ms</div>
        </div>
    </div>
</div>
"""
    
    # Add JavaScript
    html_content += """
<script>
function toggle(id) {
    const body = document.getElementById('body-' + id);
    const chev = document.getElementById('chev-' + id);
    if (body.style.display === 'block') {
        body.style.display = 'none';
        chev.classList.remove('open');
    } else {
        body.style.display = 'block';
        chev.classList.add('open');
    }
}

function expandAll() {
    document.querySelectorAll('.card-body').forEach(b => b.style.display = 'block');
    document.querySelectorAll('.chevron').forEach(c => c.classList.add('open'));
}

function collapseAll() {
    document.querySelectorAll('.card-body').forEach(b => b.style.display = 'none');
    document.querySelectorAll('.chevron').forEach(c => c.classList.remove('open'));
}

function filterTests() {
    const input = document.getElementById('searchInput').value.toLowerCase();
    document.querySelectorAll('.card').forEach(card => {
        const name = card.getAttribute('data-name') || '';
        const suite = card.getAttribute('data-suite') || '';
        if (name.includes(input) || suite.includes(input)) {
            card.style.display = 'block';
        } else {
            card.style.display = 'none';
        }
    });
}

function filterStatus(status) {
    document.querySelectorAll('.fbtn').forEach(btn => btn.classList.remove('active'));
    event.target.classList.add('active');
    
    document.querySelectorAll('.card').forEach(card => {
        if (status === 'all' || card.classList.contains(status)) {
            card.style.display = 'block';
        } else {
            card.style.display = 'none';
        }
    });
}
</script>

</div>
</body>
</html>
"""
    
    # Write to file
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    print(f"✅ Combined HTML report generated: {output_file}")
    print(f"   Total: {total} | Passed: {passed} | Failed: {failed} | Pass Rate: {pass_rate:.1f}%")


def main():
    parser = argparse.ArgumentParser(description='Generate combined V2 HTML report from Locust reports')
    parser.add_argument('--input-dir', default='results/registry/v2', help='Directory containing Locust HTML reports')
    parser.add_argument('--output', default='results/registry/v2/generate_v2_combined.html', help='Output HTML file path')
    args = parser.parse_args()
    
    print("========================================================================")
    print("📊 Generating Combined V2 HTML Report")
    print("========================================================================")
    print()
    
    # Find all HTML reports in input directory
    html_files = glob.glob(f"{args.input_dir}/*.html")
    html_files = [f for f in html_files if 'combined' not in f.lower()]  # Exclude previous combined reports
    
    if not html_files:
        print(f"❌ No HTML reports found in {args.input_dir}")
        print(f"   Run the tests first: bash run_all_v2_tests.sh")
        return 1
    
    print(f"📁 Found {len(html_files)} report file(s):")
    for file in html_files:
        print(f"   • {os.path.basename(file)}")
    print()
    
    # Parse all reports
    all_test_cases = []
    for html_file in html_files:
        print(f"📖 Parsing: {os.path.basename(html_file)}")
        test_cases = parse_locust_html(html_file)
        all_test_cases.extend(test_cases)
    
    print()
    print(f"✅ Extracted {len(all_test_cases)} test cases")
    print()
    
    # Generate combined report
    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    generate_combined_html(all_test_cases, args.output)
    
    print()
    print("========================================================================")
    print("✅ Report Generation Complete")
    print("========================================================================")
    print(f"📄 Open in browser: {args.output}")
    print()
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
