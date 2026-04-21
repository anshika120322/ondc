"""
HTML Report Generator for Test Results
Generates detailed HTML reports with complete request/response information.
"""

import json
import html as _html
from typing import List, Dict
from datetime import datetime


def _je(data) -> str:
    """Serialize data to JSON safe for embedding in <script type='application/json'>."""
    s = json.dumps(data, ensure_ascii=False)
    # Prevent </script> from closing the tag prematurely
    return s.replace('</', '<\\/')


def _he(text) -> str:
    """HTML-escape text for use as text-node content (e.g. inside <pre>)."""
    return _html.escape(str(text), quote=False)


def _ae(data) -> str:
    """Serialize data to JSON safe for embedding in a double-quoted HTML attribute."""
    s = json.dumps(data, ensure_ascii=False)
    return _html.escape(s, quote=True)


class HTMLReporter:
    """Generate HTML test reports."""
    
    @staticmethod
    def generate_report(results: List[Dict], output_file: str, test_suite_name: str = "Test Suite") -> None:
        """
        Generate HTML report from test results.
        Includes an execution timeline bar chart (Group F1) and only-failures toggle (Group F3).

        Args:
            results: List of test result dictionaries
            output_file: Path to output HTML file
            test_suite_name: Name of the test suite
        """
        passed = sum(1 for r in results if r.get('passed', False))
        failed = len(results) - passed
        pass_rate = (passed / len(results) * 100) if results else 0
        total_ms = sum(r.get('execution_time_ms', 0) for r in results)
        avg_ms = int(total_ms / len(results)) if results else 0
        max_ms = max((r.get('execution_time_ms', 0) for r in results), default=1) or 1

        # Build timeline rows (Group F1)
        timeline_row_items = []
        for r in results:
            t_ms = r.get('execution_time_ms', 0)
            bar_pct = int(t_ms / max_ms * 100) if max_ms else 0
            bar_color = '#10b981' if r.get('passed') else '#ef4444'
            rid = (r.get('test_id') or r.get('id') or '?')
            rname = (r.get('name') or r.get('test_name') or rid)[:40]
            timeline_row_items.append(
                f'<div style="display:flex;align-items:center;gap:8px;font-size:0.8em">'
                f'<span style="width:80px;text-align:right;flex-shrink:0;color:#666">{rid}</span>'
                f'<div style="flex:1;background:#e5e7eb;border-radius:3px;height:14px">'
                f'<div style="width:{bar_pct}%;background:{bar_color};height:100%;border-radius:3px"></div></div>'
                f'<span style="width:65px;flex-shrink:0;color:#888">{t_ms}ms</span>'
                f'<span style="color:#334155">{rname}</span>'
                f'</div>'
            )
        timeline_rows = '\n'.join(timeline_row_items)

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{test_suite_name} - Test Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f5f5f5;
            color: #333;
            line-height: 1.6;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}
        
        .header h1 {{
            font-size: 2em;
            margin-bottom: 10px;
        }}
        
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .summary-card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            text-align: center;
        }}
        
        .summary-card .value {{
            font-size: 2.5em;
            font-weight: bold;
            margin: 10px 0;
        }}
        
        .summary-card .label {{
            color: #666;
            font-size: 0.9em;
            text-transform: uppercase;
        }}
        
        .summary-card.passed .value {{ color: #10b981; }}
        .summary-card.failed .value {{ color: #ef4444; }}
        .summary-card.rate .value {{ color: #3b82f6; }}
        
        .test-case {{
            background: white;
            margin-bottom: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            overflow: hidden;
        }}
        
        .test-header {{
            padding: 20px;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
            transition: background 0.2s;
        }}
        
        .test-header:hover {{
            background: #f9fafb;
        }}
        
        .test-header.passed {{
            border-left: 5px solid #10b981;
        }}
        
        .test-header.failed {{
            border-left: 5px solid #ef4444;
        }}
        
        .test-title {{
            flex: 1;
        }}
        
        .test-title h3 {{
            font-size: 1.2em;
            margin-bottom: 5px;
        }}
        
        .test-title .test-id {{
            color: #666;
            font-size: 0.9em;
        }}
        
        .test-status {{
            font-weight: bold;
            padding: 8px 16px;
            border-radius: 20px;
            font-size: 0.9em;
        }}
        
        .test-status.passed {{
            background: #d1fae5;
            color: #065f46;
        }}
        
        .test-status.failed {{
            background: #fee2e2;
            color: #991b1b;
        }}
        
        .test-details {{
            display: none;
            padding: 0 20px 20px 20px;
            border-top: 1px solid #e5e7eb;
        }}
        
        .test-details.active {{
            display: block;
        }}
        
        .detail-section {{
            margin: 20px 0;
        }}
        
        .detail-section h4 {{
            color: #667eea;
            margin-bottom: 10px;
            font-size: 1.1em;
        }}
        
        .info-grid {{
            display: grid;
            grid-template-columns: auto 1fr;
            gap: 10px;
            background: #f9fafb;
            padding: 15px;
            border-radius: 6px;
        }}
        
        .info-label {{
            font-weight: 600;
            color: #666;
        }}
        
        .request-response {{
            margin: 15px 0;
            padding: 15px;
            background: #1e293b;
            border-radius: 6px;
            overflow-x: auto;
        }}
        
        .request-response.request {{
            border-left: 4px solid #3b82f6;
        }}
        
        .request-response.response {{
            border-left: 4px solid #10b981;
        }}
        
        .request-response.error {{
            border-left: 4px solid #ef4444;
        }}
        
        .request-response h5 {{
            color: #94a3b8;
            margin-bottom: 10px;
            font-size: 0.9em;
            text-transform: uppercase;
        }}
        
        .code-block {{
            background: #0f172a;
            color: #e2e8f0;
            padding: 15px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            white-space: pre;
            overflow: auto;
            max-height: 400px;
            word-wrap: normal;
        }}

        /* ── andypf-json-viewer ─────────────────────────────────── */
        andypf-json-viewer {{
            display: block;
            max-height: 450px;
            overflow: auto;
            border-radius: 6px;
            font-size: 0.88em;
            border: 1px solid #e5e7eb;
        }}

        /* ── Header table ────────────────────────────────────────── */
        .hdr-table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.85em;
            margin: 0;
        }}
        .hdr-table td {{
            padding: 4px 10px;
            vertical-align: top;
            border-bottom: 1px solid #f0f0f0;
        }}
        .hdr-table td:first-child {{
            font-weight: 600;
            color: #334155;
            white-space: nowrap;
            width: 35%;
        }}
        .hdr-table td:last-child {{
            color: #475569;
            word-break: break-all;
        }}

        /* ── Request / Response panels ───────────────────────────── */
        .req-panel, .resp-panel {{
            margin: 8px 0;
            border-radius: 6px;
            overflow: hidden;
            border: 1px solid #e5e7eb;
        }}
        .req-panel-header, .resp-panel-header {{
            padding: 10px 15px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 10px;
            cursor: pointer;
            user-select: none;
        }}
        .req-panel-header {{
            background: #eff6ff;
            border-bottom: 1px solid #dbeafe;
            color: #1d4ed8;
        }}
        .resp-panel-header {{
            background: #f0fdf4;
            border-bottom: 1px solid #bbf7d0;
            color: #166534;
        }}
        .resp-panel-header.error {{
            background: #fef2f2;
            border-bottom: 1px solid #fecaca;
            color: #991b1b;
        }}
        .req-panel-header h4, .resp-panel-header h4 {{
            margin: 0;
            font-size: 1em;
        }}
        .panel-toggle {{
            font-size: 0.85em;
            transition: transform 0.2s;
            flex-shrink: 0;
        }}
        .req-panel-header.collapsed .panel-toggle,
        .resp-panel-header.collapsed .panel-toggle {{
            transform: rotate(-90deg);
        }}
        .panel-body {{
            background: white;
            padding: 12px 15px;
            overflow: hidden;
            max-height: 6000px;
            transition: max-height 0.3s ease-out, padding 0.25s;
        }}
        .panel-body.collapsed {{
            max-height: 0;
            padding-top: 0;
            padding-bottom: 0;
        }}
        /* ── Collapsible sub-section (headers) ───────────────────── */
        .sub-section {{
            margin: 8px 0;
            border: 1px solid #f0f0f0;
            border-radius: 4px;
            overflow: hidden;
        }}
        .sub-section-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 5px 10px;
            background: #f8fafc;
            cursor: pointer;
            user-select: none;
            font-size: 0.78em;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.06em;
            color: #64748b;
        }}
        .sub-section-header:hover {{ background: #f1f5f9; }}
        .sub-toggle {{
            font-size: 0.75em;
            transition: transform 0.2s;
        }}
        .sub-section-header.collapsed .sub-toggle {{ transform: rotate(-90deg); }}
        .sub-section-body {{
            overflow: hidden;
            max-height: 2000px;
            transition: max-height 0.25s ease-out;
        }}
        .sub-section-body.collapsed {{ max-height: 0; }}
        .method-pill {{
            display: inline-block;
            background: #667eea;
            color: white;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.8em;
            font-weight: 700;
            letter-spacing: 0.05em;
            margin-right: 6px;
        }}
        .status-badge {{
            display: inline-block;
            padding: 2px 10px;
            border-radius: 4px;
            font-size: 0.9em;
            font-weight: 600;
        }}
        .status-badge.ok {{ background: #dcfce7; color: #166534; }}
        .status-badge.err {{ background: #fee2e2; color: #991b1b; }}
        .section-label {{
            font-size: 0.78em;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.06em;
            color: #64748b;
            margin: 10px 0 4px 0;
        }}
        
        .error-message {{
            background: #fee2e2;
            color: #991b1b;
            padding: 15px;
            border-radius: 6px;
            border-left: 4px solid #ef4444;
            margin: 15px 0;
        }}
        
        .step-divider {{
            margin: 30px 0;
            border-top: 2px dashed #e5e7eb;
            position: relative;
        }}
        
        .step-divider::after {{
            content: attr(data-step);
            position: absolute;
            top: -12px;
            left: 50%;
            transform: translateX(-50%);
            background: white;
            padding: 0 15px;
            color: #667eea;
            font-weight: 600;
        }}
        
        .toggle-btn {{
            background: none;
            border: none;
            color: #667eea;
            cursor: pointer;
            font-size: 1.2em;
            padding: 5px;
            transition: transform 0.2s;
        }}
        
        .toggle-btn.active {{
            transform: rotate(180deg);
        }}
        
        .timestamp {{
            color: #6b7280;
            font-size: 0.85em;
        }}
        
        .filters {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }}
        
        .filter-row {{
            display: flex;
            gap: 15px;
            align-items: center;
            flex-wrap: wrap;
        }}
        
        .filter-group {{
            display: flex;
            gap: 10px;
            align-items: center;
        }}
        
        .filter-label {{
            font-weight: 600;
            color: #667eea;
            margin-right: 5px;
        }}
        
        .filter-btn {{
            background: #f3f4f6;
            border: 2px solid #e5e7eb;
            padding: 8px 16px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 0.9em;
            transition: all 0.2s;
        }}
        
        .filter-btn:hover {{
            background: #e5e7eb;
        }}
        
        .filter-btn.active {{
            background: #667eea;
            color: white;
            border-color: #667eea;
        }}
        
        .search-box {{
            flex: 1;
            min-width: 250px;
            padding: 10px 15px;
            border: 2px solid #e5e7eb;
            border-radius: 6px;
            font-size: 0.9em;
            transition: border-color 0.2s;
        }}
        
        .search-box:focus {{
            outline: none;
            border-color: #667eea;
        }}
        
        .select-box {{
            padding: 10px 15px;
            border: 2px solid #e5e7eb;
            border-radius: 6px;
            font-size: 0.9em;
            cursor: pointer;
            background: white;
            transition: border-color 0.2s;
        }}
        
        .select-box:focus {{
            outline: none;
            border-color: #667eea;
        }}
        
        .test-case.hidden {{
            display: none;
        }}
        
        .group-header {{
            background: #f3f4f6;
            padding: 15px 20px;
            margin: 20px 0 10px 0;
            border-radius: 6px;
            font-weight: 600;
            color: #667eea;
            display: flex;
            align-items: center;
            gap: 10px;
            cursor: pointer;
            transition: background 0.2s;
            position: relative;
        }}
        
        .group-header:hover {{
            background: #e5e7eb;
        }}
        
        .group-header .count {{
            background: #667eea;
            color: white;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.85em;
        }}
        
        .group-header .expand-icon {{
            margin-left: auto;
            transition: transform 0.2s;
            font-size: 1.2em;
        }}
        
        .group-header.collapsed .expand-icon {{
            transform: rotate(-90deg);
        }}
        
        .group-content {{
            max-height: 10000px;
            overflow: hidden;
            transition: max-height 0.3s ease-out;
        }}
        
        .group-content.collapsed {{
            max-height: 0;
        }}
        
        .group-filters {{
            background: #f9fafb;
            padding: 10px 15px;
            margin: 0 0 10px 0;
            border-radius: 4px;
            display: flex;
            gap: 10px;
            align-items: center;
        }}
        
        .group-filters label {{
            font-size: 0.85em;
            color: #666;
        }}
        
        .group-filter-input {{
            flex: 1;
            padding: 6px 10px;
            border: 1px solid #e5e7eb;
            border-radius: 4px;
            font-size: 0.85em;
        }}
        
        .group-filter-input:focus {{
            outline: none;
            border-color: #667eea;
        }}
        
        .step-accordion {{
            margin: 15px 0;
            border: 1px solid #e5e7eb;
            border-radius: 6px;
            overflow: hidden;
        }}
        
        .step-accordion-header {{
            background: #f9fafb;
            padding: 12px 15px;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
            transition: background 0.2s;
            border-bottom: 1px solid #e5e7eb;
        }}
        
        .step-accordion-header:hover {{
            background: #f3f4f6;
        }}
        
        .step-accordion-header h5 {{
            margin: 0;
            color: #667eea;
            font-size: 1em;
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        
        .step-accordion-header .step-toggle {{
            transition: transform 0.2s;
            color: #667eea;
            font-size: 1.2em;
        }}
        
        .step-accordion-header.collapsed .step-toggle {{
            transform: rotate(-90deg);
        }}
        
        .step-accordion-content {{
            max-height: 5000px;
            overflow: hidden;
            transition: max-height 0.3s ease-out;
            background: white;
        }}
        
        .step-accordion-content.collapsed {{
            max-height: 0;
        }}
        
        .step-accordion-body {{
            padding: 15px;
        }}
        
        
        .copy-btn {{
            background: #667eea;
            color: white;
            border: none;
            padding: 6px 12px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 0.85em;
            margin-top: 8px;
            transition: all 0.2s;
            display: inline-flex;
            align-items: center;
            gap: 5px;
        }}
        
        .copy-btn:hover {{
            background: #5568d3;
        }}
        
        .copy-btn:active {{
            transform: scale(0.95);
        }}
        
        .copy-btn.copied {{
            background: #10b981;
        }}
        
        .request-response .code-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }}
        
        .key-pair-section {{
            background: #f0fdf4;
            border: 2px solid #86efac;
            border-radius: 8px;
            padding: 20px;
            margin: 15px 0;
        }}
        
        .key-pair-section h4 {{
            color: #166534;
            margin-bottom: 15px;
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 1.1em;
        }}
        
        .key-field {{
            margin: 12px 0;
        }}
        
        .key-field label {{
            display: block;
            font-weight: 600;
            color: #166534;
            font-size: 0.85em;
            text-transform: uppercase;
            margin-bottom: 4px;
        }}
        
        .key-value {{
            background: #0f172a;
            color: #86efac;
            padding: 10px 15px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 0.85em;
            white-space: pre-wrap;
            word-break: break-all;
        }}
        
        .key-meta {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 10px;
            background: #dcfce7;
            padding: 12px;
            border-radius: 6px;
            margin-bottom: 12px;
        }}
        
        .key-meta-item {{
            font-size: 0.9em;
        }}
        
        .key-meta-item span:first-child {{
            font-weight: 600;
            color: #166534;
            display: block;
        }}
    </style>
    <script src="https://cdn.jsdelivr.net/npm/@andypf/json-viewer@2/dist/iife/index.js"></script>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📊 {test_suite_name}</h1>
            <p class="timestamp">Generated: {datetime.now().strftime('%B %d, %Y at %I:%M %p')}</p>
        </div>
        
        <div class="summary">
            <div class="summary-card passed">
                <div class="label">Passed</div>
                <div class="value">{passed}</div>
            </div>
            <div class="summary-card failed">
                <div class="label">Failed</div>
                <div class="value">{failed}</div>
            </div>
            <div class="summary-card">
                <div class="label">Total</div>
                <div class="value">{len(results)}</div>
            </div>
            <div class="summary-card rate">
                <div class="label">Pass Rate</div>
                <div class="value">{pass_rate:.1f}%</div>
            </div>
            <div class="summary-card">
                <div class="label">Avg Time</div>
                <div class="value" style="font-size:1.6em">{avg_ms}ms</div>
            </div>
        </div>

        <!-- Group F1: Execution Timeline (collapsible) -->
        <div class="filters" id="timeline-section" style="padding-bottom:8px">
            <div style="display:flex;align-items:center;justify-content:space-between;cursor:pointer;user-select:none"
                 onclick="toggleSection('timeline-body','timeline-chevron')">
                <span style="font-weight:600;color:#667eea">⏱ Execution Timeline</span>
                <span id="timeline-chevron" style="color:#667eea;font-size:1.1em;transition:transform .2s">▼</span>
            </div>
            <div id="timeline-body" style="overflow-x:auto;margin-top:10px;display:none">
                <div id="timeline-bars" style="display:flex;flex-direction:column;gap:4px;min-width:500px">
{timeline_rows}
                </div>
            </div>
        </div>
        
        <div class="filters">
            <div class="filter-row">
                <div class="filter-group">
                    <span class="filter-label">Filter:</span>
                    <button class="filter-btn active" onclick="filterTests('all', this)">All Tests</button>
                    <button class="filter-btn" onclick="filterTests('passed', this)">✓ Passed</button>
                    <button class="filter-btn" onclick="filterTests('failed', this)">✗ Failed Only</button>
                </div>
                
                <div class="filter-group">
                    <span class="filter-label">Group By:</span>
                    <select class="select-box" onchange="groupTests(this.value)">
                        <option value="none">No Grouping</option>
                        <option value="status">Status (Passed/Failed)</option>
                        <option value="category">Test Category</option>
                        <option value="response">Response Code</option>
                        <option value="error">Error Type</option>
                    </select>
                </div>
                
                <input type="text" class="search-box" placeholder="🔍 Search by test name or ID..." 
                       onkeyup="searchTests(this.value)">
            </div>
        </div>
        
        <div class="test-cases" id="test-container">
"""
        
        # Generate test case details
        for result in results:
            html += HTMLReporter._generate_test_case_html(result)
        
        html += """
        </div>
    </div>
    
    <script>
        let currentFilter = 'all';
        let currentGroup = 'none';
        let searchTerm = '';

        // Generic collapsible toggle used by Timeline and ONDC Key Pair
        function toggleSection(bodyId, chevronId) {
            const body = document.getElementById(bodyId);
            const chev = document.getElementById(chevronId);
            if (!body) return;
            const collapsed = body.style.display === 'none';
            body.style.display = collapsed ? '' : 'none';
            if (chev) chev.style.transform = collapsed ? 'rotate(0deg)' : 'rotate(-90deg)';
        }

        function filterTests(filter, clickedBtn) {
            currentFilter = filter;

            // Update button states
            document.querySelectorAll('.filter-btn').forEach(btn => {
                btn.classList.remove('active');
            });
            if (clickedBtn) {
                clickedBtn.classList.add('active');
            }
            
            applyFilters();
        }
        
        function searchTests(term) {
            searchTerm = term.toLowerCase();
            applyFilters();
        }
        
        function applyFilters() {
            const testCases = document.querySelectorAll('.test-case');
            
            testCases.forEach(testCase => {
                const status = testCase.dataset.status;
                const testId = testCase.dataset.testId.toLowerCase();
                const testName = testCase.dataset.testName.toLowerCase();
                
                let showTest = true;
                
                // Apply status filter
                if (currentFilter !== 'all' && status !== currentFilter) {
                    showTest = false;
                }
                
                // Apply search filter
                if (searchTerm && !testId.includes(searchTerm) && !testName.includes(searchTerm)) {
                    showTest = false;
                }
                
                testCase.classList.toggle('hidden', !showTest);
            });
            
            // Update group headers visibility
            updateGroupHeaders();
        }
        
        function groupTests(groupBy) {
            currentGroup = groupBy;
            const container = document.getElementById('test-container');
            const testCases = Array.from(document.querySelectorAll('.test-case'));
            
            // Remove existing group headers and content divs
            document.querySelectorAll('.group-header').forEach(header => header.remove());
            document.querySelectorAll('.group-content').forEach(content => content.remove());
            
            if (groupBy === 'none') {
                // Just reorder by original order (test_id)
                testCases.sort((a, b) => {
                    return a.dataset.testId.localeCompare(b.dataset.testId);
                });
                
                testCases.forEach(testCase => container.appendChild(testCase));
            } else if (groupBy === 'status') {
                const passed = testCases.filter(tc => tc.dataset.status === 'passed');
                const failed = testCases.filter(tc => tc.dataset.status === 'failed');
                
                if (passed.length > 0) {
                    const header = document.createElement('div');
                    header.className = 'group-header';
                    header.dataset.groupId = 'group-passed';
                    header.innerHTML = '✓ Passed Tests <span class="count">' + passed.length + '</span><span class="expand-icon">▼</span>';
                    header.onclick = () => toggleGroup('group-passed');
                    container.appendChild(header);
                    
                    const groupContent = document.createElement('div');
                    groupContent.className = 'group-content';
                    groupContent.id = 'content-group-passed';
                    
                    const groupFilter = document.createElement('div');
                    groupFilter.className = 'group-filters';
                    groupFilter.innerHTML = '<label>Filter in group:</label><input type="text" class="group-filter-input" placeholder="Search within Passed tests..." onkeyup="filterInGroup(&apos;group-passed&apos;, this.value)">';
                    groupContent.appendChild(groupFilter);
                    
                    passed.forEach(tc => groupContent.appendChild(tc));
                    container.appendChild(groupContent);
                }
                
                if (failed.length > 0) {
                    const header = document.createElement('div');
                    header.className = 'group-header';
                    header.dataset.groupId = 'group-failed';
                    header.innerHTML = '✗ Failed Tests <span class="count">' + failed.length + '</span><span class="expand-icon">▼</span>';
                    header.onclick = () => toggleGroup('group-failed');
                    container.appendChild(header);
                    
                    const groupContent = document.createElement('div');
                    groupContent.className = 'group-content';
                    groupContent.id = 'content-group-failed';
                    
                    const groupFilter = document.createElement('div');
                    groupFilter.className = 'group-filters';
                    groupFilter.innerHTML = '<label>Filter in group:</label><input type="text" class="group-filter-input" placeholder="Search within Failed tests..." onkeyup="filterInGroup(&apos;group-failed&apos;, this.value)">';
                    groupContent.appendChild(groupFilter);
                    
                    failed.forEach(tc => groupContent.appendChild(tc));
                    container.appendChild(groupContent);
                }
            } else if (groupBy === 'category') {
                // Group by test ID prefix (e.g., A01-A05, A06-A10)
                const categories = {};
                
                testCases.forEach(tc => {
                    const testId = tc.dataset.testId;
                    const prefix = testId.match(/[A-Z]+/)[0]; // Get letter prefix
                    const num = parseInt(testId.match(/\\d+/)[0]); // Get number
                    
                    // Create category ranges (0-9, 10-19, 20-29, etc.)
                    const categoryKey = prefix + Math.floor(num / 10) + '0s';
                    
                    if (!categories[categoryKey]) {
                        categories[categoryKey] = [];
                    }
                    categories[categoryKey].push(tc);
                });
                
                // Sort categories and append
                Object.keys(categories).sort().forEach((category, index) => {
                    const tests = categories[category];
                    const groupId = 'group-cat-' + index;
                    
                    const header = document.createElement('div');
                    header.className = 'group-header';
                    header.dataset.groupId = groupId;
                    header.innerHTML = '📁 ' + category + ' <span class="count">' + tests.length + '</span><span class="expand-icon">▼</span>';
                    header.onclick = () => toggleGroup(groupId);
                    container.appendChild(header);
                    
                    const groupContent = document.createElement('div');
                    groupContent.className = 'group-content';
                    groupContent.id = 'content-' + groupId;
                    
                    const groupFilter = document.createElement('div');
                    groupFilter.className = 'group-filters';
                    groupFilter.innerHTML = '<label>Filter in group:</label><input type="text" class="group-filter-input" placeholder="Search within ' + category + '..." onkeyup="filterInGroup(&apos;' + groupId + '&apos;, this.value)">';
                    groupContent.appendChild(groupFilter);
                    
                    tests.forEach(tc => groupContent.appendChild(tc));
                    container.appendChild(groupContent);
                });
            } else if (groupBy === 'response') {
                // Group by response code
                const responseCodes = {};
                
                testCases.forEach(tc => {
                    const code = tc.dataset.responseCode || '0';
                    const codeKey = code === '0' ? 'Success (No Error)' : 'HTTP ' + code;
                    
                    if (!responseCodes[codeKey]) {
                        responseCodes[codeKey] = [];
                    }
                    responseCodes[codeKey].push(tc);
                });
                
                // Sort by code and append
                Object.keys(responseCodes).sort((a, b) => {
                    // Extract numeric codes for sorting
                    const numA = parseInt(a.match(/\\d+/) || '0');
                    const numB = parseInt(b.match(/\\d+/) || '0');
                    return numA - numB;
                }).forEach((code, index) => {
                    const tests = responseCodes[code];
                    const groupId = 'group-resp-' + index;
                    
                    const header = document.createElement('div');
                    header.className = 'group-header';
                    header.dataset.groupId = groupId;
                    
                    // Add emoji based on status code
                    let emoji = '🔵';
                    const codeNum = parseInt(code.match(/\\d+/) || '0');
                    if (codeNum >= 200 && codeNum < 300) emoji = '🟢';
                    else if (codeNum >= 400 && codeNum < 500) emoji = '🟡';
                    else if (codeNum >= 500) emoji = '🔴';
                    
                    header.innerHTML = emoji + ' ' + code + ' <span class="count">' + tests.length + '</span><span class="expand-icon">▼</span>';
                    header.onclick = () => toggleGroup(groupId);
                    container.appendChild(header);
                    
                    const groupContent = document.createElement('div');
                    groupContent.className = 'group-content';
                    groupContent.id = 'content-' + groupId;
                    
                    const groupFilter = document.createElement('div');
                    groupFilter.className = 'group-filters';
                    groupFilter.innerHTML = '<label>Filter in group:</label><input type="text" class="group-filter-input" placeholder="Search within ' + code + '..." onkeyup="filterInGroup(&apos;' + groupId + '&apos;, this.value)">';
                    groupContent.appendChild(groupFilter);
                    
                    tests.forEach(tc => groupContent.appendChild(tc));
                    container.appendChild(groupContent);
                });
            } else if (groupBy === 'error') {
                // Group by error type
                const errorTypes = {};
                
                testCases.forEach(tc => {
                    const errorType = tc.dataset.errorType || 'No Error';
                    
                    if (!errorTypes[errorType]) {
                        errorTypes[errorType] = [];
                    }
                    errorTypes[errorType].push(tc);
                });
                
                // Sort by error type and append
                Object.keys(errorTypes).sort((a, b) => {
                    // Put "No Error" first
                    if (a === 'No Error') return -1;
                    if (b === 'No Error') return 1;
                    return a.localeCompare(b);
                }).forEach((errorType, index) => {
                    const tests = errorTypes[errorType];
                    const groupId = 'group-err-' + index;
                    
                    const header = document.createElement('div');
                    header.className = 'group-header';
                    header.dataset.groupId = groupId;
                    
                    // Add emoji based on error type
                    let emoji = errorType === 'No Error' ? '✅' : '⚠️';
                    if (errorType.includes('ERR_')) emoji = '❌';
                    else if (errorType.includes('Schema')) emoji = '📋';
                    else if (errorType.includes('HTTP 4')) emoji = '🟡';
                    else if (errorType.includes('HTTP 5')) emoji = '🔴';
                    
                    header.innerHTML = emoji + ' ' + errorType + ' <span class="count">' + tests.length + '</span><span class="expand-icon">▼</span>';
                    header.onclick = () => toggleGroup(groupId);
                    container.appendChild(header);
                    
                    const groupContent = document.createElement('div');
                    groupContent.className = 'group-content';
                    groupContent.id = 'content-' + groupId;
                    
                    const groupFilter = document.createElement('div');
                    groupFilter.className = 'group-filters';
                    groupFilter.innerHTML = '<label>Filter in group:</label><input type="text" class="group-filter-input" placeholder="Search within ' + errorType + '..." onkeyup="filterInGroup(&apos;' + groupId + '&apos;, this.value)">';
                    groupContent.appendChild(groupFilter);
                    
                    tests.forEach(tc => groupContent.appendChild(tc));
                    container.appendChild(groupContent);
                });
            }
            
            applyFilters();
        }
        
        function updateGroupHeaders() {
            document.querySelectorAll('.group-header').forEach(header => {
                // Get the group content (accordion structure)
                const groupId = header.dataset.groupId;
                if (!groupId) return;
                
                const content = document.getElementById('content-' + groupId);
                if (!content) return;
                
                // Count visible tests inside this group
                const visibleTests = content.querySelectorAll('.test-case:not(.hidden)');
                
                // Hide entire group (header + content) if no visible tests
                if (visibleTests.length === 0) {
                    header.style.display = 'none';
                    content.style.display = 'none';
                } else {
                    header.style.display = 'flex';
                    content.style.display = content.classList.contains('collapsed') ? 'none' : 'block';
                    
                    // Update count in header
                    const countSpan = header.querySelector('.count');
                    if (countSpan) {
                        countSpan.textContent = visibleTests.length;
                    }
                }
            });
        }
        
        function toggleGroup(groupId) {
            const header = document.querySelector('[data-group-id="' + groupId + '"]');
            const content = document.getElementById('content-' + groupId);
            
            if (header && content) {
                const isCollapsed = content.classList.contains('collapsed');
                
                if (isCollapsed) {
                    content.classList.remove('collapsed');
                    header.classList.remove('collapsed');
                    content.style.display = 'block';
                } else {
                    content.classList.add('collapsed');
                    header.classList.add('collapsed');
                    content.style.display = 'none';
                }
            }
        }
        
        function filterInGroup(groupId, searchTerm) {
            const content = document.getElementById('content-' + groupId);
            if (!content) return;
            
            const term = searchTerm.toLowerCase();
            const testCases = content.querySelectorAll('.test-case');
            
            testCases.forEach(tc => {
                const testId = (tc.dataset.testId || '').toLowerCase();
                const testName = (tc.dataset.testName || '').toLowerCase();
                const errorMsg = (tc.dataset.errorType || '').toLowerCase();
                
                const matches = term === '' || 
                               testId.includes(term) || 
                               testName.includes(term) || 
                               errorMsg.includes(term);
                
                // Use consistent class-based hiding
                if (matches) {
                    tc.classList.remove('hidden');
                } else {
                    tc.classList.add('hidden');
                }
            });
            
            // Update group header visibility and count
            updateGroupHeaders();
        }
        
        function toggleDetails(testId) {
            const details = document.getElementById('details-' + testId);
            const btn = document.getElementById('btn-' + testId);
            
            details.classList.toggle('active');
            btn.classList.toggle('active');
        }
        
        function toggleStepAccordion(stepId) {
            const header = document.getElementById('accordion-header-' + stepId);
            const content = document.getElementById('accordion-content-' + stepId);
            
            if (header && content) {
                header.classList.toggle('collapsed');
                content.classList.toggle('collapsed');
            }
        }
        
        function copyToClipboard(elementId, buttonId) {
            const element = document.getElementById(elementId);
            const button = document.getElementById(buttonId);
            
            if (element && button) {
                const text = element.textContent;
                
                navigator.clipboard.writeText(text).then(() => {
                    const originalText = button.innerHTML;
                    button.innerHTML = '✓ Copied!';
                    button.classList.add('copied');
                    
                    setTimeout(() => {
                        button.innerHTML = originalText;
                        button.classList.remove('copied');
                    }, 2000);
                }).catch(err => {
                    console.error('Copy failed:', err);
                    button.innerHTML = '✗ Failed';
                    setTimeout(() => {
                        button.innerHTML = '📋 Copy';
                    }, 2000);
                });
            }
        }
        
        function togglePanel(id) {
            var header = document.getElementById('ph-' + id);
            var body   = document.getElementById('pb-' + id);
            if (!header || !body) return;
            header.classList.toggle('collapsed');
            body.classList.toggle('collapsed');
        }

        function toggleSubSection(id) {
            var header = document.getElementById('ssh-' + id);
            var body   = document.getElementById('ssb-' + id);
            if (!header || !body) return;
            header.classList.toggle('collapsed');
            body.classList.toggle('collapsed');
        }

        function copyFromSidecar(sidecarId, btnId) {
            var sidecar = document.getElementById(sidecarId);
            var btn = document.getElementById(btnId);
            if (!sidecar) return;
            try {
                var data = JSON.parse(sidecar.textContent);
                navigator.clipboard.writeText(JSON.stringify(data, null, 2)).then(function() {
                    if (btn) { var orig = btn.innerHTML; btn.innerHTML = '✓ Copied!'; btn.classList.add('copied'); setTimeout(function() { btn.innerHTML = orig; btn.classList.remove('copied'); }, 2000); }
                }).catch(function(err) {
                    if (btn) { btn.innerHTML = '✗ Failed'; setTimeout(function() { btn.innerHTML = '📋 Copy'; }, 2000); }
                });
            } catch(e) {
                navigator.clipboard.writeText(sidecar.textContent);
            }
        }

        // Expand all failed tests on load
        window.addEventListener('DOMContentLoaded', () => {
            document.querySelectorAll('.test-case[data-status="failed"]').forEach(tc => {
                const testId = tc.dataset.testId;
                const details = document.getElementById('details-' + testId);
                const btn = document.getElementById('btn-' + testId);
                if (details && btn) {
                    details.classList.add('active');
                    btn.classList.add('active');
                }
            });
        });
    </script>
</body>
</html>
"""
        
        # Write to file
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html)
    
    @staticmethod
    def _generate_test_case_html(result: Dict) -> str:
        """Generate HTML for a single test case."""
        test_id = result.get('test_id', 'Unknown')
        name = result.get('name', 'Unknown Test')
        passed = result.get('passed', False)
        status_class = 'passed' if passed else 'failed'
        status_text = '✓ PASSED' if passed else '✗ FAILED'
        
        # Extract response code and error type for grouping
        response_code = result.get('status_code', 0)
        error_message = result.get('error_message', '')
        
        # Extract error type from message (e.g., "ERR_102", "ERR_408", or general error descriptions)
        error_type = 'Unknown Error'
        if error_message:
            # Try to extract error code like ERR_XXX
            import re
            err_match = re.search(r'ERR_\d+', error_message)
            if err_match:
                error_type = err_match.group(0)
            elif 'Schema validation failed' in error_message:
                error_type = 'Schema Validation Error'
            elif 'Expected' in error_message and 'got' in error_message:
                # Extract the "got X" part
                got_match = re.search(r'got (\d+)', error_message)
                if got_match:
                    error_type = f'HTTP {got_match.group(1)} Error'
            else:
                # Use first part of error message
                error_type = error_message.split(':')[0][:30]
        
        html = f"""
            <div class="test-case" data-test-id="{test_id}" data-test-name="{name}" data-status="{status_class}" data-response-code="{response_code}" data-error-type="{error_type}">
                <div class="test-header {status_class}" onclick="toggleDetails('{test_id}')">
                    <div class="test-title">
                        <h3>{name}</h3>
                        <div class="test-id">ID: {test_id} | Time: {result.get('execution_time_ms', 0)}ms</div>
                    </div>
                    <button class="toggle-btn" id="btn-{test_id}">▼</button>
                    <div class="test-status {status_class}">{status_text}</div>
                </div>
                
                <div class="test-details" id="details-{test_id}">
"""
        
        # Test information
        html += f"""
                    <div class="detail-section">
                        <h4>Test Information</h4>
                        <div class="info-grid">
                            <span class="info-label">Test ID:</span>
                            <span>{test_id}</span>
                            <span class="info-label">Status:</span>
                            <span>{status_text}</span>
                            <span class="info-label">Execution Time:</span>
                            <span>{result.get('execution_time_ms', 0)}ms</span>
                            <span class="info-label">Timestamp:</span>
                            <span>{result.get('timestamp', 'N/A')}</span>
"""
        
        if result.get('status_code'):
            html += f"""
                            <span class="info-label">Status Code:</span>
                            <span>{result.get('status_code')} (Expected: {result.get('expected_status', 'N/A')})</span>
"""
        
        html += """
                        </div>
                    </div>
"""
        
        # Error message
        if result.get('error_message'):
            html += f"""
                    <div class="detail-section">
                        <div class="error-message">
                            <strong>Error:</strong> {result.get('error_message')}
                        </div>
                    </div>
"""
        
        # ONDC Key Pair section — only shown when V3 auto-registration ran for this test
        ondc_key = result.get('ondc_key_info')
        if ondc_key:
            seed_b64_id = f"seedb64-{test_id}"
            private_pem_id = f"privkey-{test_id}"
            pub_key_id = f"pubkey-{test_id}"
            key_body_id = f"key-body-{test_id}"
            key_chevron_id = f"key-chev-{test_id}"
            html += f"""
                    <div class="key-pair-section">
                        <div style="display:flex;align-items:center;justify-content:space-between;
                                    cursor:pointer;user-select:none;margin-bottom:0"
                             onclick="toggleSection('{key_body_id}','{key_chevron_id}')">
                            <h4 style="margin:0">🔑 Generated ONDC Key Pair</h4>
                            <span id="{key_chevron_id}" style="color:#166534;font-size:1.1em;transition:transform .2s">▼</span>
                        </div>
                        <div id="{key_body_id}" style="display:none;margin-top:12px">
                        <div class="key-meta">
                            <div class="key-meta-item">
                                <span>Subscriber ID</span>
                                <span>{ondc_key.get('subscriber_id', 'N/A')}</span>
                            </div>
                            <div class="key-meta-item">
                                <span>Unique Key ID</span>
                                <span>{ondc_key.get('unique_key_id', 'N/A')}</span>
                            </div>
                            <div class="key-meta-item">
                                <span>Algorithm</span>
                                <span>{ondc_key.get('signed_algorithm', 'ED25519')} / {ondc_key.get('encryption_algorithm', 'X25519')}</span>
                            </div>
                            <div class="key-meta-item">
                                <span>Valid Until</span>
                                <span>{ondc_key.get('valid_until', 'N/A')}</span>
                            </div>
                        </div>
                        <div class="key-field">
                            <label>signing_private_key → Postman env var (raw 32-byte seed, base64)</label>
                            <div class="code-header" style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;">
                                <span style="font-size:0.8em;color:#166534;">Paste into Postman env <code>signing_private_key</code> — used by pre-request script for <code>/signature/generate</code></span>
                                <button class="copy-btn" id="copy-{seed_b64_id}" onclick="copyToClipboard('{seed_b64_id}', 'copy-{seed_b64_id}')">📋 Copy</button>
                            </div>
                            <div class="key-value" id="{seed_b64_id}">{ondc_key.get('private_key_b64', '')}</div>
                        </div>
                        <div class="key-field">
                            <label>Signing Public Key (base64 DER/SPKI)</label>
                            <div class="code-header" style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;">
                                <span style="font-size:0.8em;color:#166534;">Register this with the ONDC registry</span>
                                <button class="copy-btn" id="copy-{pub_key_id}" onclick="copyToClipboard('{pub_key_id}', 'copy-{pub_key_id}')">📋 Copy Key</button>
                            </div>
                            <div class="key-value" id="{pub_key_id}">{ondc_key.get('signing_public_key', '')}</div>
                        </div>
                        <div class="key-field">
                            <label>Private Key (PEM / PKCS8) – for code reuse only</label>
                            <div class="code-header" style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;">
                                <span style="font-size:0.8em;color:#166534;">Use with Python cryptography library — NOT for Postman <code>signing_private_key</code></span>
                                <button class="copy-btn" id="copy-{private_pem_id}" onclick="copyToClipboard('{private_pem_id}', 'copy-{private_pem_id}')">📋 Copy PEM</button>
                            </div>
                            <div class="key-value" id="{private_pem_id}">{ondc_key.get('private_key_pem', '')}</div>
                        </div>
                        </div><!-- /#key-body -->
                    </div>
"""
        
        # Request/Response details
        request_details = result.get('request_details', [])
        response_details = result.get('response_details', [])
        
        # If multiple requests (workflow), use accordion for each step (default collapsed)
        use_accordion = len(request_details) > 1
        
        for i, (req, resp) in enumerate(zip(request_details, response_details)):
            step_id = f"{test_id}-step-{i}"
            step_name = req.get('step_name', f'Step {i+1}')
            
            if use_accordion:
                # Create accordion for each step (collapsed by default)
                html += f"""
                    <div class="step-accordion">
                        <div class="step-accordion-header collapsed" id="accordion-header-{step_id}" onclick="toggleStepAccordion('{step_id}')">
                            <h5>🔄 {step_name}</h5>
                            <span class="step-toggle">▼</span>
                        </div>
                        <div class="step-accordion-content collapsed" id="accordion-content-{step_id}">
                            <div class="step-accordion-body">
"""
            else:
                # Single request - no accordion needed
                html += '<div class="detail-section">'
            
            # Request panel
            req_sidecar_body_id = f"jdata-req-body-{step_id}"
            req_jv_body_id = f"jv-req-body-{step_id}"
            req_copy_btn_id = f"copy-req-body-{step_id}"
            method = _he(req.get('method', 'N/A'))
            endpoint = _he(req.get('endpoint', 'N/A'))
            req_panel_id = f"rp-{step_id}"
            req_hdr_sub_id = f"rh-{step_id}"
            html += f"""
                        <div class="req-panel">
                            <div class="req-panel-header collapsed" id="ph-{req_panel_id}" onclick="togglePanel('{req_panel_id}')">
                                <h4>🔵 Request{(' ' + str(i+1)) if use_accordion else ''}</h4>
                                <div style="display:flex;align-items:center;gap:10px">
                                    <span><span class="method-pill">{method}</span>{endpoint}</span>
                                    <span class="panel-toggle">▼</span>
                                </div>
                            </div>
                            <div class="panel-body collapsed" id="pb-{req_panel_id}">
"""
            if req.get('url'):
                html += f"""
                                <div class="section-label">Full URL</div>
                                <div class="code-block">{_he(req.get('url', ''))}</div>
"""
            if req.get('headers'):
                hdr_obj = req.get('headers', {})
                html += f"""
                                <div class="sub-section">
                                    <div class="sub-section-header collapsed" id="ssh-{req_hdr_sub_id}" onclick="toggleSubSection('{req_hdr_sub_id}')">
                                        Headers <span class="sub-toggle">▼</span>
                                    </div>
                                    <div class="sub-section-body collapsed" id="ssb-{req_hdr_sub_id}">
                                        <table class="hdr-table">
"""
                for k, v in hdr_obj.items():
                    html += f"                                            <tr><td>{_he(str(k))}</td><td>{_he(str(v))}</td></tr>\n"
                html += """                                        </table>
                                    </div>
                                </div>
"""

            if req.get('body'):
                body_obj = req.get('body', {})
                body_sidecar = _je(body_obj) if isinstance(body_obj, (dict, list)) else _je(str(body_obj))
                html += f"""
                                <div style="display:flex;justify-content:space-between;align-items:center">
                                    <div class="section-label">Body</div>
                                    <button class="copy-btn" id="{req_copy_btn_id}" onclick="copyFromSidecar('{req_sidecar_body_id}','{req_copy_btn_id}')">📋 Copy</button>
                                </div>
                                <script type="application/json" id="{req_sidecar_body_id}">{body_sidecar}</script>
                                <andypf-json-viewer id="{req_jv_body_id}"
                                  indent="2" expanded="true" theme="default-dark"
                                  show-data-types="false" show-toolbar="true"
                                  expand-icon-type="arrow" show-copy="true"
                                  show-size="true" expand-empty="false"
                                  data="{_ae(body_obj) if isinstance(body_obj, (dict, list)) else _ae(str(body_obj))}"></andypf-json-viewer>
"""
            html += """
                            </div>
                        </div>
"""

            # Response panel
            status_code = resp.get('status_code', 0)
            is_ok = 200 <= status_code < 300
            resp_header_cls = 'resp-panel-header' + ('' if is_ok else ' error')
            resp_icon = '🟢' if is_ok else '🔴'
            badge_cls = 'ok' if is_ok else 'err'
            resp_sidecar_body_id = f"jdata-resp-body-{step_id}"
            resp_jv_body_id = f"jv-resp-body-{step_id}"
            resp_copy_btn_id = f"copy-resp-body-{step_id}"

            resp_panel_id = f"rsp-{step_id}"
            resp_hdr_sub_id = f"rsph-{step_id}"
            html += f"""
                        <div class="resp-panel">
                            <div class="{resp_header_cls} collapsed" id="ph-{resp_panel_id}" onclick="togglePanel('{resp_panel_id}')">
                                <h4>{resp_icon} Response{(' ' + str(i+1)) if use_accordion else ''}</h4>
                                <div style="display:flex;align-items:center;gap:10px">
                                    <span class="status-badge {badge_cls}">{status_code}</span>
                                    <span class="panel-toggle">▼</span>
                                </div>
                            </div>
                            <div class="panel-body collapsed" id="pb-{resp_panel_id}">
"""
            if resp.get('headers'):
                rhdr_obj = resp.get('headers', {})
                html += f"""
                                <div class="sub-section">
                                    <div class="sub-section-header collapsed" id="ssh-{resp_hdr_sub_id}" onclick="toggleSubSection('{resp_hdr_sub_id}')">
                                        Headers <span class="sub-toggle">▼</span>
                                    </div>
                                    <div class="sub-section-body collapsed" id="ssb-{resp_hdr_sub_id}">
                                        <table class="hdr-table">
"""
                for k, v in rhdr_obj.items():
                    html += f"                                            <tr><td>{_he(str(k))}</td><td>{_he(str(v))}</td></tr>\n"
                html += """                                        </table>
                                    </div>
                                </div>
"""

            if resp.get('body'):
                resp_body = resp.get('body', {})
                rbody_sidecar = _je(resp_body) if isinstance(resp_body, (dict, list)) else _je(str(resp_body))
                html += f"""
                                <div style="display:flex;justify-content:space-between;align-items:center">
                                    <div class="section-label">Body</div>
                                    <button class="copy-btn" id="{resp_copy_btn_id}" onclick="copyFromSidecar('{resp_sidecar_body_id}','{resp_copy_btn_id}')">📋 Copy</button>
                                </div>
                                <script type="application/json" id="{resp_sidecar_body_id}">{rbody_sidecar}</script>
                                <andypf-json-viewer id="{resp_jv_body_id}"
                                  indent="2" expanded="true" theme="default-dark"
                                  show-data-types="false" show-toolbar="true"
                                  expand-icon-type="arrow" show-copy="true"
                                  show-size="true" expand-empty="false"
                                  data="{_ae(resp_body) if isinstance(resp_body, (dict, list)) else _ae(str(resp_body))}"></andypf-json-viewer>
"""
            html += """
                            </div>
                        </div>
"""
            
            if use_accordion:
                # Close accordion
                html += """
                            </div>
                        </div>
                    </div>
"""
            else:
                # Close single request section
                html += '</div>'
        
        html += """
                </div>
            </div>
"""
        
        return html
