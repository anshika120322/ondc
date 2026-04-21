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
    return s.replace('</', '<\\/')


def _he(text) -> str:
    """HTML-escape text for use as a text node (e.g. inside <pre> or table cell)."""
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
        
        Args:
            results: List of test result dictionaries
            output_file: Path to output HTML file
            test_suite_name: Name of the test suite
        """
        passed = sum(1 for r in results if r.get('passed', False))
        failed = len(results) - passed
        pass_rate = (passed / len(results) * 100) if results else 0
        
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
        
        .request-response.internal {{
            border-left: 4px solid #8b5cf6;
            opacity: 0.85;
        }}
        
        .step-accordion-header.internal-step {{
            background: #f5f3ff;
        }}
        
        .step-accordion-header.internal-step:hover {{
            background: #ede9fe;
        }}
        
        .step-accordion-header.internal-step h5 {{
            color: #7c3aed;
        }}
        
        .step-accordion-header.internal-step .step-toggle {{
            color: #7c3aed;
        }}

        .validation-checks-table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.85em;
            margin-top: 6px;
        }}
        .validation-checks-table th {{
            background: #1e293b;
            color: #94a3b8;
            text-align: left;
            padding: 6px 10px;
            font-weight: 600;
            font-size: 0.8em;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}
        .validation-checks-table td {{
            padding: 6px 10px;
            border-bottom: 1px solid #1e293b;
            color: #cbd5e1;
            word-break: break-word;
        }}
        .validation-checks-table tr.check-ok td:last-child {{
            color: #4ade80;
            font-weight: 600;
        }}
        .validation-checks-table tr.check-fail td:last-child {{
            color: #f87171;
            font-weight: 600;
        }}
        .validation-checks-table tr.check-fail {{
            background: rgba(239,68,68,0.06);
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
            white-space: pre-wrap;
            word-wrap: break-word;
        }}
        
        .error-message {{
            background: #fff5f5;
            color: #7f1d1d;
            padding: 14px 16px;
            border-radius: 8px;
            border: 1px solid #fca5a5;
            border-left: 4px solid #ef4444;
            margin: 15px 0;
        }}
        .err-summary-header {{
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 0.95em;
            margin-bottom: 10px;
            color: #b91c1c;
        }}
        .err-summary-icon {{
            font-size: 1.2em;
            line-height: 1;
        }}
        .err-summary-list {{
            list-style: none;
            margin: 0;
            padding: 0;
            display: flex;
            flex-direction: column;
            gap: 6px;
        }}
        .err-summary-list li {{
            display: flex;
            align-items: flex-start;
            gap: 8px;
            background: #fee2e2;
            border: 1px solid #fca5a5;
            border-radius: 5px;
            padding: 7px 10px;
            font-size: 0.88em;
            color: #7f1d1d;
            font-weight: 500;
        }}
        .err-summary-bullet {{
            color: #ef4444;
            font-weight: 700;
            flex-shrink: 0;
            line-height: 1.5;
        }}
        .err-summary-single {{
            margin: 0;
            font-size: 0.9em;
            font-weight: 500;
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
        
        .step-status-badge {{
            font-size: 0.72em;
            font-weight: 700;
            padding: 2px 9px;
            border-radius: 10px;
            letter-spacing: 0.5px;
            text-transform: uppercase;
            flex-shrink: 0;
        }}
        .step-status-badge.pass {{
            background: #d1fae5;
            color: #065f46;
        }}
        .step-status-badge.fail {{
            background: #fee2e2;
            color: #991b1b;
        }}
        .step-propagation-badge {{
            font-size: 0.72em;
            font-weight: 600;
            padding: 2px 9px;
            border-radius: 10px;
            background: #eff6ff;
            color: #1e40af;
            border: 1px solid #bfdbfe;
            flex-shrink: 0;
            letter-spacing: 0.3px;
        }}
        .step-error-box {{
            display: flex;
            align-items: flex-start;
            gap: 10px;
            background: #fff5f5;
            color: #7f1d1d;
            border: 1px solid #fca5a5;
            border-left: 4px solid #ef4444;
            border-radius: 6px;
            padding: 10px 14px;
            margin: 10px 0 14px 0;
            font-size: 0.88em;
        }}
        .step-error-box .err-icon {{
            font-size: 1.1em;
            line-height: 1.4;
            flex-shrink: 0;
            color: #ef4444;
        }}
        .step-error-box .err-body {{
            display: flex;
            flex-direction: column;
            gap: 2px;
        }}
        .step-error-box .err-label {{
            font-weight: 700;
            font-size: 0.8em;
            letter-spacing: 0.5px;
            text-transform: uppercase;
            color: #b91c1c;
        }}
        .step-error-box .err-message {{
            font-weight: 500;
            color: #7f1d1d;
            word-break: break-word;
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
        
        .req-resp-accordion {{
            margin: 10px 0;
            border: 1px solid #e5e7eb;
            border-radius: 6px;
            overflow: hidden;
            background: #fafafa;
        }}
        
        .req-resp-accordion-header {{
            background: #f3f4f6;
            padding: 10px 15px;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
            transition: background 0.2s;
        }}
        
        .req-resp-accordion-header:hover {{
            background: #e5e7eb;
        }}
        
        .req-resp-accordion-header h4 {{
            margin: 0;
            font-size: 1em;
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        
        .req-resp-accordion-header .rr-toggle {{
            transition: transform 0.2s;
            color: #667eea;
            font-size: 1em;
        }}
        
        .req-resp-accordion-header.collapsed .rr-toggle {{
            transform: rotate(-90deg);
        }}
        
        .req-resp-accordion-content {{
            max-height: 3000px;
            overflow: hidden;
            transition: max-height 0.3s ease-out;
            background: white;
        }}
        
        .req-resp-accordion-content.collapsed {{
            max-height: 0;
        }}
        
        .req-resp-accordion-body {{
            padding: 15px;
        }}

        /* ── Request bar: method pill ───────────────────────────────── */
        .rr-method-pill {{
            display: inline-block;
            padding: 1px 7px;
            border-radius: 4px;
            font-size: 0.72em;
            font-weight: 700;
            letter-spacing: 0.05em;
            flex-shrink: 0;
        }}
        .rr-method-pill.POST   {{ background: #dbeafe; color: #1d4ed8; }}
        .rr-method-pill.GET    {{ background: #d1fae5; color: #065f46; }}
        .rr-method-pill.PATCH  {{ background: #fef3c7; color: #92400e; }}
        .rr-method-pill.DELETE {{ background: #fee2e2; color: #991b1b; }}
        .rr-method-pill.PUT    {{ background: #e0f2fe; color: #0369a1; }}
        .rr-method-pill.OTHER  {{ background: #f3f4f6; color: #374151; }}

        /* ── Response bar: status badge ───────────────────────────── */
        .rr-status-badge {{
            padding: 2px 9px;
            border-radius: 10px;
            font-size: 0.75em;
            font-weight: 700;
            flex-shrink: 0;
        }}
        .rr-status-badge.ok  {{ background: #d1fae5; color: #065f46; }}
        .rr-status-badge.err {{ background: #fee2e2; color: #991b1b; }}

        /* ── Shared right-side group in bars ────────────────────────── */
        .rr-bar-right {{
            display: flex;
            align-items: center;
            gap: 6px;
            flex-shrink: 0;
        }}
        .rr-endpoint {{
            color: #6b7280;
            font-size: 0.82em;
            font-family: 'Courier New', monospace;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            max-width: 320px;
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
        
        /* ── Phase split: Pre-Requisites vs Gateway Workflow Steps ─────── */
        .phase-block {{
            margin: 15px 0;
        }}
        
        .phase-header-bar {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 10px 15px;
            border-radius: 6px;
            cursor: pointer;
            font-weight: 600;
            font-size: 0.9em;
            margin-bottom: 6px;
            transition: background 0.2s;
            user-select: none;
        }}
        
        .phase-header-bar.prereq {{
            background: #f8fafc;
            color: #64748b;
            border-left: 4px solid #94a3b8;
        }}
        
        .phase-header-bar.prereq:hover {{
            background: #f1f5f9;
        }}
        
        .phase-header-bar.gateway {{
            background: #eff6ff;
            color: #1d4ed8;
            border-left: 4px solid #3b82f6;
        }}
        
        .phase-header-bar.gateway:hover {{
            background: #dbeafe;
        }}
        
        .phase-header-bar .phase-count {{
            background: rgba(0,0,0,0.1);
            padding: 2px 10px;
            border-radius: 12px;
            font-size: 0.8em;
            font-weight: normal;
        }}
        
        .phase-header-bar .phase-toggle {{
            transition: transform 0.2s;
            font-size: 0.9em;
        }}
        
        .phase-header-bar.collapsed .phase-toggle {{
            transform: rotate(-90deg);
        }}
        
        .phase-content {{
            max-height: 50000px;
            overflow: hidden;
            transition: max-height 0.35s ease-out;
        }}
        
        .phase-content.collapsed {{
            max-height: 0;
        }}

        /* ── andypf-json-viewer ──────────────────────────────────── */
        andypf-json-viewer {{
            display: block;
            max-height: 450px;
            overflow: auto;
            border-radius: 6px;
            font-size: 0.88em;
        }}

        /* ── Header key/value table ──────────────────────────────── */
        .hdr-table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.85em;
        }}
        .hdr-table td {{
            padding: 5px 10px;
            border-bottom: 1px solid #2d3f55;
            vertical-align: top;
        }}
        .hdr-table td:first-child {{
            font-weight: 600;
            color: #94a3b8;
            white-space: nowrap;
            width: 35%;
        }}
        .hdr-table td:last-child {{
            color: #e2e8f0;
            word-break: break-all;
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
        </div>
        
        <div class="filters">
            <div class="filter-row">
                <div class="filter-group">
                    <span class="filter-label">Filter:</span>
                    <button class="filter-btn active" onclick="filterTests('all', this)">All Tests</button>
                    <button class="filter-btn" onclick="filterTests('passed', this)">✓ Passed</button>
                    <button class="filter-btn" onclick="filterTests('failed', this)">✗ Failed</button>
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
        
        function toggleReqRespAccordion(id) {
            const header = document.getElementById('rr-header-' + id);
            const content = document.getElementById('rr-content-' + id);
            
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

        function copyFromSidecar(sidecarId, btnId) {
            var sidecar = document.getElementById(sidecarId);
            var btn = document.getElementById(btnId);
            if (!sidecar) return;
            try {
                var data = JSON.parse(sidecar.textContent);
                navigator.clipboard.writeText(JSON.stringify(data, null, 2)).then(function() {
                    if (btn) {
                        var orig = btn.innerHTML;
                        btn.innerHTML = '✓ Copied!';
                        btn.classList.add('copied');
                        setTimeout(function() { btn.innerHTML = orig; btn.classList.remove('copied'); }, 2000);
                    }
                }).catch(function() {
                    if (btn) { btn.innerHTML = '✗ Failed'; setTimeout(function() { btn.innerHTML = '📋 Copy'; }, 2000); }
                });
            } catch(e) {
                navigator.clipboard.writeText(sidecar.textContent);
            }
        }
        
        function togglePhase(phaseId) {
            const header = document.getElementById('phase-header-' + phaseId);
            const content = document.getElementById('phase-content-' + phaseId);
            if (header && content) {
                header.classList.toggle('collapsed');
                content.classList.toggle('collapsed');
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
            _err_parts = [e.strip() for e in result.get('error_message', '').split(' | ') if e.strip()]
            if len(_err_parts) == 1:
                _err_body_html = f'<p class="err-summary-single">{_err_parts[0]}</p>'
            else:
                _err_items = ''.join(f'<li><span class="err-summary-bullet">&#10007;</span>{e}</li>' for e in _err_parts)
                _err_body_html = f'<ul class="err-summary-list">{_err_items}</ul>'
            html += f"""
                    <div class="detail-section">
                        <div class="error-message error-summary-box">
                            <div class="err-summary-header">
                                <span class="err-summary-icon">&#9888;</span>
                                <strong>Test Failed — {len(_err_parts)} step{'s' if len(_err_parts) != 1 else ''} with errors</strong>
                            </div>
                            {_err_body_html}
                        </div>
                    </div>
"""
        
        # ONDC Key Pair section
        ondc_key = result.get('ondc_key_info')
        if ondc_key:
            seed_b64_id = f"seedb64-{test_id}"
            private_pem_id = f"privkey-{test_id}"
            pub_key_id = f"pubkey-{test_id}"
            html += f"""
                    <div class="key-pair-section">
                        <h4>🔑 Generated ONDC Key Pair</h4>
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
                    </div>
"""
        
        # Request/Response details
        request_details = result.get('request_details', [])
        response_details = result.get('response_details', [])
        
        # If multiple requests (workflow), use accordion for each step (default collapsed)
        use_accordion = len(request_details) > 1

        # Partition steps into admin Pre-Requisites and Gateway workflow steps.
        # Admin steps (auth_type == 'admin') are registry setup calls; they are
        # grouped into a collapsed "Pre-Requisites" section so the Gateway steps
        # are immediately visible without scrolling past setup noise.
        _all_steps   = list(zip(request_details, response_details))
        # Use the 'phase' field stamped by gateway_runner (admin + registry lookup = prereq;
        # actual Gateway calls + internal steps = gateway). Fall back to auth_type check
        # for reports generated before the phase field was added.
        def _infer_phase(r):
            if 'phase' in r:
                return r['phase']
            return 'prereq' if r.get('auth_type') == 'admin' else 'gateway'
        _phase_tags  = [_infer_phase(r) for r, _ in _all_steps]
        _prereq_cnt  = _phase_tags.count('prereq')
        _gateway_cnt = _phase_tags.count('gateway')
        _pid         = test_id.replace('-', '_')
        _cur_phase   = None
        _prereq_block_idx = 0
        _gateway_block_idx = 0

        for i, (req, resp) in enumerate(zip(request_details, response_details)):
            _this_phase = _phase_tags[i]
            if _this_phase != _cur_phase:
                # Close the previous phase block before opening a new one
                if _cur_phase is not None:
                    html += """
                        </div>
                    </div>
"""
                if _this_phase == 'prereq':
                    _block_id = f"{_pid}-prereq-{_prereq_block_idx}"
                    _prereq_block_idx += 1
                    html += f"""
                    <div class="phase-block">
                        <div class="phase-header-bar prereq collapsed" id="phase-header-{_block_id}" onclick="togglePhase('{_block_id}')">
                            <span>&#128295; Pre-Requisites (Admin Setup)</span>
                            <span class="phase-count">{_prereq_cnt} steps</span>
                            <span class="phase-toggle">&#9660;</span>
                        </div>
                        <div class="phase-content collapsed" id="phase-content-{_block_id}">
"""
                else:
                    _block_id = f"{_pid}-gateway-{_gateway_block_idx}"
                    _gateway_block_idx += 1
                    html += f"""
                    <div class="phase-block">
                        <div class="phase-header-bar gateway" id="phase-header-{_block_id}" onclick="togglePhase('{_block_id}')">
                            <span>&#128309; Gateway Workflow Steps</span>
                            <span class="phase-count">{_gateway_cnt} steps</span>
                            <span class="phase-toggle">&#9660;</span>
                        </div>
                        <div class="phase-content" id="phase-content-{_block_id}">
"""
                _cur_phase = _this_phase
            step_id = f"{test_id}-step-{i}"
            step_name = req.get('step_name', f'Step {i+1}')
            is_internal = req.get('method') == 'INTERNAL'
            internal_class = ' internal-step' if is_internal else ''
            step_icon = '⚙️' if is_internal else '🔄'

            _step_passed = req.get('step_passed', None)
            _step_error = req.get('step_error', '')
            if is_internal:
                # Validation INTERNAL steps carry a real PASS/FAIL badge.
                # Documentation INTERNAL steps (step_passed=None) show no badge.
                if _step_passed is True:
                    _badge_html = '<span class="step-status-badge pass">&#10003; PASS</span>'
                elif _step_passed is False:
                    _badge_html = '<span class="step-status-badge fail">&#10007; FAIL</span>'
                else:
                    _badge_html = ''
            elif _step_passed is True:
                _badge_html = '<span class="step-status-badge pass">&#10003; PASS</span>'
            elif _step_passed is False:
                _badge_html = '<span class="step-status-badge fail">&#10007; FAIL</span>'
            else:
                _badge_html = ''

            if use_accordion:
                # Create accordion for each step (collapsed by default)
                _prop_elapsed = req.get('propagation_wait_elapsed_s')
                _prop_badge = (
                    f'<span class="step-propagation-badge">&#9202; propagation: {_prop_elapsed}s</span>'
                    if _prop_elapsed is not None else ''
                )
                html += f"""
                    <div class="step-accordion">
                        <div class="step-accordion-header collapsed{internal_class}" id="accordion-header-{step_id}" onclick="toggleStepAccordion('{step_id}')">
                            <h5>{step_icon} {step_name}</h5>
                            <span style="display:flex;align-items:center;gap:8px;">{_prop_badge}{_badge_html}<span class="step-toggle">&#9660;</span></span>
                        </div>
                        <div class="step-accordion-content collapsed" id="accordion-content-{step_id}">
                            <div class="step-accordion-body">
"""
                if _step_error:
                    html += (
                        f'<div class="step-error-box">'
                        f'<span class="err-icon">&#10007;</span>'
                        f'<div class="err-body">'
                        f'<span class="err-label">Step Failed</span>'
                        f'<span class="err-message">{_step_error}</span>'
                        f'</div></div>\n'
                    )
            else:
                # Single request - no accordion needed
                html += '<div class="detail-section">'

            # Internal steps: show validation-check table (if any) or a plain note
            if is_internal:
                _val_checks = req.get('validation_checks', [])
                if _val_checks:
                    # Build a checks table showing each assertion outcome
                    _rows = ''
                    for _c in _val_checks:
                        _row_cls = 'check-ok' if _c['ok'] else 'check-fail'
                        _icon = '&#10003;' if _c['ok'] else '&#10007;'
                        _exp_cell = _c.get('expected_label', _c.get('expect', ''))
                        _act_cell = _c.get('actual_label', _c.get('actual', ''))
                        _rows += (
                            f'<tr class="{_row_cls}">'
                            f'<td>{_c["check"]}</td>'
                            f'<td>{_exp_cell}</td>'
                            f'<td>{_act_cell}</td>'
                            f'<td>{_icon} {"PASS" if _c["ok"] else "FAIL"}</td>'
                            f'</tr>'
                        )
                    html += f"""
                                <div class="request-response internal validation-result" style="margin:12px 0;">
                                    <h5>Validation Checks</h5>
                                    <table class="validation-checks-table">
                                        <thead><tr><th>Prior Step Verified</th><th>Expected</th><th>Actual</th><th>Result</th></tr></thead>
                                        <tbody>{_rows}</tbody>
                                    </table>
                                </div>
"""
                else:
                    html += """
                                <div class="request-response internal" style="margin:12px 0;">
                                    <h5>Gateway-Internal Step</h5>
                                    <div class="code-block">This step represents Gateway-internal behaviour and does not produce an HTTP call observable by the test framework.</div>
                                </div>
"""
                if use_accordion:
                    html += """
                            </div>
                        </div>
                    </div>
"""
                else:
                    html += '</div>'
                continue

            # Request (wrapped in accordion, collapsed by default)
            req_id = f"{step_id}-req"
            _req_method   = req.get('method', 'N/A')
            _req_endpoint = _he(req.get('endpoint', 'N/A'))
            _method_css   = _req_method if _req_method in ('GET','POST','PATCH','PUT','DELETE') else 'OTHER'
            html += f"""
                        <div class="req-resp-accordion">
                            <div class="req-resp-accordion-header collapsed" id="rr-header-{req_id}" onclick="toggleReqRespAccordion('{req_id}')">
                                <h4>🔵 Request{' ' + str(i+1) if use_accordion else ''}</h4>
                                <div class="rr-bar-right">
                                    <span class="rr-method-pill {_method_css}">{_he(_req_method)}</span>
                                    <span class="rr-endpoint">{_req_endpoint}</span>
                                    <span class="rr-toggle">▼</span>
                                </div>
                            </div>
                            <div class="req-resp-accordion-content collapsed" id="rr-content-{req_id}">
                                <div class="req-resp-accordion-body">
{'                                    <div class="request-response request"><h5>Full URL</h5><div class="code-block">' + _he(req.get('url', '')) + '</div></div>' if req.get('url') else ''}
"""
            
            if req.get('headers'):
                _hdr_rows = ''.join(
                    f'<tr><td>{_he(k)}</td><td>{_he(v)}</td></tr>'
                    for k, v in req.get('headers', {}).items()
                )
                html += f"""
                                    <div class="request-response request">
                                        <h5>Headers</h5>
                                        <table class="hdr-table">{_hdr_rows}</table>
                                    </div>
"""

            if req.get('body'):
                _req_body_obj = req.get('body', {})
                _req_sc_id  = f"sc-req-body-{step_id}"
                _req_jv_id  = f"jv-req-body-{step_id}"
                _req_cp_id  = f"cp-req-body-{step_id}"
                html += f"""
                                    <div class="request-response request">
                                        <div class="code-header">
                                            <h5>Request Body</h5>
                                            <button class="copy-btn" id="{_req_cp_id}" onclick="copyFromSidecar('{_req_sc_id}','{_req_cp_id}')">📋 Copy</button>
                                        </div>
                                        <script type="application/json" id="{_req_sc_id}">{_je(_req_body_obj)}</script>
                                        <andypf-json-viewer id="{_req_jv_id}"
                                          indent="2" expanded="true" theme="default-dark"
                                          show-data-types="false" show-toolbar="true"
                                          expand-icon-type="arrow" show-copy="true"
                                          show-size="true" expand-empty="false"
                                          data="{_ae(_req_body_obj) if isinstance(_req_body_obj, (dict, list)) else _ae(str(_req_body_obj))}"></andypf-json-viewer>
                                    </div>
"""
            
            html += """
                                </div>
                            </div>
                        </div>
"""
            
            # Response (wrapped in accordion, collapsed by default)
            status_code = resp.get('status_code', 0)
            response_class = 'response' if isinstance(status_code, int) and 200 <= status_code < 300 else 'internal' if status_code == 'N/A' else 'error'
            resp_id = f"{step_id}-resp"
            # Extract ACK/NACK from response body for the status badge
            _ack_label = ''
            try:
                _ack_label = resp.get('body', {})['message']['ack']['status']
            except (KeyError, TypeError, AttributeError):
                pass
            _status_label = f"{status_code} {_ack_label}".strip() if _ack_label else str(status_code)
            _resp_badge_cls = 'ok' if response_class == 'response' else 'err'
            _resp_icon = '🟢' if response_class == 'response' else '🔴'

            html += f"""
                        <div class="req-resp-accordion">
                            <div class="req-resp-accordion-header collapsed" id="rr-header-{resp_id}" onclick="toggleReqRespAccordion('{resp_id}')">
                                <h4>{_resp_icon} Response{' ' + str(i+1) if use_accordion else ''}</h4>
                                <div class="rr-bar-right">
                                    <span class="rr-status-badge {_resp_badge_cls}">{_status_label}</span>
                                    <span class="rr-toggle">▼</span>
                                </div>
                            </div>
                            <div class="req-resp-accordion-content collapsed" id="rr-content-{resp_id}">
                                <div class="req-resp-accordion-body">
"""
            
            if resp.get('headers'):
                _resp_hdr_rows = ''.join(
                    f'<tr><td>{_he(k)}</td><td>{_he(v)}</td></tr>'
                    for k, v in resp.get('headers', {}).items()
                )
                html += f"""
                                    <div class="request-response {response_class}">
                                        <h5>Headers</h5>
                                        <table class="hdr-table">{_resp_hdr_rows}</table>
                                    </div>
"""

            if resp.get('body'):
                _resp_body_obj = resp.get('body', {})
                _resp_sc_id  = f"sc-resp-body-{step_id}"
                _resp_jv_id  = f"jv-resp-body-{step_id}"
                _resp_cp_id  = f"cp-resp-body-{step_id}"
                html += f"""
                                    <div class="request-response {response_class}">
                                        <div class="code-header">
                                            <h5>Response Body</h5>
                                            <button class="copy-btn" id="{_resp_cp_id}" onclick="copyFromSidecar('{_resp_sc_id}','{_resp_cp_id}')">📋 Copy</button>
                                        </div>
                                        <script type="application/json" id="{_resp_sc_id}">{_je(_resp_body_obj)}</script>
                                        <andypf-json-viewer id="{_resp_jv_id}"
                                          indent="2" expanded="true" theme="default-dark"
                                          show-data-types="false" show-toolbar="true"
                                          expand-icon-type="arrow" show-copy="true"
                                          show-size="true" expand-empty="false"
                                          data="{_ae(_resp_body_obj) if isinstance(_resp_body_obj, (dict, list)) else _ae(str(_resp_body_obj))}"></andypf-json-viewer>
                                    </div>
"""
            
            html += """
                                </div>
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

        # Close the last open phase block
        if _cur_phase is not None:
            html += """
                        </div>
                    </div>
"""

        html += """
                </div>
            </div>
"""
        
        return html
