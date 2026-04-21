"""
ONDC Gateway Confirm - Combined Test Report Generator

Parses the latest individual suite HTML reports and merges them into a single
timestamped teal-themed HTML report (same UI as V1/V2 combined):
  results/gateway/generate_gateway_confirm_combined_all_<YYYYMMDD_HHMMSS>.html

Input reports (must exist — run individual scripts first when gateway server is up):
  results/gateway/generate_gateway_confirm_functional.html
  results/gateway/generate_gateway_confirm_negative.html

To regenerate fresh results when gateway server is accessible:
  python func_test_scripts/generate_gateway_confirm_functional.py
  python func_test_scripts/generate_gateway_confirm_negative.py
  python func_test_scripts/generate_gateway_confirm_combined_all.py
"""

import json
import re
import sys
from datetime import datetime
from html import escape, unescape
from pathlib import Path
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _to_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _pretty_json(value: Any) -> str:
    if value is None:
        return "{}"
    if isinstance(value, str):
        try:
            return json.dumps(json.loads(value), indent=2, sort_keys=True)
        except (ValueError, TypeError):
            return value
    return json.dumps(value, indent=2, sort_keys=True)


def status_code_class(code: Any) -> str:
    c = str(code)
    if c.isdigit() and c.startswith("2"):
        return "sc-2xx"
    if c.isdigit() and c.startswith("4"):
        return "sc-4xx"
    if c.isdigit() and c.startswith("5"):
        return "sc-5xx"
    return "sc-none"


def _extract_first(pattern: str, text: str) -> Optional[str]:
    match = re.search(pattern, text, flags=re.IGNORECASE | re.DOTALL)
    return match.group(1).strip() if match else None


def _parse_status_details(raw: str) -> Dict[str, Any]:
    details: Dict[str, Any] = {"status_code": "N/A", "rsp_s": 0.0, "execution_timestamp": "N/A"}
    text = unescape(raw).strip()
    if not text:
        return details
    try:
        parsed = json.loads(text)
        details["status_code"] = parsed.get("status_code", "N/A")
        details["rsp_s"] = _to_float(parsed.get("rsp_s", 0.0))
        details["execution_timestamp"] = parsed.get("execution_timestamp", "N/A")
        return details
    except json.JSONDecodeError:
        pass
    code_m = re.search(r'"status_code"\s*:\s*(\d+)', text)
    time_m = re.search(r'"rsp_s"\s*:\s*([0-9.]+)', text)
    ts_m = re.search(r'"execution_timestamp"\s*:\s*"([^"]+)"', text)
    if code_m:
        details["status_code"] = int(code_m.group(1))
    if time_m:
        details["rsp_s"] = _to_float(time_m.group(1))
    if ts_m:
        details["execution_timestamp"] = ts_m.group(1)
    return details


# ---------------------------------------------------------------------------
# HTML report parser (reads test cards from individual suite reports)
# ---------------------------------------------------------------------------

def parse_report(html: str, suite_name: str) -> List[Dict[str, Any]]:
    """Extract all test card data from an existing interactive HTML report."""
    cards: List[Dict[str, Any]] = []

    card_pattern = re.compile(
        r'<div class="card\s+(pass|fail)"[^>]*>.*?'
        r'(?:<div class="tc-name">|<span class="tc-name">)(.*?)(?:</div>|</span>).*?'
        r'<span class="badge[^"]*badge-(?:pass|fail)">(PASS|FAIL)</span>.*?'
        r'<div class="card-body"[^>]*>(.*?)\s*</div>\s*</div>',
        flags=re.IGNORECASE | re.DOTALL,
    )

    for match in card_pattern.finditer(html):
        status = match.group(3).upper()
        body = match.group(4)
        test_name = unescape(match.group(2).strip())

        # Parse request body — try both label variations
        req_body = (
            _extract_first(r'col-label[^>]*>\s*(?:Body \(JSON\)|Request Body)\s*</div>\s*<pre class="json-block">(.*?)</pre>', body)
            or "{}"
        )
        req_headers = (
            _extract_first(r'col-label[^>]*>\s*(?:Headers|Request Headers)\s*</div>\s*<pre class="json-block">(.*?)</pre>', body)
            or "{}"
        )
        resp_body = (
            _extract_first(r'col-label[^>]*>\s*(?:Body \(JSON\)|Response Body)\s*</div>\s*<pre class="json-block">(.*?)</pre>', body)
            or "{}"
        )
        status_details_raw = (
            _extract_first(r'col-label[^>]*>\s*Status Details\s*</div>\s*<pre class="json-block">(.*?)</pre>', body)
            or "{}"
        )

        method = _extract_first(r'<strong>Method:</strong>\s*([^<]+)', body) or "POST"
        url = _extract_first(r'<strong>URL:</strong>\s*([^<]+)', body) or "N/A"

        details = _parse_status_details(status_details_raw)

        cards.append({
            "suite": suite_name,
            "test_name": test_name,
            "method": unescape(method),
            "request_url": unescape(url),
            "request_headers": unescape(req_headers),
            "request_body": unescape(req_body),
            "response_body": unescape(resp_body),
            "response_status_code": details["status_code"],
            "response_time_s": details["rsp_s"],
            "status": status,
            "execution_timestamp": details["execution_timestamp"],
        })

    return cards


# ---------------------------------------------------------------------------
# HTML report builder  (teal theme — same as V1/V2 combined)
# ---------------------------------------------------------------------------

def build_html_report(results: List[Dict[str, Any]]) -> str:
    total = len(results)
    passed = sum(1 for r in results if r["status"] == "PASS")
    failed = total - passed
    pass_rate = (passed / total * 100) if total else 0.0
    avg_rsp_s = sum(float(r["response_time_s"]) for r in results) / total if total else 0.0

    generated_at = datetime.now().strftime("%d %b %Y, %H:%M:%S")

    # --- test cards --------------------------------------------------------
    cards = []
    for idx, item in enumerate(results):
        sc = "pass" if item["status"] == "PASS" else "fail"
        code = str(item["response_status_code"])
        sc_cls = status_code_class(code)
        expectation = "negative" if item["suite"] == "Gateway Confirm Negative" else "positive"
        exp_label = "PASS EXPECTED" if expectation == "positive" else "FAIL EXPECTED"
        human = item["test_name"].replace("_", " ").title()
        description = (
            f"[{exp_label}] {human} Validates request construction, authentication "
            f"signing, endpoint routing, expected status behavior, and response "
            f"payload integrity for this Gateway Confirm scenario."
        )
        suite_slug = item["suite"].lower().replace(" ", "-")

        cards.append(f"""
        <div class="card {sc}" data-name="{escape(item['test_name']).lower()}" data-suite="{escape(suite_slug)}" data-expectation="{expectation}">
            <div class="card-header" onclick="toggle({idx})">
                <span class="suite-chip">{escape(item['suite'])}</span>
                <span class="badge badge-{sc}">{escape(item['status'])}</span>
                <span class="tc-name">{escape(item['test_name'])}</span>
                <span class="chip {sc_cls}">HTTP {escape(code)}</span>
                <span class="chip chip-time">{escape(str(item['response_time_s']))} s</span>
                <span class="chip chip-ts">{escape(item['execution_timestamp'])}</span>
                <span class="chevron" id="chev-{idx}">&gt;</span>
            </div>
            <div class="card-body" id="body-{idx}">
                <div class="section-title req-title">Request</div>
                <div class="two-col">
                    <div class="col">
                        <div class="col-label">Body (JSON)</div>
                        <pre class="json-block">{escape(item['request_body'])}</pre>
                    </div>
                    <div class="col">
                        <div class="col-label">Headers</div>
                        <pre class="json-block">{escape(item['request_headers'])}</pre>
                    </div>
                </div>
                <div class="meta-row">
                    <div><strong>Method:</strong> {escape(item['method'])}</div>
                    <div><strong>URL:</strong> {escape(item['request_url'])}</div>
                    <div><strong>Description:</strong> {escape(description)}</div>
                </div>
                <div class="section-title res-title">Response</div>
                <div class="two-col">
                    <div class="col">
                        <div class="col-label">Body (JSON)</div>
                        <pre class="json-block">{escape(item['response_body'])}</pre>
                    </div>
                    <div class="col">
                        <div class="col-label">Status Details</div>
                        <pre class="json-block">{escape(_pretty_json({'status_code': item['response_status_code'], 'rsp_s': item['response_time_s'], 'execution_timestamp': item['execution_timestamp']}))}</pre>
                    </div>
                </div>
            </div>
        </div>""")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>ONDC Gateway Confirm Combined - API Test Report</title>
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
    background: linear-gradient(135deg, #134e4a 0%, #0f766e 50%, #0ea5a5 100%);
    border: 1px solid #0f766e;
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
.hero h1 span {{ color: #99f6e4; }}
.hero p {{ color: #94a3b8; font-size: .9rem; }}
.hero p strong {{ color: #99f6e4; }}

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
.scard.total  .val {{ color: #0ea5a5; }}
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
    flex: 0 1 320px;
    min-width: 140px;
    padding: 8px 12px;
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    color: #e2e8f0;
    font-size: .85rem;
    outline: none;
}}
.search:focus {{ border-color: #0ea5a5; }}
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
.fbtn:hover {{ border-color: #0ea5a5; color: #e2e8f0; }}
.fbtn.active {{ background: #0ea5a5; border-color: #0ea5a5; color: #fff; }}
.fbtn.pass.active {{ background: #22c55e; border-color: #22c55e; }}
.fbtn.fail.active {{ background: #ef4444; border-color: #ef4444; }}
.count {{ color: #64748b; font-size: .82rem; margin-left: auto; }}

.card {{
    background: #161b22;
    border: 1px solid #21262d;
    border-radius: 10px;
    margin-bottom: 12px;
    overflow: hidden;
    transition: border-color .15s, box-shadow .15s;
}}
.card:hover {{ border-color: #30363d; box-shadow: 0 4px 16px rgba(0,0,0,.4); }}
.card.pass {{ border-left: 4px solid #22c55e; }}
.card.fail {{ border-left: 4px solid #ef4444; }}

.card-header {{
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 14px 18px;
    cursor: pointer;
    user-select: none;
    flex-wrap: wrap;
}}
.card-header:hover {{ background: rgba(255,255,255,.025); }}
.tc-name {{
    font-weight: 600;
    font-size: .92rem;
    flex: 1;
    min-width: 180px;
}}
.suite-chip {{
    font-size: .7rem;
    font-weight: 800;
    letter-spacing: .6px;
    text-transform: uppercase;
    border-radius: 20px;
    padding: 3px 10px;
    background: rgba(45,212,191,.18);
    color: #99f6e4;
}}
.badge {{
    display: inline-block;
    padding: 3px 10px;
    border-radius: 20px;
    font-size: .72rem;
    font-weight: 800;
    letter-spacing: .6px;
    flex-shrink: 0;
}}
.badge-pass {{ background: rgba(34,197,94,.15); color: #22c55e; }}
.badge-fail {{ background: rgba(239,68,68,.15); color: #ef4444; }}
.chip {{
    font-size: .75rem;
    font-weight: 700;
    padding: 3px 9px;
    border-radius: 6px;
    flex-shrink: 0;
}}
.sc-2xx {{ background: rgba(34,197,94,.1); color: #22c55e; }}
.sc-4xx {{ background: rgba(239,68,68,.1); color: #ef4444; }}
.sc-5xx {{ background: rgba(239,68,68,.1); color: #ef4444; }}
.sc-none {{ background: rgba(245,158,11,.1); color: #f59e0b; }}
.chip-time {{ background: rgba(56,189,248,.08); color: #38bdf8; }}
.chip-ts {{ background: rgba(148,163,184,.06); color: #64748b; }}
.chevron {{
    color: #4b5563;
    font-size: .85rem;
    flex-shrink: 0;
    transition: transform .2s;
    margin-left: auto;
}}
.chevron.open {{ transform: rotate(90deg); }}

.card-body {{
    display: none;
    border-top: 1px solid #21262d;
    padding: 0 0 18px;
}}

.section-title {{
    font-size: .78rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 1px;
    padding: 14px 20px 8px;
}}
.req-title {{ color: #60a5fa; border-top: 1px solid #21262d; margin-top: 4px; }}
.req-title:first-of-type {{ border-top: none; margin-top: 0; }}
.res-title {{ color: #34d399; border-top: 1px solid #21262d; }}

.two-col {{
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 0;
    padding: 0 12px;
}}
@media (max-width: 800px) {{
    .two-col {{ grid-template-columns: 1fr; }}
}}
.col {{ padding: 0 8px 0; }}
.col-label {{
    font-size: .72rem;
    text-transform: uppercase;
    letter-spacing: .8px;
    color: #64748b;
    margin-bottom: 6px;
    margin-top: 6px;
}}

.meta-row {{
    padding: 12px 20px 6px;
    color: #94a3b8;
    font-size: .86rem;
    display: grid;
    gap: 6px;
}}

pre.json-block {{
    background: #0d1117;
    border: 1px solid #21262d;
    border-radius: 8px;
    padding: 14px;
    font-family: Consolas, monospace;
    font-size: .76rem;
    color: #c9d1d9;
    overflow-x: auto;
    overflow-y: auto;
    max-height: 400px;
    white-space: pre;
    line-height: 1.55;
    tab-size: 2;
}}

.empty {{ text-align: center; padding: 60px; color: #4b5563; font-size: 1rem; }}
</style>
</head>
<body>
<div class="page">
    <div class="hero">
        <h1>ONDC <span>Gateway Confirm API</span> Combined Report</h1>
        <p>
            <strong>Source:</strong> Gateway Confirm Functional, Gateway Confirm Negative
            &nbsp;|&nbsp;
            <strong>Generated:</strong> {escape(generated_at)}
        </p>
    </div>

    <div class="summary">
        <div class="scard total"><div class="val">{total}</div><div class="lbl">Total</div></div>
        <div class="scard passed"><div class="val">{passed}</div><div class="lbl">Passed</div></div>
        <div class="scard failed"><div class="val">{failed}</div><div class="lbl">Failed</div></div>
        <div class="scard rate"><div class="val">{pass_rate:.1f}%</div><div class="lbl">Pass Rate</div></div>
        <div class="scard rsp"><div class="val">{avg_rsp_s:.3f}s</div><div class="lbl">Avg Response</div></div>
    </div>

    <div class="controls">
        <input id="search" class="search" type="text" placeholder="Search test name"/>
        <button class="fbtn active" data-f="all">All</button>
        <button class="fbtn pass" data-f="pass">Passed</button>
        <button class="fbtn fail" data-f="fail">Failed</button>
        <button class="fbtn" data-f="positive">Positive</button>
        <button class="fbtn" data-f="negative">Negative</button>
        <span class="count" id="count"></span>
    </div>

    <div id="container">
        {''.join(cards) if cards else '<div class="empty">No test results available.</div>'}
    </div>
</div>

<script>
function toggle(idx) {{
    const body = document.getElementById('body-' + idx);
    const chev = document.getElementById('chev-' + idx);
    const isOpen = body.style.display === 'block';
    body.style.display = isOpen ? 'none' : 'block';
    chev.classList.toggle('open', !isOpen);
}}

let activeFilter = 'all';

function applyFilters() {{
    const query = document.getElementById('search').value.toLowerCase();
    const cards = document.querySelectorAll('.card');
    let visible = 0;

    cards.forEach(card => {{
        const name = card.dataset.name || '';
        const expectation = card.dataset.expectation || 'positive';
        const statusOk = (
            activeFilter === 'all' ||
            (activeFilter === 'pass' && card.classList.contains('pass')) ||
            (activeFilter === 'fail' && card.classList.contains('fail')) ||
            (activeFilter === 'positive' && expectation === 'positive') ||
            (activeFilter === 'negative' && expectation === 'negative')
        );
        const searchOk = name.includes(query);
        const show = statusOk && searchOk;
        card.style.display = show ? '' : 'none';
        if (show) visible += 1;
    }});

    document.getElementById('count').textContent = visible + ' / ' + cards.length + ' visible';
}}

document.querySelectorAll('.fbtn[data-f]').forEach(btn => {{
    btn.addEventListener('click', () => {{
        document.querySelectorAll('.fbtn[data-f]').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        activeFilter = btn.getAttribute('data-f');
        applyFilters();
    }});
}});

document.getElementById('search').addEventListener('input', applyFilters);
applyFilters();
</script>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    workspace = Path(__file__).resolve().parent.parent
    reports_dir = workspace / "results" / "gateway"

    source_files = [
        ("generate_gateway_confirm_functional.html", "Gateway Confirm Functional"),
        ("generate_gateway_confirm_negative.html",   "Gateway Confirm Negative"),
    ]

    all_results: List[Dict[str, Any]] = []

    for filename, suite_name in source_files:
        file_path = reports_dir / filename
        if not file_path.exists():
            print(f"  [SKIP] {filename} not found — run the individual script first.")
            continue
        html_content = file_path.read_text(encoding="utf-8")
        cards = parse_report(html_content, suite_name)
        print(f"  [OK]   {filename} -> {len(cards)} tests parsed ({suite_name})")
        all_results.extend(cards)

    if not all_results:
        print("\nNo test results found. Run the individual gateway scripts first:")
        print("  python func_test_scripts/generate_gateway_confirm_functional.py")
        print("  python func_test_scripts/generate_gateway_confirm_negative.py")
        sys.exit(1)

    for r in all_results:
        icon = "PASS" if r["status"] == "PASS" else "FAIL"
        print(f"  [{icon}] [{r['suite']}] {r['test_name']} -- HTTP {r['response_status_code']}")

    html = build_html_report(all_results)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = reports_dir / f"generate_gateway_confirm_combined_all_{timestamp}.html"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(html, encoding="utf-8")

    passed = sum(1 for r in all_results if r["status"] == "PASS")
    failed = len(all_results) - passed
    print(f"\nReport generated: {report_path}")
    print(f"Results: {passed} passed, {failed} failed out of {len(all_results)} tests")


if __name__ == "__main__":
    main()
