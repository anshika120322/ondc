import json
import os
import re
from datetime import datetime
from html import escape, unescape
from pathlib import Path
from typing import Any, Dict, List, Optional

REPORT_FILES = [
    "generate_gateway_confirm_functional.html",
    "generate_gateway_confirm_negative.html",
]


def pretty_json(value: Any) -> str:
    if value is None:
        return "{}"
    if isinstance(value, str):
        return value
    return json.dumps(value, indent=2, sort_keys=True)


def to_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def extract_first(pattern: str, text: str) -> Optional[str]:
    match = re.search(pattern, text, flags=re.IGNORECASE | re.DOTALL)
    return match.group(1).strip() if match else None


def parse_status_details_block(status_details: str) -> Dict[str, Any]:
    details: Dict[str, Any] = {
        "status_code": "N/A",
        "rsp_s": 0.0,
        "execution_timestamp": "N/A",
    }
    raw = unescape(status_details).strip()
    if not raw:
        return details

    try:
        parsed = json.loads(raw)
        details["status_code"] = parsed.get("status_code", "N/A")
        details["rsp_s"] = to_float(parsed.get("rsp_s", 0.0), 0.0)
        details["execution_timestamp"] = parsed.get("execution_timestamp", "N/A")
        return details
    except json.JSONDecodeError:
        pass

    code_match = re.search(r'"status_code"\s*:\s*(\d+)', raw)
    time_match = re.search(r'"rsp_s"\s*:\s*([0-9.]+)', raw)
    ts_match = re.search(r'"execution_timestamp"\s*:\s*"([^"]+)"', raw)

    if code_match:
        details["status_code"] = int(code_match.group(1))
    if time_match:
        details["rsp_s"] = to_float(time_match.group(1), 0.0)
    if ts_match:
        details["execution_timestamp"] = ts_match.group(1)

    return details


def parse_interactive_report(html: str, suite_name: str) -> List[Dict[str, Any]]:
    cards: List[Dict[str, Any]] = []

    card_pattern = re.compile(
        r'<div class="card\s+(pass|fail)"[^>]*>\s*<div class="card-header"[^>]*>.*?<div class="tc-name">(.*?)</div>.*?<span class="badge\s+badge-(?:pass|fail)">(PASS|FAIL)</span>.*?<div class="card-body"[^>]*>(.*?)</div>\s*</div>\s*</div>',
        flags=re.IGNORECASE | re.DOTALL,
    )

    for match in card_pattern.finditer(html):
        status_class = match.group(1).upper()
        test_name = unescape(match.group(2).strip())
        status = match.group(3).upper() if match.group(3) else status_class
        body = match.group(4)

        request_body = extract_first(
            r'<div class="col-label">\s*Request Body\s*</div>\s*<pre class="json-block">(.*?)</pre>',
            body,
        ) or "{}"
        request_headers = extract_first(
            r'<div class="col-label">\s*Request Headers\s*</div>\s*<pre class="json-block">(.*?)</pre>',
            body,
        ) or "{}"
        response_body = extract_first(
            r'<div class="col-label">\s*Response Body\s*</div>\s*<pre class="json-block">(.*?)</pre>',
            body,
        ) or "{}"
        status_details_raw = extract_first(
            r'<div class="col-label">\s*Status Details\s*</div>\s*<pre class="json-block">(.*?)</pre>',
            body,
        ) or "{}"

        method = extract_first(r'<strong>Method:</strong>\s*([^<]+)</div>', body) or "POST"
        request_url = extract_first(r'<strong>URL:</strong>\s*([^<]+)</div>', body) or "N/A"

        details = parse_status_details_block(status_details_raw)

        cards.append(
            {
                "suite": suite_name,
                "test_name": test_name,
                "method": unescape(method),
                "request_url": unescape(request_url),
                "request_headers": unescape(request_headers),
                "request_body": unescape(request_body),
                "response_body": unescape(response_body),
                "response_status_code": details["status_code"],
                "response_time_s": details["rsp_s"],
                "status": status,
                "execution_timestamp": details["execution_timestamp"],
            }
        )

    return cards


def parse_simple_boundary_report(html: str, suite_name: str) -> List[Dict[str, Any]]:
    cards: List[Dict[str, Any]] = []

    card_pattern = re.compile(
        r'<div class="card\s+(pass|fail)">\s*<h3>(.*?)\s*-\s*(PASS|FAIL)</h3>\s*<b>Request</b>\s*<pre>(.*?)</pre>\s*<b>Response</b>\s*<pre>(.*?)</pre>\s*<p>Status Code:\s*(.*?)</p>\s*<p>Response Time:\s*(.*?)\s*s</p>',
        flags=re.IGNORECASE | re.DOTALL,
    )

    report_generated = extract_first(r'<p>Generated:\s*([^<]+)</p>', html) or "N/A"

    for match in card_pattern.finditer(html):
        status = match.group(3).upper()
        status_code_raw = unescape(match.group(6).strip())

        if status_code_raw.isdigit():
            status_code: Any = int(status_code_raw)
        else:
            status_code = status_code_raw

        cards.append(
            {
                "suite": suite_name,
                "test_name": unescape(match.group(2).strip()),
                "method": "POST",
                "request_url": "http://34.100.154.102:8080/confirm",
                "request_headers": '{\n  "Accept": "application/json",\n  "Content-Type": "application/json"\n}',
                "request_body": unescape(match.group(4).strip()),
                "response_body": unescape(match.group(5).strip()),
                "response_status_code": status_code,
                "response_time_s": to_float(match.group(7).strip(), 0.0),
                "status": status,
                "execution_timestamp": report_generated,
            }
        )

    return cards


def status_code_class(code: Any) -> str:
    code_str = str(code)
    if code_str.isdigit() and code_str.startswith("2"):
        return "sc-2xx"
    if code_str.isdigit() and code_str.startswith("4"):
        return "sc-4xx"
    if code_str.isdigit() and code_str.startswith("5"):
        return "sc-5xx"
    return "sc-none"


def suite_slug(name: str) -> str:
    return name.lower().replace(" ", "-")


def build_html_report(results: List[Dict[str, Any]]) -> str:
    total = len(results)
    passed = sum(1 for r in results if r["status"] == "PASS")
    failed = total - passed
    pass_rate = (passed / total * 100) if total else 0.0
    avg_rsp = sum(to_float(r["response_time_s"], 0.0) for r in results) / total if total else 0.0

    suites = sorted({r["suite"] for r in results})
    generated_at = datetime.now().strftime("%d %b %Y, %H:%M:%S")

    cards = []
    for idx, item in enumerate(results):
        status_class = "pass" if item["status"] == "PASS" else "fail"
        code_class = status_code_class(item["response_status_code"])
        code = escape(str(item["response_status_code"]))
        suite_name = escape(item["suite"])
        suite_class = suite_slug(item["suite"])

        cards.append(
            f"""
        <div class="card {status_class}" data-name="{escape(item['test_name']).lower()}" data-suite="{suite_class}">
            <div class="card-header" onclick="toggle({idx})">
                <span class="suite-chip">{suite_name}</span>
                <span class="badge badge-{status_class}">{escape(item['status'])}</span>
                <span class="tc-name">{escape(item['test_name'])}</span>
                <span class="chip {code_class}">HTTP {code}</span>
                <span class="chip chip-time">{escape(str(item['response_time_s']))} s</span>
                <span class="chip chip-ts">{escape(item['execution_timestamp'])}</span>
                <span class="chevron" id="chev-{idx}">></span>
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
                </div>

                <div class="section-title res-title">Response</div>
                <div class="two-col">
                    <div class="col">
                        <div class="col-label">Body (JSON)</div>
                        <pre class="json-block">{escape(item['response_body'])}</pre>
                    </div>
                    <div class="col">
                        <div class="col-label">Status Details</div>
                        <pre class="json-block">{escape(pretty_json({'status_code': item['response_status_code'], 'rsp_s': item['response_time_s'], 'execution_timestamp': item['execution_timestamp']}))}</pre>
                    </div>
                </div>
            </div>
        </div>
        """
        )

    suite_buttons = ['<button class="fbtn suite active" data-suite="all">All Suites</button>']
    for suite in suites:
        suite_buttons.append(
            f'<button class="fbtn suite" data-suite="{suite_slug(suite)}">{escape(suite)}</button>'
        )

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
.fbtn:hover {{ border-color: #818cf8; color: #e2e8f0; }}
.fbtn.active {{ background: #818cf8; border-color: #818cf8; color: #fff; }}
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
    background: rgba(129,140,248,.18);
    color: #c7d2fe;
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
            <strong>Generated:</strong> {generated_at}
            &nbsp;|&nbsp;
            <strong>Reference Style:</strong> Gateway Confirm Interactive Report
        </p>
    </div>

    <div class="summary">
        <div class="scard total"><div class="val">{total}</div><div class="lbl">Total</div></div>
        <div class="scard passed"><div class="val">{passed}</div><div class="lbl">Passed</div></div>
        <div class="scard failed"><div class="val">{failed}</div><div class="lbl">Failed</div></div>
        <div class="scard rate"><div class="val">{pass_rate:.1f}%</div><div class="lbl">Pass Rate</div></div>
        <div class="scard rsp"><div class="val">{avg_rsp:.3f}s</div><div class="lbl">Avg Response</div></div>
    </div>

    <div class="controls">
        <input id="search" class="search" type="text" placeholder="Search test name"/>
        <button class="fbtn active" data-f="all">All</button>
        <button class="fbtn pass" data-f="pass">Passed</button>
        <button class="fbtn fail" data-f="fail">Failed</button>
        {''.join(suite_buttons)}
        <span class="count" id="count"></span>
    </div>

    <div id="container">
        {''.join(cards) if cards else '<div class="empty">No Gateway Confirm cards found</div>'}
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
let activeSuite = 'all';

function applyFilters() {{
    const query = document.getElementById('search').value.toLowerCase();
    const cards = document.querySelectorAll('.card');
    let visible = 0;

    cards.forEach(card => {{
        const name = card.dataset.name || '';
        const suite = card.dataset.suite || '';
        const statusOk = activeFilter === 'all' || card.classList.contains(activeFilter);
        const suiteOk = activeSuite === 'all' || suite === activeSuite;
        const searchOk = name.includes(query);
        const show = statusOk && suiteOk && searchOk;
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

document.querySelectorAll('.fbtn[data-suite]').forEach(btn => {{
    btn.addEventListener('click', () => {{
        document.querySelectorAll('.fbtn[data-suite]').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        activeSuite = btn.getAttribute('data-suite');
        applyFilters();
    }});
}});

document.getElementById('search').addEventListener('input', applyFilters);
applyFilters();
</script>
</body>
</html>
"""


def main() -> None:
    workspace = Path(__file__).resolve().parent.parent
    reports_dir = workspace / "results" / "gateway"

    all_results: List[Dict[str, Any]] = []

    for report_name in REPORT_FILES:
        file_path = reports_dir / report_name
        if not file_path.exists():
            print(f"Skipping missing report: {report_name}")
            continue

        suite_name = report_name.replace("generate_", "").replace(".html", "").replace("_", " ").title()
        html = file_path.read_text(encoding="utf-8")

        parsed = parse_interactive_report(html, suite_name)
        if not parsed:
            parsed = parse_simple_boundary_report(html, suite_name)

        if not parsed:
            print(f"No cards parsed from: {report_name}")
            continue

        all_results.extend(parsed)

    output_html = build_html_report(all_results)
    output_path = reports_dir / "generate_gateway_confirm_combined.html"
    output_path.write_text(output_html, encoding="utf-8")
    print(f"Combined report generated: {output_path}")


if __name__ == "__main__":
    main()
