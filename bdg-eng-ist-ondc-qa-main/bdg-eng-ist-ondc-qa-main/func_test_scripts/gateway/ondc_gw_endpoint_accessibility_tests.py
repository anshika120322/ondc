"""
ONDC Gateway – Endpoint Accessibility Tests (Multi-Environment Comparison)
==========================================================================
Reads endpoints from a YAML config and fires each request against **UAT** and
**PreProd** using the correct HTTP method.

A test is marked **FAIL** only when the server returns 403 Forbidden; every
other response is treated as **PASS** (the endpoint is reachable).

Generates a single HTML report with side-by-side comparison of both
environments per endpoint.

Usage:
    python func_test_scripts/gateway/ondc_gw_endpoint_accessibility_tests.py
"""

import json
import time
from datetime import datetime
from html import escape
from pathlib import Path
from typing import Any, Dict, List

import requests
import yaml

WORKSPACE = Path(__file__).resolve().parent.parent.parent
CONFIG_PATH = WORKSPACE / "resources" / "gateway" / "test_endpoint_accessibility.yml"
RESULTS_DIR = WORKSPACE / "results" / "gateway"

# ── helpers ────────────────────────────────────────────────────────────────────

def load_config() -> Dict[str, Any]:
    with open(CONFIG_PATH, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def run_endpoint(base_url: str, method: str, path: str, verify_ssl: bool = True) -> Dict[str, Any]:
    url = base_url.rstrip("/") + path
    start = time.time()
    try:
        resp = requests.request(method, url, timeout=15, verify=verify_ssl, allow_redirects=False)
        elapsed = round(time.time() - start, 3)
        status_code = resp.status_code
        body = resp.text[:2000]
    except requests.RequestException as exc:
        elapsed = round(time.time() - start, 3)
        status_code = "ERR"
        body = str(exc)[:2000]

    is_forbidden = status_code == 403
    return {
        "method": method,
        "path": path,
        "url": url,
        "status_code": status_code,
        "response_time_s": elapsed,
        "response_body": body,
        "result": "FAIL" if is_forbidden else "PASS",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


# ── HTML report ────────────────────────────────────────────────────────────────

def build_comparison_report(
    rows: List[Dict[str, Any]],
    env_names: List[str],
) -> str:
    total = len(rows)
    stats: Dict[str, Dict[str, int]] = {}
    for name in env_names:
        passed = sum(1 for r in rows if r[name]["result"] == "PASS")
        stats[name] = {"total": total, "passed": passed, "failed": total - passed}

    mismatches = sum(1 for r in rows if r[env_names[0]]["result"] != r[env_names[1]]["result"])
    generated_at = datetime.now().strftime("%d %b %Y, %H:%M:%S")

    # Build table rows and detail payloads
    table_rows: List[str] = []
    details_payload: List[Dict[str, Any]] = []

    for idx, row in enumerate(rows):
        e0 = row[env_names[0]]
        e1 = row[env_names[1]]
        match = e0["result"] == e1["result"]
        both_fail = e0["result"] == "FAIL" and e1["result"] == "FAIL"

        if both_fail:
            row_class = "row-both-fail"
        elif not match:
            row_class = "row-mismatch"
        else:
            row_class = "row-match"

        def cell(r: Dict[str, Any]) -> str:
            sc = str(r["status_code"])
            res_cls = "res-pass" if r["result"] == "PASS" else "res-fail"
            if sc.startswith("2"):
                sc_cls = "sc-2xx"
            elif sc.startswith("4"):
                sc_cls = "sc-4xx"
            elif sc.startswith("5"):
                sc_cls = "sc-5xx"
            else:
                sc_cls = "sc-none"
            return (
                f'<td class="{res_cls}">{escape(r["result"])}</td>'
                f'<td class="{sc_cls}">{escape(sc)}</td>'
                f'<td class="td-time">{r["response_time_s"]}s</td>'
            )

        match_icon = "&#10003;" if match else "&#10007;"
        match_cls = "match-yes" if match else "match-no"

        table_rows.append(
            f'<tr class="{row_class}" data-idx="{idx}" data-path="{escape(row["path"]).lower()}" '
            f'data-match="{1 if match else 0}" data-e0="{e0["result"].lower()}" data-e1="{e1["result"].lower()}" '
            f'onclick="toggle({idx})">'
            f'<td class="td-method method-{row["method"].lower()}">{escape(row["method"])}</td>'
            f'<td class="td-path">{escape(row["path"])}</td>'
            f'{cell(e0)}{cell(e1)}'
            f'<td class="{match_cls}">{match_icon}</td>'
            f"</tr>"
            f'<tr class="detail-row" id="detail-{idx}"><td colspan="9">'
            f'<div class="detail-wrap" id="wrap-{idx}"></div></td></tr>'
        )

        details_payload.append({
            env_names[0]: {
                "url": e0["url"],
                "status_code": str(e0["status_code"]),
                "response_time_s": e0["response_time_s"],
                "response_body": e0["response_body"],
                "timestamp": e0["timestamp"],
            },
            env_names[1]: {
                "url": e1["url"],
                "status_code": str(e1["status_code"]),
                "response_time_s": e1["response_time_s"],
                "response_body": e1["response_body"],
                "timestamp": e1["timestamp"],
            },
        })

    details_json = json.dumps(details_payload, ensure_ascii=False).replace("</", "<\\/")
    env_json = json.dumps(env_names)

    s0 = stats[env_names[0]]
    s1 = stats[env_names[1]]

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>ONDC Gateway – Endpoint Accessibility Comparison</title>
<style>
*, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ font-family: 'Segoe UI', system-ui, Arial, sans-serif; background: #0d1117; color: #e2e8f0; line-height: 1.6; }}
.page {{ max-width: 1440px; margin: 0 auto; padding: 28px 20px 80px; }}

.hero {{ background: linear-gradient(135deg, #1e1b4b 0%, #312e81 50%, #4f46e5 100%); border: 1px solid #4338ca; border-radius: 12px; padding: 32px 36px; margin-bottom: 28px; box-shadow: 0 8px 32px rgba(0,0,0,.45); }}
.hero h1 {{ font-size: 1.7rem; font-weight: 800; }}
.hero h1 span {{ color: #a5b4fc; }}
.hero p {{ color: #94a3b8; font-size: .85rem; margin-top: 6px; }}
.hero p strong {{ color: #a5b4fc; }}
.hero .criteria {{ margin-top: 10px; color: #fbbf24; font-size: .8rem; }}

.summary-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 28px; }}
.env-card {{ background: #161b22; border: 1px solid #21262d; border-radius: 10px; padding: 22px 24px; }}
.env-card h2 {{ font-size: 1rem; font-weight: 700; margin-bottom: 14px; color: #e2e8f0; }}
.env-card h2 span {{ font-size: .75rem; color: #64748b; font-weight: 400; margin-left: 8px; }}
.env-stats {{ display: flex; gap: 24px; }}
.stat {{ text-align: center; }}
.stat .val {{ font-size: 2rem; font-weight: 900; line-height: 1; }}
.stat .lbl {{ font-size: .68rem; text-transform: uppercase; letter-spacing: .8px; color: #64748b; margin-top: 4px; }}
.val-total {{ color: #818cf8; }}
.val-pass {{ color: #22c55e; }}
.val-fail {{ color: #ef4444; }}
.val-rate {{ color: #38bdf8; }}

.mismatch-banner {{ background: #161b22; border: 1px solid #21262d; border-radius: 10px; padding: 16px 24px; margin-bottom: 24px; display: flex; align-items: center; gap: 14px; }}
.mismatch-banner .val {{ font-size: 2rem; font-weight: 900; color: #f59e0b; }}
.mismatch-banner .lbl {{ color: #94a3b8; font-size: .88rem; }}

.controls {{ display: flex; flex-wrap: wrap; gap: 10px; align-items: center; margin-bottom: 20px; }}
.search {{ flex: 1; min-width: 200px; padding: 9px 14px; background: #161b22; border: 1px solid #30363d; border-radius: 8px; color: #e2e8f0; font-size: .86rem; outline: none; }}
.search:focus {{ border-color: #818cf8; }}
.fbtn {{ padding: 7px 16px; border-radius: 8px; border: 1px solid #30363d; background: #161b22; color: #8b949e; cursor: pointer; font-size: .78rem; font-weight: 700; }}
.fbtn.active {{ background: #4f46e5; border-color: #4f46e5; color: #fff; }}
.fbtn.mismatch.active {{ background: #f59e0b; border-color: #f59e0b; color: #000; }}
.fbtn.pass.active {{ background: #22c55e; border-color: #22c55e; }}
.fbtn.fail.active {{ background: #ef4444; border-color: #ef4444; }}
.count {{ color: #64748b; font-size: .8rem; margin-left: auto; }}

table {{ width: 100%; border-collapse: collapse; font-size: .82rem; }}
thead th {{ background: #161b22; color: #64748b; font-size: .7rem; text-transform: uppercase; letter-spacing: .8px; padding: 10px 12px; text-align: left; position: sticky; top: 0; z-index: 2; border-bottom: 2px solid #21262d; }}
thead .env-group {{ text-align: center; border-bottom: 2px solid #30363d; }}
tbody tr {{ cursor: pointer; transition: background .15s; }}
tbody tr:hover {{ background: rgba(79,70,229,.06); }}
td {{ padding: 10px 12px; border-bottom: 1px solid #21262d; vertical-align: middle; }}

.td-method {{ font-weight: 800; font-size: .72rem; letter-spacing: .5px; }}
.method-get {{ color: #22c55e; }}
.method-post {{ color: #38bdf8; }}
.method-put {{ color: #f59e0b; }}
.method-patch {{ color: #a855f7; }}
.method-delete {{ color: #ef4444; }}
.td-path {{ font-weight: 600; font-family: Consolas, monospace; font-size: .8rem; }}
.td-time {{ color: #64748b; }}

.res-pass {{ color: #22c55e; font-weight: 700; }}
.res-fail {{ color: #ef4444; font-weight: 700; }}
.sc-2xx {{ color: #22c55e; }}
.sc-4xx {{ color: #ef4444; }}
.sc-5xx {{ color: #ef4444; }}
.sc-none {{ color: #f59e0b; }}

.match-yes {{ color: #22c55e; text-align: center; font-size: 1rem; }}
.match-no {{ color: #f59e0b; text-align: center; font-size: 1rem; font-weight: 700; }}

.row-mismatch {{ background: rgba(245,158,11,.06); border-left: 3px solid #f59e0b; }}
.row-both-fail {{ background: rgba(239,68,68,.06); border-left: 3px solid #ef4444; }}
.row-match {{ border-left: 3px solid transparent; }}

.detail-row {{ display: none; }}
.detail-row.open {{ display: table-row; }}
.detail-wrap {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; padding: 16px 8px; }}
.detail-env {{ background: #0d1117; border: 1px solid #21262d; border-radius: 8px; padding: 14px; }}
.detail-env h3 {{ font-size: .78rem; font-weight: 700; text-transform: uppercase; letter-spacing: .6px; color: #64748b; margin-bottom: 10px; }}
.detail-env .meta {{ font-size: .8rem; color: #94a3b8; margin-bottom: 8px; }}
.detail-env .meta strong {{ color: #e2e8f0; }}
pre.resp {{ background: #161b22; border: 1px solid #21262d; border-radius: 6px; padding: 12px; font-family: Consolas, monospace; font-size: .74rem; color: #c9d1d9; overflow: auto; max-height: 260px; white-space: pre-wrap; line-height: 1.5; }}

@media (max-width: 900px) {{
    .summary-grid {{ grid-template-columns: 1fr; }}
    .detail-wrap {{ grid-template-columns: 1fr; }}
}}
</style>
</head>
<body>
<div class="page">
    <div class="hero">
        <h1>ONDC Gateway – <span>Endpoint Accessibility</span> Comparison</h1>
        <p><strong>Environments:</strong> {escape(env_names[0])} vs {escape(env_names[1])} &nbsp;|&nbsp; <strong>Generated:</strong> {generated_at} &nbsp;|&nbsp; <strong>Endpoints:</strong> {total}</p>
        <div class="criteria">FAIL = 403 Forbidden (endpoint is blocked) &nbsp;|&nbsp; PASS = any other response (endpoint is reachable)</div>
    </div>

    <div class="summary-grid">
        <div class="env-card">
            <h2>{escape(env_names[0]).upper()} <span>{escape(rows[0][env_names[0]]["url"].split("/")[2]) if rows else ""}</span></h2>
            <div class="env-stats">
                <div class="stat"><div class="val val-total">{s0['total']}</div><div class="lbl">Total</div></div>
                <div class="stat"><div class="val val-pass">{s0['passed']}</div><div class="lbl">Passed</div></div>
                <div class="stat"><div class="val val-fail">{s0['failed']}</div><div class="lbl">Failed</div></div>
                <div class="stat"><div class="val val-rate">{s0['passed']/s0['total']*100:.0f}%</div><div class="lbl">Pass Rate</div></div>
            </div>
        </div>
        <div class="env-card">
            <h2>{escape(env_names[1]).upper()} <span>{escape(rows[0][env_names[1]]["url"].split("/")[2]) if rows else ""}</span></h2>
            <div class="env-stats">
                <div class="stat"><div class="val val-total">{s1['total']}</div><div class="lbl">Total</div></div>
                <div class="stat"><div class="val val-pass">{s1['passed']}</div><div class="lbl">Passed</div></div>
                <div class="stat"><div class="val val-fail">{s1['failed']}</div><div class="lbl">Failed</div></div>
                <div class="stat"><div class="val val-rate">{s1['passed']/s1['total']*100:.0f}%</div><div class="lbl">Pass Rate</div></div>
            </div>
        </div>
    </div>

    <div class="mismatch-banner">
        <div class="val">{mismatches}</div>
        <div class="lbl">endpoint{"s" if mismatches != 1 else ""} with <strong>different results</strong> between environments</div>
    </div>

    <div class="controls">
        <input id="search" class="search" type="text" placeholder="Search endpoint path …"/>
        <button class="fbtn active" data-f="all">All</button>
        <button class="fbtn mismatch" data-f="mismatch">Mismatches</button>
        <button class="fbtn pass" data-f="both-pass">Both Passed</button>
        <button class="fbtn fail" data-f="both-fail">Both Failed</button>
        <span class="count" id="count"></span>
    </div>

    <table>
        <thead>
            <tr>
                <th rowspan="2">Method</th>
                <th rowspan="2">Path</th>
                <th colspan="3" class="env-group" style="color:#818cf8;">{escape(env_names[0]).upper()}</th>
                <th colspan="3" class="env-group" style="color:#38bdf8;">{escape(env_names[1]).upper()}</th>
                <th rowspan="2">Match</th>
            </tr>
            <tr>
                <th>Result</th><th>HTTP</th><th>Time</th>
                <th>Result</th><th>HTTP</th><th>Time</th>
            </tr>
        </thead>
        <tbody id="tbody">
            {''.join(table_rows)}
        </tbody>
    </table>
</div>

<script id="details-data" type="application/json">{details_json}</script>
<script id="env-names" type="application/json">{env_json}</script>
<script>
const DETAILS = JSON.parse(document.getElementById('details-data').textContent);
const ENVS = JSON.parse(document.getElementById('env-names').textContent);

function esc(v) {{
    return String(v ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}}

function renderDetail(idx) {{
    const d = DETAILS[idx];
    let html = '';
    for (const env of ENVS) {{
        const e = d[env];
        html += `<div class="detail-env">
            <h3>${{esc(env)}}</h3>
            <div class="meta"><strong>URL:</strong> ${{esc(e.url)}}</div>
            <div class="meta"><strong>Status:</strong> ${{esc(e.status_code)}} &nbsp;|&nbsp; <strong>Time:</strong> ${{esc(e.response_time_s)}}s &nbsp;|&nbsp; <strong>At:</strong> ${{esc(e.timestamp)}}</div>
            <pre class="resp">${{esc(e.response_body || '(empty)')}}</pre>
        </div>`;
    }}
    return html;
}}

function toggle(idx) {{
    const row = document.getElementById('detail-' + idx);
    const wrap = document.getElementById('wrap-' + idx);
    const isOpen = row.classList.contains('open');
    if (!isOpen && !wrap.innerHTML) wrap.innerHTML = renderDetail(idx);
    row.classList.toggle('open', !isOpen);
}}

let activeFilter = 'all';
function applyFilters() {{
    const q = (document.getElementById('search').value || '').toLowerCase();
    const dataRows = document.querySelectorAll('tr[data-idx]');
    let vis = 0;
    dataRows.forEach(tr => {{
        const path = tr.dataset.path || '';
        const isMatch = tr.dataset.match === '1';
        const e0 = tr.dataset.e0;
        const e1 = tr.dataset.e1;
        let ok = true;
        if (activeFilter === 'mismatch') ok = !isMatch;
        else if (activeFilter === 'both-pass') ok = isMatch && e0 === 'pass';
        else if (activeFilter === 'both-fail') ok = isMatch && e0 === 'fail';
        const show = ok && path.includes(q);
        tr.style.display = show ? '' : 'none';
        const detail = document.getElementById('detail-' + tr.dataset.idx);
        if (!show && detail) detail.classList.remove('open');
        if (show) vis++;
    }});
    document.getElementById('count').textContent = vis + ' / ' + dataRows.length + ' visible';
}}

document.querySelectorAll('.fbtn[data-f]').forEach(b => {{
    b.addEventListener('click', () => {{
        document.querySelectorAll('.fbtn[data-f]').forEach(x => x.classList.remove('active'));
        b.classList.add('active');
        activeFilter = b.getAttribute('data-f');
        applyFilters();
    }});
}});
document.getElementById('search').addEventListener('input', applyFilters);
applyFilters();
</script>
</body>
</html>
"""


# ── main ───────────────────────────────────────────────────────────────────────

def main() -> None:
    cfg = load_config()
    gateway_cfg = cfg.get("ondcGateway", {})
    environments = gateway_cfg.get("environments", {})

    if not environments:
        print("ERROR: No environments defined in YAML config.")
        return

    endpoints = cfg.get("endpoints", [])
    env_names = list(environments.keys())

    print(f"Gateway Endpoint Accessibility Test — {len(endpoints)} endpoints x {len(env_names)} environments")
    for name in env_names:
        print(f"  {name}: {environments[name]['host']}")
    print("-" * 78)

    rows: List[Dict[str, Any]] = []
    for ep in endpoints:
        method = ep["method"]
        path = ep["path"]
        row: Dict[str, Any] = {"method": method, "path": path}

        for env_name in env_names:
            env_cfg = environments[env_name]
            base = env_cfg["host"]
            verify_ssl = env_cfg.get("verify_ssl", True)
            result = run_endpoint(base, method, path, verify_ssl=verify_ssl)
            row[env_name] = result

        # Console output
        tags = [f"{n}={row[n]['result']}" for n in env_names]
        codes = [f"HTTP {row[n]['status_code']}" for n in env_names]
        match_str = "OK" if row[env_names[0]]["result"] == row[env_names[1]]["result"] else "MISMATCH"
        print(f"  {method:6s}  {path:50s}  {' | '.join(tags)}  ({' | '.join(codes)})  [{match_str}]")
        rows.append(row)

    # Summary
    print("-" * 78)
    for env_name in env_names:
        passed = sum(1 for r in rows if r[env_name]["result"] == "PASS")
        failed = len(rows) - passed
        print(f"  {env_name}: Passed={passed}  Failed={failed}")
    mismatches = sum(1 for r in rows if r[env_names[0]]["result"] != r[env_names[1]]["result"])
    print(f"  Mismatches: {mismatches}")

    # Report
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = RESULTS_DIR / f"gw_endpoint_accessibility_{ts}.html"
    report_path.write_text(build_comparison_report(rows, env_names), encoding="utf-8")
    print(f"\nHTML report: {report_path}")


if __name__ == "__main__":
    main()
