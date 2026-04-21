#!/usr/bin/env python3
"""
ONDC Registry - All Lookup APIs Combined Report
================================================
Runs V1 (57), V2 (62), and V3 (90) lookup test suites in a single pass
and writes one unified timestamped HTML report:
  results/registry/generate_all_combined_<YYYYMMDD_HHMMSS>.html

Usage:
    $env:PYTHONPATH = "."; py func_test_scripts/registry/ondc_reg_all_lookup_combined_report.py
"""

import importlib.util
import json
import os
import sys
from datetime import datetime
from html import escape
from pathlib import Path
from time import perf_counter
from typing import Any, Dict, List, Optional

import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

WORKSPACE = Path(__file__).resolve().parent.parent.parent
SCRIPTS_DIR = Path(__file__).resolve().parent
RESULTS_DIR = WORKSPACE / "results" / "registry"

sys.path.insert(0, str(WORKSPACE))


# ---------------------------------------------------------------------------
# Dynamic module loader (avoids namespace conflicts between V1/V2/V3)
# ---------------------------------------------------------------------------

def _load_mod(alias: str, filename: str):
    path = SCRIPTS_DIR / filename
    spec = importlib.util.spec_from_file_location(alias, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[alias] = mod
    spec.loader.exec_module(mod)
    return mod


print("[LOAD] Importing V1 test module...")
v1 = _load_mod("v1_tests", "ondc_reg_v1_lookup_api_tests.py")

print("[LOAD] Importing V2 test module...")
v2 = _load_mod("v2_tests", "ondc_reg_v2_lookup_api_tests.py")

print("[LOAD] Importing V3 test module...")
v3 = _load_mod("v3_tests", "ondc_reg_v3_lookup_api_tests.py")

from tests.utils.ondc_auth_helper import ONDCAuthHelper  # noqa: E402 (after path setup)


# ---------------------------------------------------------------------------
# Version colour palette
# ---------------------------------------------------------------------------

VERSION_THEME = {
    "V1": {
        "suite_bg":  "rgba(245,158,11,.18)",
        "suite_fg":  "#fde68a",
        "border":    "#d97706",
        "chip_bg":   "#451a03",
        "chip_fg":   "#fcd34d",
    },
    "V2": {
        "suite_bg":  "rgba(45,212,191,.18)",
        "suite_fg":  "#99f6e4",
        "border":    "#0f766e",
        "chip_bg":   "#042f2e",
        "chip_fg":   "#99f6e4",
    },
    "V3": {
        "suite_bg":  "rgba(139,92,246,.18)",
        "suite_fg":  "#ddd6fe",
        "border":    "#7c3aed",
        "chip_bg":   "#2e1065",
        "chip_fg":   "#c4b5fd",
    },
}


def pretty_json(value: Any) -> str:
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


def version_of(suite: str) -> str:
    s = suite.upper()
    if "V3" in s:
        return "V3"
    if "V2" in s:
        return "V2"
    return "V1"


# ---------------------------------------------------------------------------
# Run V1 tests
# ---------------------------------------------------------------------------

def run_v1() -> List[Dict[str, Any]]:
    print("\n" + "=" * 60)
    print("  V1 LOOKUP TESTS")
    print("=" * 60)

    cfg = v1.load_v1_config()
    base_url = os.getenv("V1_API_BASE_URL", cfg.get("host", "https://registry-uat.kynondc.net")).rstrip("/")

    auth_helper = None
    if cfg.get("participant_id") and cfg.get("uk_id") and cfg.get("private_key_seed"):
        auth_helper = ONDCAuthHelper(
            cfg["participant_id"],
            cfg["uk_id"],
            v1.parse_private_key_seed(cfg["private_key_seed"]),
        )
        ok = v1.register_participant_runtime(cfg, auth_helper)
        print("[V1] Participant SUBSCRIBED\n" if ok else "[V1] Registration uncertain\n")

    test_cases = v1.build_test_cases(base_url)
    print(f"Running {len(test_cases)} V1 tests...")
    results = []
    for case in test_cases:
        r = v1.run_test_case(case)
        icon = "PASS" if r["status"] == "PASS" else "FAIL"
        print(f"  [{icon}] [{r['suite']}] {r['test_name']} -- HTTP {r['response_status_code']}")
        results.append(r)
    return results


# ---------------------------------------------------------------------------
# Run V2 tests
# ---------------------------------------------------------------------------

def run_v2() -> List[Dict[str, Any]]:
    print("\n" + "=" * 60)
    print("  V2 LOOKUP TESTS")
    print("=" * 60)

    tenant = os.getenv("V2_TENANT", "ondcRegistryV2Lookup")
    cfg = v2.load_v2_auth_config(
        str(WORKSPACE / "resources" / "registry" / "lookup" / "v2" / "test_lookup_v2.yml"),
        tenant,
    )
    base_url = os.getenv("V2_API_BASE_URL", cfg.get("host", "https://registry-uat.kynondc.net")).rstrip("/")
    if base_url.endswith("/lookup"):
        base_url = base_url[: -len("/lookup")]

    auth_helper = None
    if cfg.get("participant_id") and cfg.get("uk_id") and cfg.get("private_key_seed"):
        auth_helper = ONDCAuthHelper(
            cfg["participant_id"],
            cfg["uk_id"],
            v2.parse_private_key_seed(cfg["private_key_seed"]),
        )
        ok = v2.register_participant_runtime(cfg, auth_helper)
        print("[V2] Participant SUBSCRIBED\n" if ok else "[V2] Registration uncertain\n")

    test_cases = v2.build_test_cases(base_url, cfg)
    print(f"Running {len(test_cases)} V2 tests...")
    results = []
    for case in test_cases:
        r = v2.run_test_case(case, auth_helper=auth_helper)
        icon = "PASS" if r["status"] == "PASS" else "FAIL"
        print(f"  [{icon}] [{r['suite']}] {r['test_name']} -- HTTP {r['response_status_code']}")
        results.append(r)
    return results


# ---------------------------------------------------------------------------
# Run V3 tests
# ---------------------------------------------------------------------------

def run_v3() -> List[Dict[str, Any]]:
    print("\n" + "=" * 60)
    print("  V3 LOOKUP TESTS")
    print("=" * 60)

    cfg = v3.load_v3_auth_config()
    endpoint = os.getenv("V3_LOOKUP_URL", v3.FIXED_ENDPOINT)

    auth_helper = None
    if cfg.get("participant_id") and cfg.get("uk_id") and cfg.get("private_key_seed"):
        auth_helper = ONDCAuthHelper(
            cfg["participant_id"],
            cfg["uk_id"],
            v3.parse_private_key_seed(cfg["private_key_seed"]),
        )
        ok = v3.register_participant_runtime(endpoint, cfg, auth_helper)
        print("[V3] Participant SUBSCRIBED\n" if ok else "[V3] Registration uncertain\n")

    discovered = v3.discover_v3_cases()
    print(f"Running {len(discovered)} V3 tests...")
    results = []
    for case in discovered:
        r = v3.run_case(case, endpoint, cfg, auth_helper)
        icon = "PASS" if r["status"] == "PASS" else "FAIL"
        print(f"  [{icon}] [{r['suite']}] {r['test_name']} -- HTTP {r['response_status_code']}")
        results.append(r)
    return results


# ---------------------------------------------------------------------------
# Normalise result dicts so the HTML builder has a uniform shape
# ---------------------------------------------------------------------------

def normalise(r: Dict[str, Any]) -> Dict[str, Any]:
    ts = r.get("execution_timestamp", "")
    if hasattr(ts, "strftime"):
        ts = ts.strftime("%Y-%m-%d %H:%M:%S")
    return {
        "version":              version_of(r.get("suite", "")),
        "suite":                r.get("suite", ""),
        "test_name":            r.get("test_name", r.get("display_name", "")),
        "status":               r.get("status", "FAIL"),
        "response_status_code": r.get("response_status_code", "N/A"),
        "response_time_s":      r.get("response_time_s", 0.0),
        "execution_timestamp":  ts,
        "request_url":          r.get("request_url", ""),
        "request_headers":      r.get("request_headers", "{}"),
        "request_body":         r.get("request_body", "{}"),
        "response_body":        r.get("response_body", ""),
    }


# ---------------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------------

def build_combined_html(results: List[Dict[str, Any]]) -> str:
    total = len(results)
    passed = sum(1 for r in results if r["status"] == "PASS")
    failed = total - passed
    pass_rate = (passed / total * 100) if total else 0.0
    avg_rsp = (sum(float(r["response_time_s"]) for r in results) / total) if total else 0.0
    generated_at = datetime.now().strftime("%d %b %Y, %H:%M:%S")

    # per-version stats
    v_stats: Dict[str, Dict[str, int]] = {}
    for r in results:
        v = r["version"]
        v_stats.setdefault(v, {"total": 0, "passed": 0, "failed": 0})
        v_stats[v]["total"] += 1
        if r["status"] == "PASS":
            v_stats[v]["passed"] += 1
        else:
            v_stats[v]["failed"] += 1

    def ver_card(v: str, label: str, emoji: str) -> str:
        s = v_stats.get(v, {"total": 0, "passed": 0, "failed": 0})
        t = VERSION_THEME.get(v, VERSION_THEME["V1"])
        rate = f"{s['passed']/s['total']*100:.0f}%" if s["total"] else "N/A"
        return f"""
        <div class="vcard" style="border-color:{t['border']}">
            <div class="vcard-title" style="color:{t['suite_fg']}">{emoji} {label}</div>
            <div class="vcard-stats">
                <span class="vs total">{s['total']} total</span>
                <span class="vs pass">{s['passed']} pass</span>
                <span class="vs fail">{s['failed']} fail</span>
                <span class="vs rate">{rate}</span>
            </div>
        </div>"""

    ver_cards = (
        ver_card("V1", "V1 Lookup (Public)", "🟡")
        + ver_card("V2", "V2 Lookup (Auth)", "🟢")
        + ver_card("V3", "V3 Lookup (Auth+)", "🟣")
    )

    # test case cards
    cards_html = []
    for idx, item in enumerate(results):
        sc = "pass" if item["status"] == "PASS" else "fail"
        code = str(item["response_status_code"])
        sc_cls = status_code_class(code)
        ver = item["version"]
        t = VERSION_THEME.get(ver, VERSION_THEME["V1"])
        suite_slug = item["suite"].lower().replace(" ", "-")
        ver_slug = ver.lower()

        cards_html.append(f"""
        <div class="card {sc}" data-name="{escape(item['test_name']).lower()}"
             data-suite="{escape(suite_slug)}" data-version="{ver_slug}">
            <div class="card-header" onclick="toggle({idx})">
                <span class="ver-chip" style="background:{t['chip_bg']};color:{t['chip_fg']}">{ver}</span>
                <span class="suite-chip" style="background:{t['suite_bg']};color:{t['suite_fg']}">{escape(item['suite'])}</span>
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
                        <div class="col-label">Body</div>
                        <pre class="json-block">{escape(item['request_body'])}</pre>
                    </div>
                    <div class="col">
                        <div class="col-label">Headers</div>
                        <pre class="json-block">{escape(item['request_headers'])}</pre>
                    </div>
                </div>
                <div class="meta-row">
                    <div><strong>URL:</strong> {escape(item['request_url'])}</div>
                    <div><strong>Timestamp:</strong> {escape(item['execution_timestamp'])}</div>
                </div>
                <div class="section-title res-title">Response</div>
                <div class="two-col">
                    <div class="col">
                        <div class="col-label">Body</div>
                        <pre class="json-block">{escape(item['response_body'])}</pre>
                    </div>
                    <div class="col">
                        <div class="col-label">Status</div>
                        <pre class="json-block">{escape(pretty_json({'http_status': item['response_status_code'], 'time_s': item['response_time_s'], 'result': item['status']}))}</pre>
                    </div>
                </div>
            </div>
        </div>""")

    all_cards = "\n".join(cards_html)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>ONDC Registry - All Lookup APIs Combined Report</title>
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

.page {{ max-width: 1360px; margin: 0 auto; padding: 32px 20px 80px; }}

/* ── Hero ── */
.hero {{
    background: linear-gradient(135deg, #0f172a 0%, #1e1b4b 40%, #134e4a 100%);
    border: 1px solid #312e81;
    border-radius: 14px;
    padding: 36px 40px;
    margin-bottom: 28px;
    box-shadow: 0 8px 32px rgba(0,0,0,.6);
}}
.hero h1 {{ font-size: 2rem; font-weight: 900; letter-spacing: -.5px; margin-bottom: 8px; }}
.hero h1 span.v1 {{ color: #fde68a; }}
.hero h1 span.v2 {{ color: #99f6e4; }}
.hero h1 span.v3 {{ color: #ddd6fe; }}
.hero h1 span.sep {{ color: #4b5563; margin: 0 6px; }}
.hero p {{ color: #94a3b8; font-size: .9rem; }}
.hero p strong {{ color: #e2e8f0; }}

/* ── Overall summary cards ── */
.summary {{
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(160px, 1fr));
    gap: 14px;
    margin-bottom: 20px;
}}
.scard {{
    background: #161b22;
    border: 1px solid #21262d;
    border-radius: 10px;
    padding: 20px 16px;
    text-align: center;
}}
.scard .val {{ font-size: 2.2rem; font-weight: 900; line-height: 1; margin-bottom: 6px; }}
.scard .lbl {{ font-size: .7rem; text-transform: uppercase; letter-spacing: 1px; color: #64748b; }}
.scard.total  .val {{ color: #818cf8; }}
.scard.passed .val {{ color: #22c55e; }}
.scard.failed .val {{ color: #ef4444; }}
.scard.rate   .val {{ color: #38bdf8; }}
.scard.rsp    .val {{ color: #34d399; }}

/* ── Per-version cards ── */
.vcards {{
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 14px;
    margin-bottom: 28px;
}}
@media (max-width: 700px) {{ .vcards {{ grid-template-columns: 1fr; }} }}
.vcard {{
    background: #161b22;
    border: 1px solid;
    border-radius: 10px;
    padding: 18px 20px;
}}
.vcard-title {{ font-size: 1rem; font-weight: 800; margin-bottom: 10px; }}
.vcard-stats {{ display: flex; gap: 10px; flex-wrap: wrap; }}
.vs {{ font-size: .78rem; font-weight: 700; padding: 3px 10px; border-radius: 20px; }}
.vs.total {{ background: #1e293b; color: #94a3b8; }}
.vs.pass  {{ background: rgba(34,197,94,.15); color: #22c55e; }}
.vs.fail  {{ background: rgba(239,68,68,.15); color: #ef4444; }}
.vs.rate  {{ background: rgba(56,189,248,.12); color: #38bdf8; }}

/* ── Controls ── */
.controls {{
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    align-items: center;
    margin-bottom: 20px;
}}
.search {{
    flex: 0 1 300px;
    min-width: 120px;
    padding: 8px 12px;
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    color: #e2e8f0;
    font-size: .85rem;
    outline: none;
}}
.search:focus {{ border-color: #818cf8; }}
.fbtn {{
    padding: 7px 16px;
    border-radius: 8px;
    border: 1px solid #30363d;
    background: #161b22;
    color: #8b949e;
    cursor: pointer;
    font-size: .80rem;
    font-weight: 700;
    transition: all .15s;
}}
.fbtn:hover {{ border-color: #818cf8; color: #e2e8f0; }}
.fbtn.active {{ background: #312e81; border-color: #6366f1; color: #e0e7ff; }}
.fbtn.v1.active {{ background: #451a03; border-color: #d97706; color: #fde68a; }}
.fbtn.v2.active {{ background: #042f2e; border-color: #0f766e; color: #99f6e4; }}
.fbtn.v3.active {{ background: #2e1065; border-color: #7c3aed; color: #ddd6fe; }}
.fbtn.pass.active {{ background: rgba(34,197,94,.15); border-color: #22c55e; color: #22c55e; }}
.fbtn.fail.active {{ background: rgba(239,68,68,.15); border-color: #ef4444; color: #ef4444; }}
.count {{ color: #64748b; font-size: .80rem; margin-left: auto; }}

/* ── Cards ── */
.card {{
    background: #161b22;
    border: 1px solid #21262d;
    border-radius: 10px;
    margin-bottom: 10px;
    overflow: hidden;
    transition: border-color .15s, box-shadow .15s;
}}
.card:hover {{ border-color: #30363d; box-shadow: 0 4px 16px rgba(0,0,0,.4); }}
.card.pass {{ border-left: 4px solid #22c55e; }}
.card.fail {{ border-left: 4px solid #ef4444; }}

.card-header {{
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 12px 16px;
    cursor: pointer;
    user-select: none;
    flex-wrap: wrap;
}}
.card-header:hover {{ background: rgba(255,255,255,.02); }}

.ver-chip {{
    font-size: .68rem;
    font-weight: 900;
    letter-spacing: .8px;
    text-transform: uppercase;
    border-radius: 20px;
    padding: 3px 9px;
    flex-shrink: 0;
}}
.suite-chip {{
    font-size: .68rem;
    font-weight: 800;
    letter-spacing: .5px;
    text-transform: uppercase;
    border-radius: 20px;
    padding: 3px 9px;
    flex-shrink: 0;
}}
.badge {{
    display: inline-block;
    padding: 3px 9px;
    border-radius: 20px;
    font-size: .70rem;
    font-weight: 800;
    letter-spacing: .5px;
    flex-shrink: 0;
}}
.badge-pass {{ background: rgba(34,197,94,.15); color: #22c55e; }}
.badge-fail {{ background: rgba(239,68,68,.15); color: #ef4444; }}
.tc-name {{ font-weight: 600; font-size: .90rem; flex: 1; min-width: 180px; }}
.chip {{
    font-size: .72rem;
    font-weight: 700;
    padding: 3px 8px;
    border-radius: 6px;
    flex-shrink: 0;
}}
.sc-2xx {{ background: rgba(34,197,94,.1); color: #22c55e; }}
.sc-4xx {{ background: rgba(239,68,68,.1); color: #ef4444; }}
.sc-5xx {{ background: rgba(239,68,68,.1); color: #ef4444; }}
.sc-none {{ background: rgba(245,158,11,.1); color: #f59e0b; }}
.chip-time {{ background: rgba(56,189,248,.08); color: #38bdf8; }}
.chip-ts   {{ background: rgba(148,163,184,.06); color: #64748b; }}
.chevron {{ color: #4b5563; font-size: .85rem; flex-shrink: 0; transition: transform .2s; margin-left: auto; }}
.chevron.open {{ transform: rotate(90deg); }}

.card-body {{
    display: none;
    border-top: 1px solid #21262d;
    padding: 0 0 16px;
}}
.section-title {{
    font-size: .76rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 1px;
    padding: 12px 18px 6px;
}}
.req-title {{ color: #60a5fa; border-top: 1px solid #21262d; }}
.req-title:first-of-type {{ border-top: none; }}
.res-title {{ color: #34d399; border-top: 1px solid #21262d; }}

.two-col {{
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 0;
    padding: 0 10px;
}}
@media (max-width: 800px) {{ .two-col {{ grid-template-columns: 1fr; }} }}
.col {{ padding: 0 8px; }}
.col-label {{ font-size: .70rem; text-transform: uppercase; letter-spacing: .8px; color: #64748b; margin: 6px 0; }}
.meta-row {{ padding: 10px 18px 4px; color: #94a3b8; font-size: .84rem; display: grid; gap: 4px; }}

pre.json-block {{
    background: #0d1117;
    border: 1px solid #21262d;
    border-radius: 8px;
    padding: 12px;
    font-family: Consolas, monospace;
    font-size: .74rem;
    color: #c9d1d9;
    overflow-x: auto;
    overflow-y: auto;
    max-height: 380px;
    white-space: pre;
    line-height: 1.5;
    tab-size: 2;
}}
.empty {{ text-align: center; padding: 60px; color: #4b5563; }}
</style>
</head>
<body>
<div class="page">

    <div class="hero">
        <h1>ONDC Registry
            <span class="sep">|</span>
            <span class="v1">V1</span>
            <span class="sep">+</span>
            <span class="v2">V2</span>
            <span class="sep">+</span>
            <span class="v3">V3</span>
            &nbsp;Lookup APIs &mdash; Combined Report
        </h1>
        <p>
            <strong>Generated:</strong> {escape(generated_at)}
            &nbsp;&nbsp;|&nbsp;&nbsp;
            <strong>Environment:</strong> UAT Registry
            &nbsp;&nbsp;|&nbsp;&nbsp;
            <strong>Suites:</strong> V1 Functional/Negative/Boundary/Filter · V2 Functional/Negative/Boundary/Filter · V3 Functional/Negative/Boundary/Filter
        </p>
    </div>

    <!-- Overall summary -->
    <div class="summary">
        <div class="scard total"><div class="val">{total}</div><div class="lbl">Total</div></div>
        <div class="scard passed"><div class="val">{passed}</div><div class="lbl">Passed</div></div>
        <div class="scard failed"><div class="val">{failed}</div><div class="lbl">Failed</div></div>
        <div class="scard rate"><div class="val">{pass_rate:.1f}%</div><div class="lbl">Pass Rate</div></div>
        <div class="scard rsp"><div class="val">{avg_rsp:.3f}s</div><div class="lbl">Avg Response</div></div>
    </div>

    <!-- Per-version breakdown -->
    <div class="vcards">
        {ver_cards}
    </div>

    <!-- Filters -->
    <div class="controls">
        <input id="search" class="search" type="text" placeholder="Search test name or suite..."/>
        <button class="fbtn active" data-f="all">All</button>
        <button class="fbtn v1" data-f="v1">V1</button>
        <button class="fbtn v2" data-f="v2">V2</button>
        <button class="fbtn v3" data-f="v3">V3</button>
        <button class="fbtn pass" data-f="pass">Passed</button>
        <button class="fbtn fail" data-f="fail">Failed</button>
        <span class="count" id="count"></span>
    </div>

    <div id="container">
        {all_cards if all_cards else '<div class="empty">No test results.</div>'}
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
        const name    = card.dataset.name    || '';
        const suite   = card.dataset.suite   || '';
        const version = card.dataset.version || '';
        const isPass  = card.classList.contains('pass');
        const isFail  = card.classList.contains('fail');

        const versionOk = (
            activeFilter === 'all'  ||
            (activeFilter === 'v1'   && version === 'v1')   ||
            (activeFilter === 'v2'   && version === 'v2')   ||
            (activeFilter === 'v3'   && version === 'v3')   ||
            (activeFilter === 'pass' && isPass)              ||
            (activeFilter === 'fail' && isFail)
        );
        const searchOk = (name + ' ' + suite).includes(query);
        const show = versionOk && searchOk;
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
    overall_start = perf_counter()

    v1_results = run_v1()
    v2_results = run_v2()
    v3_results = run_v3()

    all_results = (
        [normalise(r) for r in v1_results]
        + [normalise(r) for r in v2_results]
        + [normalise(r) for r in v3_results]
    )

    total   = len(all_results)
    passed  = sum(1 for r in all_results if r["status"] == "PASS")
    failed  = total - passed
    elapsed = round(perf_counter() - overall_start, 1)

    html = build_combined_html(all_results)

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = RESULTS_DIR / f"generate_all_combined_{timestamp}.html"
    report_path.write_text(html, encoding="utf-8")

    print("\n" + "=" * 60)
    print("  ALL LOOKUP TESTS COMPLETE")
    print("=" * 60)
    print(f"  V1 : {sum(1 for r in v1_results if r['status']=='PASS')}/{len(v1_results)} PASS")
    print(f"  V2 : {sum(1 for r in v2_results if r['status']=='PASS')}/{len(v2_results)} PASS")
    print(f"  V3 : {sum(1 for r in v3_results if r['status']=='PASS')}/{len(v3_results)} PASS")
    print(f"  ALL: {passed}/{total} PASS  ({100*passed/total:.1f}%)  [{elapsed}s]")
    print(f"\nReport: {report_path}")


if __name__ == "__main__":
    main()
