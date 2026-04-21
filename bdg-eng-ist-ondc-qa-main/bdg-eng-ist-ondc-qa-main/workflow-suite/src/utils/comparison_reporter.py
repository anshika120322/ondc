"""
Comparison Report Generator

Generates a self-contained HTML report comparing test results across
multiple base URLs / environments.

Expected input structure
------------------------
comparison_data = {
    "generated_at": "<ISO timestamp>",
    "categories": ["admin", "v3", ...],
    "urls": [
        {"label": "Local",   "url": "http://localhost:8080"},
        {"label": "Staging", "url": "http://34.14.152.92"},
    ],
    "results": {
        "Local":   {"admin": [test_result_dict, ...], "v3": [...]},
        "Staging": {"admin": [test_result_dict, ...], "v3": [...]},
    }
}
"""

import json
from typing import Dict, List, Any
from datetime import datetime


# Palette used for coloring each URL column (cycles if > 8 URLs)
_URL_COLORS = [
    ("#3b82f6", "#dbeafe"),   # blue
    ("#10b981", "#d1fae5"),   # green
    ("#f59e0b", "#fef3c7"),   # amber
    ("#8b5cf6", "#ede9fe"),   # violet
    ("#ef4444", "#fee2e2"),   # red
    ("#06b6d4", "#cffafe"),   # cyan
    ("#ec4899", "#fce7f3"),   # pink
    ("#84cc16", "#ecfccb"),   # lime
]


class ComparisonReporter:
    """Generate an HTML comparison report across multiple environments."""

    @staticmethod
    def generate_report(comparison_data: Dict, output_file: str) -> None:
        """
        Write a self-contained HTML comparison report.

        Args:
            comparison_data: Structured dict (see module docstring).
            output_file: Absolute or relative path for the output .html file.
        """
        urls: List[Dict] = comparison_data.get("urls", [])
        categories: List[str] = comparison_data.get("categories", [])
        results: Dict[str, Dict[str, List]] = comparison_data.get("results", {})
        generated_at: str = comparison_data.get(
            "generated_at", datetime.now().isoformat()
        )
        shared_data: bool = comparison_data.get("shared_data", False)
        primary_label: str = comparison_data.get("primary_label", "")

        # ── Pre-compute stats ────────────────────────────────────────────
        # per-URL summary  { label: {total, passed, failed, avg_ms} }
        url_summaries: Dict[str, Dict] = {}
        for u in urls:
            label = u["label"]
            all_res: List[Dict] = []
            for cat in categories:
                all_res.extend(results.get(label, {}).get(cat, []))
            total = len(all_res)
            passed = sum(1 for r in all_res if r.get("passed", False))
            failed = total - passed
            times = [r.get("execution_time_ms", 0) for r in all_res]
            avg_ms = int(sum(times) / len(times)) if times else 0
            url_summaries[label] = {
                "total": total,
                "passed": passed,
                "failed": failed,
                "pass_rate": round(passed / total * 100, 1) if total else 0.0,
                "avg_ms": avg_ms,
            }

        # ordered list of (test_id, test_name) pairs per category
        # built from whichever URL ran that category first
        cat_tests: Dict[str, List[Dict]] = {}
        for cat in categories:
            seen_ids: set = set()
            tests_for_cat: List[Dict] = []
            for u in urls:
                label = u["label"]
                for r in results.get(label, {}).get(cat, []):
                    tid = r.get("test_id", "")
                    if tid and tid not in seen_ids:
                        seen_ids.add(tid)
                        tests_for_cat.append(
                            {"id": tid, "name": r.get("name", tid)}
                        )
            cat_tests[cat] = tests_for_cat

        # fast lookup: results[label][cat][test_id] → result dict
        result_index: Dict[str, Dict[str, Dict[str, Dict]]] = {}
        for u in urls:
            label = u["label"]
            result_index[label] = {}
            for cat in categories:
                result_index[label][cat] = {
                    r.get("test_id", ""): r
                    for r in results.get(label, {}).get(cat, [])
                }

        colors = {
            u["label"]: _URL_COLORS[i % len(_URL_COLORS)]
            for i, u in enumerate(urls)
        }

        # ── Build HTML ───────────────────────────────────────────────────
        html = ComparisonReporter._build_html(
            urls, categories, url_summaries, cat_tests,
            result_index, colors, generated_at,
            shared_data=shared_data, primary_label=primary_label
        )

        with open(output_file, "w", encoding="utf-8", errors="replace") as f:
            f.write(html)

        print(f"[OK] Comparison report saved to {output_file}")

    # ── Private helpers ───────────────────────────────────────────────────

    @staticmethod
    def _build_html(
        urls, categories, url_summaries, cat_tests,
        result_index, colors, generated_at,
        shared_data: bool = False, primary_label: str = ""
    ) -> str:
        num_urls = len(urls)
        ts = datetime.fromisoformat(generated_at).strftime("%B %d, %Y at %I:%M %p") \
            if generated_at else datetime.now().strftime("%B %d, %Y at %I:%M %p")

        # Summary cards for each URL
        summary_cards_html = ""
        for u in urls:
            label = u["label"]
            s = url_summaries[label]
            fg, bg = colors[label]
            rate_color = "#10b981" if s["pass_rate"] >= 90 else ("#f59e0b" if s["pass_rate"] >= 70 else "#ef4444")
            primary_badge = ' <span class="primary-badge">primary</span>' if (shared_data and label == primary_label) else ''
            summary_cards_html += f"""
            <div class="env-card" style="border-top: 4px solid {fg};">
                <div class="env-label" style="color:{fg};">{label}{primary_badge}</div>
                <div class="env-url">{u['url']}</div>
                <div class="env-stats">
                    <div class="stat"><span class="stat-val" style="color:#10b981">{s['passed']}</span><span class="stat-lbl">Passed</span></div>
                    <div class="stat"><span class="stat-val" style="color:#ef4444">{s['failed']}</span><span class="stat-lbl">Failed</span></div>
                    <div class="stat"><span class="stat-val" style="color:{rate_color}">{s['pass_rate']}%</span><span class="stat-lbl">Pass Rate</span></div>
                    <div class="stat"><span class="stat-val" style="color:#6366f1">{s['avg_ms']}ms</span><span class="stat-lbl">Avg Time</span></div>
                </div>
            </div>"""

        # Summary comparison table
        summary_table_rows = ""
        for u in urls:
            label = u["label"]
            s = url_summaries[label]
            fg, bg = colors[label]
            rate_color = "#10b981" if s["pass_rate"] >= 90 else ("#f59e0b" if s["pass_rate"] >= 70 else "#ef4444")
            bar_w = int(s["pass_rate"])
            summary_table_rows += f"""
                <tr>
                    <td><span class="env-badge" style="background:{bg};color:{fg};">{label}</span></td>
                    <td class="url-cell">{u['url']}</td>
                    <td class="num">{s['total']}</td>
                    <td class="num passed-num">{s['passed']}</td>
                    <td class="num failed-num">{s['failed']}</td>
                    <td>
                        <div class="bar-wrap">
                            <div class="bar-fill" style="width:{bar_w}%;background:{rate_color};"></div>
                            <span class="bar-label" style="color:{rate_color};">{s['pass_rate']}%</span>
                        </div>
                    </td>
                    <td class="num">{s['avg_ms']}ms</td>
                </tr>"""

        # Matrix sections (one per category)
        matrix_html = ""
        for cat in categories:
            tests = cat_tests.get(cat, [])
            if not tests:
                continue

            # Header row – one <th> per URL
            url_headers = "".join(
                f'<th style="background:{colors[u["label"]][1]};color:{colors[u["label"]][0]};">{u["label"]}</th>'
                for u in urls
            )

            # Data rows
            rows_html = ""
            num_diff = 0
            for t in tests:
                tid = t["id"]
                tname = t["name"].replace("→", "->")

                # Check if results differ across URLs (highlight divergence)
                statuses = [
                    result_index.get(u["label"], {}).get(cat, {}).get(tid, {}).get("passed")
                    for u in urls
                ]
                statuses_known = [s for s in statuses if s is not None]
                is_divergent = len(set(statuses_known)) > 1
                if is_divergent:
                    num_diff += 1

                row_class = "divergent" if is_divergent else ""

                cells = ""
                for u in urls:
                    label = u["label"]
                    res = result_index.get(label, {}).get(cat, {}).get(tid)
                    if res is None:
                        cells += '<td class="cell-na">—</td>'
                    elif res.get("passed"):
                        ms = res.get("execution_time_ms", 0)
                        cells += f'<td class="cell-pass" title="{ms}ms">✓<span class="ms">{ms}ms</span></td>'
                    else:
                        err = (res.get("error_message") or "failed")
                        err_escaped = err.replace('"', '&quot;').replace('<', '&lt;').replace('>', '&gt;')
                        ms = res.get("execution_time_ms", 0)
                        cells += f'<td class="cell-fail" title="{err_escaped}">✗<span class="ms">{ms}ms</span></td>'

                rows_html += f"""
                    <tr class="{row_class}" data-testid="{tid}" data-catid="{cat}">
                        <td class="test-id-cell">{tid}</td>
                        <td class="test-name-cell">{tname}</td>
                        {cells}
                        <td class="detail-cell"><button class="detail-btn" onclick="toggleDetail('{cat}_{tid}')">▼</button></td>
                    </tr>
                    <tr class="detail-row" id="detail_{cat}_{tid}" style="display:none;">
                        <td colspan="{2 + num_urls + 1}">
                            {ComparisonReporter._build_detail_row(tid, cat, urls, result_index, colors)}
                        </td>
                    </tr>"""

            diff_badge = f'<span class="diff-badge">{num_diff} divergent</span>' if num_diff else ""
            matrix_html += f"""
            <div class="matrix-section">
                <div class="matrix-title">
                    <span>{cat.upper()} — {len(tests)} tests</span>
                    {diff_badge}
                    <input class="matrix-search" type="text" placeholder="Search tests..."
                           oninput="filterMatrix(this, '{cat}')">
                </div>
                <div class="table-wrap">
                    <table class="matrix-table" id="matrix_{cat}">
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Test Name</th>
                                {url_headers}
                                <th></th>
                            </tr>
                        </thead>
                        <tbody>
                            {rows_html}
                        </tbody>
                    </table>
                </div>
            </div>"""

        # Assemble final HTML
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ONDC Registry — Environment Comparison Report</title>
{ComparisonReporter._css()}
</head>
<body>
<div class="container">

  <div class="page-header">
    <h1>⚖️ Environment Comparison Report</h1>
    <p class="gen-ts">Generated: {ts} &nbsp;·&nbsp; {len(urls)} environments &nbsp;·&nbsp; {len(categories)} categories{'&nbsp;·&nbsp;<span class="shared-data-badge">&#128279; Shared Data</span>' if shared_data else ''}</p>
  </div>

  <!-- Environment summary cards -->
  <div class="env-cards">
    {summary_cards_html}
  </div>

  <!-- Aggregated summary table -->
  <div class="section">
    <h2 class="section-title">Summary</h2>
    <div class="table-wrap">
      <table class="summary-table">
        <thead>
          <tr>
            <th>Environment</th>
            <th>URL</th>
            <th>Total</th>
            <th>Passed</th>
            <th>Failed</th>
            <th>Pass Rate</th>
            <th>Avg Time</th>
          </tr>
        </thead>
        <tbody>
          {summary_table_rows}
        </tbody>
      </table>
    </div>
  </div>

  <!-- Test matrix sections -->
  <div class="section">
    <h2 class="section-title">Test Matrix
        <span class="legend">
            <span class="leg pass">✓ Pass</span>
            <span class="leg fail">✗ Fail</span>
            <span class="leg na">— N/A</span>
            <span class="leg div">⚠ Divergent row</span>
        </span>
    </h2>
    {matrix_html}
  </div>

</div>

<!-- cURL Modal -->
<div id="curl-modal" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.65);z-index:9999;align-items:center;justify-content:center;padding:20px;" onclick="if(event.target===this)closeCurlDialog()">
  <div style="background:#1e293b;border-radius:12px;max-width:900px;width:100%;max-height:80vh;display:flex;flex-direction:column;box-shadow:0 20px 60px rgba(0,0,0,.6);">
    <div style="padding:14px 18px;border-bottom:1px solid #334155;display:flex;justify-content:space-between;align-items:center;flex-shrink:0;">
      <span style="color:#93c5fd;font-weight:700;font-family:'Courier New',monospace;font-size:.95em;">&#8250;_ cURL Command</span>
      <div style="display:flex;gap:8px;">
        <button id="curl-modal-copy-btn" onclick="copyCurlModal()" style="background:#f59e0b;color:#1e293b;border:none;padding:6px 14px;border-radius:6px;cursor:pointer;font-weight:700;font-size:.82em;transition:all .2s;">&#128203; Copy</button>
        <button onclick="closeCurlDialog()" style="background:#475569;color:white;border:none;padding:6px 14px;border-radius:6px;cursor:pointer;font-size:.82em;">&#x2715; Close</button>
      </div>
    </div>
    <pre id="curl-modal-code" style="margin:0;padding:16px 20px;color:#fde68a;font-family:'Courier New',monospace;font-size:.82em;white-space:pre-wrap;word-break:break-word;overflow-y:auto;flex:1;line-height:1.6;"></pre>
  </div>
</div>
{ComparisonReporter._js()}
</body>
</html>"""

    @staticmethod
    def _build_detail_row(tid, cat, urls, result_index, colors) -> str:
        """Build the expandable per-test detail panel showing each URL's full request/response."""
        panels = ""
        for u in urls:
            label = u["label"]
            fg, bg = colors[label]
            res = result_index.get(label, {}).get(cat, {}).get(tid)
            if res is None:
                panels += f"""
                <div class="detail-panel" style="border-left:4px solid {fg};">
                    <div class="dp-header" style="background:{bg};color:{fg};">{label} — not run</div>
                </div>"""
                continue

            passed = res.get("passed", False)
            status_icon = "✓ PASS" if passed else "✗ FAIL"
            status_color = "#10b981" if passed else "#ef4444"

            err_html = ""
            if not passed and res.get("error_message"):
                err_safe = _escape_html(str(res["error_message"]))
                err_html = f'<div class="dp-error">{err_safe}</div>'

            req_details = res.get("request_details") or []
            resp_details = res.get("response_details") or []

            # Pair up request/response entries (one per step)
            steps_html = ""
            n_steps = max(len(req_details), len(resp_details))
            for i in range(n_steps):
                req_item = req_details[i] if i < len(req_details) else {}
                resp_item = resp_details[i] if i < len(resp_details) else {}

                step_name = req_item.get("step_name") or resp_item.get("step_name") or ""
                step_label = f'<div class="dp-step-name">{_escape_html(step_name)}</div>' if step_name else ""

                # pre-compute safe element IDs for this step
                safe_lbl    = ''.join(c if c.isalnum() else '_' for c in label)
                req_blk_id  = f"blk_{safe_lbl}_{cat}_{tid}_{i}_req"
                req_chv_id  = f"chv_{safe_lbl}_{cat}_{tid}_{i}_req"
                resp_blk_id = f"blk_{safe_lbl}_{cat}_{tid}_{i}_resp"
                resp_chv_id = f"chv_{safe_lbl}_{cat}_{tid}_{i}_resp"

                # ── Request (collapsed by default) ─────────────────────
                method = req_item.get("method", "")
                req_url = req_item.get("url") or ""
                req_headers = req_item.get("headers") or {}
                req_body_raw = req_item.get("body")

                # Serialise request data for runtime cURL generation
                try:
                    req_data_attr = json.dumps(
                        {"method": method, "url": req_url,
                         "headers": req_headers, "body": req_body_raw},
                        ensure_ascii=True
                    ).replace('&', '&amp;').replace('"', '&quot;')
                except Exception:
                    req_data_attr = ""

                req_line = ""
                if method or req_url:
                    req_line = f'<div class="dp-req-line">{_escape_html(method)} {_escape_html(req_url)}</div>'

                req_headers_str = ""
                if req_headers:
                    try:
                        req_headers_str = _escape_html(
                            "\n".join(f"{k}: {v}" for k, v in sorted(req_headers.items()))
                        )
                    except Exception:
                        req_headers_str = _escape_html(str(req_headers))

                req_body_str = ""
                if req_body_raw is not None:
                    try:
                        req_body_str = _escape_html(json.dumps(req_body_raw, indent=2, ensure_ascii=True))
                    except Exception:
                        req_body_str = _escape_html(str(req_body_raw))

                req_html = f"""
                <div class="dp-block req-block">
                    <div class="dp-block-title dp-toggle-hdr" onclick="toggleBlock('{req_blk_id}', '{req_chv_id}')">
                        <span class="dp-chevron collapsed" id="{req_chv_id}">&#9660;</span>
                        Request
                        <button class="dp-curl-btn" onclick="event.stopPropagation();showCurlDialog(this)" title="Show cURL command">&#8250;_ cURL</button>
                    </div>
                    <div class="dp-block-body" id="{req_blk_id}" style="display:none" data-req="{req_data_attr}">
                        {req_line}
                        {f'''<div class="dp-sub-toggle-hdr" onclick="toggleBlock('{req_blk_id}_hdrs', '{req_chv_id}_hdrs')">
                            <span class="dp-sub-chevron collapsed" id="{req_chv_id}_hdrs">&#9660;</span> Headers
                        </div>
                        <div id="{req_blk_id}_hdrs" style="display:none">
                            <pre class="code headers-code">{req_headers_str}</pre>
                        </div>''' if req_headers_str else ''}
                        {f'<div class="dp-sub-title">Body</div><pre class="code">{req_body_str}</pre>' if req_body_str else '<div class="dp-sub-title" style="color:#94a3b8">(no body)</div>'}
                    </div>
                </div>"""

                # ── Response (expanded by default) ─────────────────────
                status_code = resp_item.get("status_code", res.get("status_code", ""))
                resp_headers = resp_item.get("headers") or {}
                resp_body_raw = resp_item.get("body")

                resp_headers_str = ""
                if resp_headers:
                    try:
                        resp_headers_str = _escape_html(
                            "\n".join(f"{k}: {v}" for k, v in sorted(resp_headers.items()))
                        )
                    except Exception:
                        resp_headers_str = _escape_html(str(resp_headers))

                resp_body_str = ""
                if resp_body_raw is not None:
                    try:
                        resp_body_str = _escape_html(json.dumps(resp_body_raw, indent=2, ensure_ascii=True))
                    except Exception:
                        resp_body_str = _escape_html(str(resp_body_raw))

                sc_color = "#10b981" if str(status_code).startswith("2") else "#ef4444"
                sc_badge = f'<span class="dp-status-badge" style="background:{sc_color}">{status_code}</span>' if status_code else ""

                resp_html = f"""
                <div class="dp-block resp-block">
                    <div class="dp-block-title dp-toggle-hdr" onclick="toggleBlock('{resp_blk_id}', '{resp_chv_id}')">
                        <span class="dp-chevron" id="{resp_chv_id}">&#9660;</span>
                        Response {sc_badge}
                    </div>
                    <div class="dp-block-body" id="{resp_blk_id}">
                        {f'''<div class="dp-sub-toggle-hdr" onclick="toggleBlock('{resp_blk_id}_hdrs', '{resp_chv_id}_hdrs')">
                            <span class="dp-sub-chevron collapsed" id="{resp_chv_id}_hdrs">&#9660;</span> Headers
                        </div>
                        <div id="{resp_blk_id}_hdrs" style="display:none">
                            <pre class="code headers-code">{resp_headers_str}</pre>
                        </div>''' if resp_headers_str else ''}
                        {f'<div class="dp-sub-title">Body</div><pre class="code">{resp_body_str}</pre>' if resp_body_str else '<div class="dp-sub-title" style="color:#94a3b8">(no body)</div>'}
                    </div>
                </div>"""

                steps_html += f"""
                <div class="dp-step">
                    {step_label}
                    {req_html}
                    {resp_html}
                </div>"""
                if i < n_steps - 1:
                    steps_html += '<div class="dp-step-divider"></div>'

            panels += f"""
                <div class="detail-panel" style="border-left:4px solid {fg};">
                    <div class="dp-header" style="background:{bg};color:{fg};">
                        {label} &nbsp;
                        <span style="color:{status_color};font-weight:700;">{status_icon}</span>
                        &nbsp; {res.get('execution_time_ms', 0)}ms
                    </div>
                    {err_html}
                    {steps_html}
                </div>"""

        return f'<div class="detail-panels">{panels}</div>'

    @staticmethod
    def _css() -> str:
        return """<style>
*{box-sizing:border-box;margin:0;padding:0;}
body{font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;background:#f1f5f9;color:#1e293b;line-height:1.5;}
.container{max-width:1600px;margin:0 auto;padding:24px;}
.page-header{background:linear-gradient(135deg,#1e293b 0%,#334155 100%);color:white;padding:28px 30px;border-radius:12px;margin-bottom:24px;box-shadow:0 4px 12px rgba(0,0,0,.15);}
.page-header h1{font-size:1.8em;margin-bottom:6px;}
.gen-ts{color:#94a3b8;font-size:.9em;}
.shared-data-badge{display:inline-block;font-size:.85em;font-weight:600;background:#ede9fe;color:#6d28d9;padding:1px 8px;border-radius:4px;}

/* Env cards */
.env-cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:16px;margin-bottom:24px;}
.env-card{background:white;border-radius:10px;padding:18px;box-shadow:0 2px 6px rgba(0,0,0,.08);}
.primary-badge{display:inline-block;font-size:.6em;font-weight:700;background:#6366f1;color:white;padding:1px 6px;border-radius:4px;vertical-align:middle;margin-left:6px;letter-spacing:.03em;}
.env-label{font-size:1.1em;font-weight:700;margin-bottom:4px;}
.env-url{font-size:.8em;color:#64748b;margin-bottom:12px;word-break:break-all;}
.env-stats{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;}
.stat{text-align:center;}
.stat-val{display:block;font-size:1.3em;font-weight:700;}
.stat-lbl{font-size:.75em;color:#94a3b8;text-transform:uppercase;}

/* Sections */
.section{background:white;border-radius:10px;padding:20px 24px;margin-bottom:24px;box-shadow:0 2px 6px rgba(0,0,0,.08);}
.section-title{font-size:1.2em;font-weight:700;color:#1e293b;margin-bottom:16px;display:flex;align-items:center;gap:12px;flex-wrap:wrap;}
.legend{font-size:.8em;font-weight:400;display:flex;gap:10px;align-items:center;margin-left:auto;}
.leg{padding:3px 8px;border-radius:4px;}
.leg.pass{background:#d1fae5;color:#065f46;}
.leg.fail{background:#fee2e2;color:#991b1b;}
.leg.na{background:#f1f5f9;color:#64748b;}
.leg.div{background:#fef9c3;color:#92400e;}

/* Summary table */
.table-wrap{overflow-x:auto;}
.summary-table{width:100%;border-collapse:collapse;font-size:.9em;}
.summary-table th,.summary-table td{padding:10px 14px;text-align:left;border-bottom:1px solid #e2e8f0;}
.summary-table th{background:#f8fafc;font-weight:600;color:#475569;}
.summary-table tr:hover td{background:#f8fafc;}
.env-badge{padding:3px 10px;border-radius:12px;font-size:.85em;font-weight:600;}
.url-cell{font-size:.8em;color:#64748b;max-width:240px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.num{text-align:right;font-variant-numeric:tabular-nums;}
.passed-num{color:#10b981;font-weight:600;}
.failed-num{color:#ef4444;font-weight:600;}
.bar-wrap{position:relative;height:20px;background:#f1f5f9;border-radius:10px;overflow:hidden;min-width:120px;}
.bar-fill{height:100%;border-radius:10px;transition:width .3s;}
.bar-label{position:absolute;right:8px;top:2px;font-size:.8em;font-weight:700;}

/* Matrix */
.matrix-section{margin-bottom:24px;}
.matrix-title{display:flex;align-items:center;gap:12px;padding:12px 0 8px;font-weight:700;color:#334155;font-size:1em;flex-wrap:wrap;}
.diff-badge{background:#fef9c3;color:#92400e;border:1px solid #fde68a;padding:2px 10px;border-radius:12px;font-size:.8em;font-weight:600;}
.matrix-search{margin-left:auto;padding:6px 12px;border:1px solid #e2e8f0;border-radius:6px;font-size:.85em;min-width:180px;}
.matrix-search:focus{outline:none;border-color:#6366f1;}
.matrix-table{width:100%;border-collapse:collapse;font-size:.85em;}
.matrix-table th{background:#f8fafc;padding:8px 12px;text-align:center;border:1px solid #e2e8f0;font-weight:600;white-space:nowrap;}
.matrix-table td{padding:7px 10px;border:1px solid #e2e8f0;vertical-align:middle;}
.test-id-cell{font-family:monospace;font-size:.9em;white-space:nowrap;color:#6366f1;font-weight:600;}
.test-name-cell{max-width:340px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.cell-pass{text-align:center;background:#d1fae5;color:#065f46;font-weight:700;cursor:default;}
.cell-fail{text-align:center;background:#fee2e2;color:#991b1b;font-weight:700;cursor:default;}
.cell-na{text-align:center;color:#94a3b8;background:#f8fafc;cursor:default;}
.ms{font-size:.75em;color:inherit;opacity:.75;display:block;}
.divergent>td{background:#fffbeb !important;}
.hidden-row{display:none;}
.detail-cell{text-align:center;width:36px;}
.detail-btn{background:none;border:none;cursor:pointer;color:#6366f1;font-size:1.1em;transition:transform .2s;}
.detail-btn.open{transform:rotate(180deg);}

/* Detail panels */
.detail-row td{padding:0;background:#f8fafc;}
.detail-panels{display:flex;flex-wrap:wrap;gap:0;}
.detail-panel{flex:1 1 320px;border-top:1px solid #e2e8f0;padding:0;min-width:0;}
.dp-header{padding:8px 14px;font-weight:600;font-size:.9em;display:flex;align-items:center;gap:6px;flex-wrap:wrap;}
.dp-error{margin:8px 14px;padding:8px 12px;background:#fee2e2;color:#991b1b;border-radius:4px;font-size:.85em;border-left:3px solid #ef4444;}
.dp-step{padding:8px 14px 0;}
.dp-step-name{font-size:.8em;font-weight:700;color:#6366f1;text-transform:uppercase;margin-bottom:6px;letter-spacing:.04em;}
.dp-step-divider{margin:10px 14px;border-top:2px dashed #e2e8f0;}
.dp-block{margin-bottom:8px;}
.dp-block-title{font-size:.78em;font-weight:700;text-transform:uppercase;margin-bottom:5px;display:flex;align-items:center;gap:6px;}
.dp-toggle-hdr{cursor:pointer;user-select:none;padding:5px 8px;border-radius:4px;transition:background .15s;}
.dp-toggle-hdr:hover{background:rgba(0,0,0,.06);}
.dp-chevron{font-size:.7em;transition:transform .2s;display:inline-block;}
.dp-chevron.collapsed{transform:rotate(-90deg);}
.dp-block-body{margin-top:4px;}
.dp-sub-title{font-size:.72em;font-weight:600;text-transform:uppercase;color:#94a3b8;margin:5px 0 3px;letter-spacing:.03em;}
.dp-sub-toggle-hdr{font-size:.72em;font-weight:600;text-transform:uppercase;color:#94a3b8;margin:6px 0 0;letter-spacing:.03em;cursor:pointer;user-select:none;display:flex;align-items:center;gap:4px;padding:3px 6px;border-radius:3px;transition:background .15s;}
.dp-sub-toggle-hdr:hover{background:rgba(0,0,0,.07);}
.dp-sub-chevron{font-size:.65em;display:inline-block;transition:transform .2s;}
.dp-sub-chevron.collapsed{transform:rotate(-90deg);}
.dp-req-line{font-family:'Courier New',monospace;font-size:.82em;background:#1e3a5f;color:#93c5fd;padding:6px 10px;border-radius:4px;margin-bottom:5px;word-break:break-all;}
.dp-status-badge{color:white;padding:1px 7px;border-radius:10px;font-size:.78em;font-weight:700;}
.code{background:#0f172a;color:#e2e8f0;padding:10px;border-radius:4px;font-family:'Courier New',monospace;font-size:.76em;white-space:pre-wrap;word-break:break-word;max-height:240px;overflow-y:auto;}
.headers-code{color:#a5f3fc;max-height:160px;}
.req-block .dp-block-title{color:#3b82f6;}
.resp-block .dp-block-title{color:#10b981;}
.dp-curl-btn{margin-left:auto;background:#1e3a5f;color:#93c5fd;border:1px solid #3b82f6;padding:2px 8px;border-radius:4px;cursor:pointer;font-size:.72em;font-weight:700;letter-spacing:.02em;transition:all .15s;}
.dp-curl-btn:hover{background:#3b82f6;color:white;}
</style>"""

    @staticmethod
    def _js() -> str:
        return """<script>
function toggleBlock(bodyId, chvId) {
    var body = document.getElementById(bodyId);
    var chv  = chvId ? document.getElementById(chvId) : null;
    if (!body) return;
    if (body.style.display === 'none') {
        body.style.display = '';
        if (chv) chv.classList.remove('collapsed');
    } else {
        body.style.display = 'none';
        if (chv) chv.classList.add('collapsed');
    }
}
function buildCurl(req) {
    var parts = ["curl -X " + (req.method || 'GET') + " '" + (req.url || '').replace(/'/g, "'\\''" ) + "'"];
    var hdrs = req.headers || {};
    Object.keys(hdrs).sort().forEach(function(k) {
        var v = String(hdrs[k]).replace(/'/g, "'\\''" );
        parts.push("  -H '" + k + ": " + v + "'");
    });
    if (req.body != null) {
        var b = typeof req.body === 'string' ? req.body : JSON.stringify(req.body);
        parts.push("  --data-raw '" + b.replace(/'/g, "'\\''" ) + "'");
    }
    return parts.join(" \\\n");
}
function showCurlDialog(btn) {
    // find nearest data-req among siblings / parent
    var block = btn.closest('.req-block');
    var body  = block ? block.querySelector('[data-req]') : null;
    if (!body) return;
    var raw = body.getAttribute('data-req');
    if (!raw) return;
    var req;
    try { req = JSON.parse(raw); } catch(e) { return; }
    var curl = buildCurl(req);
    document.getElementById('curl-modal-code').textContent = curl;
    var modal = document.getElementById('curl-modal');
    modal.style.display = 'flex';
}
function closeCurlDialog() {
    document.getElementById('curl-modal').style.display = 'none';
}
function copyCurlModal() {
    var code = document.getElementById('curl-modal-code');
    var btn  = document.getElementById('curl-modal-copy-btn');
    var text = code ? (code.textContent || '') : '';
    function mark() {
        if (btn) { btn.textContent = '\u2713 Copied!'; btn.classList.add('copied'); }
        setTimeout(function() { if (btn) { btn.textContent = '\ud83d\udccb Copy'; btn.classList.remove('copied'); } }, 2000);
    }
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(mark).catch(function() { _fbCopy(text); mark(); });
    } else { _fbCopy(text); mark(); }
}
function _fbCopy(text) {
    var ta = document.createElement('textarea');
    ta.value = text;
    ta.style.cssText = 'position:fixed;top:0;left:0;opacity:0';
    document.body.appendChild(ta); ta.select();
    try { document.execCommand('copy'); } catch(e) {}
    document.body.removeChild(ta);
}
function toggleDetail(key) {
    var row = document.getElementById('detail_' + key);
    var btn = event.target;
    if (!row) return;
    if (row.style.display === 'none') {
        row.style.display = 'table-row';
        btn.classList.add('open');
    } else {
        row.style.display = 'none';
        btn.classList.remove('open');
    }
}
function filterMatrix(input, cat) {
    var q = input.value.toLowerCase();
    var table = document.getElementById('matrix_' + cat);
    if (!table) return;
    var rows = table.querySelectorAll('tbody tr[data-testid]');
    rows.forEach(function(row) {
        var tid = (row.getAttribute('data-testid') || '').toLowerCase();
        var name = (row.querySelector('.test-name-cell') || {}).textContent || '';
        var match = tid.includes(q) || name.toLowerCase().includes(q);
        var detailRow = document.getElementById('detail_' + cat + '_' + row.getAttribute('data-testid'));
        if (match) {
            row.classList.remove('hidden-row');
        } else {
            row.classList.add('hidden-row');
            if (detailRow) detailRow.style.display = 'none';
        }
    });
}
</script>"""


def _escape_html(text: str) -> str:
    # Strip surrogate characters (lone surrogates are invalid UTF-8)
    text = str(text).encode("utf-8", errors="replace").decode("utf-8")
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
