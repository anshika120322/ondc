"""
Postman Collection v2.1 exporter for ONDC Registry test suite.

Converts YAML test configs into a fully importable Postman collection with:
- Pre-request scripts: Admin JWT auto-login, variable injection
- Tests (post-response) scripts: status assertions, validate field checks, store captures
- One folder per category, sub-folders for workflow tests
- Companion environment file with base_url, credentials pre-filled
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

import yaml


# ---------------------------------------------------------------------------
# Pre-request script templates
# ---------------------------------------------------------------------------

_ADMIN_AUTH_PREREQ = """\
// Auto-login: fetch admin JWT if not already stored or expired
const token = pm.environment.get("admin_token");
const tokenExpiry = pm.environment.get("admin_token_expiry");
const now = Date.now();

if (!token || !tokenExpiry || now >= parseInt(tokenExpiry)) {
    const baseUrl = pm.environment.get("base_url");
    const loginUrl = baseUrl + pm.environment.get("admin_login_path");
    pm.sendRequest({
        url: loginUrl,
        method: "POST",
        header: { "Content-Type": "application/json" },
        body: {
            mode: "raw",
            raw: JSON.stringify({
                [pm.environment.get("admin_username_field")]: pm.environment.get("admin_username"),
                [pm.environment.get("admin_password_field")]: pm.environment.get("admin_password")
            })
        }
    }, function(err, resp) {
        if (!err && resp.code === 200) {
            const body = resp.json();
            const tokenField = pm.environment.get("admin_token_field");
            const newToken = body[tokenField] || (body.data && body.data[tokenField]);
            if (newToken) {
                pm.environment.set("admin_token", newToken);
                // Expire 55 minutes from now (tokens typically valid 60 min)
                pm.environment.set("admin_token_expiry", String(Date.now() + 55 * 60 * 1000));
            }
        }
    });
}
"""

_V3_AUTH_NOTE = """\
// ONDC Ed25519 signature auth is required for this request.
// Postman sandbox does not natively support Ed25519 signing.
//
// To run this request:
//   1. Generate keys via: POST {{base_url}}/utility/generate-keypair  (JWT-gated)
//   2. Store private key externally and sign the request body using Ed25519
//   3. Set the Authorization header manually:
//      Signature keyId="{{subscriber_id}}|{{uk_id}}|ed25519",
//                algorithm="ed25519", created=<ts>, expires=<ts>,
//                headers="(created) (expires) digest",
//                signature="<base64_sig>"
//
// Or run via: python run_tests.py run --category v3
"""

_NO_AUTH_PREREQ = "// No authentication required for this request.\n"


def _subscriber_id_prereq() -> str:
    """Generate a random subscriber_id if not already set in the environment."""
    return """\
// Generate a unique subscriber_id for this test run if not already set
if (!pm.environment.get("subscriber_id")) {
    const rand = Math.random().toString(36).substring(2, 10);
    pm.environment.set("subscriber_id", "test-participant-" + rand + ".example.com");
}
if (!pm.environment.get("uk_id")) {
    pm.environment.set("uk_id", "key_" + Math.random().toString(36).substring(2, 10));
}
"""


# ---------------------------------------------------------------------------
# Helper: build Postman request item
# ---------------------------------------------------------------------------

def _make_id() -> str:
    return str(uuid.uuid4())


def _resolve_url(base_url_var: str, endpoint: str) -> Dict:
    """Build Postman URL object from endpoint string."""
    full = f"{{{{{base_url_var}}}}}{endpoint}"
    # Split path for Postman path array
    path_parts = [p for p in endpoint.strip("/").split("/") if p]
    return {
        "raw": full,
        "host": [f"{{{{{base_url_var}}}}}"],
        "path": path_parts,
    }


def _build_prereq_script(auth_type: str, extra: str = "") -> Dict:
    if auth_type == "admin":
        script = _ADMIN_AUTH_PREREQ
    elif auth_type == "v3":
        script = _V3_AUTH_NOTE
    else:
        script = _NO_AUTH_PREREQ
    if extra:
        script = extra + "\n" + script
    return {
        "listen": "prerequest",
        "script": {
            "id": _make_id(),
            "type": "text/javascript",
            "exec": script.splitlines(keepends=False),
        },
    }


def _build_tests_script(test: Dict) -> Dict:
    """Build post-response (Tests tab) script from test config."""
    lines: List[str] = []

    # Status assertion
    expected = test.get("expected_status", 200)
    lines.append(f'pm.test("Status {expected}", function() {{')
    lines.append(f'    pm.response.to.have.status({expected});')
    lines.append('});')
    lines.append('')

    # Field validations
    for v in test.get("validate", []):
        field = v.get("field", "")
        value = v.get("value")
        op = v.get("operator", "equals")
        if field and value is not None:
            accessor = _js_accessor("pm.response.json()", field)
            val_js = json.dumps(value)
            label = f"{field} {op} {value}"
            lines.append(f'pm.test("{label}", function() {{')
            if op in ("equals", "eq", "=="):
                lines.append(f'    pm.expect({accessor}).to.eql({val_js});')
            elif op in ("contains", "includes"):
                lines.append(f'    pm.expect(String({accessor})).to.include({val_js});')
            elif op in ("exists", "not_null"):
                lines.append(f'    pm.expect({accessor}).to.exist;')
            else:
                lines.append(f'    pm.expect({accessor}).to.eql({val_js});')
            lines.append('});')
            lines.append('')

    # Store captures (save response fields to environment)
    for store in test.get("store", []):
        field_path = store.get("field", "")
        as_key = store.get("as", "")
        if field_path and as_key:
            accessor = _js_accessor("pm.response.json()", field_path)
            lines.append(f'// Capture: {field_path} → env.{as_key}')
            lines.append(f'var _val = {accessor};')
            lines.append(f'if (_val !== undefined && _val !== null) {{')
            lines.append(f'    pm.environment.set("{as_key}", _val);')
            lines.append(f'}}')
            lines.append('')

    return {
        "listen": "test",
        "script": {
            "id": _make_id(),
            "type": "text/javascript",
            "exec": lines,
        },
    }


def _build_step_tests_script(step: Dict, step_name: str) -> Dict:
    """Build post-response script for a single workflow step."""
    lines: List[str] = []

    expected = step.get("expected_status", 200)
    lines.append(f'pm.test("[{step_name}] Status {expected}", function() {{')
    lines.append(f'    pm.response.to.have.status({expected});')
    lines.append('});')
    lines.append('')

    for v in step.get("validate", []):
        field = v.get("field", "")
        value = v.get("value")
        if field and value is not None:
            accessor = _js_accessor("pm.response.json()", field)
            val_js = json.dumps(value)
            lines.append(f'pm.test("[{step_name}] {field} == {value}", function() {{')
            lines.append(f'    pm.expect({accessor}).to.eql({val_js});')
            lines.append('});')
            lines.append('')

    for store in step.get("store", []):
        field_path = store.get("field", "")
        as_key = store.get("as", "")
        if field_path and as_key:
            accessor = _js_accessor("pm.response.json()", field_path)
            lines.append(f'// Capture: {field_path} → env.{as_key}')
            lines.append(f'var _val = {accessor};')
            lines.append(f'if (_val !== undefined && _val !== null) {{')
            lines.append(f'    pm.environment.set("{as_key}", _val);')
            lines.append(f'}}')
            lines.append('')

    if step.get("save_subscriber_id", False):
        lines.append('// Save subscriber_id from response')
        lines.append('var _body = pm.response.json();')
        lines.append('if (_body && _body.subscriber_id) {')
        lines.append('    pm.environment.set("subscriber_id", _body.subscriber_id);')
        lines.append('}')
        lines.append('')

    return {
        "listen": "test",
        "script": {
            "id": _make_id(),
            "type": "text/javascript",
            "exec": lines,
        },
    }


def _js_accessor(root: str, field_path: str) -> str:
    """Convert dotted field path to JS property access chain."""
    parts = field_path.split(".")
    acc = root
    for p in parts:
        acc += f'["{p}"]'
    return acc


def _auth_headers(auth_type: str) -> List[Dict]:
    if auth_type == "admin":
        return [{"key": "Authorization", "value": "Bearer {{admin_token}}", "type": "text"}]
    elif auth_type == "v3":
        return [
            {"key": "Authorization", "value": "Signature keyId=\"{{subscriber_id}}|{{uk_id}}|ed25519\",algorithm=\"ed25519\",created={{created}},expires={{expires}},headers=\"(created) (expires) digest\",signature=\"{{ondc_signature}}\"", "type": "text"},
        ]
    return []


def _body_from_data(data: Any) -> Dict:
    if not data:
        return {"mode": "raw", "raw": "", "options": {"raw": {"language": "json"}}}
    return {
        "mode": "raw",
        "raw": json.dumps(data, indent=2),
        "options": {"raw": {"language": "json"}},
    }


# ---------------------------------------------------------------------------
# Build a single simple request item
# ---------------------------------------------------------------------------

def _build_request_item(test: Dict) -> Dict:
    auth_type = test.get("auth_type", "none")
    method = test.get("method", "GET").upper()
    endpoint = test.get("endpoint", "/")
    data = test.get("data")
    name = f"[{test['id']}] {test['name']}"

    headers = [{"key": "Content-Type", "value": "application/json", "type": "text"}]
    headers += _auth_headers(auth_type)

    # Pre-request: subscriber_id seed + auth
    extra = _subscriber_id_prereq() if "{{subscriber_id}}" in str(data or "") else ""
    prereq = _build_prereq_script(auth_type, extra)
    tests_script = _build_tests_script(test)

    params = test.get("query_params", {}) or {}
    query = [{"key": k, "value": str(v)} for k, v in params.items()]

    url_obj = _resolve_url("base_url", endpoint)
    if query:
        url_obj["query"] = query

    return {
        "id": _make_id(),
        "name": name,
        "request": {
            "method": method,
            "header": headers,
            "body": _body_from_data(data) if method not in ("GET", "DELETE") else {"mode": "none"},
            "url": url_obj,
            "description": test.get("description", ""),
        },
        "event": [prereq, tests_script],
        "response": [],
    }


# ---------------------------------------------------------------------------
# Build a workflow test as a sub-folder with one item per step
# ---------------------------------------------------------------------------

def _build_workflow_folder(test: Dict) -> Dict:
    folder_name = f"[{test['id']}] {test['name']}"
    items = []

    steps = test.get("steps", [])
    for i, step in enumerate(steps):
        step_name = step.get("name", f"Step {i+1}")
        auth_type = step.get("auth_type", "none")
        method = step.get("method", "POST").upper()
        endpoint = step.get("endpoint", "/")
        data = step.get("data")

        headers = [{"key": "Content-Type", "value": "application/json", "type": "text"}]
        headers += _auth_headers(auth_type)

        # Pre-request: seed subscriber_id on first step, auth always
        extra = _subscriber_id_prereq() if i == 0 else ""
        prereq = _build_prereq_script(auth_type, extra)
        tests_script = _build_step_tests_script(step, step_name)

        params = step.get("query_params", {}) or {}
        query = [{"key": k, "value": str(v)} for k, v in params.items()]

        url_obj = _resolve_url("base_url", endpoint)
        if query:
            url_obj["query"] = query

        items.append({
            "id": _make_id(),
            "name": f"Step {i+1}: {step_name}",
            "request": {
                "method": method,
                "header": headers,
                "body": _body_from_data(data) if method not in ("GET", "DELETE") else {"mode": "none"},
                "url": url_obj,
                "description": step.get("description", step_name),
            },
            "event": [prereq, tests_script],
            "response": [],
        })

    return {
        "id": _make_id(),
        "name": folder_name,
        "description": test.get("description", ""),
        "item": items,
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class PostmanExporter:
    """Export ONDC Registry test configurations to Postman Collection v2.1."""

    @staticmethod
    def export(
        suite_config_file: str,
        category_names: List[str],
        output_collection: str,
        output_environment: Optional[str] = None,
    ) -> None:
        """
        Generate a Postman Collection (.json) and companion Environment file.

        Args:
            suite_config_file: Path to `config/test_suite.yaml`.
            category_names: List of category names to include.
            output_collection: Output path for the collection JSON.
            output_environment: Output path for the environment JSON (optional).
        """
        with open(suite_config_file, "r", encoding="utf-8") as f:
            suite_cfg = yaml.safe_load(f)

        cfg = suite_cfg.get("config", {})
        base_url = cfg.get("base_url", "http://localhost:8080")
        admin_username = cfg.get("admin_username", "admin")
        admin_password = cfg.get("admin_password", "admin123")
        admin_login_path = cfg.get("admin_login_path", "/admin/auth/login")
        username_field = cfg.get("auth_username_field", "username")
        password_field = cfg.get("auth_password_field", "password")
        token_field = cfg.get("auth_token_field", "access_token")

        all_categories = suite_cfg.get("categories", [])
        folders: List[Dict] = []

        for cat_name in category_names:
            cat_meta = next((c for c in all_categories if c["name"] == cat_name), None)
            if not cat_meta:
                print(f"  [SKIP] Category '{cat_name}' not found in suite config")
                continue
            if not cat_meta.get("enabled", True):
                print(f"  [SKIP] Category '{cat_name}' is disabled")
                continue

            config_path = str(Path(suite_config_file).parent / cat_meta["config_file"])
            try:
                with open(config_path, "r", encoding="utf-8") as f:
                    cat_cfg = yaml.safe_load(f)
            except Exception as e:
                print(f"  [ERROR] Could not load {config_path}: {e}")
                continue

            tests = cat_cfg.get("tests", [])
            folder_items: List[Dict] = []

            for test in tests:
                is_workflow = test.get("workflow", False) or ("steps" in test)
                if is_workflow:
                    folder_items.append(_build_workflow_folder(test))
                else:
                    folder_items.append(_build_request_item(test))

            suite_name = cat_cfg.get("test_suite", {}).get("name", cat_name.title())
            folders.append({
                "id": _make_id(),
                "name": suite_name,
                "description": cat_cfg.get("test_suite", {}).get("description", ""),
                "item": folder_items,
            })
            print(f"  [OK] {cat_name}: {len(tests)} tests exported")

        # ── Collection ──────────────────────────────────────────────────
        collection = {
            "info": {
                "_postman_id": _make_id(),
                "name": suite_cfg.get("suite_info", {}).get("name", "ONDC Registry"),
                "description": (
                    f"Auto-generated from ONDC Registry Test Suite v2.0\n"
                    f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}\n"
                    f"Categories: {', '.join(category_names)}"
                ),
                "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
            },
            "item": folders,
            "variable": [],
        }

        Path(output_collection).parent.mkdir(parents=True, exist_ok=True)
        with open(output_collection, "w", encoding="utf-8") as f:
            json.dump(collection, f, indent=2)
        print(f"[OK] Postman collection saved to {output_collection}")

        # ── Environment ─────────────────────────────────────────────────
        env_path = output_environment or str(Path(output_collection).with_name(
            Path(output_collection).stem + "_environment.json"
        ))

        environment = {
            "id": _make_id(),
            "name": f"ONDC Registry — {suite_cfg.get('suite_info', {}).get('name', 'Env')}",
            "values": [
                {"key": "base_url",            "value": base_url,        "enabled": True, "type": "default"},
                {"key": "admin_username",       "value": admin_username,  "enabled": True, "type": "default"},
                {"key": "admin_password",       "value": admin_password,  "enabled": True, "type": "secret"},
                {"key": "admin_login_path",     "value": admin_login_path,"enabled": True, "type": "default"},
                {"key": "admin_username_field", "value": username_field,  "enabled": True, "type": "default"},
                {"key": "admin_password_field", "value": password_field,  "enabled": True, "type": "default"},
                {"key": "admin_token_field",    "value": token_field,     "enabled": True, "type": "default"},
                {"key": "admin_token",          "value": "",              "enabled": True, "type": "secret"},
                {"key": "admin_token_expiry",   "value": "",              "enabled": True, "type": "default"},
                {"key": "subscriber_id",        "value": "",              "enabled": True, "type": "default"},
                {"key": "uk_id",                "value": "",              "enabled": True, "type": "default"},
                {"key": "request_id",           "value": "",              "enabled": True, "type": "default"},
                {"key": "signing_public_key",   "value": "",              "enabled": True, "type": "default"},
                {"key": "encryption_public_key","value": "",              "enabled": True, "type": "default"},
                {"key": "valid_from",           "value": "",              "enabled": True, "type": "default"},
                {"key": "valid_until",          "value": "",              "enabled": True, "type": "default"},
                {"key": "created",              "value": "",              "enabled": True, "type": "default"},
                {"key": "expires",              "value": "",              "enabled": True, "type": "default"},
                {"key": "ondc_signature",       "value": "",              "enabled": True, "type": "default"},
            ],
            "_postman_variable_scope": "environment",
            "_postman_exported_at": datetime.now().isoformat(),
        }

        with open(env_path, "w", encoding="utf-8") as f:
            json.dump(environment, f, indent=2)
        print(f"[OK] Postman environment saved to {env_path}")
