"""
Gateway Workflow Test Runner

Executes ONDC Gateway end-to-end workflow tests.

Key differences from the registry workflow runners:
  - Uses PRE-EXISTING participants (BAP-SEC-001, etc.) or generates fresh ones
    per run using generate_unique_id: true. Their subscriber_ids and Ed25519
    private keys are declared in the test YAML under the top-level `participants:` block.
  - Each workflow step can declare `auth_subscriber_id: <alias>` to select
    WHICH participant's ONDC-SIG key should sign that individual request.
  - Steps marked `skip: true` represent Gateway-internal actions (not real HTTP
    calls we can make) — they are logged and bypassed.
  - Supports two API endpoints via two URLs:
      base_url     → Registry Admin API  (JWT auth setup/verification steps)
      gateway_url  → Gateway API         (/search, /on_search, etc.)
    If `gateway_url` is not configured it falls back to `base_url`.
  - Context variables automatically available in every step via {{…}} templating:
      {{<alias>_id}}      subscriber_id of that participant
      {{<alias>_uri}}     callback_uri of that participant
      {{<alias>_domain}}  registered domain of that participant
      {{transaction_id}}  fresh UUID per test invocation
      {{message_id}}      fresh UUID per test invocation
      {{timestamp}}       ISO-8601 UTC timestamp

Authentication model:
  [ONDC-SIG] — Ed25519 ONDC signature (NP's own key pair)
               Required for all BAP/BPP calls to the Gateway
  [JWT]      — Bearer token (Registry Admin login)
               Used for Registry admin setup/verification steps
  OCSP, TLS, DNS TXT — NOT applicable; always skipped via dns_skip/skip_ssl_verification
"""

import os
import uuid
import time
import random
import base64
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse

# gateway-workflow-suite reuses workflow-suite's base infrastructure.
# run_tests.py inserts the workflow-suite directory into sys.path before import.
from src.executors.base_runner import BaseTestRunner, TestResult


# ---------------------------------------------------------------------------
# Private-key seed decoding helpers
# Accepted formats:
#   - 64-char lowercase hex (raw 32-byte seed)
#   - Base64-encoded PKCS#8 DER (e.g. "MC4CAQAwBQYDK2Vw..." — used in resource YAMLs)
#   - Base64-encoded NaCl 64-byte key (seed = first 32 bytes)
# Returns a PEM string suitable for ONDCSignature / serialization.load_pem_private_key.
# ---------------------------------------------------------------------------
def _decode_private_key_to_pem(raw: str) -> Optional[str]:
    """Convert private_key_seed (hex/DER-base64/NaCl-base64) to PKCS#8 PEM string."""
    if not raw:
        return None
    raw = raw.strip()

    # 1. 64-char hex → raw 32-byte seed
    if len(raw) == 64:
        try:
            seed_bytes = bytes.fromhex(raw)
            return _seed_bytes_to_pem(seed_bytes)
        except ValueError:
            pass

    # 2. Base64-encoded DER or NaCl blob
    try:
        blob = base64.b64decode(raw)
        if len(blob) == 64:
            # NaCl 64-byte secret key: first 32 bytes are the seed
            return _seed_bytes_to_pem(blob[:32])
        if len(blob) >= 32:
            # PKCS#8 DER: last 32 bytes are the raw seed
            return _seed_bytes_to_pem(blob[-32:])
    except Exception:
        pass

    return None


def _seed_bytes_to_pem(seed: bytes) -> str:
    """Wrap raw 32-byte Ed25519 seed in PKCS#8 PEM for serialization.load_pem_private_key."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding, PrivateFormat, NoEncryption
    )
    priv = Ed25519PrivateKey.from_private_bytes(seed)
    return priv.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode()


class GatewayTestRunner(BaseTestRunner):
    """
    Test runner for ONDC Gateway workflow tests.

    Reads participant definitions from the YAML config and registers each
    participant's Ed25519 key pair with the shared HTTP client so that any
    step can request an ONDC-SIG header for that participant.
    """

    def __init__(self, *args, gateway_url: Optional[str] = None, admin_url: Optional[str] = None, gateway_participant_id: Optional[str] = None, bg_lookup_subscriber_id: Optional[str] = None, bg_lookup_country: Optional[str] = None, bg_lookup_type: Optional[str] = None, mock_url: Optional[str] = None, **kwargs):
        super().__init__(*args, **kwargs)
        # gateway_url is where /search, /on_search etc. are served.
        # Falls back to base_url when not supplied.
        self.gateway_url = (gateway_url or self.base_url).rstrip('/')

        # admin_url is where /admin/subscribe, /admin/participants etc. are served.
        # On environments where the admin service is a separate host (e.g. UAT),
        # set this to that host. Falls back to base_url when not supplied.
        self.admin_url = (admin_url or self.base_url).rstrip('/')

        # Hostname of gateway_url — exposed as {{gateway_subscriber_id}} in every test step.
        self._gateway_subscriber_id: str = urlparse(self.gateway_url).netloc

        # Registry internal UUID for the gateway participant — exposed as
        # {{gateway_participant_id}} in every test step. Used in NETWORK policy
        # steps (POST /admin/policies, GET /admin/participants/<id>/policies).
        # Configured in test_suite.yaml under config.gateway_participant_id.
        self._gateway_participant_id: str = gateway_participant_id or ''

        # BG lookup parameters — used by NETWORK policy Pre-req steps to resolve
        # the gateway's participant_id at runtime via POST /v3.0/lookup.
        # Configurable per environment in test_suite.yaml comparison_targets.
        self._bg_lookup_subscriber_id: str = bg_lookup_subscriber_id or self._gateway_subscriber_id
        self._bg_lookup_country: str = bg_lookup_country or 'IND'
        self._bg_lookup_type: str = bg_lookup_type or 'BG'

        # URL of the seller/BPP mock service used for Option-A X-Gateway-Authorization checks.
        # Exposed as {{seller_mock_url}} in every test step.
        self.mock_url = (mock_url or '').rstrip('/')

        # alias → {subscriber_id, uk_id, domain, callback_uri, ...}
        self.gateway_participants: Dict[str, Dict[str, str]] = {}

        # Per-run unique suffix used when participants declare generate_unique_id: true.
        # Format: YYYYMMDDHHmmss — readable, sortable, unique per runner instance.
        self._run_id = datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def _try_login_with_retry(self, max_attempts: int = 3) -> bool:
        """
        Attempt admin login up to max_attempts times with exponential backoff.
        Returns True on first success, False if all attempts fail.
        """
        for attempt in range(1, max_attempts + 1):
            if self.client.admin_login():
                return True
            if attempt < max_attempts:
                delay = 2 ** attempt + random.uniform(0, 1)
                print(f"[RETRY] Admin login attempt {attempt}/{max_attempts} failed — retrying in {delay:.1f}s...")
                time.sleep(delay)
            else:
                print(f"[ERROR] Admin login failed after {max_attempts} attempts")
        return False

    def setup(self) -> bool:
        """
        Prepare the Gateway workflow test runner:
          1. Admin login (JWT) — needed for setup/verification steps.
             Retries up to 3 times with exponential backoff.
          2. Register every gateway participant's Ed25519 key pair.
        """
        print("Setting up Gateway Workflow Test Runner...")

        # 1. Admin login with retry + fallback
        if not self._try_login_with_retry(max_attempts=3):
            if self.client.admin_auth.auth_url:
                print("[FALLBACK] External auth service unavailable — trying registry native login endpoint...")
                self.client.admin_auth.auth_url = None
                if not self._try_login_with_retry(max_attempts=2):
                    print("[ERROR] Admin login failed on both external auth service and registry endpoint")
                    return False
            else:
                return False

        print(f"[OK] Admin login successful")

        # 2. Load and register gateway participants
        participants_cfg = self.config.get('participants', [])
        if not participants_cfg:
            print("[WARNING] No participants defined in config — ONDC-SIG steps will fail")

        for p in participants_cfg:
            alias = p.get('alias', '')
            if not alias:
                print(f"[WARNING] Skipping participant with no alias: {p}")
                continue

            # generate_unique_id: true → derive subscriber_id from prefix + run_id.
            # This ensures every test run creates its own fresh participants in the
            # Registry, preventing state bleed between parallel or sequential runs.
            if p.get('generate_unique_id', False):
                prefix = p.get('subscriber_id_prefix', alias.replace('_', '-'))
                subscriber_id = f"{prefix}-{self._run_id}.ondc.org"
                uk_id = str(uuid.uuid4())
            else:
                subscriber_id = p.get('subscriber_id', '')
                uk_id = p.get('uk_id', '')

            if not subscriber_id or not uk_id:
                print(f"[WARNING] Skipping incomplete participant definition: {p}")
                continue

            # Resolve private key — priority order:
            #   1. private_key_env  — env-var name holding a PEM string (CI/CD secrets)
            #   2. private_key_pem  — inline PEM string in YAML
            #   3. private_key_seed — DER-base64 / hex seed
            #   4. None             — generate a fresh ephemeral key
            private_key_pem: Optional[str] = None
            if p.get('private_key_env'):
                private_key_pem = os.environ.get(p['private_key_env'])
                if not private_key_pem:
                    print(f"[WARNING] Env var '{p['private_key_env']}' not set for {alias} — generating new key")
            if not private_key_pem:
                private_key_pem = p.get('private_key_pem')
            if not private_key_pem and p.get('private_key_seed'):
                private_key_pem = _decode_private_key_to_pem(p['private_key_seed'])
                if not private_key_pem:
                    print(f"[WARNING] Could not decode private_key_seed for '{alias}' — generating new key")
                else:
                    print(f"[OK] Decoded private_key_seed for '{alias}' (DER/hex -> PEM)")

            self.client.register_v3_participant(subscriber_id, uk_id, private_key_pem)

            callback_uri = p.get('callback_uri', f'https://{subscriber_id}/callback')
            self.gateway_participants[alias] = {
                'subscriber_id': subscriber_id,
                'uk_id': uk_id,
                'domain': p.get('domain', 'ONDC:RET10'),
                'callback_uri': callback_uri,
            }

            key_source = "provided PEM" if private_key_pem else "generated"
            print(f"[OK] Registered participant '{alias}' ({subscriber_id}) — key: {key_source}")

            # Inject generated public key data into the context so that steps can
            # reference {{<alias>_signing_public_key}}, {{<alias>_uk_id}}, etc.
            pub_key = self.client.get_v3_public_key(subscriber_id)
            if pub_key:
                self.gateway_participants[alias]['signing_public_key'] = pub_key.get('signing_public_key', '')
                self.gateway_participants[alias]['encryption_public_key'] = pub_key.get('encryption_public_key', '')
                self.gateway_participants[alias]['valid_from'] = pub_key.get('valid_from', '')
                self.gateway_participants[alias]['valid_until'] = pub_key.get('valid_until', '')

        print(f"[OK] Gateway Workflow Test Runner ready ({len(self.gateway_participants)} participants)")
        return True

    def teardown(self):
        """Clean up resources."""
        print("Cleaning up Gateway Workflow Test Runner...")
        self.client.close()
        print("[OK] Cleanup complete")

    # ------------------------------------------------------------------
    # Context builder
    # ------------------------------------------------------------------

    def _build_gateway_context(self) -> Dict[str, str]:
        """
        Build the variable context for a single test invocation.

        Provides:
            {{<alias>_id}}      subscriber_id
            {{<alias>_uri}}     callback_uri
            {{<alias>_domain}}  domain
            {{<alias>_uk_id}}   uk_id
            {{<alias>_signing_public_key}}
            {{<alias>_encryption_public_key}}
            {{<alias>_valid_from}}
            {{<alias>_valid_until}}
            {{transaction_id}}             fresh UUID
            {{message_id}}                 fresh UUID
            {{timestamp}}                  ISO-8601 UTC timestamp
            {{run_id}}                     YYYYMMDDHHmmss run identifier (same suffix used for participant IDs)
            {{gateway_subscriber_id}}      hostname of gateway_url (e.g. gateway-preprod.ondc.org)
            {{gateway_participant_id}}     Registry internal UUID for the gateway participant
            {{bg_lookup_subscriber_id}}    subscriber_id sent in Pre-req BG lookup (configurable per env)
            {{bg_lookup_country}}          country sent in Pre-req BG lookup (default: IND)
            {{bg_lookup_type}}             type sent in Pre-req BG lookup (default: BG)
        """
        ctx: Dict[str, str] = {
            'transaction_id': str(uuid.uuid4()),
            # order_transaction_id is a separate UUID for the select→init→confirm
            # leg of a transaction (different from the search transaction_id).
            # Used in WF-RTE-03 to prove the Gateway correctly routes both legs.
            'order_transaction_id': str(uuid.uuid4()),
            'message_id': str(uuid.uuid4()),
            'timestamp': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z',
            'run_id': self._run_id,
            'gateway_subscriber_id': self._gateway_subscriber_id,
            'gateway_participant_id': self._gateway_participant_id,
            'bg_lookup_subscriber_id': self._bg_lookup_subscriber_id,
            'bg_lookup_country': self._bg_lookup_country,
            'bg_lookup_type': self._bg_lookup_type,
            'seller_mock_url': self.mock_url,
        }
        for alias, pdata in self.gateway_participants.items():
            ctx[f'{alias}_id'] = pdata['subscriber_id']
            ctx[f'{alias}_uri'] = pdata['callback_uri']
            ctx[f'{alias}_domain'] = pdata['domain']
            ctx[f'{alias}_uk_id'] = pdata['uk_id']
            ctx[f'{alias}_signing_public_key'] = pdata.get('signing_public_key', '')
            ctx[f'{alias}_encryption_public_key'] = pdata.get('encryption_public_key', '')
            ctx[f'{alias}_valid_from'] = pdata.get('valid_from', '')
            ctx[f'{alias}_valid_until'] = pdata.get('valid_until', '')
        return ctx

    # ------------------------------------------------------------------
    # Validation override — adds not_contains support
    # ------------------------------------------------------------------

    def _validate_field(self, response_data, validation, result) -> bool:
        """
        Extends base _validate_field with gateway-specific operators:

        not_contains
        ------------
        Asserts that a field value does NOT contain the expected item.
        Useful for asserting that a subscriber_id is ABSENT from a lookup
        response list, e.g.:
            field: "*.subscriber_id"
            not_contains: "{{bpp003_id}}"

        in_range
        --------
        Asserts that a numeric field value (error code) falls within an
        inclusive integer range.  Handles both string ("15001") and integer
        (15001) typed values.  Use to enforce ONDC error-code ranges:
            Registry error codes : 10000–14999
            Gateway error codes  : 15000–19999
        Example:
            field: "error.code"
            in_range:
              min: 15000
              max: 19999

        All other validation types fall through to the base implementation.
        """
        if 'not_contains' in validation:
            field = validation['field']
            parts = [p for p in field.replace('[', '.').replace(']', '').split('.') if p]
            try:
                value = self._navigate_field(response_data, parts)
            except (KeyError, IndexError, TypeError, AttributeError):
                # Field not found — the unwanted value is definitely absent → PASS
                result.validations.append({
                    "field": field,
                    "passed": True,
                    "expected": f"not contains {validation['not_contains']}",
                    "actual": "field not found (trivially satisfied)",
                })
                return True

            expected = validation['not_contains']
            if isinstance(value, list):
                passed = expected not in value
            elif isinstance(value, str):
                passed = expected not in value
            else:
                passed = value != expected

            result.validations.append({
                "field": field,
                "passed": passed,
                "expected": f"not contains {expected}",
                "actual": value,
            })
            return passed

        if 'in_range' in validation:
            field = validation['field']
            range_cfg = validation['in_range']
            range_min = range_cfg['min']
            range_max = range_cfg['max']
            parts = [p for p in field.replace('[', '.').replace(']', '').split('.') if p]
            try:
                value = self._navigate_field(response_data, parts)
            except (KeyError, IndexError, TypeError, AttributeError):
                result.validations.append({
                    "field": field,
                    "passed": False,
                    "expected": f"in_range [{range_min}–{range_max}]",
                    "actual": "field not found",
                    "error": f"Field '{field}' not found in response",
                })
                return False

            try:
                int_val = int(value)
            except (TypeError, ValueError):
                result.validations.append({
                    "field": field,
                    "passed": False,
                    "expected": f"in_range [{range_min}–{range_max}]",
                    "actual": value,
                    "error": f"Field '{field}' value '{value}' cannot be cast to int for range check",
                })
                return False

            passed = range_min <= int_val <= range_max
            result.validations.append({
                "field": field,
                "passed": passed,
                "expected": f"in_range [{range_min}–{range_max}]",
                "actual": int_val,
                "error": (
                    None if passed
                    else f"Error code {int_val} is outside the expected range [{range_min}–{range_max}]"
                ),
            })
            return passed

        return super()._validate_field(response_data, validation, result)

    # ------------------------------------------------------------------
    # Workflow execution override
    # ------------------------------------------------------------------

    def _execute_workflow(self, test: Dict, result: TestResult) -> bool:
        """
        Execute a Gateway multi-step workflow.

        Overrides BaseTestRunner to support:
          - `skip: true`  — Gateway-internal steps (not real HTTP calls)
          - `auth_subscriber_id: <alias>`  — Selects which participant's key
            to use for ONDC-SIG on that specific step.
          - `use_base_url: true`  — Force step to target base_url (Registry)
            even when auth_type is v3 (e.g. /v2.0/lookup lives on Registry).
          - Gateway URL routing — admin steps go to base_url; all others go
            to gateway_url unless use_base_url overrides.
          - GET method  — data dict is sent as query params, not request body.
        """
        steps = test.get('steps', [])
        context = self._build_gateway_context()
        last_status_code = 200
        workflow_failed = False  # tracks whether any step has failed
        step_errors = []         # accumulates per-step error messages
        _gateway_step_fired = False  # tracks whether the propagation delay has been applied

        for i, step in enumerate(steps):
            step_name = step.get('name', f'Step {i + 1}')

            # ── Gateway-internal / documentation steps ────────────────────
            # skip: true steps are fully omitted from the HTTP call sequence.
            # method: INTERNAL steps are recorded in the report (shown as
            # Gateway-internal in the HTML accordion) but no HTTP call is made.
            if step.get('skip', False):
                continue

            if step.get('method', '').upper() == 'INTERNAL':
                validates = step.get('validates', [])
                if validates:
                    # ── Real validation step ──────────────────────────────
                    # Each entry in `validates` asserts that a named prior step
                    # passed or failed. The runner finds the most recent prior
                    # step whose name contains `step_contains` (case-insensitive
                    # substring match) and checks its `step_passed` value against
                    # the declared expectation ("passed" or "failed").
                    check_results = []
                    step_ok = True
                    for chk in validates:
                        match_substr = chk.get('step_contains', '')
                        expect = chk.get('expect', 'passed')  # 'passed' | 'failed'
                        # Optional human-readable outcome labels for the report table.
                        # e.g. expected_outcome="Accepted (ACK)", fail_outcome="Rejected / No response"
                        expected_outcome = chk.get('expected_outcome', None)
                        fail_outcome = chk.get('fail_outcome', None)
                        expected_label = expected_outcome if expected_outcome else expect

                        matched = next(
                            (rd for rd in reversed(result.request_details)
                             if match_substr.lower() in rd.get('step_name', '').lower()),
                            None
                        )
                        if matched is None:
                            actual_display = fail_outcome if fail_outcome else "not found"
                            check_results.append({
                                "check": match_substr,
                                "expected_label": expected_label,
                                "actual_label": actual_display,
                                "ok": False,
                            })
                            step_ok = False
                        else:
                            actual_passed = matched.get('step_passed', None)
                            if expect == 'passed':
                                ok = actual_passed is True
                            else:  # 'failed'
                                ok = actual_passed is False
                            raw_label = (
                                "passed" if actual_passed is True else
                                "failed" if actual_passed is False else
                                "unknown"
                            )
                            if ok:
                                actual_display = expected_outcome if expected_outcome else raw_label
                            else:
                                actual_display = fail_outcome if fail_outcome else raw_label
                            check_results.append({
                                "check": match_substr,
                                "expected_label": expected_label,
                                "actual_label": actual_display,
                                "ok": ok,
                            })
                            if not ok:
                                step_ok = False

                    req_entry = {
                        "step_name": step_name,
                        "method": "INTERNAL",
                        "step_passed": step_ok,
                        "validation_checks": check_results,
                    }
                    if not step_ok:
                        failed_checks = [c['check'] for c in check_results if not c['ok']]
                        _step_err = f"{step_name}: checks failed — {'; '.join(failed_checks)}"
                        req_entry['step_error'] = _step_err
                        step_errors.append(_step_err)
                        workflow_failed = True
                    result.request_details.append(req_entry)
                else:
                    # ── Documentation-only INTERNAL step ─────────────────
                    # step_passed=None signals the reporter: render as
                    # informational with no PASS/FAIL badge.
                    result.request_details.append({
                        "step_name": step_name,
                        "method": "INTERNAL",
                        "step_passed": None,
                    })

                # Always append a matching dummy response_details entry so that
                # zip(request_details, response_details) stays aligned.
                result.response_details.append({
                    "step_name": step_name,
                    "status_code": "INTERNAL",
                    "headers": {},
                    "body": None,
                })
                print(f"  -> {step_name}")
                if step.get('post_wait_seconds'):
                    pw = int(step['post_wait_seconds'])
                    print(f"  [WAIT] post_wait_seconds={pw}s — gateway policy propagation...")
                    time.sleep(pw)
                continue

            # ── Inject step-level `action` into context ───────────────────
            if 'action' in step:
                context['action'] = step['action']

            # ── Resolve template variables ────────────────────────────────
            step_data = self._resolve_variables(step.get('data', {}), context)
            endpoint = self._resolve_variables(
                step.get('endpoint', ''), context
            ) if isinstance(step.get('endpoint'), str) else step.get('endpoint', '')

            # ── Determine which URL to target ─────────────────────────────
            # admin steps always go to base_url (Registry Admin API).
            # use_base_url: true forces v3 steps to also use base_url.
            # All other steps go to gateway_url.
            # phase tracks which section of the HTML report this step belongs to:
            #   'prereq'  — Registry administration before the first Gateway call
            #   'gateway' — All steps once the workflow has started (including
            #               mid-workflow admin calls like PATCH INACTIVE)
            auth_type = step.get('auth_type', 'none')
            if auth_type == 'admin':
                # Admin API calls go to the dedicated admin service URL.
                # This may differ from base_url on environments where the admin
                # service is deployed separately (e.g. admin-service-uat.kynondc.net).
                target_url = self.admin_url
                step_phase = 'gateway' if _gateway_step_fired else 'prereq'
            elif step.get('use_base_url', False):
                # use_base_url: true forces v3 steps to the Registry host
                # (e.g. /v3.0/lookup which lives on the Registry, not the Gateway).
                target_url = self.client.base_url
                step_phase = 'gateway' if _gateway_step_fired else 'prereq'
            elif step.get('use_mock_url', False):
                # use_mock_url: true routes the step to the seller/BPP mock service
                # (e.g. GET /mock/requests/last to verify X-Gateway-Authorization).
                target_url = self.mock_url
                step_phase = 'gateway' if _gateway_step_fired else 'prereq'
            else:
                target_url = self.gateway_url
                step_phase = 'gateway'
                # ── Registry propagation delay ─────────────────────────────
                # On the first real Gateway call of each test, wait 5 s so the
                # Registry has time to propagate freshly-registered participants
                # to the Gateway key-store before the ONDC-SIG is verified.
                if not _gateway_step_fired:
                    _gateway_step_fired = True
                    propagation_wait = self.config.get('propagation_wait_seconds', 5)
                    print(f"  [WAIT] Pausing {propagation_wait}s for Registry propagation before first Gateway call...")
                    time.sleep(propagation_wait)

            original_base_url = self.client.base_url

            # ── Resolve which participant signs the request ────────────────
            v3_subscriber_id: Optional[str] = None
            if auth_type == 'v3':
                alias = step.get('auth_subscriber_id')
                if alias:
                    pdata = self.gateway_participants.get(alias)
                    v3_subscriber_id = pdata['subscriber_id'] if pdata else None
                    if not v3_subscriber_id:
                        print(f"    [WARNING] Unknown auth_subscriber_id alias '{alias}' — ONDC-SIG will fail")
                else:
                    # Default: first registered participant
                    if self.gateway_participants:
                        v3_subscriber_id = next(iter(self.gateway_participants.values()))['subscriber_id']

            # ── Retry config ──────────────────────────────────────────────
            _retry_cfg = step.get('retry', {})
            _retry_timeout = int(_retry_cfg.get('timeout_seconds', 0))
            _retry_interval = float(_retry_cfg.get('interval_seconds', 1))
            _retry_deadline = (time.monotonic() + _retry_timeout) if _retry_timeout else None
            _retry_start = time.monotonic() if _retry_timeout else None
            _attempt = 0

            # ── Execute HTTP request (with optional retry) ────────────────
            # GET requests carry data as query params (no body).
            # If `retry:` is declared on the step, re-runs the request every
            # `interval_seconds` until both the status code and all field
            # validations pass, or `timeout_seconds` is exhausted.
            is_get = step['method'].upper() == 'GET'
            response = None
            response_body = None
            while True:
                _attempt += 1
                _vcount_before = len(result.validations)
                self.client.base_url = target_url

                response = self.client.request(
                    method=step['method'],
                    endpoint=endpoint,
                    auth_type=auth_type,
                    subscriber_id=v3_subscriber_id,
                    data=None if is_get else (step_data if step_data else None),
                    params=step_data if is_get else None,
                    timeout=step.get('timeout', 30),
                    invalid_signature=step.get('invalid_signature', False),
                    include_digest=not (is_get or step.get('no_digest', False)),
                )
                self.client.base_url = original_base_url

                try:
                    response_body = response.json()
                except Exception:
                    response_body = response.text

                if _retry_deadline:
                    # Pre-check: used ONLY for the retry decision.
                    # Any result.validations entries appended here are always
                    # rolled back before we break — the committed validation
                    # block below is the single source of truth for the report.
                    _exp = step.get('expected_status', 200)
                    _exp_statuses = _exp if isinstance(_exp, list) else [_exp]
                    _status_ok = response.status_code in _exp_statuses

                    _val_ok = True
                    if _status_ok and 'validate' in step:
                        _resp_data = response_body if isinstance(response_body, (dict, list)) else {}
                        for _v in step['validate']:
                            _rv = self._resolve_variables(_v, context)
                            if not self._validate_field(_resp_data, _rv, result):
                                _val_ok = False
                                break

                    # Always roll back validations added in this retry iteration
                    del result.validations[_vcount_before:]

                    if not (_status_ok and _val_ok) and time.monotonic() < _retry_deadline:
                        time.sleep(_retry_interval)
                        continue

                break  # no retry config, or retry decision reached

            # ── Compute propagation wait elapsed (only for retry steps) ───
            _propagation_elapsed = None
            if _retry_start is not None:
                _propagation_elapsed = round(time.monotonic() - _retry_start, 1)

            # ── Capture request details ───────────────────────────────────
            expected_statuses_pre = step.get('expected_status', 200)
            expected_statuses_pre = expected_statuses_pre if isinstance(expected_statuses_pre, list) else [expected_statuses_pre]
            step_passed_pre = response.status_code in expected_statuses_pre
            _req_entry = {
                "step_name": step_name,
                "method": step['method'],
                "endpoint": endpoint,
                "url": response.request.url if hasattr(response, 'request') else None,
                "auth_type": auth_type,
                "auth_subscriber_id": v3_subscriber_id,
                "headers": dict(response.request.headers) if hasattr(response, 'request') else {},
                "body": step_data,
                "phase": step_phase,
                "step_passed": step_passed_pre,
            }
            if _propagation_elapsed is not None:
                _req_entry["propagation_wait_elapsed_s"] = _propagation_elapsed
            # capture_request_headers: ["Authorization"] — snapshot specific outbound
            # request headers into the report so the actual ONDC-SIG value is visible.
            if step.get('capture_request_headers'):
                _cap_names = (
                    step['capture_request_headers']
                    if isinstance(step['capture_request_headers'], list)
                    else [step['capture_request_headers']]
                )
                _all_req_hdrs = dict(response.request.headers) if hasattr(response, 'request') else {}
                _req_entry['captured_request_headers'] = {
                    k: v for k, v in _all_req_hdrs.items()
                    if any(k.lower() == n.lower() for n in _cap_names)
                }
            result.request_details.append(_req_entry)

            # ── Parse response ────────────────────────────────────────────
            _resp_entry = {
                "step_name": step_name,
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "body": response_body,
            }
            # capture_response_headers: ["X-Gateway-Authorization"] — snapshot
            # specific inbound response headers for visibility in the report.
            if step.get('capture_response_headers'):
                _cap_names = (
                    step['capture_response_headers']
                    if isinstance(step['capture_response_headers'], list)
                    else [step['capture_response_headers']]
                )
                _resp_entry['captured_response_headers'] = {
                    k: v for k, v in response.headers.items()
                    if any(k.lower() == n.lower() for n in _cap_names)
                }
            result.response_details.append(_resp_entry)

            last_status_code = response.status_code

            # ── Post-step wait (propagation delay for mid-test registrations) ──
            # Use `post_wait_seconds: N` on any step to pause N seconds after
            # that step completes — e.g. after registering a new participant
            # mid-test so the Registry has time to propagate before the next call.
            if step.get('post_wait_seconds'):
                pw = int(step['post_wait_seconds'])
                print(f"  [WAIT] post_wait_seconds={pw}s — allowing Registry propagation...")
                time.sleep(pw)

            # ── Status code check ─────────────────────────────────────────
            expected = step.get('expected_status', 200)
            expected_statuses = expected if isinstance(expected, list) else [expected]

            if response.status_code not in expected_statuses:
                _step_err = f"{step_name}: Expected {expected}, got {response.status_code}"
                result.error_message = _step_err
                result.status_code = response.status_code
                result.expected_status = expected_statuses[0]
                result.response_body = response_body
                # Stamp the error onto the most-recently-added request_details entry
                if result.request_details:
                    result.request_details[-1]['step_error'] = _step_err
                    result.request_details[-1]['step_passed'] = False
                if step.get('continue_on_failure', False):
                    print(f"    [CONTINUE] Step failed (status {response.status_code}) but continue_on_failure=true — proceeding")
                    step_errors.append(_step_err)
                    workflow_failed = True
                    continue
                return False

            # ── Store response fields into context ────────────────────────
            if 'store' in step:
                for store_item in step.get('store', []):
                    field_path = store_item.get('field', '')
                    as_key = store_item.get('as', '')
                    if field_path and as_key:
                        parts = [p for p in field_path.replace('[', '.').replace(']', '').split('.') if p]
                        try:
                            val = self._navigate_field(response_body, parts)
                        except (KeyError, IndexError, TypeError, AttributeError):
                            val = None
                        if val is not None:
                            context[as_key] = val
                            print(f"    [STORE] {as_key} = {val}")

            # ── Field validations ─────────────────────────────────────────
            if 'validate' in step:
                try:
                    response_data = response.json()
                except Exception:
                    response_data = {}

                for validation in step['validate']:
                    # Resolve template variables inside validation values so
                    # entries like  value: "{{bap_sec_id}}"  work correctly.
                    resolved_validation = self._resolve_variables(validation, context)
                    if not self._validate_field(response_data, resolved_validation, result):
                        failed_v = next(
                            (v for v in reversed(result.validations) if not v.get('passed')), None
                        )
                        if failed_v:
                            err = failed_v.get('error', 'Validation failed')
                            _step_err = f"{step_name}: {err}"
                        else:
                            _step_err = f"{step_name}: Validation failed for field '{validation['field']}'"
                        result.error_message = _step_err
                        if result.request_details:
                            result.request_details[-1]['step_error'] = _step_err
                            result.request_details[-1]['step_passed'] = False
                        if step.get('continue_on_failure', False):
                            print(f"    [CONTINUE] Step validation failed but continue_on_failure=true — proceeding")
                            step_errors.append(_step_err)
                            workflow_failed = True
                            break
                        return False

        result.status_code = last_status_code
        result.expected_status = last_status_code
        if step_errors:
            result.error_message = " | ".join(step_errors)
        return not workflow_failed
