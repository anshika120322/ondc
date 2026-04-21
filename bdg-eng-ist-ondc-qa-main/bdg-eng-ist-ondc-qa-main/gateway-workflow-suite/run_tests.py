#!/usr/bin/env python3
"""
ONDC Gateway Workflow Test Suite — Main Orchestrator

Runs end-to-end Gateway workflow tests from the config/ directory.
Reuses workflow-suite's base infrastructure (auth, http_client, base_runner)
by inserting the workflow-suite directory at the front of sys.path.

Usage:
    python run_tests.py run --category security
    python run_tests.py run --category routing
    python run_tests.py run --all
    python run_tests.py run --test-id WF-SEC-01
"""

import sys
import os
from pathlib import Path

# ── Path setup ────────────────────────────────────────────────────────────────
# Make workflow-suite's src package importable so gateway_runner can inherit
# BaseTestRunner, HTTPClient, DataGenerator, etc. without code duplication.
_REPO_ROOT = Path(__file__).resolve().parent.parent
_WORKFLOW_SUITE = _REPO_ROOT / "workflow-suite"
if str(_WORKFLOW_SUITE) not in sys.path:
    sys.path.insert(0, str(_WORKFLOW_SUITE))

# ── Standard imports (after path setup) ──────────────────────────────────────
import click
import yaml
import json
from datetime import datetime
from typing import List, Optional


def _load_gateway_runner():
    """
    Load GatewayTestRunner from gateway-workflow-suite/src/ via importlib.

    Both gateway-workflow-suite/src/ and workflow-suite/src/ share the same
    package name 'src'. workflow-suite/src must be first in sys.path so that
    gateway_runner.py can import BaseTestRunner via
    'from src.executors.base_runner import ...'. importlib lets us load the
    gateway_runner module directly by file path, bypassing the sys.path
    namespace conflict.
    """
    import importlib.util
    _path = Path(__file__).resolve().parent / "src" / "executors" / "gateway_runner.py"
    spec = importlib.util.spec_from_file_location("_gw_runner", str(_path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.GatewayTestRunner


GatewayTestRunner = _load_gateway_runner()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _resolve_env(config: dict, env_name: str) -> dict:
    """Resolve a named environment from comparison_targets and apply URLs to config['config']."""
    targets = config.get('config', {}).get('comparison_targets', [])
    match = next((t for t in targets if t.get('label', '').lower() == env_name.lower()), None)
    if not match:
        available = ', '.join(t['label'] for t in targets) if targets else '(none defined)'
        raise click.BadParameter(
            f"Unknown environment '{env_name}'. Available: {available}",
            param_hint="'--env'"
        )
    cfg = config.setdefault('config', {})
    cfg['base_url'] = match['url']
    if 'gateway_url' in match:
        cfg['gateway_url'] = match['gateway_url']
    if 'auth_url' in match:
        cfg['auth_url'] = match['auth_url']
    if 'ssl_verify' in match:
        cfg['ssl_verify'] = match['ssl_verify']
    if 'admin_url' in match:
        cfg['admin_url'] = match['admin_url']
    if 'admin_username' in match:
        cfg['admin_username'] = match['admin_username']
    if 'admin_password' in match:
        cfg['admin_password'] = match['admin_password']
    if 'gateway_participant_id' in match:
        cfg['gateway_participant_id'] = match['gateway_participant_id']
    if 'bg_lookup_subscriber_id' in match:
        cfg['bg_lookup_subscriber_id'] = match['bg_lookup_subscriber_id']
    if 'bg_lookup_country' in match:
        cfg['bg_lookup_country'] = match['bg_lookup_country']
    if 'bg_lookup_type' in match:
        cfg['bg_lookup_type'] = match['bg_lookup_type']
    if 'seller_mock_url' in match:
        cfg['seller_mock_url'] = match['seller_mock_url']
    return match


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

class GatewayWorkflowOrchestrator:
    """Orchestrates gateway workflow test categories defined in config/test_suite.yaml."""

    RUNNER_MAP = {
        "security":    GatewayTestRunner,
        "routing":     GatewayTestRunner,
        "status":      GatewayTestRunner,
        "policy":      GatewayTestRunner,
        "domain":      GatewayTestRunner,
        "propagation": GatewayTestRunner,
    }

    def __init__(
        self,
        config_file: str = "config/test_suite.yaml",
        test_ids: Optional[List[str]] = None,
        optional_mode: str = "skip",
    ):
        self.config_file = config_file
        self.config: dict = {}
        self.test_ids = test_ids
        self.optional_mode = optional_mode

    def load_config(self) -> bool:
        try:
            with open(self.config_file, "r", encoding="utf-8") as f:
                self.config = yaml.safe_load(f)
            info = self.config.get("suite_info", {})
            print(f"[OK] Loaded gateway workflow suite config")
            print(f"  Suite:  {info.get('name', 'Gateway Workflow Tests')}")
            print(f"  Tests:  {info.get('total_tests', '?')}")
            return True
        except Exception as e:
            print(f"[ERROR] Cannot load config: {e}")
            return False

    def _runner_kwargs(self) -> dict:
        cfg = self.config.get("config", {})
        return dict(
            auth_url=cfg.get("auth_url"),
            admin_username=cfg.get("admin_username", "admin"),
            admin_password=cfg.get("admin_password", "admin123"),
            username_field=cfg.get("auth_username_field", "username"),
            password_field=cfg.get("auth_password_field", "password"),
            token_field=cfg.get("auth_token_field", "access_token"),
            gateway_url=cfg.get("gateway_url"),
            ssl_verify=cfg.get("ssl_verify", True),
            admin_url=cfg.get("admin_url"),
            gateway_participant_id=cfg.get("gateway_participant_id"),
            bg_lookup_subscriber_id=cfg.get("bg_lookup_subscriber_id"),
            bg_lookup_country=cfg.get("bg_lookup_country"),
            bg_lookup_type=cfg.get("bg_lookup_type"),            mock_url=cfg.get('seller_mock_url'),        )

    def run_category(self, category_name: str) -> dict:
        # Locate category definition
        category = next(
            (c for c in self.config.get("categories", []) if c["name"] == category_name),
            None,
        )
        if not category:
            print(f"[ERROR] Category '{category_name}' not found in suite config")
            return {}
        if not category.get("enabled", True):
            print(f"[DISABLED] Category '{category_name}' is disabled")
            return {}

        print(f"\n{'=' * 72}")
        print(f"CATEGORY: {category['description']}")
        print(f"Tests:    {category.get('test_count', '?')}")
        print(f"{'=' * 72}")

        cfg = self.config.get("config", {})
        base_url = cfg.get("base_url", "http://localhost:8080")
        config_path = Path("config") / category["config_file"]

        runner_cls = self.RUNNER_MAP.get(category_name, GatewayTestRunner)
        runner = runner_cls(
            str(config_path),
            base_url,
            self.test_ids,
            self.optional_mode,
            **self._runner_kwargs(),
        )

        if not runner.load_config():
            return {}
        if not runner.setup():
            print(f"[ERROR] Setup failed for category '{category_name}'")
            return {}

        summary = runner.run_all_tests()

        # Save results to output/
        output_dir = Path(self.config.get("output", {}).get("directory", "output"))
        output_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_file = output_dir / f"{category_name}_results_{ts}.json"
        runner.save_results(str(out_file))
        print(f"[OK] Results saved -> {out_file}")

        runner.teardown()
        return summary

    def run_all(self) -> dict:
        print(f"\n{'*' * 72}")
        print("RUNNING COMPLETE GATEWAY WORKFLOW TEST SUITE")
        print(f"{'*' * 72}\n")

        overall = {"total": 0, "passed": 0, "failed": 0, "categories": {}}

        for cat_name in self.config.get("execution_order", []):
            s = self.run_category(cat_name)
            if s:
                overall["total"] += s["total"]
                overall["passed"] += s["passed"]
                overall["failed"] += s["failed"]
                overall["categories"][cat_name] = s

        rate = (overall["passed"] / overall["total"] * 100) if overall["total"] else 0
        print(f"\n{'*' * 72}")
        print("FINAL SUMMARY")
        print(f"{'*' * 72}")
        print(f"Total:   {overall['total']}")
        print(f"Passed:  {overall['passed']}  [OK]")
        print(f"Failed:  {overall['failed']}  [FAIL]")
        print(f"Rate:    {rate:.1f}%")
        print(f"{'*' * 72}\n")
        return overall


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

@click.group()
def cli():
    """ONDC Gateway Workflow Test Suite runner."""


@cli.command()
@click.option("--config", "config_file", default="config/test_suite.yaml",
              help="Path to main suite config YAML")
@click.option("--category", default=None,
              help="Run a single category (security, routing, status, policy, domain, propagation)")
@click.option("--all", "run_all", is_flag=True, help="Run all enabled categories")
@click.option("--test-id", "test_ids", multiple=True,
              help="Specific test ID(s) to run, e.g. WF-SEC-01.  Repeatable.")
@click.option("--optional-mode", default="skip",
              type=click.Choice(["skip", "include", "only"]),
              help="How to handle optional tests")
@click.option("--env", "-e", default="uat", metavar="NAME",
              help="Named environment from comparison_targets (e.g. uat, preprod). Defaults to 'uat'.")
def run(config_file, category, run_all, test_ids, optional_mode, env):
    """Run gateway workflow tests."""
    orchestrator = GatewayWorkflowOrchestrator(
        config_file=config_file,
        test_ids=list(test_ids) if test_ids else None,
        optional_mode=optional_mode,
    )

    if not orchestrator.load_config():
        sys.exit(1)

    target = _resolve_env(orchestrator.config, env)
    print(f"[ENV] Using environment: {target['label']} ({target['url']})")

    if run_all:
        summary = orchestrator.run_all()
    elif category:
        summary = orchestrator.run_category(category)
    else:
        print("[INFO] No --category or --all flag supplied.  Use --help for usage.")
        sys.exit(0)

    failed = summary.get("failed", 0)
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    # When run from inside gateway-workflow-suite/, adjust cwd to suite root
    os.chdir(Path(__file__).resolve().parent)
    cli()
