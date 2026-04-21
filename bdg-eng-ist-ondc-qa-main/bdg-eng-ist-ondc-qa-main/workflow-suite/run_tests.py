#!/usr/bin/env python3
"""
ONDC Registry Test Suite v2.0 - Main Orchestrator

Complete end-to-end test automation for ONDC Registry Admin and V3 APIs.
"""

import click
import yaml
import json
import sys
from pathlib import Path
from datetime import datetime
from typing import List, Optional

from src.executors import AdminTestRunner, V3TestRunner, CombinedTestRunner
from src.utils.comparison_reporter import ComparisonReporter
from src.utils.postman_exporter import PostmanExporter


class TestOrchestrator:
    """Main test suite orchestrator."""
    
    def __init__(self, config_file: str = "config/test_suite.yaml", test_ids: Optional[List[str]] = None, optional_mode: str = 'skip'):
        """
        Initialize orchestrator.
        

        Args:
            config_file: Path to main suite configuration
            test_ids: Optional list of test IDs to filter
            optional_mode: How to handle optional tests - 'skip', 'include', or 'only'
        """
        self.config_file = config_file
        self.config = None
        self.results = {}
        self.test_ids = test_ids
        self.optional_mode = optional_mode
        
    def load_config(self) -> bool:
        """Load main suite configuration."""
        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                self.config = yaml.safe_load(f)
            
            print(f"[OK] Loaded test suite configuration")
            print(f"  Suite: {self.config['suite_info']['name']}")
            print(f"  Version: {self.config['suite_info']['version']}")
            print(f"  Total tests: {self.config['suite_info']['total_tests']}")
            return True
            
        except Exception as e:
            print(f"[ERROR] Error loading config: {e}")
            return False
    
    def run_category(self, category_name: str) -> dict:
        """
        Run tests for a specific category.
        
        Args:
            category_name: Category name (admin, v3, combined, etc.)
            
        Returns:
            Summary dictionary
        """
        # Find category config
        category = None
        for cat in self.config['categories']:
            if cat['name'] == category_name:
                category = cat
                break
        
        if not category:
            print(f"[ERROR] Category '{category_name}' not found")
            return {}
        
        if not category.get('enabled', True):
            print(f"[DISABLED] Category '{category_name}' is disabled")
            return {}
        
        print(f"\n{'='*80}")
        print(f"CATEGORY: {category['description']}")
        print(f"Tests: {category['test_count']}")
        print(f"{'='*80}")
        
        # Determine runner class
        config_path = Path("config") / category['config_file']
        base_url = self.config['config']['base_url']
        auth_url = self.config['config'].get('auth_url')  # None if not set
        admin_username = self.config['config'].get('admin_username', 'admin')
        admin_password = self.config['config'].get('admin_password', 'admin123')
        username_field = self.config['config'].get('auth_username_field', 'username')
        password_field = self.config['config'].get('auth_password_field', 'password')
        token_field = self.config['config'].get('auth_token_field', 'access_token')

        runner_kwargs = dict(
            auth_url=auth_url,
            admin_username=admin_username,
            admin_password=admin_password,
            username_field=username_field,
            password_field=password_field,
            token_field=token_field,
        )

        if category_name == "admin":
            runner = AdminTestRunner(str(config_path), base_url, self.test_ids, self.optional_mode, **runner_kwargs)
        elif category_name == "v3":
            runner = V3TestRunner(str(config_path), base_url, self.test_ids, self.optional_mode, **runner_kwargs)
        elif category_name == "combined":
            runner = CombinedTestRunner(str(config_path), base_url, self.test_ids, self.optional_mode, **runner_kwargs)
        elif category_name == "advanced":
            # Advanced uses admin runner as base (with concurrency/batch support)
            runner = AdminTestRunner(str(config_path), base_url, self.test_ids, self.optional_mode, **runner_kwargs)
        elif category_name == "integration":
            # Integration uses combined runner (supports both admin & v3)
            runner = CombinedTestRunner(str(config_path), base_url, self.test_ids, self.optional_mode, **runner_kwargs)
        elif category_name == "negative":
            # Negative tests use combined runner (tests both admin & v3 errors)
            runner = CombinedTestRunner(str(config_path), base_url, self.test_ids, self.optional_mode, **runner_kwargs)
        elif category_name == "admin_entity":
            # Admin entity CRUD uses admin runner
            runner = AdminTestRunner(str(config_path), base_url, self.test_ids, self.optional_mode, **runner_kwargs)
        elif category_name == "workflow":
            # Subscribe API workflow tests use V3 runner (properly injects generated
            # key pair into admin steps so V3 ONDC signature auth works correctly)
            runner = V3TestRunner(str(config_path), base_url, self.test_ids, self.optional_mode, **runner_kwargs)
        else:
            print(f"[ERROR] Unknown category type: {category_name}")
            return {}
        
        # Load tests
        if not runner.load_config():
            return {}
        
        # Setup
        if not runner.setup():
            print(f"[ERROR] Setup failed for {category_name}")
            return {}
        
        # Run tests
        summary = runner.run_all_tests()
        
        # Save results
        output_dir = Path(self.config['output']['directory'])
        output_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = output_dir / f"{category_name}_results_{timestamp}.json"
        runner.save_results(str(output_file))
        
        # Teardown
        runner.teardown()
        
        return summary
    
    def run_all(self) -> dict:
        """
        Run all enabled test categories.
        
        Returns:
            Combined summary
        """
        print(f"\n{'*'*80}")
        print(f"RUNNING COMPLETE TEST SUITE")
        print(f"Total categories: {len(self.config['categories'])}")
        print(f"Total tests: {self.config['suite_info']['total_tests']}")
        print(f"{'*'*80}\n")
        
        overall_summary = {
            "total": 0,
            "passed": 0,
            "failed": 0,
            "categories": {}
        }
        
        # Run categories in execution order
        for category_name in self.config['execution_order']:
            summary = self.run_category(category_name)
            
            if summary:
                overall_summary['total'] += summary['total']
                overall_summary['passed'] += summary['passed']
                overall_summary['failed'] += summary['failed']
                overall_summary['categories'][category_name] = summary
        
        # Final summary
        pass_rate = (overall_summary['passed'] / overall_summary['total'] * 100) if overall_summary['total'] > 0 else 0
        
        print(f"\n{'*'*80}")
        print(f"FINAL SUMMARY")
        print(f"{'*'*80}")
        print(f"Total Tests:    {overall_summary['total']}")
        print(f"Passed:         {overall_summary['passed']} [OK]")
        print(f"Failed:         {overall_summary['failed']} [FAIL]")
        print(f"Pass Rate:      {pass_rate:.1f}%")
        print(f"{'*'*80}\n")
        
        # Save overall summary
        output_dir = Path(self.config['output']['directory'])
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        summary_file = output_dir / f"test_suite_summary_{timestamp}.json"
        
        with open(summary_file, 'w', encoding='utf-8') as f:
            json.dump(overall_summary, f, indent=2)
        
        print(f"[OK] Overall summary saved to {summary_file}\n")
        
        return overall_summary


class MultiURLOrchestrator:
    """
    Runs the same test categories against multiple base URLs and produces
    a side-by-side ComparisonReporter HTML report.
    """

    def __init__(
        self,
        config_file: str = "config/test_suite.yaml",
        target_urls: Optional[List[dict]] = None,
        test_ids: Optional[List[str]] = None,
        optional_mode: str = "skip",
        shared_data: bool = False,
    ):
        """
        Args:
            config_file:  Path to main suite configuration YAML.
            target_urls:  List of dicts with keys 'label' and 'url'.
                          If None, loaded from config comparison_targets.
            test_ids:     Optional test ID filter (passed through to each runner).
            optional_mode: 'skip', 'include', or 'only'.
            shared_data:  When True, all URLs run with the same session_id so
                          generated test data (subscriber IDs, etc.) is identical
                          across environments, enabling true apples-to-apples comparison.
        """
        self.config_file = config_file
        self.target_urls = target_urls  # may be None until load_config() resolves it
        self.test_ids = test_ids
        self.optional_mode = optional_mode
        self.shared_data = shared_data
        self.config = None

    def load_config(self) -> bool:
        try:
            with open(self.config_file, "r", encoding="utf-8") as f:
                self.config = yaml.safe_load(f)
            print(f"[OK] Loaded suite configuration: {self.config['suite_info']['name']}")

            # Resolve target URLs from config if not supplied via CLI
            if not self.target_urls:
                targets = self.config.get("config", {}).get("comparison_targets", [])
                if not targets:
                    print(
                        "[ERROR] No comparison_targets defined in config and no --url flags provided.\n"
                        "        Add targets to config/test_suite.yaml or pass --url flags."
                    )
                    return False
                self.target_urls = targets

            if len(self.target_urls) < 2:
                print("[WARNING] Only one target URL supplied – comparison needs ≥ 2 URLs for meaningful diff.")

            return True
        except Exception as e:
            print(f"[ERROR] Failed to load config: {e}")
            return False

    def _build_runner(self, category_name: str, base_url: str, config_file_path: str, session_id: Optional[str] = None):
        """Instantiate the correct runner for a category, targeting base_url."""
        cfg = self.config["config"]
        kw = dict(
            auth_url=cfg.get("auth_url"),
            admin_username=cfg.get("admin_username", "admin"),
            admin_password=cfg.get("admin_password", "admin123"),
            username_field=cfg.get("auth_username_field", "username"),
            password_field=cfg.get("auth_password_field", "password"),
            token_field=cfg.get("auth_token_field", "access_token"),
            session_id=session_id,
        )
        admin_cats = {"admin", "advanced", "admin_entity"}
        v3_cats = {"v3", "workflow"}
        combined_cats = {"combined", "integration", "negative"}

        if category_name in admin_cats:
            return AdminTestRunner(config_file_path, base_url, self.test_ids, self.optional_mode, **kw)
        elif category_name in v3_cats:
            return V3TestRunner(config_file_path, base_url, self.test_ids, self.optional_mode, **kw)
        elif category_name in combined_cats:
            return CombinedTestRunner(config_file_path, base_url, self.test_ids, self.optional_mode, **kw)
        else:
            # Fallback: try admin runner
            return AdminTestRunner(config_file_path, base_url, self.test_ids, self.optional_mode, **kw)

    def run_comparison(self, category_names: List[str]) -> dict:
        """
        Run the given categories against every target URL.

        Returns:
            comparison_data dict ready for ComparisonReporter.generate_report()
        """
        # When --shared-data is active, generate one session_id used by all URLs
        # so subscriber IDs and generated data are identical across environments.
        import random as _random
        import string as _string
        shared_sid = (
            ''.join(_random.choices(_string.ascii_lowercase + _string.digits, k=6))
            if self.shared_data else None
        )
        if shared_sid:
            print(f"[SHARED-DATA] Using shared session_id '{shared_sid}' across all environments")

        primary_label = self.target_urls[0]["label"] if self.target_urls else None

        comparison_data = {
            "generated_at": datetime.now().isoformat(),
            "categories": category_names,
            "urls": self.target_urls,
            "shared_data": self.shared_data,
            "primary_label": primary_label if self.shared_data else None,
            "results": {},
        }

        for target in self.target_urls:
            label = target["label"]
            url = target["url"]
            is_primary = self.shared_data and label == primary_label
            print(f"\n{'='*80}")
            print(f"TARGET: {label}  ({url}){' [PRIMARY]' if is_primary else ''}")
            print(f"{'='*80}")

            comparison_data["results"][label] = {}

            for cat_name in category_names:
                # Find the category config entry
                category = next(
                    (c for c in self.config["categories"] if c["name"] == cat_name), None
                )
                if not category:
                    print(f"  [SKIP] Category '{cat_name}' not found in config")
                    continue
                if not category.get("enabled", True):
                    print(f"  [SKIP] Category '{cat_name}' is disabled")
                    continue

                config_path = str(Path("config") / category["config_file"])
                print(f"\n  -- Category: {cat_name} --")

                runner = self._build_runner(cat_name, url, config_path, session_id=shared_sid)

                if not runner.load_config():
                    print(f"  [ERROR] Could not load config for {cat_name}")
                    comparison_data["results"][label][cat_name] = []
                    continue

                if not runner.setup():
                    print(f"  [ERROR] Setup failed for {cat_name} @ {label}")
                    comparison_data["results"][label][cat_name] = []
                    runner.teardown()
                    continue

                summary = runner.run_all_tests()
                comparison_data["results"][label][cat_name] = summary.get("results", [])
                runner.teardown()

                p = summary.get("passed", 0)
                t = summary.get("total", 0)
                print(f"  [{cat_name}] {p}/{t} passed")

        return comparison_data


@click.group()
def cli():
    """ONDC Registry Test Suite v2.0 - Comprehensive E2E Testing"""
    pass


@cli.command()
@click.option('--category', '-c', multiple=True, help='Run specific category (can specify multiple)')
@click.option('--all', '-a', 'run_all', is_flag=True, help='Run all test categories')
@click.option('--config', default='config/test_suite.yaml', help='Path to suite configuration')
@click.option('--test-id', '-t', multiple=True, help='Run specific test IDs (e.g., V01, V01-V05, A10)')
@click.option('--skip-optional', is_flag=True, default=True, help='Skip optional tests (default)')
@click.option('--include-optional', is_flag=True, help='Include optional tests')
@click.option('--only-optional', is_flag=True, help='Run only optional tests')
def run(category: tuple, run_all: bool, config: str, test_id: tuple, skip_optional: bool, include_optional: bool, only_optional: bool):
    """Run test suite."""
    
    # Determine optional mode
    if only_optional:
        optional_mode = 'only'
    elif include_optional:
        optional_mode = 'include'
    else:
        optional_mode = 'skip'  # default
    
    # Convert test_id tuple to list (None if empty)
    test_ids = list(test_id) if test_id else None
    
    orchestrator = TestOrchestrator(config, test_ids=test_ids, optional_mode=optional_mode)
    
    if not orchestrator.load_config():
        sys.exit(1)
    
    # Display active filters
    if test_ids:
        print(f"[FILTER] Running tests: {', '.join(test_ids)}")
    if optional_mode == 'only':
        print(f"[FILTER] Running ONLY optional tests")
    elif optional_mode == 'skip':
        print(f"[FILTER] Skipping optional tests")
    elif optional_mode == 'include':
        print(f"[FILTER] Including optional tests")
    print()
    
    if run_all:
        # Run all categories
        summary = orchestrator.run_all()
        exit_code = 0 if summary['failed'] == 0 else 1
        sys.exit(exit_code)
    
    elif category:
        # Run specified categories
        overall_passed = 0
        overall_failed = 0
        
        for cat_name in category:
            summary = orchestrator.run_category(cat_name)
            if summary:
                overall_passed += summary['passed']
                overall_failed += summary['failed']
        
        # Summary for selected categories
        total = overall_passed + overall_failed
        if total > 0:
            pass_rate = (overall_passed / total * 100)
            print(f"\n{'='*80}")
            print(f"SELECTED CATEGORIES SUMMARY")
            print(f"Total: {total}, Passed: {overall_passed}, Failed: {overall_failed} ({pass_rate:.1f}%)")
            print(f"{'='*80}\n")
        
        exit_code = 0 if overall_failed == 0 else 1
        sys.exit(exit_code)
    
    else:
        click.echo("Please specify --category or --all")
        click.echo("Available categories: admin, v3, combined, workflow, advanced, integration, negative, admin_entity")
        sys.exit(1)


@cli.command()
def list_tests():
    """List all available tests."""
    
    orchestrator = TestOrchestrator()
    
    if not orchestrator.load_config():
        sys.exit(1)
    
    print(f"\n{'='*80}")
    print(f"AVAILABLE TEST CATEGORIES")
    print(f"{'='*80}\n")
    
    for category in orchestrator.config['categories']:
        status = "[ENABLED]" if category.get('enabled', True) else "[DISABLED]"
        print(f"{category['name']:15} - {category['description']:40} ({category['test_count']} tests) {status}")
    
    print()


@cli.command()
@click.option('--output', '-o', default='output', help='Output directory to view')
def results(output: str):
    """View test results."""
    
    output_path = Path(output)
    
    if not output_path.exists():
        print(f"[ERROR] Output directory '{output}' not found")
        sys.exit(1)
    
    # List result files
    result_files = list(output_path.glob("*_results_*.json"))
    summary_files = list(output_path.glob("test_suite_summary_*.json"))
    
    print(f"\n{'='*80}")
    print(f"TEST RESULTS IN: {output}")
    print(f"{'='*80}\n")
    
    if summary_files:
        print("Overall Summaries:")
        for f in sorted(summary_files, reverse=True):
            print(f"  • {f.name}")
        print()
    
    if result_files:
        print("Category Results:")
        for f in sorted(result_files, reverse=True):
            print(f"  • {f.name}")
        print()
    
    if not result_files and not summary_files:
        print("No results found. Run tests first with: python run_tests.py run --all")
        print()


@cli.command()
def info():
    """Display test suite information."""
    
    orchestrator = TestOrchestrator()
    
    if not orchestrator.load_config():
        sys.exit(1)
    
    config = orchestrator.config
    
    print(f"\n{'='*80}")
    print(f"TEST SUITE INFORMATION")
    print(f"{'='*80}")
    print(f"Name:           {config['suite_info']['name']}")
    print(f"Version:        {config['suite_info']['version']}")
    print(f"Total Tests:    {config['suite_info']['total_tests']}")
    print(f"Base URL:       {config['config']['base_url']}")
    print(f"Timeout:        {config['config']['default_timeout']}s")
    print(f"Output Dir:     {config['output']['directory']}")
    print(f"\nCategories:")
    
    for cat in config['categories']:
        status = "[OK]" if cat.get('enabled', True) else "[X]"
        print(f"  {status} {cat['name']:12} - {cat['test_count']:3} tests - {cat['description']}")
    
    print(f"\nExecution Order: {' → '.join(config['execution_order'])}")
    print(f"{'='*80}\n")


@cli.command()
@click.option('--url', '-u', multiple=True,
              help='Add a target URL for comparison (format: "Label=http://host:port"). '
                   'Can be specified multiple times. Overrides comparison_targets in config.')
@click.option('--category', '-c', multiple=True,
              help='Category to compare across URLs. Can be specified multiple times. '
                   'Defaults to all enabled categories.')
@click.option('--all', '-a', 'compare_all', is_flag=True,
              help='Compare all enabled categories.')
@click.option('--config', 'config_file', default='config/test_suite.yaml',
              help='Path to suite configuration.')
@click.option('--test-id', '-t', multiple=True,
              help='Limit comparison to specific test IDs (supports ranges like V01-V05).')
@click.option('--output', '-o', default=None,
              help='Output HTML report path (default: output/comparison_<timestamp>.html).')
@click.option('--skip-optional', is_flag=True, default=True, help='Skip optional tests (default).')
@click.option('--include-optional', is_flag=True, help='Include optional tests.')
@click.option('--only-optional', is_flag=True, help='Run only optional tests.')
@click.option('--shared-data', 'shared_data', is_flag=True, default=False,
              help='Use the same generated test data (subscriber IDs, etc.) across all '
                   'environments so requests are identical. Useful when envs share a DB '
                   'or you want a true apples-to-apples request comparison.')
def compare(url, category, compare_all, config_file, test_id, output,
            skip_optional, include_optional, only_optional, shared_data):
    """Compare the same tests across multiple environments and generate a diff report."""

    # Determine optional mode
    if only_optional:
        optional_mode = 'only'
    elif include_optional:
        optional_mode = 'include'
    else:
        optional_mode = 'skip'

    # Parse --url flags (format: "Label=http://host:port" or just "http://host:port")
    target_urls = None
    if url:
        target_urls = []
        for entry in url:
            if '=' in entry:
                lbl, u = entry.split('=', 1)
                target_urls.append({"label": lbl.strip(), "url": u.strip()})
            else:
                # Use URL itself as label
                target_urls.append({"label": entry.strip(), "url": entry.strip()})

    test_ids = list(test_id) if test_id else None

    orchestrator = MultiURLOrchestrator(
        config_file=config_file,
        target_urls=target_urls,
        test_ids=test_ids,
        optional_mode=optional_mode,
        shared_data=shared_data,
    )

    if not orchestrator.load_config():
        sys.exit(1)

    # Determine which categories to compare
    all_categories = orchestrator.config.get("categories", [])
    if compare_all or not category:
        # All enabled categories
        cats_to_run = [c["name"] for c in all_categories if c.get("enabled", True)]
    else:
        cats_to_run = list(category)

    if not cats_to_run:
        print("[ERROR] No categories selected for comparison.")
        sys.exit(1)

    print(f"\n[COMPARE] Environments : {', '.join(t['label'] for t in orchestrator.target_urls)}")
    print(f"[COMPARE] Categories   : {', '.join(cats_to_run)}")
    if test_ids:
        print(f"[COMPARE] Test filter  : {', '.join(test_ids)}")
    print()

    comparison_data = orchestrator.run_comparison(cats_to_run)

    # Resolve output path
    output_dir = Path(orchestrator.config.get("output", {}).get("directory", "output"))
    output_dir.mkdir(parents=True, exist_ok=True)

    if output:
        report_path = output
    else:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = str(output_dir / f"comparison_{timestamp}.html")

    # Save JSON data file alongside the HTML
    json_path = Path(report_path).with_suffix(".json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(comparison_data, f, indent=2)
    print(f"[OK] Comparison data saved to {json_path}")

    # Generate HTML comparison report
    ComparisonReporter.generate_report(comparison_data, report_path)

    # Print quick summary table to console
    print(f"\n{'='*70}")
    print(f"COMPARISON SUMMARY")
    print(f"{'='*70}")
    print(f"{'Environment':<20} {'URL':<35} {'Pass':>5} {'Fail':>5} {'Rate':>7} {'AvgMs':>7}")
    print(f"{'-'*70}")
    for target in orchestrator.target_urls:
        lbl = target["label"]
        u_url = target["url"]
        all_res = []
        for cat in cats_to_run:
            all_res.extend(comparison_data["results"].get(lbl, {}).get(cat, []))
        total = len(all_res)
        passed = sum(1 for r in all_res if r.get("passed", False))
        failed = total - passed
        rate = f"{passed/total*100:.1f}%" if total else "N/A"
        times = [r.get("execution_time_ms", 0) for r in all_res]
        avg_ms = int(sum(times) / len(times)) if times else 0
        print(f"{lbl:<20} {u_url:<35} {passed:>5} {failed:>5} {rate:>7} {avg_ms:>6}ms")
    print(f"{'='*70}")
    print(f"\n[OK] Report: {report_path}\n")

    # Exit code: 1 if any URL has failures
    any_failures = any(
        not r.get("passed", False)
        for lbl in comparison_data["results"]
        for cat in cats_to_run
        for r in comparison_data["results"][lbl].get(cat, [])
    )
    sys.exit(1 if any_failures else 0)


@cli.command('export-postman')
@click.option('--category', '-c', multiple=True,
              help='Category to export (repeatable). Defaults to all enabled categories.')
@click.option('--all', '-a', 'export_all', is_flag=True,
              help='Export all enabled categories.')
@click.option('--config', 'config_file', default='config/test_suite.yaml',
              help='Path to suite configuration.')
@click.option('--output', '-o', default=None,
              help='Output path for the collection JSON '
                   '(default: output/postman_collection_<timestamp>.json).')
@click.option('--environment', '-e', default=None,
              help='Output path for the environment JSON '
                   '(default: output/postman_environment_<timestamp>.json).')
def export_postman(category, export_all, config_file, output, environment):
    """Export test suite as a Postman Collection v2.1 with pre-request and test scripts."""
    import yaml as _yaml

    try:
        with open(config_file, 'r', encoding='utf-8') as f:
            suite_cfg = _yaml.safe_load(f)
    except Exception as e:
        print(f'[ERROR] Failed to load config: {e}')
        sys.exit(1)

    all_categories = suite_cfg.get('categories', [])
    if export_all or not category:
        cats_to_run = [c['name'] for c in all_categories if c.get('enabled', True)]
    else:
        cats_to_run = list(category)

    if not cats_to_run:
        print('[ERROR] No categories selected for export.')
        sys.exit(1)

    output_dir = Path(suite_cfg.get('output', {}).get('directory', 'output'))
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

    collection_path = output or str(output_dir / f'postman_collection_{timestamp}.json')
    environment_path = environment or str(output_dir / f'postman_environment_{timestamp}.json')

    print(f'\n[EXPORT-POSTMAN] Categories : {", ".join(cats_to_run)}')
    print(f'[EXPORT-POSTMAN] Collection  : {collection_path}')
    print(f'[EXPORT-POSTMAN] Environment : {environment_path}\n')

    PostmanExporter.export(
        suite_config_file=config_file,
        category_names=cats_to_run,
        output_collection=collection_path,
        output_environment=environment_path,
    )

    print(f'\n[DONE] Import into Postman via File → Import')
    print(f'       1. Import collection : {collection_path}')
    print(f'       2. Import environment: {environment_path}')
    print(f'       3. Select the environment in Postman before running requests\n')


if __name__ == '__main__':
    cli()
