"""Keep the policy domain independent and inside native CI and coverage gates."""

from __future__ import annotations

import fnmatch
from pathlib import Path

import pytest
import yaml

from scripts.ci.rust_test_archive_inputs import Inputs

ROOT = Path(__file__).resolve().parents[1]
BUNDLE = ROOT / "rust/crates/guard-policy-bundle"


def test_policy_domain_does_not_depend_on_runtime_command_or_scanner() -> None:
    inputs = Inputs(ROOT)
    inputs.package(BUNDLE / "Cargo.toml")
    packages = {manifest.parent.name for manifest in inputs.packages}
    assert {"guard-policy-bundle", "guard-policy-snapshot", "guard-contracts"} <= packages
    assert packages.isdisjoint({"guard-runtime", "guard-command", "guard-scanner"})


@pytest.mark.parametrize("partition", ["core", "runtime"])
def test_policy_domain_sources_and_fixtures_are_bound_to_consuming_archives(partition: str) -> None:
    inputs = Inputs(ROOT)
    files = inputs.collect(partition)
    assert BUNDLE / "Cargo.toml" in inputs.packages
    for source in (BUNDLE / "src").glob("*.rs"):
        assert source in files
    for fixture in (BUNDLE / "tests/fixtures").iterdir():
        assert fixture in files


def test_moved_policy_domain_keeps_the_mdm_conformance_gate() -> None:
    workflow = yaml.safe_load((ROOT / ".github/workflows/mdm-local-lab.yml").read_text())
    triggers = workflow.get("on", workflow.get(True))
    patterns = triggers["pull_request"]["paths"]
    for path in [*BUNDLE.rglob("*.rs"), BUNDLE / "Cargo.toml"]:
        relative = path.relative_to(ROOT).as_posix()
        assert any(fnmatch.fnmatchcase(relative, pattern) for pattern in patterns), relative


def test_moved_domain_remains_production_and_tests_remain_tests_in_sonar() -> None:
    properties = dict(
        line.split("=", 1)
        for line in (ROOT / "sonar-project.properties").read_text().splitlines()
        if "=" in line and not line.startswith("#")
    )
    exclusions = properties["sonar.exclusions"].split(",")
    test_patterns = properties["sonar.test.inclusions"].split(",")
    for path in (BUNDLE / "src").glob("*.rs"):
        relative = path.relative_to(ROOT).as_posix()
        excluded = any(fnmatch.fnmatchcase(relative, pattern) for pattern in exclusions)
        test = any(fnmatch.fnmatchcase(relative, pattern) for pattern in test_patterns)
        assert excluded == test == path.name.endswith("_tests.rs"), relative


def test_quality_lints_and_formats_the_boundary_contracts_without_dropping_existing_paths() -> None:
    action = yaml.safe_load((ROOT / ".github/actions/ci-job-quality/action.yml").read_text())
    checks = {
        step["name"]: step["run"]
        for step in action["runs"]["steps"]
        if step.get("name") in {"Lint production sources", "Check formatting for production sources"}
    }
    assert len(checks) == 2
    required = {
        "src/",
        "tests/test_guard_durable_io.py",
        "tests/test_guard_managed_install_context.py",
        "tests/test_guard_private_file_io.py",
        "tests/test_native_offline_cache.py",
        "tests/test_native_policy_test_support.py",
        "tests/test_ci_native_evaluator_cache.py",
        "tests/test_policy_bundle_crate_boundary.py",
        "tests/test_ci_command_source_inputs_manifest.py",
    }
    for command in checks.values():
        assert required <= set(command.replace("\\\n", " ").split())
