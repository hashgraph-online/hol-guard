"""Run generated CLI and MCP tests against an independent, actually registered source tree."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.extension_builder.kit import build_kit
from codex_plugin_scanner.guard.extension_builder.models import make_discovery, make_operation
from codex_plugin_scanner.guard.extension_builder.render_native import test_path as generated_test_path
from codex_plugin_scanner.guard.extension_builder.repository_write import apply_kit
from codex_plugin_scanner.guard.extension_builder.review import default_review
from tests.extension_builder_support import REPOSITORY, make_kit


def _copy_source_tree(destination: Path) -> None:
    ignored = shutil.ignore_patterns("__pycache__", "*.pyc", "node_modules")
    for name in ("src", "contracts", "contributions", "docs/guard/contracts", "scripts/release"):
        shutil.copytree(REPOSITORY / name, destination / name, ignore=ignored)
    shutil.copyfile(REPOSITORY / "pyproject.toml", destination / "pyproject.toml")
    (destination / "tests").mkdir()


@pytest.mark.parametrize("maximum_inventory", [False, True])
def test_generated_contributions_load_and_run_their_native_cases(tmp_path: Path, maximum_inventory: bool) -> None:
    repository = tmp_path / "independent-checkout"
    _copy_source_tree(repository)
    cli = make_kit(tmp_path, reviewed=True)
    if maximum_inventory:
        operations = tuple(make_operation("cli", path=(f"operation{i}",), evidence={}) for i in range(256))
        discovery = make_discovery(cli.discovery.metadata, "cli", "0" * 64, operations, cli.discovery.limitations)
        cli = build_kit(discovery, default_review(discovery))
    mcp = make_kit(tmp_path, "mcp", reviewed=True)
    apply_kit(cli, repository, write=True)
    apply_kit(mcp, repository, write=True)
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(repository / "src")
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    for variable in list(environment):
        if variable.startswith(("COV_CORE_", "COVERAGE_")):
            environment.pop(variable)
    for variable in (
        "PYTEST_ADDOPTS",
        "COVERAGE_PROCESS_START",
        "GUARD_PYTEST_DURATION_OUTPUT",
        "GUARD_PYTEST_UNDER_COVERAGE",
    ):
        environment.pop(variable, None)
    staging = subprocess.run(
        [sys.executable, str(repository / "scripts/release/stage_guard_cloud_review_artifacts.py")],
        cwd=repository,
        env=environment,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert staging.returncode == 0, staging.stdout + staging.stderr
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            generated_test_path(cli.discovery.metadata),
            generated_test_path(mcp.discovery.metadata),
        ],
        cwd=repository,
        env=environment,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "passed" in result.stdout
    assert not list(repository.glob(".hol-guard-*"))
