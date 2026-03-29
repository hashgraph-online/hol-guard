"""Tests for operational-security checks."""

import tempfile
from pathlib import Path

from codex_plugin_scanner.checks.operational_security import (
    check_dependabot_configured,
    check_dependency_lockfiles,
    run_operational_security_checks,
)


def _write_file(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def test_operational_checks_not_applicable_without_surface():
    with tempfile.TemporaryDirectory() as tmpdir:
        results = run_operational_security_checks(Path(tmpdir))
        assert sum(check.points for check in results) == 0
        assert sum(check.max_points for check in results) == 0


def test_operational_checks_pass_for_hardened_workflows():
    with tempfile.TemporaryDirectory() as tmpdir:
        plugin_dir = Path(tmpdir)
        _write_file(
            plugin_dir / ".github" / "workflows" / "ci.yml",
            """
            on:
              pull_request:
              push:
                branches: [main]
            jobs:
              test:
                permissions:
                  contents: read
                runs-on: ubuntu-latest
                steps:
                  - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567
            """,
        )
        _write_file(
            plugin_dir / ".github" / "dependabot.yml",
            """
            version: 2
            updates:
              - package-ecosystem: "github-actions"
                directory: "/"
                schedule:
                  interval: "weekly"
            """,
        )
        _write_file(plugin_dir / "package.json", '{"name": "fixture", "version": "1.0.0"}')
        _write_file(plugin_dir / "package-lock.json", '{"name": "fixture", "lockfileVersion": 3}')

        results = run_operational_security_checks(plugin_dir)

        assert all(check.passed for check in results)
        assert sum(check.points for check in results) == 20
        assert sum(check.max_points for check in results) == 20


def test_operational_checks_flag_common_workflow_risks():
    with tempfile.TemporaryDirectory() as tmpdir:
        plugin_dir = Path(tmpdir)
        _write_file(
            plugin_dir / ".github" / "workflows" / "ci.yml",
            """
            on:
              pull_request_target:
            permissions: write-all
            jobs:
              test:
                runs-on: ubuntu-latest
                steps:
                  - uses: actions/checkout@v5
                    with:
                      ref: ${{ github.event.pull_request.head.sha }}
            """,
        )
        _write_file(plugin_dir / "package.json", '{"name": "fixture", "version": "1.0.0"}')

        results = run_operational_security_checks(plugin_dir)
        names = {check.name: check for check in results}

        assert names["Third-party GitHub Actions pinned to SHAs"].passed is False
        assert names["No write-all GitHub Actions permissions"].passed is False
        assert names["No privileged untrusted checkout patterns"].passed is False
        assert names["Dependabot configured for automation surfaces"].passed is False
        assert names["Dependency manifests have lockfiles"].passed is False


def test_dependabot_accepts_single_quoted_github_actions_ecosystem():
    with tempfile.TemporaryDirectory() as tmpdir:
        plugin_dir = Path(tmpdir)
        _write_file(
            plugin_dir / ".github" / "workflows" / "ci.yml",
            """
            on:
              push:
            jobs:
              test:
                runs-on: ubuntu-latest
                steps:
                  - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567
            """,
        )
        _write_file(
            plugin_dir / ".github" / "dependabot.yml",
            """
            version: 2
            updates:
              - package-ecosystem: 'github-actions'
                directory: "/"
                schedule:
                  interval: weekly
            """,
        )

        result = check_dependabot_configured(plugin_dir)

        assert result.passed is True
        assert result.points == 3


def test_dependency_lockfiles_accept_pinned_requirements_with_pyproject():
    with tempfile.TemporaryDirectory() as tmpdir:
        plugin_dir = Path(tmpdir)
        _write_file(plugin_dir / "pyproject.toml", '[project]\nname = "fixture"\nversion = "1.0.0"\n')
        _write_file(plugin_dir / "requirements.txt", "requests==2.32.3\nrich==13.9.4\n")

        result = check_dependency_lockfiles(plugin_dir)

        assert result.passed is True
        assert result.points == 3
