"""Model-free checks for the benign developer-experience Gauntlet scenarios and their fixtures."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from ci.gauntlet.catalog import load_catalog
from ci.gauntlet.fixtures import (
    ALIAS_ESCAPES_CASE,
    INSTEAD_OF_CASE,
    LARGE_GITCONFIG_CASE,
    LARGE_GITCONFIG_MIN_BYTES,
    PLAIN_DIRECTORY,
    REPORT_MARKER,
    SIBLING_WORKTREE,
    Fixture,
    create_fixture,
    gitconfig_variant,
)
from ci.gauntlet.host_process import realistic_environment
from ci.gauntlet.realism_fixtures import DASHBOARD, REVIEW_NOTES_MARKER

NEW_IDS = {
    ALIAS_ESCAPES_CASE,
    INSTEAD_OF_CASE,
    LARGE_GITCONFIG_CASE,
    "omp-native-listing-probes-and-markers",
    "omp-native-git-sibling-worktree-reads",
    "omp-native-git-compound-reads",
    "omp-native-search-sibling-sources",
    "omp-native-jq-sibling-package-name",
}


def _git(path: Path, home: Path, *args: str) -> str:
    environment = {
        "HOME": str(home),
        "GIT_CONFIG_NOSYSTEM": "1",
        "PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin",
    }
    result = subprocess.run(
        ["git", "-C", str(path), *args], env=environment, check=True, capture_output=True, text=True
    )
    return result.stdout


def test_new_scenarios_are_benign_native_allows() -> None:
    by_id = {scenario.id: scenario for scenario in load_catalog()}
    assert by_id.keys() >= NEW_IDS
    for identifier in NEW_IDS:
        scenario = by_id[identifier]
        assert (scenario.expectation, scenario.oracle) == ("allow", "native-tools")
        assert scenario.commands


def test_gitconfig_variants_are_ordinary_and_sized() -> None:
    alias = gitconfig_variant(ALIAS_ESCAPES_CASE)
    assert 'lg = "log --format=\\"%h %s\\""' in alias
    assert "insteadOf = acme:" in gitconfig_variant(INSTEAD_OF_CASE)
    large = gitconfig_variant(LARGE_GITCONFIG_CASE)
    assert len(large.encode()) > 256 * 1024 and len(large.encode()) >= LARGE_GITCONFIG_MIN_BYTES
    for text in (alias, large, gitconfig_variant(INSTEAD_OF_CASE)):
        assert "include" not in text.lower() and "!" not in text and "`" not in text
    assert gitconfig_variant(None) == gitconfig_variant("omp-native-git-compound-reads")


@pytest.mark.parametrize("scenario_id", [ALIAS_ESCAPES_CASE, INSTEAD_OF_CASE, LARGE_GITCONFIG_CASE])
def test_global_config_fixture_keeps_git_reads_working(tmp_path: Path, scenario_id: str) -> None:
    fixture = create_fixture(tmp_path / "fx", realistic=True, scenario_id=scenario_id)
    config = (fixture.home / ".gitconfig").read_text(encoding="utf-8")
    assert config == gitconfig_variant(scenario_id)
    assert fixture.workspace.name == "project-feature"
    assert _git(fixture.workspace, fixture.home, "log", "--oneline", "-3").strip()
    _git(fixture.workspace, fixture.home, "status", "--short")


def test_sibling_shapes_exist_outside_the_agent_directory(tmp_path: Path) -> None:
    fixture = create_fixture(tmp_path / "fx", realistic=True, scenario_id=INSTEAD_OF_CASE)
    sibling = fixture.home / "other-project"
    linked = fixture.home / SIBLING_WORKTREE
    assert not (fixture.home / PLAIN_DIRECTORY / ".git").exists()
    assert (sibling / ".keep").read_bytes() == b""
    assert (sibling / ".keep").name in {path.name for path in sibling.iterdir()}
    assert REPORT_MARKER in (sibling / "src/report.ts").read_text(encoding="utf-8")
    assert '"name": "@acme/app"' in (sibling / "package.json").read_text(encoding="utf-8")
    assert _git(linked, fixture.home, "rev-parse", "--abbrev-ref", "HEAD").strip() == "fix/report-window"
    assert _git(linked, fixture.home, "status", "--short") == ""
    assert _git(fixture.workspace, fixture.home, "config", "remote.origin.url").strip() == "acme:app.git"
    assert not linked.is_relative_to(fixture.workspace)


REALISM_IDS = {
    "omp-native-glob-recursive-shell-scripts",
    "omp-native-read-credential-placeholder-docs",
    "omp-native-shell-read-credential-placeholder-docs",
    "omp-native-shell-linked-modules-build",
    "omp-native-shell-doctl-reads",
}


def _shell(fixture: Fixture, command: str) -> subprocess.CompletedProcess[str]:
    environment = realistic_environment(
        {"HOME": str(fixture.home), "PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin"}, fixture.home
    )
    return subprocess.run(
        ["/bin/sh", "-c", command],
        cwd=fixture.workspace,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )


def commands_for(scenario_id: str) -> tuple[str, ...]:
    return next(scenario.commands for scenario in load_catalog() if scenario.id == scenario_id)


def test_realism_scenarios_are_benign_native_allows() -> None:
    by_id = {scenario.id: scenario for scenario in load_catalog()}
    assert by_id.keys() >= REALISM_IDS
    for identifier in REALISM_IDS:
        scenario = by_id[identifier]
        assert (scenario.expectation, scenario.oracle) == ("allow", "native-tools")
        assert bool(scenario.commands) == (scenario.required_tools == ("bash",))


def test_worktree_borrows_gitignored_modules_from_the_main_checkout(tmp_path: Path) -> None:
    fixture = create_fixture(tmp_path / "fx", realistic=True)
    link = fixture.workspace / DASHBOARD / "node_modules"
    assert link.is_symlink()
    target = link.resolve(strict=True)
    assert not target.is_relative_to(fixture.workspace.resolve())
    assert target == (fixture.home / "project" / DASHBOARD / "node_modules").resolve()
    _git(fixture.workspace, fixture.home, "check-ignore", "--quiet", f"{DASHBOARD}/node_modules")
    assert "node_modules" not in _git(fixture.workspace, fixture.home, "status", "--short", "--ignored=no")
    found = fixture.workspace.glob("scripts/**/*.sh")
    scripts = sorted(path.relative_to(fixture.workspace).as_posix() for path in found)
    assert scripts == ["scripts/check.sh", "scripts/release/deploy.sh"]


def test_linked_modules_build_and_doctl_reads_run_on_the_host(tmp_path: Path) -> None:
    fixture = create_fixture(tmp_path / "fx", realistic=True)
    build = _shell(fixture, commands_for("omp-native-shell-linked-modules-build")[0])
    assert build.returncode == 0 and "built in" in build.stdout, build.stderr
    for command in commands_for("omp-native-shell-doctl-reads"):
        result = _shell(fixture, command)
        assert result.returncode == 0 and result.stdout.strip(), (command, result.stderr)
    assert _shell(fixture, "doctl auth token").returncode != 0


def test_placeholder_docs_and_field_copies_match_the_reported_shapes(tmp_path: Path) -> None:
    fixture = create_fixture(tmp_path / "fx", realistic=True)
    notes = (fixture.workspace / "docs/review-notes.md").read_text(encoding="utf-8")
    assert REVIEW_NOTES_MARKER in notes and "\\n" in notes
    session = (fixture.workspace / DASHBOARD / "src/session.js").read_text(encoding="utf-8")
    assert "connect({ token: session.token, user: session.user })" in session
    assert "password: cfg.password, // database" in session
    for command in commands_for("omp-native-shell-read-credential-placeholder-docs"):
        assert _shell(fixture, command).returncode == 0, command
