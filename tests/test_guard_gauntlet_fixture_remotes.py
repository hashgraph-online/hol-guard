from __future__ import annotations

import subprocess
from pathlib import Path

from ci.gauntlet.fixture_remotes import REMOTE_URLS_CASE, REMOTE_URLS_ORIGIN
from ci.gauntlet.fixtures import ALIAS_ESCAPES_CASE, create_fixture


def _remote_urls(fixture_workspace: Path, home: Path) -> subprocess.CompletedProcess[str]:
    environment = {
        "HOME": str(home),
        "GIT_CONFIG_NOSYSTEM": "1",
        "PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin",
    }
    return subprocess.run(
        ["git", "-C", str(fixture_workspace), "config", "--get-regexp", "remote.*url"],
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )


def test_remote_url_scenario_checkout_has_a_remote_to_report(tmp_path: Path) -> None:
    fixture = create_fixture(tmp_path / "fx", realistic=True, scenario_id=REMOTE_URLS_CASE)
    # The scenario's own command: with no remote it exits 1 and the case is a tool failure.
    urls = _remote_urls(fixture.workspace, fixture.home)
    assert urls.returncode == 0, urls.stderr
    assert urls.stdout.strip() == f"remote.origin.url {REMOTE_URLS_ORIGIN}"


def test_other_scenarios_keep_a_checkout_without_a_remote(tmp_path: Path) -> None:
    fixture = create_fixture(tmp_path / "fx", realistic=True, scenario_id=ALIAS_ESCAPES_CASE)
    assert _remote_urls(fixture.workspace, fixture.home).returncode == 1
