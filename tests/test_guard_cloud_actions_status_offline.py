"""`cloud-actions status --offline` reads only the saved profile file.

It never opens the secret store, which can take a lock, fix permissions or
rewrite the key, so the command stays a read that changes nothing on disk.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli.cloud_actions_session import CloudActionsSessionStore
from tests.cloud_actions_login_support import (
    Browser,
    FakeCloud,
    _cli,
    _json_out,
    _login,
    browser_fixture,  # noqa: F401 -- shared fixture
    cloud_fixture,  # noqa: F401 -- shared fixture
)


def _signed_in(cloud: FakeCloud, home: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert _login(cloud, home) == 0
    capsys.readouterr()


def _status(home: Path, capsys: pytest.CaptureFixture[str], *extra: str) -> tuple[int, dict[str, object], str]:
    code = _cli("status", "--guard-home", str(home), "--json", *extra)
    payload, text = _json_out(capsys)
    return code, payload, text


def _edit_profile(home: Path, **changes: object) -> None:
    path = home / "cloud-actions" / "profiles" / "default.json"
    record = json.loads(path.read_text())
    record.update(changes)
    path.write_text(json.dumps(record))


def test_status_offline_never_opens_the_secret_store(
    cloud: FakeCloud,
    browser: Browser,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _signed_in(cloud, tmp_path, capsys)
    files = tmp_path / "cloud-actions"

    def _snapshot() -> dict[str, tuple[int, int]]:
        return {str(path): (path.stat().st_mode, path.stat().st_mtime_ns) for path in sorted(files.rglob("*"))}

    def _refuse(*_args: object) -> None:
        raise AssertionError("status --offline opened the secret store")

    before = _snapshot()
    monkeypatch.setattr(CloudActionsSessionStore, "load_secrets", _refuse)
    monkeypatch.setattr(CloudActionsSessionStore, "lock", _refuse)

    code, payload, _ = _status(tmp_path, capsys, "--offline")

    assert (code, payload["state"]) == (0, "signed_in")
    assert _snapshot() == before


def test_status_offline_without_a_saved_secret_is_signed_out(
    cloud: FakeCloud, browser: Browser, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _signed_in(cloud, tmp_path, capsys)
    _edit_profile(tmp_path, secret_ref=None)

    _, payload, _ = _status(tmp_path, capsys, "--offline")

    assert payload["state"] == "signed_out"


def test_status_offline_says_it_did_not_check_the_saved_secret(
    cloud: FakeCloud, browser: Browser, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _signed_in(cloud, tmp_path, capsys)
    for path in (tmp_path / "secrets").iterdir():
        if path.name.startswith("cloud-actions-"):
            path.unlink()

    _, offline, _ = _status(tmp_path, capsys, "--offline")
    _, online, _ = _status(tmp_path, capsys)

    assert (offline["state"], offline["secret_checked"]) == ("signed_in", False)
    assert online["state"] == "signed_out"


def test_status_online_checks_the_saved_secret(
    cloud: FakeCloud, browser: Browser, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _signed_in(cloud, tmp_path, capsys)

    _, payload, _ = _status(tmp_path, capsys)

    assert (payload["state"], payload["secret_checked"]) == ("signed_in", True)
