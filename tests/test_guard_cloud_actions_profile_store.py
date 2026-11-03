"""How a saved Cloud actions sign-in survives failures, other commands and other clouds."""

from __future__ import annotations

import subprocess
import sys
import threading
import urllib.request
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli import cloud_actions_oauth, cloud_actions_session
from codex_plugin_scanner.guard.cli import commands_dispatch_cloud_actions as dispatch
from codex_plugin_scanner.guard.cli.cloud_actions_oauth import (
    CloudActionsSignInError,
    discover_cloud_actions_server,
)
from codex_plugin_scanner.guard.cli.cloud_actions_session import (
    CloudActionsProfileBusyError,
    CloudActionsSessionStore,
)
from codex_plugin_scanner.guard.mdm.network import ManagedNetworkError
from tests.cloud_actions_login_support import (
    Browser,
    FakeCloud,
    _cli,
    _json_out,
    _login,
    browser_fixture,  # noqa: F401 -- shared fixture
    cloud_fixture,  # noqa: F401 -- shared fixture
    serve_fake_cloud,
)


def _secret_files(home: Path) -> set[str]:
    return {path.name for path in (home / "secrets").iterdir() if path.name.startswith("cloud-actions-")}


def test_a_failed_profile_write_keeps_the_previous_sign_in_whole(
    cloud: FakeCloud,
    browser: Browser,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert _login(cloud, tmp_path) == 0
    store = CloudActionsSessionStore(tmp_path)
    before = store.load_secrets("default")
    files_before = _secret_files(tmp_path)
    capsys.readouterr()

    real_write = cloud_actions_session._write_private_atomic  # pyright: ignore[reportPrivateUsage]

    def failing_write(path: Path, text: str) -> None:
        if path.parent.name == "profiles":
            raise OSError("disk full")
        real_write(path, text)

    monkeypatch.setattr(cloud_actions_session, "_write_private_atomic", failing_write)
    assert _login(cloud, tmp_path) != 0

    assert store.load_secrets("default") == before
    assert _secret_files(tmp_path) == files_before
    second_access, second_refresh = cloud.issued[2:]
    assert {entry["token"] for entry in cloud.revocations} == {second_access, second_refresh}


def test_signing_in_again_removes_the_replaced_secret(
    cloud: FakeCloud, browser: Browser, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert _login(cloud, tmp_path) == 0
    first = _secret_files(tmp_path)
    assert _login(cloud, tmp_path) == 0
    capsys.readouterr()

    second = _secret_files(tmp_path)
    assert len(first) == len(second) == 1
    assert first != second


def test_signing_in_to_another_cloud_ends_the_grant_on_the_first(
    cloud: FakeCloud,
    browser: Browser,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert _login(cloud, tmp_path) == 0
    first_access, first_refresh = cloud.issued
    with serve_fake_cloud() as other:
        monkeypatch.setattr(dispatch, "open_browser_url", Browser(other))
        assert _login(other, tmp_path) == 0
        capsys.readouterr()

        assert other.revocations == []
    assert {entry["token"] for entry in cloud.revocations} == {first_access, first_refresh}
    profile = CloudActionsSessionStore(tmp_path).load("default")
    assert profile is not None and profile.issuer == other.origin


def test_a_profile_held_by_another_command_is_not_changed(
    cloud: FakeCloud,
    browser: Browser,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert _login(cloud, tmp_path) == 0
    store = CloudActionsSessionStore(tmp_path)
    before = store.load_secrets("default")
    capsys.readouterr()
    monkeypatch.setattr(cloud_actions_session, "_LOCK_WAIT_SECONDS", 0.2)
    held = threading.Event()
    release = threading.Event()

    def hold() -> None:
        with CloudActionsSessionStore(tmp_path).lock("default"):
            held.set()
            _ = release.wait(10)

    holder = threading.Thread(target=hold)
    holder.start()
    try:
        assert held.wait(5)
        assert _login(cloud, tmp_path) == 1
        login_reply, _ = _json_out(capsys)
        assert _cli("logout", "--guard-home", str(tmp_path), "--json") == 1
        logout_reply, _ = _json_out(capsys)
    finally:
        release.set()
        holder.join()

    assert login_reply["reason"] == logout_reply["reason"] == "profile_busy"
    assert store.load_secrets("default") == before
    second_access, second_refresh = cloud.issued[2:]
    assert {entry["token"] for entry in cloud.revocations} == {second_access, second_refresh}


def test_the_lock_gives_up_after_its_wait(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cloud_actions_session, "_LOCK_WAIT_SECONDS", 0.2)
    store = CloudActionsSessionStore(tmp_path)
    with store.lock("default"), pytest.raises(CloudActionsProfileBusyError), store.lock("default"):
        pass


def test_a_blocked_network_reads_as_unreachable(monkeypatch: pytest.MonkeyPatch) -> None:
    def blocked(request: urllib.request.Request, **_: object) -> object:
        raise ManagedNetworkError("proxy refused")

    monkeypatch.setattr(cloud_actions_oauth, "managed_urlopen", blocked)

    with pytest.raises(CloudActionsSignInError) as raised:
        _ = discover_cloud_actions_server("http://127.0.0.1:9")
    assert raised.value.reason == "discovery_unreachable"


def test_hook_paths_do_not_load_the_sign_in_modules() -> None:
    probe = (
        "import sys\n"
        "import codex_plugin_scanner.guard.cli.commands_dispatch_cloud_actions\n"
        "import codex_plugin_scanner.guard.cli.commands_support\n"
        "loaded = sorted(name for name in sys.modules if '.cloud_actions_' in name)\n"
        "print(','.join(loaded))\n"
    )
    result = subprocess.run([sys.executable, "-c", probe], capture_output=True, text=True, check=True, timeout=120)

    assert result.stdout.strip() == ""
