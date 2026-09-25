"""Installed extension fixtures must await the committed policy before probing it."""

from __future__ import annotations

import json
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from ci.native_runtime import probe_installed_native_extensions as probe
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer


@pytest.mark.parametrize(("publish_timeout", "expected_deadline"), [(2.0, 105.0), (8.0, 108.0)])
def test_control_publication_finishes_before_hook_admission_with_one_deadline(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, publish_timeout: float, expected_deadline: float
) -> None:
    clock = [100.0]
    events: list[str] = []
    published = [False]
    monkeypatch.setattr(probe.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(probe, "_PUBLISH_TIMEOUT_SECONDS", publish_timeout)

    def register(workspace: Path) -> None:
        assert workspace == tmp_path
        events.append("register")

    def wait(deadline: float) -> bool:
        assert deadline == expected_deadline
        events.append("wait")
        # An in-flight older generation can fail before the committed controls
        # finish publishing. Admission must not run during that setup state.
        clock[0] = expected_deadline - 0.5
        published[0] = True
        return True

    def prepare(workspace: Path, *, deadline: float) -> dict[str, object]:
        assert workspace == tmp_path
        assert published[0]
        assert deadline == expected_deadline
        events.append("admit")
        return {"generation": 7}

    publisher = SimpleNamespace(
        register_workspace=register,
        start=lambda: events.append("start"),
        wait_until_ready=wait,
        current_snapshot=lambda: {"command_extensions": {"revision": 3}},
    )
    worker = SimpleNamespace(policy_snapshot_publisher=publisher, prepare_workspace_policy=prepare)
    daemon = cast(GuardDaemonServer, SimpleNamespace(_server=SimpleNamespace(hook_worker=worker)))

    assert probe.ready(daemon, tmp_path, 3) == {"generation": 7}
    assert events == ["register", "start", "wait", "admit"]


@pytest.mark.parametrize(
    ("acked", "revision", "reason"), [(False, 3, "policy_not_ready"), (True, 2, "wrong_control_generation")]
)
def test_unavailable_or_stale_control_publication_still_fails_closed(
    tmp_path: Path, acked: bool, revision: int, reason: str
) -> None:
    def prepare(workspace: Path, *, deadline: float) -> dict[str, object]:
        assert acked, "Unacknowledged policy must never reach hook admission"
        return {"generation": 7}

    publisher = SimpleNamespace(
        register_workspace=lambda workspace: None,
        start=lambda: None,
        wait_until_ready=lambda deadline: acked,
        current_snapshot=lambda: {"command_extensions": {"revision": revision}},
    )
    worker = SimpleNamespace(policy_snapshot_publisher=publisher, prepare_workspace_policy=prepare)
    daemon = cast(GuardDaemonServer, SimpleNamespace(_server=SimpleNamespace(hook_worker=worker)))

    with pytest.raises(RuntimeError, match=reason):
        probe.ready(daemon, tmp_path, 3)


def test_failed_readiness_reports_bounded_current_and_previous_publisher_state(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    release = threading.Event()
    old_thread = threading.Thread(target=lambda: release.wait(timeout=1))
    old_thread.start()
    previous = SimpleNamespace(last_error=None, closed=True, _thread=old_thread)
    publisher = SimpleNamespace(
        register_workspace=lambda workspace: None,
        start=lambda: None,
        wait_until_ready=lambda deadline: False,
        last_error="native_resident_restart_circuit_open",
        closed=False,
        _thread=threading.current_thread(),
    )
    # Missing prepare_workspace_policy also proves a failed publication never
    # reaches admission, even when an earlier publisher is still retiring.
    worker = SimpleNamespace(policy_snapshot_publisher=publisher)
    daemon = cast(GuardDaemonServer, SimpleNamespace(_server=SimpleNamespace(hook_worker=worker)))
    try:
        with pytest.raises(RuntimeError, match="policy_not_ready"):
            probe.ready(daemon, tmp_path, 3, previous_publisher=previous)
        diagnostic = json.loads(capsys.readouterr().out)
        assert diagnostic == {
            "schema": "guard.installed-native-extension-readiness-failure.v1",
            "stage": "publication",
            "publisher": {
                "last_error_code": "native_resident_restart_circuit_open",
                "last_error_present": True,
                "closed": False,
                "thread_alive": True,
            },
            "previous_publisher": {
                "last_error_code": None,
                "last_error_present": False,
                "closed": True,
                "thread_alive": True,
            },
        }
    finally:
        release.set()
        old_thread.join(timeout=1)
    assert not old_thread.is_alive()


@pytest.mark.parametrize("error", ["private/path/secret", "native_policy_snapshot_private_token", {"secret": "value"}])
def test_readiness_diagnostic_rejects_arbitrary_error_text_and_lifecycle_values(error: object) -> None:
    private = "private/request/path-or-secret"
    publisher = SimpleNamespace(last_error=error, closed=private, _thread=private, guard_home=private)
    diagnostic = probe.policy_readiness_diagnostic(publisher)
    assert diagnostic == {
        "last_error_code": None,
        "last_error_present": True,
        "closed": None,
        "thread_alive": None,
    }
    assert "private" not in json.dumps(diagnostic)
    assert "secret" not in json.dumps(diagnostic)
