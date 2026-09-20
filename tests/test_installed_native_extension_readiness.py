"""Installed extension fixtures must await the committed policy before probing it."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from ci.native_runtime import probe_installed_native_extensions as probe
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer


def test_control_publication_finishes_before_hook_admission_with_one_deadline(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    clock = [100.0]
    events: list[str] = []
    published = [False]
    monkeypatch.setattr(probe.time, "monotonic", lambda: clock[0])

    def register(workspace: Path) -> None:
        assert workspace == tmp_path
        events.append("register")

    def wait(deadline: float) -> bool:
        assert deadline == 105.0
        events.append("wait")
        # An in-flight older generation can fail before the committed controls
        # finish publishing. Admission must not run during that setup state.
        clock[0] = 104.5
        published[0] = True
        return True

    def prepare(workspace: Path, *, deadline: float) -> dict[str, object]:
        assert workspace == tmp_path
        assert published[0]
        assert deadline == 105.0
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
