from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from scripts import native_slo_session as session_module
from scripts.native_slo_session import AdapterSession


@pytest.mark.parametrize("preparation_seconds", [0.05, 0.401])
def test_session_readiness_uses_registered_workspace_and_preserves_budget(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, preparation_seconds: float
) -> None:
    workspace = tmp_path / "workspace"
    registered: set[Path] = set()
    publications: list[Path] = []
    clock = [10.0]

    def register_workspace(path: Path) -> bool:
        if path in registered:
            return False
        registered.add(path)
        return True

    def start_daemon() -> None:
        publications.extend(registered)

    def prepare_workspace_policy(path: Path, *, deadline: float) -> object:
        assert deadline == pytest.approx(10.4)
        if register_workspace(path):
            publications.append(path)
            clock[0] += 0.4
        clock[0] += preparation_seconds
        return object()

    publisher = SimpleNamespace(register_workspace=register_workspace)
    worker = SimpleNamespace(policy_snapshot_publisher=publisher, prepare_workspace_policy=prepare_workspace_policy)
    daemon = SimpleNamespace(_server=SimpleNamespace(hook_worker=worker), start=start_daemon, port=12345)
    session = cast(AdapterSession, SimpleNamespace(daemon=daemon, workspace=workspace))
    monkeypatch.setattr(session_module.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(session_module.time, "perf_counter", lambda: clock[0])

    if preparation_seconds > 0.4:
        with pytest.raises(RuntimeError, match=r"native readiness exceeded budget \(401\.000 ms\)"):
            AdapterSession.start(session)
    else:
        AdapterSession.start(session)
        assert session.readiness_ms == pytest.approx(50.0)

    assert publications == [workspace]
    assert registered == {workspace}
    assert session._connection is not None
    session._connection.close()
