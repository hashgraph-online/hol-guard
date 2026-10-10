"""Hook request path metadata is validated and audited without a Python hook fallback."""

from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.daemon import server as server_module
from codex_plugin_scanner.guard.store import GuardStore


def _handler(store: GuardStore) -> server_module._GuardDaemonHandler:
    handler = object.__new__(server_module._GuardDaemonHandler)
    handler.server = SimpleNamespace(store=store)
    return handler


def test_relative_workspace_is_rejected_as_metadata(tmp_path: Path) -> None:
    handler = _handler(GuardStore(tmp_path / "guard-home"))

    with pytest.raises(server_module._HookPathValidationError) as error:
        handler._validated_hook_directory_string("workspace", "relative-workspace", roots=(tmp_path,))

    assert (error.value.parameter, error.value.reason) == ("workspace", "relative_path")
    assert error.value.code == "invalid_hook_workspace_path"


def test_workspace_symlink_outside_safe_roots_is_rejected(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    link = home / "linked-workspace"
    try:
        link.symlink_to(Path(home.anchor), target_is_directory=True)
    except (NotImplementedError, OSError):
        pytest.skip("symlinks are not supported in this environment")
    handler = _handler(GuardStore(tmp_path / "guard-home"))

    with pytest.raises(server_module._HookPathValidationError) as error:
        handler._validated_hook_directory_string("workspace", str(link), roots=(home.resolve(),))

    assert (error.value.parameter, error.value.reason) == ("workspace", "unexpected_root")


def test_unexpected_guard_home_is_rejected(tmp_path: Path) -> None:
    handler = _handler(GuardStore(tmp_path / "guard-home"))

    with pytest.raises(server_module._HookPathValidationError) as error:
        handler._validated_hook_guard_home(str(tmp_path / "other-guard-home"))

    assert (error.value.parameter, error.value.reason) == ("guard-home", "unexpected_guard_home")
    assert error.value.code == "invalid_hook_guard_home_path"


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFOs are not supported in this environment")
def test_special_guard_home_path_is_rejected(tmp_path: Path) -> None:
    fifo = tmp_path / "guard-home.fifo"
    os.mkfifo(fifo)
    handler = _handler(GuardStore(tmp_path / "guard-home"))

    with pytest.raises(server_module._HookPathValidationError) as error:
        handler._validated_hook_guard_home(str(fifo))

    assert error.value.parameter == "guard-home"


def test_path_rejection_is_recorded_and_survives_audit_timeout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path / "guard-home")
    handler = _handler(store)
    handler.command = "POST"
    handler.path = "/v1/hooks/claude-code?workspace=relative-workspace"
    audit_lock = server_module.threading.Lock()
    persisted: list[tuple[str, dict[str, object]]] = []
    outcomes = iter([True, TimeoutError("audit storage timed out")])

    class _Persistence:
        def persist(self, name: str, payload: dict[str, object], _now: str) -> bool:
            outcome = next(outcomes)
            if isinstance(outcome, Exception):
                return False
            persisted.append((name, payload))
            return outcome

    handler.server = SimpleNamespace(store=store, denial_audit_lock=audit_lock, audit_persistence=_Persistence())

    handler._record_hook_path_rejection(parameter="workspace", reason="relative_path")
    handler._record_hook_path_rejection(parameter="workspace", reason="relative_path")

    assert [name for name, _payload in persisted] == ["daemon.hook.path_rejected"]
    assert persisted[0][1]["parameter"] == "workspace"
    assert persisted[0][1]["reason"] == "relative_path"
