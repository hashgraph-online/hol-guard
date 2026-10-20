"""A refused hook path is audited once, even when audit storage is slow.

Which paths a hook may name is the runtime's question now: the handler asks
``_settled_hook_directories`` and records whatever verdict comes back. The
rejection reasons themselves (``relative_path``, ``unexpected_root``,
``unexpected_guard_home``, ``path_resolve_failed``) are covered by
``rust/crates/guard-runtime/src/directory_trust_tests.rs``; what stays here is
the auditing the daemon still owns.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.daemon import server as server_module
from codex_plugin_scanner.guard.store import GuardStore


def _handler(store: GuardStore) -> server_module._GuardDaemonHandler:
    handler = object.__new__(server_module._GuardDaemonHandler)
    handler.server = SimpleNamespace(store=store)
    return handler


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
