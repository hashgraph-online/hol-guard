from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from codex_plugin_scanner.guard import store as guard_store_module
from codex_plugin_scanner.guard.daemon import hook_process_entrypoint as hook_entrypoint_module


def test_evaluator_becomes_ready_when_store_prewarm_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = MagicMock()
    connection.recv.return_value = ("stop", None)
    monkeypatch.setattr(
        guard_store_module,
        "GuardStore",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("migration busy")),
    )
    timeout_name = "HOL_GUARD_INTERNAL_HOOK_SQLITE_TIMEOUT_MS"
    original_timeout = os.environ.get(timeout_name)
    # Production invokes this entrypoint in its own process. Contain its process
    # environment here so later storage tests retain their actual startup budget.
    with monkeypatch.context() as process_environment:
        process_environment.setenv(timeout_name, "0")
        hook_entrypoint_module._hook_evaluator_main(  # pyright: ignore[reportPrivateUsage]
            connection, str(tmp_path / "guard-home")
        )
        assert os.environ[timeout_name] == "250"

    assert os.environ.get(timeout_name) == original_timeout
    connection.send.assert_called_once_with(("ready", None))
