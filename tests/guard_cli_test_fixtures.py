"""Local autouse fixtures shared only by the partitioned CLI tests."""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.cli import update_commands as guard_update_commands_module
from tests.update_context_test_support import build_legacy_update_context, stage_legacy_wheel


@pytest.fixture(autouse=True)
def _use_legacy_update_context(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        guard_update_commands_module,
        "build_trusted_update_context",
        build_legacy_update_context,
    )
    monkeypatch.setattr(guard_update_commands_module, "stage_trusted_wheel", stage_legacy_wheel)
    monkeypatch.setattr(
        guard_update_commands_module,
        "record_local_wheel_receipt",
        lambda _artifact, *, guard_home, installed_version: guard_home / "local-wheel-source.json",
    )


@pytest.fixture(autouse=True)
def _isolate_codex_runtime_marker(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CODEX_MANAGED_BY_BUN", raising=False)
    monkeypatch.delenv("CODEX_HOME", raising=False)
