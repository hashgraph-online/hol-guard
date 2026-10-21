"""Behavioral regressions for Sonar's invariant-return findings."""

from __future__ import annotations

import argparse
from unittest.mock import Mock

import pytest

from codex_plugin_scanner.guard.cli import commands_dispatch_records as records
from codex_plugin_scanner.guard.runtime.extension_control_authority import (
    AuthorityHealth,
    ExtensionControlAuthorityView,
)
from codex_plugin_scanner.guard.runtime.extension_control_runtime import ExtensionControlRuntime


@pytest.mark.parametrize("health", [health for health in AuthorityHealth if health is not AuthorityHealth.PROTECTED])
def test_unprotected_snapshot_preserves_both_protected_revision_floors(health: AuthorityHealth) -> None:
    def view(revision: int, managed_revision: int, health: AuthorityHealth) -> ExtensionControlAuthorityView:
        return ExtensionControlAuthorityView(health, revision, "a" * 64, (), managed_revision)

    runtime = ExtensionControlRuntime(view(4, 2, AuthorityHealth.PROTECTED))
    unprotected = runtime.refresh(view(0, 0, health))

    assert runtime.current() is unprotected
    assert unprotected.health is health
    for revision, managed_revision in ((3, 2), (5, 1)):
        with pytest.raises(ValueError, match="move backwards"):
            runtime.refresh(view(revision, managed_revision, AuthorityHealth.PROTECTED))
        assert runtime.current() is unprotected
    replacement = runtime.refresh(view(5, 3, AuthorityHealth.PROTECTED))
    assert runtime.current() is replacement
    assert (replacement.revision, replacement.managed_revision) == (5, 3)


@pytest.mark.parametrize("format_name,json_output", [("markdown", False), ("markdown", True), ("json", False)])
def test_abom_emits_exactly_one_selected_format(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    format_name: str,
    json_output: bool,
) -> None:
    payload = {"markdown": "# Inventory", "items": []}
    emit = Mock()
    monkeypatch.setattr(records, "_require_guard_store", Mock(), raising=False)
    monkeypatch.setattr(records, "_build_abom_payload", Mock(return_value=payload), raising=False)
    monkeypatch.setattr(records, "_emit", emit, raising=False)

    result = records._run_guard_abom_command(argparse.Namespace(format=format_name, json=json_output))

    assert result == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    if format_name == "markdown" and not json_output:
        assert captured.out == "# Inventory\n"
        emit.assert_not_called()
    else:
        assert captured.out == ""
        emit.assert_called_once_with("abom", payload, True)
