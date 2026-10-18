"""Guard-clause coverage for native hook evaluation helpers."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.cli import commands_hook_native_eval as eval_module
from codex_plugin_scanner.guard.cli.commands_hook_native_edge_facts import _native_edge_facts
from codex_plugin_scanner.guard.cli.commands_hook_native_eval import (
    _runtime_external_archive_command_matches_executable,
    _runtime_external_archive_has_digest_binding_sink,
)
from codex_plugin_scanner.guard.cli.commands_hook_native_generic import _observed_action_detail
from codex_plugin_scanner.guard.native_shell_helpers import NativeShellHelpersError


def test_archive_command_matcher_asks_the_resident_and_forwards_the_executable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The parse itself is covered in `package_shim_invocation_tests.rs`."""

    asked: list[tuple[str, str, str]] = []

    def record(action: str, command: str, **fields: object) -> bool:
        asked.append((action, command, str(fields["executable"])))
        return True

    monkeypatch.setattr(eval_module, "call", record)
    assert _runtime_external_archive_command_matches_executable("cat ./archive.tar", "cat") is True
    assert asked == [("invokes_executable", "cat ./archive.tar", "cat")]


def test_archive_command_matcher_never_asks_without_a_command() -> None:
    def refuse(action: str, command: str, **fields: object) -> bool:
        raise AssertionError("asked about an absent command")

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(eval_module, "call", refuse)
        assert _runtime_external_archive_command_matches_executable(None, "cat") is False


def test_archive_command_matcher_treats_an_unreachable_resident_as_no_match(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No binding sink leaves the approval with the user, not with the shim."""

    def unavailable(action: str, command: str, **fields: object) -> bool:
        raise NativeShellHelpersError("native_shell_helpers_unavailable")

    monkeypatch.setattr(eval_module, "call", unavailable)
    assert _runtime_external_archive_command_matches_executable("cat ./archive.tar", "cat") is False


def test_native_edge_facts_forward_the_edge_verdict_without_deciding() -> None:
    assert _native_edge_facts(None, "PostToolUse") is None
    edge = {"decision": "deny", "policy_action": "block", "reason_code": "native_secret_exfiltration", "extra": 1}
    assert _native_edge_facts(edge, "PreToolUse", artifact_type="package_request") == {
        "event_name": "PreToolUse",
        "policy_action": "block",
        "minimum_action": None,
        "decision": "deny",
        "reason_code": "native_secret_exfiltration",
        "package_request": True,
    }
    assert _native_edge_facts({}, "PostToolUse", artifact_type="command")["package_request"] is False


def test_digest_binding_sink_requires_manager_and_path_executable(tmp_path) -> None:
    context = SimpleNamespace()
    assert (
        _runtime_external_archive_has_digest_binding_sink(
            artifact=SimpleNamespace(metadata=None),
            context=context,
            raw_command="tar xf a.tgz",
            runtime_workspace=tmp_path,
        )
        is False
    )
    assert (
        _runtime_external_archive_has_digest_binding_sink(
            artifact=SimpleNamespace(metadata={"package_manager": "uv"}),
            context=context,
            raw_command="tar xf a.tgz",
            runtime_workspace=tmp_path,
        )
        is False
    )
    assert (
        _runtime_external_archive_has_digest_binding_sink(
            artifact=SimpleNamespace(metadata={"package_manager": "uv", "package_executable": "uv"}),
            context=context,
            raw_command="uv run tool",
            runtime_workspace=tmp_path,
        )
        is False
    )
    assert (
        _runtime_external_archive_has_digest_binding_sink(
            artifact=SimpleNamespace(metadata={"package_manager": "uv", "package_executable": "/usr/bin/uv"}),
            context=context,
            raw_command="cat other",
            runtime_workspace=tmp_path,
        )
        is False
    )


def test_digest_binding_sink_matches_resolved_shim_path(tmp_path, monkeypatch) -> None:
    real_executable = tmp_path / "uv"
    real_executable.write_text("#!/bin/sh\n", encoding="utf-8")
    other = tmp_path / "other-uv"
    other.write_text("#!/bin/sh\n", encoding="utf-8")

    def fake_status(_context, *, path_env=None):
        return {
            "manager_details": [
                {"manager": "pip", "integrity": "mismatch", "shim_path": str(other)},
                {"manager": "uv", "integrity": "ok", "shim_path": str(real_executable)},
            ]
        }

    monkeypatch.setattr(eval_module, "package_shim_status", fake_status)
    # The launch test itself is the resident's; this exercises the shim match.
    monkeypatch.setattr(eval_module, "call", lambda *args, **fields: True)
    artifact = SimpleNamespace(metadata={"package_manager": "uv", "package_executable": str(real_executable)})
    assert (
        _runtime_external_archive_has_digest_binding_sink(
            artifact=artifact,
            context=SimpleNamespace(),
            raw_command=f"{real_executable} run tool",
            runtime_workspace=tmp_path,
        )
        is True
    )

    def mismatched_status(_context, *, path_env=None):
        return {"manager_details": [{"manager": "uv", "integrity": "ok", "shim_path": str(other)}]}

    monkeypatch.setattr(eval_module, "package_shim_status", mismatched_status)
    assert (
        _runtime_external_archive_has_digest_binding_sink(
            artifact=artifact,
            context=SimpleNamespace(),
            raw_command=f"{real_executable} run tool",
            runtime_workspace=tmp_path,
        )
        is False
    )


def test_observed_action_detail_falls_back_to_envelope_composition(tmp_path) -> None:
    assert _observed_action_detail(None, action_envelope=None, home_dir=tmp_path) is None
    envelope = SimpleNamespace(tool_name=None, target_paths=())
    assert _observed_action_detail(None, action_envelope=envelope, home_dir=tmp_path) is None
    envelope = SimpleNamespace(tool_name="Read", target_paths=("/etc/hosts",))
    detail = _observed_action_detail(None, action_envelope=envelope, home_dir=tmp_path)
    assert isinstance(detail, str) and "Read" in detail
