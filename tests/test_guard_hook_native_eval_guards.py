"""Guard-clause coverage for native hook evaluation helpers."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.cli.commands_hook_native_eval import (
    _native_edge_floor_action,
    _requested_policy_action_normalization,
    _runtime_external_archive_command_matches_executable,
    _runtime_external_archive_has_digest_binding_sink,
)
from codex_plugin_scanner.guard.cli import commands_hook_native_eval as eval_module
from codex_plugin_scanner.guard.cli.commands_hook_native_generic import (
    _observed_action_detail,
    _should_relax_configured_default,
)


@pytest.mark.parametrize(
    "raw_command",
    [
        None,
        "`id`",
        "$(id)",
        "cat file\nwhoami",
        "cat file\rwhoami",
        "'unbalanced",
    ],
)
def test_archive_command_matcher_rejects_unsafe_or_malformed_commands(raw_command: str | None) -> None:
    assert _runtime_external_archive_command_matches_executable(raw_command, "cat") is False


def test_archive_command_matcher_rejects_wrong_executable_and_metachar_tokens() -> None:
    assert _runtime_external_archive_command_matches_executable("ls -la", "cat") is False
    assert _runtime_external_archive_command_matches_executable("cat ;", "cat") is False
    assert _runtime_external_archive_command_matches_executable("cat file > out", "cat") is False


def test_archive_command_matcher_accepts_plain_matching_command() -> None:
    assert _runtime_external_archive_command_matches_executable("cat ./archive.tar", "cat") is True
    assert _runtime_external_archive_command_matches_executable("unzip -l bundle.zip", "unzip") is True


def test_requested_policy_action_normalization_prefers_cli_then_stored_then_payload() -> None:
    cli = _requested_policy_action_normalization("allow", "block", {"policy_action": "review"})
    assert cli is not None and cli.action == "allow"
    stored = _requested_policy_action_normalization(None, "block", {"policy_action": "review"})
    assert stored is not None and stored.action == "block"
    payload = _requested_policy_action_normalization(None, None, {"policy_action": "review"})
    assert payload is not None and payload.action == "review"
    assert _requested_policy_action_normalization(None, None, {}) is None


def test_native_edge_floor_action_only_floors_post_tool_use() -> None:
    assert _native_edge_floor_action(None, "PostToolUse") is None
    assert _native_edge_floor_action({"decision": "deny"}, "PreToolUse") is None
    assert _native_edge_floor_action({"decision": "deny"}, "PostToolUse") == "require-reapproval"
    assert _native_edge_floor_action({"decision": "deny"}, "PostToolUse", artifact_default_action="warn") is None
    assert _native_edge_floor_action({"policy_action": "allow"}, "PostToolUse") == "allow"


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


def test_should_relax_configured_default_requires_review_tier_and_no_override(tmp_path) -> None:
    assert (
        _should_relax_configured_default(
            configured_action="review",
            has_narrow_override=True,
            home_dir=tmp_path,
            payload={},
            runtime_workspace=tmp_path,
        )
        is False
    )
    assert (
        _should_relax_configured_default(
            configured_action="allow",
            has_narrow_override=False,
            home_dir=tmp_path,
            payload={},
            runtime_workspace=tmp_path,
        )
        is False
    )


def test_should_relax_configured_default_rejects_prompt_submit_without_clean_prompt(tmp_path) -> None:
    base = {
        "configured_action": "review",
        "has_narrow_override": False,
        "home_dir": tmp_path,
        "runtime_workspace": tmp_path,
    }
    assert _should_relax_configured_default(payload={"hook_event_name": "UserPromptSubmit"}, **base) is False
    assert (
        _should_relax_configured_default(payload={"hook_event_name": "UserPromptSubmit", "prompt": "   "}, **base)
        is False
    )
    assert (
        _should_relax_configured_default(
            payload={"hook_event_name": "UserPromptSubmit", "prompt": "read my .env file"}, **base
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
