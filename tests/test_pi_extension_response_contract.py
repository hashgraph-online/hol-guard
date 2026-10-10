"""Focused runtime contract tests for the generated Pi/OMP hook extension."""

from __future__ import annotations

import hashlib
from pathlib import Path

from codex_plugin_scanner.guard.daemon.hook_worker_responses import (
    harness_json_from_native_pre_tool,
    observe_lifecycle_fail_safe_response,
)
from tests.pi_extension_response_callback_support import (
    _run_generated_callback_payload,
    _run_generated_source_ref_fixture,
)
from tests.pi_extension_response_runtime_support import (
    _run_generated_fixture,
    _run_generated_tool_result_fixture,
)
from tests.pi_extension_response_source_support import _generated_source


def test_canonical_omp_allow_deny_and_lifecycle_shapes() -> None:
    allow = harness_json_from_native_pre_tool(
        "omp",
        {"decision": "allow", "minimum_action": "allow", "reason_code": "fixture_allow"},
    )
    deny = harness_json_from_native_pre_tool(
        "omp",
        {
            "decision": "deny",
            "minimum_action": "block",
            "reason": "fixture block",
            "reason_code": "fixture_block",
        },
    )
    lifecycle = observe_lifecycle_fail_safe_response(
        "omp",
        event_name="UserPromptSubmit",
        reason_code="fixture_lifecycle",
    )

    assert allow["decision"] == "allow"
    assert deny["decision"] == "deny"
    assert lifecycle == {
        "decision": "allow",
        "policy_action": "allow",
        "reason_code": "fixture_lifecycle",
    }


def test_generated_omp_rejects_ambiguous_success_and_preserves_retry_semantics(tmp_path: Path) -> None:
    result = _run_generated_fixture(_generated_source(tmp_path))

    assert result["daemon_allow"] == {"decision": "allow"}
    assert result["daemon_lifecycle_allow"] == {
        "decision": "allow",
        "policy_action": "allow",
        "reason_code": "fixture_lifecycle",
    }
    assert result["daemon_deny"] == {"decision": "deny", "reason": "fixture block"}
    assert result["daemon_empty"] == {"response": None, "recoveryKind": "transport-failure"}
    assert result["daemon_whitespace"] == {"response": None, "recoveryKind": "transport-failure"}
    assert result["daemon_malformed"] == {
        "decision": "deny",
        "reason": "HOL Guard received an invalid response from the authenticated local daemon.",
        "reason_code": "daemon_invalid_response",
    }
    assert result["daemon_malformed_reason"] == {"response": None, "recoveryKind": "transport-failure"}
    assert result["daemon_null_reason"] == {"decision": "deny", "reason": None}
    assert result["daemon_omitted_reason"] == {"decision": "deny"}
    assert result["daemon_shape"] == {"response": None, "recoveryKind": "transport-failure"}
    assert result["daemon_array"] == {"response": None, "recoveryKind": "transport-failure"}
    assert result["daemon_unknown"] == {"response": None, "recoveryKind": "transport-failure"}
    assert result["daemon_block"] == {"decision": "deny", "reason": "fixture block"}
    assert result["daemon_oversized_body"] == {
        "response": None,
        "recoveryKind": "transport-failure",
    }

    assert result["retry_still_malformed"] == {
        "decision": "deny",
        "reason": "HOL Guard fallback did not return a valid decision. Retry the action.",
        "reason_code": "guard_cli_invalid_response",
    }
    assert result["retry_still_malformed_daemon_calls"] == 2
    assert result["retry_still_malformed_recovery_calls"] == 1
    assert result["retry_still_malformed_cli_calls"] == 1

    assert result["retry_malformed_reason"] == {
        "decision": "deny",
        "reason": "HOL Guard fallback did not return a valid decision. Retry the action.",
        "reason_code": "guard_cli_invalid_response",
    }
    assert result["retry_malformed_reason_daemon_calls"] == 2
    assert result["retry_malformed_reason_recovery_calls"] == 1
    assert result["retry_malformed_reason_cli_calls"] == 1

    assert result["retry_valid"] == {"decision": "allow"}
    assert result["retry_valid_daemon_calls"] == 2
    assert result["retry_valid_recovery_calls"] == 1
    assert result["retry_valid_cli_calls"] == 0
    assert result["posttool_daemon_allow"] == {
        "decision": "allow",
        "reason_code": "native_policy_not_ready",
    }
    assert result["posttool_daemon_allow_daemon_calls"] == 1
    assert result["posttool_daemon_allow_recovery_calls"] == 0
    assert result["posttool_daemon_allow_cli_calls"] == 0
    assert result["stale_daemon_cli_success"] == {"decision": "allow"}
    assert result["stale_daemon_cli_daemon_calls"] == 1
    assert result["stale_daemon_cli_recovery_calls"] == 0
    assert result["stale_daemon_cli_calls"] == 0

    assert result["cli_missing_decision"] == {
        "decision": "deny",
        "reason": "HOL Guard fallback did not return a valid decision. Retry the action.",
        "reason_code": "guard_cli_invalid_response",
    }
    assert result["cli_empty_prompt"] == {
        "decision": "deny",
        "reason": "HOL Guard fallback did not return a valid decision. Retry the action.",
        "reason_code": "guard_cli_invalid_response",
    }
    assert result["cli_empty_post"] == {
        "decision": "deny",
        "reason": "HOL Guard fallback did not return a valid decision. Retry the action.",
        "reason_code": "guard_cli_invalid_response",
    }
    assert result["cli_malformed_reason"] == {
        "decision": "deny",
        "reason": "HOL Guard fallback did not return a valid decision. Retry the action.",
        "reason_code": "guard_cli_invalid_response",
    }
    assert result["cli_null_reason"] == {"decision": "deny", "reason": None}
    assert result["cli_omitted_reason"] == {"decision": "deny"}
    assert result["cli_lifecycle_allow"] == {"decision": "allow", "policy_action": "allow"}
    assert result["cli_allow"] == {"decision": "allow"}
    assert result["cli_deny"] == {"decision": "deny", "reason": "fixture block"}
    assert result["cli_block_prompt"] == {"decision": "deny", "reason": "fixture block"}
    assert result["cli_block_post"] == {"decision": "deny", "reason": "fixture block"}
    assert result["cli_nonzero_allow"] == {"decision": "deny", "reason": "cli failed"}
    assert result["cli_signal_allow"] == {"decision": "deny", "reason": "Blocked by HOL Guard."}


def test_generated_omp_tool_result_preserves_daemon_allow_without_hash(tmp_path: Path) -> None:
    result = _run_generated_tool_result_fixture(_generated_source(tmp_path))

    assert result["valid"] is True
    assert result["missing_directive"] is True
    assert result["contradictory_directive"]["content"][0]["text"] == "reviewed-safe"
    assert result["contradictory_directive"].get("isError") is not True
    assert result["missing_excerpt"]["isError"] is True
    assert result["missing_digest"]["isError"] is True
    assert result["mismatched_digest"]["isError"] is True
    assert result["reviewed_excerpt"]["content"][0]["text"] == "reviewed-long"
    assert result["reviewed_excerpt"].get("isError") is not True
    assert result["observe_mode"] is True


def test_generated_omp_directory_result_stays_inline_not_source_ref(tmp_path: Path) -> None:
    source = _generated_source(tmp_path)
    content_text = "workspace/\n.env\n"
    content = [{"type": "text", "text": content_text}]
    digest = hashlib.sha256(content_text.encode()).hexdigest()

    regular = _run_generated_source_ref_fixture(source, content, tmp_path / "example.py")
    directory = _run_generated_source_ref_fixture(
        source,
        content,
        tmp_path / "workspace",
        details={"isDirectory": True, "resolvedPath": str(tmp_path / "workspace")},
    )

    assert regular["sourceRef"] is not None
    assert directory["sourceRef"] is None

    directory_handler = _run_generated_callback_payload(
        source,
        content,
        {
            "decision": "allow",
            "model_output_action": "allow_original",
            "reviewed_output_sha256": digest,
        },
        tool_name="read",
        tool_input={"path": str(tmp_path / "workspace")},
        details={
            "isDirectory": True,
            "resolvedPath": str(tmp_path / "workspace"),
            "meta": {"source": {"type": "path", "value": str(tmp_path / "workspace")}},
        },
    )
    regular_handler = _run_generated_callback_payload(
        source,
        content,
        {
            "decision": "allow",
            "model_output_action": "allow_original",
            "reviewed_output_sha256": digest,
        },
        tool_name="read",
        tool_input={"path": str(tmp_path / "workspace")},
        details={"source": "fixture"},
    )

    assert directory_handler["preserved"] is True
    assert "guard_source_ref" not in directory_handler["payload"]
    assert directory_handler["payload"]["tool_input"] == {"path": str(tmp_path / "workspace")}
    assert directory_handler["payload"]["resolved_directory_target"] == str(tmp_path / "workspace")

    selector_directory_handler = _run_generated_callback_payload(
        source,
        content,
        {
            "decision": "allow",
            "model_output_action": "allow_original",
            "reviewed_output_sha256": digest,
        },
        tool_name="read",
        tool_input={"path": f"{tmp_path / 'workspace'}:1-5"},
        details={
            "isDirectory": True,
            "resolvedPath": str(tmp_path / "workspace"),
            "meta": {"source": {"type": "path", "value": str(tmp_path / "workspace")}},
        },
    )
    assert selector_directory_handler["preserved"] is True
    assert selector_directory_handler["payload"]["tool_input"] == {"path": f"{tmp_path / 'workspace'}:1-5"}
    assert selector_directory_handler["payload"]["resolved_directory_target"] == str(tmp_path / "workspace")

    assert regular_handler["preserved"] is True
    assert "resolved_directory_target" not in regular_handler["payload"]
    assert regular_handler["payload"]["guard_source_ref"]["kind"] == "source_file"

    # A resolved path without the explicit directory flag can also describe a
    # file result. Keep the source-file re-read path for that ambiguous shape.
    legacy_file_text = "print(1)\n"
    legacy_file_digest = hashlib.sha256(legacy_file_text.encode()).hexdigest()
    legacy_file_handler = _run_generated_callback_payload(
        source,
        [{"type": "text", "text": legacy_file_text}],
        {
            "decision": "allow",
            "model_output_action": "allow_original",
            "reviewed_output_sha256": legacy_file_digest,
        },
        tool_name="read",
        tool_input={"path": str(tmp_path / "legacy.py")},
        details={
            "resolvedPath": str(tmp_path / "legacy.py"),
            "meta": {"source": {"type": "path", "value": str(tmp_path / "legacy.py")}},
        },
    )
    assert legacy_file_handler["preserved"] is True
    assert legacy_file_handler["payload"]["guard_source_ref"]["kind"] == "source_file"
    assert legacy_file_handler["payload"]["guard_source_ref"]["path"] == str(tmp_path / "legacy.py")


def test_generated_omp_selector_review_uses_host_resolved_source_path(tmp_path: Path) -> None:
    source = _generated_source(tmp_path)
    result = _run_generated_callback_payload(
        source,
        [{"type": "text", "text": "selected source"}],
        {"decision": "allow", "notice": "reviewed"},
        tool_name="read",
        tool_input={"path": "/tmp/project/src/example.ts:1-5"},
        details={
            "isDirectory": False,
            "meta": {"source": {"value": "/tmp/project/src/example.ts"}},
        },
    )

    assert result["payload"]["tool_input"] == {"path": "/tmp/project/src/example.ts"}
    assert result["preserved"] is True


def test_generated_tool_result_keeps_checked_excerpt_after_local_content_cap(tmp_path: Path) -> None:
    source = _generated_source(tmp_path)
    content = [{"type": "text", "text": f"block-{index}"} for index in range(25)]
    result = _run_generated_callback_payload(
        source,
        content,
        {"decision": "allow", "notice": "excerpt"},
    )

    returned = result["result"]
    assert isinstance(returned, dict)
    assert returned.get("isError") is not True
    returned_text = returned["content"][0]["text"]
    assert isinstance(returned_text, str)
    assert returned_text.startswith("block-0\n")
    assert "block-23" in returned_text
    assert "block-24" not in returned_text
