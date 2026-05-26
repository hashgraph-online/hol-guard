"""Phase 07 executable harness coverage matrix for package interception."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.package_intent import extract_package_intent_request

_HARNESS_COVERAGE_MATRIX = (
    {
        "harness": "codex",
        "tool_name": "bash",
        "command": "npm install minimist@1.2.8",
        "proof_test": (
            "tests/test_guard_package_hook_phase14.py::"
            "test_phase14_guard_hook_enriches_package_contract_for_managed_harnesses[codex]"
        ),
    },
    {
        "harness": "claude-code",
        "tool_name": "bash",
        "command": "npm install minimist@1.2.8",
        "proof_test": (
            "tests/test_guard_package_hook_phase14.py::"
            "test_phase14_guard_hook_enriches_package_contract_for_managed_harnesses[claude-code]"
        ),
    },
    {
        "harness": "copilot",
        "tool_name": "bash",
        "command": "npm install minimist@1.2.8",
        "proof_test": (
            "tests/test_guard_package_hook_phase14.py::"
            "test_phase14_guard_hook_enriches_package_contract_for_managed_harnesses[copilot]"
        ),
    },
    {
        "harness": "gemini",
        "tool_name": "bash",
        "command": "npm install minimist@1.2.8",
        "proof_test": (
            "tests/test_guard_package_hook_phase14.py::"
            "test_phase14_guard_hook_enriches_package_contract_for_managed_harnesses[gemini]"
        ),
    },
    {
        "harness": "cursor",
        "tool_name": "run_terminal_command",
        "command": "npm install minimist@1.2.8",
        "proof_test": (
            "tests/test_guard_mcp_package_proxy_phase14.py::"
            "test_phase14_runtime_mcp_proxy_queues_package_request_not_generic_tool_call[cursor]"
        ),
    },
    {
        "harness": "opencode",
        "tool_name": "run_terminal_command",
        "command": "npm install minimist@1.2.8",
        "proof_test": (
            "tests/test_guard_mcp_package_proxy_phase14.py::"
            "test_phase14_runtime_mcp_proxy_queues_package_request_not_generic_tool_call[opencode]"
        ),
    },
    {
        "harness": "hermes",
        "tool_name": "run_terminal_command",
        "command": "npm install minimist@1.2.8",
        "proof_test": (
            "tests/test_guard_mcp_package_proxy_phase14.py::"
            "test_phase14_runtime_mcp_proxy_queues_package_request_not_generic_tool_call[hermes]"
        ),
    },
    {
        "harness": "openclaw",
        "tool_name": "run_terminal_command",
        "command": "npm install minimist@1.2.8",
        "proof_test": (
            "tests/test_guard_mcp_package_proxy_phase14.py::"
            "test_phase14_runtime_mcp_proxy_queues_package_request_not_generic_tool_call[openclaw]"
        ),
    },
)


def _matrix_ids() -> list[str]:
    return [entry["harness"] for entry in _HARNESS_COVERAGE_MATRIX]


@pytest.mark.parametrize("entry", _HARNESS_COVERAGE_MATRIX, ids=_matrix_ids())
def test_phase07_harness_coverage_matrix_extracts_package_intent(
    entry: dict[str, str],
    tmp_path: Path,
) -> None:
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir(parents=True, exist_ok=True)

    intent = extract_package_intent_request(
        entry["tool_name"],
        {"command": entry["command"]},
        action_envelope_command=entry["command"],
        workspace=workspace_dir,
    )

    assert intent is not None
    assert intent.intent_kind == "install"
    assert intent.package_manager == "npm"
    assert Path(entry["proof_test"].split("::")[0]).exists()
    assert entry["proof_test"].startswith("tests/test_guard_")
