"""Regression coverage for incomplete local-script inspection at the request adapter."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.secret_file_requests import extract_sensitive_tool_action_request


@pytest.mark.parametrize("case", ("missing", "oversized", "cycle", "symlink"))
def test_incomplete_script_inspection_still_builds_review_request(case: str, tmp_path: Path) -> None:
    script = tmp_path / "check.sh"
    if case == "oversized":
        script.write_text("#" * (33 * 1024))
    elif case == "cycle":
        script.write_text("bash check.sh\n")
    elif case == "symlink":
        target = tmp_path / "other.sh"
        target.write_text("echo harmless\n")
        script.symlink_to(target)

    request = extract_sensitive_tool_action_request(
        "Bash",
        {"command": "bash check.sh"},
        cwd=tmp_path,
        home_dir=tmp_path,
    )

    assert request is not None
    assert request.action_class == "local script execution shell command"
    assert request.guard_default_action == "require-reapproval"
    assert request.reason_code == "shell_local_script_execution_review"


def test_missing_workspace_search_with_exec_flag_still_requires_review(tmp_path: Path) -> None:
    request = extract_sensitive_tool_action_request(
        "Bash",
        {"command": "rg --pre ./payload TOKEN ."},
        cwd=None,
        home_dir=tmp_path,
    )
    assert request is not None
    assert request.guard_default_action == "require-reapproval"


@pytest.mark.parametrize(
    "command",
    (
        "command rg --pre ./payload TOKEN .",
        "exec rg --pre ./payload TOKEN .",
        "exec -cl rg --pre ./payload TOKEN .",
        "command -- rg --pre ./payload TOKEN .",
        "exec -- rg --pre ./payload TOKEN .",
    ),
)
def test_wrapped_search_preprocessor_still_requires_review(command: str, tmp_path: Path) -> None:
    request = extract_sensitive_tool_action_request(
        "Bash",
        {"command": command},
        cwd=None,
        home_dir=tmp_path,
    )
    assert request is not None
    assert request.guard_default_action == "require-reapproval"
