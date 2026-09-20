from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime import command_inspection
from codex_plugin_scanner.guard.runtime.command_inspection import inspect_command
from codex_plugin_scanner.guard.runtime.secret_file_requests import extract_sensitive_tool_action_request
from tests.native_command_test_support import real_native_command_evaluation


def _native_inspection(
    command: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[dict[str, object], object]:
    reviewed = real_native_command_evaluation(command, cwd=tmp_path)
    monkeypatch.setattr(command_inspection, "review_command_native", lambda *_args, **_kwargs: reviewed)
    payload = inspect_command(command, cwd=tmp_path, home_dir=tmp_path)
    match = extract_sensitive_tool_action_request(
        "Shell",
        {"command": command},
        cwd=tmp_path,
        home_dir=tmp_path,
        canonical_command=reviewed.evaluation.command,
        native_evaluation=reviewed.evaluation,
    )
    return payload, match


@pytest.mark.parametrize(
    ("command", "expected_status", "expected_match"),
    [
        ("git clean --no-dry-run -nfdx", "no_match", False),
        # The last effective flag wins for both preview spellings. Native
        # execution still has a separate review floor, asserted below.
        ("git push origin main --force --no-dry-run --dry-run", "no_match", False),
    ],
)
def test_real_native_git_preview_order_matches_effective_flags(
    command: str,
    expected_status: str,
    expected_match: bool,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload, match = _native_inspection(command, tmp_path, monkeypatch)
    assert payload["status"] == expected_status
    assert (match is not None) is expected_match
    if command.startswith("git push"):
        reviewed = real_native_command_evaluation(command, cwd=tmp_path)
        assert reviewed.native_minimum_action == "review"
        assert reviewed.evaluation.minimum_action == "review"
        assert reviewed.payload["explicitly_benign"] is False
        assert not reviewed.evaluation.decision_plane.proof_routes


@pytest.mark.parametrize(
    "command",
    [
        "git clean -nfdx --no-dry-run",
        "git clean --dry-run -fdx --no-dry-run",
        "git push origin main --force --dry-run --no-dry-run",
    ],
)
def test_disabled_git_preview_aliases_remain_runtime_sensitive(
    command: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload, match = _native_inspection(command, tmp_path, monkeypatch)

    assert payload["status"] == "review"
    assert match is not None
    assert match.action_class == "git destructive command"


@pytest.mark.parametrize(
    ("command", "expected_status", "expected_matched"),
    [
        (
            "aws ec2 terminate-instances --instance-ids i-123 --dry-run --no-dry-run",
            "review",
            True,
        ),
        (
            "aws ec2 terminate-instances --instance-ids i-123 --no-dry-run --dry-run",
            "no_match",
            False,
        ),
        ("aws rds delete-db-instance --generate-cli-skeleton=output", "no_match", False),
    ],
)
def test_native_inspection_honors_effective_safe_option_semantics(
    command: str,
    expected_status: str,
    expected_matched: bool,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload, _match = _native_inspection(command, tmp_path, monkeypatch)
    assert payload["status"] == expected_status
    assert payload["classification"]["matched"] is expected_matched
