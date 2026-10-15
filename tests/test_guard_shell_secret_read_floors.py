"""Regression coverage for direct reads, scripts and immutable review floors."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.native_command_model import _canonical_command_from_native
from codex_plugin_scanner.guard.runtime.command_evaluation import evaluate_command
from codex_plugin_scanner.guard.runtime.secret_file_requests import (
    build_tool_action_request_artifact,
    extract_sensitive_tool_action_request,
)
from tests.native_command_test_support import real_native_review_fixture


def _evaluate_native(command: str, *, cwd: Path):
    fixture = real_native_review_fixture(command)
    extensions = fixture.payload["command_extensions"]
    assert isinstance(extensions, dict)
    if extensions["evaluation_error"] is not None:
        assert extensions["observations"] == []
        return None, extensions["evaluation_error"]
    canonical = _canonical_command_from_native(command, fixture.payload["command_model"])
    assert canonical is not None
    return (
        evaluate_command(
            command,
            canonical_command=canonical,
            cwd=cwd,
            home_dir=cwd,
            extension_control_snapshot=fixture.snapshot,
            native_extension_evidence=fixture.payload,
        ),
        None,
    )


def _assert_review_or_native_unavailable(evaluation, evaluation_error) -> None:
    if evaluation is None:
        assert evaluation_error in {
            "native_command_evaluation_failed",
            "transparent_wrapper_not_yet_supported",
        }
        return
    assert evaluation.minimum_action in {"review", "block"}
    assert evaluation.decision_plane.action in {"require-reapproval", "block"}


@pytest.mark.parametrize("source", ("echo harmless\n", 'p=.en; cat "${p}v"\n'))
def test_no_detected_secret_does_not_authorize_arbitrary_scripts(source: str, tmp_path: Path) -> None:
    (tmp_path / "check.sh").write_text(source)
    result, error = _evaluate_native("bash check.sh", cwd=tmp_path)
    _assert_review_or_native_unavailable(result, error)


def test_script_changes_change_the_request_identity(tmp_path: Path) -> None:
    script = tmp_path / "check.sh"
    identities = []
    for source in ("cat .env\n", "head -n 1 .env\n"):
        script.write_text(source)
        request = extract_sensitive_tool_action_request(
            "Bash", {"command": "bash check.sh"}, cwd=tmp_path, home_dir=tmp_path
        )
        assert request is not None
        artifact = build_tool_action_request_artifact(
            harness="claude-code", request=request, config_path=str(tmp_path / "policy.json"), source_scope="project"
        )
        assert "local_secret_read" in artifact.metadata["risk_classes"]
        identities.append(artifact.artifact_id)
    assert identities[0] != identities[1]
