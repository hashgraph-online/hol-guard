"""The native queue producer and dashboard parser share a wire fixture."""

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon.hook_native_review_approval import _native_review_action_envelope


def test_native_review_produces_dashboard_wire_contract() -> None:
    expected = json.loads((Path(__file__).parent / "fixtures/native-review-action-envelope.json").read_text())
    actual = _native_review_action_envelope(
        request_id="native-review-fixture",
        harness="omp",
        tool_name="eval",
        command=None,
        launch_target="tool:eval",
        workspace=None,
    )
    assert actual == expected


@pytest.mark.parametrize("harness", ("pi", "omp"))
def test_native_review_displays_redacted_read_details(harness: str) -> None:
    envelope = _native_review_action_envelope(
        request_id="read-review",
        harness=harness,
        tool_name="read",
        command=None,
        launch_target="tool:read",
        workspace=None,
        payload={
            "tool_name": "read",
            "tool_input": {"path": "src/example.py", "password": "fixture-private-value"},
        },
    )
    assert envelope["action_type"] == "file_read"
    assert envelope["target_paths"] == ["src/example.py"]
    assert envelope["action_id"] == "read-review"
    assert "fixture-private-value" not in json.dumps(envelope)
    assert "src/example.py" in json.dumps(envelope["raw_payload_redacted"])


def test_native_review_displays_eval_input() -> None:
    envelope = _native_review_action_envelope(
        request_id="eval-review",
        harness="omp",
        tool_name="eval",
        command=None,
        launch_target="tool:eval",
        workspace=None,
        payload={"tool_name": "eval", "tool_input": {"code": "1 + 1"}},
    )
    assert envelope["action_type"] == "mcp_tool"
    assert "1 + 1" in json.dumps(envelope["raw_payload_redacted"])
