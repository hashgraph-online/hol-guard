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
        payload={"tool_name": "eval", "tool_input": {"code": "1 + 1"}},
    )
    assert actual == expected


@pytest.mark.parametrize("harness", ("pi", "omp", "unregistered-native-fixture"))
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
        native_action={"action_type": "file_read"},
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
    assert envelope["action_type"] == "config_change"
    assert "1 + 1" in json.dumps(envelope["raw_payload_redacted"])


def test_native_review_preserves_configuration_classification() -> None:
    envelope = _native_review_action_envelope(
        request_id="config-review", harness="omp", tool_name="configure", command=None,
        launch_target="tool:configure", workspace=None,
        payload={"tool_name": "configure", "tool_input": {"setting": "example"}},
        native_action={"action_type": "config"},
    )
    assert envelope["action_type"] == "config_change"
    assert "example" in json.dumps(envelope["raw_payload_redacted"])


@pytest.mark.parametrize("harness", ("", " \t\n"))
def test_native_review_rejects_empty_harness(harness: str) -> None:
    with pytest.raises(ValueError, match="harness must not be empty"):
        _native_review_action_envelope(
            request_id="invalid-harness", harness=harness, tool_name="read", command=None,
            launch_target="tool:read", workspace=None, payload={"tool_name": "read"},
        )


def test_native_review_does_not_infer_kind_from_tool_name() -> None:
    envelope = _native_review_action_envelope(
        request_id="native-config", harness="omp", tool_name="read", command=None,
        launch_target="tool:read", workspace=None,
        payload={"tool_name": "read", "tool_input": {"path": "src/example.py"}},
        native_action={"action_type": "config"},
    )
    assert envelope["action_type"] == "config_change"
    assert envelope["target_paths"] == []


def test_native_review_preserves_full_code_without_filesystem_io(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("Review presentation must not inspect files")

    code = "1 + 1\n" * 100
    with monkeypatch.context() as scoped:
        for method in ("resolve", "stat", "lstat", "read_text", "read_bytes", "is_symlink"):
            scoped.setattr(Path, method, forbidden)
        envelope = _native_review_action_envelope(
            request_id="pure-review", harness="omp", tool_name="eval", command=None,
            launch_target="tool:eval", workspace=None,
            payload={"tool_name": "eval", "tool_input": {"code": code, "apiKey": "fixture-private-value"}},
        )
    assert envelope["raw_payload_redacted"]["tool_input"]["code"] == code
    assert "fixture-private-value" not in json.dumps(envelope)
