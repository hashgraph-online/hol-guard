"""The native queue producer and dashboard parser share a wire fixture."""

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_hook_adapter
from codex_plugin_scanner.guard.store import GuardStore


@pytest.fixture(autouse=True)
def _bound_native_runtime(native_approval_reuse_runtime: Path) -> Path:
    """Review presentation is answered by the compiled resident."""

    return native_approval_reuse_runtime


def _query(harness: str, payload: dict[str, object], native_result: dict[str, object] | None = None) -> dict:
    review = {
        "result": {"decision": "review", **(native_result or {})},
        "native_receipt": None,
        "request_id": uuid.uuid4().hex,
        "approval_center_url": "http://127.0.0.1:4781/approvals",
        "guard_home": "/guard-home",
        "review_binding": None,
        "exact_token": None,
        "once_only_reason": None,
        "queue_group_id": None,
        "bound_bash": None,
    }
    return native_hook_adapter.native_review_query(harness, payload, review, workspace=None, home_dir=None)


def _queued_envelope(root: Path, query: dict[str, object]) -> dict[str, object]:
    """The envelope of the request the resident builds and queues from ``query``."""

    store = GuardStore(root / uuid.uuid4().hex)
    row = store.queue_native_review(query, datetime.now(tz=timezone.utc).isoformat())
    assert row is not None
    envelope = row["action_envelope_json"]
    assert isinstance(envelope, dict)
    return envelope


def _envelope(
    root: Path, harness: str, payload: dict[str, object], native_result: dict[str, object] | None = None
) -> dict[str, object]:
    return _queued_envelope(root, _query(harness, payload, native_result))


def test_native_review_produces_dashboard_wire_contract(tmp_path: Path) -> None:
    expected = json.loads((Path(__file__).parent / "fixtures/native-review-action-envelope.json").read_text())
    actual = _envelope(
        tmp_path,
        "omp",
        {"tool_name": "eval", "tool_input": {"code": "1 + 1"}},
    )
    # ``action_id`` is now the stable canonical-action hash rather than the
    # request id, so the fixture only pins the remaining wire fields.
    assert {**actual, "action_id": expected["action_id"]} == expected


@pytest.mark.parametrize("harness", ("pi", "omp"))
def test_native_review_displays_redacted_read_details(tmp_path: Path, harness: str) -> None:
    envelope = _envelope(
        tmp_path,
        harness,
        {
            "tool_name": "read",
            "tool_input": {"path": "src/example.py", "password": "fixture-private-value"},
        },
    )
    assert envelope["action_type"] == "file_read"
    assert envelope["target_paths"] == ["src/example.py"]
    assert envelope["action_id"]
    assert "fixture-private-value" not in json.dumps(envelope)
    assert "src/example.py" in json.dumps(envelope["raw_payload_redacted"])


def test_native_review_displays_eval_input(tmp_path: Path) -> None:
    envelope = _envelope(
        tmp_path,
        "omp",
        {"tool_name": "eval", "tool_input": {"code": "1 + 1"}},
    )
    assert envelope["action_type"] == "shell_command"
    assert "1 + 1" in json.dumps(envelope["raw_payload_redacted"])


def test_native_review_preserves_configuration_classification(tmp_path: Path) -> None:
    envelope = _envelope(
        tmp_path,
        "omp",
        {"tool_name": "configure", "tool_input": {"setting": "example"}},
    )
    assert envelope["action_type"] == "config_change"
    assert "example" in json.dumps(envelope["raw_payload_redacted"])


def test_native_review_sets_command_category_from_command_extension_observations(tmp_path: Path) -> None:
    envelope = _envelope(
        tmp_path,
        "omp",
        {"tool_name": "Bash", "tool_input": {"command": "docker version --format '{{.Server.Version}}'"}},
        {
            "command_extensions": {
                "observations": [
                    {
                        "extension_id": "command.container-runtime",
                        "rule_id": "command.container-runtime.docker-sensitive",
                        "effective_segment_indexes": [0],
                    }
                ]
            }
        },
    )
    assert envelope["command_category"] == "command.container-runtime"


def test_native_review_redacts_code_without_filesystem_io(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("Review presentation must not inspect files")

    code = "1 + 1\n" * 4
    payload = {"tool_name": "eval", "tool_input": {"code": code, "apiKey": "fixture-private-value"}}
    # The daemon's half of the presentation, the query, must do no file I/O;
    # the resident builds the request from it inside the queue write.
    with monkeypatch.context() as scoped:
        for method in ("resolve", "stat", "lstat", "read_text", "read_bytes", "is_symlink"):
            scoped.setattr(Path, method, forbidden)
        query = _query("omp", payload)
    envelope = _queued_envelope(tmp_path, query)
    assert envelope["raw_payload_redacted"]["tool_input"]["code"] == code
    assert "fixture-private-value" not in json.dumps(envelope)
