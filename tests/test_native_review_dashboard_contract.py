"""The native queue producer and dashboard parser share a wire fixture."""

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_hook_adapter
from codex_plugin_scanner.guard.daemon.hook_native_review_approval import _native_review_action_envelope


@pytest.fixture(autouse=True)
def _bound_native_runtime(native_approval_reuse_runtime: Path) -> Path:
    """Review presentation is answered by the compiled resident."""

    return native_approval_reuse_runtime


def _envelope(harness: str, payload: dict[str, object]) -> dict[str, object]:
    envelope = _native_review_action_envelope(
        harness=harness,
        payload=payload,
        workspace=None,
        home_dir=None,
    )
    assert envelope is not None
    return envelope


def test_native_review_produces_dashboard_wire_contract() -> None:
    expected = json.loads((Path(__file__).parent / "fixtures/native-review-action-envelope.json").read_text())
    actual = _envelope(
        "omp",
        {"tool_name": "eval", "tool_input": {"code": "1 + 1"}},
    )
    # ``action_id`` is now the stable canonical-action hash rather than the
    # request id, so the fixture only pins the remaining wire fields.
    assert {**actual, "action_id": expected["action_id"]} == expected


@pytest.mark.parametrize("harness", ("pi", "omp"))
def test_native_review_displays_redacted_read_details(harness: str) -> None:
    envelope = _envelope(
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


def test_native_review_displays_eval_input() -> None:
    envelope = _envelope(
        "omp",
        {"tool_name": "eval", "tool_input": {"code": "1 + 1"}},
    )
    assert envelope["action_type"] == "shell_command"
    assert "1 + 1" in json.dumps(envelope["raw_payload_redacted"])


def test_native_review_preserves_configuration_classification() -> None:
    envelope = _envelope(
        "omp",
        {"tool_name": "configure", "tool_input": {"setting": "example"}},
    )
    assert envelope["action_type"] == "config_change"
    assert "example" in json.dumps(envelope["raw_payload_redacted"])


def _recorded_answers(monkeypatch: pytest.MonkeyPatch) -> list[tuple[dict[str, object], dict[str, object]]]:
    """Record the real resident's (request, answer) pairs for the next presentation."""

    real = native_hook_adapter._resident_request
    recorded: list[tuple[dict[str, object], dict[str, object]]] = []

    def record(**kwargs: object) -> dict[str, object] | None:
        answer = real(**kwargs)  # type: ignore[arg-type]
        assert answer is not None
        recorded.append((kwargs["request"], answer))  # type: ignore[arg-type]
        return answer

    monkeypatch.setattr(native_hook_adapter, "_resident_request", record)
    return recorded


def test_native_review_redacts_code_without_filesystem_io(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("Review presentation must not inspect files")

    code = "1 + 1\n" * 4
    payload = {"tool_name": "eval", "tool_input": {"code": code, "apiKey": "fixture-private-value"}}
    # Phase 1: the compiled resident answers; its transport is allowed to touch the
    # filesystem (runtime identity, sockets). Record its request/answer pairs.
    recorded = _recorded_answers(monkeypatch)
    assert _envelope("omp", payload)
    home = native_hook_adapter._resolve_digest_home(None)
    # Phase 2: replay the resident's own answers through the unchanged adapter with the
    # transport seam stubbed, so the Python presentation path itself must do no file I/O.
    pending = list(recorded)

    def replay(*, request: dict[str, object], **_kwargs: object) -> dict[str, object]:
        original, answer = pending.pop(0)
        assert request["query"] == original["query"]
        return {
            **answer,
            "request_id": request["request_id"],
            "request_sha256": "sha256:" + native_hook_adapter._canonical_request_sha256(request),
        }

    with monkeypatch.context() as scoped:
        scoped.setattr(native_hook_adapter, "_resolve_digest_home", lambda _home: home)
        scoped.setattr(native_hook_adapter, "ensure_resident_prerequisite", lambda _home: True)
        scoped.setattr(native_hook_adapter, "_resident_request", replay)
        for method in ("resolve", "stat", "lstat", "read_text", "read_bytes", "is_symlink"):
            scoped.setattr(Path, method, forbidden)
        envelope = _envelope("omp", payload)
    assert not pending
    assert envelope["raw_payload_redacted"]["tool_input"]["code"] == code
    assert "fixture-private-value" not in json.dumps(envelope)
