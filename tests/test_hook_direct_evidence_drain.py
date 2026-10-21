from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_decision_receipt
from codex_plugin_scanner.guard.daemon import hook_native_cli_observer
from codex_plugin_scanner.guard.daemon.hook_direct_evidence_drain import (
    DirectHookEvidenceDrain,
    record_direct_hook_evidence,
)

RECEIPT = {"decision_id": "e" * 64, "policy_action": "allow"}
PAYLOAD = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "ls"}}
RESPONSE = {"continue": True, "policy_action": "allow", "reason_code": "native_allow"}


class _Writer:
    def __init__(self) -> None:
        self.receipts: list[Mapping[str, object]] = []
        self.activity: list[dict[str, object]] = []

    def submit_native_decision_receipt(self, *, receipt: Mapping[str, object]) -> None:
        self.receipts.append(receipt)

    def submit_command_activity(self, **values: object) -> None:
        self.activity.append(values)


@dataclass
class _Host:
    guard_home: Path
    store: object = field(default_factory=object)
    activity_writer: _Writer = field(default_factory=_Writer)
    policy_snapshot_publisher: object = field(default_factory=object)
    post_tool_activity: list[dict[str, object]] = field(default_factory=list)

    def _record_post_tool_activity(self, *, harness: str, payload: Mapping[str, object], succeeded: bool) -> None:
        self.post_tool_activity.append({"harness": harness, "payload": payload, "succeeded": succeeded})


def _host(tmp_path: Path) -> _Host:
    return _Host(tmp_path)


def _record(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "harness": "codex",
        "workspace": "/work",
        "home_dir": "/home/user",
        "payload": dict(PAYLOAD),
        "receipt": dict(RECEIPT),
        "harness_response": dict(RESPONSE),
    }
    value.update(overrides)
    return value


@pytest.fixture
def observed(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, object]]:
    calls: list[dict[str, object]] = []
    monkeypatch.setattr(native_decision_receipt, "validate_native_decision_receipt", lambda receipt: receipt)
    monkeypatch.setattr(
        hook_native_cli_observer,
        "observe_native_pre_tool_cli",
        lambda store, **values: calls.append(values),
    )
    return calls


def test_a_drained_answer_is_recorded_like_a_daemon_allow(tmp_path: Path, observed: list[dict[str, object]]) -> None:
    host = _host(tmp_path)
    assert record_direct_hook_evidence(host, _record())

    assert host.activity_writer.receipts == [RECEIPT]
    assert observed == [{"payload": PAYLOAD, "workspace": Path("/work"), "home_dir": Path("/home/user")}]
    [activity] = host.activity_writer.activity
    assert activity["harness"] == "codex"
    assert activity["event"] == "PreToolUse"
    assert activity["policy_action"] == "allow"
    assert activity["receipt_id"] == RECEIPT["decision_id"]


class _EventStore:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, object]]] = []

    def add_event(self, event_name: str, payload: dict[str, object], now: str) -> None:
        del now
        self.events.append((event_name, payload))


def test_a_drained_answer_that_waited_out_a_policy_update_leaves_a_window_event(
    tmp_path: Path, observed: list[dict[str, object]]
) -> None:
    host = _Host(tmp_path, store=_EventStore())
    assert record_direct_hook_evidence(host, _record(fence_wait_ms=300))

    [(name, payload)] = host.store.events  # pyright: ignore[reportAttributeAccessIssue]
    assert name == "policy_source_fence_window"
    assert payload["absorbed_calls"] == 1
    assert payload["exhausted_calls"] == 0
    assert host.activity_writer.receipts == [RECEIPT]


def test_a_drained_answer_without_a_wait_leaves_no_window_event(
    tmp_path: Path, observed: list[dict[str, object]]
) -> None:
    host = _Host(tmp_path, store=_EventStore())
    assert record_direct_hook_evidence(host, _record())
    assert record_direct_hook_evidence(host, _record(fence_wait_ms=0))
    assert host.store.events == []  # pyright: ignore[reportAttributeAccessIssue]


@pytest.mark.parametrize(
    "harness", ["claude-code", "cursor", "kimi", "copilot", "zcode", "hermes", "opencode", "grok", "pi", "omp"]
)
def test_a_drained_answer_is_recorded_for_its_harness(
    tmp_path: Path, observed: list[dict[str, object]], harness: str
) -> None:
    host = _host(tmp_path)
    assert record_direct_hook_evidence(host, _record(harness=harness))

    [activity] = host.activity_writer.activity
    assert activity["harness"] == harness
    assert activity["policy_action"] == "allow"


class _Capture:
    def __init__(self) -> None:
        self.captured: list[dict[str, object]] = []

    def submit_native_capture(self, **values: object) -> bool:
        self.captured.append(values)
        return True


@pytest.mark.parametrize(("harness", "captured"), [("codex", 1), ("claude-code", 0), ("cursor", 0)])
def test_a_codex_receipt_reaches_the_binding_capture(
    tmp_path: Path, observed: list[dict[str, object]], harness: str, captured: int
) -> None:
    host = _host(tmp_path)
    capture = _Capture()
    host.capture_writer = capture  # pyright: ignore[reportAttributeAccessIssue]
    assert record_direct_hook_evidence(host, _record(harness=harness))

    assert len(capture.captured) == captured
    if captured:
        assert capture.captured[0]["guard_home"] == tmp_path
        assert capture.captured[0]["receipt"] == RECEIPT


@pytest.mark.parametrize(
    "record",
    [
        "not a record",
        _record(harness="gemini"),
        _record(payload="ls"),
        _record(workspace=None),
        _record(harness_response=None),
        _record(event="Stop"),
        _record(event=None),
    ],
)
def test_a_malformed_record_is_not_recorded(tmp_path: Path, observed: list[dict[str, object]], record: object) -> None:
    host = _host(tmp_path)
    assert not record_direct_hook_evidence(host, record)
    assert host.activity_writer.receipts == []
    assert host.activity_writer.activity == []
    assert observed == []
    assert host.post_tool_activity == []


def test_an_unmanaged_harness_is_passed_through_without_recording(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, observed: list[dict[str, object]]
) -> None:
    from codex_plugin_scanner.guard.daemon import hook_managed_install_state

    harnesses: list[str] = []

    def unmanaged(host: object, harness: str) -> bool:
        harnesses.append(harness)
        return True

    monkeypatch.setattr(hook_managed_install_state, "_hook_harness_is_unmanaged", unmanaged)
    host = _host(tmp_path)
    assert record_direct_hook_evidence(host, _record())
    assert harnesses == ["codex"]
    assert host.activity_writer.receipts == []
    assert host.activity_writer.activity == []
    assert observed == []


def test_an_invalid_receipt_is_not_submitted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, observed: list[dict[str, object]]
) -> None:
    monkeypatch.setattr(native_decision_receipt, "validate_native_decision_receipt", lambda receipt: None)
    host = _host(tmp_path)
    assert record_direct_hook_evidence(host, _record())
    assert host.activity_writer.receipts == []
    assert host.activity_writer.activity[0]["receipt_id"] is None


def _page(records: list[object], remaining: int, through: int | None = None, epoch: object = "e1") -> bytes:
    body: dict[str, object] = {
        "schema": "guard-hook-direct-evidence.v1",
        "records": records,
        "remaining": remaining,
    }
    if through is not None:
        body["through"] = through
        body["epoch"] = epoch
    return json.dumps(body).encode()


def test_drain_pulls_pages_until_the_queue_is_empty(tmp_path: Path, observed: list[dict[str, object]]) -> None:
    host = _host(tmp_path)
    pages = [_page([_record(), "junk"], 1, through=2), _page([_record()], 0, through=3)]
    requests: list[dict[str, object]] = []

    def client(**values: object) -> bytes:
        requests.append(values)
        return pages.pop(0)

    drain = DirectHookEvidenceDrain(host, transport=lambda: (tmp_path / "guard-runtime", client))
    assert drain.drain_once() is False
    assert (drain.recorded, drain.rejected, drain.failures) == (2, 1, 0)
    assert len(requests) == 2
    assert requests[0]["executable"] == tmp_path / "guard-runtime"
    assert json.loads(requests[0]["payload"]) == {  # pyright: ignore[reportArgumentType]
        "operation": "hook_direct_evidence_drain",
        "deadline_budget_ms": 2_000,
        "request": {"guard_home": str(tmp_path)},
    }
    assert json.loads(requests[1]["payload"])["request"]["ack_through"] == 2  # pyright: ignore[reportArgumentType]
    assert json.loads(requests[1]["payload"])["request"]["ack_epoch"] == "e1"  # pyright: ignore[reportArgumentType]


@pytest.mark.parametrize("epoch", [None, "", 7])
def test_a_cursor_without_its_resident_epoch_is_a_bad_page(tmp_path: Path, epoch: object) -> None:
    output = _page([_record()], 0, through=1, epoch=epoch)
    drain = DirectHookEvidenceDrain(_host(tmp_path), transport=lambda: (tmp_path, lambda **_: output))
    assert drain.drain_once() is False
    assert (drain.recorded, drain.failures) == (0, 1)


def test_a_restarted_resident_gets_the_cursor_of_its_own_page(
    tmp_path: Path, observed: list[dict[str, object]]
) -> None:
    host = _host(tmp_path)
    pages = [_page([_record()], 0, through=9, epoch="old"), _page([_record()], 0, through=1, epoch="new"), _page([], 0)]
    requests: list[dict[str, object]] = []

    def client(**values: object) -> bytes:
        requests.append(values)
        return pages.pop(0)

    drain = DirectHookEvidenceDrain(host, transport=lambda: (tmp_path, client))
    for _ in range(3):
        drain.drain_once()
    sent = [json.loads(request["payload"])["request"] for request in requests]  # pyright: ignore[reportArgumentType]
    assert [(item.get("ack_epoch"), item.get("ack_through")) for item in sent] == [(None, None), ("old", 9), ("new", 1)]


@pytest.mark.parametrize("output", [None, b"", b"not json", b'{"schema":"other","records":[],"remaining":0}'])
def test_drain_counts_a_bad_page_as_a_failure(tmp_path: Path, output: bytes | None) -> None:
    drain = DirectHookEvidenceDrain(_host(tmp_path), transport=lambda: (tmp_path, lambda **_: output))
    assert drain.drain_once() is False
    assert drain.failures == 1


def test_a_lost_page_is_requested_again_with_the_same_cursor(tmp_path: Path) -> None:
    host = _host(tmp_path)
    outputs = [None, _page([_record()], 0, through=4)]
    requests: list[dict[str, object]] = []

    def client(**values: object) -> bytes | None:
        requests.append(values)
        output = outputs.pop(0)
        return output

    drain = DirectHookEvidenceDrain(host, transport=lambda: (tmp_path / "guard-runtime", client))
    assert drain.drain_once() is False
    assert drain.failures == 1
    assert drain.drain_once() is False
    assert drain.recorded == 1
    assert "ack_through" not in json.loads(requests[0]["payload"])["request"]  # pyright: ignore[reportArgumentType]
    assert "ack_through" not in json.loads(requests[1]["payload"])["request"]  # pyright: ignore[reportArgumentType]


def test_drain_without_a_resident_does_nothing(tmp_path: Path) -> None:
    drain = DirectHookEvidenceDrain(_host(tmp_path), transport=lambda: None)
    assert drain.drain_once() is False
    assert drain.failures == 0


def test_stop_collects_what_the_resident_still_holds(tmp_path: Path, observed: list[dict[str, object]]) -> None:
    host = _host(tmp_path)
    drain = DirectHookEvidenceDrain(host, transport=lambda: (tmp_path, lambda **_: _page([_record()], 0, through=1)))
    drain.stop()
    assert drain.recorded == 1


POST_PAYLOAD = {
    "hook_event_name": "PostToolUse",
    "tool_name": "Bash",
    "tool_input": {"command": "ls"},
    "tool_response": {"stdout": "README.md"},
}


@pytest.mark.parametrize(("harness", "captured"), [("codex", 1), ("claude-code", 0)])
def test_a_drained_post_tool_use_is_recorded_like_the_daemon_records_it(
    tmp_path: Path, observed: list[dict[str, object]], harness: str, captured: int
) -> None:
    host = _host(tmp_path)
    capture = _Capture()
    host.capture_writer = capture  # pyright: ignore[reportAttributeAccessIssue]
    record = _record(event="PostToolUse", harness=harness, payload=dict(POST_PAYLOAD))
    assert record_direct_hook_evidence(host, record)

    assert host.activity_writer.receipts == [RECEIPT]
    assert len(capture.captured) == captured
    assert host.post_tool_activity == [{"harness": harness, "payload": POST_PAYLOAD, "succeeded": True}]
    # The pre-tool recording does not run after a tool already ran.
    assert observed == []
    assert host.activity_writer.activity == []


def test_a_failed_tool_is_recorded_as_failed(tmp_path: Path, observed: list[dict[str, object]]) -> None:
    host = _host(tmp_path)
    payload = {**POST_PAYLOAD, "exit_code": 2}
    assert record_direct_hook_evidence(host, _record(event="PostToolUse", payload=payload))

    [activity] = host.post_tool_activity
    assert activity["succeeded"] is False


PROMPT_PAYLOAD = {"hook_event_name": "UserPromptSubmit", "prompt": "List the files in this repository."}


@pytest.mark.parametrize(("harness", "captured"), [("codex", 1), ("claude-code", 0)])
def test_a_drained_prompt_records_only_its_receipt_and_capture(
    tmp_path: Path, observed: list[dict[str, object]], harness: str, captured: int
) -> None:
    host = _host(tmp_path)
    capture = _Capture()
    host.capture_writer = capture  # pyright: ignore[reportAttributeAccessIssue]
    record = _record(event="UserPromptSubmit", harness=harness, payload=dict(PROMPT_PAYLOAD))
    assert record_direct_hook_evidence(host, record)

    assert host.activity_writer.receipts == [RECEIPT]
    assert len(capture.captured) == captured
    # The daemon records no command activity or observation for a prompt.
    assert observed == []
    assert host.activity_writer.activity == []
    assert host.post_tool_activity == []
