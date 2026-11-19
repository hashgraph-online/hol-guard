from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from codex_plugin_scanner.guard.evidence_drains.mcp_write_result import McpEvidenceWriteResult
from codex_plugin_scanner.guard.resident_evidence_drain import ResidentEvidenceDrain, _decode_page
from codex_plugin_scanner.guard.resident_evidence_fallback import _record_mcp_with_one_retry


def _page(*, records: list[object], remaining: int, through: int | None = None, epoch: str = "e1") -> bytes:
    value: dict[str, object] = {
        "schema": "guard-hook-direct-evidence.v1",
        "records": records,
        "remaining": remaining,
    }
    if through is not None:
        value.update(through=through, epoch=epoch)
    return json.dumps(value).encode()


def _host(tmp_path: Path) -> SimpleNamespace:
    return SimpleNamespace(
        guard_home=tmp_path,
        policy_snapshot_publisher=object(),
        activity_writer=None,
        hook_counters=None,
    )


def test_resident_drain_only_advances_the_rust_cursor(tmp_path: Path) -> None:
    pages = [_page(records=[{"receipt": {}}], remaining=1, through=2), _page(records=[], remaining=0)]
    requests: list[dict[str, object]] = []

    def client(**values: object) -> bytes:
        requests.append(values)
        return pages.pop(0)

    drain = ResidentEvidenceDrain(
        _host(tmp_path),
        transport=lambda: (tmp_path / "runtime", client),
        record_handler=lambda _record: True,
    )

    assert drain.drain_once() is False
    assert drain.pages == 2
    assert drain.records == 1
    assert drain.failures == 0
    assert json.loads(requests[1]["payload"]) ["request"] == {
        "guard_home": str(tmp_path),
        "ack_epoch": "e1",
        "ack_through": 2,
    }


def test_resident_drain_refuses_to_ack_records_left_for_the_daemon(tmp_path: Path) -> None:
    requests: list[dict[str, object]] = []

    def client(**values: object) -> bytes:
        requests.append(values)
        return _page(records=[{"receipt": {"decision_id": "x"}}], remaining=0, through=1)

    drain = ResidentEvidenceDrain(
        _host(tmp_path),
        transport=lambda: (tmp_path / "runtime", client),
        record_handler=lambda _record: False,
    )

    assert drain.drain_once() is False
    assert drain.failures == 1
    assert len(requests) == 1
    assert "ack_through" not in json.loads(requests[0]["payload"])["request"]


def test_resident_drain_does_not_repeat_records_handled_before_a_retry(tmp_path: Path) -> None:
    record = {"receipt": {"decision_id": "x"}}
    calls: list[object] = []
    responses = [
        _page(records=[record], remaining=0, through=1),
        _page(records=[record], remaining=0, through=1),
    ]

    def client(**_values: object) -> bytes:
        return responses.pop(0)

    def handler(value: object) -> bool:
        calls.append(value)
        return True

    drain = ResidentEvidenceDrain(
        _host(tmp_path),
        transport=lambda: (tmp_path / "runtime", client),
        record_handler=handler,
    )

    assert drain.drain_once() is False
    assert drain.drain_once() is False
    assert calls == [record]


def test_resident_drain_counts_fallback_exceptions_as_retryable(tmp_path: Path) -> None:
    def handler(_record: object) -> bool:
        raise RuntimeError("temporary store failure")

    drain = ResidentEvidenceDrain(
        _host(tmp_path),
        transport=lambda: (tmp_path / "runtime", lambda **_: _page(records=[{}], remaining=0, through=1)),
        record_handler=handler,
    )

    assert drain.drain_once() is False
    assert drain.failures == 1


def test_mcp_fallback_keeps_transient_write_pending() -> None:
    calls: list[object] = []

    def failed_write() -> McpEvidenceWriteResult:
        calls.append("write")
        return McpEvidenceWriteResult(False, False)

    record = {"kind": "mcp_tool_call", "identity": "identity"}
    assert _record_mcp_with_one_retry(record, failed_write) == "retry"
    assert _record_mcp_with_one_retry(record, failed_write) == "retry"
    assert _record_mcp_with_one_retry(record, failed_write) == "retry"
    assert _record_mcp_with_one_retry(record, failed_write) == "retry"
    assert _record_mcp_with_one_retry(record, failed_write) == "retry"
    assert calls == ["write", "write", "write", "write", "write"]


def test_mcp_fallback_drops_after_a_committed_followup_failure() -> None:
    calls: list[object] = []

    def committed_failure() -> McpEvidenceWriteResult:
        calls.append("write")
        return McpEvidenceWriteResult(False, True)

    record = {"kind": "mcp_tool_call", "identity": "committed"}
    assert _record_mcp_with_one_retry(record, committed_failure) == "drop"
    assert calls == ["write"]


def test_resident_drain_keeps_completion_keys_while_a_page_retries(tmp_path: Path) -> None:
    record_a, record_b, record_c = {"id": "a"}, {"id": "b"}, {"id": "c"}
    responses = [
        _page(records=[record_a, record_b, record_c], remaining=0, through=1, epoch="e1"),
        _page(records=[record_a, record_b, record_c], remaining=0, through=1, epoch="e1"),
    ]
    calls: list[object] = []

    def client(**_values: object) -> bytes:
        return responses.pop(0)

    def handler(record: object) -> bool:
        calls.append(record)
        return record != record_c

    drain = ResidentEvidenceDrain(
        _host(tmp_path),
        transport=lambda: (tmp_path / "runtime", client),
        record_handler=handler,
    )
    drain._handled_epoch = "e1"
    drain._handled_records = {f"old-{index}" for index in range(4095)}

    assert drain.drain_once() is False
    assert drain.drain_once() is False
    assert calls == [record_a, record_b, record_c, record_c]


def test_resident_drain_shutdown_budget_skips_expired_final_poll(tmp_path: Path) -> None:
    requests: list[dict[str, object]] = []

    def client(**values: object) -> bytes:
        requests.append(values)
        return _page(records=[], remaining=0)

    drain = ResidentEvidenceDrain(_host(tmp_path), transport=lambda: (tmp_path / "runtime", client))

    assert drain.stop(timeout_seconds=0) is True
    assert requests == []


def test_resident_drain_shutdown_delivers_the_final_cursor(tmp_path: Path) -> None:
    pages = [_page(records=[], remaining=0, through=1), _page(records=[], remaining=0)]
    requests: list[dict[str, object]] = []

    def client(**values: object) -> bytes:
        requests.append(values)
        return pages.pop(0)

    drain = ResidentEvidenceDrain(_host(tmp_path), transport=lambda: (tmp_path / "runtime", client))

    assert drain.stop(timeout_seconds=1) is True
    assert len(requests) == 2
    assert json.loads(requests[1]["payload"])["request"]["ack_through"] == 1


def test_resident_drain_does_not_record_page_contents_in_python(tmp_path: Path) -> None:
    received: list[object] = []

    def client(**_values: object) -> bytes:
        received.append("called")
        return _page(records=[{"receipt": {"decision_id": "x"}}], remaining=0, through=1)

    host = _host(tmp_path)
    host.activity_writer = SimpleNamespace(submit_native_decision_receipt=lambda **_: received.append("written"))
    drain = ResidentEvidenceDrain(host, transport=lambda: (tmp_path / "runtime", client))

    assert drain.drain_once() is False
    assert received == ["called"]


def test_resident_drain_rejects_invalid_pages(tmp_path: Path) -> None:
    drain = ResidentEvidenceDrain(_host(tmp_path), transport=lambda: (tmp_path, lambda **_: b"not-json"))

    assert drain.drain_once() is False
    assert drain.failures == 1


def test_page_decoder_keeps_counters_as_diagnostics_only() -> None:
    counters = SimpleNamespace(observed=[])
    counters.observe_page = lambda epoch, value: counters.observed.append((epoch, value))

    assert _decode_page(_page(records=[], remaining=0), counters) == ([], 0, None)
    assert counters.observed == []
