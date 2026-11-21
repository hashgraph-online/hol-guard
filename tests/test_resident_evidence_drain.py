from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import resident_evidence_drain
from codex_plugin_scanner.guard.resident_evidence_drain import ResidentEvidenceDrain, _decode_batch


def _batch(*, record_count: int, pages: int = 1, more: bool = False, failed: bool = False) -> bytes:
    value: dict[str, object] = {
        "schema": "guard-hook-direct-evidence-batch.v1",
        "record_count": record_count,
        "pages": pages,
        "more": more,
        "failed": failed,
        "epoch": "e1",
    }
    return json.dumps(value).encode()


def _host(tmp_path: Path) -> SimpleNamespace:
    return SimpleNamespace(
        guard_home=tmp_path,
        policy_snapshot_publisher=object(),
        activity_writer=None,
        hook_counters=None,
    )


def test_resident_drain_uses_one_request_for_all_pages_from_the_resident(tmp_path: Path) -> None:
    requests: list[dict[str, object]] = []

    def client(**values: object) -> bytes:
        requests.append(values)
        return _batch(record_count=3, pages=2)

    drain = ResidentEvidenceDrain(
        _host(tmp_path),
        transport=lambda: (tmp_path / "runtime", client),
    )

    assert drain.drain_once() is False
    assert drain.pages == 2
    assert drain.records == 3
    assert drain.failures == 0
    assert len(requests) == 1
    request = json.loads(requests[0]["payload"])
    assert request["request"]["guard_home"] == str(tmp_path)
    batch = request["request"]["batch"]
    assert batch["shutdown"] is False
    assert 0 < batch["budget_ms"] < request["deadline_budget_ms"]


def test_resident_drain_waits_to_retry_after_a_partial_failure(tmp_path: Path) -> None:
    batches = [
        _batch(record_count=4, pages=2, failed=True),
        _batch(record_count=1, more=True),
    ]
    requests: list[dict[str, object]] = []

    def client(**values: object) -> bytes:
        requests.append(values)
        return batches.pop(0)

    drain = ResidentEvidenceDrain(_host(tmp_path), transport=lambda: (tmp_path / "runtime", client))

    assert drain.drain_once() is False
    assert drain.failures == 1
    assert drain.records == 4
    assert len(requests) == 1
    assert drain.drain_once() is True
    assert json.loads(requests[1]["payload"])["operation"] == "hook_direct_evidence_commit"


def test_resident_drain_shutdown_budget_skips_expired_final_poll(tmp_path: Path) -> None:
    requests: list[dict[str, object]] = []

    def client(**values: object) -> bytes:
        requests.append(values)
        return _batch(record_count=0)

    drain = ResidentEvidenceDrain(_host(tmp_path), transport=lambda: (tmp_path / "runtime", client))

    assert drain.stop(timeout_seconds=0) is True
    assert requests == []


def test_resident_drain_shutdown_commits_the_final_page_in_one_request(tmp_path: Path) -> None:
    batches = [_batch(record_count=1)]
    requests: list[dict[str, object]] = []

    def client(**values: object) -> bytes:
        requests.append(values)
        return batches.pop(0)

    drain = ResidentEvidenceDrain(_host(tmp_path), transport=lambda: (tmp_path / "runtime", client))

    assert drain.stop(timeout_seconds=1) is True
    assert len(requests) == 1
    assert drain.records == 1
    assert json.loads(requests[0]["payload"])["request"]["batch"]["shutdown"] is True


def test_resident_drain_shutdown_uses_the_remaining_budget_for_another_batch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = [0.0]
    monkeypatch.setattr(resident_evidence_drain, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    deadlines: list[object] = []

    def client(**values: object) -> bytes:
        deadlines.append(values["deadline_monotonic"])
        clock[0] += 1.8
        return _batch(record_count=1, more=len(deadlines) == 1)

    drain = ResidentEvidenceDrain(_host(tmp_path), transport=lambda: (tmp_path / "runtime", client))
    assert drain.stop(timeout_seconds=3.5)
    assert deadlines == [2.0, 3.5]
    assert drain.records == 2


def test_resident_drain_does_not_record_page_contents_in_python(tmp_path: Path) -> None:
    received: list[object] = []

    def client(**_values: object) -> bytes:
        received.append("called")
        return _batch(record_count=1)

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

    assert _decode_batch(_batch(record_count=0), counters) == (1, 0, False, False)
    assert counters.observed == []
