from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from codex_plugin_scanner.guard.resident_evidence_drain import ResidentEvidenceDrain, _decode_page


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


def test_resident_drain_acknowledges_the_native_page_without_inspecting_records(tmp_path: Path) -> None:
    pages = [_page(records=[{"receipt": {"decision_id": "x"}}], remaining=0, through=1), _page(records=[], remaining=0)]
    requests: list[dict[str, object]] = []

    def client(**values: object) -> bytes:
        requests.append(values)
        return pages.pop(0)

    drain = ResidentEvidenceDrain(_host(tmp_path), transport=lambda: (tmp_path / "runtime", client))

    assert drain.drain_once() is False
    assert drain.failures == 0
    assert len(requests) == 1
    assert drain.drain_once() is False
    assert json.loads(requests[1]["payload"])["request"] == {
        "guard_home": str(tmp_path),
        "ack_epoch": "e1",
        "ack_through": 1,
    }


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
