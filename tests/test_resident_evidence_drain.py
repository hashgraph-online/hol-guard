from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from codex_plugin_scanner.guard.resident_evidence_drain import ResidentEvidenceDrain, _decode_page


def _page(*, record_count: int, remaining: int, epoch: str = "e1") -> bytes:
    value: dict[str, object] = {
        "schema": "guard-hook-direct-evidence-commit.v1",
        "record_count": record_count,
        "remaining": remaining,
        "epoch": epoch,
    }
    return json.dumps(value).encode()


def _host(tmp_path: Path) -> SimpleNamespace:
    return SimpleNamespace(
        guard_home=tmp_path,
        policy_snapshot_publisher=object(),
        activity_writer=None,
        hook_counters=None,
    )


def test_resident_drain_repeats_a_commit_request_without_a_cursor(tmp_path: Path) -> None:
    pages = [_page(record_count=1, remaining=1), _page(record_count=0, remaining=0)]
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
    assert [json.loads(request["payload"])["request"] for request in requests] == [
        {"guard_home": str(tmp_path)},
        {"guard_home": str(tmp_path)},
    ]


def test_resident_drain_stops_after_committing_the_final_page(tmp_path: Path) -> None:
    pages = [_page(record_count=1, remaining=0), _page(record_count=0, remaining=0)]
    requests: list[dict[str, object]] = []

    def client(**values: object) -> bytes:
        requests.append(values)
        return pages.pop(0)

    drain = ResidentEvidenceDrain(_host(tmp_path), transport=lambda: (tmp_path / "runtime", client))

    assert drain.drain_once() is False
    assert drain.failures == 0
    assert len(requests) == 1
    assert drain.drain_once() is False
    assert json.loads(requests[1]["payload"])["operation"] == "hook_direct_evidence_commit"


def test_resident_drain_shutdown_budget_skips_expired_final_poll(tmp_path: Path) -> None:
    requests: list[dict[str, object]] = []

    def client(**values: object) -> bytes:
        requests.append(values)
        return _page(record_count=0, remaining=0)

    drain = ResidentEvidenceDrain(_host(tmp_path), transport=lambda: (tmp_path / "runtime", client))

    assert drain.stop(timeout_seconds=0) is True
    assert requests == []


def test_resident_drain_shutdown_commits_the_final_page_in_one_request(tmp_path: Path) -> None:
    pages = [_page(record_count=1, remaining=0)]
    requests: list[dict[str, object]] = []

    def client(**values: object) -> bytes:
        requests.append(values)
        return pages.pop(0)

    drain = ResidentEvidenceDrain(_host(tmp_path), transport=lambda: (tmp_path / "runtime", client))

    assert drain.stop(timeout_seconds=1) is True
    assert len(requests) == 1
    assert drain.records == 1


def test_resident_drain_does_not_record_page_contents_in_python(tmp_path: Path) -> None:
    received: list[object] = []

    def client(**_values: object) -> bytes:
        received.append("called")
        return _page(record_count=1, remaining=0)

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

    assert _decode_page(_page(record_count=0, remaining=0), counters) == (0, 0)
    assert counters.observed == []
