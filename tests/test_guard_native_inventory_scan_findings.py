"""The scan-findings bridge ships the runs and keeps no classification of its own."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import inventory_contract, native_resident_client
from codex_plugin_scanner.guard import native_inventory_scan_findings as bridge


class _Severity(Enum):
    HIGH = "high"


@dataclass
class _RawFinding:
    rule_id: str = "rule-1"
    title: str = "Something"
    description: str = "Details"
    file_path: str | None = "/w/skills/s0/SKILL.md"
    line_number: int | None = 12
    severity: object = "high"


@dataclass
class _Run:
    source: str = "cisco-aisec"
    status: str = "enabled"
    message: str = "scanned"
    duration_ms: int = 40
    metadata: dict[str, object] | None = None
    findings: tuple[object, ...] = ()


@dataclass
class _Item:
    item_id: str = "codex:skill:s0"
    metadata: dict[str, object] | None = None


def _resident(monkeypatch: pytest.MonkeyPatch, reply) -> list[dict[str, object]]:
    """Stub the transport; the returned list records every request wire sent."""

    sent: list[dict[str, object]] = []
    monkeypatch.setattr(bridge, "_resolve_digest_home", lambda _home: Path("/tmp/inventory-scan-home"))
    monkeypatch.setattr(bridge, "ensure_resident_prerequisite", lambda _home: True)

    def fake(*, request, **_kwargs):
        sent.append(request)
        return reply(request)

    monkeypatch.setattr(bridge, "_resident_request", fake)
    monkeypatch.setattr(bridge, "_payload", lambda response, _request, _home: response)
    return sent


def _answers(_request: dict[str, object]) -> dict[str, object]:
    return {"findings": [], "sources": []}


def _ask(runs, items=(), **kwargs):
    return bridge.native_inventory_scan_findings(
        runs,
        harness="codex",
        items=items,
        home_dir=Path("/h"),
        workspace_dir=Path("/w"),
        **kwargs,
    )


def test_nothing_to_classify_never_reaches_the_resident(monkeypatch: pytest.MonkeyPatch) -> None:
    sent = _resident(monkeypatch, _answers)
    assert _ask([]) == ([], [])
    assert sent == []


def test_items_alone_still_reach_the_resident(monkeypatch: pytest.MonkeyPatch) -> None:
    """A detection that walked symlinks carries evidence even with no scanner."""

    sent = _resident(monkeypatch, _answers)
    _ask([], items=[_Item()])
    assert len(sent) == 1


def test_items_without_a_symlink_walk_need_no_request(monkeypatch: pytest.MonkeyPatch) -> None:
    sent = _resident(monkeypatch, _answers)
    assert _ask([], items=[_Item()], include_symlinks=False) == ([], [])
    assert sent == []


def test_the_wire_carries_the_fields_the_grammar_reads(monkeypatch: pytest.MonkeyPatch) -> None:
    sent = _resident(monkeypatch, _answers)
    monkeypatch.setattr(bridge.Path, "cwd", classmethod(lambda _cls: Path("/run/from")))
    _ask(
        [_Run(metadata={"totalFindings": 1}, findings=(_RawFinding(),))],
        items=[_Item(metadata={"configPath": "/w/skills/s0/SKILL.md", "sourceOfTruth": {"validationState": "loop"}})],
    )
    (wire,) = sent
    assert wire["schema"] == "guard-inventory-scan-findings-request.v1"
    assert wire["harness"] == "codex"
    assert wire["home_dir"] == "/h"
    assert wire["workspace_dir"] == "/w"
    assert wire["cwd"] == "/run/from"
    assert wire["include_symlinks"] is True
    assert wire["cisco_runs"] == [
        {
            "source": "cisco-aisec",
            "status": "enabled",
            "message": "scanned",
            "duration_ms": 40,
            "metadata": {"totalFindings": 1},
            "findings": [
                {
                    "rule_id": "rule-1",
                    "title": "Something",
                    "description": "Details",
                    "file_path": "/w/skills/s0/SKILL.md",
                    "line_number": 12,
                    "severity": "high",
                }
            ],
        }
    ]
    assert wire["items"] == [
        {
            "item_id": "codex:skill:s0",
            "metadata": {"configPath": "/w/skills/s0/SKILL.md", "sourceOfTruth": {"validationState": "loop"}},
        }
    ]


def test_a_severity_enum_ships_its_token_not_its_member_name(monkeypatch: pytest.MonkeyPatch) -> None:
    """The resident normalizes the token, so it has to receive the token."""

    sent = _resident(monkeypatch, _answers)
    _ask([_Run(findings=(_RawFinding(severity=_Severity.HIGH),))])
    assert sent[0]["cisco_runs"][0]["findings"][0]["severity"] == "high"


def test_an_item_ships_only_the_metadata_the_grammar_reads(monkeypatch: pytest.MonkeyPatch) -> None:
    sent = _resident(monkeypatch, _answers)
    _ask([], items=[_Item(metadata={"configPath": "/w/a", "secretToken": "shh", "sourceOfTruth": {}})])
    assert sent[0]["items"][0]["metadata"] == {"configPath": "/w/a", "sourceOfTruth": {}}


def test_a_workspace_the_caller_does_not_have_is_left_out(monkeypatch: pytest.MonkeyPatch) -> None:
    sent = _resident(monkeypatch, _answers)
    bridge.native_inventory_scan_findings([_Run()], harness="codex", items=(), home_dir=Path("/h"))
    assert "workspace_dir" not in sent[0]


def test_a_bigger_scan_is_given_a_longer_deadline() -> None:
    """A fixed deadline would fail an inventory purely for being big."""

    small = bridge._request_timeout_seconds(1)
    large = bridge._request_timeout_seconds(bridge._MAX_ITEMS)
    assert bridge._TIMEOUT_FLOOR_SECONDS <= small < large <= bridge._TIMEOUT_CEILING_SECONDS


def test_the_bridge_never_offers_more_than_the_transport_frames() -> None:
    """A bound above the frame limit refuses a scan as a dead runtime.

    The bridge measures the serialized envelope and so does the resident client,
    on the very same bytes, so a bound at the client's ceiling admits every scan
    the client would have framed and no more. A bound above it would hand the
    client a request it drops before dispatch, and the caller would read a scan
    that merely asked for too much as a runtime that stopped answering.
    """

    assert bridge._MAX_REQUEST_BYTES <= native_resident_client._MAX_REQUEST_BYTES


def test_more_than_the_cap_fails_closed_rather_than_splitting(monkeypatch: pytest.MonkeyPatch) -> None:
    """Findings deduplicate across the whole scan, so batches would differ."""

    _resident(monkeypatch, _answers)
    with pytest.raises(bridge.InventoryScanFindingsUnavailableError):
        _ask([_Run()] * (bridge._MAX_RUNS + 1))


@pytest.mark.parametrize(
    "reply",
    [
        lambda request: {"findings": "nope", "sources": []},
        lambda request: {"findings": [], "sources": "nope"},
        lambda request: {"findings": ["nope"], "sources": []},
        lambda request: "nope",
    ],
)
def test_an_answer_that_does_not_match_the_request_is_refused(monkeypatch: pytest.MonkeyPatch, reply) -> None:
    _resident(monkeypatch, reply)
    with pytest.raises(bridge.InventoryScanFindingsUnavailableError):
        _ask([_Run()])


def test_a_resident_that_cannot_run_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    _resident(monkeypatch, _answers)
    monkeypatch.setattr(bridge, "ensure_resident_prerequisite", lambda _home: False)
    with pytest.raises(bridge.InventoryScanFindingsUnavailableError):
        _ask([_Run()])


def test_a_deleted_working_directory_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    """Reading the working directory is I/O, and it answers like any other."""

    _resident(monkeypatch, _answers)

    def gone() -> Path:
        raise FileNotFoundError(2, "No such file or directory")

    monkeypatch.setattr(bridge.Path, "cwd", staticmethod(gone))
    with pytest.raises(bridge.InventoryScanFindingsUnavailableError):
        _ask([_Run()])


def test_a_transport_failure_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    def explode(request):
        raise OSError("no socket")

    _resident(monkeypatch, explode)
    with pytest.raises(bridge.InventoryScanFindingsUnavailableError):
        _ask([_Run()])


def test_a_record_the_dataclass_cannot_take_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    """Disagreement about the contract is unavailability, not a partial answer."""

    def strange(_entries, **_kwargs):
        return [{"finding_id": "x", "not_a_field": 1}], []

    monkeypatch.setattr(inventory_contract, "native_inventory_scan_findings", strange)
    with pytest.raises(bridge.InventoryScanFindingsUnavailableError):
        inventory_contract._scan_records(
            [],
            harness="codex",
            items=(),
            home_dir=Path("/h"),
            workspace_dir=None,
            include_symlinks=True,
        )


def test_the_snapshot_builder_passes_the_resident_answers_through(monkeypatch: pytest.MonkeyPatch) -> None:
    def answer(_entries, **_kwargs):
        return (
            [
                {
                    "finding_id": "cisco-aisec:rule-1:0123456789abcdef",
                    "source": "cisco-aisec",
                    "severity": "high",
                    "confidence": "high",
                    "title": "Something",
                    "artifact_id": "codex:skill:s0",
                    "check_id": "rule-1",
                    "summary": "Details",
                    "evidence": {"scannerStatus": "enabled"},
                }
            ],
            [{"source_id": "cisco-aisec:0123456789ab", "source_type": "scanner", "status": "available"}],
        )

    monkeypatch.setattr(inventory_contract, "native_inventory_scan_findings", answer)
    findings, sources = inventory_contract._scan_records(
        [],
        harness="codex",
        items=(),
        home_dir=Path("/h"),
        workspace_dir=None,
        include_symlinks=True,
    )
    assert [finding.check_id for finding in findings] == ["rule-1"]
    assert [source.status for source in sources] == ["available"]
