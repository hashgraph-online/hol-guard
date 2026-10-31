"""The snapshot-digest bridge ships the rows the identity reads and keeps no fallback."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard import inventory_contract_fingerprints as fingerprints
from codex_plugin_scanner.guard import native_inventory_snapshot_digest as bridge
from codex_plugin_scanner.guard.inventory_contract_models import (
    GuardAgentInventoryFinding,
    GuardAgentInventoryItem,
    GuardInventorySource,
)

_DIGEST = "a" * 64


def _item() -> GuardAgentInventoryItem:
    return GuardAgentInventoryItem(
        item_id="codex:skill:abc",
        item_kind="skill",
        display_name="Skill",
        description="A skill",
        source_fingerprint="fingerprint",
        content_hash="sha256:abc",
        capability_categories=("filesystem",),
        risk_level="low",
        security_score=90,
        scanner_sources=("inventory",),
        drift_state="unchanged",
        metadata={"path": "/w/skills/s0", "observedAt": "08:00"},
    )


def _finding() -> GuardAgentInventoryFinding:
    return GuardAgentInventoryFinding(
        finding_id="f-1",
        source="inventory",
        severity="low",
        confidence="high",
        title="Title",
        artifact_id="codex:skill:abc",
        check_id="check",
        evidence={"path": "/w/skills/s0"},
    )


def _source() -> GuardInventorySource:
    return GuardInventorySource(
        source_id="codex:config:abc",
        source_type="config",
        status="available",
        captured_at="2026-01-01T00:00:00Z",
        detail="{home}/.codex",
    )


def _resident(monkeypatch: pytest.MonkeyPatch, reply) -> list[dict[str, object]]:
    """Stub the transport; the returned list records every request wire sent."""

    sent: list[dict[str, object]] = []
    monkeypatch.setattr(bridge, "_resolve_digest_home", lambda _home: Path("/tmp/inventory-digest-home"))
    monkeypatch.setattr(bridge, "ensure_resident_prerequisite", lambda _home: True)

    def fake(*, request, **_kwargs):
        sent.append(request)
        return reply(request)

    monkeypatch.setattr(bridge, "_resident_request", fake)
    monkeypatch.setattr(bridge, "_payload", lambda response, _request, _home: response)
    return sent


def _answer(_request: dict[str, object]) -> dict[str, object]:
    return {"digest": _DIGEST}


def _ask(**kwargs) -> str:
    arguments: dict[str, object] = {
        "agent_type": "codex",
        "items": (_item(),),
        "findings": (_finding(),),
        "sources": (_source(),),
        "runtime_version": "3.44.0",
    }
    arguments.update(kwargs)
    return bridge.native_inventory_snapshot_digest(**arguments)


def test_the_wire_carries_the_rows_the_identity_reads(monkeypatch: pytest.MonkeyPatch) -> None:
    sent = _resident(monkeypatch, _answer)
    assert _ask() == _DIGEST
    (wire,) = sent
    assert wire["schema"] == "guard-inventory-snapshot-digest-request.v1"
    assert wire["agent_type"] == "codex"
    assert wire["runtime_version"] == "3.44.0"
    assert wire["items"] == [
        {
            "item_id": "codex:skill:abc",
            "item_kind": "skill",
            "metadata": {"path": "/w/skills/s0", "observedAt": "08:00"},
            "capability_categories": ["filesystem"],
            "content_hash": "sha256:abc",
            "drift_state": "unchanged",
            "risk_level": "low",
            "scanner_sources": ["inventory"],
            "security_score": 90,
            "source_fingerprint": "fingerprint",
        }
    ]
    assert wire["sources"] == [
        {
            "source_id": "codex:config:abc",
            "source_type": "config",
            "status": "available",
            "detail": "{home}/.codex",
        }
    ]


def test_an_absent_description_travels_as_one(monkeypatch: pytest.MonkeyPatch) -> None:
    # An absent summary and an empty one are different snapshots, so the key
    # travels either way rather than being dropped when it is None.
    sent = _resident(monkeypatch, _answer)
    _ask()
    (wire,) = sent
    findings = wire["findings"]
    assert isinstance(findings, list)
    assert findings[0]["summary"] is None


def test_the_whole_snapshot_travels_in_one_request(monkeypatch: pytest.MonkeyPatch) -> None:
    # A digest over part of an inventory is not a digest of it, so there is
    # nothing to batch however many rows arrive.
    sent = _resident(monkeypatch, _answer)
    _ask(items=tuple(_item() for _ in range(600)))
    assert len(sent) == 1
    items = sent[0]["items"]
    assert isinstance(items, list)
    assert len(items) == 600


def test_an_unprepared_resident_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    _resident(monkeypatch, _answer)
    monkeypatch.setattr(bridge, "ensure_resident_prerequisite", lambda _home: False)
    with pytest.raises(bridge.InventorySnapshotDigestUnavailableError):
        _ask()


def test_a_transport_failure_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    def raise_runtime(_request: dict[str, object]) -> dict[str, object]:
        raise RuntimeError("no resident")

    _resident(monkeypatch, raise_runtime)
    with pytest.raises(bridge.InventorySnapshotDigestUnavailableError):
        _ask()


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"digest": "short"},
        {"digest": 7},
        "not-a-mapping",
        # Sixty-four characters that are not a hash. The digest becomes the
        # snapshot's identity, so a length check alone would let a runtime that
        # no longer agrees with this contract name the snapshot.
        {"digest": "z" * 64},
        {"digest": "A" * 64},
    ],
)
def test_an_answer_that_is_not_a_digest_fails_closed(monkeypatch: pytest.MonkeyPatch, payload: object) -> None:
    _resident(monkeypatch, lambda _request: payload)
    with pytest.raises(bridge.InventorySnapshotDigestUnavailableError):
        _ask()


def test_the_snapshot_hash_is_the_residents_answer(monkeypatch: pytest.MonkeyPatch) -> None:
    # Nothing recomputes the identity in Python: the contract helper is the
    # bridge call and nothing else.
    asked: list[dict[str, object]] = []

    def fake(**kwargs: object) -> str:
        asked.append(kwargs)
        return _DIGEST

    monkeypatch.setattr(fingerprints, "native_inventory_snapshot_digest", fake)
    answered = fingerprints._inventory_snapshot_content_hash(
        agent_type="codex",
        items=(_item(),),
        findings=(),
        sources=(),
        runtime_version=None,
    )
    assert answered == _DIGEST
    assert asked[0]["agent_type"] == "codex"
    assert asked[0]["runtime_version"] is None
