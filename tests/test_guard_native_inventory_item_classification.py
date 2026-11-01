"""The item-classification bridge ships artifacts and keeps no fallback."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_inventory_item_classification as bridge
from codex_plugin_scanner.guard.inventory_contract_items import _classified_metadata

_READINGS = {
    "item_kind": "skill",
    "metadata_removals": [],
    "metadata_updates": {},
    "content_hash": "sha256:hash",
    "capability_categories": [],
    "risk_level": "info",
}


def _entries(count: int, *, metadata: dict[str, object] | None = None) -> list[dict[str, object]]:
    return [
        {
            "artifact_id": f"artifact-{index}",
            "artifact_type": "skill",
            "name": f"skill-{index}",
            "metadata": dict(metadata or {}),
        }
        for index in range(count)
    ]


def _resident(monkeypatch: pytest.MonkeyPatch, reply) -> list[dict[str, object]]:
    """Stub the transport; the returned list records every request wire sent."""

    sent: list[dict[str, object]] = []
    monkeypatch.setattr(bridge, "_resolve_digest_home", lambda _home: Path("/tmp/inventory-classification-home"))
    monkeypatch.setattr(bridge, "ensure_resident_prerequisite", lambda _home: True)

    def fake(*, request, **_kwargs):
        sent.append(request)
        return reply(request)

    monkeypatch.setattr(bridge, "_resident_request", fake)
    monkeypatch.setattr(bridge, "_payload", lambda response, _request, _home: response)
    return sent


def _answers(request: dict[str, object]) -> dict[str, object]:
    entries = request["entries"]
    assert isinstance(entries, list)
    return {"items": [dict(_READINGS) for _ in entries]}


def test_no_entries_never_reaches_the_resident(monkeypatch: pytest.MonkeyPatch) -> None:
    sent = _resident(monkeypatch, _answers)
    assert bridge.native_inventory_item_classification([]) == []
    assert sent == []


def test_the_wire_carries_the_identity_the_contract_asks_for(monkeypatch: pytest.MonkeyPatch) -> None:
    sent = _resident(monkeypatch, _answers)
    entry = _entries(1)[0] | {"primary_content_hash": "sha256:read"}
    bridge.native_inventory_item_classification([entry])
    (wire,) = sent
    assert wire["schema"] == "guard-inventory-item-classification-request.v1"
    assert wire["entries"] == [
        {
            "artifact_id": "artifact-0",
            "artifact_type": "skill",
            "name": "skill-0",
            "metadata": {},
            "primary_content_hash": "sha256:read",
        }
    ]


def test_an_empty_content_hash_is_left_off_the_wire(monkeypatch: pytest.MonkeyPatch) -> None:
    sent = _resident(monkeypatch, _answers)
    bridge.native_inventory_item_classification([_entries(1)[0] | {"primary_content_hash": ""}])
    (wire,) = sent
    entries = wire["entries"]
    assert isinstance(entries, list)
    assert "primary_content_hash" not in entries[0]


def test_more_artifacts_than_one_request_holds_are_asked_in_order(monkeypatch: pytest.MonkeyPatch) -> None:
    sent = _resident(monkeypatch, _answers)
    answers = bridge.native_inventory_item_classification(_entries(bridge._MAX_ENTRIES + 3))
    assert len(answers) == bridge._MAX_ENTRIES + 3
    first, second = (wire["entries"] for wire in sent)
    assert isinstance(first, list)
    assert isinstance(second, list)
    assert len(first) == bridge._MAX_ENTRIES
    assert [entry["artifact_id"] for entry in second] == ["artifact-512", "artifact-513", "artifact-514"]


def test_metadata_too_large_for_one_request_is_split_by_size(monkeypatch: pytest.MonkeyPatch) -> None:
    """An MCP server's tool definitions outgrow the limit long before 512 entries."""

    sent = _resident(monkeypatch, _answers)
    bulky = {"tools": "t" * (bridge._MAX_BATCH_ENTRY_BYTES // 2)}
    answers = bridge.native_inventory_item_classification(_entries(4, metadata=bulky))
    assert len(answers) == 4
    assert len(sent) == 4
    assert [len(wire["entries"]) for wire in sent] == [1, 1, 1, 1]


def test_one_artifact_larger_than_a_request_still_travels_alone(monkeypatch: pytest.MonkeyPatch) -> None:
    sent = _resident(monkeypatch, _answers)
    bulky = {"tools": "t" * (bridge._MAX_BATCH_ENTRY_BYTES + 1)}
    bridge.native_inventory_item_classification([*_entries(1, metadata=bulky), *_entries(1)])
    assert [len(wire["entries"]) for wire in sent] == [1, 1]


def test_metadata_that_cannot_be_serialized_is_counted_as_a_whole_batch() -> None:
    assert bridge._wire_bytes({"metadata": {"value": object()}}) == bridge._MAX_BATCH_ENTRY_BYTES


def test_an_unusable_runtime_classifies_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    _resident(monkeypatch, _answers)
    monkeypatch.setattr(bridge, "ensure_resident_prerequisite", lambda _home: False)
    with pytest.raises(bridge.InventoryItemClassificationUnavailableError):
        bridge.native_inventory_item_classification(_entries(1))


def test_a_home_that_cannot_be_resolved_classifies_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    _resident(monkeypatch, _answers)

    def raising(_home):
        raise OSError("home")

    monkeypatch.setattr(bridge, "_resolve_digest_home", raising)
    with pytest.raises(bridge.InventoryItemClassificationUnavailableError):
        bridge.native_inventory_item_classification(_entries(1))


@pytest.mark.parametrize(
    "payload",
    [
        "not-a-mapping",
        {},
        {"items": "not-a-list"},
        # One answer short of the artifacts asked about: the caller would have
        # to decide which artifact went unclassified.
        {"items": [dict(_READINGS)]},
        # Every reading but the risk level, which the caller would then be
        # deriving itself.
        {"items": [{key: value for key, value in _READINGS.items() if key != "risk_level"}] * 2},
    ],
)
def test_an_answer_that_is_not_a_classification_fails_closed(monkeypatch: pytest.MonkeyPatch, payload: object) -> None:
    _resident(monkeypatch, lambda _request: payload)
    with pytest.raises(bridge.InventoryItemClassificationUnavailableError):
        bridge.native_inventory_item_classification(_entries(2))


def test_a_refused_request_classifies_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    def raising(_request):
        raise RuntimeError("refused")

    _resident(monkeypatch, raising)
    with pytest.raises(bridge.InventoryItemClassificationUnavailableError):
        bridge.native_inventory_item_classification(_entries(1))


def test_edits_apply_to_the_mapping_the_scan_built_without_reordering_it() -> None:
    entry = {"metadata": {"first": 1, "second": 2, "third": 3}}
    classification = {"metadata_removals": ["second"], "metadata_updates": {"third": 30, "fourth": 4}}
    metadata = _classified_metadata(entry, classification)
    assert list(metadata) == ["first", "third", "fourth"]
    assert metadata == {"first": 1, "third": 30, "fourth": 4}


def test_an_answer_with_no_edits_leaves_the_mapping_as_the_scan_built_it() -> None:
    entry = {"metadata": {"first": 1, "second": 2}}
    assert _classified_metadata(entry, dict(_READINGS)) == {"first": 1, "second": 2}


def test_a_removal_the_mapping_never_carried_changes_nothing() -> None:
    entry = {"metadata": {"first": 1}}
    assert _classified_metadata(entry, {"metadata_removals": ["absent"]}) == {"first": 1}
