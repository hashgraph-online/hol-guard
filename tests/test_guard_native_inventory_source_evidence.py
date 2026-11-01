"""The inventory source-evidence bridge ships identities and keeps no fallback."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard import inventory_contract
from codex_plugin_scanner.guard import native_inventory_source_evidence as bridge
from codex_plugin_scanner.guard.adapters.base import GuardArtifact, HarnessDetection


def _entries(count: int) -> list[dict[str, object]]:
    return [
        {
            "harness": "codex",
            "artifact_type": "skill",
            "config_path": f"/w/skills/s{index}/SKILL.md",
        }
        for index in range(count)
    ]


def _resident(monkeypatch: pytest.MonkeyPatch, reply) -> list[dict[str, object]]:
    """Stub the transport; the returned list records every request wire sent."""

    sent: list[dict[str, object]] = []
    monkeypatch.setattr(bridge, "_resolve_digest_home", lambda _home: Path("/tmp/inventory-evidence-home"))
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
    return {
        "evidence": [
            {"source_of_truth": None, "primary_content_hash": f"sha256:{entry['config_path']}"} for entry in entries
        ]
    }


def _ask(entries, **kwargs):
    return bridge.native_inventory_source_evidence(entries, home_dir=Path("/h"), workspace_dir=Path("/w"), **kwargs)


def test_no_entries_never_reaches_the_resident(monkeypatch: pytest.MonkeyPatch) -> None:
    sent = _resident(monkeypatch, _answers)
    assert _ask([]) == []
    assert sent == []


def test_the_wire_carries_the_identities_the_contract_asks_for(monkeypatch: pytest.MonkeyPatch) -> None:
    sent = _resident(monkeypatch, _answers)
    _ask(_entries(1), include_symlinks=False, follow_unsafe_symlinks=True)
    (wire,) = sent
    assert wire["schema"] == "guard-inventory-source-evidence-request.v1"
    assert wire["home_dir"] == "/h"
    assert wire["workspace_dir"] == "/w"
    assert wire["include_symlinks"] is False
    assert wire["follow_unsafe_symlinks"] is True
    assert wire["entries"] == [
        {
            "harness": "codex",
            "artifact_type": "skill",
            "config_path": "/w/skills/s0/SKILL.md",
        }
    ]


def test_an_entry_without_a_config_path_omits_the_key(monkeypatch: pytest.MonkeyPatch) -> None:
    sent = _resident(monkeypatch, lambda request: {"evidence": [{}]})
    _ask([{"harness": "codex", "artifact_type": "config", "config_path": None}])
    assert sent[0]["entries"] == [{"harness": "codex", "artifact_type": "config"}]


def test_a_workspace_the_caller_does_not_have_is_left_out(monkeypatch: pytest.MonkeyPatch) -> None:
    sent = _resident(monkeypatch, _answers)
    bridge.native_inventory_source_evidence(_entries(1), home_dir=Path("/h"))
    assert "workspace_dir" not in sent[0]


def test_relative_paths_are_anchored_to_the_callers_directory(monkeypatch: pytest.MonkeyPatch) -> None:
    """The resident resolves before it checks containment, and only absolutes resolve."""

    sent = _resident(monkeypatch, lambda request: {"evidence": [{}, {}]})
    monkeypatch.setattr(bridge.Path, "cwd", classmethod(lambda _cls: Path("/run/from")))
    bridge.native_inventory_source_evidence(
        [
            {"harness": "codex", "artifact_type": "skill", "config_path": "skills/s0/SKILL.md"},
            {"harness": "codex", "artifact_type": "skill", "config_path": "~/skills/s1/SKILL.md"},
        ],
        home_dir=Path("home"),
        workspace_dir=Path("work"),
    )
    (wire,) = sent
    assert wire["home_dir"] == "/run/from/home"
    assert wire["workspace_dir"] == "/run/from/work"
    assert [entry["config_path"] for entry in wire["entries"]] == [
        "/run/from/skills/s0/SKILL.md",
        # Left for the resident to expand, as the Python source did.
        "~/skills/s1/SKILL.md",
    ]


def test_an_anchored_path_also_carries_the_one_the_harness_wrote(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The instruction role reads the configured path, not the directory we ran in."""

    sent = _resident(monkeypatch, lambda request: {"evidence": [{}, {}]})
    monkeypatch.setattr(
        bridge.Path, "cwd", classmethod(lambda _cls: Path("/run/from/docs/security"))
    )
    bridge.native_inventory_source_evidence(
        [
            {"harness": "codex", "artifact_type": "instruction", "config_path": "notes.md"},
            {
                "harness": "codex",
                "artifact_type": "instruction",
                "config_path": "/w/notes.md",
            },
        ],
        home_dir=Path("/h"),
    )
    (wire,) = sent
    relative, absolute = wire["entries"]
    assert relative["config_path"] == "/run/from/docs/security/notes.md"
    assert relative["configured_path"] == "notes.md"
    # An absolute path is already what the harness wrote, so the request keeps
    # the shape every caller sends today and its digest with it.
    assert "configured_path" not in absolute


def test_a_bigger_batch_is_given_a_longer_deadline() -> None:
    """A fixed deadline would fail an inventory purely for being big."""

    small = bridge._batch_timeout_seconds(1)
    large = bridge._batch_timeout_seconds(bridge._MAX_ENTRIES)
    assert bridge._TIMEOUT_FLOOR_SECONDS <= small < large <= bridge._TIMEOUT_CEILING_SECONDS


def test_more_entries_than_the_cap_are_asked_for_in_order(monkeypatch: pytest.MonkeyPatch) -> None:
    sent = _resident(monkeypatch, _answers)
    answers = _ask(_entries(bridge._MAX_ENTRIES + 7))
    assert [len(wire["entries"]) for wire in sent] == [bridge._MAX_ENTRIES, 7]
    assert [answer["primary_content_hash"] for answer in answers] == [
        f"sha256:{entry['config_path']}" for entry in _entries(bridge._MAX_ENTRIES + 7)
    ]


@pytest.mark.parametrize(
    "reply",
    [
        lambda request: {"evidence": []},
        lambda request: {"evidence": "nope"},
        lambda request: {"evidence": ["nope"]},
        lambda request: "nope",
    ],
)
def test_an_answer_that_does_not_match_the_request_is_refused(monkeypatch: pytest.MonkeyPatch, reply) -> None:
    _resident(monkeypatch, reply)
    with pytest.raises(bridge.InventorySourceEvidenceUnavailableError):
        _ask(_entries(1))


def test_a_resident_that_cannot_run_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    _resident(monkeypatch, _answers)
    monkeypatch.setattr(bridge, "ensure_resident_prerequisite", lambda _home: False)
    with pytest.raises(bridge.InventorySourceEvidenceUnavailableError):
        _ask(_entries(1))


def test_a_deleted_working_directory_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    """Reading the working directory is I/O, and it answers like any other."""

    _resident(monkeypatch, _answers)

    def gone() -> Path:
        raise FileNotFoundError(2, "No such file or directory")

    monkeypatch.setattr(bridge.Path, "cwd", staticmethod(gone))
    with pytest.raises(bridge.InventorySourceEvidenceUnavailableError):
        _ask(_entries(1))


def test_a_transport_failure_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    def explode(request):
        raise OSError("no socket")

    _resident(monkeypatch, explode)
    with pytest.raises(bridge.InventorySourceEvidenceUnavailableError):
        _ask(_entries(1))


def _detection(count: int) -> HarnessDetection:
    return HarnessDetection(
        harness="codex",
        installed=True,
        command_available=False,
        config_paths=(),
        artifacts=tuple(
            GuardArtifact(
                artifact_id=f"codex:skill:s{index}",
                name=f"s{index}",
                harness="codex",
                artifact_type="skill",
                source_scope="project",
                config_path=f"/w/skills/s{index}/SKILL.md",
            )
            for index in range(count)
        ),
    )


def _no_scan(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin the scan bridge: a snapshot makes a second resident call, and these
    tests are about the first one."""

    monkeypatch.setattr(inventory_contract, "native_inventory_scan_findings", lambda *_a, **_k: ([], []))


def _no_classification(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin the classification bridge: a snapshot makes a second resident call,
    and these tests are about the first one. The answer is the shape
    ``_item_from_artifact`` reads, with no metadata edits."""

    def classify(entries, **_kwargs):
        return [
            {
                "item_kind": "skill",
                "metadata_removals": [],
                "metadata_updates": {},
                "content_hash": str(entry.get("primary_content_hash") or "sha256:0"),
                "capability_categories": [],
                "risk_level": "low",
            }
            for entry in entries
        ]

    monkeypatch.setattr(inventory_contract, "native_inventory_item_classification", classify)


def test_a_snapshot_asks_once_for_every_artifact(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    calls: list[list[dict[str, object]]] = []

    def capture(entries, **_kwargs):
        calls.append(list(entries))
        return [
            {"item_kind": "skill", "source_of_truth": None, "primary_content_hash": f"sha256:{index:064x}"}
            for index, _ in enumerate(entries)
        ]

    monkeypatch.setattr(inventory_contract, "native_inventory_source_evidence", capture)
    _no_scan(monkeypatch)
    _no_classification(monkeypatch)
    detection = _detection(3)
    snapshot = inventory_contract.inventory_snapshot_from_detection(
        detection,
        generated_at="2026-06-10T12:00:00+00:00",
        home_dir=tmp_path,
        workspace_dir=tmp_path / "w",
        artifacts=detection.artifacts,
    )
    assert len(calls) == 1
    assert [entry["artifact_type"] for entry in calls[0]] == ["skill", "skill", "skill"]
    assert [item.content_hash for item in snapshot.items] == [f"sha256:{index:064x}" for index in range(3)]


def test_a_snapshot_without_the_resident_fails_closed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def explode(entries, **_kwargs):
        raise bridge.InventorySourceEvidenceUnavailableError

    monkeypatch.setattr(inventory_contract, "native_inventory_source_evidence", explode)
    _no_scan(monkeypatch)
    _no_classification(monkeypatch)
    detection = _detection(1)
    with pytest.raises(bridge.InventorySourceEvidenceUnavailableError):
        inventory_contract.inventory_snapshot_from_detection(
            detection,
            generated_at="2026-06-10T12:00:00+00:00",
            home_dir=tmp_path,
            artifacts=detection.artifacts,
        )


def test_the_client_asks_for_the_resident_that_reads_kind_and_role(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A v1 resident refuses an entry with no ``item_kind`` and an older one
    answers without the instruction role. This client derives neither, so it
    asks for v3: anything older is plain unavailability rather than an
    inventory that silently loses evidence it never sees missing."""

    asked: list[object] = []
    monkeypatch.setattr(bridge, "_resolve_digest_home", lambda _home: Path("/tmp/inventory-evidence-home"))
    monkeypatch.setattr(bridge, "ensure_resident_prerequisite", lambda _home: True)
    monkeypatch.setattr(bridge, "_payload", lambda response, _request, _home: response)

    def fake(*, request, required_feature, **_kwargs):
        asked.append(required_feature)
        return _answers(request)

    monkeypatch.setattr(bridge, "_resident_request", fake)

    _ask(_entries(1))

    assert bridge.INVENTORY_SOURCE_EVIDENCE_FEATURE == "inventory-source-evidence-v3"
    assert asked == ["inventory-source-evidence-v3"]
