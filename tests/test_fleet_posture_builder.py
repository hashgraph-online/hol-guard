"""Fleet posture builder: protection states, inventory modes, opt-out and size cap."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from jsonschema import Draft202012Validator

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.runtime import fleet_posture as fp
from codex_plugin_scanner.guard.store import GuardStore

SCHEMA = json.loads(
    (Path(__file__).resolve().parents[1] / "contracts" / "fleet-posture" / "v1" / "schema.json").read_text(
        encoding="utf-8"
    )
)
NOW = datetime(2026, 10, 16, 12, 0, 0, tzinfo=timezone.utc)
HASH_A = "sha256:" + "a" * 64


def _validate(payload: dict[str, object]) -> None:
    Draft202012Validator(SCHEMA).validate(payload)


class FakeAdapter:
    def __init__(
        self,
        harness: str,
        *,
        status: str = "active",
        config_paths: tuple[str, ...] = ("/cfg",),
        artifacts: tuple[dict[str, object], ...] = (),
        blind_spots: tuple[str, ...] = (),
    ) -> None:
        self.harness = harness
        self._status = status
        self._config_paths = config_paths
        self._artifacts = artifacts
        self._blind_spots = blind_spots

    def diagnostics(self, _context: HarnessContext) -> dict[str, object]:
        return {
            "setup_status": self._status,
            "config_paths": list(self._config_paths),
            "artifacts": list(self._artifacts),
            "installed": self._status != "not_found",
        }

    def setup_contract(self) -> SimpleNamespace:
        return SimpleNamespace(
            coverage=SimpleNamespace(
                native_hooks=True,
                browser_fallback=False,
                mcp_proxy=True,
                prompt_hooks=False,
                blind_spots=self._blind_spots,
            )
        )


def _iso(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def _row(
    name: str, *, harness: str = "claude-code", artifact_hash: str | None = HASH_A[7:], kind: str = "skill"
) -> dict[str, object]:
    return {
        "artifact_name": name,
        "artifact_type": kind,
        "harness": harness,
        "artifact_hash": artifact_hash,
        "source_scope": "global",
        "config_path": f"/home/user/.config/{name}",
        "first_seen_at": "2026-10-01T00:00:00Z",
        "last_seen_at": "2026-10-16T00:00:00Z",
        "present": 1,
        "removed_at": None,
    }


@pytest.fixture
def store(tmp_path: Path) -> GuardStore:
    return GuardStore(tmp_path / "guard")


@pytest.fixture
def context(tmp_path: Path) -> HarnessContext:
    return HarnessContext(home_dir=tmp_path / "home", workspace_dir=None, guard_home=tmp_path / "guard")


def _config(**overrides: object) -> SimpleNamespace:
    base: dict[str, object] = {
        "install_owner": "user",
        "harness_postures": {},
        "protection_posture": "protected",
        "mode": "enforce",
    }
    base.update(overrides)
    return SimpleNamespace(**base)


def _set_inventory(store: GuardStore, monkeypatch: pytest.MonkeyPatch, rows: list[dict[str, object]]) -> None:
    monkeypatch.setattr(store, "list_inventory", lambda harness=None: list(rows))


def _set_receipts(monkeypatch: pytest.MonkeyPatch, store: GuardStore, timestamps: dict[str, datetime]) -> None:
    def list_receipts(limit: int = 100, harness: str | None = None) -> list[dict[str, object]]:
        stamp = timestamps.get(harness or "")
        return [] if stamp is None else [{"timestamp": _iso(stamp)}]

    monkeypatch.setattr(store, "list_receipts", list_receipts)


def _build(
    store: GuardStore,
    context: HarnessContext,
    adapters: list[FakeAdapter],
    **kwargs: object,
) -> fp.FleetPostureBuild:
    config = kwargs.pop("config", _config())
    settings = fp.FleetPostureSettings(context=context, guard_config=config, now=NOW, **kwargs)  # type: ignore[arg-type]
    return fp.build_fleet_posture_state(store, adapters, settings)


def _tools(built: fp.FleetPostureBuild) -> dict[str, dict[str, object]]:
    return {tool["harness"]: tool for tool in built.payload["aiTools"]}  # type: ignore[union-attr, index]


def test_every_protection_state_is_derived(
    store: GuardStore, context: HarnessContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_inventory(store, monkeypatch, [])
    _set_receipts(
        monkeypatch,
        store,
        {
            "claude-code": NOW - timedelta(hours=2),
            "codex": NOW - timedelta(days=30),
            "cursor": NOW - timedelta(hours=1),
        },
    )
    adapters = [
        FakeAdapter("claude-code"),
        FakeAdapter("codex"),
        FakeAdapter("cursor"),
        FakeAdapter("gemini", status="partial"),
        FakeAdapter("kimi", status="broken"),
        FakeAdapter("grok", status="not_found", config_paths=("/cfg",)),
        FakeAdapter("pi", status="not_found", config_paths=()),
        FakeAdapter("antigravity"),
    ]
    config = _config(harness_postures={"cursor": "watch"})
    built = _build(store, context, adapters, config=config)
    tools = _tools(built)
    states = {harness: tool["protectionState"] for harness, tool in tools.items()}
    assert states == {
        "claude-code": "protected",
        "codex": "stale",
        "cursor": "paused",
        "gemini": "needs_setup",
        "kimi": "broken",
        "grok": "needs_setup",
        "antigravity": "protected",
    }
    assert "pi" not in tools
    assert tools["cursor"]["postureOverride"] == "off"
    assert tools["claude-code"]["postureOverride"] == "default"
    _validate(built.payload)


def test_not_detected_tools_are_reported_once_they_disappear(
    store: GuardStore, context: HarnessContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_inventory(store, monkeypatch, [])
    _set_receipts(monkeypatch, store, {"codex": NOW})
    first = _build(store, context, [FakeAdapter("codex")])
    fp.commit_fleet_posture_sent(store, first, now=_iso(NOW))
    second = _build(
        store,
        context,
        [FakeAdapter("codex", status="not_found", config_paths=())],
        diagnostics_ttl_seconds=0,
    )
    assert _tools(second)["codex"]["protectionState"] == "not_detected"
    _validate(second.payload)


def test_global_watch_posture_marks_every_tool_paused(
    store: GuardStore, context: HarnessContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_inventory(store, monkeypatch, [])
    _set_receipts(monkeypatch, store, {"codex": NOW})
    built = _build(store, context, [FakeAdapter("codex")], config=_config(protection_posture="watch"))
    assert _tools(built)["codex"]["protectionState"] == "paused"


def test_tool_version_comes_from_the_detected_host_artifact(
    store: GuardStore, context: HarnessContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_inventory(store, monkeypatch, [])
    _set_receipts(monkeypatch, store, {"cline": NOW})
    host = {"artifact_type": "harness_host", "metadata": {"version": "3.2.1"}}
    unknown = {"artifact_type": "harness_host", "metadata": {"version": "unknown"}}
    built = _build(
        store, context, [FakeAdapter("cline", artifacts=(host,)), FakeAdapter("codex", artifacts=(unknown,))]
    )
    tools = _tools(built)
    assert tools["cline"]["toolVersion"] == "3.2.1"
    assert tools["codex"]["toolVersion"] is None


def test_first_build_is_full_and_building_does_not_write_state(
    store: GuardStore, context: HarnessContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_inventory(store, monkeypatch, [_row("one"), _row("two")])
    _set_receipts(monkeypatch, store, {"claude-code": NOW})
    built = _build(store, context, [FakeAdapter("claude-code")])
    inventory = built.payload["inventory"]
    assert inventory["mode"] == "full"  # type: ignore[index]
    assert {item["name"] for item in inventory["items"]} == {"one", "two"}  # type: ignore[index]
    assert store.get_sync_payload(fp.LAST_SENT_STATE_KEY) in (None, {})
    _validate(built.payload)


def test_unchanged_inventory_sends_an_empty_delta_after_commit(
    store: GuardStore, context: HarnessContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_inventory(store, monkeypatch, [_row("one")])
    _set_receipts(monkeypatch, store, {"claude-code": NOW})
    first = _build(store, context, [FakeAdapter("claude-code")])
    fp.commit_fleet_posture_sent(store, first, now=_iso(NOW))
    second = _build(store, context, [FakeAdapter("claude-code")])
    assert second.mode == "delta"
    assert second.payload["inventory"]["items"] == []  # type: ignore[index]
    assert second.payload["inventory"]["removed"] == []  # type: ignore[index]
    assert second.payload["inventory"]["digest"] == first.payload["inventory"]["digest"]  # type: ignore[index]
    _validate(second.payload)


def test_uncommitted_build_is_resent_in_full(
    store: GuardStore, context: HarnessContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_inventory(store, monkeypatch, [_row("one")])
    _set_receipts(monkeypatch, store, {"claude-code": NOW})
    _build(store, context, [FakeAdapter("claude-code")])
    again = _build(store, context, [FakeAdapter("claude-code")])
    assert again.mode == "full"


def test_delta_lists_added_changed_and_removed_items(
    store: GuardStore, context: HarnessContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    rows = [_row("keep"), _row("change"), _row("drop")]
    _set_inventory(store, monkeypatch, rows)
    _set_receipts(monkeypatch, store, {"claude-code": NOW})
    first = _build(store, context, [FakeAdapter("claude-code")])
    fp.commit_fleet_posture_sent(store, first, now=_iso(NOW))
    rows[:] = [_row("keep"), _row("change", artifact_hash="b" * 64), _row("new")]
    second = _build(store, context, [FakeAdapter("claude-code")])
    inventory = second.payload["inventory"]
    assert second.mode == "delta"
    assert sorted(item["name"] for item in inventory["items"]) == ["change", "new"]  # type: ignore[index]
    assert [item["name"] for item in inventory["removed"]] == ["drop"]  # type: ignore[index]
    assert inventory["digest"] != first.payload["inventory"]["digest"]  # type: ignore[index]
    _validate(second.payload)


def test_full_inventory_request_forces_full_then_clears(
    store: GuardStore, context: HarnessContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_inventory(store, monkeypatch, [_row("one")])
    _set_receipts(monkeypatch, store, {"claude-code": NOW})
    first = _build(store, context, [FakeAdapter("claude-code")])
    fp.commit_fleet_posture_sent(store, first, now=_iso(NOW))
    fp.request_full_inventory(store, source="cloud", now=_iso(NOW))
    assert fp.full_inventory_requested(store)
    forced = _build(store, context, [FakeAdapter("claude-code")])
    assert forced.mode == "full"
    fp.commit_fleet_posture_sent(store, forced, now=_iso(NOW))
    assert not fp.full_inventory_requested(store)
    assert _build(store, context, [FakeAdapter("claude-code")]).mode == "delta"


def test_full_inventory_is_refreshed_after_a_week(
    store: GuardStore, context: HarnessContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_inventory(store, monkeypatch, [_row("one")])
    _set_receipts(monkeypatch, store, {"claude-code": NOW})
    first = _build(store, context, [FakeAdapter("claude-code")])
    fp.commit_fleet_posture_sent(store, first, now=_iso(NOW))
    later = fp.FleetPostureSettings(context=context, guard_config=_config(), now=NOW + timedelta(days=8))
    assert fp.build_fleet_posture_state(store, [FakeAdapter("claude-code")], later).mode == "full"


def test_opt_out_sends_digest_only_without_detail(
    store: GuardStore, context: HarnessContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_inventory(store, monkeypatch, [_row("one")])
    _set_receipts(monkeypatch, store, {"claude-code": NOW})
    adapters = [FakeAdapter("claude-code", blind_spots=("subagent tool calls",))]
    full = _build(store, context, adapters)
    assert _tools(full)["claude-code"]["blindSpots"] == ["subagent tool calls"]
    fp.set_fleet_posture_reporting(store, enabled=False, now=_iso(NOW))
    minimal = _build(store, context, adapters)
    assert minimal.mode == "digest_only"
    assert minimal.payload["inventory"]["items"] == []  # type: ignore[index]
    assert minimal.payload["inventory"]["removed"] == []  # type: ignore[index]
    assert minimal.payload["inventory"]["digest"].startswith("sha256:")  # type: ignore[index, union-attr]
    assert minimal.payload["machine"]["osVersion"] is None  # type: ignore[index]
    assert _tools(minimal)["claude-code"]["blindSpots"] == []
    assert _tools(minimal)["claude-code"]["protectionState"] == "protected"
    _validate(minimal.payload)


def test_managed_installs_cannot_opt_out(
    store: GuardStore, context: HarnessContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_inventory(store, monkeypatch, [_row("one")])
    _set_receipts(monkeypatch, store, {"claude-code": NOW})
    fp.set_fleet_posture_reporting(store, enabled=False, now=_iso(NOW))
    built = _build(store, context, [FakeAdapter("claude-code")], config=_config(install_owner="mdm"))
    assert built.mode == "full"
    assert fp.fleet_posture_managed(_config(install_owner="mdm"))
    assert fp.fleet_posture_reporting_enabled(store, _config(install_owner="mdm"))
    assert not fp.fleet_posture_reporting_enabled(store, _config())


def test_opt_out_does_not_advance_the_delta_baseline(
    store: GuardStore, context: HarnessContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_inventory(store, monkeypatch, [_row("one")])
    _set_receipts(monkeypatch, store, {"claude-code": NOW})
    fp.set_fleet_posture_reporting(store, enabled=False, now=_iso(NOW))
    minimal = _build(store, context, [FakeAdapter("claude-code")])
    fp.commit_fleet_posture_sent(store, minimal, now=_iso(NOW))
    fp.set_fleet_posture_reporting(store, enabled=True, now=_iso(NOW))
    assert _build(store, context, [FakeAdapter("claude-code")]).mode == "full"


def test_oversized_inventory_is_sent_in_chunks_that_fit_the_cap(
    store: GuardStore, context: HarnessContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    rows = [_row(f"{index:03d}-" + "x" * 190) for index in range(240)]
    _set_inventory(store, monkeypatch, rows)
    _set_receipts(monkeypatch, store, {"claude-code": NOW})
    seen: set[str] = set()
    for _ in range(6):
        built = _build(store, context, [FakeAdapter("claude-code")])
        assert built.payload_bytes <= fp.MAX_PAYLOAD_BYTES
        assert built.mode == "delta"
        _validate(built.payload)
        seen.update(item["name"] for item in built.payload["inventory"]["items"])  # type: ignore[index]
        fp.commit_fleet_posture_sent(store, built, now=_iso(NOW))
    assert seen == {row["artifact_name"] for row in rows}
    assert _build(store, context, [FakeAdapter("claude-code")]).payload["inventory"]["items"] == []  # type: ignore[index]


def test_digest_only_fallback_when_not_even_one_item_fits(
    store: GuardStore, context: HarnessContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_inventory(store, monkeypatch, [_row("one")])
    _set_receipts(monkeypatch, store, {"claude-code": NOW})
    fp.set_fleet_posture_reporting(store, enabled=False, now=_iso(NOW))
    floor = _build(store, context, [FakeAdapter("claude-code")]).payload_bytes
    fp.set_fleet_posture_reporting(store, enabled=True, now=_iso(NOW))
    monkeypatch.setattr(fp, "MAX_PAYLOAD_BYTES", floor + 20)
    built = _build(store, context, [FakeAdapter("claude-code")])
    assert built.mode == "digest_only"
    assert built.payload["inventory"]["items"] == []  # type: ignore[index]
    assert built.payload["inventory"]["digest"].startswith("sha256:")  # type: ignore[index, union-attr]
    assert not built.advanced_inventory
    fp.commit_fleet_posture_sent(store, built, now=_iso(NOW))
    monkeypatch.setattr(fp, "MAX_PAYLOAD_BYTES", 65536)
    assert _build(store, context, [FakeAdapter("claude-code")]).mode == "full"


def test_policy_section_mirrors_the_acknowledgement(store: GuardStore) -> None:
    ack = {
        "status": "synced",
        "bundleHash": "sha256:" + "c" * 64,
        "bundleVersion": "7",
        "appliedAt": "2026-10-16T11:00:00Z",
    }
    section = fp.policy_section(store, ack)
    assert section["status"] == "applied"
    assert section["appliedBundleVersion"] is None  # legacy string versions are not integers
    assert section["appliedAt"] == "2026-10-16T11:00:00Z"
    v2 = {
        "contractVersion": "guard-policy-bundle.v2",
        "status": "applied",
        "bundleHash": "sha256:" + "d" * 64,
        "bundleVersion": 12,
        "policyRevision": 3,
        "observedAt": "2026-10-16T11:30:00+00:00",
    }
    section = fp.policy_section(store, v2)
    assert (section["appliedBundleVersion"], section["appliedPolicyVersionNumber"]) == (12, 3)
    assert section["appliedAt"] == "2026-10-16T11:30:00Z"
    assert fp.policy_section(store, None)["status"] == "none"
    store.set_sync_payload("policy_bundle_last_error", {"reason": "invalid_signature"}, _iso(NOW))
    rejected = fp.policy_section(store, None)
    assert (rejected["status"], rejected["errorCode"]) == ("rejected", "invalid_signature")


def test_client_section_reflects_auto_update_state(
    store: GuardStore, context: HarnessContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_inventory(store, monkeypatch, [])
    _set_receipts(monkeypatch, store, {})
    store.set_sync_payload(
        fp.AUTO_UPDATE_STATE_KEY,
        {
            "last_check_at": "2026-10-16T06:00:00+00:00",
            "last_status": {"auto_updatable": True, "update_available": True, "release_channel": "alpha"},
        },
        _iso(NOW),
    )
    client = _build(store, context, []).payload["client"]
    assert client["channel"] == "alpha"  # type: ignore[index]
    assert client["autoUpdate"] == {  # type: ignore[index]
        "enabled": True,
        "lastCheckedAt": "2026-10-16T06:00:00Z",
        "lastResult": "update_available",
    }


@pytest.mark.parametrize(
    ("state", "expected"),
    [
        ({"last_update_exit_code": 1, "last_update_at": "2026-10-16T06:00:00+00:00"}, "failed"),
        ({"last_update_exit_code": 0, "last_update_at": "2026-10-16T06:00:00+00:00"}, "updated"),
        ({"last_update_error": True}, "failed"),
        ({}, "update_available"),
    ],
)
def test_failed_auto_update_attempt_is_reported_as_failed(
    store: GuardStore,
    context: HarnessContext,
    monkeypatch: pytest.MonkeyPatch,
    state: dict[str, object],
    expected: str,
) -> None:
    _set_inventory(store, monkeypatch, [])
    _set_receipts(monkeypatch, store, {})
    store.set_sync_payload(
        fp.AUTO_UPDATE_STATE_KEY,
        {
            "last_check_at": "2026-10-16T06:00:00+00:00",
            "last_status": {"auto_updatable": True, "update_available": True, "release_channel": "stable"},
            **state,
        },
        _iso(NOW),
    )
    client = _build(store, context, []).payload["client"]
    assert client["autoUpdate"]["lastResult"] == expected  # type: ignore[index]


def test_unreadable_inventory_raises_instead_of_reporting_an_empty_one(
    store: GuardStore, context: HarnessContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(harness: str | None = None) -> list[dict[str, object]]:
        raise RuntimeError("database is locked")

    monkeypatch.setattr(store, "list_inventory", broken)
    _set_receipts(monkeypatch, store, {})
    with pytest.raises(RuntimeError):
        _build(store, context, [])
    assert store.get_sync_payload(fp.LAST_SENT_STATE_KEY) in (None, {})


def test_inventory_beyond_five_thousand_items_is_digested_and_tracked(
    store: GuardStore, context: HarnessContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    rows = [_row(f"item-{index:05d}") for index in range(5200)]
    _set_inventory(store, monkeypatch, rows)
    _set_receipts(monkeypatch, store, {})
    built = _build(store, context, [])
    assert built.next_state["inventoryItemsTracked"] == 5200
    assert built.mode == "delta"
    _set_inventory(store, monkeypatch, rows[:-1])
    shorter = _build(store, context, [])
    assert shorter.payload["inventory"]["digest"] != built.payload["inventory"]["digest"]  # type: ignore[index]


def test_forced_full_refresh_streams_every_item_even_when_requested_on_every_reply(
    store: GuardStore, context: HarnessContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    rows = [_row(f"{index:03d}-" + "x" * 120) for index in range(600)]
    _set_inventory(store, monkeypatch, rows)
    _set_receipts(monkeypatch, store, {})
    seen: set[str] = set()
    for _ in range(40):
        fp.request_full_inventory(store, source="cloud", now=_iso(NOW))
        built = _build(store, context, [])
        assert built.payload_bytes <= fp.MAX_PAYLOAD_BYTES
        seen.update(item["name"] for item in built.payload["inventory"]["items"])  # type: ignore[index]
        fp.commit_fleet_posture_sent(store, built, now=_iso(NOW))
        if not built.next_state["fullStreaming"]:
            break
    assert seen == {str(row["artifact_name"]) for row in rows}
    assert built.next_state["fullStreaming"] is False
    assert built.next_state["fullSentAt"] == _iso(NOW)


def test_removals_beyond_one_chunk_are_not_forgotten(
    store: GuardStore, context: HarnessContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    rows = [_row(f"item-{index:03d}") for index in range(520)]
    _set_inventory(store, monkeypatch, rows)
    _set_receipts(monkeypatch, store, {})
    for _ in range(12):
        built = _build(store, context, [])
        fp.commit_fleet_posture_sent(store, built, now=_iso(NOW))
        if not built.next_state["fullStreaming"]:
            break
    _set_inventory(store, monkeypatch, [])
    removed: set[str] = set()
    for _ in range(12):
        built = _build(store, context, [])
        removed.update(entry["name"] for entry in built.payload["inventory"]["removed"])  # type: ignore[index]
        fp.commit_fleet_posture_sent(store, built, now=_iso(NOW))
    assert removed == {str(row["artifact_name"]) for row in rows}


def test_removal_is_suppressed_while_another_path_still_holds_the_same_item(
    store: GuardStore, context: HarnessContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    first = _row("shared")
    second = {**_row("shared"), "config_path": "/other/place/shared"}
    _set_inventory(store, monkeypatch, [first, second])
    _set_receipts(monkeypatch, store, {})
    fp.commit_fleet_posture_sent(store, _build(store, context, []), now=_iso(NOW))
    _set_inventory(store, monkeypatch, [first])
    built = _build(store, context, [])
    assert built.payload["inventory"]["removed"] == []  # type: ignore[index]
    fp.commit_fleet_posture_sent(store, built, now=_iso(NOW))
    _set_inventory(store, monkeypatch, [])
    gone = _build(store, context, [])
    assert [entry["name"] for entry in gone.payload["inventory"]["removed"]] == ["shared"]  # type: ignore[index]


def test_path_and_host_hashes_are_keyed_per_install(
    store: GuardStore, context: HarnessContext, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import hashlib

    row = _row("one")
    _set_inventory(store, monkeypatch, [row])
    _set_receipts(monkeypatch, store, {})
    built = _build(store, context, [])
    path_hash = built.payload["inventory"]["items"][0]["pathHash"]  # type: ignore[index]
    plain = "sha256:" + hashlib.sha256(str(row["config_path"]).encode()).hexdigest()
    assert path_hash != plain
    assert _build(store, context, []).payload["inventory"]["items"][0]["pathHash"] == path_hash  # type: ignore[index]
    other = GuardStore(tmp_path / "other-guard")
    _set_inventory(other, monkeypatch, [row])
    _set_receipts(monkeypatch, other, {})
    assert _build(other, context, []).payload["inventory"]["items"][0]["pathHash"] != path_hash  # type: ignore[index]
    _validate(built.payload)


def test_tool_diagnostics_are_cached_between_builds(
    store: GuardStore, context: HarnessContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_inventory(store, monkeypatch, [])
    _set_receipts(monkeypatch, store, {})
    adapter = FakeAdapter("claude-code")
    calls: list[str] = []
    original = adapter.diagnostics

    def counting(context: HarnessContext) -> dict[str, object]:
        calls.append("probe")
        return original(context)

    monkeypatch.setattr(adapter, "diagnostics", counting)
    _build(store, context, [adapter])
    _build(store, context, [adapter])
    assert calls == ["probe"]
    _build(store, context, [adapter], diagnostics_ttl_seconds=0)
    assert calls == ["probe", "probe"]


def test_hash_key_is_read_once_per_build(
    store: GuardStore, context: HarnessContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_inventory(store, monkeypatch, [_row(f"item-{index}") for index in range(50)])
    _set_receipts(monkeypatch, store, {})
    reads: list[str] = []
    original = store.get_sync_payload

    def counting(key: str) -> object:
        reads.append(key)
        return original(key)

    monkeypatch.setattr(store, "get_sync_payload", counting)
    _build(store, context, [])
    assert reads.count(fp.HASH_KEY_STATE_KEY) == 1
