"""Fleet posture reports what the AIBOM collection found, and machines carry their host name."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import store_inventory as naming
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.inventory_contract import GuardAgentInventoryItem, GuardAgentInventorySnapshot
from codex_plugin_scanner.guard.runtime import fleet_posture as fp
from codex_plugin_scanner.guard.runtime import fleet_posture_tools as tools
from codex_plugin_scanner.guard.runtime.fleet_posture_aibom import (
    AIBOM_ITEMS_STATE_KEY,
    fleet_inventory_rows,
    remember_aibom_items,
)
from codex_plugin_scanner.guard.runtime.fleet_posture_inventory import inventory_items
from codex_plugin_scanner.guard.store import GuardStore

NOW = datetime(2026, 10, 20, 12, 0, 0, tzinfo=timezone.utc)
HASH = "sha256:" + "b" * 64


def _item(item_id: str, kind: str, name: str, *, artifact_type: str | None = None) -> GuardAgentInventoryItem:
    metadata: dict[str, object] = {"configPath": f"{{home}}/.codex/{name}"}
    if artifact_type is not None:
        metadata["artifactType"] = artifact_type
    return GuardAgentInventoryItem(
        item_id=item_id,
        item_kind=kind,  # type: ignore[arg-type]
        display_name=name,
        description="",
        source_fingerprint="f",
        content_hash=HASH,
        capability_categories=(),
        metadata=metadata,
    )


def _snapshot(harness: str, generated_at: str, *items: GuardAgentInventoryItem) -> GuardAgentInventorySnapshot:
    return GuardAgentInventorySnapshot(f"{harness}:1", f"{harness}:agent", harness, generated_at, items=items)  # type: ignore[arg-type]


@pytest.fixture
def store(tmp_path: Path) -> GuardStore:
    return GuardStore(tmp_path / "guard")


def test_aibom_items_reach_fleet_posture_when_the_inventory_table_is_empty(
    store: GuardStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(store, "list_inventory", lambda harness=None: [])
    remember_aibom_items(
        store,
        [
            _snapshot(
                "codex",
                "2026-10-20T11:00:00Z",
                _item("codex:global:chrome-devtools", "mcp_server", "chrome-devtools"),
                _item("codex:project:review", "skill", "review", artifact_type="skill_file"),
                # Kinds fleet posture does not report stay out.
                _item("codex:global:agents", "prompt_pack", "AGENTS.md"),
            ),
            # Harnesses outside the contract stay out.
            _snapshot("not-a-harness", "2026-10-20T11:00:00Z", _item("x:global:y", "skill", "y")),
        ],
        now="2026-10-20T11:00:00Z",
    )
    context = HarnessContext(home_dir=tmp_path / "home", workspace_dir=None, guard_home=tmp_path / "guard")
    config = SimpleNamespace(install_owner="user", harness_postures={}, protection_posture="protected", mode="enforce")
    built = fp.build_fleet_posture_state(
        store, [], fp.FleetPostureSettings(context=context, guard_config=config, now=NOW)
    )
    items = {(item["kind"], item["name"], item["source"]) for item in built.payload["inventory"]["items"]}  # type: ignore[index]
    assert items == {("mcp_server", "chrome-devtools", "user"), ("skill", "review", "project")}


def test_inventory_table_rows_win_over_the_same_aibom_item(
    store: GuardStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    table_row = {
        "artifact_name": "chrome-devtools",
        "artifact_type": "mcp_server",
        "harness": "codex",
        # The table keeps the absolute path; the AIBOM item only knows its redacted form.
        "config_path": str(home / ".codex" / "chrome-devtools"),
        "first_seen_at": "2026-10-01T00:00:00Z",
        "last_seen_at": "2026-10-20T00:00:00Z",
    }
    monkeypatch.setattr(store, "list_inventory", lambda harness=None: [table_row])
    remember_aibom_items(
        store,
        [
            _snapshot(
                "codex",
                "2026-10-20T11:00:00Z",
                _item("codex:global:chrome-devtools", "mcp_server", "chrome-devtools"),
                _item("codex:global:other", "mcp_server", "other"),
            )
        ],
        now="2026-10-20T11:00:00Z",
        home_dir=home,
    )
    rows = fleet_inventory_rows(store)
    assert rows[0] is table_row
    assert [row["artifact_name"] for row in rows] == ["chrome-devtools", "other"]
    assert rows[1]["config_path"] == str(home.resolve() / ".codex" / "other")
    items = inventory_items(store, hash_key=b"k" * 32)
    assert sorted(item["name"] for item in items) == ["chrome-devtools", "other"]


def test_a_removed_table_row_does_not_hide_the_item_found_installed_again(
    store: GuardStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    removed = {
        "artifact_name": "chrome-devtools",
        "artifact_type": "mcp_server",
        "harness": "codex",
        "config_path": str(home / ".codex" / "chrome-devtools"),
        "first_seen_at": "2026-10-01T00:00:00Z",
        "last_seen_at": "2026-10-05T00:00:00Z",
        "present": 0,
        "removed_at": "2026-10-05T00:00:00Z",
    }
    monkeypatch.setattr(store, "list_inventory", lambda harness=None: [removed])
    remember_aibom_items(
        store,
        [
            _snapshot(
                "codex", "2026-10-20T11:00:00Z", _item("codex:global:chrome-devtools", "mcp_server", "chrome-devtools")
            )
        ],
        now="2026-10-20T11:00:00Z",
        home_dir=home,
    )
    assert [item["name"] for item in inventory_items(store, hash_key=b"k" * 32)] == ["chrome-devtools"]


def test_stored_rows_carry_the_item_hash_and_survive_a_runtime_that_cannot_answer(
    store: GuardStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    from codex_plugin_scanner.guard import native_runner_authority as authority

    item = _item("codex:global:one", "skill", "one")
    assert (
        remember_aibom_items(store, [_snapshot("codex", "2026-10-19T00:00:00Z", item)], now="2026-10-19T00:00:00Z") == 1
    )
    stored = store.get_sync_payload(AIBOM_ITEMS_STATE_KEY)
    assert isinstance(stored, dict)
    assert (stored["rows"][0]["artifact_hash"], stored["rows"][0]["present"]) == (HASH, True)

    def _unavailable(*_args: object, **_kwargs: object) -> dict[str, object]:
        raise authority.NativeRunnerAuthorityError("native_runner_authority_unavailable")

    monkeypatch.setattr(authority, "native_runner_authority", _unavailable)
    # A collection the runtime cannot answer for leaves the stored rows as they were.
    assert remember_aibom_items(store, [_snapshot("codex", "2026-10-20T00:00:00Z")], now="2026-10-20T00:00:00Z") == 0
    assert store.get_sync_payload(AIBOM_ITEMS_STATE_KEY) == stored


@pytest.mark.parametrize("label", ["Local machine", "local-device", "This machine", "  "])
def test_generic_labels_are_sent_as_the_host_name(label: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(naming.platform, "node", lambda: "Ada-MacBook-Pro.local")
    assert naming.effective_device_label(label) == "Ada-MacBook-Pro"


def test_a_chosen_label_is_kept(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(naming.platform, "node", lambda: "Ada-MacBook-Pro.local")
    assert naming.effective_device_label("Build server 3") == "Build server 3"


def test_a_chosen_label_that_reads_like_a_default_is_kept(store: GuardStore, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(naming.platform, "node", lambda: "Ada-MacBook-Pro.local")
    seeded = str(store.get_device_metadata()["device_label"])
    assert tools.device_display_name(store, seeded) == "Ada-MacBook-Pro"
    store.set_device_label("Local machine", "2026-10-20T00:00:00Z")
    assert tools.device_display_name(store, "Local machine") == "Local machine"
    # Clearing the label hands the name back to the host name.
    store.set_device_label("", "2026-10-20T00:01:00Z")
    assert tools.device_display_name(store, "Local machine") == "Ada-MacBook-Pro"


def test_a_generic_label_stays_when_the_host_has_no_usable_name(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(naming.platform, "node", lambda: "localhost")
    assert naming.effective_device_label("Local machine") == "Local machine"


def test_a_daemon_without_workspace_context_still_records_user_wide_inventory(
    store: GuardStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from codex_plugin_scanner.guard import aibom_cli
    from codex_plugin_scanner.guard.aibom_commands import remember_user_inventory_if_due

    contexts: list[HarnessContext] = []

    def _collect(context: HarnessContext, **_kwargs: object) -> tuple[GuardAgentInventorySnapshot, ...]:
        contexts.append(context)
        return (
            _snapshot(
                "codex", "2026-10-20T11:00:00Z", _item("codex:global:chrome-devtools", "mcp_server", "chrome-devtools")
            ),
        )

    monkeypatch.setattr(aibom_cli, "collect_aibom_snapshots", _collect)
    monkeypatch.setattr(aibom_cli, "_resolve_trust_attestation_context", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(store, "list_inventory", lambda harness=None: [])
    home = tmp_path / "home"
    first = remember_user_inventory_if_due(
        store, generated_at="2026-10-20T11:00:00Z", min_interval_seconds=600, home_dir=home
    )
    again = remember_user_inventory_if_due(
        store, generated_at="2026-10-20T11:05:00Z", min_interval_seconds=600, home_dir=home
    )

    assert first == {"collected": True, "collected_at": "2026-10-20T11:00:00Z", "snapshots": 1, "items": 1}
    assert again["reason"] == "recently_collected"
    assert len(contexts) == 1 and contexts[0].workspace_dir is None
    assert store.get_sync_payload("aibom_sync_summary") is None
    assert {row["artifact_name"] for row in fleet_inventory_rows(store)} == {"chrome-devtools"}
