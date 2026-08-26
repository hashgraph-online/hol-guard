from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.daemon.local_cli_api import LocalCliApiService
from codex_plugin_scanner.guard.runtime.custom_extension_continuity import (
    CUSTOM_EXTENSION_CONTINUITY_SCHEMA,
    CUSTOM_EXTENSION_CONTINUITY_STATE_KEY,
)
from codex_plugin_scanner.guard.runtime.local_cli_identity import UnlistedCliIdentity
from codex_plugin_scanner.guard.store import GuardStore


def test_recognize_reads_help_and_lists_commands(tmp_path: Path, monkeypatch) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.local_cli_api.Path.home",
        staticmethod(lambda: home),
    )
    script = home / "ship.py"
    script.write_text(
        """
print(\"\"\"Commands:
  deploy  Ship the build
  status  Show status
\"\"\")
""",
        encoding="utf-8",
    )
    store = GuardStore(home)
    service = LocalCliApiService(store=store)
    result = service.recognize({"command": f"python3 {script} deploy"})
    item = result["item"]
    assert isinstance(item, dict)
    ids = [entry["command_id"] for entry in item["commands"]]
    assert "root" in ids
    assert "deploy" in ids
    assert "status" in ids
    assert "other" in ids
    assert result["help_status"] == "ok"
    assert "commands" in str(result["summary"]).lower()


def test_list_items_exposes_continuity_only_when_every_production_flag_is_enabled(
    tmp_path: Path,
    monkeypatch,
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.local_cli_api.Path.home",
        staticmethod(lambda: home),
    )
    identity = UnlistedCliIdentity(
        cli_id="local-cli.ship-12345678",
        name="ship",
        kind="executable",
        identity_hash="a" * 64,
        example_label="ship",
    )
    store = GuardStore(home)
    store.record_local_cli_observation(identity, seen_at="2026-08-25T16:00:00Z")
    store.set_sync_payload(
        CUSTOM_EXTENSION_CONTINUITY_STATE_KEY,
        {
            "schema_version": CUSTOM_EXTENSION_CONTINUITY_SCHEMA,
            "cloud_revision": 1,
            "observed_at": "2026-08-25T16:00:00Z",
            "expires_at": "2099-08-25T17:00:00Z",
            "stale": False,
            "items": {
                identity.cli_id: {
                    "status": "applied",
                    "reason": "same_identity",
                    "cloud_revision": 1,
                    "surface": "cli",
                }
            },
        },
        "2026-08-25T16:00:00Z",
    )
    flags = (
        "GUARD_EXTENSION_CATALOG_SYNC_V1",
        "GUARD_POLICY_EXTENSION_TARGETS_V1",
        "GUARD_MANAGED_EXTENSION_CONTROLS_V1",
        "GUARD_MANAGED_CONTROLS_ATOMIC_APPLY_V1",
        "GUARD_EXTENSION_FIRST_CONTROLS_UI",
    )
    for name in flags:
        monkeypatch.setenv(name, "true")
    enabled = LocalCliApiService(store=store).list_items()
    assert enabled["cloud"]["continuity_enabled"] is True
    assert enabled["items"][0]["continuity"]["status"] == "applied"

    monkeypatch.setenv("GUARD_EXTENSION_FIRST_CONTROLS_UI", "false")
    disabled = LocalCliApiService(store=store).list_items()
    assert disabled["cloud"]["continuity_enabled"] is False
    assert disabled["items"][0]["continuity"] is None


def test_list_items_returns_stored_grants_when_discovery_fails(tmp_path: Path, monkeypatch) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.local_cli_api.Path.home",
        staticmethod(lambda: home),
    )
    identity = UnlistedCliIdentity(
        cli_id="local-cli.ship-12345678",
        name="ship",
        kind="executable",
        identity_hash="a" * 64,
        example_label="ship",
    )
    store = GuardStore(home)
    store.record_local_cli_observation(identity, seen_at="2026-08-25T16:00:00Z")
    store.upsert_local_cli_grant(
        identity=identity,
        state="allowed",
        expected_revision=0,
        updated_at="2026-08-25T16:00:00Z",
    )
    service = LocalCliApiService(store=store)

    def fail_labels() -> dict[str, str]:
        raise RuntimeError("harness discovery unavailable")

    def fail_observe() -> dict[str, str]:
        raise AssertionError("list_items must not persist harness MCP")

    monkeypatch.setattr(service, "_cached_source_labels", fail_labels)
    monkeypatch.setattr(service, "_observe_harness_mcp_servers", fail_observe)
    payload = service.list_items()
    items = payload["items"]
    assert isinstance(items, list)
    assert len(items) == 1
    listed = items[0]
    assert isinstance(listed, dict)
    assert listed["cli_id"] == identity.cli_id
    assert listed["state"] == "allowed"


def test_list_items_fallback_hides_unset_package_scripts_without_a_project(
    tmp_path: Path,
    monkeypatch,
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.local_cli_api.Path.home",
        staticmethod(lambda: home),
    )
    project = tmp_path / "gone-app"
    project.mkdir()
    (project / "package.json").write_text(
        '{"name":"gone-app","scripts":{"guard:audit":"tsx audit.ts"}}\n',
        encoding="utf-8",
    )
    (project / "pnpm-lock.yaml").write_text("{}\n", encoding="utf-8")
    store = GuardStore(home)
    service = LocalCliApiService(store=store)
    recognized = service.recognize({"command": "pnpm run", "cwd": str(project)})
    item = recognized["item"]
    assert isinstance(item, dict)
    (project / "package.json").unlink()
    payload = service.list_items()
    items = payload["items"]
    assert isinstance(items, list)
    assert all(entry.get("cli_id") != item["cli_id"] for entry in items if isinstance(entry, dict))


def test_list_items_keeps_granted_package_scripts_after_project_is_gone(
    tmp_path: Path,
    monkeypatch,
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.local_cli_api.Path.home",
        staticmethod(lambda: home),
    )
    project = tmp_path / "ads-app"
    project.mkdir()
    (project / "package.json").write_text(
        '{"name":"ads-app","scripts":{"guard:audit":"tsx audit.ts"}}\n',
        encoding="utf-8",
    )
    (project / "pnpm-lock.yaml").write_text("{}\n", encoding="utf-8")
    store = GuardStore(home)
    service = LocalCliApiService(store=store)
    recognized = service.recognize({"command": "pnpm run", "cwd": str(project)})
    item = recognized["item"]
    assert isinstance(item, dict)
    listed = UnlistedCliIdentity(
        cli_id=str(item["cli_id"]),
        name=str(item["name"]),
        kind="script",
        identity_hash=str(item["identity_hash"]),
        example_label=str(item["example_label"]),
        interpreter_name="pnpm",
    )
    store.upsert_local_cli_grant(
        identity=listed,
        state="allowed",
        expected_revision=int(recognized["revision"]),
        updated_at="2026-08-25T16:00:00Z",
    )
    (project / "package.json").unlink()
    payload = service.list_items()
    items = payload["items"]
    assert isinstance(items, list)
    granted = next(entry for entry in items if isinstance(entry, dict) and entry.get("cli_id") == listed.cli_id)
    assert granted["state"] == "allowed"
    assert granted["surface"] == "package-scripts"
