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
