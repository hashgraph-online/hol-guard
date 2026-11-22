"""The native store answers the single-value local CLI reads."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.store import GuardStore


def test_a_fresh_store_reads_no_local_cli_authority(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")

    assert store.read_local_cli_revision() == 0
    assert store.read_local_cli_surface("local-cli.tool") is None
    assert store.has_local_cli_block_rules() is False
    assert store.read_local_cli_capabilities("local-cli.tool") == {
        "loopback-network": "off",
        "state-dir-read": "off",
        "state-dir-write": "off",
    }


def test_a_cause_for_an_unobserved_cli_changes_nothing(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")

    changed = store.note_local_cli_capability_cause(
        cli_id="local-cli.tool", identity_hash="hash", cause="connect_loopback"
    )

    assert changed == 0
