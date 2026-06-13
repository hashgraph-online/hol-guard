"""Serializer safety guards for AIBOM inventory snapshots (#196, #197, #209)."""

from __future__ import annotations

import json
from pathlib import Path

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.inventory_contract import (
    GuardAgentInventoryFinding,
    GuardAgentInventoryItem,
    GuardAgentInventorySnapshot,
    serialize_inventory_snapshot,
)
from codex_plugin_scanner.guard.store import GuardStore

_UNSAFE_PATH_MARKER = "/".join(["", "Users", "agent", "secret.txt"])
_SECRET_MARKER = "sk-testsecretvalueserializer"


def _snapshot_with_metadata(metadata: dict[str, object]) -> GuardAgentInventorySnapshot:
    return GuardAgentInventorySnapshot(
        snapshot_id="snap-serializer-security",
        agent_id="hermes-prod",
        agent_type="hermes",
        generated_at="2026-06-10T12:00:00.000Z",
        items=(
            GuardAgentInventoryItem(
                item_id="hermes:skill:serializer-security",
                item_kind="skill",
                display_name="Serializer security",
                description="Serializer security regression fixture.",
                source_fingerprint="fp-serializer-security",
                content_hash="sha256:serializer-security",
                capability_categories=(),
                metadata=metadata,
            ),
        ),
    )


def test_serialize_inventory_snapshot_redacts_raw_absolute_paths() -> None:
    snapshot = _snapshot_with_metadata({"localPath": _UNSAFE_PATH_MARKER})
    payload = serialize_inventory_snapshot(snapshot)
    encoded = json.dumps(payload, sort_keys=True)

    assert _UNSAFE_PATH_MARKER not in encoded
    assert payload["items"][0]["metadata"]["localPath"] == "[REDACTED]"


def test_serialize_inventory_snapshot_redacts_nested_sensitive_key_values() -> None:
    snapshot = _snapshot_with_metadata({"token": {"value": "npm_secret_value"}})
    payload = serialize_inventory_snapshot(snapshot)
    encoded = json.dumps(payload, sort_keys=True)

    assert "npm_secret_value" not in encoded
    token_metadata = payload["items"][0]["metadata"]["token"]
    assert isinstance(token_metadata, dict)
    assert token_metadata["value"] == "[REDACTED]"


def test_serialize_inventory_snapshot_redacts_secret_like_values() -> None:
    snapshot = _snapshot_with_metadata({"token": _SECRET_MARKER})
    payload = serialize_inventory_snapshot(snapshot)
    encoded = json.dumps(payload, sort_keys=True)

    assert _SECRET_MARKER not in encoded
    assert payload["items"][0]["metadata"]["token"] == "[REDACTED]"


def test_serialize_inventory_snapshot_redacts_unsafe_finding_summaries() -> None:
    snapshot = GuardAgentInventorySnapshot(
        snapshot_id="snap-serializer-security",
        agent_id="hermes-prod",
        agent_type="hermes",
        generated_at="2026-06-10T12:00:00.000Z",
        findings=(
            GuardAgentInventoryFinding(
                finding_id="finding-1",
                artifact_id="hermes:skill:serializer-security",
                check_id="aibom.serializer.unsafe",
                severity="high",
                confidence="high",
                source="metadata",
                title="Unsafe path",
                summary=f"Detected {_UNSAFE_PATH_MARKER}",
            ),
        ),
    )
    payload = serialize_inventory_snapshot(snapshot)
    encoded = json.dumps(payload, sort_keys=True)

    assert _UNSAFE_PATH_MARKER not in encoded
    assert payload["findings"][0]["summary"] == "[REDACTED]"


def test_guard_doctor_includes_aibom_status_without_raw_paths(tmp_path: Path, capsys) -> None:
    home_dir = tmp_path / "guard-home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    GuardStore(home_dir)

    rc = main(
        [
            "guard",
            "doctor",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    output = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert "aibom" in output
    assert output["aibom"]["snapshot_count"] >= 0
    encoded = json.dumps(output["aibom"], sort_keys=True)
    assert str(tmp_path) not in encoded
    assert _SECRET_MARKER not in encoded
