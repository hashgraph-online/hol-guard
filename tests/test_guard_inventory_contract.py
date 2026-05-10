from __future__ import annotations

import json
from pathlib import Path

from codex_plugin_scanner.guard.inventory_contract import (
    GuardAgentInventoryFinding,
    GuardAgentInventoryItem,
    GuardAgentInventorySnapshot,
    classify_endpoint_host,
    fingerprint_mapping,
    fingerprint_path_tree,
    fingerprint_text,
    inventory_item_id,
    redact_headers,
    redact_local_path,
    redact_url,
    serialize_inventory_snapshot,
)


def test_inventory_snapshot_serialization_redacts_raw_secrets(tmp_path: Path) -> None:
    skill_dir = tmp_path / "home" / "skills" / "danger"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text("use token sk-testsecretvalue and Authorization: Bearer secret\n")

    snapshot = GuardAgentInventorySnapshot(
        snapshot_id="snap-hermes-1",
        agent_id="agent-hermes",
        agent_type="hermes",
        generated_at="2026-05-10T00:00:00Z",
        runtime_version="hermes-test",
        items=(
            GuardAgentInventoryItem(
                item_id="skill-danger",
                item_kind="skill",
                display_name="Danger skill",
                source_fingerprint=fingerprint_path_tree(skill_dir, home_dir=tmp_path / "home"),
                content_hash=fingerprint_text((skill_dir / "SKILL.md").read_text()),
                capability_categories=("reads_secrets", "network_egress"),
                metadata={
                    "headers": redact_headers({"Authorization": "Bearer secret", "X-Trace": "safe"}),
                    "url": redact_url("https://user:pass@example.com/mcp?token=secret&mode=safe"),
                    "path": redact_local_path(skill_dir / "SKILL.md", home_dir=tmp_path / "home"),
                },
            ),
        ),
        findings=(
            GuardAgentInventoryFinding(
                finding_id="finding-1",
                source="hol-detector",
                severity="high",
                confidence="high",
                title="Secret access",
                artifact_id="skill-danger",
                check_id="secret-access",
            ),
        ),
        redaction_report={"raw_secret_values": False, "redacted_fields": ("headers.authorization", "url.token")},
    )

    payload = serialize_inventory_snapshot(snapshot)
    encoded = json.dumps(payload, sort_keys=True)

    assert "sk-testsecretvalue" not in encoded
    assert "Bearer secret" not in encoded
    assert "user:pass" not in encoded
    assert str(tmp_path / "home") not in encoded
    assert payload["items"][0]["metadata"]["headers"]["authorization"] == "present_redacted"
    assert payload["items"][0]["metadata"]["headers"]["x-trace"] == "present"


def test_inventory_helpers_emit_safe_endpoint_and_stable_hashes(tmp_path: Path) -> None:
    config_a = {"b": [2, 1], "a": {"nested": True}}
    config_b = {"a": {"nested": True}, "b": [2, 1]}
    path_a = tmp_path / "skill-a" / "SKILL.md"
    path_b = tmp_path / "renamed" / "SKILL.md"
    path_a.parent.mkdir()
    path_b.parent.mkdir()
    path_a.write_text("name: demo\n\nRun search query\n")
    path_b.write_text("name: demo\n\nRun search   query\n")

    assert fingerprint_mapping(config_a) == fingerprint_mapping(config_b)
    assert inventory_item_id("hermes", "skill", "demo", path_a.read_text()) == inventory_item_id(
        "hermes",
        "skill",
        "demo",
        path_b.read_text(),
    )
    assert classify_endpoint_host("https://user:pass@example.com/mcp?token=value") == "remote_public"
    assert redact_url("https://user:pass@example.com/mcp?token=value&mode=safe") == "https://example.com/mcp?token=redacted&mode=safe"
    assert redact_local_path(path_a, home_dir=tmp_path) == "{home}/skill-a/SKILL.md"
