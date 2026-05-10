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
    inventory_snapshot_from_detection,
    redact_headers,
    redact_local_path,
    redact_url,
    serialize_inventory_snapshot,
)


class _Detection:
    harness = "hermes"
    artifacts = ()

    def __init__(self, config_paths: tuple[str, ...]) -> None:
        self.config_paths = config_paths


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
    assert classify_endpoint_host("http://172.20.4.5:8080/mcp") == "local_private"
    assert redact_url("https://user:pass@example.com/mcp?token=value&mode=safe") == "https://example.com/mcp?token=redacted&mode=safe"
    assert redact_url("https://example.com/mcp?auth=value&mode=safe") == "https://example.com/mcp?auth=redacted&mode=safe"
    assert redact_url("https://example.com/mcp?mode=safe;token=value") == "https://example.com/mcp?mode=safe&token=redacted"
    assert redact_url("http://localhost:${PORT}/mcp?auth=value") == "http://localhost/mcp?auth=redacted"
    assert redact_url("http://[2001:db8::1]:8080/mcp?token=value") == "http://[2001:db8::1]:8080/mcp?token=redacted"
    assert redact_url("http://[not-an-ip]/mcp?token=value") == "malformed_url_redacted"
    assert redact_local_path(path_a, home_dir=tmp_path) == "{home}/skill-a/SKILL.md"


def test_fingerprint_path_tree_skips_large_ignored_and_path_objects(tmp_path: Path) -> None:
    root = tmp_path / "workspace"
    (root / "node_modules" / "pkg").mkdir(parents=True)
    (root / ".git" / "objects").mkdir(parents=True)
    (root / "safe").mkdir(parents=True)
    (root / "safe" / "config.json").write_text('{"ok": true}\n')
    (root / "node_modules" / "pkg" / "ignored.json").write_text('{"ignored": true}\n')
    (root / ".git" / "objects" / "ignored").write_text("ignored\n")

    fingerprint = fingerprint_path_tree(root, home_dir=tmp_path)
    (root / "node_modules" / "pkg" / "ignored.json").write_text('{"ignored": "changed"}\n')
    (root / ".git" / "objects" / "ignored").write_text("changed\n")
    fingerprint_after_ignored_changes = fingerprint_path_tree(root, home_dir=tmp_path)
    snapshot = GuardAgentInventorySnapshot(
        snapshot_id="snap-path-object",
        agent_id="agent",
        agent_type="openclaw",
        generated_at="2026-05-10T00:00:00Z",
        items=(
            GuardAgentInventoryItem(
                item_id="item",
                item_kind="repository",
                display_name="Repo",
                source_fingerprint=fingerprint,
                content_hash=fingerprint_text("repo"),
                capability_categories=("reads_files",),
                metadata={"pathObject": root / "safe" / "config.json"},
            ),
        ),
    )

    encoded = json.dumps(serialize_inventory_snapshot(snapshot), sort_keys=True)

    assert fingerprint_after_ignored_changes == fingerprint
    assert str(tmp_path) not in encoded


def test_inventory_snapshot_deduplicates_config_sources(tmp_path: Path) -> None:
    config_path = tmp_path / ".hermes" / "config.yaml"
    config_path.parent.mkdir(parents=True)
    config_path.write_text("mcp_servers: {}\n")

    snapshot = inventory_snapshot_from_detection(
        _Detection((str(config_path), str(config_path))),
        generated_at="2026-05-10T00:00:00Z",
        home_dir=tmp_path,
    )

    assert len(snapshot.sources) == 1
