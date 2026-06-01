from __future__ import annotations

import json
from pathlib import Path

from codex_plugin_scanner.guard.inventory_cisco import CiscoInventoryRun
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
from codex_plugin_scanner.guard.models import GuardArtifact, HarnessDetection
from codex_plugin_scanner.models import Finding, Severity


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
    assert classify_endpoint_host("http://[not-an-ip]/mcp") == "remote_public"
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


def test_inventory_snapshot_extracts_mcp_tool_items(tmp_path: Path) -> None:
    detection = HarnessDetection(
        harness="hermes",
        installed=True,
        command_available=False,
        config_paths=(),
        artifacts=(
            GuardArtifact(
                artifact_id="hermes:mcp:json:tools",
                name="tools",
                harness="hermes",
                artifact_type="mcp_server",
                source_scope="global",
                config_path=str(tmp_path / ".hermes" / "mcp_servers.json"),
                metadata={
                    "tools": [
                        {
                            "name": "search_docs",
                            "title": "Search docs",
                            "description": "Read-only search over project documentation.",
                            "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}}},
                            "outputSchema": {"type": "object"},
                            "annotations": {"readOnlyHint": True, "destructiveHint": False},
                        },
                        {
                            "name": "delete_file",
                            "description": "Delete a file from disk.",
                            "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}},
                            "annotations": {"destructiveHint": True},
                        },
                    ]
                },
            ),
        ),
    )

    snapshot = inventory_snapshot_from_detection(
        detection,
        generated_at="2026-05-10T00:00:00Z",
        home_dir=tmp_path,
    )
    items = {item.item_id: item for item in snapshot.items}

    assert "hermes:mcp:json:tools:tool:search_docs" in items
    assert "hermes:mcp:json:tools:tool:delete_file" in items
    assert items["hermes:mcp:json:tools:tool:search_docs"].capability_categories == ("reads_files",)
    assert "writes_files" in items["hermes:mcp:json:tools:tool:delete_file"].capability_categories
    assert items["hermes:mcp:json:tools:tool:delete_file"].risk_level == "high"


def test_inventory_snapshot_handles_missing_mcp_tool_schema_and_scale(tmp_path: Path) -> None:
    tools = [{"name": f"tool_{index}", "description": "No schema available."} for index in range(500)]
    detection = HarnessDetection(
        harness="openclaw",
        installed=True,
        command_available=False,
        config_paths=(),
        artifacts=(
            GuardArtifact(
                artifact_id="openclaw:mcp:bulk",
                name="bulk",
                harness="openclaw",
                artifact_type="mcp_server",
                source_scope="global",
                config_path=str(tmp_path / ".openclaw" / "openclaw.json"),
                metadata={"tools": tools},
            ),
        ),
    )

    snapshot = inventory_snapshot_from_detection(
        detection,
        generated_at="2026-05-10T00:00:00Z",
        home_dir=tmp_path,
    )
    tool_items = [item for item in snapshot.items if item.item_kind == "mcp_tool"]

    assert len(tool_items) == 500
    assert all(item.capability_categories == ("unknown",) for item in tool_items)


def test_inventory_snapshot_preserves_empty_mcp_tool_schemas(tmp_path: Path) -> None:
    detection = HarnessDetection(
        harness="hermes",
        installed=True,
        command_available=False,
        config_paths=(),
        artifacts=(
            GuardArtifact(
                artifact_id="hermes:mcp:empty-schema",
                name="empty-schema",
                harness="hermes",
                artifact_type="mcp_server",
                source_scope="global",
                config_path=str(tmp_path / ".hermes" / "mcp_servers.json"),
                metadata={"tools": [{"name": "ping", "inputSchema": {}, "output_schema": {}}]},
            ),
        ),
    )

    snapshot = inventory_snapshot_from_detection(
        detection,
        generated_at="2026-05-10T00:00:00Z",
        home_dir=tmp_path,
    )
    tool = next(item for item in snapshot.items if item.item_kind == "mcp_tool")

    assert tool.metadata["schemaPresent"] is True
    assert tool.metadata["inputSchemaHash"] == fingerprint_mapping({})
    assert tool.metadata["outputSchemaHash"] == fingerprint_mapping({})


def test_inventory_snapshot_mcp_capabilities_avoid_substring_false_positives(tmp_path: Path) -> None:
    detection = HarnessDetection(
        harness="hermes",
        installed=True,
        command_available=False,
        config_paths=(),
        artifacts=(
            GuardArtifact(
                artifact_id="hermes:mcp:false-positive",
                name="false-positive",
                harness="hermes",
                artifact_type="mcp_server",
                source_scope="global",
                config_path=str(tmp_path / ".hermes" / "mcp_servers.json"),
                metadata={
                    "tools": [
                        {
                            "name": "thread_listener",
                            "description": "Returns execution_id for listened events.",
                            "inputSchema": {"type": "object", "properties": {"execution_id": {"type": "string"}}},
                        },
                        {
                            "name": "credential_probe",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "api_key": {"type": "string"},
                                    "apiKey": {"type": "string"},
                                },
                            },
                        },
                    ]
                },
            ),
        ),
    )

    snapshot = inventory_snapshot_from_detection(
        detection,
        generated_at="2026-05-10T00:00:00Z",
        home_dir=tmp_path,
    )
    tool_items = {item.display_name: item for item in snapshot.items if item.item_kind == "mcp_tool"}

    assert tool_items["thread_listener"].capability_categories == ("unknown",)
    assert tool_items["credential_probe"].capability_categories == ("reads_secrets",)


def test_inventory_snapshot_mcp_capabilities_ignore_schema_boilerplate(tmp_path: Path) -> None:
    detection = HarnessDetection(
        harness="hermes",
        installed=True,
        command_available=False,
        config_paths=(),
        artifacts=(
            GuardArtifact(
                artifact_id="hermes:mcp:schema-boilerplate",
                name="schema-boilerplate",
                harness="hermes",
                artifact_type="mcp_server",
                source_scope="global",
                config_path=str(tmp_path / ".hermes" / "mcp_servers.json"),
                metadata={
                    "tools": [
                        {
                            "name": "local_formatter",
                            "inputSchema": {
                                "$schema": "https://json-schema.org/draft/2020-12/schema",
                                "type": "object",
                                "properties": {"format": {"type": "string"}},
                            },
                        },
                        {
                            "name": "remote_probe",
                            "inputSchema": {
                                "$schema": "https://json-schema.org/draft/2020-12/schema",
                                "type": "object",
                                "properties": {"url": {"type": "string"}},
                            },
                        },
                    ]
                },
            ),
        ),
    )

    snapshot = inventory_snapshot_from_detection(
        detection,
        generated_at="2026-05-10T00:00:00Z",
        home_dir=tmp_path,
    )
    tool_items = {item.display_name: item for item in snapshot.items if item.item_kind == "mcp_tool"}

    assert tool_items["local_formatter"].capability_categories == ("unknown",)
    assert tool_items["remote_probe"].capability_categories == ("network_egress",)


def test_inventory_snapshot_mcp_tool_fallback_skips_non_schema_tool_allowlist(tmp_path: Path) -> None:
    detection = HarnessDetection(
        harness="hermes",
        installed=True,
        command_available=False,
        config_paths=(),
        artifacts=(
            GuardArtifact(
                artifact_id="hermes:mcp:tool-schema-fallback",
                name="tool-schema-fallback",
                harness="hermes",
                artifact_type="mcp_server",
                source_scope="global",
                config_path=str(tmp_path / ".hermes" / "mcp_servers.json"),
                metadata={
                    "tools": ["*"],
                    "tool_schemas": [
                        {
                            "name": "search_repo",
                            "description": "Search local project files.",
                        }
                    ],
                },
            ),
        ),
    )

    snapshot = inventory_snapshot_from_detection(
        detection,
        generated_at="2026-05-10T00:00:00Z",
        home_dir=tmp_path,
    )
    tool_items = [item for item in snapshot.items if item.item_kind == "mcp_tool"]

    assert len(tool_items) == 1
    assert tool_items[0].display_name == "search_repo"
    assert tool_items[0].capability_categories == ("reads_files",)


def test_inventory_snapshot_maps_cisco_findings_to_redacted_inventory_evidence(tmp_path: Path) -> None:
    skill_path = tmp_path / ".hermes" / "skills" / "ops" / "reviewer" / "SKILL.md"
    skill_path.parent.mkdir(parents=True)
    skill_path.write_text("---\nname: reviewer\n---\nUse safe local review.\n")
    detection = HarnessDetection(
        harness="hermes",
        installed=True,
        command_available=False,
        config_paths=(str(skill_path),),
        artifacts=(
            GuardArtifact(
                artifact_id="hermes:skill:ops:reviewer",
                name="reviewer",
                harness="hermes",
                artifact_type="skill",
                source_scope="global",
                config_path=str(skill_path),
                metadata={"content_hash": "abc123"},
            ),
        ),
    )
    finding = Finding(
        rule_id="CISCO-SKILL-PROMPT-INJECTION",
        severity=Severity.HIGH,
        category="skill-security",
        title="Prompt injection token=fixture_secretvalue",
        description=f"Unsafe instruction in {skill_path} with token=fixture_secretvalue",
        file_path=str(skill_path),
        line_number=7,
        source="cisco-skill-scanner",
    )
    cisco_run = CiscoInventoryRun(
        source="cisco-skill-scanner",
        status="enabled",
        message="Cisco skill scanner found token=fixture_secretvalue",
        findings=(finding, finding),
        duration_ms=42,
        metadata={"totalFindings": 2},
    )

    snapshot = inventory_snapshot_from_detection(
        detection,
        generated_at="2026-05-10T00:00:00Z",
        home_dir=tmp_path,
        cisco_runs=(cisco_run,),
    )
    payload = serialize_inventory_snapshot(snapshot)
    encoded = json.dumps(payload, sort_keys=True)

    assert len(payload["findings"]) == 1
    assert payload["findings"][0]["source"] == "cisco-skill-scanner"
    assert payload["findings"][0]["severity"] == "high"
    assert payload["findings"][0]["confidence"] == "high"
    assert payload["findings"][0]["artifact_id"] == "hermes:skill:ops:reviewer"
    assert payload["findings"][0]["evidence"]["durationMs"] == 42
    assert payload["findings"][0]["evidence"]["riskComponent"]["scoreDelta"] == -25
    assert payload["sources"][-1]["source_type"] == "scanner"
    assert "fixture_secretvalue" not in encoded
    assert str(tmp_path) not in encoded
