"""Tests for awesome-list submission helpers."""

from pathlib import Path

from codex_plugin_scanner.scanner import scan_plugin
from codex_plugin_scanner.submission import (
    SubmissionMetadata,
    build_submission_issue_body,
    build_submission_issue_title,
    build_submission_payload,
    resolve_submission_metadata,
)

FIXTURES = Path(__file__).parent / "fixtures"


def test_resolve_submission_metadata_prefers_manifest_fields() -> None:
    result = scan_plugin(FIXTURES / "good-plugin")

    metadata = resolve_submission_metadata(
        FIXTURES / "good-plugin",
        result,
        github_repository="hashgraph-online/example-good-plugin",
    )

    assert metadata.plugin_name == "Example Good Plugin"
    assert metadata.plugin_url == "https://github.com/hashgraph-online/codex-plugin-scanner"
    assert metadata.description == "Reusable security-first plugin fixture"
    assert metadata.author == "Hashgraph Online"
    assert metadata.category == "Community Plugins"


def test_resolve_submission_metadata_falls_back_to_github_context() -> None:
    result = scan_plugin(FIXTURES / "minimal-plugin")

    metadata = resolve_submission_metadata(
        FIXTURES / "minimal-plugin",
        result,
        github_repository="hashgraph-online/minimal-plugin",
    )

    assert metadata.plugin_name == "minimal-plugin"
    assert metadata.plugin_url == "https://github.com/hashgraph-online/minimal-plugin"
    assert metadata.author == "hashgraph-online"
    assert metadata.description == "A minimal plugin"


def test_submission_payload_and_issue_body_include_registry_data() -> None:
    result = scan_plugin(FIXTURES / "good-plugin")
    metadata = SubmissionMetadata(
        plugin_name="Example Good Plugin",
        plugin_url="https://github.com/hashgraph-online/example-good-plugin",
        description="Reusable security-first plugin fixture",
        author="Hashgraph Online",
        category="Community Plugins",
    )

    payload = build_submission_payload(
        metadata,
        result,
        source_repository="hashgraph-online/example-good-plugin",
        source_sha="abc123",
        workflow_url="https://github.com/hashgraph-online/example-good-plugin/actions/runs/1",
        scanner_version="1.2.0",
    )
    body = build_submission_issue_body(
        metadata,
        result,
        payload=payload,
        workflow_url="https://github.com/hashgraph-online/example-good-plugin/actions/runs/1",
    )

    assert payload["score"] == 100
    assert payload["grade"] == "A"
    assert payload["pluginUrl"] == metadata.plugin_url
    assert "## Registry Payload" in body
    assert '"pluginName": "Example Good Plugin"' in body
    assert metadata.plugin_url in body


def test_submission_issue_title_uses_plugin_prefix() -> None:
    metadata = SubmissionMetadata(
        plugin_name="Example Good Plugin",
        plugin_url="https://github.com/hashgraph-online/example-good-plugin",
        description="Reusable security-first plugin fixture",
        author="Hashgraph Online",
        category="Community Plugins",
    )

    assert build_submission_issue_title(metadata) == "[Plugin] Example Good Plugin"
    assert build_submission_issue_title(metadata, prefix="[Registry]") == "[Registry] Example Good Plugin"
