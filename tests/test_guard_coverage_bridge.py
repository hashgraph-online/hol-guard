from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.action_runner import _build_step_summary_lines
from codex_plugin_scanner.cli_ui import build_plain_text
from codex_plugin_scanner.ecosystems._json_support import load_json_object
from codex_plugin_scanner.guard_coverage_bridge import _event_matches_surface, build_guard_coverage_bridge
from codex_plugin_scanner.models import CategoryResult, PackageSummary, ScanResult
from codex_plugin_scanner.reporting import build_json_payload, format_markdown
from codex_plugin_scanner.scanner import scan_plugin

FIXTURES = Path(__file__).parent / "fixtures"


def test_codex_skills_map_to_prompt_coverage() -> None:
    result = scan_plugin(FIXTURES / "good-plugin")

    bridge = build_guard_coverage_bridge(result)

    assert bridge is not None
    assert bridge["schemaVersion"] == "guard-coverage-bridge.v1"
    assert bridge["detectedSurfaces"] == ["prompt"]
    assert bridge["harnesses"][0]["harness"] == "codex"
    assert bridge["harnesses"][0]["coverage"][0]["status"] == "configured"
    assert bridge["harnesses"][0]["coverage"][0]["claims"][0]["event"] == "UserPromptSubmit"


def test_claude_mcp_surface_uses_blocking_pretool_claim() -> None:
    result = ScanResult(
        score=100,
        grade="A",
        categories=(),
        timestamp="2026-01-01T00:00:00Z",
        plugin_dir="plugin",
        ecosystems=("claude",),
        packages=(
            PackageSummary(
                ecosystem="claude",
                package_kind="single-plugin",
                root_path="plugin",
                components=("mcp_servers",),
            ),
        ),
    )

    bridge = build_guard_coverage_bridge(result)

    assert bridge is not None
    harness = bridge["harnesses"][0]
    assert harness["harness"] == "claude-code"
    assert harness["coverage"][0]["surface"] == "mcp_tool"
    assert harness["coverage"][0]["status"] == "configured"
    assert harness["coverage"][0]["claims"][0]["event"] == "PreToolUse"


def test_pretooluse_claims_respect_tool_filters() -> None:
    filtered = {"event": "PreToolUse", "tools": ["Write", "Edit", "MultiEdit"]}
    unfiltered = {"event": "PreToolUse", "tools": []}

    assert not _event_matches_surface(filtered, "mcp_tool")
    assert not _event_matches_surface(unfiltered, "prompt")
    assert _event_matches_surface(unfiltered, "mcp_tool")


def test_non_utf8_manifest_is_treated_as_invalid_json(tmp_path: Path) -> None:
    manifest = tmp_path / "plugin.json"
    manifest.write_bytes(b"\xff")

    assert load_json_object(manifest) == {}


def test_mixed_scan_keeps_surfaces_with_their_ecosystem() -> None:
    result = ScanResult(
        score=100,
        grade="A",
        categories=(),
        timestamp="2026-01-01T00:00:00Z",
        plugin_dir="plugin",
        ecosystems=("claude", "codex"),
        packages=(
            PackageSummary(
                ecosystem="codex",
                package_kind="single-plugin",
                root_path="codex",
                components=("skills",),
            ),
            PackageSummary(
                ecosystem="claude",
                package_kind="single-plugin",
                root_path="claude",
                components=("mcp_servers",),
            ),
        ),
    )

    bridge = build_guard_coverage_bridge(result)

    assert bridge is not None
    by_harness = {harness["harness"]: harness for harness in bridge["harnesses"]}
    assert bridge["detectedSurfaces"] == ["mcp_tool", "prompt"]
    assert [item["surface"] for item in by_harness["codex"]["coverage"]] == ["prompt"]
    assert [item["surface"] for item in by_harness["claude-code"]["coverage"]] == ["mcp_tool"]


def test_bridge_is_omitted_without_runtime_components(tmp_path: Path) -> None:
    result = ScanResult(
        score=100,
        grade="A",
        categories=(),
        timestamp="2026-01-01T00:00:00Z",
        plugin_dir=str(tmp_path),
        ecosystems=("codex",),
        packages=(
            PackageSummary(
                ecosystem="codex",
                package_kind="single-plugin",
                root_path=str(tmp_path),
            ),
        ),
    )

    assert build_guard_coverage_bridge(result) is None


def test_reports_include_contextual_bridge_only_when_relevant() -> None:
    result = scan_plugin(FIXTURES / "good-plugin")

    payload = build_json_payload(result)
    markdown = format_markdown(result)
    plain_text = build_plain_text(result)
    summary = "\n".join(
        _build_step_summary_lines(
            mode="scan",
            score=str(result.score),
            grade=result.grade,
            grade_label="Excellent",
            max_severity="none",
            findings_total="0",
            report_path="",
            registry_payload_path="",
            submission_issues=[],
            submission_eligible=False,
            guard_coverage=payload["guardCoverage"],
        )
    )

    assert payload["guardCoverage"]["schemaVersion"] == "guard-coverage-bridge.v1"
    assert "## Guard coverage context" in markdown
    assert "Guard coverage context:" in plain_text
    assert "## Guard coverage context" in summary
    assert "does not prove that Guard is installed" in markdown
    assert "https://github.com/hashgraph-online/hol-guard/blob/main/docs/guard/harness-claims.md" in summary


def test_package_component_names_are_not_serialized_into_public_json() -> None:
    result = ScanResult(
        score=100,
        grade="A",
        categories=(CategoryResult(name="Security", checks=()),),
        timestamp="2026-01-01T00:00:00Z",
        plugin_dir="plugin",
        ecosystems=("codex",),
        packages=(
            PackageSummary(
                ecosystem="codex",
                package_kind="single-plugin",
                root_path="plugin",
                components=("skills",),
            ),
        ),
    )

    package_payload = build_json_payload(result)["packages"][0]

    assert "components" not in package_payload
