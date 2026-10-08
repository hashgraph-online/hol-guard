"""Claude marketplace structure checks."""

from __future__ import annotations

import json
from pathlib import Path

from codex_plugin_scanner.checks.claude import check_marketplace_structure
from codex_plugin_scanner.ecosystems.claude import ClaudeAdapter
from codex_plugin_scanner.ecosystems.types import Ecosystem, NormalizedPackage
from codex_plugin_scanner.models import ScanOptions
from codex_plugin_scanner.scanner import scan_plugin


def _marketplace(raw_manifest: dict[str, object], tmp_path: Path) -> NormalizedPackage:
    return NormalizedPackage(
        ecosystem=Ecosystem.CLAUDE,
        package_kind="marketplace",
        root_path=tmp_path,
        manifest_path=tmp_path / ".claude-plugin" / "marketplace.json",
        raw_manifest=raw_manifest,
    )


def test_marketplace_without_strict_passes(tmp_path: Path) -> None:
    result = check_marketplace_structure(
        _marketplace(
            {
                "name": "my-plugins",
                "owner": {"name": "Example"},
                "plugins": [{"name": "quality-review-plugin", "source": "./plugins/quality-review-plugin"}],
            },
            tmp_path,
        )
    )

    assert result.passed is True
    assert result.points == 4
    assert result.findings == ()


def test_marketplace_plugin_strict_boolean_passes(tmp_path: Path) -> None:
    result = check_marketplace_structure(
        _marketplace(
            {
                "name": "my-plugins",
                "owner": {"name": "Example"},
                "plugins": [
                    {
                        "name": "quality-review-plugin",
                        "source": "./plugins/quality-review-plugin",
                        "strict": True,
                    }
                ],
            },
            tmp_path,
        )
    )

    assert result.passed is True
    assert result.points == 4
    assert result.findings == ()


def test_marketplace_root_strict_without_plugins_still_reports_strict(tmp_path: Path) -> None:
    result = check_marketplace_structure(
        _marketplace(
            {
                "name": "my-plugins",
                "owner": {"name": "Example"},
                "strict": True,
            },
            tmp_path,
        )
    )

    assert result.passed is False
    assert [finding.rule_id for finding in result.findings] == [
        "CLAUDE_MARKETPLACE_PLUGINS_MISSING",
        "CLAUDE_MARKETPLACE_STRICT_INVALID",
    ]


def test_marketplace_root_strict_is_rejected(tmp_path: Path) -> None:
    result = check_marketplace_structure(
        _marketplace(
            {
                "name": "my-plugins",
                "owner": {"name": "Example"},
                "strict": True,
                "plugins": [{"name": "quality-review-plugin", "source": "./plugins/quality-review-plugin"}],
            },
            tmp_path,
        )
    )

    assert result.passed is False
    assert result.points == 0
    assert [finding.rule_id for finding in result.findings] == ["CLAUDE_MARKETPLACE_STRICT_INVALID"]
    assert "plugins[]" in result.findings[0].description


def test_marketplace_non_boolean_plugin_strict_is_rejected(tmp_path: Path) -> None:
    result = check_marketplace_structure(
        _marketplace(
            {
                "name": "my-plugins",
                "owner": {"name": "Example"},
                "plugins": [
                    {
                        "name": "quality-review-plugin",
                        "source": "./plugins/quality-review-plugin",
                        "strict": "true",
                    }
                ],
            },
            tmp_path,
        )
    )

    assert result.passed is False
    assert result.points == 0
    assert [finding.rule_id for finding in result.findings] == ["CLAUDE_MARKETPLACE_STRICT_INVALID"]
    assert "plugins[0]" in result.findings[0].description


def test_scan_documented_marketplace_does_not_emit_strict_finding(tmp_path: Path) -> None:
    marketplace = tmp_path / "my-marketplace"
    manifest_dir = marketplace / ".claude-plugin"
    manifest_dir.mkdir(parents=True)
    (manifest_dir / "marketplace.json").write_text(
        json.dumps(
            {
                "name": "my-plugins",
                "owner": {"name": "Example"},
                "plugins": [
                    {
                        "name": "quality-review-plugin",
                        "source": "./plugins/quality-review-plugin",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    result = scan_plugin(marketplace, ScanOptions(ecosystem="claude", cisco_skill_scan="off"))

    assert all(finding.rule_id != "CLAUDE_MARKETPLACE_STRICT_INVALID" for finding in result.findings)
    structure = next(
        check
        for category in result.categories
        for check in category.checks
        if check.name == "Claude marketplace structure"
    )
    assert structure.passed is True
    assert structure.points == 4


def test_claude_adapter_does_not_collapse_marketplace_strict(tmp_path: Path) -> None:
    manifest_path = tmp_path / ".claude-plugin" / "marketplace.json"
    manifest_path.parent.mkdir(parents=True)
    manifest_path.write_text(
        json.dumps(
            {
                "name": "my-plugins",
                "owner": {"name": "Example"},
                "strict": True,
                "plugins": [
                    {
                        "name": "quality-review-plugin",
                        "source": "./plugins/quality-review-plugin",
                        "strict": False,
                    },
                    {
                        "name": "docs-plugin",
                        "source": "./plugins/docs-plugin",
                        "strict": True,
                    },
                ],
            }
        ),
        encoding="utf-8",
    )

    adapter = ClaudeAdapter()
    package = adapter.parse(adapter.detect(tmp_path)[0])

    assert "strict" not in package.policies
