from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PLUGIN_ROOT = ROOT / "integrations" / "claude-code-plugin"


def test_claude_marketplace_manifest_is_minimal_and_install_focused() -> None:
    manifest = json.loads((PLUGIN_ROOT / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8"))

    assert manifest["name"] == "hol-guard"
    assert manifest["displayName"] == "HOL Guard"
    assert manifest["repository"] == "https://github.com/hashgraph-online/hol-guard"
    assert manifest["homepage"] == "https://hol.org/guard"
    assert manifest["license"] == "Apache-2.0"
    assert "security" in manifest["keywords"]
    assert "mcp" in manifest["keywords"]

    # The marketplace companion must not create a second hook implementation.
    # `hol-guard init` remains the authority for installing Claude Code hooks.
    assert "hooks" not in manifest
    assert not (PLUGIN_ROOT / "hooks").exists()


def test_setup_skill_drives_real_guard_install_without_silent_side_effects() -> None:
    setup = (PLUGIN_ROOT / "skills" / "setup" / "SKILL.md").read_text(encoding="utf-8")

    assert "disable-model-invocation: true" in setup
    assert "pipx install hol-guard" in setup
    assert "hol-guard init" in setup
    assert "hol-guard status" in setup
    assert "explicit approval" in setup
    assert "Do not claim protection from plugin installation alone" in setup
    assert "Guard Cloud" in setup
    assert "optional" in setup


def test_status_skill_is_read_only_by_default() -> None:
    status = (PLUGIN_ROOT / "skills" / "status" / "SKILL.md").read_text(encoding="utf-8")

    assert "disable-model-invocation: true" in status
    assert "read-only checks first" in status
    assert "hol-guard --version" in status
    assert "hol-guard status" in status
    assert "/hol-guard:setup" in status and "pipx install hol-guard" not in status and "hol-guard init" not in status
