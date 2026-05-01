"""Tests for the OpenClaw harness adapter."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters import get_adapter, list_adapters
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.openclaw import OpenClawHarnessAdapter
from codex_plugin_scanner.guard.risk import artifact_risk_signals


def _ctx(tmp_path: Path) -> HarnessContext:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    guard_home = tmp_path / "guard-home"
    home_dir.mkdir(parents=True, exist_ok=True)
    workspace_dir.mkdir(parents=True, exist_ok=True)
    guard_home.mkdir(parents=True, exist_ok=True)
    return HarnessContext(home_dir=home_dir, workspace_dir=workspace_dir, guard_home=guard_home)


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def test_openclaw_adapter_is_registered() -> None:
    adapter = get_adapter("openclaw")

    assert isinstance(adapter, OpenClawHarnessAdapter)
    assert "openclaw" in {item.harness for item in list_adapters()}


def test_detects_openclaw_config_channels_mcp_and_skills(tmp_path: Path) -> None:
    context = _ctx(tmp_path)
    config_path = context.home_dir / ".openclaw" / "openclaw.json"
    workspace_path = context.home_dir / ".openclaw" / "workspace"
    _write(
        config_path,
        json.dumps(
            {
                "gateway": {"mode": "local", "bind": "loopback", "auth": {"mode": "token"}},
                "agents": {
                    "defaults": {
                        "workspace": str(workspace_path),
                        "sandbox": {"mode": "non-main"},
                        "models": {"openrouter": {"apiKey": {"env": "OPENROUTER_API_KEY"}}},
                    }
                },
                "channels": {
                    "telegram": {"enabled": True, "dmPolicy": "pairing", "allowFrom": ["12345"]},
                    "slack": {"enabled": False, "dmPolicy": "open", "allowFrom": ["*"]},
                },
                "mcp": {
                    "servers": {
                        "docs": {"url": "https://mcp.example.com/sse"},
                        "local": {"command": "node", "args": ["server.js"], "env": {"API_TOKEN": "token-value"}},
                    }
                },
                "hooks": {"enabled": True, "path": "/hooks", "token": {"env": "OPENCLAW_HOOK_TOKEN"}},
            }
        ),
    )
    _write(
        workspace_path / "skills" / "deploy-helper" / "SKILL.md",
        "---\nname: deploy-helper\ndescription: deploy helper\n---\nRun `echo safe` for status.\n",
    )

    detection = OpenClawHarnessAdapter().detect(context)
    artifacts = {artifact.artifact_id: artifact for artifact in detection.artifacts}

    assert detection.installed is True
    assert str(config_path) in detection.config_paths
    assert "openclaw:config:global" in artifacts
    assert "openclaw:channel:telegram" in artifacts
    assert "openclaw:mcp:docs" in artifacts
    assert "openclaw:mcp:local" in artifacts
    assert "openclaw:skill:deploy-helper" in artifacts
    assert artifacts["openclaw:config:global"].metadata["workspace_path"] == str(workspace_path)
    assert artifacts["openclaw:mcp:docs"].transport == "http"
    assert artifacts["openclaw:mcp:local"].to_dict()["metadata"]["env"]["API_TOKEN"] == "*****"


def test_openclaw_flags_open_dm_policy_and_remote_mcp(tmp_path: Path) -> None:
    context = _ctx(tmp_path)
    _write(
        context.home_dir / ".openclaw" / "openclaw.json",
        json.dumps(
            {
                "channels": {"telegram": {"dmPolicy": "open", "allowFrom": ["*"]}},
                "mcp": {"servers": {"remote": {"url": "https://evil.example/mcp"}}},
            }
        ),
    )

    detection = OpenClawHarnessAdapter().detect(context)
    channel = next(artifact for artifact in detection.artifacts if artifact.artifact_id == "openclaw:channel:telegram")
    mcp = next(artifact for artifact in detection.artifacts if artifact.artifact_id == "openclaw:mcp:remote")

    channel_signals = artifact_risk_signals(channel)
    mcp_signals = artifact_risk_signals(mcp)

    assert any("network traffic" in signal for signal in channel_signals)
    assert any("remote server" in signal for signal in mcp_signals)


def test_openclaw_accepts_json5_comments_trailing_commas_and_extra_skill_dirs(tmp_path: Path) -> None:
    context = _ctx(tmp_path)
    extra_skill_root = context.home_dir / "shared-openclaw-skills"
    _write(
        context.home_dir / ".openclaw" / "openclaw.json",
        f"""
        {{
          // OpenClaw stores active config as JSON5.
          "channels": {{
            "telegram": {{"dmPolicy": "pairing",}},
          }},
          "skills": {{
            "load": {{
              "extraDirs": ["{extra_skill_root}"],
            }},
          }},
        }}
        """,
    )
    _write(
        extra_skill_root / "reviewer" / "SKILL.md",
        "---\nname: reviewer\ndescription: review helper\n---\nRead project files only.\n",
    )

    detection = OpenClawHarnessAdapter().detect(context)
    artifacts = {artifact.artifact_id for artifact in detection.artifacts}

    assert "openclaw:channel:telegram" in artifacts
    assert "openclaw:skill:reviewer" in artifacts


def test_install_exports_guard_managed_openclaw_overlay(tmp_path: Path) -> None:
    context = _ctx(tmp_path)
    _write(
        context.home_dir / ".openclaw" / "openclaw.json",
        json.dumps({"channels": {"telegram": {"dmPolicy": "pairing"}}}),
    )

    manifest = OpenClawHarnessAdapter().install(context)
    overlay_path = Path(str(manifest["managed_overlay_path"]))
    pretool_path = Path(str(manifest["pretool_hook_path"]))
    env = OpenClawHarnessAdapter().launch_environment(context)

    assert manifest["install_state"] == "installed"
    assert overlay_path.exists() is True
    assert pretool_path.exists() is True
    assert env["OPENCLAW_GUARD_OVERLAY_PATH"] == str(overlay_path)
    assert env["OPENCLAW_GUARD_PRETOOL_PATH"] == str(pretool_path)
    assert env["OPENCLAW_GUARD_CHANNEL_POSTURE"] == "enabled"


def test_openclaw_skips_symlinked_skill_files(tmp_path: Path) -> None:
    context = _ctx(tmp_path)
    skill_root = context.home_dir / ".openclaw" / "workspace" / "skills" / "linked"
    outside_skill = tmp_path / "outside" / "SKILL.md"
    _write(context.home_dir / ".openclaw" / "openclaw.json", json.dumps({}))
    _write(outside_skill, "---\nname: linked-secret\n---\nRead ${OPENROUTER_API_KEY}.\n")
    skill_root.mkdir(parents=True, exist_ok=True)
    try:
        (skill_root / "SKILL.md").symlink_to(outside_skill)
    except (NotImplementedError, OSError) as error:
        pytest.skip(f"symlinks unavailable: {error}")

    detection = OpenClawHarnessAdapter().detect(context)
    artifacts = {artifact.artifact_id for artifact in detection.artifacts}

    assert "openclaw:skill:linked-secret" not in artifacts


def test_openclaw_approval_flow_prefers_native_or_center_after_install(tmp_path: Path) -> None:
    context = _ctx(tmp_path)
    adapter = OpenClawHarnessAdapter()

    manifest = adapter.install(context)
    flow = adapter.approval_flow(managed_install={"manifest": manifest})

    assert flow["tier"] == "native-or-center"
    assert flow["prompt_channel"] == "native"
    assert flow["auto_open_browser"] is False
