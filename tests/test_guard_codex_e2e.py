"""End-to-end Guard tests for headless Codex flows."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures"
PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _run_guard_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "codex_plugin_scanner.cli", *args],
        cwd=PROJECT_ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


def _copy_malicious_codex_workspace(destination: Path) -> Path:
    source = FIXTURES / "guard-codex-malicious-mcp"
    shutil.copytree(source, destination)
    (destination / ".env").write_text("OPENAI_API_KEY=fixture-test-key\n", encoding="utf-8")
    return destination


def test_guard_run_codex_blocks_malicious_mcp_fixture_end_to_end(tmp_path):
    home_dir = tmp_path / "home"
    workspace_dir = _copy_malicious_codex_workspace(tmp_path / "workspace")

    result = _run_guard_cli(
        "guard",
        "run",
        "codex",
        "--home",
        str(home_dir),
        "--workspace",
        str(workspace_dir),
        "--dry-run",
        "--json",
    )

    payload = json.loads(result.stdout)

    assert result.returncode == 1
    assert payload["blocked"] is True
    assert payload["artifacts"][0]["artifact_label"] == "MCP server"
    assert payload["artifacts"][0]["source_label"] == "project Codex config"
    assert "credential_sink" in payload["artifacts"][0]["trigger_summary"]
    assert "bash -lc" in payload["artifacts"][0]["launch_summary"]
    assert "local environment secrets" in payload["artifacts"][0]["risk_summary"].lower()
    assert "network" in payload["artifacts"][0]["risk_summary"].lower()


def test_guard_run_codex_honors_exact_allow_after_blocked_mcp_review(tmp_path):
    home_dir = tmp_path / "home"
    workspace_dir = _copy_malicious_codex_workspace(tmp_path / "workspace")

    blocked = _run_guard_cli(
        "guard",
        "run",
        "codex",
        "--home",
        str(home_dir),
        "--workspace",
        str(workspace_dir),
        "--dry-run",
        "--json",
    )
    blocked_payload = json.loads(blocked.stdout)
    artifact_id = blocked_payload["artifacts"][0]["artifact_id"]

    decision = _run_guard_cli(
        "guard",
        "allow",
        "codex",
        "--home",
        str(home_dir),
        "--workspace",
        str(workspace_dir),
        "--scope",
        "artifact",
        "--artifact-id",
        artifact_id,
        "--reason",
        "fixture exact approval",
        "--json",
    )
    decision_payload = json.loads(decision.stdout)

    rerun = _run_guard_cli(
        "guard",
        "run",
        "codex",
        "--home",
        str(home_dir),
        "--workspace",
        str(workspace_dir),
        "--dry-run",
        "--json",
    )
    rerun_payload = json.loads(rerun.stdout)

    assert blocked.returncode == 1
    assert decision.returncode == 0
    assert decision_payload["decision"]["scope"] == "artifact"
    assert rerun.returncode == 0
    assert rerun_payload["blocked"] is False
    assert rerun_payload["artifacts"][0]["policy_action"] == "allow"
