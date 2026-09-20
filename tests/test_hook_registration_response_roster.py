"""Keep current generated event sets connected to their response fixtures."""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard.adapters import cline_hooks, cursor_hook_config, grok_config
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.claude_code import ClaudeCodeHarnessAdapter
from codex_plugin_scanner.guard.adapters.codex import CodexHarnessAdapter
from codex_plugin_scanner.guard.adapters.contracts import HARNESS_CONTRACTS
from codex_plugin_scanner.guard.adapters.copilot import CopilotHarnessAdapter
from codex_plugin_scanner.guard.adapters.kimi import KimiHarnessAdapter
from codex_plugin_scanner.guard.adapters.pi_extension_source import managed_extension_source
from codex_plugin_scanner.guard.adapters.zcode import ZCodeHarnessAdapter
from codex_plugin_scanner.guard.config import tomllib

_ROOT = Path(__file__).resolve().parents[1]
_ROSTER: dict[str, Any] = json.loads(
    (_ROOT / "tests/fixtures/guard-hook-responses/registration-roster.v1.json").read_text(encoding="utf-8")
)
_ROWS = {row["harness"]: row for row in _ROSTER["surfaces"]}


def _context(tmp_path: Path) -> HarnessContext:
    home = tmp_path / "home"
    workspace = home / "workspace"
    workspace.mkdir(parents=True)
    return HarnessContext(home_dir=home, workspace_dir=workspace, guard_home=home / ".hol-guard")


def _expected(harness: str) -> set[str]:
    return set(_ROWS[harness]["managed_events"])


def _keys(value: object) -> set[str]:
    assert isinstance(value, dict)
    assert all(isinstance(key, str) for key in value)
    return set(value)


def test_every_canonical_harness_and_alias_has_an_explicit_surface_classification() -> None:
    assert set(_ROWS) == {contract.harness for contract in HARNESS_CONTRACTS}
    for contract in HARNESS_CONTRACTS:
        row = _ROWS[contract.harness]
        assert row["aliases"] == list(contract.install_aliases)
        assert row["claim_limits"]
        assert row["response_fixture_paths"]
        for path in row["response_fixture_paths"]:
            body = (_ROOT / path).read_text(encoding="utf-8")
            assert any(
                isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_")
                for node in ast.walk(ast.parse(body))
            ), path
    assert _ROWS["gemini"]["managed_events"] == _ROWS["antigravity"]["managed_events"] == []
    assert _ROWS["paseo"]["event_class"] == "delegated_provider_not_direct_native_hook"


@pytest.mark.parametrize("harness", ("claude-code", "codex", "copilot"))
def test_actual_priority_and_permission_installers_match_closed_event_roster(tmp_path: Path, harness: str) -> None:
    context = _context(tmp_path)
    if harness == "claude-code":
        ClaudeCodeHarnessAdapter().install(context)
        payload = json.loads((context.home_dir / ".claude/settings.json").read_text(encoding="utf-8"))
    elif harness == "codex":
        manifest = CodexHarnessAdapter().install(context)
        payload = tomllib.loads(Path(str(manifest["managed_hook_config_path"])).read_text(encoding="utf-8"))
    else:
        CopilotHarnessAdapter().install(context)
        assert context.workspace_dir is not None
        payload = json.loads(
            (context.workspace_dir / ".github/hooks/hol-guard-copilot.json").read_text(encoding="utf-8")
        )
    assert set(payload["hooks"]) == _expected(harness)


def test_bounded_hook_builders_match_closed_event_roster() -> None:
    kimi = tomllib.loads(KimiHarnessAdapter._build_managed_block("fixed fixture command"))
    assert {entry["event"] for entry in kimi["hooks"]} == _expected("kimi")
    grok = grok_config.build_pretool_hook_json("fixed fixture command")
    observed = grok_config.build_observe_hook_json("fixed fixture command")
    assert _keys(grok["hooks"]) | _keys(observed["hooks"]) == _expected("grok")
    hooks: dict[str, object] = {}
    ZCodeHarnessAdapter()._sync_managed_hook_groups(hooks, "fixed fixture command")
    assert _keys(hooks["events"]) == _expected("zcode")
    assert set(cline_hooks._EVENTS) == _expected("cline")
    assert set(cursor_hook_config._MANAGED_HOOK_EVENTS) == _expected("cursor")
    assert set(cursor_hook_config._OBSERVER_MANAGED_HOOK_EVENTS) == {"afterShellExecution", "afterMCPExecution"}


@pytest.mark.parametrize("harness", ("pi", "omp"))
def test_actual_extension_generator_matches_callback_roster(tmp_path: Path, harness: str) -> None:
    source = managed_extension_source(
        guard_home=tmp_path / "guard-home",
        home_dir=tmp_path / "home",
        settings_path=tmp_path / "settings.json",
        harness=harness,
        display_name=harness,
    )
    callbacks = re.findall(r'pi\.on\("([^"\n]+)"', source)
    assert len(callbacks) == len(set(callbacks))
    assert set(callbacks) == _expected(harness)


def test_every_cline_generated_event_has_complete_response_and_exit_capture() -> None:
    contract = json.loads(
        (_ROOT / "tests/fixtures/guard-hook-responses/current-cline-native.v1.json").read_text(encoding="utf-8")
    )
    assert set(contract["events"]) == _expected("cline")
    assert contract["exit_code"] == 0
    for condition in contract["conditions"].values():
        assert condition["nonblocking"]["cancel"] is False
        assert type(condition["blocking"]["cancel"]) is bool


def test_every_bounded_auxiliary_registration_has_response_and_exit_capture() -> None:
    contract = json.loads(
        (_ROOT / "tests/fixtures/guard-hook-responses/auxiliary-events.v1.json").read_text(encoding="utf-8")
    )
    for harness in ("copilot", "kimi", "grok", "zcode"):
        captured = {case["event"] for case in contract["cases"] if case["harness"] == harness}
        # Pre/post tools already have their own native delivery fixtures. The
        # auxiliary events must not disappear behind that pre/post coverage.
        existing_tools = {"PreToolUse", "PostToolUse", "preToolUse", "postToolUse"}
        assert captured == _expected(harness) - existing_tools
