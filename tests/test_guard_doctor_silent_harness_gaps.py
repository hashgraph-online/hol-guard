from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters import get_adapter
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.omp_code_mode import OMP_CODE_MODE_WARNING, omp_code_mode_warnings
from codex_plugin_scanner.guard.codex_hook_registration import codex_hook_doctor_warnings
from codex_plugin_scanner.guard.codex_hook_trust import codex_command_hook_hash, stale_guard_hook_coordinates

GUARD_COMMAND = "/opt/guard/1.2.3/hol-guard-codex-hook --harness codex"


def test_codex_hash_known_answer() -> None:
    # Canonical identity per codex-rs discovery.rs hook_hash + fingerprint.rs version_for_toml:
    # sorted-key compact JSON of {event_name label, matcher, hooks:[normalized handler]}, SHA-256.
    canonical = (
        '{"event_name":"pre_tool_use","hooks":[{"async":false,"command":"echo hi","timeout":600,'
        '"type":"command"}],"matcher":"Bash"}'
    )
    expected = "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()
    assert codex_command_hook_hash("PreToolUse", "Bash", {"type": "command", "command": "echo hi"}) == expected


def test_codex_hash_normalization() -> None:
    base = {"type": "command", "command": "x"}
    # UserPromptSubmit ignores matchers; default timeout is 600; default context limit is dropped.
    assert codex_command_hook_hash("UserPromptSubmit", "Bash", base) == codex_command_hook_hash(
        "UserPromptSubmit", None, {**base, "timeout": 600, "additionalContextLimit": 2500}
    )
    assert codex_command_hook_hash("PreToolUse", "A", base) != codex_command_hook_hash("PreToolUse", "B", base)
    assert codex_command_hook_hash("PreToolUse", None, {**base, "statusMessage": "m"}) != codex_command_hook_hash(
        "PreToolUse", None, base
    )


def _payload(trusted: str | None, config_path: Path) -> dict[str, object]:
    handler = {"type": "command", "command": GUARD_COMMAND, "timeout": 30}
    payload: dict[str, object] = {"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [handler]}]}}
    if trusted is not None:
        key = f"{config_path}:pre_tool_use:0:0"
        payload["hooks"]["state"] = {key: {"trusted_hash": trusted}}  # type: ignore[index]
    return payload


def test_stale_trust_detection(tmp_path: Path) -> None:
    config = tmp_path / "config.toml"
    handler = {"type": "command", "command": GUARD_COMMAND, "timeout": 30}
    good = codex_command_hook_hash("PreToolUse", "Bash", handler)
    assert stale_guard_hook_coordinates(_payload(good, config), config) == []
    assert stale_guard_hook_coordinates(_payload(None, config), config)
    assert stale_guard_hook_coordinates(_payload("sha256:" + "0" * 64, config), config)


def test_stale_trust_ignores_foreign_hooks(tmp_path: Path) -> None:
    config = tmp_path / "config.toml"
    payload = {"hooks": {"PreToolUse": [{"hooks": [{"type": "command", "command": "/usr/bin/other-tool"}]}]}}
    assert stale_guard_hook_coordinates(payload, config) == []


def test_doctor_warning_copy() -> None:
    warnings = codex_hook_doctor_warnings(
        {
            "config_present": True,
            "codex_hooks_enabled": True,
            "managed_hook_installed": True,
            "integrity_status": "valid",
            "hook_trust_stale": True,
        }
    )
    assert any("/hooks" in item and "press t" in item for item in warnings)


@pytest.mark.parametrize(
    ("body", "expect"),
    [
        ("providers:\n  openai-codex:\n    codeMode: auto\n", True),
        ("providers:\n  openai-codex:\n    codeMode: on\n", True),
        ("providers.openai-codex.codeMode: on\n", True),
        ("providers:\n  openai-codex:\n    codeMode: off\n", False),
        ("providers:\n  openai-codex:\n    other: 1\n", False),
        ("not: [valid\n", False),
        ("", False),
    ],
)
def test_omp_code_mode_warning(tmp_path: Path, body: str, expect: bool) -> None:
    config = tmp_path / "config.yml"
    config.write_text(body, encoding="utf-8")
    assert (omp_code_mode_warnings(config) == [OMP_CODE_MODE_WARNING]) is expect


def test_omp_code_mode_missing_file(tmp_path: Path) -> None:
    assert omp_code_mode_warnings(tmp_path / "nope.yml") == []


def test_omp_diagnostics_include_warning(tmp_path: Path) -> None:
    home = tmp_path / "home"
    (home / ".omp/agent").mkdir(parents=True)
    (home / ".omp/agent/config.yml").write_text("providers:\n  openai-codex:\n    codeMode: auto\n")
    context = HarnessContext(home_dir=home, workspace_dir=None, guard_home=tmp_path / "guard-home")
    payload = get_adapter("omp").diagnostics(context)
    assert OMP_CODE_MODE_WARNING in payload["warnings"]
