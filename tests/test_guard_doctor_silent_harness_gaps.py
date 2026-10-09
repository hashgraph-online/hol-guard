from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters import get_adapter
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.omp_code_mode import OMP_CODE_MODE_WARNING, omp_code_mode_warnings
from codex_plugin_scanner.guard.codex_hook_trust import (
    CODEX_HOOK_TRUST_WARNING,
    apply_codex_hook_trust_doctor,
    codex_command_hook_hash,
    stale_guard_hook_coordinates,
)

GUARD_COMMAND = "/opt/guard/1.2.3/hol-guard-codex-hook --harness codex"


# Known answers reported by Codex 0.162.0 itself (`codex app-server` hooks/list currentHash)
# for these exact config.toml handlers; they are not derived from Guard's port.
@pytest.mark.parametrize(
    ("event_name", "matcher", "handler", "codex_hash"),
    [
        (
            "PreToolUse",
            "Bash",
            {"type": "command", "command": "echo hi"},
            "sha256:3bbce6504b48cc6f0d7fe24bd36273633d1bfa5879bc87f4ed7ccd16f24d1415",
        ),
        (
            "PreToolUse",
            "Bash",
            {"type": "command", "command": GUARD_COMMAND, "timeout": 30, "statusMessage": "Guard"},
            "sha256:103ed76439033dc93efebe0002e731e92827d95021d4105ac98311de0d533a00",
        ),
        (
            "UserPromptSubmit",
            None,
            {"type": "command", "command": "echo prompt", "additionalContextLimit": 4000},
            "sha256:6253537142a4ded7ac5f2b96d167c3e75cada8f5e4853172233c541575bb1173",
        ),
    ],
)
def test_codex_hash_known_answer(
    event_name: str, matcher: str | None, handler: dict[str, object], codex_hash: str
) -> None:
    assert codex_command_hook_hash(event_name, matcher, handler) == codex_hash


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


def test_stale_trust_skips_disabled_handlers(tmp_path: Path) -> None:
    config = tmp_path / "config.toml"
    handler = {"type": "command", "command": GUARD_COMMAND, "timeout": 30}
    disabled_group = {"hooks": {"PreToolUse": [{"matcher": "Bash", "enabled": False, "hooks": [handler]}]}}
    disabled_handler = {"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{**handler, "disabled": True}]}]}}
    switched_off = _payload(None, config)
    switched_off["hooks"]["state"] = {f"{config}:pre_tool_use:0:0": {"enabled": False}}  # type: ignore[index]
    for payload in (disabled_group, disabled_handler, switched_off):
        assert stale_guard_hook_coordinates(payload, config) == []


def test_stale_trust_accepts_canonical_config_path(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    (tmp_path / "link").symlink_to(real)
    config = tmp_path / "link" / "config.toml"
    handler = {"type": "command", "command": GUARD_COMMAND, "timeout": 30}
    good = codex_command_hook_hash("PreToolUse", "Bash", handler)
    payload = _payload(None, config)
    payload["hooks"]["state"] = {f"{real / 'config.toml'}:pre_tool_use:0:0": {"trusted_hash": good}}  # type: ignore[index]
    assert stale_guard_hook_coordinates(payload, config) == []


@pytest.mark.parametrize(("stale", "status"), [(True, "partial"), (False, "active")])
def test_doctor_does_not_report_untrusted_hooks_active(stale: bool, status: str) -> None:
    payload: dict[str, object] = {"warnings": ["existing"], "setup_status": "active"}
    apply_codex_hook_trust_doctor(payload, {"hook_trust_stale": stale})
    assert payload["setup_status"] == status
    assert (CODEX_HOOK_TRUST_WARNING in payload["warnings"]) is stale  # type: ignore[operator]
    assert "/hooks" in CODEX_HOOK_TRUST_WARNING and "press t" in CODEX_HOOK_TRUST_WARNING


def test_doctor_keeps_broken_status_when_trust_is_stale() -> None:
    payload: dict[str, object] = {"warnings": [], "setup_status": "broken"}
    apply_codex_hook_trust_doctor(payload, {"hook_trust_stale": True})
    assert payload["setup_status"] == "broken"


_AUTO = "providers:\n  openai-codex:\n    codeMode: auto\n"
_OFF = "providers:\n  openai-codex:\n    codeMode: off\n"


@pytest.mark.parametrize(
    ("body", "expect"),
    [
        (_AUTO, True),
        ("providers:\n  openai-codex:\n    codeMode: on\n", True),
        ("providers.openai-codex.codeMode: on\n", True),
        (_OFF, False),
        ("providers:\n  openai-codex:\n    other: 1\n", False),
        ("not: [valid\n", False),
        ("", False),
    ],
)
def test_omp_code_mode_warning(tmp_path: Path, body: str, expect: bool) -> None:
    config = tmp_path / ".omp/agent/config.yml"
    config.parent.mkdir(parents=True)
    config.write_text(body, encoding="utf-8")
    assert (omp_code_mode_warnings(tmp_path, environ={}) == [OMP_CODE_MODE_WARNING.format(path=config)]) is expect


def test_omp_code_mode_missing_file(tmp_path: Path) -> None:
    assert omp_code_mode_warnings(tmp_path, environ={}) == []


def _write(path: Path, body: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    return path


def test_omp_code_mode_reads_effective_layers(tmp_path: Path) -> None:
    home = tmp_path / "home"
    workspace = tmp_path / "workspace"
    yaml_config = _write(home / ".omp/agent/config.yaml", _AUTO)
    assert omp_code_mode_warnings(home, environ={}) == [OMP_CODE_MODE_WARNING.format(path=yaml_config)]
    _write(home / ".omp/agent/config.yml", _OFF)
    assert omp_code_mode_warnings(home, environ={}) == []
    project = _write(workspace / ".omp/config.yml", _AUTO)
    assert omp_code_mode_warnings(home, workspace, environ={}) == [OMP_CODE_MODE_WARNING.format(path=project)]
    _write(workspace / ".omp/config.yml", _OFF)
    _write(home / ".omp/agent/config.yml", _AUTO)
    assert omp_code_mode_warnings(home, workspace, environ={}) == []


def test_omp_code_mode_honors_agent_dir_environment(tmp_path: Path) -> None:
    home = tmp_path / "home"
    custom = _write(tmp_path / "agent/config.yml", _AUTO)
    assert omp_code_mode_warnings(home, environ={"PI_CODING_AGENT_DIR": str(custom.parent)}) == [
        OMP_CODE_MODE_WARNING.format(path=custom)
    ]
    renamed = _write(home / ".pi-alt/agent/config.yml", _AUTO)
    assert omp_code_mode_warnings(home, environ={"PI_CONFIG_DIR": ".pi-alt"}) == [
        OMP_CODE_MODE_WARNING.format(path=renamed)
    ]


def test_omp_diagnostics_include_warning(tmp_path: Path) -> None:
    home = tmp_path / "home"
    config = _write(home / ".omp/agent/config.yml", _AUTO)
    context = HarnessContext(
        home_dir=home, workspace_dir=None, guard_home=tmp_path / "guard-home", home_override_explicit=True
    )
    payload = get_adapter("omp").diagnostics(context)
    assert OMP_CODE_MODE_WARNING.format(path=config) in payload["warnings"]
