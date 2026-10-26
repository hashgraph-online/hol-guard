"""Install has to leave Codex trusting the hooks it just wrote.

Codex runs a user-layer hook only when ``[hooks.state]`` holds a matching
trusted hash, and skips it in silence otherwise. A Windows tester saw exactly
that: four Guard hooks in ``config.toml``, zero receipts, and no warning from
Codex. These tests pin the recorder to Guard's own handlers and to the hash
Codex itself computes.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import tomllib

from codex_plugin_scanner.guard.codex_config import dump_toml
from codex_plugin_scanner.guard.codex_hook_trust import (
    codex_command_hook_hash,
    record_guard_hook_trust,
    remap_hook_state,
    stale_guard_hook_coordinates,
)

GUARD_COMMAND = "/opt/guard/1.2.3/hol-guard-codex-hook --harness codex"
FOREIGN_COMMAND = "/usr/bin/other-tool"


def _guard_handler() -> dict[str, Any]:
    return {"type": "command", "command": GUARD_COMMAND, "timeout": 30}


def _payload(*, foreign: bool = False) -> dict[str, Any]:
    handlers: list[dict[str, object]] = [_guard_handler()]
    if foreign:
        handlers.append({"type": "command", "command": FOREIGN_COMMAND})
    return {
        "hooks": {
            "PreToolUse": [{"matcher": "Bash", "hooks": handlers}],
            "UserPromptSubmit": [{"hooks": [_guard_handler()]}],
        }
    }


def _state(payload: dict[str, Any]) -> dict[str, Any]:
    return payload["hooks"]["state"]


def test_recording_trust_leaves_no_hook_for_codex_to_skip(tmp_path: Path) -> None:
    config = tmp_path / "config.toml"
    payload = _payload()
    assert stale_guard_hook_coordinates(payload, config)

    recorded = record_guard_hook_trust(payload, config)

    assert len(recorded) == 2
    assert stale_guard_hook_coordinates(payload, config) == []


def test_the_recorded_hash_is_the_one_codex_computes(tmp_path: Path) -> None:
    config = tmp_path / "config.toml"
    payload = _payload()

    record_guard_hook_trust(payload, config)

    expected = codex_command_hook_hash("PreToolUse", "Bash", _guard_handler())
    assert [entry["trusted_hash"] for entry in _state(payload).values()] == [
        expected,
        codex_command_hook_hash("UserPromptSubmit", None, _guard_handler()),
    ]


def test_another_tools_hook_is_left_untrusted(tmp_path: Path) -> None:
    config = tmp_path / "config.toml"
    payload = _payload(foreign=True)

    record_guard_hook_trust(payload, config)

    assert not any(key.endswith(":pre_tool_use:0:1") for key in _state(payload))


def test_a_handler_the_user_switched_off_stays_switched_off(tmp_path: Path) -> None:
    config = tmp_path / "config.toml"
    payload = _payload()
    key = f"{config.resolve()}:pre_tool_use:0:0"
    payload["hooks"]["state"] = {key: {"enabled": False}}

    recorded = record_guard_hook_trust(payload, config)

    assert key not in recorded
    assert _state(payload)[key] == {"enabled": False}


def test_recording_keeps_the_rest_of_an_existing_state_entry(tmp_path: Path) -> None:
    config = tmp_path / "config.toml"
    payload = _payload()
    key = f"{config.resolve()}:pre_tool_use:0:0"
    payload["hooks"]["state"] = {key: {"enabled": True, "trusted_hash": "sha256:" + "0" * 64}}

    record_guard_hook_trust(payload, config)

    entry = _state(payload)[key]
    assert entry["enabled"] is True
    assert entry["trusted_hash"] == codex_command_hook_hash("PreToolUse", "Bash", _guard_handler())


def test_recording_twice_changes_nothing_the_second_time(tmp_path: Path) -> None:
    config = tmp_path / "config.toml"
    payload = _payload()
    record_guard_hook_trust(payload, config)
    before = dict(_state(payload))

    assert record_guard_hook_trust(payload, config) == []
    assert _state(payload) == before


def test_foreign_hook_state_is_never_rewritten(tmp_path: Path) -> None:
    config = tmp_path / "config.toml"
    payload = _payload(foreign=True)
    foreign_key = f"{config.resolve()}:pre_tool_use:0:1"
    payload["hooks"]["state"] = {foreign_key: {"trusted_hash": "sha256:" + "a" * 64}}

    record_guard_hook_trust(payload, config)

    assert _state(payload)[foreign_key] == {"trusted_hash": "sha256:" + "a" * 64}


def test_a_payload_without_hooks_records_nothing(tmp_path: Path) -> None:
    payload: dict[str, Any] = {"features": {"hooks": True}}

    assert record_guard_hook_trust(payload, tmp_path / "config.toml") == []
    assert "hooks" not in payload


def test_the_recorded_trust_survives_the_config_file_round_trip(tmp_path: Path) -> None:
    """The state key holds a path and colons, so it has to be written quoted."""

    config = tmp_path / "config.toml"
    payload = _payload()
    record_guard_hook_trust(payload, config)

    config.write_text(dump_toml(payload), encoding="utf-8")
    reloaded = tomllib.loads(config.read_text(encoding="utf-8"))

    assert stale_guard_hook_coordinates(reloaded, config) == []


def test_a_hash_under_the_symlink_alias_still_writes_the_canonical_key(tmp_path: Path) -> None:
    """Codex reads trust under the canonical path and nowhere else.

    A config reached through a symlink gives the recorder two aliases for the
    same hook. Accepting a match under the alias while leaving the canonical
    key absent left the hook untrusted, so Codex skipped it in silence.
    """

    real = tmp_path / "real"
    real.mkdir()
    config_file = real / "config.toml"
    config_file.touch()
    link = tmp_path / "link"
    link.symlink_to(real)
    config = link / "config.toml"
    payload = _payload()
    expected = codex_command_hook_hash("PreToolUse", "Bash", _guard_handler())
    alias = f"{config}:pre_tool_use:0:0"
    payload["hooks"]["state"] = {alias: {"trusted_hash": expected}}

    record_guard_hook_trust(payload, config)

    canonical = f"{config.resolve()}:pre_tool_use:0:0"
    assert canonical != alias
    assert _state(payload)[canonical]["trusted_hash"] == expected
    assert stale_guard_hook_coordinates(payload, config) == []


def test_state_follows_a_hook_that_the_install_moved(tmp_path: Path) -> None:
    """Reinstall appends Guard's groups after the ones it leaves alone.

    The foreign group that used to sit at index 0 is now at index 1, and the
    disabled choice its owner made must move with it rather than stay on the
    key a Guard handler has just taken.
    """

    config = tmp_path / "config.toml"
    foreign = {"matcher": "Bash", "hooks": [{"type": "command", "command": FOREIGN_COMMAND, "timeout": 30}]}
    guard = {"matcher": "Bash", "hooks": [_guard_handler()]}
    before = {"PreToolUse": [foreign]}
    hooks: dict[str, Any] = {
        "PreToolUse": [guard, foreign],
        "state": {f"{config.resolve()}:pre_tool_use:0:0": {"enabled": False}},
    }

    remap_hook_state(before, hooks, config)

    assert hooks["state"] == {f"{config.resolve()}:pre_tool_use:1:0": {"enabled": False}}

    payload = {"hooks": hooks}
    recorded = record_guard_hook_trust(payload, config)

    assert recorded == [f"{config.resolve()}:pre_tool_use:0:0"]
    assert stale_guard_hook_coordinates(payload, config) == []


def test_state_for_a_hook_the_install_removed_is_dropped(tmp_path: Path) -> None:
    config = tmp_path / "config.toml"
    gone = {"matcher": "Bash", "hooks": [{"type": "command", "command": FOREIGN_COMMAND, "timeout": 30}]}
    hooks: dict[str, Any] = {
        "PreToolUse": [{"matcher": "Bash", "hooks": [_guard_handler()]}],
        "state": {f"{config.resolve()}:pre_tool_use:0:0": {"enabled": False}},
    }

    remap_hook_state({"PreToolUse": [gone]}, hooks, config)

    assert hooks["state"] == {}


def test_state_that_names_no_known_handler_is_left_alone(tmp_path: Path) -> None:
    config = tmp_path / "config.toml"
    other = f"{tmp_path / 'elsewhere.toml'}:pre_tool_use:0:0"
    hooks: dict[str, Any] = {
        "PreToolUse": [{"matcher": "Bash", "hooks": [_guard_handler()]}],
        "state": {other: {"enabled": False}},
    }

    remap_hook_state({"PreToolUse": [{"matcher": "Bash", "hooks": [_guard_handler()]}]}, hooks, config)

    assert hooks["state"] == {other: {"enabled": False}}


def test_an_upgrade_keeps_a_guard_hook_the_user_switched_off(tmp_path: Path) -> None:
    """An upgrade rewrites Guard's own handler, so its hash never matches.

    The command path carries the version, and the hash is built from it, so
    nothing in the new config hashes to what the old state knew. Dropping the
    entry would let ``record_guard_hook_trust`` trust the hook as if it were
    newly installed and switch a hook the user turned off back on.
    """

    config = tmp_path / "config.toml"
    upgraded = {"type": "command", "command": "/opt/guard/1.3.0/hol-guard-codex-hook --harness codex", "timeout": 30}
    before = {"PreToolUse": [{"matcher": "Bash", "hooks": [_guard_handler()]}]}
    hooks: dict[str, Any] = {
        "PreToolUse": [{"matcher": "Bash", "hooks": [upgraded]}],
        "state": {f"{config.resolve()}:pre_tool_use:0:0": {"enabled": False, "trusted_hash": "stale"}},
    }

    remap_hook_state(before, hooks, config)

    # The stale trust goes; the user's choice stays.
    assert hooks["state"] == {f"{config.resolve()}:pre_tool_use:0:0": {"enabled": False}}

    payload = {"hooks": hooks}
    assert record_guard_hook_trust(payload, config) == []
    assert _state(payload)[f"{config.resolve()}:pre_tool_use:0:0"] == {"enabled": False}


def test_an_upgrade_that_leaves_two_guard_hooks_on_one_event_drops_the_state(tmp_path: Path) -> None:
    """Only an unambiguous replacement may carry the choice."""

    config = tmp_path / "config.toml"
    upgraded = {"type": "command", "command": "/opt/guard/1.3.0/hol-guard-codex-hook --harness codex", "timeout": 30}
    before = {"PreToolUse": [{"matcher": "Bash", "hooks": [_guard_handler()]}]}
    hooks: dict[str, Any] = {
        "PreToolUse": [{"matcher": "Bash", "hooks": [upgraded]}, {"matcher": "Write", "hooks": [upgraded]}],
        "state": {f"{config.resolve()}:pre_tool_use:0:0": {"enabled": False}},
    }

    remap_hook_state(before, hooks, config)

    assert hooks["state"] == {}
