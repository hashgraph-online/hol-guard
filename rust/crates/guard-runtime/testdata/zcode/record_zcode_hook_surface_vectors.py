#!/usr/bin/env python3
"""Record ZCode hook-surface vectors from the ORIGINAL Python implementation.

Run against a checkout that still holds `ZCodeHarnessAdapter`'s
`_sync_managed_hook_groups` (the base of the commit that introduced the native
`zcode_hook_settings` runner-authority kind), never from Rust output:

    PYTHONPATH=$PWD/src python3 <this-file> <output vectors.json>

Each case drives the real `prepare_install` or `uninstall` over one fake ZCode
home and records, per hook surface (`config.json`, then the CLI's
`setting.json`), the request the native kind receives and what the original
Python did: the whole file text it wrote (or `null` when it wrote nothing),
the pre-install `enabled` record it saved, or the refusal it raised.
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

from codex_plugin_scanner.guard.adapters import zcode
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.zcode import ZCodeHarnessAdapter
from codex_plugin_scanner.guard.adapters.zcode_config import GUARD_MANAGED_MARKER, ZCODE_PRETOOL_MATCHERS

if not hasattr(ZCodeHarnessAdapter, "_sync_managed_hook_groups"):
    sys.exit("refusing to record: the original Python ZCode hook settings are gone")

FAKE_HOME = "/home/user"
COMMAND = "guard-hook-bridge --harness zcode"
GUARD = f"{COMMAND} # {GUARD_MANAGED_MARKER}"
STALE = f"old-guard-hook --harness zcode # {GUARD_MANAGED_MARKER}"
TIMEOUTS = {"PreToolUse": 30, "UserPromptSubmit": 30}
CONFIG = "@HOME@/.zcode/cli/config.json"
SETTING = "@HOME@/.zcode/cli/setting.json"


def entry(command: str, matcher: object = None) -> dict[str, object]:
    value: dict[str, object] = {}
    if matcher is not None:
        value["matcher"] = matcher
    value["hooks"] = [{"type": "command", "command": command}]
    return value


def text(value: object) -> str:
    return json.dumps(value, indent=2, ensure_ascii=False)


USER_EVENTS = {"Stop": [entry("echo stop")], "PreToolUse": [entry("echo read", "Read")]}
GUARDED = {
    "enabled": True,
    "events": {
        "PreToolUse": [entry(STALE, "Bash"), entry("echo read", "Read")],
        "UserPromptSubmit": [entry(STALE)],
        "Stop": [entry("echo stop")],
    },
}
ONLY_GUARD = {"enabled": True, "events": {"PreToolUse": [entry(STALE, "Bash")]}}
ODD_VALUES = (
    '{"theme": "caf\\u00e9 über \U0001f600", "bell": "\\u0007\\u007f\u007f", '
    '"numbers": [1.5, 1e20, 1E400, -1E400, -0.0, 1.0e5, 0.00001, 1e16, '
    "123456789012345678901234567890, -0, 10.0, NaN], "
    '"dup": {"a": 1, "b": 2, "a": 3}, "nested": {"x": [[], {}, [{}]]}, '
    '"mcp": {"servers": {"s": {"command": "srv", "args": ["--x"]}}}, '
    '"hooks": {"events": {"Stop": [{"hooks": [{"command": "echo \\u2603"}]}]}}}'
)

# name -> (config text or None, setting text or None, state or None)
INSTALL: dict[str, tuple[str | None, str | None, object]] = {
    "absent_config": (None, None, None),
    "empty_config": ("{}", None, None),
    "empty_config_and_setting": ("{}", "{}", None),
    "non_object_sections_replaced_in_place": (
        '{"mcp": [], "theme": "dark", "plugins": null, "hooks": []}',
        None,
        None,
    ),
    "user_order_kept": (
        text({"plugins": {"p": True}, "theme": "dark", "mcp": {}, "hooks": {"enabled": True, "events": USER_EVENTS}}),
        None,
        None,
    ),
    "hooks_before_sections": (text({"hooks": {"events": USER_EVENTS}, "zeta": 1}), None, None),
    "odd_values_render_like_python": (ODD_VALUES, ODD_VALUES, None),
    "compact_text": ('{"hooks":{"enabled":true},"mcp":{}}', '{"hooks":{"enabled":true}}', None),
    "duplicate_hooks_key": ('{"hooks": [], "x": 1, "hooks": {"enabled": true}}', None, None),
    "invalid_config": ("{not json", None, None),
    "empty_text_config": ("", None, None),
    "bom_config": ("﻿{}", None, None),
    "array_config": ("[]", None, None),
    "null_config": ("null", None, None),
    "string_config": ('"text"', None, None),
    "disabled_with_handlers": (text({"hooks": {"enabled": False, "events": USER_EVENTS}}), None, None),
    "disabled_without_handlers": (text({"hooks": {"enabled": False, "events": {}}}), None, None),
    "disabled_number_with_handlers": (text({"hooks": {"enabled": 0, "events": USER_EVENTS}}), None, None),
    "setting_invalid": ("{}", "{oops", None),
    "setting_array": ("{}", "[1]", None),
    "setting_disabled_with_handlers": (
        "{}",
        text({"hooks": {"enabled": False, "Stop": [entry("echo stop")]}}),
        None,
    ),
    "setting_not_normalized": ("{}", text({"mcp": [], "hooks": {"events": {}}}), None),
    "legacy_flat_groups_fold": (
        text(
            {
                "hooks": {
                    "PreToolUse": [entry(STALE, "Bash"), entry("echo legacy", "Bash")],
                    "Stop": [entry("echo stop")],
                    "custom": [1],
                    "events": {"Stop": [entry("echo stop")], "Notification": [entry("echo n")]},
                }
            }
        ),
        text({"hooks": {"UserPromptSubmit": [entry(STALE)], "enabled": True}}),
        None,
    ),
    "reinstall_saved_record": (
        text({"mcp": {}, "plugins": {}, "hooks": GUARDED}),
        text({"hooks": GUARDED}),
        {
            "managed_config_path": CONFIG,
            "hooks_enabled_before": {
                CONFIG: {"present": True, "value": False},
                SETTING: {"present": False, "value": None},
            },
        },
    ),
    "reinstall_legacy_state_record": (
        text({"hooks": GUARDED}),
        text({"hooks": GUARDED}),
        {"managed_config_path": CONFIG, "hooks_enabled_before": {"present": True, "value": False}},
    ),
    "saved_record_ignored_without_guard_entries": (
        text({"hooks": {"enabled": True, "events": USER_EVENTS}}),
        None,
        {"managed_config_path": CONFIG, "hooks_enabled_before": {CONFIG: {"present": True, "value": False}}},
    ),
    "invalid_saved_record_uses_live_flag": (
        text({"hooks": GUARDED}),
        None,
        {"managed_config_path": CONFIG, "hooks_enabled_before": {CONFIG: {"present": True, "value": "no"}}},
    ),
    "live_flag_odd_value": (text({"hooks": {"enabled": "yes", "events": {}}}), None, None),
    "live_flag_absent": (text({"hooks": {"events": USER_EVENTS}}), None, None),
    "pretool_matchers_merge": (
        text(
            {
                "hooks": {
                    "events": {
                        "PreToolUse": [
                            {"matcher": " Bash ", "hooks": [{"command": "echo mine"}, {"command": STALE}]},
                            "not an entry",
                        ]
                    }
                }
            }
        ),
        None,
        None,
    ),
}

# name -> (config text or None, setting text or None, state or None)
UNINSTALL: dict[str, tuple[str | None, str | None, object]] = {
    "prunes_and_drops_live_true": (text({"mcp": {}, "hooks": GUARDED}), None, None),
    "only_guard_removes_hooks": (text({"plugins": {}, "hooks": ONLY_GUARD, "z": 1}), None, None),
    "saved_absent_pops_enabled": (
        text({"hooks": ONLY_GUARD}),
        text({"hooks": GUARDED}),
        {
            "managed_config_path": CONFIG,
            "hooks_enabled_before": {
                CONFIG: {"present": False, "value": None},
                SETTING: {"present": False, "value": None},
            },
        },
    ),
    "saved_false_restored": (
        text({"hooks": GUARDED}),
        text({"hooks": GUARDED}),
        {
            "managed_config_path": CONFIG,
            "hooks_enabled_before": {
                CONFIG: {"present": True, "value": False},
                SETTING: {"present": True, "value": True},
            },
        },
    ),
    "legacy_state_record": (
        text({"hooks": GUARDED}),
        text({"hooks": GUARDED}),
        {"managed_config_path": CONFIG, "hooks_enabled_before": {"present": True, "value": False}},
    ),
    "no_hooks_key": (text({"mcp": {}}), None, None),
    "hooks_not_object": (text({"hooks": [entry(STALE)]}), None, None),
    "invalid_json": ("{nope", "[]", None),
    "no_guard_entries_unchanged": (text({"hooks": {"enabled": True, "events": USER_EVENTS}}), None, None),
    "empty_events_dropped": (text({"hooks": {"events": {}, "enabled": False}}), None, None),
    "legacy_flat_groups": (
        text({"hooks": {"PreToolUse": [entry(STALE, "Bash")], "Stop": [entry("echo stop"), entry(STALE)]}}),
        None,
        None,
    ),
    "odd_values_render_like_python": (
        ODD_VALUES.replace('"echo \\u2603"', json.dumps(STALE)),
        ODD_VALUES,
        None,
    ),
    "duplicate_hooks_key": (
        '{"hooks": {"enabled": true}, "x": 1, "hooks": ' + json.dumps(ONLY_GUARD) + "}",
        None,
        None,
    ),
}


def fake(value: object, home: Path) -> object:
    """The value with this run's temporary home spelled as the fake one."""

    return json.loads(json.dumps(value).replace(str(home), FAKE_HOME))


def real(value: object, home: Path) -> object:
    return json.loads(json.dumps(value).replace("@HOME@", str(home)))


def setup(root: Path, config: str | None, setting: str | None, state: object) -> HarnessContext:
    home = root / "home"
    cli = home / ".zcode" / "cli"
    cli.mkdir(parents=True)
    if config is not None:
        (cli / "config.json").write_text(config, encoding="utf-8")
    if setting is not None:
        (cli / "setting.json").write_text(setting, encoding="utf-8")
    context = HarnessContext(home_dir=home, workspace_dir=None, guard_home=root / "guard-home")
    if state is not None:
        state_dir = context.guard_home / "managed" / "zcode"
        state_dir.mkdir(parents=True)
        (state_dir / "install.state.json").write_text(json.dumps(real(state, home)), encoding="utf-8")
    return context


def surfaces(context: HarnessContext) -> list[tuple[str, Path]]:
    cli = context.home_dir / ".zcode" / "cli"
    return [("config.json", cli / "config.json"), ("setting.json", cli / "setting.json")]


def base_request(op: str, path: Path, text_value: str | None, state: object, home: Path) -> dict[str, object]:
    saved = state if isinstance(state, dict) else {}
    return {
        "op": op,
        "text": text_value,
        "path": fake(str(path), home),
        "history": fake(real(saved.get("hooks_enabled_before"), home), home),
        "managed_config_path": fake(real(saved.get("managed_config_path"), home), home),
    }


def record_install(name: str, config: str | None, setting: str | None, state: object) -> list[dict[str, object]]:
    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw).resolve()
        context = setup(root, config, setting, state)
        home = context.home_dir
        error: str | None = None
        files: dict[str, bytes] = {}
        history: dict[str, object] = {}
        try:
            prepared = ZCodeHarnessAdapter().prepare_install(context)
        except ValueError as raised:
            error = str(raised)
        else:
            files = {str(change.path): change.after for change in prepared.files if change.after is not None}
            state_text = files[str((context.guard_home / "managed" / "zcode" / "install.state.json").resolve())]
            history = json.loads(state_text)["hooks_enabled_before"]
        cases = []
        for label, path in surfaces(context):
            text_value = config if label == "config.json" else setting
            if label == "setting.json" and text_value is None:
                continue
            request = base_request("install", path, text_value, state, home)
            request.update(
                desktop=label == "config.json",
                matchers=list(ZCODE_PRETOOL_MATCHERS),
                command=COMMAND,
                timeouts=dict(TIMEOUTS),
            )
            if error is not None:
                if label not in error:
                    continue
                refusal = "hooks_disabled" if "disabled" in error else "not_object"
                expected: dict[str, object] = {"refusal": refusal}
            else:
                after = files[str(path.resolve())].decode("utf-8")
                expected = {"text": after, "enabled": history[str(path)]}
            cases.append({"name": f"install/{name}/{label}", "request": request, "expected": expected})
        if error is not None and not cases:
            raise SystemExit(f"{name}: unattributed refusal {error!r}")
        return cases


def record_uninstall(name: str, config: str | None, setting: str | None, state: object) -> list[dict[str, object]]:
    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw).resolve()
        context = setup(root, config, setting, state)
        home = context.home_dir
        writes: dict[str, str] = {}
        zcode.write_text_at_authorized_path = lambda path, value: writes.__setitem__(str(path), value)
        ZCodeHarnessAdapter().uninstall(context)
        cases = []
        for label, path in reversed(surfaces(context)):
            text_value = config if label == "config.json" else setting
            if text_value is None:
                continue
            request = base_request("uninstall", path, text_value, state, home)
            expected = {"text": writes.get(str(path))}
            cases.append({"name": f"uninstall/{name}/{label}", "request": request, "expected": expected})
        return cases


def main() -> None:
    if len(sys.argv) != 2:
        sys.exit("usage: record_zcode_hook_surface_vectors.py <output vectors.json>")
    zcode.prepare_guard_shim = lambda *_args, **_kwargs: SimpleNamespace(manifest={}, files=())
    zcode.remove_guard_shim = lambda *_args, **_kwargs: {}
    ZCodeHarnessAdapter._hook_command_parts = staticmethod(  # pyright: ignore[reportAttributeAccessIssue]
        lambda *_args, **_kwargs: tuple(COMMAND.split())
    )
    cases: list[dict[str, object]] = []
    for name, (config, setting, state) in INSTALL.items():
        cases.extend(record_install(name, config, setting, state))
    for name, (config, setting, state) in UNINSTALL.items():
        cases.extend(record_uninstall(name, config, setting, state))
    vectors = {"schema": "hol-guard-zcode-hook-surface-vectors.v1", "cases": cases}
    Path(sys.argv[1]).write_text(json.dumps(vectors, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"recorded {len(cases)} cases")


if __name__ == "__main__":
    main()
