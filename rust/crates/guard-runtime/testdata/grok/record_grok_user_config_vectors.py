"""Record parity vectors for the native ``grok_user_config`` runner-authority kind.

The vectors pin the behavior of the tomlkit merge in
``guard/adapters/grok_user_config.py`` as it existed before the resident took it
over. Each case runs the original ``prepare_user_config_text`` or
``remove_user_config_settings`` and records the exact merged text, ownership
state or error. Install cases are chained: the merged text is removed,
reinstalled with and without its ownership state, and migrated to a new hook
command while the old one is reported missing. The Rust vectors test replays the
same requests against the op.

Run from a checkout of the base commit that still has the tomlkit merge:

    PYTHONPATH=src python \
        rust/crates/guard-runtime/testdata/grok/record_grok_user_config_vectors.py [OUTPUT]

It rewrites ``user_config_vectors.json`` next to this script by default.
"""

from __future__ import annotations

import inspect
import json
import sys
from pathlib import Path

import tomllib

import codex_plugin_scanner.guard.cli.grok_hook_validation as hook_validation
from codex_plugin_scanner.guard.adapters import grok_config, grok_user_config

_OUTPUT = Path(__file__).with_name("user_config_vectors.json")
_COMMAND = "/opt/hol-guard/bin/hol-guard hook --harness grok"
_NEXT_COMMAND = "/opt/hol-guard-next/bin/hol-guard hook --harness grok"
_ESCAPED_COMMAND = 'C:\\Program Files\\Guard\\guard.exe hook "grok" caf\u00e9 \u2603\t\x01'
_PERMISSION = "[permission]\n"
# Documents that also run the migrate and after-remove steps; the rest stop at reinstall.
_FULL_FLOW = frozenset(
    {
        "empty", "comment-blank", "root-kv-unterminated", "table", "tables", "crlf", "crlf-deny", "unicode",
        "permission-child", "deny-multiline", "deny-multiline-comment", "deny-managed-some", "deny-line-comment",
        "compat-true", "compat-both", "compat-parent", "compat-child", "hooks-aot", "hooks-inline",
        "hooks-inline-multiline", "hooks-table-aot", "hooks-owned-inline", "full", "root-then-sections",
        "inline-permission", "dotted-vendor", "implicit-permission",
    }
)  # fmt: skip
_MANAGED = list(grok_config.MANAGED_DENY_RULES)
_AOT_FOREIGN = (
    '[[hooks.PreToolUse]]\nmatcher = "Bash"\n\n[[hooks.PreToolUse.hooks]]\ntype = "command"\ncommand = "foo"\n'
)
_AOT_OWNED = f'[[hooks.PreToolUse]]\n[[hooks.PreToolUse.hooks]]\ntype = "command"\ncommand = "{_COMMAND}"\n'
_INLINE_FOREIGN = '[hooks]\nPreToolUse = [{matcher = "Bash", hooks = [{type = "command", command = "foo"}]}]\n'

# Documents the byte-exact engine reproduces.
_EXACT: dict[str, str] = {
    "empty": "",
    "newline": "\n",
    "comment": "# my config\n",
    "comment-blank": "# my config\n\n",
    "root-kv": 'model = "synthetic-model" # keep\n',
    "root-kv-unterminated": 'model = "synthetic-model"',
    "table": '[ui]\ntheme = "dark"\n',
    "table-blank": '[ui]\ntheme = "dark"\n\n',
    "table-unterminated": '[ui]\ntheme = "dark"',
    "tables": '[ui]\ntheme = "dark"\n\n[models]\nx = 1\n',
    "tail-comment": '[ui]\ntheme = "dark"\n# trailing\n',
    "unicode": '# caf\u00e9\nname = "h\u00e9llo \u2603"\n[ui]\ntheme = "\u00fcber"\n',
    "crlf": '[ui]\r\ntheme = "dark"\r\n',
    "crlf-deny": '[permission]\r\ndeny = [\r\n  "a",\r\n  "b",\r\n]\r\n',
    "indented-header": '  [ permission ]\n  deny = ["a"]\n',
    "quoted-header": '["permission"]\ndeny = ["a"]\n',
    "quoted-dotted-sibling": '[permission]\nmode = "ask"\n["permission.extra"]\nvalues = []\n',
    "quoted-dotted-only": '["permission.extra"]\nvalues = []\n',
    "quoted-bracket-key": '["a]b"]\nx = 1\n[permission]\ndeny = ["a"]\n',
    "quoted-key": '[permission]\n"deny" = ["a"]\n',
    "header-comment": "[permission] # hi\ndeny = []\n",
    "permission-mode": '[permission]\nmode = "ask"\n',
    "permission-empty": _PERMISSION,
    "permission-comment": "[permission]\n# only a comment\n",
    "permission-child": '[permission]\nmode = "ask"\n[permission.sub]\ny = 1\n',
    "permission-child-blank": '[permission]\nmode = "ask"\n\n[permission.sub]\ny = 1\n',
    "permission-child-super": '[permission]\nmode = "ask"\n[permission.sub.deep]\ny = 1\n',
    "deny-empty": "[permission]\ndeny = []\n",
    "deny-empty-comment": "[permission]\ndeny = [ # c\n]\n",
    "deny-one": '[permission]\ndeny = ["Bash(x)"]\n',
    "deny-trailing-comma": '[permission]\ndeny = ["Bash(x)",]\n',
    "deny-spaced": '[permission]\ndeny   =   [ "Bash(x)" , "Read(y)" ]\n',
    "deny-multiline": '[permission]\ndeny = [\n  "Bash(x)",\n  "Read(y)",\n]\n',
    "deny-multiline-bare": '[permission]\ndeny = [\n  "Bash(x)",\n  "Read(y)"\n]\n',
    "deny-multiline-comment": '[permission]\ndeny = [\n  "Bash(x)", # why\n  "Read(y)",\n]\n',
    "deny-multiline-blank": '[permission]\ndeny = [\n\n  "Bash(x)",\n\n  "Read(y)",\n\n]\n',
    "deny-literal-strings": "[permission]\ndeny = ['a', '''b''']\n",
    "deny-line-comment": '[permission]\ndeny = ["Bash(x)"] # trailing\nmode = "ask"\n',
    "deny-managed-some": f'[permission]\ndeny = ["{_MANAGED[0]}", "{_MANAGED[5]}"]\n',
    "deny-managed-all": "[permission]\ndeny = [" + ", ".join(json.dumps(rule) for rule in _MANAGED) + "]\n",
    "compat-true": "[compat.claude]\nhooks = true\n",
    "compat-false": "[compat.claude]\nhooks = false\n",
    "compat-missing": "[compat.claude]\nother = 1\n",
    "compat-comment": "[compat.cursor]\nhooks = true # why\n",
    "compat-empty": "[compat.claude]\n",
    "compat-both": "[compat.claude]\nhooks = true\n\n[compat.cursor]\nhooks = false\n",
    "compat-reversed": "[compat.cursor]\nhooks = false\n\n[compat.claude]\nhooks = true\n",
    "compat-parent": "[compat]\nx = 1\n",
    "compat-parent-vendor": "[compat]\nx = 1\n\n[compat.claude]\nhooks = true\n",
    "compat-child": "[compat.claude]\nother = 1\n[compat.claude.sub]\ny = 1\n[compat.cursor]\nz = 2\n",
    "hooks-aot": _AOT_FOREIGN,
    "hooks-inline": _INLINE_FOREIGN,
    "hooks-inline-empty": "[hooks]\nPreToolUse = []\n",
    "hooks-inline-multiline": (
        '[hooks]\nPreToolUse = [\n  {matcher = "Bash", hooks = [{type = "command", command = "foo"}]},\n]\n'
    ),
    "hooks-other": "[hooks]\nother = 1\n",
    "hooks-table-aot": "[hooks]\n" + _AOT_FOREIGN,
    "hooks-observe-aot": _AOT_FOREIGN.replace("PreToolUse", "SessionStart"),
    "hooks-matcher-empty": _AOT_OWNED.replace("[[hooks.PreToolUse]]\n", '[[hooks.PreToolUse]]\nmatcher = ""\n\n'),
    "hooks-owned-aot": _AOT_OWNED + "timeout = 90\n",
    "hooks-owned-inline": f'[hooks]\nPreToolUse = [{{hooks = [{{type = "command", command = "{_COMMAND}"}}]}}]\n',
    "hooks-stale-aot": _AOT_OWNED.replace(_COMMAND, _NEXT_COMMAND),
    "full": (
        '# top\nmodel = "x"\n\n[permission]\ndeny = ["a"]\n\n[compat.claude]\nhooks = true\n\n'
        "[hooks]\nPreToolUse = []\n"
    ),
    "root-then-sections": 'model = "x"\n\n# note\n\n[ui]\ntheme = "dark"\n\n' + _AOT_FOREIGN + "\n[models]\nx = 1\n",
}

# Layouts that live outside an explicit ``[table]`` section; the byte layout is
# tomlkit's, so replays assert the same TOML value rather than the same text.
_SEMANTIC: dict[str, str] = {
    "inline-permission": 'permission = {deny = ["a"]}\n',
    "inline-permission-empty": "permission = {}\n",
    "dotted-permission": 'permission.deny = ["a"]\n',
    "dotted-permission-mode": 'permission.mode = "ask"\n',
    "inline-vendor": "[compat]\nclaude = {hooks = true}\n",
    "inline-vendor-empty": "[compat]\nclaude = {}\n",
    "dotted-vendor": "[compat]\nclaude.hooks = true\n",
    "dotted-compat": "compat.claude.hooks = true\n",
    "dotted-hooks": "hooks.PreToolUse = []\n",
    "implicit-permission": "[permission.sub]\nx = 1\n",
    "quoted-dotted-part": '[permission."x.y"]\nz = 1\n',
    "implicit-vendor": "[compat.claude.sub]\nx = 1\n",
}

# Each rejected document names the exact message the original raised.
_ERRORS: dict[str, str] = {
    "permission-scalar": "permission = 1\n",
    "permission-array": "[[permission]]\nx = 1\n",
    "deny-scalar": '[permission]\ndeny = "invalid"\n',
    "deny-not-strings": "[permission]\ndeny = [1]\n",
    "compat-scalar": "compat = 1\n",
    "vendor-scalar": "[compat]\nclaude = 1\n",
    "vendor-hooks-string": '[compat.claude]\nhooks = "invalid"\n',
    "cursor-hooks-int": "[compat.claude]\nhooks = true\n[compat.cursor]\nhooks = 1\n",
    "hooks-scalar": "hooks = 1\n",
    "event-scalar": '[hooks]\nPreToolUse = "invalid"\n',
    "observe-event-scalar": "[hooks]\nSessionStart = 1\n",
    "invalid-toml": "[permission]\npermission=",
    "invalid-toml-header": "[permission\ndeny = []\n",
    "invalid-toml-bom": "\ufeff[ui]\nx = 1\n",
}


def _scenario(text: str, command: str, state: dict, missing: set[str]) -> tuple[list[str], tuple]:
    """Run the original merge once; return the commands it asked about and its outcome."""
    asked: list[str] = []

    def is_missing(candidate: str, _hook_command: str) -> bool:
        asked.append(candidate)
        return candidate in missing

    hook_validation.is_missing_grok_hook_command = is_missing
    try:
        outcome = ("ok", *grok_user_config.prepare_user_config_text(text, command, previous_state=state))
    except ValueError as error:
        outcome = ("error", str(error))
    return sorted(set(asked)), outcome


def _case(name: str, text: str, command: str, state: dict, missing: set[str], layout: str) -> dict | None:
    asked, outcome = _scenario(text, command, state, missing)
    case: dict = {
        "candidates": asked,
        "existing_text": text,
        "hook_command": command,
        "layout": layout,
        "missing": sorted(missing),
        "name": name,
        "op": "merge",
        "previous_state": state,
    }
    if outcome[0] == "ok":
        case["expect"] = {"merged": outcome[1], "state": outcome[2]}
        tomllib.loads(outcome[1])
        return case
    try:
        tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        case["expect"] = {"error": "invalid_toml"}
        return case
    if outcome[1].startswith("Grok "):
        case["expect"] = {"error": outcome[1]}
        return case
    return None


def _remove_case(name: str, text: str, state: dict, layout: str) -> dict:
    return {
        "existing_text": text,
        "layout": layout,
        "name": name,
        "op": "remove",
        "previous_state": state,
        "expect": {"text": grok_user_config.remove_user_config_settings(text, state)},
    }


def _flow(name: str, text: str, layout: str, cases: list[dict]) -> None:
    install = _case(f"{name}/install", text, _COMMAND, {}, set(), layout)
    if install is None or "merged" not in install["expect"]:
        raise SystemExit(f"{name}: install did not produce a merge")
    cases.append(install)
    merged, state = install["expect"]["merged"], install["expect"]["state"]
    cases.append(_remove_case(f"{name}/remove", merged, state, layout))
    steps = [("reinstall", merged, _COMMAND, state, set())]
    if name in _FULL_FLOW:
        steps += [
            ("reinstall-without-state", merged, _COMMAND, {}, set()),
            ("migrate", merged, _NEXT_COMMAND, state, {_COMMAND}),
            ("migrate-without-state", merged, _NEXT_COMMAND, {}, {_COMMAND}),
            ("migrate-keep", merged, _NEXT_COMMAND, {}, set()),
        ]
    for step, existing, command, prior, missing in steps:
        case = _case(f"{name}/{step}", existing, command, prior, missing, layout)
        if case is None:
            raise SystemExit(f"{name}/{step}: unexpected original failure")
        cases.append(case)
    if name in _FULL_FLOW:
        removed = grok_user_config.remove_user_config_settings(merged, state)
        after = _case(f"{name}/after-remove", removed, _COMMAND, {}, set(), layout)
        if after is not None:
            cases.append(after)


def main() -> None:
    source = inspect.getsource(grok_user_config.prepare_user_config_text)
    if "tomlkit.parse" not in source:
        raise SystemExit("run this against the base commit that still has the tomlkit merge")
    cases: list[dict] = []
    for name, text in _EXACT.items():
        _flow(name, text, "exact", cases)
    for name, text in _SEMANTIC.items():
        _flow(name, text, "semantic", cases)
    escaped = _case("escaped-command/install", "", _ESCAPED_COMMAND, {}, set(), "exact")
    if escaped is not None:
        cases.append(escaped)
    for name, text in _ERRORS.items():
        case = _case(f"error/{name}", text, _COMMAND, {}, set(), "exact")
        if case is None or "error" not in case["expect"]:
            raise SystemExit(f"{name}: expected a rejection")
        cases.append(case)
    cases.append(
        _remove_case("remove/unknown-state", _EXACT["full"], {"created_keys": ["ui", 3], "hook_command": 7}, "exact")
    )
    state = _case("seed", _EXACT["compat-true"], _COMMAND, {}, set(), "exact")["expect"]["state"]  # type: ignore[index]
    cases.append(_remove_case("remove/foreign-text", _EXACT["table"], state, "exact"))
    document = {
        "cases": cases,
        "constants": {
            "compat_vendors": list(grok_config.FOREIGN_HOOK_COMPAT_VENDORS),
            "managed_deny_rules": _MANAGED,
            "observe_events": list(grok_config.OBSERVE_HOOK_EVENTS),
            "observe_timeout": 15,
            "pretool_timeout": grok_config.GROK_PRETOOL_HOOK_TIMEOUT_SECONDS,
        },
        "schema": "guard-grok-user-config-vectors.v1",
    }
    output = Path(sys.argv[1]) if len(sys.argv) > 1 else _OUTPUT
    output.write_text(json.dumps(document, ensure_ascii=False, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    print(f"recorded {len(cases)} cases to {output}")


if __name__ == "__main__":
    main()
