"""Record parity vectors for the native ``kimi_hook_config`` runner-authority kind.

The vectors pin the managed hooks block of ``guard/adapters/kimi.py`` as it
existed before the resident took it over: ``_build_managed_block``,
``_toml_escape``, ``_remove_managed_block`` and the text that
``prepare_install`` and ``uninstall`` wrote to ``~/.kimi-code/config.toml``.
Each case stores the request the Python shim sends and the exact text the
original code produced.

Run from a checkout of the base commit that still has the Python edits:

    PYTHONPATH=src python \
        rust/crates/guard-runtime/testdata/kimi/record_kimi_hook_config_vectors.py [OUTPUT]

It rewrites ``hook_config_vectors.json`` next to this script by default.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from codex_plugin_scanner.guard.adapters.kimi import (  # pyright: ignore[reportAttributeAccessIssue]
    KimiHarnessAdapter,
    _remove_managed_block,  # pyright: ignore[reportAttributeAccessIssue]
)

_OUTPUT = Path(__file__).with_name("hook_config_vectors.json")
_BEGIN = "# BEGIN HOL GUARD MANAGED HOOKS"
_END = "# END HOL GUARD MANAGED HOOKS"
_BLOCK = f'{_BEGIN}\n[[hooks]]\nevent = "Stop"\ncommand = "old"\ntimeout = 30\n{_END}\n'
_USER = '[[hooks]]\nevent = "PostToolUse"\ncommand = "user-format.sh"\n'

_TEXTS: tuple[tuple[str, str], ...] = (
    ("empty", ""),
    ("whitespace-only", " \n\t\n"),
    ("user-hooks", _USER),
    ("user-hooks-no-newline", _USER.rstrip("\n")),
    ("block-only", _BLOCK),
    ("user-then-block", f"{_USER}\n{_BLOCK}"),
    ("block-then-user", f"{_BLOCK}\n{_USER}"),
    ("block-without-newline", f"keep = true\n{_BEGIN}\nx = 1\n{_END}"),
    ("indented-block-eats-following-indent", f"a = 1\n\n  {_BEGIN}\nx\n{_END}\n\n\n  b = 2\n"),
    ("two-blocks", f"a = 1\n{_BLOCK}b = 2\n{_BLOCK}c = 3\n"),
    ("unterminated-begin", f"{_BEGIN}\nx = 1\n"),
    ("stray-marker-lines", f"{_BLOCK}  # stray HOL GUARD MANAGED HOOKS note\r\nkeep = 1\n# HOL GUARD MANAGED HOOKS\n"),
    ("crlf-block", f"a = 1\r\n{_BEGIN}\r\nx = 1\r\n{_END}\r\nb = 2\r\n"),
    ("separator-before-block", f"x = 1\n\x1c{_BLOCK}y = 2\n"),
    ("nbsp-before-block", f"x = 1\n\N{NO-BREAK SPACE}{_BLOCK}y = 2\n"),
    ("trailing-separators", "x = 1\n\x1d\x1e\x1f\x0b\x0c\x85"),
    ("trailing-line-separator", "x = 1\N{LINE SEPARATOR}\N{PARAGRAPH SEPARATOR}\N{IDEOGRAPHIC SPACE}"),
    ("leading-separators", "\x1c\N{NO-BREAK SPACE}\nx = 1\n"),
    ("unicode-text", 'name = "caf\N{LATIN SMALL LETTER E WITH ACUTE}"\n'),
)

_COMMANDS: tuple[tuple[str, str], ...] = (
    ("plain", "/usr/bin/python3 -m codex_plugin_scanner.cli guard hook --harness kimi"),
    ("quotes-and-backslashes", 'python -c "print(\\"hello\\")" C:\\Guard\\bin'),
    ("unicode", "/home/caf\N{LATIN SMALL LETTER E WITH ACUTE}/guard hook"),
    ("empty", ""),
)


def _install_text(existing: str, hook_command: str) -> str:
    managed_block = KimiHarnessAdapter._build_managed_block(hook_command)  # pyright: ignore[reportAttributeAccessIssue]
    cleaned_text = _remove_managed_block(existing)
    return f"{cleaned_text.rstrip()}\n\n{managed_block}\n".lstrip()


def _uninstall_text(existing: str) -> str:
    return _remove_managed_block(existing).rstrip() + "\n"


def _cases() -> list[dict[str, object]]:
    cases: list[dict[str, object]] = []
    for name, text in _TEXTS:
        command_name, command = _COMMANDS[len(cases) % len(_COMMANDS)]
        cases.append(
            {
                "name": f"install-{name}-{command_name}",
                "request": {"op": "install", "text": text, "hook_command": command},
                "text": _install_text(text, command),
            }
        )
        cases.append(
            {
                "name": f"uninstall-{name}",
                "request": {"op": "uninstall", "text": text},
                "text": _uninstall_text(text),
            }
        )
    for command_name, command in _COMMANDS:
        cases.append(
            {
                "name": f"install-user-hooks-{command_name}-command",
                "request": {"op": "install", "text": _USER, "hook_command": command},
                "text": _install_text(_USER, command),
            }
        )
    installed = _install_text(_USER, _COMMANDS[1][1])
    cases.append(
        {
            "name": "reinstall-replaces-block",
            "request": {"op": "install", "text": installed, "hook_command": _COMMANDS[0][1]},
            "text": _install_text(installed, _COMMANDS[0][1]),
        }
    )
    cases.append(
        {
            "name": "uninstall-after-install",
            "request": {"op": "uninstall", "text": installed},
            "text": _uninstall_text(installed),
        }
    )
    return cases


def main() -> None:
    output = Path(sys.argv[1]) if len(sys.argv) > 1 else _OUTPUT
    document = {"schema": "hol-guard-kimi-hook-config-vectors.v1", "cases": _cases()}
    output.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
