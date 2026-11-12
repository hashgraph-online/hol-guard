"""Record parity vectors for the native ``grok_legacy_settings`` runner-authority kind.

The vectors pin ``remove_legacy_settings`` in
``guard/adapters/grok_install_settings.py`` as it existed before the resident
took it over: the regex removal of Guard's managed block from Grok's legacy
``managed_config.toml`` and the restoration of the ``compat.<vendor>`` hooks
values recorded in Guard's install state. Each case stores the request the
Python shim sends and the exact text the original code produced.

Run from a checkout of the base commit that still has the Python edits:

    PYTHONPATH=src python \
        rust/crates/guard-runtime/testdata/grok/record_grok_legacy_settings_vectors.py [OUTPUT]

It rewrites ``legacy_settings_vectors.json`` next to this script by default.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from codex_plugin_scanner.guard.adapters.grok_install_settings import remove_legacy_settings

_OUTPUT = Path(__file__).with_name("legacy_settings_vectors.json")
_BEGIN = "# BEGIN HOL GUARD MANAGED GROK"
_END = "# END HOL GUARD MANAGED GROK"
_BLOCK = f"{_BEGIN}\n[permission]\ndeny = []\n{_END}\n"
_CLAUDE_FALSE = "[compat.claude]\nskills = true\nhooks = false\n"

_CASES: tuple[tuple[str, str, object], ...] = (
    ("no-block-keeps-text", "[compat.claude]\nhooks = false\n", {"claude": "true"}),
    ("empty", "", {"claude": "true"}),
    ("block-only", _BLOCK, None),
    ("block-after-key", f"keep = true\n\n{_BLOCK}", None),
    ("block-without-newline", f"keep = true\n{_BEGIN}\nx = 1\n{_END}", None),
    ("indented-block-eats-following-indent", f"a = 1\n\n  {_BEGIN}\nx\n{_END}\n\n\n  b = 2\n", None),
    ("two-blocks", f"a = 1\n{_BLOCK}b = 2\n{_BLOCK}c = 3\n", None),
    ("unterminated-begin", f"{_BEGIN}\nx = 1\n", None),
    (
        "stray-marker-lines",
        f"{_BLOCK}  # stray HOL GUARD MANAGED GROK note\r\nkeep = 1\n# HOL GUARD MANAGED GROK\n",
        None,
    ),
    ("separator-before-block", f"x = 1\n\x1c{_BLOCK}y = 2\n", None),
    ("nbsp-before-block", f"x = 1\n\N{NO-BREAK SPACE}{_BLOCK}y = 2\n", None),
    ("ideographic-space-before-block", f"x = 1\n\N{IDEOGRAPHIC SPACE}{_BLOCK}y = 2\n", None),
    (
        "mixed-newline-hooks",
        "[compat.claude]\nskills = true\nhooks = false\r\n\n[ui]\nsimple_mode = true\n\n" + _BLOCK,
        {"claude": "true", "cursor": None},
    ),
    ("restore-value", _CLAUDE_FALSE + _BLOCK, {"claude": "true"}),
    ("restore-removes-line", _CLAUDE_FALSE + _BLOCK, {"claude": ""}),
    ("restore-inserts-line", "[compat.cursor]\nskills = true\n" + _BLOCK, {"cursor": "true"}),
    ("restore-absent-table", "[ui]\nx = 1\n" + _BLOCK, {"claude": "true", "cursor": ""}),
    ("restore-none-and-non-text", _CLAUDE_FALSE + _BLOCK, {"claude": None, "cursor": 5}),
    ("prior-not-object", _CLAUDE_FALSE + _BLOCK, ["claude", "true"]),
    ("prior-missing", _CLAUDE_FALSE + _BLOCK, "missing"),
    ("header-comment", "[compat.claude] # vendor\nhooks = false\n" + _BLOCK, {"claude": "true"}),
    ("indented-header", "  [compat.claude]\n  hooks = false\n" + _BLOCK, {"claude": "[]"}),
    ("crlf-header-not-found", "[compat.claude]\r\nhooks = false\r\n" + _BLOCK, {"claude": "true"}),
    ("hooks-spacing", "[compat.claude]\n\thooks   =   false # x\n" + _BLOCK, {"claude": "true"}),
    ("hooks-prefixed-key-is-not-hooks", "[compat.claude]\nhookshot = 1\nhooks.x = 2\n" + _BLOCK, {"claude": "true"}),
    ("vertical-tab-splits-line", "[compat.claude]\nfoo = 1\x0bhooks = false\nbar = 2\n" + _BLOCK, {"claude": "true"}),
    (
        "line-separator-splits-line",
        "[compat.claude]\nfoo = 1\N{LINE SEPARATOR}hooks = false\n" + _BLOCK,
        {"claude": ""},
    ),
    ("lone-carriage-return", "[compat.claude]\nfoo = 1\rhooks = false\rbar = 2\n" + _BLOCK, {"claude": "true"}),
    ("table-at-end-without-newline", _BLOCK + "[compat.claude]", {"claude": "true"}),
    (
        "table-ends-at-next-header",
        "[compat.claude]\nskills = 1\n  [other]\nhooks = false\n" + _BLOCK,
        {"claude": "true"},
    ),
    ("first-hooks-only", "[compat.claude]\nhooks = 1\nhooks = 2\n" + _BLOCK, {"claude": "3"}),
    (
        "both-vendors",
        "[compat.claude]\nhooks = false\n[compat.cursor]\nhooks = false\n" + _BLOCK,
        {"claude": "true", "cursor": ""},
    ),
    (
        "vendor-order-matters",
        "[compat.claude]\n[compat.cursor]\nhooks = false\n" + _BLOCK,
        {"cursor": "x", "claude": "1\n[compat.cursor]"},
    ),
    (
        "vendor-order-reversed",
        "[compat.claude]\n[compat.cursor]\nhooks = false\n" + _BLOCK,
        {"claude": "1\n[compat.cursor]", "cursor": "x"},
    ),
    ("vendor-with-regex-characters", "[compat.a.b]\nhooks = 1\n[compat.aXb]\nhooks = 2\n" + _BLOCK, {"a.b": "9"}),
    (
        "unicode-text",
        '[compat.claude]\nname = "caf\N{LATIN SMALL LETTER E WITH ACUTE} \N{SNOWMAN}"\nhooks = false\n' + _BLOCK,
        {"claude": "true"},
    ),
)


def _request(text: str, raw: object) -> dict[str, object]:
    prior = [[key, value] for key, value in raw.items()] if isinstance(raw, dict) else []
    return {"text": text, "prior_compat_hooks": prior}


def _record(name: str, text: str, raw: object) -> dict[str, object]:
    state: dict[str, object] = {} if raw == "missing" else {"prior_compat_hooks": raw}
    # The base-commit signature, which still took the state path.
    result = remove_legacy_settings(text.encode("utf-8"), Path("unused-state.json"), state)  # pyright: ignore[reportCallIssue]
    assert result is not None
    return {"name": name, "request": _request(text, raw), "text": result.decode("utf-8")}


def main() -> None:
    output = Path(sys.argv[1]) if len(sys.argv) > 1 else _OUTPUT
    cases = [_record(*case) for case in _CASES]
    document = {"schema": "hol-guard-grok-legacy-settings-vectors.v1", "cases": cases}
    output.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
