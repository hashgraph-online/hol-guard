#!/usr/bin/env python3
"""Record Devin JSONC parsing vectors from the ORIGINAL Python parser.

Run against a checkout that still holds `adapters/devin_config.parse_devin_jsonc`
with its Python `_strip_jsonc_syntax` (the base of the commit that moved the
parser into the native `devin_jsonc` kind), never from Rust output:

    cd <base-worktree>
    PYTHONPATH=$PWD/src python3 <this-file> <output jsonc_vectors.json>

Each case records, for one config text, the `had_comments` and
`parse_failed` flags and the JSON text of the parsed payload. A parse that
raises is recorded as a refusal.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

CASES: list[tuple[str, str]] = [
    ("empty", ""),
    ("whitespace", " \n\t\r\n "),
    ("strict_object", '{"b": 1, "a": {"x": [1, 2.5, null, true]}, "b": 2}'),
    ("strict_array", "[1, 2]"),
    ("strict_scalar", "5"),
    ("strict_string", '"text"'),
    ("nan_and_big", '{"n": NaN, "i": -Infinity, "big": 123456789012345678901234567890}'),
    ("line_comment", '// head\n{"a": 1}\n'),
    ("line_comment_cr", '// head\r{"a": 1}'),
    ("block_comment", '/* a\n b */{"a": /* inline */ 1}'),
    ("unterminated_block_comment", '{"a": 1} /* open'),
    ("unterminated_block_comment_inside", '{"a": /* open'),
    ("comment_markers_in_strings", '{"url": "http://x/*y*/", "b": "a//b"} // tail'),
    ("escaped_quote_in_string", '{"a": "say \\"//hi\\"", "b": 1,}'),
    ("trailing_commas", '{"a": [1, 2, ], "o": {"k": 1,\n\t},\n}'),
    ("comma_before_line_comment", '{"a": 1, // c\n}'),
    ("comma_before_block_comment", '{"a": [1, /* c */ ], "b": 2 /* d */, }'),
    ("comma_before_unterminated_comment", '{"a": 1, /* open'),
    ("comma_in_string_kept", '{"s": "x,}", "t": "y, ]"}'),
    ("comments_only", "// only a comment\n/* and a block */"),
    ("comments_then_array", "// c\n[1, 2,]"),
    ("comments_then_scalar", "/* c */ 7"),
    ("comments_then_garbage", "// c\n{not json"),
    ("garbage", "{not json"),
    ("single_quotes", "{'a': 1}"),
    ("bare_keys", "{a: 1}"),
    ("bom", '\ufeff{"a": 1}'),
    ("lone_surrogate_escape", '{"v": "\\udc00"}'),
    ("lone_surrogate_escape_with_comment", '// c\n{"v": "\\ud800"}'),
    ("unicode_text", '{"näme": "ü", // c\n "b": "é",}'),
    ("hooks_shape", '{\n  // Guard\n  "hooks": {"PreToolUse": [{"matcher": "^exec$", "hooks": []},]},\n}'),
    ("slash_at_end", '{"a": 1}/'),
    ("lone_slash_inside", '{"a": 1 / 2}'),
    ("big_integer_over_limit", '{"a": ' + "9" * 5000 + "}"),
    ("big_integer_over_limit_with_comment", '// c\n{"a": ' + "9" * 5000 + "}"),
]


def record(name: str, text: str, parse) -> dict:
    try:
        document = parse(text)
    except (ValueError, RecursionError):
        return {"name": name, "text": text, "refused": True}
    return {
        "name": name,
        "text": text,
        "payload": json.dumps(document.payload),
        "had_comments": document.had_comments,
        "parse_failed": document.parse_failed,
    }


def main() -> None:
    try:
        from codex_plugin_scanner.guard.adapters.devin_config import _strip_jsonc_syntax, parse_devin_jsonc
    except ImportError:
        sys.exit("refusing to record: the original Python Devin JSONC parser is gone")
    del _strip_jsonc_syntax
    recorded = [record(name, text, parse_devin_jsonc) for name, text in CASES]
    document = {"schema": "guard-devin-jsonc-vectors.v1", "cases": recorded}
    Path(sys.argv[1]).write_text(
        json.dumps(document, indent=1, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"recorded {len(recorded)} cases")


if __name__ == "__main__":
    main()
