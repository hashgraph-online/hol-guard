#!/usr/bin/env python3
"""Record OpenClaw configuration-loading vectors from the ORIGINAL Python loader.

Run against a checkout that still holds `adapters/openclaw_config.load_config`
(the base of the commit that moved the loader into the native
`openclaw_detect` kind), never from Rust output:

    cd <base-worktree>
    PYTHONPATH=$PWD/src python3 <this-file> <output config_vectors.json>

Each case materializes a fixture tree under a temporary root and records the
JSON text of `load_config(<root>/home/.openclaw/openclaw.json)`: comment and
trailing-comma stripping, JSON5 keys and single-quoted strings, `$include`
resolution with its depth and cycle limits, and the deep merge. A loader that
raises is recorded as a refusal. `<ROOT>` stands for the fixture root. No case
spells `~`, which Python expands from the recording host's own home.
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "gemini"))

from adapter_vector_cases import case, file, link, raw  # noqa: E402
from record_adapter_vectors import materialize, release, scrub  # noqa: E402

CONFIG = "home/.openclaw/openclaw.json"
DIR = "home/.openclaw"


def chain(depth: int) -> list[dict]:
    """`openclaw.json` includes `c1.json`, which includes `c2.json`, and so on."""
    files = [file(CONFIG, '{"$include": "c1.json", "level": 0}')]
    for level in range(1, depth + 1):
        files.append(file(f"{DIR}/c{level}.json", json.dumps({"$include": f"c{level + 1}.json", f"l{level}": level})))
    return files


def config_cases() -> list[dict]:
    return [
        case("missing"),
        case("strict_json", [file(CONFIG, '{"b": 1, "a": {"x": [1, 2.5, null, true]}, "b": 2}')]),
        case("not_an_object", [file(CONFIG, "[1]")]),
        case("unparseable", [file(CONFIG, "{not json at all")]),
        case("empty_file", [file(CONFIG, "")]),
        case("bom", [file(CONFIG, '\ufeff{"a": 1}')]),
        case("not_utf8", [raw(CONFIG, b'{"a": "\xff"}')]),
        case("directory", dirs=[CONFIG]),
        case(
            "comments",
            [
                file(
                    CONFIG,
                    '// head\n{"url": "http://x/*y*/", /* block\n spans */ "b": "a//b", "c": \'it\\\'s // not\'}\n',
                )
            ],
        ),
        case("carriage_return_comment", [file(CONFIG, '// c\r{"a": 1}\r')]),
        case("crlf_comment", [file(CONFIG, '// c\r\n{"a": 1}\r\n')]),
        case("unterminated_block_comment", [file(CONFIG, '{"a": 1} /* open')]),
        case("trailing_commas", [file(CONFIG, '{"a": [1, 2, ], "s": "x,}", "o": {"k": 1,\n\t},\n}')]),
        case("comma_before_comment", [file(CONFIG, '{"a": 1, // c\n}')]),
        case(
            "json5_keys",
            [file(CONFIG, "{a: 1, $b: 2, _c-d: {e9: 3}, 'q': 4, 9x: 5}")],
        ),
        case("json5_key_space_before_colon", [file(CONFIG, "{ a  : 1,\n  b\t:\n 2 }")]),
        case("json5_key_without_colon", [file(CONFIG, "{a 1}")]),
        case("json5_value_identifier", [file(CONFIG, "{a: b}")]),
        case(
            "single_quote_escapes",
            [file(CONFIG, "{a: 'it\\'s', b: 'say \"hi\"', c: 'x\\\\y', d: 'n\\nt\\tq\\/', e: '\\u0041', f: '\\z'}")],
        ),
        case("double_quotes_inside_single", [file(CONFIG, "{a: 'one \\\"two\\\"'}")]),
        case("single_inside_double", [file(CONFIG, '{"a": "it\'s", b: \'ok\',}')]),
        case("unicode_text", [file(CONFIG, "{näme: 'ü', b: 'é'}")]),
        case("nan_and_big", [file(CONFIG, '{"n": NaN, "i": Infinity, "big": 123456789012345678901234567890}')]),
        case(
            "include_list",
            [
                file(CONFIG, '{"$include": ["a.json", "", "  ", 5, null, "b.txt", "sub/c.JSON", " d.json5 "], "z": 0}'),
                file(f"{DIR}/a.json", '{"a": 1, "m": {"x": 1, "y": [1]}}'),
                file(f"{DIR}/b.txt", '{"b": 1}'),
                file(f"{DIR}/sub/c.JSON", '{"c": 1, "m": {"y": [2], "z": 1}}'),
                file(f"{DIR}/d.json5", "{d: 1, m: {x: 'd'}}"),
            ],
        ),
        case(
            "include_local_wins",
            [
                file(CONFIG, '{"m": {"x": "local"}, "$include": "a.yaml", "k": "local"}'),
                file(f"{DIR}/a.yaml", '{"k": "inc", "m": {"x": "inc", "y": "inc"}, "n": 1}'),
            ],
        ),
        case(
            "include_object_replaces_scalar",
            [
                file(CONFIG, '{"$include": ["a.json", "b.json"], "s": {"z": 1}}'),
                file(f"{DIR}/a.json", '{"s": 1, "t": {"x": 1}}'),
                file(f"{DIR}/b.json", '{"s": {"y": 1}, "t": 2}'),
            ],
        ),
        case("include_not_string", [file(CONFIG, '{"$include": {"path": "a.json"}, "a": 0}')]),
        case("include_missing", [file(CONFIG, '{"$include": "gone.json", "a": 0}')]),
        case(
            "include_not_object",
            [file(CONFIG, '{"$include": "a.json", "a": 0}'), file(f"{DIR}/a.json", "[1, 2]")],
        ),
        case(
            "include_unparseable",
            [file(CONFIG, '{"$include": "a.json", "a": 0}'), file(f"{DIR}/a.json", "{broken")],
        ),
        case(
            "include_cycle",
            [
                file(CONFIG, '{"$include": "a.json", "root": 1}'),
                file(f"{DIR}/a.json", '{"$include": ["openclaw.json", "a.json"], "a": 1}'),
            ],
        ),
        case(
            "include_twice",
            [
                file(CONFIG, '{"$include": ["a.json", "b.json"]}'),
                file(f"{DIR}/a.json", '{"$include": "s.json", "a": 1}'),
                file(f"{DIR}/b.json", '{"$include": "s.json", "b": 1}'),
                file(f"{DIR}/s.json", '{"shared": {"n": 1}}'),
            ],
        ),
        case("include_depth_limit", chain(10)),
        case(
            "include_parent_and_absolute",
            [
                file(CONFIG, '{"$include": ["../up.json", "<ROOT>/abs/x.json5"]}'),
                file("home/up.json", '{"up": 1}'),
                file("abs/x.json5", "{abs: true}"),
            ],
        ),
        case(
            "include_through_link",
            [
                file(CONFIG, '{"$include": "linked/a.json"}'),
                file("elsewhere/a.json", '{"$include": "b.json", "a": 1}'),
                file("elsewhere/b.json", '{"b": "beside the target"}'),
                file(f"{DIR}/linked/b.json", '{"b": "beside the link"}'),
            ],
            [link(f"{DIR}/linked/a.json", "<ROOT>/elsewhere/a.json")],
        ),
        case(
            "config_is_link",
            [file("elsewhere/real.json", '{"$include": "x.json", "a": 1}'), file("elsewhere/x.json", '{"x": 1}')],
            [link(CONFIG, "<ROOT>/elsewhere/real.json")],
        ),
        case("dangling_link", symlinks=[link(CONFIG, "<ROOT>/gone.json")]),
        case(
            "lone_surrogate_value",
            [file(CONFIG, '{"$include": "a.json"}'), file(f"{DIR}/a.json", '{"v": "\\udc00"}')],
        ),
    ]


def run_case(spec: dict, load_config) -> dict:
    root = Path(tempfile.mkdtemp(prefix="openclaw-cfg-vec-")).resolve()
    try:
        materialize(root, spec)
        try:
            outcome: dict = {"payload": json.dumps(load_config(root / CONFIG))}
        except (ValueError, TypeError, RecursionError, OSError, RuntimeError):
            outcome = {"refused": True}
        record = {key: spec[key] for key in ("name", "files", "symlinks", "dirs", "dir_modes", "home")}
        record.update(scrub(outcome, root))
        return record
    finally:
        release(root)


def main() -> None:
    try:
        from codex_plugin_scanner.guard.adapters.openclaw_config import load_config
    except ImportError:
        sys.exit("refusing to record: the original Python OpenClaw loader is gone")
    recorded = [run_case(spec, load_config) for spec in config_cases()]
    document = {"schema": "guard-openclaw-config-vectors.v1", "cases": recorded}
    Path(sys.argv[1]).write_text(
        json.dumps(document, indent=1, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"recorded {len(recorded)} cases")


if __name__ == "__main__":
    main()
