"""Freeze the pinned Python OMP NDJSON reader without benchmark imports."""

from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any


ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / "ci/gauntlet/evidence.py"
SOURCE_SHA256 = "b76344cf9700c73abebd5d65a81d34aa28c960b591fc2bc485423afa038efe2f"


def pinned_reader():
    raw = SOURCE.read_bytes()
    if hashlib.sha256(raw).hexdigest() != SOURCE_SHA256:
        raise ValueError("pinned OMP evidence source changed")
    functions = [node for node in ast.parse(raw, filename=str(SOURCE)).body
                 if isinstance(node, ast.FunctionDef) and node.name == "read_events"]
    if len(functions) != 1:
        raise ValueError("pinned OMP reader is missing or ambiguous")
    module = ast.fix_missing_locations(ast.Module(body=functions, type_ignores=[]))
    namespace = {"Path": Path, "Any": Any, "json": json, "TRANSCRIPT_LIMIT": 16 * 1024 * 1024}
    exec(compile(module, str(SOURCE), "exec"), namespace)
    return namespace["read_events"]


def cases():
    return [
        ("empty", b""),
        ("blank-lines", b" \n\t\r\n"),
        ("one-model", b'{"type":"model_turn","calls":[]}\n'),
        ("two-events", b'{"type":"model_turn"}\n{"type":"tool_execution_start"}\n'),
        ("crlf", b'{"type":"a"}\r\n{"type":"b"}\r\n'),
        ("unicode-separator", '{"type":"a"}\u2028{"type":"b"}'.encode()),
        ("unicode-value", '{"type":"model_turn","name":"caf\u00e9"}'.encode()),
        ("empty-type", b'{"type":""}\n'),
        ("missing-type", b'{}\n'),
        ("numeric-type", b'{"type":1}\n'),
        ("array", b'[]\n'),
        ("null", b'null\n'),
        ("broken-json", b'{broken}\n'),
        ("invalid-utf8", b'\xff\n'),
        ("bom", b'\xef\xbb\xbf{"type":"a"}\n'),
    ]


def main() -> None:
    read_events = pinned_reader()
    frozen = []
    with TemporaryDirectory(prefix="gauntlet-omp-transcript-") as directory:
        path = Path(directory) / "events.jsonl"
        for name, raw in cases():
            path.write_bytes(raw)
            try:
                events = read_events(path)
                accepted, error = True, None
            except (ValueError, UnicodeError, json.JSONDecodeError) as caught:
                events, accepted, error = None, False, type(caught).__name__
            frozen.append({"name": name, "raw_hex": raw.hex(), "accepted": accepted,
                           "events": events, "error_class": error})
    print(json.dumps({"schema": "gauntlet-omp-transcript-fixtures.v1",
                      "source_sha256": SOURCE_SHA256, "cases": frozen},
                     indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
