"""Freeze the pinned Python provider transport-round reducer without runtime imports."""

from __future__ import annotations

import ast
import copy
import hashlib
import json
import re
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / "ci/gauntlet/transport.py"
SOURCE_SHA256 = "facd2b1ba8b1f41c5054362a95b969abce7ee7f2c217bd69366e5fa1e11aaacb"


def pinned_reducer():
    raw = SOURCE.read_bytes()
    if hashlib.sha256(raw).hexdigest() != SOURCE_SHA256:
        raise ValueError("pinned provider transport source changed")
    functions = [node for node in ast.parse(raw, filename=str(SOURCE)).body
                 if isinstance(node, ast.FunctionDef) and node.name == "reconcile_rounds"]
    if len(functions) != 1:
        raise ValueError("pinned provider round reducer is missing or ambiguous")
    module = ast.fix_missing_locations(ast.Module(body=functions, type_ignores=[]))
    namespace = {"Any": Any, "re": re}
    exec(compile(module, str(SOURCE), "exec"), namespace)
    return namespace["reconcile_rounds"]


def complete(request="a" * 64):
    return {"status": "completed", "request_sha256": request, "response_sha256": "b" * 64,
            "response_bytes": 128, "response_models": ["qwen"]}


def retry(status=429, request="a" * 64):
    return {"status": "provider-error", "error_type": "HTTPError", "http_status": status,
            "delivered_bytes": 0, "request_sha256": request}


def cases():
    rows = [
        ("empty", []),
        ("one-complete", [complete()]),
        ("two-complete", [complete(), complete("c" * 64)]),
        ("retry-429", [retry(), complete()]),
        ("retry-500", [retry(500), complete()]),
        ("retry-599", [retry(599), complete()]),
        ("two-retries", [retry(), retry(503), complete()]),
        ("independent-retries", [retry(), complete(), retry(request="c" * 64), complete("c" * 64)]),
    ]

    def changed(name, source, edit):
        value = copy.deepcopy(source)
        edit(value)
        rows.append((name, value))

    changed("retry-400", [retry(), complete()], lambda r: r[0].update(http_status=400))
    changed("retry-600", [retry(), complete()], lambda r: r[0].update(http_status=600))
    changed("retry-http-bool", [retry(), complete()], lambda r: r[0].update(http_status=True))
    changed("partial-delivery", [retry(), complete()], lambda r: r[0].update(delivered_bytes=1))
    changed("wrong-error-type", [retry(), complete()], lambda r: r[0].update(error_type="TimeoutError"))
    changed("no-retry", [retry()], lambda r: None)
    changed("changed-request", [retry(), complete()], lambda r: r[1].update(request_sha256="c" * 64))
    changed("bad-request-digest", [complete()], lambda r: r[0].update(request_sha256="bad"))
    changed("bad-response-digest", [complete()], lambda r: r[0].update(response_sha256="bad"))
    changed("zero-response-bytes", [complete()], lambda r: r[0].update(response_bytes=0))
    changed("float-response-bytes", [complete()], lambda r: r[0].update(response_bytes=1.0))
    changed("empty-models", [complete()], lambda r: r[0].update(response_models=[]))
    changed("missing-models", [complete()], lambda r: r[0].pop("response_models"))
    changed("bad-after-recovery", [retry(), complete()], lambda r: r[1].update(response_sha256="bad"))
    changed("bad-after-complete", [complete(), complete("c" * 64)],
            lambda r: r[1].update(response_sha256="bad"))
    return rows


def main() -> None:
    reconcile = pinned_reducer()
    frozen = [{"name": name, "rounds": rounds, "valid": valid, "recovered": recovered}
              for name, rounds in cases() for valid, recovered in [reconcile(rounds)]]
    print(json.dumps({"schema": "gauntlet-provider-round-fixtures.v1",
                      "source_sha256": SOURCE_SHA256, "cases": frozen},
                     indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
