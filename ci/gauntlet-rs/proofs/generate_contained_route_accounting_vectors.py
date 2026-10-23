"""Freeze the exact Python contained-route accounting block without execution."""

from __future__ import annotations

import ast
from collections import Counter
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / "ci/gauntlet/benchmark/private_cell_runtime_custody.py"
OUTPUT = ROOT / "ci/gauntlet-rs/crates/gauntlet-evidence/tests/fixtures/contained_route_accounting_v1.json"
sys.path.insert(0, str(ROOT))
from ci.gauntlet.benchmark.json_data import digest  # noqa: E402


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def source_block():
    tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
    function = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                    and node.name == "verify_private_cell_runtime")
    body = function.body
    starts = [index for index, node in enumerate(body) if isinstance(node, ast.Assign)
              and any(isinstance(target, ast.Name) and target.id == "events"
                      for target in node.targets)]
    ends = [index for index, node in enumerate(body) if isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Call) and len(node.value.args) == 2
            and isinstance(node.value.args[1], ast.Constant)
            and node.value.args[1].value ==
            "contained authorization/result is missing, duplicated or transplanted"]
    if len(starts) != 1 or len(ends) != 1 or ends[0] - starts[0] != 4:
        raise ValueError("exact contained-route accounting source block changed")
    return compile(ast.fix_missing_locations(ast.Module(body=body[starts[0]:ends[0] + 1],
                                                type_ignores=[])), str(SOURCE), "exec")


def base_case():
    execution = {"payload_digest": "b" * 64, "native_command": ["inert"]}
    token = "a" * 64
    return {"builtin": {"contained_transport_observations": [
        {"kind": "contained-route-prepared", "token_digest": token},
        {"kind": "contained-route-consumed", "token_digest": token,
         "payload_digest": execution["payload_digest"]},
        {"kind": "actual-contained-result", "token_digest": token,
         "result_digest": digest(execution)},
    ]}, "plane": {"executions": [execution]}}


def cases():
    base = base_case()
    yield "valid-one", base

    def altered(name, edit):
        row = deepcopy(base)
        edit(row, row["builtin"]["contained_transport_observations"], row["plane"]["executions"])
        return name, row

    yield altered("missing-prepare", lambda _, events, __: events.pop(0))
    yield altered("duplicate-consume", lambda _, events, __: events.insert(2, deepcopy(events[1])))
    yield altered("missing-finish", lambda _, events, __: events.pop())
    yield altered("wrong-finish-token", lambda _, events, __: events[2].__setitem__("token_digest", "c" * 64))
    yield altered("wrong-consumed-payload", lambda _, events, __: events[1].__setitem__("payload_digest", "c" * 64))
    yield altered("wrong-finished-result", lambda _, events, __: events[2].__setitem__("result_digest", "c" * 64))
    yield altered("duplicate-finish", lambda _, events, __: events.append(deepcopy(events[2])))
    yield altered("unmatched-execution", lambda _, __, executions: executions.append({
        "payload_digest": "c" * 64, "native_command": ["other"]}))
    yield altered("unused-prepared-route", lambda _, events, __: events.append({
        "kind": "contained-route-prepared", "token_digest": "c" * 64}))
    yield altered("unrelated-transport-event", lambda _, events, __: events.append({
        "kind": "peer-authenticated", "token_digest": "c" * 64}))
    second = deepcopy(base)
    other = {"payload_digest": "c" * 64, "native_command": ["other"]}
    second["plane"]["executions"].append(other)
    second["builtin"]["contained_transport_observations"].extend([
        {"kind": "contained-route-prepared", "token_digest": "d" * 64},
        {"kind": "contained-route-consumed", "token_digest": "d" * 64,
         "payload_digest": other["payload_digest"]},
        {"kind": "actual-contained-result", "token_digest": "d" * 64,
         "result_digest": digest(other)},
    ])
    yield "valid-two", second
    empty = {"builtin": {"contained_transport_observations": []},
             "plane": {"executions": []}}
    yield "zero-routes-loop-only", empty


def main() -> None:
    block = source_block()
    rows = []
    for name, row in cases():
        scope = {"builtin": row["builtin"], "plane": row["plane"],
                 "Counter": Counter, "digest": digest, "_require": require}
        try:
            exec(block, scope)
            accepted, reason = True, None
        except Exception as error:
            accepted, reason = False, str(error)
        rows.append({"name": name, **row, "accepted": accepted, "reason": reason})
    OUTPUT.write_text(json.dumps({"schema": "gauntlet-python-contained-route-accounting.v1",
                                  "source_sha256": hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
                                  "cases": rows}, sort_keys=True, separators=(",", ":")) + "\n",
                      encoding="utf-8")
    print(f"frozen {len(rows)} Python contained-route cases: "
          f"{sum(row['accepted'] for row in rows)} accepted")


if __name__ == "__main__":
    main()
