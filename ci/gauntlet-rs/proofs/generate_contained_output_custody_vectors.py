"""Freeze exact Python contained-output/Post relation over synthetic records.

This extracts the pinned functions without importing the product, controller,
SDK or model. All rows are inert supplied JSON, not observed executions.
"""

from __future__ import annotations

import argparse
import ast
import copy
import hashlib
import json
import math
from pathlib import Path


def extracted(name: str, source: str) -> ast.FunctionDef:
    return copy.deepcopy(next(node for node in ast.parse(source).body
                              if isinstance(node, ast.FunctionDef) and node.name == name))


def canonical_json(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def merge_delta(base, changed):
    if isinstance(base, dict) and isinstance(changed, dict):
        result = {name: None for name in base.keys() - changed.keys()}
        for name, value in changed.items():
            if name not in base:
                result[name] = value
            elif canonical_json(base[name]) != canonical_json(value):
                result[name] = merge_delta(base[name], value)
        return result
    return changed


def apply_merge_delta(base, patch):
    if not isinstance(patch, dict):
        return copy.deepcopy(patch)
    result = copy.deepcopy(base) if isinstance(base, dict) else {}
    for name, value in patch.items():
        if value is None:
            result.pop(name, None)
        else:
            result[name] = apply_merge_delta(result.get(name), value)
    return result


PRE = "a" * 64
POST = "b" * 64
CALL = "sdk-contained-control"


def base_case(captured_output) -> dict:
    stdout = "model-free captured output\n"
    stderr = ""
    result = {
        "exit_code": 0, "payload_digest": PRE, "stdout": stdout, "stderr": stderr,
        "stdout_sha256": hashlib.sha256(stdout.encode()).hexdigest(),
        "stderr_sha256": hashlib.sha256(stderr.encode()).hexdigest(),
    }
    captured = captured_output(result)
    pre = {"kind": "actual-hook-response", "hook_event_name": "PreToolUse",
           "payload_digest": PRE, "tool_call_id": CALL}
    post = {"kind": "actual-hook-response", "hook_event_name": "PostToolUse",
            "tool_call_id": CALL, "payload_digest": POST,
            "actual_output_sha256": captured["output_sha256"]}
    binding = {
        "sequence": 7, "kind": "actual-contained-output-binding", "tool_call_id": CALL,
        "pre_payload_digest": PRE, "payload_digest": POST,
        "result_digest": captured["result_digest"],
        "output_sha256": captured["output_sha256"],
        "sdk_output_sha256": "c" * 64,
        "schema": "controller-contained-output.v1",
    }
    return {
        "transport_observations": [pre, post, binding],
        "contained_transport_observations": [{"kind": "contained-route-consumed",
                                              "payload_digest": PRE}],
        "product_plane": {"executions": [result]},
    }


def cases(base: dict) -> list[dict]:
    rows = []

    def add(name: str, mutate=None) -> None:
        value = copy.deepcopy(base)
        if mutate is not None:
            mutate(value)
        rows.append({"name": name, "builtin": value})

    add("valid-single")
    add("valid-empty", lambda v: (v["transport_observations"].clear(),
                                  v["contained_transport_observations"].clear(),
                                  v["product_plane"]["executions"].clear()))
    add("missing-binding", lambda v: v["transport_observations"].pop())
    add("missing-consumed", lambda v: v["contained_transport_observations"].clear())
    add("wrong-schema", lambda v: v["transport_observations"][2].update(schema="other"))
    add("extra-binding-field", lambda v: v["transport_observations"][2].update(extra=True))
    add("wrong-sdk-output-hash", lambda v: v["transport_observations"][2].update(sdk_output_sha256="C" * 64))
    add("missing-pre", lambda v: v["transport_observations"].pop(0))
    add("missing-post", lambda v: v["transport_observations"].pop(1))
    add("wrong-call-id", lambda v: v["transport_observations"][2].update(tool_call_id="other"))
    add("wrong-result-payload", lambda v: v["product_plane"]["executions"][0].update(payload_digest="d" * 64))
    add("wrong-result-digest", lambda v: v["transport_observations"][2].update(result_digest="0" * 64))
    add("wrong-output-hash", lambda v: v["transport_observations"][2].update(output_sha256="0" * 64))
    add("wrong-post-output-hash", lambda v: v["transport_observations"][1].update(actual_output_sha256="0" * 64))
    add("wrong-post-payload", lambda v: v["transport_observations"][1].update(payload_digest="0" * 64))
    add("changed-stream-digest", lambda v: v["product_plane"]["executions"][0].update(stdout_sha256="0" * 64))

    def other_consumed(value: dict) -> None:
        value["transport_observations"].append({
            "kind": "actual-hook-response", "hook_event_name": "PreToolUse",
            "payload_digest": "e" * 64, "tool_call_id": "other-call",
        })
        value["contained_transport_observations"][0]["payload_digest"] = "e" * 64
    add("consumed-wrong-call", other_consumed)
    return rows


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    source = args.source.read_text(encoding="utf-8")
    output_path = args.source.with_name("contained_output_binding.py")
    output_source = output_path.read_text(encoding="utf-8")
    product_path = args.source.with_name("product_custody.py")
    product_source = product_path.read_text(encoding="utf-8")
    json_path = args.source.with_name("json_data.py")
    json_source = json_path.read_text(encoding="utf-8")
    functions = [extracted("_require", product_source),
                 extracted("_bounded", json_source), extracted("canonical_json", json_source),
                 extracted("digest", json_source), extracted("captured_output", output_source),
                 extracted("verify_contained_outputs", source)]
    module = ast.fix_missing_locations(ast.Module(body=functions, type_ignores=[]))
    namespace = {
        "hashlib": hashlib, "json": json, "math": math,
        "ContractError": ValueError, "MAX_DEPTH": 32, "MAX_NODES": 500_000,
        "MAX_RECORD_BYTES": 16 * 1024 * 1024,
        "PROFILE": "controller-contained-output.v1",
        "re": __import__("re"),
    }
    exec(compile(module, str(args.source), "exec"), namespace)
    base = base_case(namespace["captured_output"])
    rows = cases(base)
    compact = []
    for row in rows:
        try:
            result = namespace["verify_contained_outputs"](row["builtin"])
        except ValueError as error:
            row["accepted"] = False
            row["error"] = str(error)
        else:
            row["accepted"] = True
            row["result"] = result
        delta = merge_delta(base, row["builtin"])
        assert canonical_json(apply_merge_delta(base, delta)) == canonical_json(row["builtin"])
        compact_row = {"name": row["name"], "patch": delta, "accepted": row["accepted"]}
        compact_row["result" if row["accepted"] else "error"] = row[
            "result" if row["accepted"] else "error"
        ]
        compact.append(compact_row)
    args.out.write_text(json.dumps({
        "schema": "gauntlet-contained-output-custody-fixtures.v1",
        "source_sha256": hashlib.sha256(args.source.read_bytes()).hexdigest(),
        "output_binding_sha256": hashlib.sha256(output_path.read_bytes()).hexdigest(),
        "product_custody_sha256": hashlib.sha256(product_path.read_bytes()).hexdigest(),
        "json_data_sha256": hashlib.sha256(json_path.read_bytes()).hexdigest(),
        "base": base, "cases": compact,
    }, sort_keys=True, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
