"""Freeze Python deterministic control checks after the signed session opening.

Only private-cell runtime and cancellation custody are synthetic stubs. The
checks under test are the exact pinned verify_control, request_rejection,
_boundary and captured_output ASTs. No product, SDK or model is executed.
"""

from __future__ import annotations

import argparse
import ast
import base64
import copy
import hashlib
import json
import math
from pathlib import Path, PurePosixPath

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from generate_control_opening_vectors import canonical_json, extracted
from generate_control_session_vectors import ROOT, base_session_case, resign


NEGATIVES = {
    "wrong-sha", "foreign-workspace", "foreign-cwd", "wrong-event", "wrong-tool",
    "nonstring-command", "duplicate-field", "wrong-schema", "missing-payload",
}


def merge_delta(base, changed):
    """Return a compact JSON Merge Patch, used only for fixture storage."""
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


def base_full_case(role: str) -> tuple[dict, dict, str]:
    control, expected, key = base_session_case()
    plane = control["developer_runtime"]["record"]["native_builtin_audit"]["record"]["product_plane"]
    stdout = "captured synthetic output\n"
    stderr = ""
    plane["executions"] = [] if role == "cancel" else [{
        "exit_code": 124 if role == "timeout" else 0,
        "stdout": stdout, "stderr": stderr,
        "stdout_sha256": hashlib.sha256(stdout.encode()).hexdigest(),
        "stderr_sha256": hashlib.sha256(stderr.encode()).hexdigest(),
    }]
    control["developer_runtime"]["record"]["native_builtin_audit"]["record"]["review_summary"] = {
        "post_review_counts": {"sdk-contained-control": 1},
    }
    control["sdk_result"] = {
        "modelContextProjection": {
            "schema": "contained-command-context-control.v1",
            "originalCommandVisible": True,
            "executionTransportRetained": True,
            "scope": "actual SDK synthetic-stream control; no model inference",
        },
        "modelExercised": False, "providerRequests": 0,
        "syntheticStreamCalls": 3, "mcpExercised": True,
        "results": [{}, {"isError": False, "content": [{
            "type": "text",
            "text": "Exit code: 0\nSTDOUT:\ncaptured synthetic output\n\nSTDERR:\n",
        }]}],
    }
    control["actual_sdk_bash_success"] = True
    control["native_timeout_seconds"] = 5
    control["detached_child_samples"] = [{"pid": 701}]
    control["detached_child_alive_before_cell_teardown"] = False
    control["cell_closed_before_explicit_teardown"] = False
    control["late_effect_present"] = False
    for name in ("real_sdk_pre_replay_refused", "real_sdk_route_replay_refused",
                 "real_sdk_post_replay_refused"):
        control[name] = True
    control["same_uid_peer_negative"] = {"denied": True}
    control["kernel_boundary_negatives"] = {"rows": [{"denied": True} for _ in range(21)]}
    control["request_binding_negatives"] = [{
        "case": name, "exit_code": 126, "trap_effect_present": False,
        "kernel_process_samples": [{"pid": 701}],
        "stderr": "contained_test_authorization_failed: synthetic refusal",
    } for name in sorted(NEGATIVES)]
    paths = [ROOT + "/controller-canary.txt", ROOT + "/agent/agent-canary.txt",
             "/product/guard/native-boundary-canary.txt"]
    control["native_contained_boundary_negatives"] = {"rows": [
        *({"surface": "path", "path": path, "operation": operation, "denied": True}
          for path in paths for operation in ("read", "write")),
        {"surface": "network", "family": 2, "denied": True},
        {"surface": "network", "family": 10, "denied": True},
    ]}
    control["canary_initial_sha256"] = {"controller": "a", "agent": "b", "product": "c"}
    control["canary_terminal_sha256"] = copy.deepcopy(control["canary_initial_sha256"])
    control["plane"] = copy.deepcopy(plane)
    resign(control)
    return control, expected, key


def cases() -> list[dict]:
    rows = []

    def add(name: str, role: str, mutate=None) -> None:
        control, expected, key = base_full_case(role)
        if mutate is not None:
            mutate(control)
        control["plane"] = copy.deepcopy(
            control["developer_runtime"]["record"]["native_builtin_audit"]["record"]["product_plane"]
        )
        resign(control)
        rows.append({"name": name, "role": role, "control": control,
                     "expected": expected, "public_key_hex": key})

    def plane(control):
        return control["developer_runtime"]["record"]["native_builtin_audit"]["record"]["product_plane"]

    for role in ("success", "timeout", "cancel", "input-binding", "boundary"):
        add("valid-" + role, role)
    add("producer-passed-false-ignored", "success", lambda c: c.update(passed=False))
    add("projection-missing", "success", lambda c: c["sdk_result"].pop("modelContextProjection"))
    add("projection-extra-field", "success", lambda c: c["sdk_result"]["modelContextProjection"].update(extra=True))
    add("projection-bool-as-int", "success", lambda c: c["sdk_result"]["modelContextProjection"].update(originalCommandVisible=1))
    add("projection-wrong-scope", "success", lambda c: c["sdk_result"]["modelContextProjection"].update(scope="model"))
    add("model-exercised", "cancel", lambda c: c["sdk_result"].update(modelExercised=True))
    add("provider-request", "cancel", lambda c: c["sdk_result"].update(providerRequests=1))
    add("wrong-stream-count", "cancel", lambda c: c["sdk_result"].update(syntheticStreamCalls=2))
    add("mcp-not-exercised", "cancel", lambda c: c["sdk_result"].update(mcpExercised=False))
    add("native-execution-missing", "success", lambda c: plane(c)["executions"].clear())
    add("required-post-missing", "success", lambda c: c["developer_runtime"]["record"]["native_builtin_audit"]["record"]["review_summary"].update(post_review_counts={}))
    add("success-native-exit", "success", lambda c: plane(c)["executions"][0].update(exit_code=1))
    add("success-sdk-bash-false", "success", lambda c: c.update(actual_sdk_bash_success=False))
    add("success-sdk-error", "success", lambda c: c["sdk_result"]["results"][1].update(isError=True))
    add("success-output-mismatch", "success", lambda c: c["sdk_result"]["results"][1].update(content=[]))
    add("boundary-output-mismatch", "boundary", lambda c: c["sdk_result"]["results"][1].update(content=[]))
    add("success-stdout-digest-mismatch", "success", lambda c: plane(c)["executions"][0].update(stdout_sha256="0" * 64))
    add("boundary-stderr-digest-mismatch", "boundary", lambda c: plane(c)["executions"][0].update(stderr_sha256="0" * 64))
    add("timeout-duration", "timeout", lambda c: c.update(native_timeout_seconds=4))
    add("timeout-native-exit", "timeout", lambda c: plane(c)["executions"][0].update(exit_code=0))
    add("timeout-no-samples", "timeout", lambda c: c.update(detached_child_samples=[]))
    add("timeout-child-survived", "timeout", lambda c: c.update(detached_child_alive_before_cell_teardown=True))
    add("timeout-late-effect", "timeout", lambda c: c.update(late_effect_present=True))
    add("replay-pre-accepted", "success", lambda c: c.update(real_sdk_pre_replay_refused=False))
    add("replay-route-accepted", "input-binding", lambda c: c.update(real_sdk_route_replay_refused=False))
    add("same-uid-peer-accepted", "boundary", lambda c: c["same_uid_peer_negative"].update(denied=False))
    add("kernel-negative-missing", "success", lambda c: c["kernel_boundary_negatives"]["rows"].pop())
    add("kernel-negative-allowed", "success", lambda c: c["kernel_boundary_negatives"]["rows"][0].update(denied=False))
    add("binding-case-duplicate", "input-binding", lambda c: c["request_binding_negatives"][0].update(case="wrong-sha"))
    add("binding-wrong-exit", "input-binding", lambda c: c["request_binding_negatives"][0].update(exit_code=0))
    add("binding-effect", "input-binding", lambda c: c["request_binding_negatives"][0].update(trap_effect_present=True))
    add("binding-no-samples", "input-binding", lambda c: c["request_binding_negatives"][0].update(kernel_process_samples=[]))
    add("binding-wrong-stderr", "input-binding", lambda c: c["request_binding_negatives"][0].update(stderr="denied"))
    add("boundary-negative-missing", "boundary", lambda c: c["native_contained_boundary_negatives"]["rows"].pop())
    add("boundary-negative-allowed", "boundary", lambda c: c["native_contained_boundary_negatives"]["rows"][0].update(denied=False))
    add("boundary-wrong-path", "boundary", lambda c: c["native_contained_boundary_negatives"]["rows"][0].update(path="/tmp/other"))
    add("boundary-wrong-family", "boundary", lambda c: c["native_contained_boundary_negatives"]["rows"][-1].update(family=1))
    add("boundary-canary-changed", "boundary", lambda c: c["canary_terminal_sha256"].update(product="other"))
    add("boundary-canary-missing", "boundary", lambda c: c["canary_initial_sha256"].pop("agent"))
    return rows


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--custody", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    source = args.source.read_text(encoding="utf-8")
    custody = args.custody.read_text(encoding="utf-8")
    output_path = args.source.with_name("contained_output_binding.py")
    output_source = output_path.read_text(encoding="utf-8")
    json_data_path = args.source.with_name("json_data.py")
    json_data_source = json_data_path.read_text(encoding="utf-8")
    functions = [extracted(name, custody) for name in ("_require", "_signed")]
    functions += [extracted(name, source) for name in ("request_rejection", "_boundary", "verify_control")]
    functions += [extracted(name, json_data_source) for name in ("_bounded", "canonical_json", "digest")]
    functions.append(extracted("captured_output", output_source))
    namespace = {
        "base64": base64, "canonical_json": canonical_json,
        "hashlib": hashlib, "json": json, "math": math,
        "Ed25519PublicKey": Ed25519PublicKey, "PurePosixPath": PurePosixPath,
        "ROLES": {"success", "timeout", "cancel", "input-binding", "boundary"},
        "NEGATIVES": NEGATIVES,
        "ContractError": ValueError,
        "MAX_DEPTH": 32, "MAX_NODES": 500_000, "MAX_RECORD_BYTES": 16 * 1024 * 1024,
        "PROFILE": "controller-contained-output.v1",
        "verify_private_cell_runtime": lambda *_a, **_kw: {"custody_verified": True},
        "_cancel": lambda *_a, **_kw: None,
    }
    module = ast.fix_missing_locations(ast.Module(body=functions, type_ignores=[]))
    exec(compile(module, str(args.source), "exec"), namespace)
    rows = cases()
    for row in rows:
        try:
            result = namespace["verify_control"](
                row["role"], row["control"],
                public_key=row["public_key_hex"], expected=row["expected"],
            )
        except ValueError as error:
            row["accepted"] = False
            row["error"] = str(error)
        else:
            row["accepted"] = True
            row["result"] = result
    bases = {}
    compact = []
    for row in rows:
        role = row["role"]
        if role not in bases:
            control, expected, key = base_full_case(role)
            bases[role] = {"control": control, "expected": expected, "public_key_hex": key}
            if role != "cancel":
                bases[role]["captured_output"] = namespace["captured_output"](control["plane"]["executions"][0])
        base = bases[role]
        assert row["expected"] == base["expected"]
        assert row["public_key_hex"] == base["public_key_hex"]
        delta = merge_delta(base["control"], row["control"])
        assert canonical_json(apply_merge_delta(base["control"], delta)) == canonical_json(row["control"])
        compact_row = {"name": row["name"], "role": role, "control_patch": delta,
                       "accepted": row["accepted"]}
        compact_row["result" if row["accepted"] else "error"] = row[
            "result" if row["accepted"] else "error"
        ]
        compact.append(compact_row)
    args.out.write_text(json.dumps({
        "schema": "gauntlet-control-reported-tail-fixtures.v1",
        "source_sha256": hashlib.sha256(args.source.read_bytes()).hexdigest(),
        "custody_sha256": hashlib.sha256(args.custody.read_bytes()).hexdigest(),
        "output_binding_sha256": hashlib.sha256(output_path.read_bytes()).hexdigest(),
        "json_data_sha256": hashlib.sha256(json_data_path.read_bytes()).hexdigest(),
        "ast_function": "verify_control, request_rejection, _boundary, captured_output",
        "stubs": ["verify_private_cell_runtime", "_cancel"],
        "bases": bases,
        "cases": compact,
    }, sort_keys=True, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
