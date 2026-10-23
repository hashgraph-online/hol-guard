"""Freeze the exact Python `_cancel` reported-field branch with external custody stubbed.

The source AST is extracted, except for its relative `version_options` import.
Product, private-cell, Native review and kernel validators are inert stubs.
No controller, SDK, product or model is run.
"""

from __future__ import annotations

import argparse
import ast
import copy
import hashlib
import json
from pathlib import Path

from generate_control_opening_vectors import canonical_json, extracted
from generate_control_reported_tail_vectors import (
    apply_merge_delta,
    base_full_case,
    merge_delta,
)
from generate_control_session_vectors import resign


SUMMARY = {"missing_required_post_call_ids": ["sdk-contained-control"],
           "post_review_counts": {}}


def base_case() -> tuple[dict, dict, str]:
    control, expected, key = base_full_case("cancel")
    runtime = control["developer_runtime"]["record"]
    builtin = runtime["native_builtin_audit"]["record"]
    plane = builtin["product_plane"]
    runtime.update(errors=[], prompt_allowed=True, native_mcp_audit={})
    builtin["review_summary"] = copy.deepcopy(SUMMARY)
    builtin.update(transport_observations=[], contained_transport_observations=[])
    plane.update(runtime_prefix="/opt/guard-runtime", controller_identity={"pid": 501})
    command = ["/opt/guard-runtime/bin/python", "-I", "-B", "-m",
               "codex_plugin_scanner.cli", "guard", "execute-contained-test"]
    command_hash = hashlib.sha256(b"\0".join(item.encode() for item in command) + b"\0").hexdigest()
    sample = {"pid": 601, "identity": {"start_time": "42"},
              "command_sha256": command_hash}
    plane["observations"] = [{
        "kind": "actual-native-capture-failure", "exception_type": "InterruptedError",
        "kernel_process_samples": [sample], "command": command, "cell_closed": True,
    }]
    plane["executions"] = []
    control.update(cell_closed_before_explicit_teardown=True,
                   detached_child_alive_before_cell_teardown=False,
                   late_effect_present=False,
                   detached_child_samples=[{"pid": 601}])
    control["plane"] = copy.deepcopy(plane)
    resign(control)
    return control, expected, key


def cases() -> list[tuple[str, object]]:
    def plane(row):
        return row["developer_runtime"]["record"]["native_builtin_audit"]["record"]["product_plane"]

    def builtin(row):
        return row["developer_runtime"]["record"]["native_builtin_audit"]["record"]

    def runtime(row):
        return row["developer_runtime"]["record"]

    return [
        ("valid-cancel", lambda c: None),
        ("producer-passed-false-ignored", lambda c: c.update(passed=False)),
        ("setup-errors", lambda c: runtime(c).update(errors=["error"])),
        ("prompt-disallowed", lambda c: runtime(c).update(prompt_allowed=False)),
        ("missing-interruption", lambda c: plane(c)["observations"].clear()),
        ("wrong-exception", lambda c: plane(c)["observations"][0].update(exception_type="TimeoutError")),
        ("empty-kernel-samples", lambda c: plane(c)["observations"][0].update(kernel_process_samples=[])),
        ("duplicate-kernel-sample", lambda c: plane(c)["observations"][0]["kernel_process_samples"].append(
            copy.deepcopy(plane(c)["observations"][0]["kernel_process_samples"][0]))),
        ("wrong-command", lambda c: plane(c)["observations"][0]["command"].__setitem__(6, "other")),
        ("wrong-command-hash", lambda c: plane(c)["observations"][0]["kernel_process_samples"][0]
            .update(command_sha256="0" * 64)),
        ("missing-required-post", lambda c: builtin(c)["review_summary"]
            .update(missing_required_post_call_ids=[])),
        ("completed-execution", lambda c: plane(c)["executions"].append({"exit_code": 0})),
        ("cell-still-open", lambda c: plane(c)["observations"][0].update(cell_closed=False)),
        ("outside-cell-still-open", lambda c: c.update(cell_closed_before_explicit_teardown=False)),
        ("detached-child-survived", lambda c: c.update(detached_child_alive_before_cell_teardown=True)),
        ("late-effect", lambda c: c.update(late_effect_present=True)),
        ("no-detached-samples", lambda c: c.update(detached_child_samples=[])),
    ]


def run_python(source: str, custody: str, control: dict) -> tuple[bool, str | None]:
    function = extracted("_cancel", source)
    assert isinstance(function.body[1], ast.ImportFrom)
    assert function.body[1].module == "product_version"
    function.body[1] = ast.Pass()
    require = extracted("_require", custody)
    module = ast.fix_missing_locations(ast.Module(body=[require, function], type_ignores=[]))
    namespace = {
        "hashlib": hashlib,
        "version_options": lambda *_: {},
        "verify_product_audit": lambda *_a, **_kw: None,
        "verify_private_cell_plane": lambda *_a, **_kw: None,
        "_reviews": lambda *_a, **_kw: None,
        "_kernel": lambda *_a, **_kw: None,
        "review_summary": lambda *_a: copy.deepcopy(SUMMARY),
    }
    exec(compile(module, "local_executor_controls._cancel", "exec"), namespace)
    record = control["developer_runtime"]["record"]
    builtin = record["native_builtin_audit"]["record"]
    plane = builtin["product_plane"]
    observation = control["sdk_gate"]["observation"]
    options = {
        "expected_settings": record["settings"],
        "agent_identity": control["agent_identity"],
        "workspace_source": plane["task_mounts"][0]["source"],
        "provider_mounts": tuple(row["source"] for row in plane["task_mounts"][1:]),
        "sdk_pid": observation["pid"],
        "sdk_identity": observation["identity"],
    }
    try:
        namespace["_cancel"](control, record, builtin, plane, bytes.fromhex(control["controller_public_key_hex"]), options)
    except ValueError as error:
        return False, str(error)
    return True, None


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--custody", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    source = args.source.read_text(encoding="utf-8")
    custody = args.custody.read_text(encoding="utf-8")
    base, expected, key = base_case()
    rows = []
    for name, mutate in cases():
        control = copy.deepcopy(base)
        mutate(control)
        control["plane"] = copy.deepcopy(
            control["developer_runtime"]["record"]["native_builtin_audit"]["record"]["product_plane"]
        )
        resign(control)
        accepted, error = run_python(source, custody, control)
        patch = merge_delta(base, control)
        assert canonical_json(apply_merge_delta(base, patch)) == canonical_json(control)
        row = {"name": name, "control_patch": patch, "accepted": accepted}
        if error is not None:
            row["error"] = error
        rows.append(row)
    assert sum(row["accepted"] for row in rows) == 2
    assert len(rows) == 17
    args.out.write_text(json.dumps({
        "schema": "gauntlet-cancel-reported-fixtures.v1",
        "source_sha256": hashlib.sha256(args.source.read_bytes()).hexdigest(),
        "custody_sha256": hashlib.sha256(args.custody.read_bytes()).hexdigest(),
        "ast_function": "_cancel (relative version_options import replaced by a fixed stub)",
        "stubs": ["verify_product_audit", "verify_private_cell_plane", "_reviews", "_kernel",
                  "review_summary", "version_options"],
        "outside_review_summary": SUMMARY,
        "base": {"control": base, "expected": expected, "public_key_hex": key},
        "cases": rows,
    }, sort_keys=True, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
