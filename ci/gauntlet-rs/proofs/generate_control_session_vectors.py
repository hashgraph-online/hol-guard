"""Freeze Python verify_control through session paths and SDK pre-import flags.

This extracts only body[1:28]. It signs synthetic records and does not import
the controller, SDK or product, or execute a benchmark.
"""

from __future__ import annotations

import argparse
import ast
import base64
import copy
import hashlib
import json
from pathlib import Path, PurePosixPath

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from generate_control_opening_vectors import base_case, canonical_json, extracted, signed


SESSION = "session-001"
ROOT = "/tmp/gauntlet/" + SESSION


def extracted_session(source: str) -> ast.Module:
    function = extracted("verify_control", source)
    assert "if role == 'success'" in ast.unparse(function.body[28])
    function.name = "verify_session_opening"
    function.body = function.body[1:28] + [ast.Return(value=ast.parse(
        "{'session_id': session, 'workspace_source': workspace, "
        "'provider_mounts': providers, 'sdk_observation': observation, "
        "'agent_identity': options['agent_identity'], "
        "'public_prompt_digest': options['expected_prompt_digest']}"
    ).body[0].value)]
    function.decorator_list = []
    return ast.fix_missing_locations(ast.Module(body=[function], type_ignores=[]))


def resign(control: dict) -> None:
    runtime = control["developer_runtime"]["record"]
    runtime["native_builtin_audit"] = signed(runtime["native_builtin_audit"]["record"])
    control["developer_runtime"] = signed(runtime)


def base_session_case() -> tuple[dict, dict, str]:
    control, expected, key = base_case()
    plane = {
        "workspace_path": "/runtime/home/project",
        "task_mounts": [
            {"source": ROOT + "/tasks/checkout", "destination": "/runtime/home/project"},
            {"source": ROOT + "/tasks/remote", "destination": "/runtime/home/remote"},
            {"source": ROOT + "/tasks/home", "destination": "/runtime/home/home"},
        ],
    }
    runtime = control["developer_runtime"]["record"]
    runtime["controller_session_id"] = SESSION
    runtime["public_prompt_digest"] = "a" * 64
    runtime["native_builtin_audit"]["record"]["product_plane"] = plane
    control["plane"] = copy.deepcopy(plane)
    control["sdk_gate"] = {
        "cleanup_complete": True, "error": None,
        "observation": {
            "kernel_peer_authenticated": True, "bound_before_sdk_import": True,
            "pid": 217, "identity": {"pid": 217, "start_time": "42"},
        },
    }
    control["agent_identity"] = {"pid": 301}
    resign(control)
    return control, expected, key


def cases() -> list[dict]:
    rows = []

    def add(name: str, mutate=None, role: str = "success") -> None:
        control, expected, key = base_session_case()
        if mutate is not None:
            mutate(control, expected)
        resign(control)
        rows.append({"name": name, "role": role, "control": control,
                     "expected": expected, "public_key_hex": key})

    for role in ("success", "timeout", "cancel", "input-binding", "boundary"):
        add("valid-" + role, role=role)

    def valid_v4(control: dict, expected: dict) -> None:
        expected.pop("package_version")
        runtime = control["developer_runtime"]["record"]
        runtime["settings"].pop("package_version")
        runtime["schema_version"] = "4.0"
    add("valid-v4", valid_v4)

    def wrong_session(control: dict, _expected: dict) -> None:
        control["developer_runtime"]["record"]["controller_session_id"] = "other"
    add("wrong-session", wrong_session)

    def parent_traversal(control: dict, _expected: dict) -> None:
        plane = control["developer_runtime"]["record"]["native_builtin_audit"]["record"]["product_plane"]
        plane["task_mounts"][0]["source"] = ROOT + "/../" + SESSION + "/tasks/checkout"
        control["plane"] = copy.deepcopy(plane)
    add("parent-traversal", parent_traversal)

    def wrong_checkout(control: dict, _expected: dict) -> None:
        plane = control["developer_runtime"]["record"]["native_builtin_audit"]["record"]["product_plane"]
        plane["task_mounts"][0]["source"] = ROOT + "/tasks/other"
        control["plane"] = copy.deepcopy(plane)
    add("wrong-checkout", wrong_checkout)

    def wrong_remote(control: dict, _expected: dict) -> None:
        plane = control["developer_runtime"]["record"]["native_builtin_audit"]["record"]["product_plane"]
        plane["task_mounts"][1]["source"] = ROOT + "/tasks/unrelated"
        control["plane"] = copy.deepcopy(plane)
    add("wrong-remote", wrong_remote)

    def missing_home(control: dict, _expected: dict) -> None:
        plane = control["developer_runtime"]["record"]["native_builtin_audit"]["record"]["product_plane"]
        plane["task_mounts"].pop()
        control["plane"] = copy.deepcopy(plane)
    add("missing-home", missing_home)

    add("sdk-cleanup-incomplete", lambda c, e: c["sdk_gate"].update(cleanup_complete=False))
    add("sdk-error", lambda c, e: c["sdk_gate"].update(error="failure"))
    add("peer-unauthenticated", lambda c, e: c["sdk_gate"]["observation"].update(kernel_peer_authenticated=False))
    add("post-import-binding", lambda c, e: c["sdk_gate"]["observation"].update(bound_before_sdk_import=False))
    return rows


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--custody", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    source = args.source.read_text(encoding="utf-8")
    custody = args.custody.read_text(encoding="utf-8")
    require_fn = extracted("_require", custody)
    signed_fn = extracted("_signed", custody)
    module = ast.fix_missing_locations(ast.Module(body=[require_fn, signed_fn], type_ignores=[]))
    namespace = {
        "base64": base64, "canonical_json": canonical_json,
        "Ed25519PublicKey": Ed25519PublicKey, "PurePosixPath": PurePosixPath,
        "ROLES": {"success", "timeout", "cancel", "input-binding", "boundary"},
    }
    exec(compile(module, str(args.custody), "exec"), namespace)
    exec(compile(extracted_session(source), str(args.source), "exec"), namespace)
    rows = cases()
    for row in rows:
        try:
            result = namespace["verify_session_opening"](
                row["role"], row["control"], public_key=row["public_key_hex"], expected=row["expected"]
            )
        except ValueError as error:
            row["accepted"] = False
            row["error"] = str(error)
        else:
            row["accepted"] = True
            row["result"] = result
    args.out.write_text(json.dumps({
        "schema": "gauntlet-control-session-fixtures.v1",
        "source_sha256": hashlib.sha256(args.source.read_bytes()).hexdigest(),
        "custody_sha256": hashlib.sha256(args.custody.read_bytes()).hexdigest(),
        "ast_statements": "verify_control body[1:28]",
        "cases": rows,
    }, sort_keys=True, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
