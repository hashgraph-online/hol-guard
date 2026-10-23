"""Freeze the exact opening AST of Python verify_control with synthetic records.

Run with system Python containing cryptography 41+; no controller, product or
model code is imported or executed. The AST stops before session/path checks.
"""
from __future__ import annotations

import argparse
import ast
import base64
import copy
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def extracted(name, source):
    tree = ast.parse(source)
    return copy.deepcopy(next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == name))


def opening_function(source):
    function = extracted("verify_control", source)
    assert "session = record['controller_session_id']" in ast.unparse(function.body[17])
    function.name = "verify_opening"
    function.body = function.body[1:17] + [ast.Return(value=ast.parse(
        "{'runtime': record, 'builtin': builtin, 'settings': settings, 'plane': plane}"
    ).body[0].value)]
    function.decorator_list = []
    return ast.fix_missing_locations(ast.Module(body=[function], type_ignores=[]))


def private_key():
    return Ed25519PrivateKey.from_private_bytes(bytes([7]) * 32)


def signed(record):
    signature = private_key().sign(canonical_json(record).encode())
    return {"record": record, "signature": base64.b64encode(signature).decode()}


def base_case():
    expected = {
        "source_sha": "source", "prefix_digest": "prefix", "bwrap_sha256": "bwrap",
        "executor_image_id": "executor", "mcp_image_id": "mcp", "package_version": "3.50.0a0",
        "private_cell": {
            "artifact_manifest_sha256": "artifacts", "initializer_sha256": "initializer",
            "native_sha256": "native", "runtime_tree_digest": "runtime",
            "idmap_runtime": "ubuntu2404-product-v1", "cpu_profile": "quota-v1",
        },
    }
    settings = copy.deepcopy(expected)
    settings["contained_output_binding"] = "controller-contained-output.v1"
    settings["contained_completion_profile"] = "guard-contained-completion.v1"
    plane = {"synthetic_plane": 73}
    runtime = {"schema_version": "5.0", "settings": settings,
               "native_builtin_audit": signed({"product_plane": plane})}
    public_key = private_key().public_key().public_bytes_raw().hex()
    control = {
        "control_completed": True, "sdk_exercised": True, "model_exercised": False,
        "root_imported_product": False, "image_released": True,
        "agent_cgroup_absent": True, "agent_profile_removed": True,
        "agent_remove_returncode": 0, "controller_public_key_hex": public_key,
        "developer_runtime": signed(runtime), "plane": plane, "passed": True,
    }
    return control, expected, public_key


def cases():
    result = []
    def add(name, mutate=None, role="success"):
        control, expected, public_key = base_case()
        if mutate is not None:
            mutate(control, expected)
        result.append({"name": name, "role": role, "control": control,
                       "expected": expected, "public_key_hex": public_key})

    add("valid-success")
    add("valid-timeout", role="timeout")
    add("valid-input-binding", role="input-binding")
    def valid_v4(control, expected):
        expected.pop("package_version")
        runtime = control["developer_runtime"]["record"]
        runtime["settings"].pop("package_version")
        runtime["schema_version"] = "4.0"
        control["developer_runtime"] = signed(runtime)
    add("valid-v4-without-package-version", valid_v4)
    add("unknown-role", role="injection")
    add("control-not-complete", lambda c, e: c.update(control_completed=False))
    add("sdk-not-exercised", lambda c, e: c.update(sdk_exercised=False))
    add("model-exercised", lambda c, e: c.update(model_exercised=True))
    add("root-imported", lambda c, e: c.update(root_imported_product=True))
    add("cleanup-error", lambda c, e: c.update(cleanup_error="synthetic"))
    add("image-not-released", lambda c, e: c.update(image_released=False))
    add("agent-cgroup-present", lambda c, e: c.update(agent_cgroup_absent=False))
    add("profile-present", lambda c, e: c.update(agent_profile_removed=False))
    add("remove-failed", lambda c, e: c.update(agent_remove_returncode=1))
    add("key-mismatch", lambda c, e: c.update(controller_public_key_hex="00" * 32))
    add("runtime-tampered", lambda c, e: c["developer_runtime"]["record"]["settings"].update(source_sha="other"))
    add("source-pin-mismatch", lambda c, e: e.update(source_sha="other"))
    add("version-pin-mismatch", lambda c, e: e.update(package_version="other"))
    add("backend-pin-mismatch", lambda c, e: e["private_cell"].update(native_sha256="other"))
    add("plane-mismatch", lambda c, e: c.update(plane={"synthetic_plane": 74}))
    def builtin_tampered(control, _expected):
        runtime = control["developer_runtime"]["record"]
        runtime["native_builtin_audit"]["record"]["product_plane"] = {"synthetic_plane": 74}
        control["developer_runtime"] = signed(runtime)
    add("builtin-tampered", builtin_tampered)
    def profile_mismatch(control, _expected):
        runtime = control["developer_runtime"]["record"]
        runtime["settings"]["contained_output_binding"] = "other"
        control["developer_runtime"] = signed(runtime)
    add("profile-mismatch", profile_mismatch)
    add("schema-version-mismatch", lambda c, e: e.pop("package_version"))
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--custody", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    source = args.source.read_text()
    custody = args.custody.read_text()
    require_fn = extracted("_require", custody)
    signed_fn = extracted("_signed", custody)
    module = ast.fix_missing_locations(ast.Module(body=[require_fn, signed_fn], type_ignores=[]))
    namespace = {"base64": base64, "canonical_json": canonical_json,
                 "Ed25519PublicKey": Ed25519PublicKey,
                 "ROLES": {"success", "timeout", "cancel", "input-binding", "boundary"}}
    exec(compile(module, str(args.custody), "exec"), namespace)
    exec(compile(opening_function(source), str(args.source), "exec"), namespace)
    rows = cases()
    for row in rows:
        try:
            observed = namespace["verify_opening"](row["role"], row["control"],
                public_key=row["public_key_hex"], expected=row["expected"])
        except ValueError as error:
            row["accepted"] = False
            row["error"] = str(error)
        else:
            row["accepted"] = True
            row["result"] = observed
    fixture = {"schema": "gauntlet-control-opening-fixtures.v1",
               "source_sha256": hashlib.sha256(args.source.read_bytes()).hexdigest(),
               "custody_sha256": hashlib.sha256(args.custody.read_bytes()).hexdigest(),
               "ast_statements": "verify_control body[1:17]",
               "cases": rows}
    args.out.write_text(json.dumps(fixture, sort_keys=True, indent=2) + "\n")


if __name__ == "__main__":
    main()
