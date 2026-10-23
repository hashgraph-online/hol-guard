"""Freeze the exact Python private-runtime contained-result loop as data cases.

AST extraction runs only the named pure result loop. It never imports a product
or runs a controller, contained command, provider, or model.
"""

from __future__ import annotations

import ast
from copy import deepcopy
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys

ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / "ci/gauntlet/benchmark/private_cell_runtime_custody.py"
OUTPUT = ROOT / "ci/gauntlet-rs/crates/gauntlet-evidence/tests/fixtures/contained_cli_results_v1.json"
sys.path.insert(0, str(ROOT))


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def result_loop():
    tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
    function = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                    and node.name == "verify_private_cell_runtime")
    loops = [node for node in ast.walk(function) if isinstance(node, ast.For)
             and isinstance(node.target, ast.Name) and node.target.id == "result"
             and isinstance(node.iter, ast.Subscript)
             and isinstance(node.iter.value, ast.Name) and node.iter.value.id == "plane"]
    if len(loops) != 1:
        raise ValueError("expected exactly one source contained-result loop")
    return compile(ast.fix_missing_locations(ast.Module(body=loops, type_ignores=[])),
                   str(SOURCE), "exec")


def base_case() -> dict:
    settings = {"package_version": "3.49.0"}
    controller = {"boot_id": "boot-A", "mount_namespace": "mnt:[10]",
                  "pid_namespace": "pid:[10]", "network_namespace": "net:[10]"}
    agent = {"mount_namespace": "mnt:[20]", "pid_namespace": "pid:[20]",
             "network_namespace": "net:[20]"}
    request_sha = "a" * 64
    command = ["/opt/guard/bin/python", "-I", "-B", "-m", "codex_plugin_scanner.cli",
               "guard", "execute-contained-test", "--harness", "omp", "--guard-home",
               "/product/guard", "--home", "/runtime/home", "--workspace", "/workspace",
               "--request-file", "/product/home/tx-1/request.json", "--request-sha256",
               request_sha, "--timeout-seconds", "60"]
    command_sha = hashlib.sha256(b"\0".join(part.encode() for part in command) + b"\0").hexdigest()
    sample = {"command_sha256": command_sha, "user_namespace": "user:[30]",
              "identity": {"effective_uid": 10004, "effective_gid": 10004,
                           "no_new_privileges": 1, "boot_id": "boot-A",
                           "effective_capabilities": "0000000000000000",
                           "mount_namespace": "mnt:[30]", "pid_namespace": "pid:[30]",
                           "network_namespace": "net:[30]"}}
    execution = {"native_command": command, "request_sha256": request_sha,
                 "exit_code": 0, "stdout": "completed\n", "stderr": "",
                 "stdout_sha256": hashlib.sha256(b"completed\n").hexdigest(),
                 "stderr_sha256": hashlib.sha256(b"").hexdigest(),
                 "product_claims_authenticated": False,
                 "containment_conformance_established": False,
                 "kernel_process_samples": [sample]}
    plane = {"runtime_prefix": "/opt/guard", "workspace_path": "/workspace",
             "controller_identity": controller, "product_user_namespace": "user:[30]",
             "executions": [execution]}
    return {"plane": plane, "settings": settings, "agent_identity": agent}


def cases():
    base = base_case()
    yield "valid-release-result", base

    def altered(name, edit):
        row = deepcopy(base)
        edit(row, row["plane"]["executions"][0], row["plane"]["executions"][0]["kernel_process_samples"][0])
        return name, row

    yield altered("wrong-python", lambda _, result, __: result["native_command"].__setitem__(0, "/tmp/python"))
    yield altered("wrong-switch", lambda _, result, __: result["native_command"].__setitem__(7, "--arbitrary"))
    yield altered("wrong-workspace", lambda _, result, __: result["native_command"].__setitem__(14, "/other"))
    yield altered("traversal-request", lambda _, result, __: result["native_command"].__setitem__(16, "/product/home/../request.json"))
    yield altered("wrong-request-digest", lambda _, result, __: result.__setitem__("request_sha256", "b" * 64))
    yield altered("zero-deadline", lambda _, result, __: result["native_command"].__setitem__(20, "0"))
    yield altered("long-deadline", lambda _, result, __: result["native_command"].__setitem__(20, "901"))
    yield altered("boolean-exit", lambda _, result, __: result.__setitem__("exit_code", True))
    yield altered("changed-stdout", lambda _, result, __: result.__setitem__("stdout", "changed"))
    yield altered("changed-stderr", lambda _, result, __: result.__setitem__("stderr", "error"))
    yield altered("promoted-product-claim", lambda _, result, __: result.__setitem__("product_claims_authenticated", True))
    yield altered("missing-samples", lambda _, result, __: result.__setitem__("kernel_process_samples", []))
    yield altered("unmatched-command-sample", lambda _, __, sample: sample.__setitem__("command_sha256", "0" * 64))
    yield altered("root-sample", lambda _, __, sample: sample["identity"].__setitem__("effective_uid", 0))
    yield altered("missing-no-new-privileges", lambda _, __, sample: sample["identity"].__setitem__("no_new_privileges", 0))
    yield altered("other-boot", lambda _, __, sample: sample["identity"].__setitem__("boot_id", "boot-B"))
    yield altered("agent-mount-namespace", lambda row, __, sample: sample["identity"].__setitem__("mount_namespace", row["agent_identity"]["mount_namespace"]))
    yield altered("nonzero-capabilities-in-product-userns", lambda _, __, sample: sample["identity"].__setitem__("effective_capabilities", "0000000000000001"))
    yield altered("release-home-swapped", lambda _, result, __: result["native_command"].__setitem__(12, "/product/home"))
    yield altered("truncated-command", lambda _, result, __: result["native_command"].pop())
    yield altered("new-userns-with-capability", lambda row, __, sample: (
        sample["identity"].__setitem__("effective_capabilities", "0000000000000001"),
        sample.__setitem__("user_namespace", "user:[40]")))
    yield altered("unrelated-descendant-sample", lambda _, result, sample: result["kernel_process_samples"].append({
        **deepcopy(sample), "command_sha256": "0" * 64}))
    yield altered("zero-capability-without-userns", lambda _, __, sample: sample.pop("user_namespace"))
    empty = deepcopy(base)
    empty["plane"]["executions"] = []
    yield "zero-results-loop-only", empty
    legacy = deepcopy(base)
    legacy["settings"] = {}
    legacy["plane"]["executions"][0]["native_command"][12] = "/product/home"
    command = legacy["plane"]["executions"][0]["native_command"]
    legacy["plane"]["executions"][0]["kernel_process_samples"][0]["command_sha256"] = (
        hashlib.sha256(b"\0".join(part.encode() for part in command) + b"\0").hexdigest())
    yield "valid-legacy-home", legacy


def main() -> None:
    loop = result_loop()
    rows = []
    for name, row in cases():
        scope = {"plane": row["plane"], "expected_settings": row["settings"],
                 "agent_identity": row["agent_identity"],
                 "__package__": "ci.gauntlet.benchmark", "_require": require,
                 "PurePosixPath": PurePosixPath, "hashlib": hashlib, "re": re}
        try:
            exec(loop, scope)
            accepted, reason = True, None
        except Exception as error:
            accepted, reason = False, str(error)
        rows.append({"name": name, **row, "accepted": accepted, "reason": reason})
    OUTPUT.write_text(json.dumps({"schema": "gauntlet-python-contained-cli-results.v1",
                                  "source_sha256": hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
                                  "cases": rows}, sort_keys=True, separators=(",", ":")) + "\n",
                      encoding="utf-8")
    print(f"frozen {len(rows)} exact-source Python contained CLI result cases: "
          f"{sum(row['accepted'] for row in rows)} accepted")


if __name__ == "__main__":
    main()
