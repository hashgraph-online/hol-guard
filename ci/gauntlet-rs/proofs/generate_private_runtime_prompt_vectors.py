"""Freeze the signed public-prompt relation in Python private runtime custody.

The extracted AST is the real Python relation. Its native `_hook` call is
deliberately stubbed: these vectors do not establish a kernel-observed hook.
"""

from __future__ import annotations

import ast
import base64
from copy import deepcopy
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / "ci/gauntlet/benchmark/private_cell_runtime_custody.py"
CUSTODY = ROOT / "ci/gauntlet/benchmark/developer_product_custody.py"
OUTPUT = ROOT / "ci/gauntlet-rs/crates/gauntlet-evidence/tests/fixtures/private_runtime_prompt_v1.json"
KEY = Ed25519PrivateKey.from_private_bytes(bytes([23]) * 32)
PUBLIC = KEY.public_key().public_bytes_raw()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def signed(record):
    return {"record": record, "signature": base64.b64encode(KEY.sign(canonical(record).encode())).decode()}


def source_block():
    tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
    function = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                    and node.name == "verify_private_cell_runtime")
    body = function.body
    starts = [index for index, node in enumerate(body) if isinstance(node, ast.Expr)
              and isinstance(node.value, ast.Call)
              and len(node.value.args) == 2
              and isinstance(node.value.args[1], ast.Constant)
              and node.value.args[1].value == "exact normal MCP task context required"]
    ends = [index for index, node in enumerate(body) if isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Call)
            and len(node.value.args) == 2
            and isinstance(node.value.args[1], ast.Constant)
            and node.value.args[1].value == "builtin task prompt lacks matching actual native admission"]
    if len(starts) != 1 or len(ends) != 1 or ends[0] - starts[0] != 10:
        raise ValueError("private runtime public-prompt source block changed")
    return compile(ast.fix_missing_locations(ast.Module(body=body[starts[0]:ends[0] + 1],
                                                type_ignores=[])), str(SOURCE), "exec")


def signed_reader():
    tree = ast.parse(CUSTODY.read_text(encoding="utf-8"))
    names = {"_require", "_signed"}
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
    if {node.name for node in functions} != names:
        raise ValueError("signed reader changed")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    scope = {"base64": base64, "canonical_json": canonical,
             "Ed25519PublicKey": Ed25519PublicKey}
    exec(compile(ast.fix_missing_locations(ast.Module(body=functions, type_ignores=[])),
                 str(CUSTODY), "exec"), scope)
    return scope


def base():
    session = "session-123"
    prompt = "Review the public task"
    prompt_digest = digest(prompt)
    actor = {"boot_id": "boot-1", "mount_namespace": "mnt-1",
             "pid_namespace": "pid-1", "network_namespace": "net-1"}
    hook = {"identity": deepcopy(actor), "response": {"decision": "allow"}}
    context = {"phase": "developer", "public_prompt_digest": prompt_digest,
               "public_prompt": prompt, "hooks": [hook]}
    payload = {"hook_event_name": "UserPromptSubmit", "prompt": prompt,
               "config_path": "/product/home/omp.json", "session_id": session}
    payload_digest = digest(payload)
    builtin = {"product_plane": {"controller_identity": {"boot_id": "boot-1"},
                                  "hooks": [{"payload_digest": payload_digest,
                                             "response_digest": "response-1"}]},
               "transport_observations": [{"kind": "actual-user-prompt-response",
                                           "payload_digest": payload_digest,
                                           "response_digest": "response-1",
                                           "product_response": {"decision": "allow"}}]}
    mcp = {"product_plane": {"controller_identity": {"boot_id": "boot-1"},
                             "observations": [{"kind": "container-boundary", "identity": actor}]}}
    record = {"native_task_contexts": [signed(context)],
              "native_builtin_audit": signed(builtin), "native_mcp_audit": signed(mcp)}
    return {"runtime": signed(record), "session_id": session,
            "prompt_digest": prompt_digest, "public_key_hex": PUBLIC.hex()}


def cases():
    row = base()
    yield "valid", row

    def altered(name, edit, resign=False):
        value = deepcopy(row)
        edit(value)
        if resign:
            record = value["runtime"]["record"]
            record["native_builtin_audit"] = signed(record["native_builtin_audit"]["record"])
            record["native_mcp_audit"] = signed(record["native_mcp_audit"]["record"])
            record["native_task_contexts"] = [signed(item["record"]) for item in record["native_task_contexts"]]
            value["runtime"] = signed(record)
        return name, value

    def record(value):
        return value["runtime"]["record"]

    def context(value):
        return record(value)["native_task_contexts"][0]["record"]

    def builtin(value):
        return record(value)["native_builtin_audit"]["record"]

    def mcp(value):
        return record(value)["native_mcp_audit"]["record"]

    yield altered("valid-unrelated-transport", lambda v: builtin(v)["transport_observations"].append(
        {"kind": "peer-authenticated"}), True)
    yield altered("valid-extra-native-hook", lambda v: builtin(v)["product_plane"]["hooks"].append(
        {"payload_digest": "other", "response_digest": "other"}), True)
    yield altered("missing-context", lambda v: record(v).update(native_task_contexts=[]), True)
    yield altered("duplicate-context", lambda v: record(v)["native_task_contexts"].append(
        deepcopy(record(v)["native_task_contexts"][0])), True)
    yield altered("wrong-phase", lambda v: context(v).update(phase="system"), True)
    yield altered("wrong-outside-prompt", lambda v: v.update(prompt_digest="0" * 64))
    yield altered("changed-prompt-text", lambda v: context(v).update(public_prompt="other"), True)
    yield altered("missing-hook", lambda v: context(v).update(hooks=[]), True)
    yield altered("hook-denied", lambda v: context(v)["hooks"][0]["response"].update(decision="deny"), True)
    yield altered("mcp-boundary-mismatch", lambda v: context(v)["hooks"][0]["identity"].update(
        pid_namespace="pid-other"), True)
    yield altered("missing-prompt-response", lambda v: builtin(v).update(transport_observations=[]), True)
    yield altered("duplicate-prompt-response", lambda v: builtin(v)["transport_observations"].append(
        deepcopy(builtin(v)["transport_observations"][0])), True)
    yield altered("wrong-payload-digest", lambda v: builtin(v)["transport_observations"][0].update(
        payload_digest="0" * 64), True)
    yield altered("builtin-response-denied", lambda v: builtin(v)["transport_observations"][0][
        "product_response"].update(decision="deny"), True)
    yield altered("unmatched-native-hook", lambda v: builtin(v)["product_plane"]["hooks"][0].update(
        response_digest="wrong"), True)
    yield altered("context-signature-tampered", lambda v: context(v).update(phase="system"))
    yield altered("runtime-signature-tampered", lambda v: record(v).update(extra=1))
    yield altered("wrong-outside-key", lambda v: v.update(public_key_hex="0" * 64))
    yield altered("wrong-session", lambda v: v.update(session_id="other"))
    yield altered("mcp-signature-tampered", lambda v: mcp(v)["product_plane"].update(extra=1))
    yield altered("builtin-signature-tampered", lambda v: builtin(v).update(extra=1))


def main():
    block = source_block()
    scope = signed_reader()
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    rows = []
    for name, value in cases():
        try:
            key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(value["public_key_hex"]))
            record = scope["_signed"](value["runtime"], key)
            builtin = scope["_signed"](record["native_builtin_audit"], key)
            mcp = scope["_signed"](record["native_mcp_audit"], key)
            plane = builtin["product_plane"]
            assert mcp["product_plane"]["controller_identity"] == plane["controller_identity"]
            local = {**scope, "record": record, "builtin": builtin, "plane": plane,
                     "key": key, "expected_session_id": value["session_id"],
                     "expected_prompt_digest": value["prompt_digest"],
                     "agent_identity": {}, "digest": digest,
                     "_hook": lambda hook, *_a, **_kw: hook["response"]}
            exec(block, local)
            accepted, reason = True, None
        except ValueError as error:
            accepted, reason = False, str(error)
        rows.append({"name": name, **value, "accepted": accepted, "reason": reason})
    OUTPUT.write_text(json.dumps({"schema": "gauntlet-python-private-runtime-prompt.v1",
                                  "source_sha256": hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
                                  "custody_sha256": hashlib.sha256(CUSTODY.read_bytes()).hexdigest(),
                                  "stubbed": ["_hook", "verify_product_audit", "verify_private_cell_plane"],
                                  "cases": rows}, sort_keys=True, separators=(",", ":")) + "\n",
                      encoding="utf-8")
    print(f"frozen {len(rows)} Python private prompt cases: "
          f"{sum(row['accepted'] for row in rows)} accepted")


if __name__ == "__main__":
    main()
