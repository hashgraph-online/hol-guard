"""Freeze Python SDK peer, Native transport and operation-accounting relations."""

from __future__ import annotations

import ast
from collections import Counter
from copy import deepcopy
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / "ci/gauntlet/benchmark/developer_product_custody.py"
OUTPUT = ROOT / "ci/gauntlet-rs/crates/gauntlet-evidence/tests/fixtures/native_transport_v1.json"


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def source_functions():
    tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
    names = {"_require", "_reviews", "_operations"}
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
    if {node.name for node in functions} != names:
        raise ValueError("Native transport source functions changed")
    scope = {"Counter": Counter, "digest": digest}
    exec(compile(ast.fix_missing_locations(ast.Module(body=functions, type_ignores=[])),
                 str(SOURCE), "exec"), scope)
    return scope


def base():
    sdk_identity = {"pid_namespace": "sdk-net", "effective_uid": 10001}
    pre_response = {"decision": "allow"}
    post_response = {"decision": "allow", "model_output_action": "allow_original",
                     "reviewed_output_sha256": "c" * 64}
    pre = {"kind": "actual-hook-response", "hook_event_name": "PreToolUse",
           "tool_name": "bash", "tool_call_id": "call-1", "original_input_digest": "a" * 64,
           "payload_digest": "1" * 64, "response_digest": digest(pre_response),
           "product_response": pre_response}
    post = {"kind": "actual-hook-response", "hook_event_name": "PostToolUse",
            "tool_name": "bash", "tool_call_id": "call-1", "original_input_digest": "a" * 64,
            "actual_output_sha256": "c" * 64, "payload_digest": "2" * 64,
            "response_digest": digest(post_response), "product_response": post_response}
    builtin = {"transport_observations": [
        {"kind": "peer-authenticated", "peer_pid": 101, "peer_uid": 10001,
         "identity": deepcopy(sdk_identity)},
        {"kind": "peer-authenticated", "peer_pid": 101, "peer_uid": 10001,
         "identity": deepcopy(sdk_identity)}, pre, post]}
    plane = {"hooks": [
        {"payload_digest": pre["payload_digest"], "response_digest": pre["response_digest"]},
        {"payload_digest": post["payload_digest"], "response_digest": post["response_digest"]}]}
    record = {"settings": {"max_tool_calls": 2}, "operations": {"maximum": 2, "admitted": 1,
              "events": [{"sequence": 1, "source": "sdk-builtin",
                          "request_digest": pre["payload_digest"], "admitted": True}]},
              "native_mcp_audit": {"record": {"transport_observations": []}}}
    return {"builtin": builtin, "plane": plane, "record": record,
            "sdk_pid": 101, "sdk_identity": sdk_identity, "require_sdk": True}


def cases():
    root = base()
    yield "valid", root

    def altered(name, edit):
        row = deepcopy(root)
        edit(row)
        return name, row

    def events(row):
        return row["builtin"]["transport_observations"]

    def pre(row):
        return events(row)[2]

    def post(row):
        return events(row)[3]

    def operations(row):
        return row["record"]["operations"]

    yield altered("peer-not-required", lambda row: (row.update(require_sdk=False), events(row).pop(0), events(row).pop(0)))
    yield altered("missing-peer", lambda row: events(row).pop(0))
    yield altered("wrong-peer-pid", lambda row: events(row)[0].update(peer_pid=102))
    yield altered("wrong-peer-uid", lambda row: events(row)[0].update(peer_uid=0))
    yield altered("wrong-peer-identity", lambda row: events(row)[0].update(identity={"other": 1}))
    yield altered("wrong-hook-event", lambda row: pre(row).update(hook_event_name="UserPromptSubmit"))
    yield altered("wrong-tool", lambda row: pre(row).update(tool_name="other"))
    yield altered("native-hook-unmatched", lambda row: row["plane"]["hooks"].pop(0))
    yield altered("response-digest-mismatch", lambda row: pre(row).update(response_digest="0" * 64))
    yield altered("changed-pre-input", lambda row: (events(row).insert(3, deepcopy(pre(row))),
        events(row)[3].update(original_input_digest="b" * 64),
        events(row).append(deepcopy(events(row)[0])),
        row["plane"]["hooks"].append(deepcopy(row["plane"]["hooks"][0]))))
    yield altered("post-without-pre", lambda row: events(row).pop(2))
    yield altered("post-input-mismatch", lambda row: post(row).update(original_input_digest="b" * 64))
    yield altered("post-output-short", lambda row: post(row).update(actual_output_sha256="short"))
    yield altered("post-reviewed-output-mismatch", lambda row: (
        post(row)["product_response"].update(reviewed_output_sha256="d" * 64),
        post(row).update(response_digest=digest(post(row)["product_response"])),
        row["plane"]["hooks"][1].update(response_digest=post(row)["response_digest"])))
    yield altered("maximum-mismatch", lambda row: operations(row).update(maximum=3))
    yield altered("admitted-mismatch", lambda row: operations(row).update(admitted=2))
    yield altered("too-many-operations", lambda row: operations(row)["events"].extend(
        {"sequence": index, "source": "sdk-builtin", "request_digest": "other", "admitted": False}
        for index in (2, 3, 4)))
    yield altered("sequence-gap", lambda row: operations(row)["events"][0].update(sequence=2))
    yield altered("wrong-source", lambda row: operations(row)["events"][0].update(source="other"))
    yield altered("non-bool-admitted", lambda row: operations(row)["events"][0].update(admitted=1))
    yield altered("missing-operation", lambda row: operations(row).update(events=[]))
    yield altered("unadmitted-pre", lambda row: operations(row)["events"][0].update(admitted=False))
    yield altered("wrong-request-digest", lambda row: operations(row)["events"][0].update(request_digest="0" * 64))
    yield altered("valid-denied-operation", lambda row: (operations(row)["events"].append(
        {"sequence": 2, "source": "native-mcp", "request_digest": "unrelated", "admitted": False})))
    def mcp_forwarded(row):
        request = {"kind": "forwarded", "family": "tool", "session_id": "mcp-session",
                   "message": {"method": "tools/call", "params": {"name": "probe"}}}
        row["record"]["native_mcp_audit"]["record"]["transport_observations"].append(request)
        row["record"]["operations"]["events"].append(
            {"sequence": 2, "source": "native-mcp", "request_digest": digest({
                "family": request["family"], "session_id": request["session_id"],
                "message": request["message"]}), "admitted": True})
        row["record"]["operations"]["admitted"] = 2
    yield altered("valid-mcp-forwarded", mcp_forwarded)
    yield altered("wrong-mcp-forwarded-digest", lambda row: (
        mcp_forwarded(row), operations(row)["events"][1].update(request_digest="0" * 64)))


def main():
    scope = source_functions()
    rows = []
    for name, row in cases():
        try:
            reviews = scope["_reviews"](row["builtin"], row["plane"],
                                        sdk_pid=row["sdk_pid"], sdk_identity=row["sdk_identity"],
                                        require_sdk=row["require_sdk"])
            scope["_operations"](row["record"], reviews)
            accepted, reason = True, None
        except (ValueError, KeyError, TypeError, IndexError) as error:
            accepted, reason = False, str(error)
        rows.append({"name": name, **row, "accepted": accepted, "reason": reason})
    OUTPUT.write_text(json.dumps({"schema": "gauntlet-python-native-transport.v1",
                                  "source_sha256": hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
                                  "cases": rows}, sort_keys=True, separators=(",", ":")) + "\n",
                      encoding="utf-8")
    print(f"frozen {len(rows)} Python transport cases: "
          f"{sum(row['accepted'] for row in rows)} accepted")


if __name__ == "__main__":
    main()
