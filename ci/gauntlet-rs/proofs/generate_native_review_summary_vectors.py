"""Freeze Python Native review completeness without importing product code."""

from __future__ import annotations

import ast
from collections import Counter
from copy import deepcopy
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / "ci/gauntlet/benchmark/builtin_hook_supervisor.py"
STATUS = ROOT / "ci/gauntlet/benchmark/native_review_status.py"
OUTPUT = ROOT / "ci/gauntlet-rs/crates/gauntlet-evidence/tests/fixtures/native_review_summary_v1.json"


def function(tree, name):
    return deepcopy(next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                         and node.name == name))


def source_functions():
    supervisor = ast.parse(SOURCE.read_text(encoding="utf-8"))
    status = ast.parse(STATUS.read_text(encoding="utf-8"))
    summary = function(supervisor, "review_summary")
    imports = [node for node in summary.body if isinstance(node, ast.ImportFrom)]
    if len(imports) != 1 or imports[0].module != "native_review_status" or [
            alias.name for alias in imports[0].names] != ["review_completed"]:
        raise ValueError("Native review import boundary changed")
    summary.body.remove(imports[0])
    constant = next(node for node in status.body if isinstance(node, ast.Assign)
                    and any(isinstance(target, ast.Name) and target.id == "UNREVIEWABLE_REASONS"
                            for target in node.targets))
    scope = {"Counter": Counter}
    for body, filename in [([constant, function(status, "review_completed")], STATUS),
                           ([summary], SOURCE)]:
        exec(compile(ast.fix_missing_locations(ast.Module(body=body, type_ignores=[])),
                     str(filename), "exec"), scope)
    return scope


def event(kind, call, payload, decision="allow", **response):
    return {"kind": "actual-hook-response", "hook_event_name": kind,
            "tool_call_id": call, "payload_digest": payload,
            "product_response": {"decision": decision, **response}}


def cases():
    pre = event("PreToolUse", "a", "payload-a")
    post = event("PostToolUse", "a", "payload-a")
    base = {"events": [pre, post], "contained": []}
    yield "valid-pre-post", base

    def altered(name, edit):
        row = deepcopy(base)
        edit(row)
        return name, row

    yield altered("missing-post", lambda row: row["events"].pop())
    yield altered("unreviewable-post", lambda row: row["events"][1]["product_response"].update(
        reason_code="native_post_tool_unavailable"))
    yield altered("unreviewable-pre", lambda row: row["events"][0]["product_response"].update(
        reason_code="native_pre_tool_unavailable"))
    yield altered("recording-only-post", lambda row: row["events"][1]["product_response"].update(
        recording_only=True))
    yield altered("observe-mode-pre", lambda row: row["events"][0]["product_response"].update(
        observe_mode=True))
    yield altered("extra-post", lambda row: row["events"].append(deepcopy(post)))
    yield altered("duplicate-pre-one-post", lambda row: row["events"].insert(1, deepcopy(pre)))
    yield altered("unrelated-event", lambda row: row["events"].append({"kind": "peer-authenticated"}))
    yield altered("unknown-reason-still-reviewed", lambda row: row["events"][1][
        "product_response"].update(reason_code="unknown-code"))
    yield altered("unreviewable-non-bool-flag", lambda row: row["events"][1][
        "product_response"].update(recording_only=1))
    yield altered("native-refusal", lambda row: row["events"][:].__setitem__(slice(None), [
        event("PreToolUse", "denied", "payload-denied", decision="deny")]))
    yield altered("native-refusal-plus-backend", lambda row: (
        row.update(events=[event("PreToolUse", "denied", "payload-denied", decision="deny")]),
        row["contained"].append({"kind": "contained-route-consumed", "payload_digest": "payload-denied"})))
    yield altered("backend-with-post", lambda row: (
        row.update(events=[event("PreToolUse", "denied", "payload-denied", decision="deny"),
                           event("PostToolUse", "denied", "payload-denied")]),
        row["contained"].append({"kind": "contained-route-consumed", "payload_digest": "payload-denied"})))
    yield altered("unmatched-consumed", lambda row: row["contained"].append(
        {"kind": "contained-route-consumed", "payload_digest": "other"}))
    yield altered("post-only", lambda row: row.update(events=[post]))
    yield altered("two-sorted-calls", lambda row: row.update(events=[
        event("PreToolUse", "z", "z"), event("PreToolUse", "a", "a"),
        event("PostToolUse", "z", "z"), event("PostToolUse", "a", "a")] ))
    yield altered("empty", lambda row: row.update(events=[], contained=[]))
    yield altered("missing-call-id", lambda row: row["events"][0].pop("tool_call_id"))
    yield altered("missing-decision", lambda row: row["events"][0]["product_response"].pop("decision"))


def review_cases(reasons):
    responses = [
        ("allow", {"decision": "allow"}),
        ("deny", {"decision": "deny"}),
        ("native-policy-not-ready", {"reason_code": "native_policy_not_ready"}),
        ("native-post-unavailable", {"reason_code": "native_post_tool_unavailable"}),
        ("native-prompt-unavailable", {"reason_code": "native_prompt_unavailable"}),
        ("unknown-reason", {"reason_code": "unknown"}),
        ("recording-only", {"recording_only": True}),
        ("observe-mode", {"observe_mode": True}),
        ("integer-one-recording", {"recording_only": 1}),
        ("false-recording", {"recording_only": False}),
        ("not-a-dict", []),
    ]
    responses.extend((f"unreviewable-{reason}", {"reason_code": reason})
                     for reason in sorted(reasons))
    return responses


def main():
    scope = source_functions()
    rows = []
    for name, row in cases():
        try:
            result = scope["review_summary"](row["events"], row["contained"])
            error = None
        except (KeyError, TypeError, AttributeError) as exc:
            result, error = None, f"{type(exc).__name__}: {exc}"
        rows.append({"name": name, **row, "result": result, "error": error})
    reviews = [{"name": name, "response": response,
                "completed": scope["review_completed"](response)}
               for name, response in review_cases(scope["UNREVIEWABLE_REASONS"])]
    OUTPUT.write_text(json.dumps({"schema": "gauntlet-python-native-review-summary.v1",
                                  "source_sha256": hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
                                  "status_sha256": hashlib.sha256(STATUS.read_bytes()).hexdigest(),
                                  "cases": rows, "review_cases": reviews,
                                  "reason_count": len(scope["UNREVIEWABLE_REASONS"])},
                                 sort_keys=True, separators=(",", ":")) + "\n",
                      encoding="utf-8")
    print(f"frozen {len(rows)} Native summary cases and {len(reviews)} review-status cases")


if __name__ == "__main__":
    main()
