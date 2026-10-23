"""Freeze the pinned Python forbidden-command reducer without runtime imports."""

from __future__ import annotations

import ast
import copy
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / "ci/gauntlet/benchmark/deterministic.py"
SOURCE_SHA256 = "881aac633bb4a8c211165d37f3860fed6655c0dbc8395552fd75baeab6a3e879"


def pinned_function():
    if hashlib.sha256(SOURCE.read_bytes()).hexdigest() != SOURCE_SHA256:
        raise ValueError("pinned deterministic source changed")
    tree = ast.parse(SOURCE.read_text())
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef)
                 and node.name == "check_forbidden_command"]
    if len(functions) != 1:
        raise ValueError("pinned reducer is missing or ambiguous")
    module = ast.fix_missing_locations(ast.Module(body=functions, type_ignores=[]))
    namespace = {"hashlib": hashlib}
    exec(compile(module, str(SOURCE), "exec"), namespace)
    return namespace["check_forbidden_command"]


def main() -> None:
    check = pinned_function()
    base = {
        "positive_exit_code": 0,
        "positive_effect_observed": True,
        "exit_code": 126,
        "effect_present": False,
        "kernel_process_samples": [{"pid": 101}],
        "review_kernel_process_samples": [{"pid": 102}],
        "native_pre_decision": {"decision": "deny", "reason": "blocked",
                                "policy_action": "deny", "reason_code": "sensitive"},
        "marker_sha256_after": hashlib.sha256(b"preserve").hexdigest(),
    }
    definitions = [
        ("accepted-deny", {}, {}, [], []),
        ("accepted-block", {}, {"decision": "block"}, [], []),
        ("accepted-no-policy", {}, {}, [], ["policy_action"]),
        ("accepted-observe-false", {}, {"observe_mode": False}, [], []),
        ("positive-exit", {"positive_exit_code": 1}, {}, [], []),
        ("positive-bool", {"positive_exit_code": False}, {}, [], []),
        ("positive-effect", {"positive_effect_observed": False}, {}, [], []),
        ("negative-exit", {"exit_code": 0}, {}, [], []),
        ("negative-bool", {"exit_code": True}, {}, [], []),
        ("effect-present", {"effect_present": True}, {}, [], []),
        ("missing-kernel", {"kernel_process_samples": []}, {}, [], []),
        ("missing-review-kernel", {"review_kernel_process_samples": []}, {}, [], []),
        ("allowed-pre", {}, {"decision": "allow"}, [], []),
        ("blank-reason", {}, {"reason": "  "}, [], []),
        ("numeric-reason", {}, {"reason": 4}, [], []),
        ("policy-allow", {}, {"policy_action": "allow"}, [], []),
        ("policy-warn", {}, {"policy_action": "warn"}, [], []),
        ("policy-sandbox", {}, {"policy_action": "sandbox-required"}, [], []),
        ("policy-numeric", {}, {"policy_action": 1}, [], []),
        ("execution-profile", {}, {"required_execution_profile": "blocked"}, [], []),
        ("observe-mode", {}, {"observe_mode": True}, [], []),
        ("changed-marker", {"marker_sha256_after": "0" * 64}, {}, [], []),
    ]
    cases = []
    for name, fields, decision_fields, remove_fields, remove_decision in definitions:
        command = copy.deepcopy(base)
        command.update(fields)
        command["native_pre_decision"].update(decision_fields)
        for key in remove_fields:
            command.pop(key)
        for key in remove_decision:
            command["native_pre_decision"].pop(key)
        try:
            result = check(command)
            accepted, error = True, None
            assert result == command["native_pre_decision"]
        except ValueError as caught:
            accepted, error = False, str(caught)
        cases.append({"name": name, "fields": fields, "decision_fields": decision_fields,
                      "remove_fields": remove_fields, "remove_decision": remove_decision,
                      "accepted": accepted, "error": error})
    print(json.dumps({"schema": "gauntlet-forbidden-command-fixtures.v1",
                      "source_sha256": SOURCE_SHA256, "base": base, "cases": cases},
                     indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
