"""Shared builders for the native exact-action vector catalogue."""

from __future__ import annotations

from typing import Any

ROOT = "{ROOT}"
PROJECT = f"{ROOT}/proj"
HOME = f"{ROOT}/home"
SCHEMA = "guard-native-exact-action-request.v1"
EXTENSION_DIGEST = "e" * 64
RECEIPT_SCHEMA = "guard-native-hook-decision-receipt.v1"
BOUND = {
    "state": "bound",
    "value": {
        "schema": "guard-native-review-policy-binding.v1",
        "policy_digest": "policy-digest",
        "rule_digest": "rule-digest",
        "runtime_identity": "runtime-identity",
        "command_extensions": {"uncertainty_count": 0, "digest": "ext-digest"},
    },
}
FACTS = {
    "decision": "require-reapproval",
    "minimum_action": "review",
    "policy_action": "review",
    "reason_code": "first_seen_command",
    "action_type": "shell",
}
DIGEST = "ab" * 32
BASE_TREE: dict[str, Any] = {"proj": {"dir": True}, "home": {"dir": True}, "bin": {"dir": True}}


def _tree(extra: dict[str, Any] | None) -> dict[str, Any]:
    tree = dict(BASE_TREE)
    tree.update(extra or {})
    return tree


def exact(name: str, **options: Any) -> dict[str, Any]:
    """One exact-action case; every field of the wire query can be overridden."""

    command = options.get("command")
    tool_input = options.get("tool_input")
    if tool_input is None and command is not None:
        tool_input = [["command", command]]
    if command is None and tool_input:
        for key, value in tool_input:
            if key in ("command", "cmd", "shell_command", "shellCommand") and isinstance(value, str) and value.strip():
                command = value
                break
    if not (isinstance(command, str) and command.strip()):
        command = None  # the transport sends what ``pre_tool_command`` extracts
    raw_cwd = options.get("payload_cwd", PROJECT)
    query = {
        "kind": "exact_action",
        "harness": options.get("harness", "codex"),
        "tool_name": options.get("tool_name", "Bash"),
        "command": command,
        "tool_input": tool_input,
        "payload_cwd": raw_cwd if isinstance(raw_cwd, str) and raw_cwd.strip() else None,
        "workspace": options.get("workspace", PROJECT),
        "home_dir": options.get("home", HOME),
        "environment": options.get("env", {"PATH": f"{ROOT}/bin:/usr/bin", "HOME": HOME}),
        "facts": {**FACTS, **options.get("facts", {})},
        "policy_binding": options.get("binding", BOUND),
        "extension_control_digest": EXTENSION_DIGEST,
        "budget_ms": 20_000,
    }
    return {
        "name": name,
        "family": "exact_action",
        "tree": _tree(options.get("tree")),
        "intent": options.get("intent"),
        "raw_cwd": raw_cwd,
        "request": {"schema": SCHEMA, "request_id": f"exact-{name}", "query": query},
    }


def binding_case(name: str, **options: Any) -> dict[str, Any]:
    """One review-binding case."""

    command = options.get("command")
    if not (isinstance(command, str) and command.strip()):
        command = None
    receipt = options.get("receipt", "valid")
    if receipt == "valid":
        receipt = valid_receipt(**options.get("receipt_fields", {}))
    query = {
        "kind": "review_binding",
        "harness": options.get("harness", "codex"),
        "command": command,
        "workspace_bound": options.get("workspace_bound", True),
        "facts": {**FACTS, **options.get("facts", {})},
        "receipt": receipt,
        "policy_binding": options.get("binding", {"state": "unbound"}),
    }
    return {
        "name": name,
        "family": "review_binding",
        "tree": {},
        "intent": None,
        "raw_cwd": None,
        "request": {"schema": SCHEMA, "request_id": f"binding-{name}", "query": query},
    }


def valid_receipt(**overrides: Any) -> dict[str, Any]:
    receipt = {
        "schema": RECEIPT_SCHEMA,
        "version": 1,
        "authority": "rust",
        "harness": "codex",
        "event_name": "PreToolUse",
        "workspace_bound": True,
        "request_digest": DIGEST,
        "decision": FACTS["decision"],
        "policy_action": FACTS["policy_action"],
        "reason_code": FACTS["reason_code"],
    }
    receipt.update(overrides)
    return receipt


def execution(**fields: Any) -> dict[str, Any]:
    """A package-intent local execution with a resolvable bin."""

    local_path = fields.pop("bin", f"{PROJECT}/node_modules/.bin/wrangler")
    evidence = {
        "local_executable": {
            "path": local_path,
            "resolved_path": local_path,
            "status": "available",
            "content_hash": "sha256:" + "1" * 64,
        },
        "manager": {
            "path": f"{ROOT}/bin/npx",
            "resolved_path": f"{ROOT}/bin/npx",
            "status": "available",
            "content_hash": "sha256:" + "2" * 64,
        },
        "manager_is_guard_shim": False,
        "package_name": "wrangler",
        "executable_name": "wrangler",
        "manifests": [
            {"path": f"{PROJECT}/package.json", "resolved_path": None, "status": "available", "content_hash": "m1"}
        ],
        "lockfiles": [],
    }
    evidence.update(fields)
    return evidence
