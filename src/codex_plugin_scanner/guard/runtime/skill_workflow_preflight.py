"""Advisory workflow requirements, separate from activation and authority."""

from __future__ import annotations

import json
import re

from ..strict_json_pairs import unique_json_object
from .composio_contract import composio_requires_action_review
from .local_cli_identity import is_local_cli_id

_TOOL_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}\Z")


def parse_guard_skill_dependencies(frontmatter: dict[str, object]) -> dict[str, object]:
    metadata = frontmatter.get("metadata")
    raw = metadata.get("hol-guard.dependencies") if isinstance(metadata, dict) else None
    if raw is None:
        return {"source": "guard-extension", "status": "absent", "tools": []}
    try:
        if not isinstance(raw, str) or len(raw.encode()) > 8192:
            raise ValueError("invalid dependencies")
        manifest = json.loads(raw, object_pairs_hook=_unique_object, parse_constant=_invalid_constant)
        if (
            not isinstance(manifest, dict)
            or set(manifest) != {"schema_version", "tools"}
            or manifest["schema_version"] != "guard.skill-dependencies.v1"
            or not isinstance(manifest["tools"], list)
            or len(manifest["tools"]) > 50
        ):
            raise ValueError("invalid dependencies")
        tools: list[dict[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for tool in manifest["tools"]:
            if not isinstance(tool, dict) or set(tool) != {"connection_id", "tool_name"}:
                raise ValueError("invalid dependencies")
            connection, name = tool["connection_id"], tool["tool_name"]
            if not isinstance(connection, str) or not is_local_cli_id(connection):
                raise ValueError("invalid dependencies")
            if not isinstance(name, str) or not _TOOL_NAME.fullmatch(name) or (connection, name) in seen:
                raise ValueError("invalid dependencies")
            seen.add((connection, name))
            tools.append({"connection_id": connection, "tool_name": name})
        return {"source": "guard-extension", "status": "declared", "tools": tools}
    except (ValueError, TypeError, RecursionError, UnicodeError):
        return {"source": "guard-extension", "status": "invalid", "tools": []}


def preflight_skill_dependencies(
    dependencies: dict[str, object],
    items: list[dict[str, object]],
    *,
    revision: int,
) -> dict[str, object]:
    connections = {item["cli_id"]: item for item in items}
    requests = dependencies.get("tools")
    requirements: list[dict[str, object]] = []
    for request in requests if isinstance(requests, list) else []:
        if not isinstance(request, dict):
            continue
        connection_id, name = request.get("connection_id"), request.get("tool_name")
        item = connections.get(connection_id)
        state, reason = "unresolved", "connection-not-observed"
        identity = None
        if item is not None:
            identity = item.get("identity_hash")
            commands = item.get("commands")
            command = (
                next((entry for entry in commands if isinstance(entry, dict) and entry.get("usage") == name), None)
                if isinstance(commands, list)
                else None
            )
            if item.get("stale"):
                reason = "connection-changed"
            elif item.get("state") == "blocked" or (command is not None and command.get("state") == "block"):
                state, reason = "deny", "saved-deny"
            elif command is None:
                reason = "tool-not-observed"
            elif isinstance(name, str) and composio_requires_action_review(name):
                state, reason = "ask", "provider-account-and-action-unverified"
            elif item.get("state") == "allowed" and command.get("state") == "allow":
                state, reason = "saved-allow", "live-runtime-check-still-required"
            else:
                state, reason = "ask", "permission-review-needed"
        requirements.append(
            {
                "connection_id": connection_id,
                "tool_name": name,
                "identity_hash": identity,
                "state": state,
                "reason": reason,
            }
        )
    return {
        "schema_version": "guard.workflow-preflight.v1",
        "dependency_source": "guard-extension",
        "dependency_status": dependencies.get("status", "absent"),
        "authority_revision": revision,
        "requirements": requirements,
        "requirements_complete": False,
        "permissions_granted": False,
        "runtime_checks_required": True,
    }


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    return unique_json_object(pairs, "duplicate manifest key")


def _invalid_constant(_value: str) -> object:
    raise ValueError("nonfinite manifest value")
