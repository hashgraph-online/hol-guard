"""Summarize approval rows that ordinary work created, with the Always option they offer."""

from __future__ import annotations

import re
from typing import Any

PERSISTENT_SCOPES = frozenset({"workspace", "harness", "global", "publisher", "artifact"})
# Connector classes a pending row can belong to: MCP tool calls by server transport, and
# local connectors by their ``local_cli_observation.surface``.
CONNECTOR_CLASSES = (
    "mcp-tool:stdio",
    "mcp-tool:remote",
    "surface:cli",
    "surface:mcp",
    "surface:package-scripts",
)
_SURFACES = frozenset({"cli", "mcp", "package-scripts"})
# A connector-setup group is a digest pair, never a name or a path.
CONNECTOR_GROUP_ID = re.compile(r"connector:(?P<identity>[0-9a-f]{64}):(?P<action>[0-9a-f]{16})")
REDACTED_GROUP = "redacted-group"


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _opaque_group(value: Any) -> str:
    """Keep a queue group only when it is a connector digest id; any other text is not evidence."""
    group = str(value or "")
    return group if not group or CONNECTOR_GROUP_ID.fullmatch(group) else REDACTED_GROUP


def approval_rows(store: Any, known_ids: set[str]) -> list[dict[str, Any]]:
    """Return redacted-by-construction facts for rows added during the run.

    Only the tool, reason, queue group and whether an Always option is offered are kept; commands and
    paths are already in the redacted tool evidence, so they are not copied again. The queue group
    is kept only as an opaque ``connector:<hash>:<digest>`` id; any other stored value is replaced.
    """
    from codex_plugin_scanner.guard.approval_scope_support import request_scope_observation

    rows = []
    observations = _observations(store)
    for row in store.list_approval_requests(status=None, limit=200):
        if not isinstance(row, dict) or str(row.get("request_id") or "") in known_ids:
            continue
        # The native contract also binds a token carried in the artifact hash, not only the envelope's.
        contract, token = request_scope_observation(row)
        scopes = [str(scope) for scope in contract.allow_scopes]
        envelope = _mapping(row.get("action_envelope_json"))
        decision = _mapping(row.get("decision_v2_json"))
        rows.append(
            {
                "tool_name": str(envelope.get("tool_name") or row.get("tool_name") or ""),
                "reason_code": str(
                    _mapping(envelope.get("native_origin_receipt")).get("reason_code")
                    or decision.get("reason_code")
                    or row.get("reason_code")
                    or ""
                ),
                "exact_action_persistence_eligible": contract.exact_action_persistence_eligible is True,
                "allow_scopes": scopes,
                "exact_context_token_present": bool(token),
                "once_only_reason": contract.once_only_reason,
                "queue_group_id": _opaque_group(row.get("queue_group_id")),
                "always_available": contract.exact_action_persistence_eligible is True
                or any(scope in PERSISTENT_SCOPES for scope in scopes),
                "dedupe_count": int(row.get("dedupe_count") or 1),
            }
        )
        rows[-1]["connector_class"] = connector_class(rows[-1], envelope, observations)
        rows[-1]["connector"] = row_connector(rows[-1], envelope, observations)
    return rows


def always_gap(rows: list[dict[str, Any]]) -> list[str]:
    """Name rows that a user could not turn into a lasting allow, a defect for read-only work."""
    return [str(row.get("tool_name") or "unknown") for row in rows if row.get("always_available") is not True]


def offers_always(row: dict[str, Any]) -> bool:
    """A review row offering an exact-action lasting allow: eligible contract plus its context token."""
    return (
        row.get("always_available") is True
        and row.get("exact_action_persistence_eligible") is True
        and row.get("exact_context_token_present") is True
    )


def _observations(store: Any) -> list[dict[str, Any]]:
    """Local connector observations, or none when this store predates them."""
    try:
        items = store.list_local_cli_items()
    except Exception:
        return []
    return [item for item in items if isinstance(item, dict)] if isinstance(items, list) else []


def _mcp_server(tool_name: str) -> str | None:
    parts = tool_name.split("__")
    return parts[1] if len(parts) >= 3 and parts[0] == "mcp" else None


def _remote(item: dict[str, Any]) -> bool:
    return any(
        str(item.get(key) or "").startswith(("http://", "https://")) for key in ("server_command", "source_path")
    )


def row_connector(row: dict[str, Any], envelope: dict[str, Any], observations: list[dict[str, Any]]) -> str | None:
    """The connector a pending row is about: its MCP server, or the local CLI it was observed as.

    A row whose connector cannot be resolved stays ``None``, so a judge never counts it for a
    connector it cannot prove it belongs to.
    """
    server = _mcp_server(str(row.get("tool_name") or ""))
    if server is not None:
        return server
    name = _mapping(envelope.get("local_cli_observation")).get("name")
    group = str(row.get("queue_group_id") or "")
    if not name and group.startswith("connector:"):
        digest = group.removeprefix("connector:")
        found = [
            item for item in observations if digest in {item.get("identity_hash"), item.get("server_identity_hash")}
        ]
        name = found[0].get("name") if found else None
    return name if isinstance(name, str) and name else None


def connector_class(row: dict[str, Any], envelope: dict[str, Any], observations: list[dict[str, Any]]) -> str | None:
    """Classify one pending row; ``None`` when it is not about a connector at all."""
    server = _mcp_server(str(row.get("tool_name") or ""))
    if server is not None:
        matches = [item for item in observations if item.get("surface") == "mcp" and item.get("name") == server]
        if not matches:
            return "mcp-tool:unknown"
        return "mcp-tool:remote" if any(_remote(item) for item in matches) else "mcp-tool:stdio"
    observation = _mapping(envelope.get("local_cli_observation"))
    surface = observation.get("surface")
    group = str(row.get("queue_group_id") or "")
    if surface is None and group.startswith("connector:"):
        digest = group.removeprefix("connector:")
        found = [
            item for item in observations if digest in {item.get("identity_hash"), item.get("server_identity_hash")}
        ]
        surface = found[0].get("surface") if found else "cli"
    return f"surface:{surface}" if surface in _SURFACES else None


def covered_connector_classes(scenarios: Any) -> set[str]:
    """Classes these cases exercise, read from the cases themselves."""
    from .connector_fixtures import ECHO_MCP, LANECTL, REMOTE_MCP

    covered: set[str] = set()
    for scenario in scenarios:
        servers = {_mcp_server(tool) for tool in scenario.required_tools}
        if ECHO_MCP in servers:
            covered.update({"mcp-tool:stdio", "surface:mcp"})
        if REMOTE_MCP in servers:
            covered.update({"mcp-tool:remote", "surface:mcp"})
        if any(LANECTL in command for command in scenario.commands):
            covered.add("surface:cli")
    return covered


def connector_classes(rows: Any) -> list[str]:
    """The connector class of each pending row, so a report case keeps them after its raw rows are dropped."""
    classes = (row.get("connector_class") for row in rows or [] if isinstance(row, dict))
    return sorted(name for name in classes if isinstance(name, str))


def connector_coverage(cases: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Pending connector rows by class and the classes this run proved, from the cases it ran.

    A class is covered only by a connector case that ran in this run and passed, so a
    targeted run, a skipped case or a failed one never claims the classes it did not
    exercise. ``None`` when the run held no connector case at all. ``supported`` is what
    the catalog could exercise, kept apart from what this run did.
    """
    from .catalog import CONNECTOR_CATALOG, load_catalog

    catalog = {scenario.id: scenario for scenario in load_catalog(CONNECTOR_CATALOG)}
    ran = [case for case in cases if case.get("id") in catalog]
    if not ran:
        return None
    observed: dict[str, int] = {}
    for case in ran:
        names = case.get("connector_classes")
        names = names if isinstance(names, list) else connector_classes(case.get("approval_rows"))
        for name in names:
            observed[name] = observed.get(name, 0) + 1
    covered = covered_connector_classes(catalog[case["id"]] for case in ran if case.get("outcome") == "pass")
    universe = sorted(set(CONNECTOR_CLASSES) | set(observed))
    return {
        "observed": dict(sorted(observed.items())),
        "covered": sorted(covered),
        "supported": sorted(covered_connector_classes(catalog.values())),
        "uncovered": [{"class": name, "rows": observed.get(name, 0)} for name in universe if name not in covered],
    }
