"""Policy decision display context enrichment for remembered rules."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

_GENERIC_POLICY_REASONS = (
    "approved in review",
    "approved in local approval center",
    "local auto-resume proof",
    "local e2e approval proof",
)


def _is_generic_policy_reason(reason: str | None) -> bool:
    if reason is None or not reason.strip():
        return True
    normalized = reason.strip().lower()
    return any(phrase in normalized for phrase in _GENERIC_POLICY_REASONS)


def _is_human_policy_label(value: str | None) -> bool:
    if value is None or not value.strip():
        return False
    normalized = value.strip()
    lowered = normalized.lower()
    if lowered.startswith("family:"):
        return False
    if len(normalized) >= 32 and all(ch in "0123456789abcdef" for ch in lowered):
        return False
    if ":" in normalized:
        tail = normalized.split(":")[-1]
        if len(tail) >= 16 and all(ch in "0123456789abcdef" for ch in tail):
            return False
    return True


def _normalize_hash_for_match(value: str) -> str:
    return value.strip().lower().removeprefix("sha256:")


def _artifact_hash_match_variants(artifact_hash: str) -> tuple[str, ...]:
    normalized = _normalize_hash_for_match(artifact_hash)
    variants = {artifact_hash, f"sha256:{normalized}", normalized}
    return tuple(variant for variant in variants if variant)


def _artifact_hash_in_clause(artifact_hash: str) -> tuple[str, tuple[object, ...]]:
    variants = _artifact_hash_match_variants(artifact_hash)
    placeholders = ", ".join("?" for _ in variants)
    return f"artifact_hash in ({placeholders})", variants


def _path_basename_label(path: str) -> str | None:
    normalized = path.strip().replace("\\", "/").rstrip("/")
    if not normalized or normalized.startswith("workspace:"):
        return None
    if normalized.startswith("/") or normalized.startswith("~") or (len(normalized) >= 2 and normalized[1] == ":"):
        segments = [segment for segment in normalized.split("/") if segment]
        if segments:
            return segments[-1]
    return None


def _workspace_display_label(source_scope: str | None, workspace: str | None) -> str | None:
    if source_scope and source_scope.strip():
        label = _path_basename_label(source_scope)
        if label is not None:
            return label
    if workspace and workspace.strip() and not workspace.strip().startswith("workspace:"):
        label = _path_basename_label(workspace)
        if label is not None:
            return label
        return workspace.strip()
    return None


def _sanitize_remembered_command(value: str) -> str:
    cleaned = value.strip()
    if cleaned.endswith("'2>'"):
        cleaned = cleaned[: -len("'2>'")].strip()
    if cleaned.endswith("2>"):
        cleaned = cleaned[: -len("2>")].strip()
    return cleaned


def _extract_backtick_phrases(text: str) -> list[str]:
    phrases: list[str] = []
    start = 0
    while True:
        open_tick = text.find("`", start)
        if open_tick < 0:
            break
        close_tick = text.find("`", open_tick + 1)
        if close_tick < 0:
            break
        phrase = text[open_tick + 1 : close_tick].strip()
        if phrase:
            phrases.append(phrase)
        start = close_tick + 1
    return phrases


def _parse_provenance_workspace_path(provenance: str | None) -> str | None:
    if provenance is None or not provenance.strip():
        return None
    normalized = provenance.strip()
    lowered = normalized.lower()
    marker = "evaluated from "
    if marker in lowered:
        path = normalized[lowered.index(marker) + len(marker) :].strip()
        if path.startswith("/") or path.startswith("~") or (len(path) >= 2 and path[1] == ":"):
            return _directory_scope_path(path.rstrip("/"))
    return None


def _directory_scope_path(path: str) -> str | None:
    normalized = path.rstrip("/")
    if not normalized:
        return None
    suffix = Path(normalized).suffix.lower()
    if suffix in {".json", ".toml", ".yaml", ".yml", ".lock", ".md", ".txt"}:
        parent = str(Path(normalized).parent)
        return parent if parent and parent != "." else normalized
    return normalized


def _parse_scanner_evidence_fields(
    scanner_evidence_json: str | None,
) -> tuple[str | None, str | None]:
    if scanner_evidence_json is None or not scanner_evidence_json.strip():
        return None, None
    try:
        payload = json.loads(scanner_evidence_json)
    except json.JSONDecodeError:
        return None, None
    entries = payload if isinstance(payload, list) else [payload]
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        package = entry.get("package")
        if not isinstance(package, dict):
            continue
        redacted = package.get("redactedCommand")
        command = _sanitize_remembered_command(str(redacted)) if isinstance(redacted, str) else None
        package_manager = package.get("packageManager")
        ecosystem = package.get("ecosystem")
        context: str | None = None
        if isinstance(package_manager, str) and package_manager.strip():
            context = f"Package install via {package_manager.strip()}"
        elif isinstance(ecosystem, str) and ecosystem.strip():
            context = f"Package install via {ecosystem.strip()}"
        if command or context:
            return command, context
    return None, None


def _normalize_policy_scope_path(path: str | None) -> str | None:
    if path is None or not path.strip():
        return None
    normalized = path.strip()
    if normalized.startswith("workspace:"):
        return None
    if normalized.startswith("/") or normalized.startswith("~") or (len(normalized) >= 2 and normalized[1] == ":"):
        return normalized.rstrip("/")
    return None


def _find_policy_source_receipt_row(
    connection: sqlite3.Connection,
    *,
    harness: str,
    artifact_id: str | None,
    artifact_hash: str | None,
) -> sqlite3.Row | None:
    conditions: list[str] = []
    params: list[object] = []
    if harness != "*":
        conditions.append("harness = ?")
        params.append(harness)
    if artifact_hash:
        hash_clause, hash_params = _artifact_hash_in_clause(artifact_hash)
        conditions.append(hash_clause)
        params.extend(hash_params)
    elif artifact_id:
        conditions.append("artifact_id = ?")
        params.append(artifact_id)
    if not conditions:
        return None
    order_params: list[object] = []
    order_clause = "timestamp desc"
    if artifact_id:
        order_clause = "case when artifact_id = ? then 0 else 1 end, timestamp desc"
        order_params.append(artifact_id)
    return connection.execute(
        f"""
        select receipt_id, artifact_name, capabilities_summary, provenance_summary, source_scope,
               scanner_evidence_json, artifact_id
        from runtime_receipts
        where {" and ".join(conditions)}
        order by {order_clause}
        limit 1
        """,
        tuple([*params, *order_params]),
    ).fetchone()


def _find_policy_inventory_row(
    connection: sqlite3.Connection,
    *,
    harness: str,
    artifact_id: str | None,
) -> sqlite3.Row | None:
    if artifact_id is None or not artifact_id.strip():
        return None
    return connection.execute(
        """
        select artifact_name, launch_command, source_scope
        from artifact_inventory
        where harness = ? and artifact_id = ?
        limit 1
        """,
        (harness, artifact_id),
    ).fetchone()


def _find_policy_approval_row(
    connection: sqlite3.Connection,
    *,
    harness: str,
    artifact_id: str | None,
    artifact_hash: str | None,
) -> sqlite3.Row | None:
    conditions = ["status = 'resolved'"]
    params: list[object] = []
    if harness != "*":
        conditions.append("harness = ?")
        params.append(harness)
    if artifact_id:
        conditions.append("artifact_id = ?")
        params.append(artifact_id)
    if artifact_hash:
        hash_clause, hash_params = _artifact_hash_in_clause(artifact_hash)
        conditions.append(hash_clause)
        params.extend(hash_params)
    if len(conditions) <= 1:
        return None
    return connection.execute(
        f"""
        select request_id, artifact_name, launch_summary, launch_target, workspace, resolved_at,
               trigger_summary, resolution_scope
        from approval_requests
        where {" and ".join(conditions)}
        order by resolved_at desc
        limit 1
        """,
        tuple(params),
    ).fetchone()


def find_policy_source_context(
    connection: sqlite3.Connection,
    *,
    harness: str,
    artifact_id: str | None,
    artifact_hash: str | None,
    workspace: str | None,
    reason: str | None,
) -> dict[str, str] | None:
    receipt_row = _find_policy_source_receipt_row(
        connection,
        harness=harness,
        artifact_id=artifact_id,
        artifact_hash=artifact_hash,
    )
    inventory_row = _find_policy_inventory_row(connection, harness=harness, artifact_id=artifact_id)
    approval_row = _find_policy_approval_row(
        connection,
        harness=harness,
        artifact_id=artifact_id,
        artifact_hash=artifact_hash,
    )

    remembered_command: str | None = None
    remembered_context: str | None = None
    workspace_label: str | None = None
    source_receipt_id: str | None = None
    source_scope_path: str | None = None

    if receipt_row is not None:
        source_receipt_id = str(receipt_row["receipt_id"])
        scanner_command, scanner_context = _parse_scanner_evidence_fields(
            str(receipt_row["scanner_evidence_json"]) if receipt_row["scanner_evidence_json"] is not None else None
        )
        if scanner_command and _is_human_policy_label(scanner_command):
            remembered_command = scanner_command
        if scanner_context:
            remembered_context = scanner_context
        receipt_name = receipt_row["artifact_name"]
        if remembered_command is None and _is_human_policy_label(
            str(receipt_name) if receipt_name is not None else None
        ):
            remembered_command = _sanitize_remembered_command(str(receipt_name))
        caps = receipt_row["capabilities_summary"]
        if remembered_context is None and caps is not None and str(caps).strip():
            remembered_context = str(caps).strip()
        provenance_path = _parse_provenance_workspace_path(
            str(receipt_row["provenance_summary"]) if receipt_row["provenance_summary"] is not None else None
        )
        receipt_scope_path = _normalize_policy_scope_path(
            str(receipt_row["source_scope"]) if receipt_row["source_scope"] is not None else None
        )
        source_scope_path = receipt_scope_path or _normalize_policy_scope_path(provenance_path)
        workspace_label = _workspace_display_label(
            str(receipt_row["source_scope"]) if receipt_row["source_scope"] is not None else None,
            workspace,
        )

    if inventory_row is not None:
        launch_command = inventory_row["launch_command"]
        if remembered_command is None and _is_human_policy_label(
            str(launch_command) if launch_command is not None else None
        ):
            remembered_command = str(launch_command).strip()
        inventory_name = inventory_row["artifact_name"]
        if remembered_context is None and _is_human_policy_label(
            str(inventory_name) if inventory_name is not None else None
        ):
            remembered_context = str(inventory_name).strip()
        if workspace_label is None:
            workspace_label = _workspace_display_label(
                str(inventory_row["source_scope"]) if inventory_row["source_scope"] is not None else None,
                workspace,
            )

    if approval_row is not None:
        approval_name = approval_row["artifact_name"]
        launch_target = approval_row["launch_target"]
        launch_summary = approval_row["launch_summary"]
        trigger_summary = approval_row["trigger_summary"]
        if approval_row["workspace"] is not None:
            approval_path = _normalize_policy_scope_path(str(approval_row["workspace"]))
            if approval_path is not None:
                source_scope_path = approval_path
        if remembered_command is None and trigger_summary is not None:
            for phrase in _extract_backtick_phrases(str(trigger_summary)):
                candidate = _sanitize_remembered_command(phrase)
                if _is_human_policy_label(candidate):
                    remembered_command = candidate
                    break
        if remembered_command is None and launch_target is not None:
            for phrase in _extract_backtick_phrases(str(launch_target)):
                candidate = _sanitize_remembered_command(phrase)
                if _is_human_policy_label(candidate):
                    remembered_command = candidate
                    break
        if remembered_command is None and _is_human_policy_label(
            str(launch_target) if launch_target is not None else None
        ):
            remembered_command = _sanitize_remembered_command(str(launch_target))
        if remembered_command is None and _is_human_policy_label(str(approval_name)):
            remembered_command = _sanitize_remembered_command(str(approval_name))
        if remembered_context is None and _is_human_policy_label(
            str(launch_summary) if launch_summary is not None else None
        ):
            remembered_context = str(launch_summary).strip()
        if workspace_label is None and approval_row["workspace"] is not None:
            workspace_label = _workspace_display_label(str(approval_row["workspace"]), workspace)

    if remembered_command is None and not _is_generic_policy_reason(reason):
        remembered_command = reason.strip() if reason is not None else None

    if (
        source_receipt_id is None
        and remembered_command is None
        and remembered_context is None
        and source_scope_path is None
    ):
        return None

    payload: dict[str, str] = {}
    if source_receipt_id is not None:
        payload["source_receipt_id"] = source_receipt_id
    if remembered_command is not None:
        payload["remembered_command"] = remembered_command
    if remembered_context is not None:
        payload["remembered_context"] = remembered_context
    if workspace_label is not None:
        payload["workspace_label"] = workspace_label
    if source_scope_path is not None:
        payload["source_scope_path"] = source_scope_path
    return payload or None
