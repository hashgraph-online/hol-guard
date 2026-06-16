"""Policy decision display context enrichment for remembered rules."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from hashlib import sha256
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


_SCANNER_GENERATED_LABEL_MARKERS = (
    "credential-looking",
    "credential looking",
    "secret-looking",
    "suspicious output",
    "looking output",
    "scanner flagged",
)

_SCOPED_HARNESS_FAMILIES = frozenset(
    {
        "file-read",
        "mcp",
        "mcp-tool",
        "package-request",
        "prompt",
        "prompt-env-read",
        "prompt-file",
        "tool-action",
    }
)
_SCOPED_RUNTIME_EXACT_FAMILIES = frozenset(
    {
        "file-read",
        "package-request",
        "prompt",
        "tool-action",
    }
)
_RUNTIME_SCOPED_EXACT_MATCH_PREFIX = "runtime-exact:"


def _is_scanner_generated_label(value: str) -> bool:
    lowered = value.strip().lower()
    if not lowered:
        return True
    if any(marker in lowered for marker in _SCANNER_GENERATED_LABEL_MARKERS):
        return True
    return lowered.endswith(" review") and "`" not in value


def _is_human_policy_label(value: str | None) -> bool:
    if value is None or not value.strip():
        return False
    normalized = value.strip()
    lowered = normalized.lower()
    if _is_scanner_generated_label(normalized):
        return False
    if lowered.startswith("family:"):
        return False
    if len(normalized) >= 32 and all(ch in "0123456789abcdef" for ch in lowered):
        return False
    if ":" in normalized:
        tail = normalized.split(":")[-1]
        if len(tail) >= 16 and all(ch in "0123456789abcdef" for ch in tail):
            return False
    return True


def _extract_approval_command(approval_row: sqlite3.Row) -> str | None:
    trigger_summary = approval_row["trigger_summary"]
    if trigger_summary is not None:
        for phrase in _extract_backtick_phrases(str(trigger_summary)):
            candidate = _sanitize_remembered_command(phrase)
            if _is_human_policy_label(candidate):
                return candidate
    launch_target = approval_row["launch_target"]
    if launch_target is not None:
        for phrase in _extract_backtick_phrases(str(launch_target)):
            candidate = _sanitize_remembered_command(phrase)
            if _is_human_policy_label(candidate):
                return candidate
        if _is_human_policy_label(str(launch_target)):
            return _sanitize_remembered_command(str(launch_target))
    approval_name = approval_row["artifact_name"]
    if approval_name is not None and _is_human_policy_label(str(approval_name)):
        return _sanitize_remembered_command(str(approval_name))
    return None


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


def _artifact_family_key(artifact_id: str | None) -> str | None:
    if artifact_id is None or not artifact_id.strip():
        return None
    if artifact_id.startswith("family:"):
        family = artifact_id.removeprefix("family:").strip().lower()
        return artifact_id if family in _SCOPED_HARNESS_FAMILIES else None
    parts = artifact_id.split(":")
    if len(parts) < 3:
        return None
    family = parts[2].strip().lower()
    if family not in _SCOPED_HARNESS_FAMILIES:
        return None
    return f"family:{family}"


def _runtime_scoped_exact_match_key(artifact_id: str | None) -> str | None:
    if artifact_id is None or not artifact_id.strip() or artifact_id.startswith("family:"):
        return None
    family_key = _artifact_family_key(artifact_id)
    if family_key is None or family_key.removeprefix("family:") not in _SCOPED_RUNTIME_EXACT_FAMILIES:
        return None
    digest = sha256(artifact_id.encode("utf-8")).hexdigest()
    return f"{_RUNTIME_SCOPED_EXACT_MATCH_PREFIX}{digest}"


def _is_runtime_scoped_exact_match_key(value: str | None) -> bool:
    return isinstance(value, str) and value.startswith(_RUNTIME_SCOPED_EXACT_MATCH_PREFIX)


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
    row = connection.execute(
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
    if row is not None or not artifact_hash:
        return row
    if not _is_runtime_scoped_exact_match_key(artifact_hash):
        return None
    return _find_runtime_exact_receipt_row(
        connection,
        harness=harness,
        artifact_id=artifact_id,
        artifact_hash=artifact_hash,
    )


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
    row = connection.execute(
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
    if row is not None or not artifact_hash:
        return row
    if not _is_runtime_scoped_exact_match_key(artifact_hash):
        return None
    return _find_runtime_exact_approval_row(
        connection,
        harness=harness,
        artifact_id=artifact_id,
        artifact_hash=artifact_hash,
    )


def _build_policy_source_context_from_rows(
    *,
    receipt_row: sqlite3.Row | None,
    inventory_row: sqlite3.Row | None,
    approval_row: sqlite3.Row | None,
    workspace: str | None,
    reason: str | None,
) -> dict[str, str] | None:
    remembered_command: str | None = None
    remembered_context: str | None = None
    workspace_label: str | None = None
    source_receipt_id: str | None = None
    source_scope_path: str | None = None

    if approval_row is not None:
        remembered_command = _extract_approval_command(approval_row)
        launch_summary = approval_row["launch_summary"]
        if remembered_context is None and _is_human_policy_label(
            str(launch_summary) if launch_summary is not None else None
        ):
            remembered_context = str(launch_summary).strip()
        if approval_row["workspace"] is not None:
            approval_path = _normalize_policy_scope_path(str(approval_row["workspace"]))
            if approval_path is not None:
                source_scope_path = approval_path
            workspace_label = _workspace_display_label(str(approval_row["workspace"]), workspace)

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
        if remembered_context is None and caps is not None:
            cap_text = str(caps).strip()
            if cap_text and _is_human_policy_label(cap_text):
                remembered_context = cap_text
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
    return _build_policy_source_context_from_rows(
        receipt_row=receipt_row,
        inventory_row=inventory_row,
        approval_row=approval_row,
        workspace=workspace,
        reason=reason,
    )


_POLICY_RECEIPT_COLUMNS = """
    receipt_id, artifact_name, capabilities_summary, provenance_summary, source_scope,
    scanner_evidence_json, artifact_id, harness, artifact_hash, timestamp
"""

_POLICY_INVENTORY_COLUMNS = "artifact_name, launch_command, source_scope, harness, artifact_id"

_POLICY_APPROVAL_COLUMNS = """
    request_id, artifact_name, launch_summary, launch_target, workspace, resolved_at,
    trigger_summary, resolution_scope, harness, artifact_id, artifact_hash
"""


def _runtime_exact_match_family(artifact_id: str | None) -> str | None:
    family_key = _artifact_family_key(artifact_id)
    if family_key is None:
        return None
    family = family_key.removeprefix("family:")
    if family not in _SCOPED_RUNTIME_EXACT_FAMILIES:
        return None
    return family


def _find_runtime_exact_receipt_row(
    connection: sqlite3.Connection,
    *,
    harness: str,
    artifact_id: str | None,
    artifact_hash: str,
) -> sqlite3.Row | None:
    if not _is_runtime_scoped_exact_match_key(artifact_hash):
        return None
    family = _runtime_exact_match_family(artifact_id)
    if family is None:
        return None
    conditions: list[str] = ["artifact_id like ?"]
    params: list[object] = [f"%:{family}:%"]
    if harness != "*":
        conditions.append("harness = ?")
        params.append(harness)
    query = f"select {_POLICY_RECEIPT_COLUMNS} from runtime_receipts"
    if conditions:
        query += f" where {' and '.join(conditions)}"
    query += " order by timestamp desc"
    for row in connection.execute(query, tuple(params)):
        row_artifact_id = str(row["artifact_id"]) if row["artifact_id"] is not None else None
        if _runtime_scoped_exact_match_key(row_artifact_id) == artifact_hash:
            return row
    return None


def _find_runtime_exact_approval_row(
    connection: sqlite3.Connection,
    *,
    harness: str,
    artifact_id: str | None,
    artifact_hash: str,
) -> sqlite3.Row | None:
    if not _is_runtime_scoped_exact_match_key(artifact_hash):
        return None
    family = _runtime_exact_match_family(artifact_id)
    if family is None:
        return None
    conditions = ["status = 'resolved'", "artifact_id like ?"]
    params: list[object] = [f"%:{family}:%"]
    if harness != "*":
        conditions.append("harness = ?")
        params.append(harness)
    for row in connection.execute(
        f"""
        select {_POLICY_APPROVAL_COLUMNS}
        from approval_requests
        where {" and ".join(conditions)}
        order by resolved_at desc
        """,
        tuple(params),
    ):
        row_artifact_id = str(row["artifact_id"]) if row["artifact_id"] is not None else None
        if _runtime_scoped_exact_match_key(row_artifact_id) == artifact_hash:
            return row
    return None


def _row_sort_timestamp(value: object) -> str:
    return str(value) if value is not None else ""


def _select_best_receipt_row(rows: list[sqlite3.Row], artifact_id: str | None) -> sqlite3.Row | None:
    if not rows:
        return None
    return max(
        rows,
        key=lambda row: (
            1 if artifact_id and str(row["artifact_id"]) == artifact_id else 0,
            _row_sort_timestamp(row["timestamp"]),
        ),
    )


def _select_best_approval_row(rows: list[sqlite3.Row], artifact_id: str | None) -> sqlite3.Row | None:
    if not rows:
        return None
    return max(
        rows,
        key=lambda row: (
            1 if artifact_id and str(row["artifact_id"]) == artifact_id else 0,
            _row_sort_timestamp(row["resolved_at"]),
        ),
    )


@dataclass
class PolicySourceContextIndex:
    receipts_by_harness_artifact: dict[tuple[str, str], list[sqlite3.Row]] = field(default_factory=dict)
    receipts_by_harness_hash: dict[tuple[str, str], list[sqlite3.Row]] = field(default_factory=dict)
    inventory_by_harness_artifact: dict[tuple[str, str], sqlite3.Row] = field(default_factory=dict)
    approvals_by_harness_artifact: dict[tuple[str, str], list[sqlite3.Row]] = field(default_factory=dict)
    approvals_by_harness_hash: dict[tuple[str, str], list[sqlite3.Row]] = field(default_factory=dict)


def _append_indexed_row(
    index: dict[tuple[str, str], list[sqlite3.Row]],
    key: tuple[str, str],
    row: sqlite3.Row,
) -> None:
    bucket = index.get(key)
    if bucket is None:
        index[key] = [row]
        return
    bucket.append(row)


def _policy_harness_scope(items: list[tuple[str, str | None, str | None]]) -> tuple[bool, list[str]]:
    harnesses = {harness for harness, _, _ in items if harness}
    include_all_harnesses = "*" in harnesses
    concrete_harnesses = sorted(harness for harness in harnesses if harness != "*")
    return include_all_harnesses, concrete_harnesses


def _harness_filter_sql(include_all_harnesses: bool, harnesses: list[str]) -> tuple[str, list[object]]:
    if include_all_harnesses or not harnesses:
        return "", []
    placeholders = ", ".join("?" for _ in harnesses)
    return f"and harness in ({placeholders})", list(harnesses)


def _extend_receipt_hash_candidates(
    index: PolicySourceContextIndex,
    harness: str,
    variant: str,
    candidates: list[sqlite3.Row],
) -> None:
    if harness == "*":
        for (_, row_variant), rows in index.receipts_by_harness_hash.items():
            if row_variant == variant:
                candidates.extend(rows)
        return
    candidates.extend(index.receipts_by_harness_hash.get((harness, variant), []))


def _extend_receipt_artifact_candidates(
    index: PolicySourceContextIndex,
    harness: str,
    artifact_id: str,
    candidates: list[sqlite3.Row],
) -> None:
    if harness == "*":
        for (_, row_artifact_id), rows in index.receipts_by_harness_artifact.items():
            if row_artifact_id == artifact_id:
                candidates.extend(rows)
        return
    candidates.extend(index.receipts_by_harness_artifact.get((harness, artifact_id), []))


def _extend_approval_hash_candidates(
    index: PolicySourceContextIndex,
    harness: str,
    variant: str,
    candidates: list[sqlite3.Row],
) -> None:
    if harness == "*":
        for (_, row_variant), rows in index.approvals_by_harness_hash.items():
            if row_variant == variant:
                candidates.extend(rows)
        return
    candidates.extend(index.approvals_by_harness_hash.get((harness, variant), []))


def _extend_approval_artifact_candidates(
    index: PolicySourceContextIndex,
    harness: str,
    artifact_id: str,
    candidates: list[sqlite3.Row],
) -> None:
    if harness == "*":
        for (_, row_artifact_id), rows in index.approvals_by_harness_artifact.items():
            if row_artifact_id == artifact_id:
                candidates.extend(rows)
        return
    candidates.extend(index.approvals_by_harness_artifact.get((harness, artifact_id), []))


def _policy_artifact_matches_candidate(policy_artifact_id: str | None, candidate_artifact_id: str | None) -> bool:
    if not policy_artifact_id:
        return True
    if candidate_artifact_id == policy_artifact_id:
        return True
    policy_family = _artifact_family_key(policy_artifact_id)
    candidate_family = _artifact_family_key(candidate_artifact_id)
    return policy_family is not None and policy_family == candidate_family


def _filter_approval_candidates(
    rows: list[sqlite3.Row],
    *,
    harness: str,
    artifact_id: str | None,
    artifact_hash: str | None,
) -> list[sqlite3.Row]:
    if not artifact_id and not artifact_hash:
        return []
    hash_variants = set(_artifact_hash_match_variants(artifact_hash)) if artifact_hash else set()
    filtered: list[sqlite3.Row] = []
    seen_request_ids: set[str] = set()
    for row in rows:
        if harness != "*" and str(row["harness"]) != harness:
            continue
        row_artifact_id = str(row["artifact_id"]) if row["artifact_id"] is not None else None
        if not _policy_artifact_matches_candidate(artifact_id, row_artifact_id):
            continue
        if artifact_hash:
            row_hash = str(row["artifact_hash"]) if row["artifact_hash"] is not None else ""
            if row_hash not in hash_variants and _runtime_scoped_exact_match_key(row_artifact_id) != artifact_hash:
                continue
        request_id = str(row["request_id"])
        if request_id in seen_request_ids:
            continue
        seen_request_ids.add(request_id)
        filtered.append(row)
    return filtered


def build_policy_source_context_index(
    connection: sqlite3.Connection,
    *,
    items: list[tuple[str, str | None, str | None]],
) -> PolicySourceContextIndex:
    index = PolicySourceContextIndex()
    if not items:
        return index

    include_all_harnesses, harnesses = _policy_harness_scope(items)
    artifact_ids = sorted({artifact_id for _, artifact_id, _ in items if artifact_id})
    fallback_artifact_ids = sorted(
        {
            artifact_id
            for _, artifact_id, artifact_hash in items
            if artifact_id and (not artifact_hash or _is_runtime_scoped_exact_match_key(artifact_hash))
        }
    )
    runtime_exact_families = sorted(
        {
            family
            for _, artifact_id, artifact_hash in items
            if artifact_hash and _is_runtime_scoped_exact_match_key(artifact_hash)
            for family in [_runtime_exact_match_family(artifact_id)]
            if family is not None
        }
    )
    hash_variants: set[str] = set()
    for _, _, artifact_hash in items:
        if artifact_hash:
            hash_variants.update(_artifact_hash_match_variants(artifact_hash))

    harness_filter_sql, harness_filter_params = _harness_filter_sql(include_all_harnesses, harnesses)

    if fallback_artifact_ids or hash_variants:
        match_clauses: list[str] = []
        params: list[object] = []
        if fallback_artifact_ids:
            artifact_placeholders = ", ".join("?" for _ in fallback_artifact_ids)
            match_clauses.append(f"artifact_id in ({artifact_placeholders})")
            params.extend(fallback_artifact_ids)
        if runtime_exact_families:
            match_clauses.extend("artifact_id like ?" for _ in runtime_exact_families)
            params.extend(f"%:{family}:%" for family in runtime_exact_families)
        if hash_variants:
            hash_placeholders = ", ".join("?" for _ in hash_variants)
            match_clauses.append(f"artifact_hash in ({hash_placeholders})")
            params.extend(sorted(hash_variants))
        receipt_rows = connection.execute(
            f"""
            select {_POLICY_RECEIPT_COLUMNS}
            from runtime_receipts
            where ({" or ".join(match_clauses)})
            {harness_filter_sql}
            order by timestamp desc
            """,
            tuple([*params, *harness_filter_params]),
        ).fetchall()
        for row in receipt_rows:
            harness = str(row["harness"])
            artifact_id = row["artifact_id"]
            if artifact_id is not None and str(artifact_id).strip():
                row_artifact_id = str(artifact_id)
                _append_indexed_row(index.receipts_by_harness_artifact, (harness, row_artifact_id), row)
                exact_key = _runtime_scoped_exact_match_key(row_artifact_id)
                if exact_key is not None:
                    _append_indexed_row(index.receipts_by_harness_hash, (harness, exact_key), row)
            artifact_hash = row["artifact_hash"]
            if artifact_hash is not None and str(artifact_hash).strip():
                for variant in _artifact_hash_match_variants(str(artifact_hash)):
                    _append_indexed_row(index.receipts_by_harness_hash, (harness, variant), row)

    if harnesses and artifact_ids:
        harness_placeholders = ", ".join("?" for _ in harnesses)
        artifact_placeholders = ", ".join("?" for _ in artifact_ids)
        inventory_rows = connection.execute(
            f"""
            select {_POLICY_INVENTORY_COLUMNS}
            from artifact_inventory
            where harness in ({harness_placeholders})
              and artifact_id in ({artifact_placeholders})
            """,
            tuple([*harnesses, *artifact_ids]),
        ).fetchall()
        for row in inventory_rows:
            index.inventory_by_harness_artifact[(str(row["harness"]), str(row["artifact_id"]))] = row

    if fallback_artifact_ids or hash_variants:
        match_clauses = []
        params: list[object] = []
        if fallback_artifact_ids:
            artifact_placeholders = ", ".join("?" for _ in fallback_artifact_ids)
            match_clauses.append(f"artifact_id in ({artifact_placeholders})")
            params.extend(fallback_artifact_ids)
        if runtime_exact_families:
            match_clauses.extend("artifact_id like ?" for _ in runtime_exact_families)
            params.extend(f"%:{family}:%" for family in runtime_exact_families)
        if hash_variants:
            hash_placeholders = ", ".join("?" for _ in hash_variants)
            match_clauses.append(f"artifact_hash in ({hash_placeholders})")
            params.extend(sorted(hash_variants))
        approval_rows = connection.execute(
            f"""
            select {_POLICY_APPROVAL_COLUMNS}
            from approval_requests
            where status = 'resolved'
              and ({" or ".join(match_clauses)})
            {harness_filter_sql}
            order by resolved_at desc
            """,
            tuple([*params, *harness_filter_params]),
        ).fetchall()
        for row in approval_rows:
            harness = str(row["harness"])
            artifact_id = row["artifact_id"]
            if artifact_id is not None and str(artifact_id).strip():
                row_artifact_id = str(artifact_id)
                _append_indexed_row(index.approvals_by_harness_artifact, (harness, row_artifact_id), row)
                exact_key = _runtime_scoped_exact_match_key(row_artifact_id)
                if exact_key is not None:
                    _append_indexed_row(index.approvals_by_harness_hash, (harness, exact_key), row)
            artifact_hash = row["artifact_hash"]
            if artifact_hash is not None and str(artifact_hash).strip():
                for variant in _artifact_hash_match_variants(str(artifact_hash)):
                    _append_indexed_row(index.approvals_by_harness_hash, (harness, variant), row)

    return index


def lookup_policy_source_context(
    index: PolicySourceContextIndex,
    *,
    harness: str,
    artifact_id: str | None,
    artifact_hash: str | None,
    workspace: str | None,
    reason: str | None,
) -> dict[str, str] | None:
    receipt_candidates: list[sqlite3.Row] = []
    if artifact_hash:
        for variant in _artifact_hash_match_variants(artifact_hash):
            _extend_receipt_hash_candidates(index, harness, variant, receipt_candidates)
    if artifact_id and (not artifact_hash or _is_runtime_scoped_exact_match_key(artifact_hash)):
        _extend_receipt_artifact_candidates(index, harness, artifact_id, receipt_candidates)
    receipt_row = _select_best_receipt_row(receipt_candidates, artifact_id)

    inventory_row = (
        index.inventory_by_harness_artifact.get((harness, artifact_id))
        if artifact_id is not None and artifact_id.strip() and harness != "*"
        else None
    )

    approval_candidates_raw: list[sqlite3.Row] = []
    if artifact_id and (not artifact_hash or _is_runtime_scoped_exact_match_key(artifact_hash)):
        _extend_approval_artifact_candidates(index, harness, artifact_id, approval_candidates_raw)
    if artifact_hash:
        for variant in _artifact_hash_match_variants(artifact_hash):
            _extend_approval_hash_candidates(index, harness, variant, approval_candidates_raw)
    approval_candidates = _filter_approval_candidates(
        approval_candidates_raw,
        harness=harness,
        artifact_id=artifact_id,
        artifact_hash=artifact_hash,
    )
    approval_row = _select_best_approval_row(approval_candidates, artifact_id)

    return _build_policy_source_context_from_rows(
        receipt_row=receipt_row,
        inventory_row=inventory_row,
        approval_row=approval_row,
        workspace=workspace,
        reason=reason,
    )
