"""Binding-checked, bounded pending review scans."""

from __future__ import annotations

import sqlite3
from collections.abc import Mapping

from .store_review_event_outbox_binding import load_review_oauth_binding, normalized_delivery_binding


def list_pending_review_request_ids(
    connection: sqlite3.Connection,
    *,
    source: str,
    binding: Mapping[str, str],
    limit: int,
    after_request_id: str | None,
    through_request_id: str | None,
    descending: bool,
) -> list[str]:
    normalized = normalized_delivery_binding(
        oauth_subject_hash=binding["oauth_subject_hash"],
        workspace_id=binding["workspace_id"],
        machine_id=binding["machine_id"],
        machine_installation_id=binding["machine_installation_id"],
    )
    current = load_review_oauth_binding(connection, source)
    current_values = (
        (
            current["oauth_subject_hash"],
            current["workspace_id"],
            current["machine_id"],
            current["machine_installation_id"],
        )
        if current is not None
        else None
    )
    if current_values != normalized:
        return []
    query = """
        select a.request_id
        from approval_requests as a
        join guard_review_outbox_request_sequences as s
          on s.local_request_id = a.request_id
        where a.status = 'pending'
          and a.oauth_source = ?
          and s.oauth_source = ?
          and s.oauth_subject_hash = ?
          and s.workspace_id = ?
          and s.machine_id = ?
          and s.machine_installation_id = ?
    """
    parameters: list[object] = [source, source, *normalized]
    if after_request_id is not None:
        query += " and a.request_id > ?"
        parameters.append(after_request_id)
    if through_request_id is not None:
        query += " and a.request_id <= ?"
        parameters.append(through_request_id)
    query += " order by a.request_id " + ("desc" if descending else "asc") + " limit ?"
    parameters.append(max(1, int(limit)))
    rows = connection.execute(query, parameters).fetchall()
    return [str(row["request_id"]) for row in rows]
