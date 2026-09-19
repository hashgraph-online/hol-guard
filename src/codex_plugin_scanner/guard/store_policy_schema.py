"""Additive storage columns for authenticated generic policy rows."""

from __future__ import annotations

import sqlite3


def ensure_generic_policy_columns(connection: sqlite3.Connection) -> None:
    existing = {str(row["name"]) for row in connection.execute("pragma table_info(policy_decisions)")}
    for name, column_type in (
        ("exact_command_sha256", "text"),
        ("publisher", "text"),
        ("artifact_hash", "text"),
        ("owner", "text"),
        ("source", "text not null default 'local'"),
        ("expires_at", "text"),
        ("integrity_version", "integer"),
        ("integrity_generation", "integer"),
        ("payload_hash", "text"),
        ("payload_mac", "text"),
        ("integrity_key_id", "text"),
        ("signed_at", "text"),
        ("policy_document_schema_version", "text"),
        ("policy_document_id", "text"),
        ("policy_document_digest", "text"),
        ("policy_rule_id", "text"),
        ("policy_provenance_json", "text"),
    ):
        if name not in existing:
            connection.execute(f"alter table policy_decisions add column {name} {column_type}")
