"""Local storage helpers for HOL Guard supply-chain bundle caching."""

from __future__ import annotations

import json
import sqlite3


def supply_chain_bundle_schema_statement() -> str:
    """CREATE TABLE IF NOT EXISTS for cached supply-chain bundles."""

    return """
    CREATE TABLE IF NOT EXISTS guard_supply_chain_bundle_cache (
        workspace_id text primary key,
        bundle_version text not null,
        key_id text not null,
        tier text not null,
        policy_hash text not null,
        feed_snapshot_hash text not null,
        scoring_version text not null,
        payload_hash text not null,
        response_json text not null,
        cached_at text not null
    )
    """


def supply_chain_eval_cache_schema_statement() -> str:
    """CREATE TABLE IF NOT EXISTS for local supply-chain evaluation cache."""

    return """
    CREATE TABLE IF NOT EXISTS guard_supply_chain_eval_cache (
        workspace_id text not null,
        package_intent_hash text not null,
        feed_snapshot_hash text not null,
        policy_hash text not null,
        scoring_version text not null,
        bundle_version text not null,
        decision_json text not null,
        updated_at text not null,
        primary key (
            workspace_id,
            package_intent_hash,
            feed_snapshot_hash,
            policy_hash,
            scoring_version,
            bundle_version
        )
    )
    """


def supply_chain_index_statements() -> tuple[str, ...]:
    """Index statements for supply-chain cache tables."""

    return (
        "CREATE INDEX IF NOT EXISTS idx_supply_chain_bundle_cached_at ON guard_supply_chain_bundle_cache(cached_at)",
        (
            "CREATE INDEX IF NOT EXISTS idx_supply_chain_eval_bundle_version ON "
            "guard_supply_chain_eval_cache(bundle_version)"
        ),
        "CREATE INDEX IF NOT EXISTS idx_supply_chain_eval_updated_at ON guard_supply_chain_eval_cache(updated_at)",
    )


def upsert_supply_chain_bundle(
    conn: sqlite3.Connection,
    *,
    workspace_id: str,
    response: dict[str, object],
    cached_at: str,
) -> None:
    """Insert or replace the latest cached supply-chain bundle for a workspace."""

    bundle = response.get("bundle")
    if not isinstance(bundle, dict):
        raise ValueError("response must include a bundle object")
    conn.execute(
        """
        INSERT OR REPLACE INTO guard_supply_chain_bundle_cache (
            workspace_id,
            bundle_version,
            key_id,
            tier,
            policy_hash,
            feed_snapshot_hash,
            scoring_version,
            payload_hash,
            response_json,
            cached_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            workspace_id,
            str(bundle["bundleVersion"]),
            str(bundle["keyId"]),
            str(bundle["tier"]),
            str(bundle["policyHash"]),
            str(bundle["feedSnapshotHash"]),
            str(bundle["scoringVersion"]),
            str(response["payloadHash"]),
            json.dumps(response),
            cached_at,
        ),
    )


def get_supply_chain_bundle(conn: sqlite3.Connection, *, workspace_id: str) -> dict[str, object] | None:
    """Return the cached supply-chain bundle payload for a workspace."""

    row = conn.execute(
        """
        SELECT response_json, cached_at
        FROM guard_supply_chain_bundle_cache
        WHERE workspace_id = ?
        """,
        (workspace_id,),
    ).fetchone()
    if row is None:
        return None
    payload = json.loads(row["response_json"])
    if not isinstance(payload, dict):
        return None
    payload["cached_at"] = row["cached_at"]
    return payload


def upsert_supply_chain_evaluation(
    conn: sqlite3.Connection,
    *,
    workspace_id: str,
    package_intent_hash: str,
    feed_snapshot_hash: str,
    policy_hash: str,
    scoring_version: str,
    bundle_version: str,
    decision: dict[str, object],
    updated_at: str,
) -> None:
    """Insert or replace a cached local evaluation decision."""

    conn.execute(
        """
        INSERT OR REPLACE INTO guard_supply_chain_eval_cache (
            workspace_id,
            package_intent_hash,
            feed_snapshot_hash,
            policy_hash,
            scoring_version,
            bundle_version,
            decision_json,
            updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            workspace_id,
            package_intent_hash,
            feed_snapshot_hash,
            policy_hash,
            scoring_version,
            bundle_version,
            json.dumps(decision),
            updated_at,
        ),
    )


def get_supply_chain_evaluation(
    conn: sqlite3.Connection,
    *,
    workspace_id: str,
    package_intent_hash: str,
    feed_snapshot_hash: str,
    policy_hash: str,
    scoring_version: str,
    bundle_version: str,
) -> dict[str, object] | None:
    """Return a cached local evaluation decision."""

    row = conn.execute(
        """
        SELECT bundle_version, decision_json, updated_at
        FROM guard_supply_chain_eval_cache
        WHERE workspace_id = ?
          AND package_intent_hash = ?
          AND feed_snapshot_hash = ?
          AND policy_hash = ?
          AND scoring_version = ?
          AND bundle_version = ?
        """,
        (
            workspace_id,
            package_intent_hash,
            feed_snapshot_hash,
            policy_hash,
            scoring_version,
            bundle_version,
        ),
    ).fetchone()
    if row is None:
        return None
    decision = json.loads(row["decision_json"])
    if not isinstance(decision, dict):
        return None
    decision["bundle_version"] = row["bundle_version"]
    decision["updated_at"] = row["updated_at"]
    return decision
