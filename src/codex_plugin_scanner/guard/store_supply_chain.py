"""Schema for the HOL Guard supply-chain caches.

The native store reads and writes these tables; see
``supply_chain_bundle_cache_op.rs`` in ``hol-guard-runtime``.
"""

from __future__ import annotations


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
