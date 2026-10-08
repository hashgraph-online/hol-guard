"""GuardStore domain mixin extracted from store.py."""

# pyright: reportAttributeAccessIssue=false, reportUndefinedVariable=false

from __future__ import annotations

# ruff: noqa: F403,F405
from .store_base import *


class StoreCloudCacheMixin:
    def cache_advisories(self, advisories: list[dict[str, object]], now: str) -> int:
        stored = 0
        with self._connect() as connection:
            for advisory in advisories:
                cache_key = self._advisory_cache_key(advisory)
                connection.execute(
                    """
                    insert into publisher_cache (publisher_key, payload_json, updated_at)
                    values (?, ?, ?)
                    on conflict(publisher_key) do update set
                      payload_json = excluded.payload_json,
                      updated_at = excluded.updated_at
                    """,
                    (cache_key, json.dumps(advisory), now),
                )
                stored += 1
        return stored

    def list_cached_advisories(self, limit: int | None = 100) -> list[dict[str, object]]:
        with self._connect() as connection:
            if limit is None:
                rows = connection.execute(
                    """
                    select publisher_key, payload_json, updated_at
                    from publisher_cache
                    order by updated_at desc
                    """
                ).fetchall()
            else:
                rows = connection.execute(
                    """
                    select publisher_key, payload_json, updated_at
                    from publisher_cache
                    order by updated_at desc
                    limit ?
                    """,
                    (limit,),
                ).fetchall()
        items: list[dict[str, object]] = []
        for row in rows:
            payload = json.loads(str(row["payload_json"]))
            if not isinstance(payload, dict):
                continue
            items.append(
                {
                    "cache_key": str(row["publisher_key"]),
                    "updated_at": str(row["updated_at"]),
                    **payload,
                }
            )
        return items

    def cache_supply_chain_bundle(
        self,
        workspace_id: str,
        response: dict[str, object],
        now: str,
    ) -> None:
        with self._connect() as connection:
            persist_supply_chain_bundle(
                connection,
                workspace_id=workspace_id,
                response=response,
                cached_at=now,
            )

    def get_cached_supply_chain_bundle(self, workspace_id: str) -> dict[str, object] | None:
        with self._connect() as connection:
            return load_supply_chain_bundle(connection, workspace_id=workspace_id)

    def cache_supply_chain_evaluation(
        self,
        *,
        workspace_id: str,
        package_intent_hash: str,
        feed_snapshot_hash: str,
        policy_hash: str,
        scoring_version: str,
        bundle_version: str,
        decision: dict[str, object],
        now: str,
    ) -> None:
        with self._connect() as connection:
            persist_supply_chain_evaluation(
                connection,
                workspace_id=workspace_id,
                package_intent_hash=package_intent_hash,
                feed_snapshot_hash=feed_snapshot_hash,
                policy_hash=policy_hash,
                scoring_version=scoring_version,
                bundle_version=bundle_version,
                decision=decision,
                updated_at=now,
            )

    def get_cached_supply_chain_evaluation(
        self,
        *,
        workspace_id: str,
        package_intent_hash: str,
        feed_snapshot_hash: str,
        policy_hash: str,
        scoring_version: str,
        bundle_version: str,
    ) -> dict[str, object] | None:
        with self._connect() as connection:
            return load_supply_chain_evaluation(
                connection,
                workspace_id=workspace_id,
                package_intent_hash=package_intent_hash,
                feed_snapshot_hash=feed_snapshot_hash,
                policy_hash=policy_hash,
                scoring_version=scoring_version,
                bundle_version=bundle_version,
            )
