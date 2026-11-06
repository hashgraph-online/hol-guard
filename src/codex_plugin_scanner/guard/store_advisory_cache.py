"""GuardStore advisory cache: Cloud advisories kept for the CLI and product views."""

# pyright: reportAttributeAccessIssue=false

from __future__ import annotations

import json
import sqlite3


class StoreAdvisoryCacheMixin:
    def cache_advisories(self, advisories: list[dict[str, object]], now: str) -> int:
        stored = 0
        for payloads in _advisory_batches([json.dumps(advisory) for advisory in advisories]):
            count = self._native_store_call("cache_advisories", {"payloads": payloads, "now": now})
            if not isinstance(count, int) or isinstance(count, bool):
                raise sqlite3.DatabaseError("native_advisory_cache_invalid")
            stored += count
        return stored

    def list_cached_advisories(self, limit: int | None = 100) -> list[dict[str, object]]:
        rows: list[dict[str, object]] = []
        after: object = None
        while True:
            remaining = None if limit is None or limit < 0 else limit - len(rows)
            page = self._native_store_call("list_cached_advisories", {"limit": remaining, "after": after})
            if not isinstance(page, dict) or not isinstance(page.get("rows"), list):
                raise sqlite3.DatabaseError("native_advisory_cache_invalid")
            rows.extend(page["rows"])
            after = page.get("next")
            if page.get("more") is not True or not page["rows"] or after is None:
                break
        if not all(isinstance(row, dict) for row in rows):
            raise sqlite3.DatabaseError("native_advisory_cache_invalid")
        items: list[dict[str, object]] = []
        for row in rows:
            payload = json.loads(str(row["payload_json"]))
            if isinstance(payload, dict):
                items.append({"cache_key": str(row["publisher_key"]), "updated_at": str(row["updated_at"]), **payload})
        return items


def _advisory_batches(payloads: list[str], budget: int = 1024 * 1024) -> list[list[str]]:
    """Split payloads (sized as escaped again in the request) under the resident frame limit."""
    batches: list[list[str]] = [[]]
    used = 0
    for payload in payloads:
        size = len(json.dumps(payload))
        if batches[-1] and used + size > budget:
            batches.append([])
            used = 0
        batches[-1].append(payload)
        used += size
    return batches
