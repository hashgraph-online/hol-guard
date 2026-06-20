"""GuardStore domain mixin extracted from store.py."""

# pyright: reportAttributeAccessIssue=false, reportUndefinedVariable=false

from __future__ import annotations

# ruff: noqa: F403,F405
from .store_base import *


class StoreEvidenceMixin:
    def list_evidence(
        self,
        *,
        harness: str | None = None,
        category: str | None = None,
        severity: str | None = None,
        request_id: str | None = None,
        action_identity: str | None = None,
        before_cursor: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, object]]:
        with self._connect() as connection:
            records = _list_evidence_impl(
                connection,
                harness=harness,
                category=category,
                severity=severity,
                request_id=request_id,
                action_identity=action_identity,
                before_cursor=before_cursor,
                limit=limit,
            )
        return [
            {
                "evidence_id": r.evidence_id,
                "action_id": r.action_id,
                "request_id": r.request_id,
                "harness": r.harness,
                "workspace": r.workspace,
                "signal_id": r.signal_id,
                "category": r.category,
                "severity": r.severity,
                "confidence": r.confidence,
                "summary": r.summary,
                "details": r.details,
                "action_identity": r.action_identity,
                "created_at": r.created_at,
            }
            for r in records
        ]

    def add_evidence(self, record: EvidenceRecord) -> None:
        with self._connect() as connection:
            _store_evidence_impl(connection, record)

    @staticmethod
    def _advisory_cache_key(advisory: dict[str, object]) -> str:
        advisory_id = advisory.get("id")
        if isinstance(advisory_id, str) and advisory_id.strip():
            return advisory_id.strip()
        advisory_digest = sha256(
            json.dumps(advisory, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
        ).hexdigest()
        return f"anonymous:{advisory_digest}"
