"""Receipt evidence amendment for Guard wrapper-mode runs."""

from __future__ import annotations

from collections.abc import Mapping

from ..store import GuardStore


def _receipt_rowid_cursor(store: GuardStore) -> int:
    return store.latest_receipt_rowid() or 0


def _append_authority_evidence_to_receipts(
    store: GuardStore,
    *,
    after_rowid: int,
    evaluation: Mapping[str, object],
    evidence: Mapping[str, object],
    approval_source: str,
    source_actions: frozenset[str],
    replace_existing_source: bool = False,
) -> None:
    """Attach runner-composed authority to receipts emitted by one evaluation."""

    raw_artifacts = evaluation.get("artifacts")
    if not isinstance(raw_artifacts, list):
        return
    artifact_ids = {
        artifact_id
        for item in raw_artifacts
        if isinstance(item, Mapping)
        for artifact_id in (item.get("artifact_id"),)
        if isinstance(artifact_id, str) and artifact_id
    }
    if not artifact_ids:
        return
    # The resident reads, merges and rewrites this evaluation's receipts in one
    # write transaction; unrelated receipts are never touched.
    store.amend_receipt_authority_evidence(
        after_rowid=after_rowid,
        artifact_ids=artifact_ids,
        evidence=evidence,
        approval_source=approval_source,
        source_actions=source_actions,
        replace_existing_source=replace_existing_source,
    )
