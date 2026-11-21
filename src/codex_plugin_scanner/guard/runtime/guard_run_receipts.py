"""Receipt evidence amendment for Guard wrapper-mode runs."""

from __future__ import annotations

import json
from collections.abc import Mapping

from ..store import GuardStore
from . import runner_native_authority as _authority

_RECEIPT_PAGE_ROWS = 500
_RECEIPT_BATCH_BYTES = 512 * 1024


def _receipt_rowid_cursor(store: GuardStore) -> int:
    with store._connect() as connection:
        row = connection.execute("select coalesce(max(rowid), 0) as cursor from runtime_receipts").fetchone()
    return int(row["cursor"]) if row is not None else 0


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
    # Runtime detector authority is composed in this aggregate, so its receipt
    # evidence is amended in the same local transaction boundary. Rust owns
    # which rows change and how; this function only reads and writes the rows.
    # Only rows of this evaluation's artifacts are projected, in batches that
    # stay under the transport envelope, so unrelated receipts never count.
    with store._connect() as connection:
        batch: list[Mapping[str, object]] = []
        batch_bytes = 0

        def flush() -> None:
            nonlocal batch, batch_bytes
            if not batch:
                return
            updates = _authority.receipt_evidence_updates(
                batch,
                artifact_ids=artifact_ids,
                evidence=evidence,
                approval_source=approval_source,
                source_actions=source_actions,
                replace_existing_source=replace_existing_source,
            )
            for update in updates:
                connection.execute(
                    """
                    update runtime_receipts
                    set scanner_evidence_json = ?, approval_source = ?
                    where rowid = ?
                    """,
                    (
                        json.dumps(update["scanner_evidence"], sort_keys=True),
                        update["approval_source"],
                        update["rowid"],
                    ),
                )
            batch, batch_bytes = [], 0

        cursor = after_rowid
        while True:
            page = connection.execute(
                """
                select rowid, artifact_id, policy_decision, scanner_evidence_json, approval_source
                from runtime_receipts
                where rowid > ?
                order by rowid asc
                limit ?
                """,
                (cursor, _RECEIPT_PAGE_ROWS),
            ).fetchall()
            if not page:
                break
            cursor = int(page[-1]["rowid"])
            for row in page:
                if row["artifact_id"] not in artifact_ids:
                    continue
                row_bytes = len(str(row["scanner_evidence_json"])) + 512
                if batch and batch_bytes + row_bytes > _RECEIPT_BATCH_BYTES:
                    flush()
                batch.append(row)
                batch_bytes += row_bytes
        flush()
