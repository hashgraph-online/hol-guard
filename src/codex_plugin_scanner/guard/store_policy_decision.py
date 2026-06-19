"""Single policy-decision lookup helpers for GuardStore."""

from __future__ import annotations

from .policy_integrity import is_remote_policy_source
from .store_policy_source_context import build_policy_source_context_index


def get_policy_decision_payload(
    store,
    *,
    decision_id: int,
    approval_gate_policy_source: str,
    now: str,
) -> dict[str, object] | None:
    query = """
        select decision_id, harness, scope, artifact_id, artifact_hash, workspace, publisher,
               action, reason, owner, source, expires_at, updated_at, integrity_version,
               integrity_generation,
               payload_hash, payload_mac, integrity_key_id, signed_at
        from policy_decisions
        where decision_id = ?
          and not (source = ? and expires_at is not null)
    """
    with store._connect() as connection:
        state = store._refresh_policy_integrity_state(connection, now=now, create_key=False)
        key, key_id = store._policy_integrity_secret_material(create=False)
        row = connection.execute(query, (decision_id, approval_gate_policy_source)).fetchone()
        if row is None:
            return None
        source_context_index = build_policy_source_context_index(
            connection,
            items=[
                (
                    str(row["harness"]),
                    str(row["artifact_id"]) if row["artifact_id"] is not None else None,
                    str(row["artifact_hash"]) if row["artifact_hash"] is not None else None,
                )
            ],
        )
        payload = store._policy_decision_dict_from_row(
            connection,
            row,
            source_context_index=source_context_index,
        )
        if not is_remote_policy_source(row["source"]):
            generation = state.get("generation")
            trusted_generation = (
                generation if isinstance(generation, int) and not isinstance(generation, bool) else None
            )
            integrity_result = store._policy_integrity_result_for_row(
                row,
                mode=str(state.get("mode") or "degraded"),
                key=key,
                key_id=key_id,
                trusted_generation=trusted_generation,
            )
            payload["integrity_status"] = integrity_result.status
            payload["integrity_message"] = integrity_result.message
            payload["integrity_mode"] = state.get("mode")
            payload["integrity_enforcement"] = state.get("enforcement")
        return payload
