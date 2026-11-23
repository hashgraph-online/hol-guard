"""Single policy-decision lookup helpers for GuardStore."""

from __future__ import annotations

from .policy_integrity import is_remote_policy_source


def _native_policy_decision_row(store, decision_id: int) -> dict[str, object] | None:
    """The saved decision ``decision_id``, read by the native store.

    The native store leaves out a temporary approval-gate grant, exactly as the
    listing does, so it reads as no decision.
    """
    reply = store._native_store_call("read_policy_decision_row", {"decision_id": decision_id})
    if not isinstance(reply, dict) or "row" not in reply:
        raise RuntimeError("Guard could not read the saved policy decision.")
    row = reply["row"]
    if row is None:
        return None
    if not isinstance(row, dict):
        raise RuntimeError("Guard could not read the saved policy decision.")
    return row


def get_policy_decision_payload(
    store,
    *,
    decision_id: int,
    now: str,
) -> dict[str, object] | None:
    row = _native_policy_decision_row(store, decision_id)
    if row is None:
        return None
    payload = store._policy_decision_dict_from_row(row)
    if not is_remote_policy_source(str(row["source"])):
        with store._connect() as connection:
            state = store._refresh_policy_integrity_state(connection, now=now, create_key=False)
        key, key_id = store._policy_integrity_secret_material(create=False)
        generation = state.get("generation")
        trusted_generation = generation if isinstance(generation, int) and not isinstance(generation, bool) else None
        integrity_result = store._policy_integrity_results_for_rows(
            [row],
            mode=str(state.get("mode") or "degraded"),
            key=key,
            key_id=key_id,
            trusted_generation=trusted_generation,
        )[0]
        payload["integrity_status"] = integrity_result.status
        payload["integrity_message"] = integrity_result.message
        payload["integrity_mode"] = state.get("mode")
        payload["integrity_enforcement"] = state.get("enforcement")
    store._attach_policy_source_contexts([payload])
    return payload
