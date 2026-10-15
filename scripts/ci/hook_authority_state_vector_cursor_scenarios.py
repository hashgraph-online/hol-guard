"""Cursor and freshness scenarios for the hook authority state vector recorder."""

from __future__ import annotations

from hook_authority_state_vector_support import (
    OTHER_KEY_ID,
    T0,
    T1,
    T2,
    T3,
    hook_state,
    op,
)


def cursor_scenarios() -> list[tuple[str, list[dict[str, object]]]]:
    conv = "conv-1"
    command = "git push origin main"
    state_key = hook_state._cursor_pending_shell_state_key(conv, command)
    allow_key = hook_state._cursor_native_shell_allow_state_key(conv, command)
    artifact = {"artifact_id": "cursor:runtime:shell:1", "name": "Shell", "harness": "cursor"}

    def pending_payload(**extra: object) -> dict[str, object]:
        return {
            "conversation_id": conv,
            "saved_at": T0,
            "artifact_id": "cursor:runtime:shell:1",
            "artifact_hash": "hash-authentic",
            "command": command,
            **extra,
        }

    scenarios: list[tuple[str, list[dict[str, object]]]] = []
    scenarios.append(
        (
            "cursor_pending_lifecycle",
            [
                op("cursor_store_pending_state", conversation_id=conv, command=command, payload=pending_payload()),
                op("cursor_append_key", conversation_id=conv, pending_key=state_key),
                op("cursor_append_key", conversation_id=conv, pending_key=state_key),
                op("cursor_load_index", T1, conversation_id=conv),
                op("cursor_load_pending_state", T1, conversation_id=conv, command=command),
                op("cursor_load_pending_state", T1, conversation_id=conv, command=command, state_key=state_key),
                op(
                    "cursor_store_pending_state",
                    T1,
                    conversation_id=conv,
                    command=command,
                    payload=pending_payload(approval_request_ids=["r1"], saved_at=T1),
                ),
                op("cursor_load_pending_state", T1, conversation_id=conv, command=command),
                op("cursor_store_index", T1, conversation_id=conv, pending_keys=[state_key, state_key]),
                op("cursor_load_index", T1, conversation_id=conv),
                op("cursor_store_index", T1, conversation_id=conv, pending_keys=[]),
                op("cursor_load_index", T1, conversation_id=conv),
            ],
        )
    )
    scenarios.append(
        (
            "cursor_pending_context_mismatch_and_expiry",
            [
                op("cursor_store_pending_state", conversation_id=conv, command=command, payload=pending_payload()),
                op("cursor_load_pending_state", T1, conversation_id=conv, command=command, state_key=state_key + "x"),
                op(
                    "cursor_store_pending_state",
                    conversation_id=conv,
                    command=command,
                    payload=pending_payload(conversation_id="conv-2"),
                ),
                op("cursor_load_pending_state", T1, conversation_id=conv, command=command),
                op(
                    "cursor_store_pending_state",
                    conversation_id=conv,
                    command=command,
                    payload=pending_payload(command="other"),
                ),
                op("cursor_load_pending_state", T1, conversation_id=conv, command=command),
                op(
                    "cursor_store_pending_state",
                    conversation_id=conv,
                    command=command,
                    payload=pending_payload(artifact_hash=None),
                ),
                op("cursor_load_pending_state", T1, conversation_id=conv, command=command),
                op("cursor_store_pending_state", conversation_id=conv, command=command, payload=pending_payload()),
                op("cursor_load_pending_state", T3, conversation_id=conv, command=command),
                op("cursor_load_pending_state", T3, conversation_id=conv, command=command),
            ],
        )
    )
    scenarios.append(
        (
            "cursor_pending_tampered_and_unsigned",
            [
                op("cursor_store_pending_state", conversation_id=conv, command=command, payload=pending_payload()),
                {"do": "raw_mutate", "key": state_key, "set": {"artifact_hash": "forged"}},
                op("cursor_load_pending_state", T1, conversation_id=conv, command=command),
                {"do": "raw_set", "key": state_key, "payload": pending_payload()},
                op("cursor_load_pending_state", T1, conversation_id=conv, command=command),
                {"do": "raw_set_text", "key": state_key, "text": "not json at all"},
                op("cursor_load_pending_state", T1, conversation_id=conv, command=command),
            ],
        )
    )
    scenarios.append(
        (
            "cursor_index_integrity",
            [
                op("cursor_append_key", conversation_id=conv, pending_key=state_key),
                {
                    "do": "raw_mutate",
                    "key": "cursor_pending_shells:conv-1",
                    "set": {"pending_keys": ["cursor_pending_shell:other:abc"]},
                },
                op("cursor_load_index", T1, conversation_id=conv),
                op("cursor_append_key", conversation_id=conv, pending_key=state_key),
                {"do": "raw_mutate", "key": "cursor_pending_shells:conv-1", "set": {"conversation_id": "conv-9"}},
                op("cursor_load_index", T1, conversation_id=conv),
                op("cursor_append_key", conversation_id=conv, pending_key=state_key),
                op("cursor_load_index", T3, conversation_id=conv),
                {"do": "key", "present": False},
                op("cursor_append_key", conversation_id=conv, pending_key=state_key),
                op("cursor_store_index", conversation_id=conv, pending_keys=[state_key]),
                op("cursor_store_pending_state", conversation_id=conv, command=command, payload=pending_payload()),
            ],
        )
    )
    scenarios.append(
        (
            "cursor_allowance_lifecycle",
            [
                op(
                    "cursor_record_allow",
                    conversation_id=conv,
                    command=command,
                    artifact=artifact,
                    artifact_hash="hash-authentic",
                ),
                op("cursor_load_allowance", T1, conversation_id=conv, command=command),
                op("cursor_load_allowance", T1, conversation_id=conv, command="git status"),
                op("cursor_load_allowance", T1, conversation_id="conv-2", command=command),
                op("cursor_load_allowance", T2, conversation_id=conv, command=command),
                op("cursor_load_allowance", T3, conversation_id=conv, command=command),
                op("cursor_load_allowance", T3, conversation_id=conv, command=command),
            ],
        )
    )
    scenarios.append(
        (
            "cursor_allowance_tampering",
            [
                op(
                    "cursor_record_allow",
                    conversation_id=conv,
                    command=command,
                    artifact=artifact,
                    artifact_hash="hash-authentic",
                ),
                {"do": "raw_mutate", "key": allow_key, "set": {"artifact_hash": "forged"}},
                op("cursor_load_allowance", T1, conversation_id=conv, command=command),
                op(
                    "cursor_record_allow",
                    conversation_id=conv,
                    command=command,
                    artifact=artifact,
                    artifact_hash="hash-authentic",
                ),
                {"do": "raw_mutate", "key": allow_key, "set": {}, "drop": ["integrity"]},
                op("cursor_load_allowance", T1, conversation_id=conv, command=command),
                op(
                    "cursor_record_allow",
                    conversation_id=conv,
                    command=command,
                    artifact=artifact,
                    artifact_hash="hash-authentic",
                ),
                {"do": "raw_mutate", "key": allow_key, "set": {"action": "deny"}},
                op("cursor_load_allowance", T1, conversation_id=conv, command=command),
                {"do": "raw_set_text", "key": allow_key, "text": "{broken"},
                op("cursor_load_allowance", T1, conversation_id=conv, command=command),
                {"do": "raw_set", "key": allow_key, "payload": ["x"]},
                op("cursor_load_allowance", T1, conversation_id=conv, command=command),
                op(
                    "cursor_record_allow",
                    conversation_id=conv,
                    command=command,
                    artifact=artifact,
                    artifact_hash="hash-authentic",
                ),
                {
                    "do": "raw_copy",
                    "from": allow_key,
                    "to": hook_state._cursor_native_shell_allow_state_key(conv, "git status"),
                },
                op("cursor_load_allowance", T1, conversation_id=conv, command="git status"),
                {"do": "key", "present": False},
                op("cursor_load_allowance", T1, conversation_id=conv, command=command),
                op(
                    "cursor_record_allow",
                    conversation_id=conv,
                    command=command,
                    artifact=artifact,
                    artifact_hash="hash-authentic",
                ),
            ],
        )
    )
    scenarios.append(
        (
            "cursor_allowance_wrong_key_id_and_unsigned",
            [
                op(
                    "cursor_record_allow",
                    conversation_id=conv,
                    command=command,
                    artifact=artifact,
                    artifact_hash="hash-authentic",
                ),
                {"do": "key", "present": True, "key_id": OTHER_KEY_ID},
                op("cursor_load_allowance", T1, conversation_id=conv, command=command),
                {"do": "key", "present": True},
                {
                    "do": "raw_set",
                    "key": allow_key,
                    "payload": {
                        "state_key": allow_key,
                        "conversation_id": conv,
                        "saved_at": T0,
                        "action": "allow",
                        "command": command,
                        "artifact_id": "a",
                    },
                },
                op("cursor_load_allowance", T1, conversation_id=conv, command=command),
            ],
        )
    )
    scenarios.append(
        (
            "cursor_lean_ctx_command_keys",
            [
                op(
                    "cursor_record_allow",
                    conversation_id=conv,
                    command="lean-ctx -c 'git status'",
                    artifact=artifact,
                    artifact_hash="h",
                ),
                op("cursor_load_allowance", T1, conversation_id=conv, command="git status"),
                op("cursor_load_allowance", T1, conversation_id=conv, command="lean-ctx -c 'git status'"),
            ],
        )
    )
    return scenarios


def freshness_scenario() -> tuple[str, list[dict[str, object]]]:
    cases = [
        ("2026-10-11T12:00:00+00:00", "2026-10-11T12:30:00+00:00", 1800),
        ("2026-10-11T12:00:00+00:00", "2026-10-11T12:30:00.000001+00:00", 1800),
        ("2026-10-11T12:00:00Z", "2026-10-11T12:00:00Z", 1800),
        ("2026-10-11T12:00:00", "2026-10-11T12:10:00+00:00", 1800),
        ("2026-10-11T12:00:00+00:00", "2026-10-11T12:10:00", 1800),
        ("2026-10-11T14:00:00+02:00", "2026-10-11T12:10:00+00:00", 1800),
        ("2026-10-11T12:10:00+00:00", "2026-10-11T12:00:00+00:00", 1800),
        ("2026-10-11T12:00:00.123456+00:00", "2026-10-11T12:00:00.123455+00:00", 1800),
        ("not-a-time", "2026-10-11T12:00:00+00:00", 1800),
        ("", "2026-10-11T12:00:00+00:00", 1800),
        (None, "2026-10-11T12:00:00+00:00", 1800),
        ("2026-10-11T12:00:00+00:00", "garbage", 1800),
        ("2026-10-11T12:00:00+00:00", "2026-10-11T12:00:00+00:00", 0),
        ("2026-10-11T12:00:00.5+00:00", "2026-10-11T12:00:01+00:00", 0),
        ("2026-10-11 12:00:00+00:00", "2026-10-11 12:00:30+00:00", 60),
    ]
    actions = [
        {"do": "op", "op": "state_is_fresh", "args": {"saved_at": saved, "now": now, "max_age_seconds": max_age}}
        for saved, now, max_age in cases
    ]
    return "freshness_matrix", actions
