"""Claude scenarios for the hook authority state vector recorder."""

from __future__ import annotations

from hook_authority_state_vector_support import (
    OTHER_KEY_ID,
    T0,
    T1,
    T2,
    T3,
    T4,
    claude_artifact,
    op,
    pending_keys,
    record_notice,
)


def claude_scenarios() -> list[tuple[str, list[dict[str, object]]]]:
    art = "claude-code:runtime:file-read:.env"
    pk = pending_keys("s1", art)[0]
    cmd = "artifact:" + art
    scenarios: list[tuple[str, list[dict[str, object]]]] = []

    def notice_flow(tool_name: str | None, load_tool: str | None, label: str) -> None:
        scenarios.append(
            (
                label,
                [
                    record_notice(tool=tool_name),
                    op("claude_load_index", session_id="s1"),
                    op("claude_load_notice", T1, session_id="s1", tool_name=load_tool),
                    op(
                        "claude_load_pending",
                        T1,
                        session_id="s1",
                        pending_key=pk,
                        expected_artifact_id=art,
                        expected_artifact_hash="hash-authentic",
                        expected_command=cmd,
                    ),
                    op("claude_load_pending", T1, session_id="s1", pending_key=pk),
                    op("claude_load_single_pending", T1, session_id="s1"),
                    op(
                        "claude_mark_prompt_seen",
                        T1,
                        session_id="s1",
                        artifact_id=art,
                        artifact_hash="hash-authentic",
                        command=cmd,
                    ),
                    op("claude_load_single_pending", T1, session_id="s1"),
                    op("claude_remove_pending", T1, session_id="s1", pending_key=pk),
                    op("claude_load_index", T1, session_id="s1"),
                    op("claude_load_single_pending", T1, session_id="s1"),
                ],
            )
        )

    notice_flow("Read", "Read", "claude_notice_flow_tool_match")
    notice_flow("Read", "Write", "claude_notice_flow_tool_mismatch_no_fallback")
    notice_flow(None, "Read", "claude_notice_flow_session_fallback")
    notice_flow(None, None, "claude_notice_flow_no_tool")

    metadata_artifact = claude_artifact(
        command="git push --force",
        metadata={"raw_command_text": "git push --force origin main", "wrapper_chain": ["bash", "", 3, "sudo"]},
    )
    scenarios.append(
        (
            "claude_notice_command_binding_and_wrapper_chain",
            [
                record_notice(artifact=metadata_artifact),
                op("claude_load_notice", T1, session_id="s1", tool_name="Read"),
                record_notice(artifact=claude_artifact(artifact_id="a2", command="ls -la"), tool="Bash"),
                op("claude_load_notice", T1, session_id="s1", tool_name="Bash"),
                record_notice(
                    artifact=claude_artifact(artifact_id="a3", metadata={"wrapper_chain": "oops"}), tool="Edit"
                ),
                op("claude_load_notice", T1, session_id="s1", tool_name="Edit"),
                op("claude_load_index", T1, session_id="s1"),
            ],
        )
    )
    scenarios.append(
        (
            "claude_two_pending_prompt_seen_selection",
            [
                record_notice(artifact=claude_artifact("a1")),
                record_notice(artifact=claude_artifact("a2"), tool="Bash"),
                op("claude_load_single_pending", T1, session_id="s1"),
                op("claude_load_index", T1, session_id="s1"),
                op(
                    "claude_mark_prompt_seen",
                    T1,
                    session_id="s1",
                    artifact_id="a2",
                    artifact_hash="hash-authentic",
                    command="artifact:a2",
                ),
                op("claude_load_single_pending", T1, session_id="s1"),
                op(
                    "claude_mark_prompt_seen",
                    T1,
                    session_id="s1",
                    artifact_id="a1",
                    artifact_hash="hash-authentic",
                    command="artifact:a1",
                ),
                op("claude_load_single_pending", T1, session_id="s1"),
                op("claude_remove_pending", T1, session_id="s1", pending_key=pending_keys("s1", "a1")[0]),
                op("claude_load_index", T1, session_id="s1"),
                op("claude_load_single_pending", T1, session_id="s1"),
            ],
        )
    )
    scenarios.append(
        (
            "claude_mark_prompt_seen_mismatch_and_missing",
            [
                record_notice(),
                op(
                    "claude_mark_prompt_seen", T1, session_id="s1", artifact_id=art, artifact_hash="forged", command=cmd
                ),
                op("claude_load_index", T1, session_id="s1"),
                op(
                    "claude_mark_prompt_seen",
                    T1,
                    session_id="s1",
                    artifact_id="missing",
                    artifact_hash="x",
                    command="y",
                ),
                op("claude_load_single_pending", T1, session_id="s1"),
            ],
        )
    )
    expiry_flow: list[dict[str, object]] = [
        record_notice(),
        op("claude_load_notice", T2, session_id="s1", tool_name="Read"),
        op("claude_load_notice", T3, session_id="s1", tool_name="Read"),
        op("claude_load_index", T3, session_id="s1"),
        op("claude_load_single_pending", T3, session_id="s1"),
    ]
    scenarios.append(("claude_expiry_boundary", expiry_flow))
    scenarios.append(
        (
            "claude_pending_expired_after_notice_kept",
            [
                record_notice(),
                {"do": "raw_mutate", "key": pk, "set": {}},
                op("claude_load_pending", T3, session_id="s1", pending_key=pk),
                op("claude_load_notice", T3, session_id="s1", tool_name="Read"),
            ],
        )
    )
    scenarios.append(
        (
            "claude_tampered_pending_hash",
            [
                record_notice(),
                {"do": "raw_mutate", "key": pk, "set": {"artifact_hash": "hash-forged"}},
                op("claude_load_notice", T1, session_id="s1", tool_name="Read"),
                op("claude_load_pending", T1, session_id="s1", pending_key=pk),
                op("claude_load_index", T1, session_id="s1"),
            ],
        )
    )
    scenarios.append(
        (
            "claude_tampered_notice",
            [
                record_notice(),
                {"do": "raw_mutate", "key": "claude_permission_notice:s1:Read", "set": {"approval_code": "forged"}},
                op("claude_load_notice", T1, session_id="s1", tool_name="Read"),
                op("claude_load_pending", T1, session_id="s1", pending_key=pk),
            ],
        )
    )
    scenarios.append(
        (
            "claude_missing_integrity_and_json_garbage",
            [
                record_notice(),
                {"do": "raw_mutate", "key": pk, "set": {}, "drop": ["integrity"]},
                op("claude_load_pending", T1, session_id="s1", pending_key=pk),
                {"do": "raw_set_text", "key": "claude_pending_permissions:s1", "text": "{not json"},
                op("claude_load_index", T1, session_id="s1"),
                {"do": "raw_set", "key": "claude_pending_permissions:s1", "payload": ["list"]},
                op("claude_load_index", T1, session_id="s1"),
                {"do": "raw_set_text", "key": "claude_pending_permissions:s1", "text": "42"},
                op("claude_load_index", T1, session_id="s1"),
                {"do": "raw_set", "key": "claude_pending_permissions:s1", "payload": {"integrity": "nope"}},
                op("claude_load_index", T1, session_id="s1"),
            ],
        )
    )
    scenarios.append(
        (
            "claude_state_key_mismatch_copy",
            [
                record_notice(),
                {"do": "raw_copy", "from": pk, "to": pending_keys("s1", "other")[0]},
                op("claude_load_pending", T1, session_id="s1", pending_key=pending_keys("s1", "other")[0]),
                {
                    "do": "raw_copy",
                    "from": "claude_permission_notice:s1:Read",
                    "to": "claude_permission_notice:s2:Read",
                },
                op("claude_load_notice", T1, session_id="s2", tool_name="Read"),
                op("claude_load_notice", T1, session_id="s1", tool_name="Read"),
            ],
        )
    )
    scenarios.append(
        (
            "claude_session_context_mismatch",
            [
                record_notice(),
                op("claude_load_pending", T1, session_id="s2", pending_key=pk),
                op("claude_load_pending", T1, session_id="s1", pending_key=pk, expected_artifact_id="different"),
                op("claude_load_pending", T1, session_id="s1", pending_key=pk, expected_artifact_hash="different"),
                op("claude_load_pending", T1, session_id="s1", pending_key=pk, expected_command="different"),
                op("claude_load_notice", T1, session_id="s1", tool_name="Read"),
            ],
        )
    )
    scenarios.append(
        (
            "claude_index_context_mismatch",
            [
                record_notice(),
                {"do": "raw_mutate", "key": "claude_pending_permissions:s1", "set": {"session_id": "s9"}},
                op("claude_load_index", T1, session_id="s1"),
                record_notice(),
                {
                    "do": "raw_mutate",
                    "key": "claude_pending_permissions:s1",
                    "set": {"pending_keys": ["claude_pending_permission:other:x"]},
                },
                op("claude_load_index", T1, session_id="s1"),
                {
                    "do": "raw_set",
                    "key": "claude_pending_permissions:s1",
                    "payload": {"session_id": "s1", "pending_keys": "x", "saved_at": T0},
                },
                op("claude_load_index", T1, session_id="s1"),
            ],
        )
    )
    scenarios.append(
        (
            "claude_index_duplicates_deduped_and_notice_pending_removed",
            [
                record_notice(),
                record_notice(),
                op("claude_load_index", T1, session_id="s1"),
                {"do": "raw_delete", "key": pk},
                op("claude_load_notice", T1, session_id="s1", tool_name="Read"),
                op("claude_load_index", T1, session_id="s1"),
                op("claude_load_single_pending", T1, session_id="s1"),
            ],
        )
    )
    scenarios.append(
        (
            "claude_pending_with_one_tampered_one_valid",
            [
                record_notice(artifact=claude_artifact("a1")),
                record_notice(artifact=claude_artifact("a2"), tool="Bash"),
                {"do": "raw_mutate", "key": pending_keys("s1", "a1")[0], "set": {"artifact_hash": "forged"}},
                op("claude_load_single_pending", T1, session_id="s1"),
                op("claude_load_index", T1, session_id="s1"),
            ],
        )
    )
    scenarios.append(
        (
            "claude_key_unavailable",
            [
                {"do": "key", "present": False},
                record_notice(),
                op("claude_load_index", T1, session_id="s1"),
                {"do": "key", "present": True},
                record_notice(),
                {"do": "key", "present": False},
                op("claude_load_notice", T1, session_id="s1", tool_name="Read"),
                op("claude_load_pending", T1, session_id="s1", pending_key=pk),
                {"do": "key", "present": True, "key_id": OTHER_KEY_ID},
                op("claude_load_notice", T1, session_id="s1", tool_name="Read"),
                {"do": "key", "present": True},
                record_notice(),
                op(
                    "claude_mark_prompt_seen",
                    T4,
                    session_id="s1",
                    artifact_id=art,
                    artifact_hash="hash-authentic",
                    command=cmd,
                ),
            ],
        )
    )
    scenarios.append(
        (
            "claude_remove_pending_leaves_other_and_drops_empty_index",
            [
                record_notice(artifact=claude_artifact("a1")),
                record_notice(artifact=claude_artifact("a2"), tool="Bash"),
                op("claude_remove_pending", T1, session_id="s1", pending_key=pending_keys("s1", "a2")[0]),
                op("claude_load_index", T1, session_id="s1"),
                op("claude_remove_pending", T1, session_id="s1", pending_key=pending_keys("s1", "a1")[0]),
                op("claude_load_index", T1, session_id="s1"),
                op("claude_remove_pending", T1, session_id="s1", pending_key=pending_keys("s1", "absent")[0]),
            ],
        )
    )
    scenarios.append(
        (
            "claude_unicode_artifact_fields",
            [
                record_notice(artifact=claude_artifact("claude-code:runtime:é:.env", name="Lire ☃")),
                op("claude_load_notice", T1, session_id="s1", tool_name="Read"),
            ],
        )
    )
    return scenarios
