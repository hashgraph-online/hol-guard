from __future__ import annotations

import json

from codex_plugin_scanner.guard.native_runtime_identity import native_request_identity


def test_native_request_identity_is_stable_and_privacy_safe() -> None:
    payload = {
        "hook_event_name": "PostToolUse",
        "tool_response": "private payload value",
    }
    first = native_request_identity(
        binary_sha256="a" * 64,
        runtime_version="3.0.0a1",
        build_sha="b" * 40,
        rule_digest="c" * 64,
        payload=payload,
        source_ref_external_allowed=False,
        payload_kind="inline",
        source_scope="project",
    )
    second = native_request_identity(
        binary_sha256="a" * 64,
        runtime_version="3.0.0a1",
        build_sha="b" * 40,
        rule_digest="c" * 64,
        payload=payload,
        source_ref_external_allowed=False,
        payload_kind="inline",
        source_scope="project",
    )

    assert first == second
    assert first["operation"] == "post_tool_review"
    assert first["payload_size_bytes"] == len(
        json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    )
    snapshot = first["policy_snapshot"]
    assert isinstance(snapshot, dict)
    assert snapshot["generation"] != 0
    assert all(
        isinstance(snapshot[key], str) and len(snapshot[key]) == 64
        for key in (
            "rule_set_digest",
            "strict_config_digest",
            "never_allow_digest",
            "source_policy_digest",
        )
    )
    serialized = json.dumps(first, sort_keys=True)
    assert "private payload value" not in serialized
    assert "/" not in serialized


def test_source_policy_changes_generation_without_exposing_source_values() -> None:
    base = native_request_identity(
        binary_sha256="a" * 64,
        runtime_version="test",
        build_sha="test",
        rule_digest="c" * 64,
        payload={},
        source_ref_external_allowed=False,
        payload_kind="inline",
        source_scope="project",
    )
    external = native_request_identity(
        binary_sha256="a" * 64,
        runtime_version="test",
        build_sha="test",
        rule_digest="c" * 64,
        payload={},
        source_ref_external_allowed=True,
        payload_kind="source_ref",
        source_scope="external",
    )
    assert base["policy_snapshot"] != external["policy_snapshot"]
