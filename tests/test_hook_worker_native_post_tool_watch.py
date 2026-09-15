from codex_plugin_scanner.guard.daemon.hook_worker_native import _watch_native_post_tool_result
from codex_plugin_scanner.guard.daemon.hook_worker_responses import harness_json_from_native_post_tool
from codex_plugin_scanner.guard.runtime.hook_source_read import sha256_text


def _native_deny() -> dict[str, object]:
    return {
        "decision": "deny",
        "model_output_action": "block",
        "policy_action": "block",
        "reason": "output requires review",
    }


def test_complete_inline_recording_only_output_gets_matching_proof() -> None:
    content = "complete tool output"
    payload = {"tool_response": [{"type": "text", "text": content}]}

    result = _watch_native_post_tool_result(_native_deny(), payload)

    assert result["decision"] == "allow"
    assert result["model_output_action"] == "allow_original"
    assert result["reviewed_output_sha256"] == sha256_text(content)
    assert harness_json_from_native_post_tool("pi", result)["reviewed_output_sha256"] == sha256_text(content)


def test_source_ref_proof_is_copied_without_hashing_an_excerpt() -> None:
    digest = "a" * 64
    payload = {
        "guard_source_ref": {"output_sha256": digest},
        "tool_response_summary": {
            "text_excerpt": "bounded excerpt",
            "excerpt_truncated": True,
        },
    }

    result = _watch_native_post_tool_result(_native_deny(), payload)

    assert result["reviewed_output_sha256"] == digest


def test_inherited_excerpt_digest_is_removed_during_allow_original_rewrite() -> None:
    payload = {
        "stdout": "bounded excerpt",
        "tool_response_summary": {
            "text_excerpt": "bounded excerpt",
            "excerpt_truncated": True,
        },
    }
    native = {
        **_native_deny(),
        "reviewed_output_sha256": sha256_text("bounded excerpt"),
    }

    result = _watch_native_post_tool_result(native, payload)

    assert result["decision"] == "allow"
    assert result["model_output_action"] == "allow_original"
    assert "reviewed_output_sha256" not in result


def test_inherited_excerpt_digest_is_removed_from_existing_allow_response() -> None:
    payload = {
        "stdout": "bounded excerpt",
        "tool_response_summary": {
            "text_excerpt": "bounded excerpt",
            "excerpt_truncated": True,
        },
    }
    native = {
        "decision": "allow",
        "model_output_action": "allow_original",
        "policy_action": "warn",
        "reviewed_output_sha256": sha256_text("bounded excerpt"),
    }

    result = _watch_native_post_tool_result(native, payload)

    assert result["decision"] == "allow"
    assert result["model_output_action"] == "allow_original"
    assert "reviewed_output_sha256" not in result


def test_stale_allow_original_uses_canonical_inline_proof() -> None:
    content = "canonical inline output"
    native = {
        "decision": "allow",
        "model_output_action": "allow_original",
        "policy_action": "warn",
        "reviewed_output_sha256": "b" * 64,
    }
    payload = {"tool_response": [{"type": "text", "text": content}]}

    result = _watch_native_post_tool_result(native, payload)

    assert result["reviewed_output_sha256"] == sha256_text(content)


def test_summary_without_digest_falls_back_to_complete_inline_output() -> None:
    content = "complete inline output"
    payload = {
        "tool_response_summary": {"text_excerpt": "bounded excerpt"},
        "tool_response": [{"type": "text", "text": content}],
    }

    result = _watch_native_post_tool_result(_native_deny(), payload)

    assert result["reviewed_output_sha256"] == sha256_text(content)


def test_truncated_or_excerpt_only_output_gets_no_fabricated_proof() -> None:
    payload = {
        "stdout": "bounded excerpt",
        "tool_response_summary": {
            "text_excerpt": "bounded excerpt",
            "excerpt_truncated": True,
        },
    }

    result = _watch_native_post_tool_result(_native_deny(), payload)

    assert "reviewed_output_sha256" not in result
    assert "observe_mode" not in result


def test_existing_observe_mode_is_preserved_during_rewrite() -> None:
    payload = {"stdout": "bounded excerpt"}
    native = {**_native_deny(), "observe_mode": True}

    result = _watch_native_post_tool_result(native, payload)

    assert result["observe_mode"] is True
    assert "reviewed_output_sha256" not in result


def test_truncated_inline_output_gets_no_proof() -> None:
    payload = {"tool_response": ["x"] * 25}

    result = _watch_native_post_tool_result(_native_deny(), payload)

    assert "reviewed_output_sha256" not in result
    assert "observe_mode" not in result
