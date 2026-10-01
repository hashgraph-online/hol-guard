import hashlib

from codex_plugin_scanner.guard.daemon.hook_worker_responses import harness_json_from_native_post_tool


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def test_cline_native_projection_preserves_reviewed_output_binding() -> None:
    digest = _sha256_text("complete tool output")
    response = {
        "decision": "allow",
        "model_output_action": "allow_original",
        "reviewed_output_sha256": digest,
        "policy_action": "allow",
        "reason": "SECRET_REASON",
        "unreviewed_metadata": "SECRET_METADATA",
    }

    assert harness_json_from_native_post_tool("cline", response) == {
        "decision": "allow",
        "model_output_action": "allow_original",
        "reviewed_output_sha256": digest,
        "policy_action": "allow",
    }


def test_cline_native_projection_preserves_exact_reviewed_excerpt() -> None:
    response = {
        "decision": "allow",
        "model_output_action": "replace_with_reviewed_excerpt",
        "reviewed_excerpt": "SAFE_EXCERPT",
        "reason_code": "output_too_large",
    }

    assert harness_json_from_native_post_tool("cline", response) == {
        "decision": "allow",
        "model_output_action": "replace_with_reviewed_excerpt",
        "reviewed_excerpt": "SAFE_EXCERPT",
    }
