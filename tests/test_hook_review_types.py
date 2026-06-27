"""Tests for shared hook-review typed API."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.runtime.hook_review_types import (
    HookOutputSummary,
    HookReviewRequest,
    HookReviewResponse,
    HookSourceFileRef,
)


def _response(**overrides: object) -> HookReviewResponse:
    defaults: dict[str, object] = {
        "decision": "allow",
        "reason": None,
        "model_output_action": "allow_original",
    }
    defaults.update(overrides)
    return HookReviewResponse(**defaults)  # type: ignore[arg-type]


class TestHookReviewResponseToHarnessJson:
    def test_decision_and_model_output_action_always_present(self) -> None:
        payload = _response().to_harness_json()
        assert payload["decision"] == "allow"
        assert payload["model_output_action"] == "allow_original"

    def test_omits_none_reason(self) -> None:
        payload = _response(reason=None).to_harness_json()
        assert "reason" not in payload

    def test_includes_non_empty_reason(self) -> None:
        payload = _response(reason="blocked by policy").to_harness_json()
        assert payload["reason"] == "blocked by policy"

    def test_omits_empty_reviewed_output_sha256(self) -> None:
        payload = _response(reviewed_output_sha256=None).to_harness_json()
        assert "reviewed_output_sha256" not in payload

    def test_includes_non_empty_reviewed_output_sha256(self) -> None:
        payload = _response(reviewed_output_sha256="abc123").to_harness_json()
        assert payload["reviewed_output_sha256"] == "abc123"

    def test_omits_none_reviewed_excerpt(self) -> None:
        payload = _response(reviewed_excerpt=None).to_harness_json()
        assert "reviewed_excerpt" not in payload

    def test_includes_reviewed_excerpt_when_set(self) -> None:
        payload = _response(reviewed_excerpt="safe excerpt").to_harness_json()
        assert payload["reviewed_excerpt"] == "safe excerpt"

    def test_omits_none_policy_action(self) -> None:
        payload = _response(policy_action=None).to_harness_json()
        assert "policy_action" not in payload

    def test_includes_policy_action_when_set(self) -> None:
        payload = _response(policy_action="allow").to_harness_json()
        assert payload["policy_action"] == "allow"

    def test_notice_and_reason_code_always_present(self) -> None:
        payload = _response().to_harness_json()
        assert payload["notice"] == "none"
        assert payload["reason_code"] == "unknown"

    def test_block_response_omits_optional_fields(self) -> None:
        payload = _response(
            decision="deny",
            reason="HOL Guard blocked this output.",
            model_output_action="block",
            notice="warning",
            reason_code="secret_detected",
        ).to_harness_json()
        assert payload["decision"] == "deny"
        assert payload["model_output_action"] == "block"
        assert payload["notice"] == "warning"
        assert payload["reason_code"] == "secret_detected"
        assert "reviewed_output_sha256" not in payload
        assert "reviewed_excerpt" not in payload
        assert "policy_action" not in payload


class TestHookReviewRequestImmutability:
    def test_frozen_dataclass(self) -> None:
        request = HookReviewRequest(
            harness="pi",
            event_name="PostToolUse",
            payload={},
            payload_kind="inline",
            config_path=None,
            cwd=Path("/workspace"),
            home_dir=Path("/home"),
            guard_home=Path("/guard"),
            source_scope="project",
        )
        try:
            request.harness = "codex"  # type: ignore[misc]
        except AttributeError:
            pass
        else:
            raise AssertionError("HookReviewRequest should be frozen")

    def test_source_ref_optional(self) -> None:
        request = HookReviewRequest(
            harness="pi",
            event_name="PreToolUse",
            payload={},
            payload_kind="inline",
            config_path=None,
            cwd=None,
            home_dir=Path("/home"),
            guard_home=Path("/guard"),
            source_scope="project",
        )
        assert request.source_ref is None
        assert request.output_summary is None


class TestHookSourceFileRefDefaults:
    def test_adapter_stat_defaults_to_empty(self) -> None:
        ref = HookSourceFileRef(
            version=1,
            path="src/foo.ts",
            output_sha256="abc",
            output_chars=100,
        )
        assert ref.adapter_stat == {}
        assert ref.tool_input_path is None

    def test_adapter_stat_can_be_set(self) -> None:
        ref = HookSourceFileRef(
            version=1,
            path="src/foo.ts",
            output_sha256="abc",
            output_chars=100,
            tool_input_path="src/foo.ts",
            adapter_stat={"size": 100, "mtimeMs": 1760000000000},
        )
        assert ref.adapter_stat == {"size": 100, "mtimeMs": 1760000000000}


class TestHookOutputSummaryDefaults:
    def test_optional_fields_default_none(self) -> None:
        summary = HookOutputSummary(
            text_excerpt="hello",
            excerpt_truncated=False,
            output_sha256="abc",
            output_chars=5,
        )
        assert summary.content_items_seen is None
        assert summary.object_keys_seen is None
        assert summary.max_depth_seen is None
