"""Bounded observation of real request bindings and native posture receipts.

Only observation wrappers are installed. They call the production native edge
unchanged, and the existing receipt witness verifies its durable readback.
The Rust result remains intrinsic in Watch; Python's actual observe argument
and delivered response must instead match that request's acknowledged mode.
"""

from __future__ import annotations

import hashlib
import json
import threading
from collections.abc import Mapping
from dataclasses import replace
from typing import Any
from unittest.mock import patch

from scripts.native_slo_mixed_witness import ReceiptWitness
from scripts.native_slo_workloads import (
    QualificationCase,
    _availability_expected,
    _content,
    _native_post,
    _native_pre,
    _post_expected,
    _pre_expected,
    _validate_projection,
    validate_native_result,
)

POSTURE_ROUTES = tuple(
    (harness, event) for harness in ("claude-code", "codex") for event in ("PreToolUse", "PostToolUse")
)
MAX_POSTURE_ATTEMPTS = 1024
_UNAVAILABLE = frozenset(
    {
        "native_policy_not_ready",
        "native_pre_tool_unavailable",
        "native_post_tool_unavailable",
        "native_command_control_fence_unavailable",
    }
)


def posture_case(harness: str, event: str, mode: str = "enforce") -> QualificationCase:
    if (harness, event) not in POSTURE_ROUTES or mode not in {"enforce", "observe"}:
        raise ValueError("posture route or mode unsupported")
    watch = mode == "observe"
    if event == "PreToolUse":
        body: dict[str, object] = {
            "hook_event_name": event,
            "tool_name": "Bash",
            "tool_input": {"command": "rm -rf /"},
            "guard_remaining_ms": 4000,
        }
        reason = "native_destructive_command"
        expected = _pre_expected(harness, "watch" if watch else "block", reason, recording_only=watch)
        native = _native_pre("block", reason)
    else:
        content = _content(1024, True).decode("ascii")
        digest = hashlib.sha256(content.encode("ascii")).hexdigest()
        body = {
            "hook_event_name": event,
            "tool_name": "Read",
            "tool_response": [{"type": "text", "text": content}],
            "guard_remaining_ms": 4000,
        }
        expected = _post_expected(harness, "watch" if watch else "block", "output_secret_match", digest)
        native = _native_post("block", "output_secret_match", digest)
    return QualificationCase(
        case_id=f"posture-{harness}-{event}-{mode}",
        harness=harness,
        event=event,
        canonical_event=event,
        size_class="small",
        payload=body,
        expected=expected,
        expected_route="native_resident",
        setup="watch" if watch else "normal",
        surface="installed_canonical",
        content_bytes=0,
        wire_bytes=len(json.dumps(body, separators=(",", ":")).encode()),
        payload_kind="inline",
        native_expected=native,
    )


def binding_key(binding: Mapping[str, Any]) -> tuple[object, ...]:
    return tuple(binding.get(key) for key in ("generation", "policy_digest", "runtime_identity", "mode"))


def receipt_intrinsic_matches(receipt: Mapping[str, object], case: QualificationCase) -> bool:
    expected = case.native_expected
    if expected is None:
        return False
    return (
        all(receipt.get(key) == expected.fields.get(key) for key in ("decision", "policy_action", "reason_code"))
        and receipt.get("model_output_action") == expected.fields.get("model_output_action", "not_applicable")
        and receipt.get("observed_policy_action") is None
        and receipt.get("reviewed_output_sha256") is None
        and receipt.get("observe_mode") is False
    )


class PostureWitness(ReceiptWitness):
    def __init__(self, session: Any, *, receipt_profile: str) -> None:
        super().__init__(session, maximum=MAX_POSTURE_ATTEMPTS, receipt_profile=receipt_profile)
        self.contexts: dict[str, dict[str, Any]] = {}
        self.context_lock = threading.Lock()

    def __enter__(self) -> PostureWitness:
        from codex_plugin_scanner.guard.native_decision_receipt import validate_native_decision_receipt

        super().__enter__()
        worker = self.session.daemon._server.hook_worker
        review = worker._review_raw_hook_native

        def observed(**kwargs: Any) -> Any:
            attempt = kwargs.get("payload", {}).get("tool_use_id")
            result = review(**kwargs)
            if not isinstance(attempt, str) or not attempt.startswith("mixed-load-"):
                return result
            binding = kwargs.get("policy_snapshot")
            receipt = validate_native_decision_receipt(result.get("receipt")) if isinstance(result, Mapping) else None
            mode = binding.get("mode") if isinstance(binding, Mapping) else None
            native_valid = False
            intrinsic_valid = False
            native = result.get("result") if isinstance(result, Mapping) else None
            if (
                receipt is not None
                and isinstance(mode, str)
                and mode in {"enforce", "observe"}
                and isinstance(native, Mapping)
            ):
                try:
                    case = posture_case(kwargs["harness"], kwargs["event"], mode)
                    validate_native_result(case, native)
                    native_valid = True
                    intrinsic_valid = receipt_intrinsic_matches(receipt, case)
                except (AssertionError, KeyError, TypeError, ValueError):
                    pass
            proof = {
                "binding": {
                    key: binding.get(key) for key in ("generation", "policy_digest", "runtime_identity", "mode")
                }
                if isinstance(binding, Mapping)
                else None,
                "observe_argument_valid": kwargs.get("observe_mode") is (mode == "observe"),
                "native_valid": native_valid,
                "receipt_present": receipt is not None,
                "receipt_binding_valid": receipt is not None
                and isinstance(binding, Mapping)
                and intrinsic_valid
                and all(
                    receipt.get(native) == binding.get(request)
                    for native, request in (
                        ("policy_generation", "generation"),
                        ("policy_digest", "policy_digest"),
                        ("runtime_identity", "runtime_identity"),
                    )
                )
                and receipt.get("harness") == kwargs.get("harness")
                and receipt.get("event_name") == kwargs.get("event")
                and receipt.get("observe_mode") is False
                and receipt.get("workspace_bound") is True,
            }
            with self.context_lock:
                if attempt in self.contexts or len(self.contexts) >= MAX_POSTURE_ATTEMPTS:
                    self.count("posture_duplicate_or_overflow")
                else:
                    self.contexts[attempt] = proof
            return result

        self._stack.enter_context(patch.object(worker, "_review_raw_hook_native", observed))
        return self

    def context(self, attempt: str) -> dict[str, Any] | None:
        with self.context_lock:
            return self.contexts.get(attempt)


def validate_delivery(
    *,
    case: QualificationCase,
    response: Mapping[str, object],
    context: Mapping[str, Any] | None,
    known_bindings: set[tuple[object, ...]],
    required: str | tuple[object, ...] | None,
) -> str:
    """Return a proven native or unavailable outcome; reject unknown denials."""
    if context is not None and context.get("receipt_present") is True:
        binding = context.get("binding")
        if not isinstance(binding, Mapping) or binding_key(binding) not in known_bindings:
            raise AssertionError("posture receipt has no authenticated acknowledged binding")
        if not all(
            context.get(key) is True for key in ("observe_argument_valid", "native_valid", "receipt_binding_valid")
        ):
            raise AssertionError("posture native request binding or result mismatch")
        if required == "unavailable" or (isinstance(required, tuple) and binding_key(binding) != required):
            raise AssertionError("posture probe used unexpected authority")
        expected = posture_case(case.harness, case.event, str(binding["mode"]))
        _validate_projection(expected.expected, response, case.case_id)
        return "native_resident"
    if isinstance(required, tuple):
        raise AssertionError("posture acknowledged probe has no native receipt")
    if context is not None and context.get("observe_argument_valid") is not True:
        raise AssertionError("posture unavailable request changed acknowledged mode")
    reason = response.get("reason_code")
    if not isinstance(reason, str) or reason not in _UNAVAILABLE:
        raise AssertionError("posture response is not an explicit unavailable outcome")
    expected = _availability_expected(case.harness, case.event, reason)
    _validate_projection(expected, response, replace(case, expected=expected).case_id)
    return "native_fail_safe"
