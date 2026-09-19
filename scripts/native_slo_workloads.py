"""Frozen, synthetic hook workloads and independent delivered-response oracles.

No runtime response renderer is imported here. These expectations describe the
2e672d2 contract; updating candidate code must not silently update its oracle.
The daemon-adapter boundary is explicit: it does not prove installed CLI stdout,
exit status, or observation-only hooks' ability to withhold model output.
"""

from __future__ import annotations

import hashlib
import json
import platform
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from dataclasses import replace as replace
from pathlib import Path
from typing import cast

from scripts.native_slo_workload_cases import build_cases as build_cases

_CORPUS_PATH = Path(__file__).resolve().parents[1] / "tests/fixtures/guard-native-qualification/corpus.v1.json"
_MAX_CASES = 2_048
_REMAINING_MS = 4_000
_MISSING = object()
_POLICY_RISK_KEYS = (
    "local_secret_read",
    "credential_exfiltration",
    "data_flow_exfiltration",
    "destructive_shell",
    "encoded_execution",
    "network_egress",
    "prompt_injection",
    "mcp_dangerous_tool",
    "malicious_skill",
    "package_script",
    "persistence",
    "guard_bypass",
    "cloud_advisory",
    "encoded_exfiltration",
    "execution",
    "supply_chain",
    "policy_bypass",
)
_SEMANTIC_FIELDS = (
    "decision",
    "continue",
    "policy_action",
    "model_output_action",
    "reason_code",
    "behavior",
    "interrupt",
    "cancel",
    "permission",
    "hookSpecificOutput.hookEventName",
    "hookSpecificOutput.permissionDecision",
    "observe_mode",
    "observed_policy_action",
    "reviewed_output_sha256",
    "reviewed_excerpt",
)


@dataclass(frozen=True, slots=True)
class ExpectedResponse:
    """Exact semantic projection plus human-readable outcome classification."""

    decision: str
    model_action: str
    reason_class: str
    fields: Mapping[str, object]
    nonempty_fields: tuple[str, ...] = ()
    exact_empty: bool = False

    @property
    def reason_code(self) -> str | None:
        value = self.fields.get("reason_code")
        return value if isinstance(value, str) else None

    @property
    def policy_action(self) -> str | None:
        value = self.fields.get("policy_action")
        return value if isinstance(value, str) else None


@dataclass(frozen=True, slots=True)
class QualificationCase:
    case_id: str
    harness: str
    event: str
    canonical_event: str
    size_class: str
    payload: Mapping[str, object]
    expected: ExpectedResponse
    expected_route: str
    setup: str
    surface: str
    content_bytes: int
    wire_bytes: int
    payload_kind: str
    native_expected: ExpectedResponse | None = None
    boundary: str = "daemon_adapter"
    expected_http_status: int = 200
    validation_scope: str = "full_semantics"

    @property
    def semantic_sample(self) -> bool:
        source_denial = (
            self.payload_kind == "source_file_ref"
            and self.native_expected is not None
            and (self.native_expected.reason_code in {"no_output_to_review", "observe_no_output_to_review"})
        )
        return (
            self.native_expected is not None
            and self.expected_http_status == 200
            and not source_denial
            and self.validation_scope != "platform_source_reference_denial"
        )

    @property
    def installed_enforcement(self) -> bool:
        return self.surface.startswith("installed_") and self.surface != "installed_observation_only"


def corpus_manifest() -> dict[str, object]:
    value = json.loads(_CORPUS_PATH.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or value.get("schema") != "hol-guard.native-qualification-corpus.v1":
        raise ValueError("native_qualification_corpus_invalid")
    return value


def oracle_source_digest() -> str:
    """Bind both frozen expectations and the case builder used by the collector."""
    root = Path(__file__).parent
    sources = {
        name: hashlib.sha256((root / name).read_bytes()).hexdigest()
        for name in ("native_slo_workloads.py", "native_slo_workload_cases.py")
    }
    return hashlib.sha256(json.dumps(sources, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def configuration_text(setup: str) -> str:
    """Explicit synthetic policy to publish before a case, never production defaults.

    Set up a fresh private Guard home before constructing its daemon. The driver
    must inspect the acknowledged effective policy; writing TOML alone is not
    evidence that the native generation has changed.
    """

    if setup not in cast(Mapping[str, object], corpus_manifest()["setup_requirements"]):
        raise ValueError("native_qualification_setup_unknown")
    watch = setup in {"watch", "watch_unavailable"}
    return (
        f'mode = "{"observe" if watch else "enforce"}"\n'
        f'protection_posture = "{"watch" if watch else "protected"}"\n'
        "watch_auto_revert_hours = 0\n"
        'default_action = "allow"\n'
        'subprocess_action = "allow"\n'
        'unknown_publisher_action = "allow"\n'
        'changed_hash_action = "allow"\n'
        'new_network_domain_action = "allow"\n'
        "desktop_notifications = false\n"
        "[risk_actions]\n" + "".join(f'{key} = "allow"\n' for key in _POLICY_RISK_KEYS)
    )


def _pre_expected(
    harness: str, kind: str, reason: str, *, availability: bool = False, recording_only: bool = False
) -> ExpectedResponse:
    action = {"benign": "allow", "watch": "warn", "review": "review", "block": "block"}[kind]
    fields: dict[str, object] = {"policy_action": action, "reason_code": reason}
    direct_response = availability or recording_only
    decision_harness = harness in {"pi", "omp", "grok", "openclaw"} or (direct_response and harness == "hermes")
    simple = harness in {"pi", "omp"} or (direct_response and decision_harness)
    permission = "allow" if kind in {"benign", "watch"} else "deny"
    if kind == "review" and harness not in {"codex", "kimi", "grok", "zcode", "hermes", "pi", "omp"}:
        permission = "ask"
    if decision_harness:
        fields["decision"] = "allow" if kind in {"benign", "watch"} else "deny"
    if not simple:
        fields["hookSpecificOutput.hookEventName"] = "PreToolUse"
        fields["hookSpecificOutput.permissionDecision"] = permission
        if kind in {"benign", "watch"} and harness not in {"grok", "openclaw"}:
            fields["continue"] = True
    if harness in {"pi", "omp"} and kind in {"review", "block"} and not availability:
        fields["model_output_action"] = "block"
    required: tuple[str, ...] = ()
    if kind == "review":
        fields["prompted"] = True
        required = ("approval_request_id", "approval_url", "primary_approval_request_id", "primary_approval_url")
    reason_class = {"benign": "benign", "watch": "observation", "review": "review", "block": "completed_block"}[kind]
    if availability:
        reason_class = "availability_continue" if kind == "watch" else "integrity_block"
    return ExpectedResponse(permission, "not_applicable", reason_class, fields, required)


def _post_expected(harness: str, kind: str, reason: str, digest: str | None = None) -> ExpectedResponse:
    allowed = kind in {"benign", "watch"}
    action = "warn" if kind == "watch" else "allow" if allowed else "block"
    fields: dict[str, object] = {"policy_action": action}
    if harness in {"pi", "omp"}:
        fields.update(
            decision="allow" if allowed else "deny",
            model_output_action="allow_original" if allowed else "block",
            reason_code=reason,
        )
        if allowed and digest is not None:
            fields["reviewed_output_sha256"] = digest
    else:
        fields["hookSpecificOutput.hookEventName"] = "PostToolUse"
        if not allowed:
            fields.update(decision="block", model_output_action="block", reason_code=reason, **{"continue": True})
    return ExpectedResponse(
        "allow" if allowed else "block",
        "allow_original" if allowed else "block",
        "benign" if kind == "benign" else "observation" if kind == "watch" else "completed_block",
        fields,
    )


def _availability_expected(harness: str, event: str, reason: str) -> ExpectedResponse:
    if event == "PreToolUse":
        integrity = reason in {"invalid_hook_payload_reference", "daemon_hook_queue_bytes"}
        result = _pre_expected(harness, "block" if integrity else "watch", reason, availability=True)
        if integrity and harness == "hermes":
            return ExpectedResponse(
                "block", "not_applicable", "integrity_block", {**result.fields, "decision": "block"}
            )
        return result
    if event == "PermissionRequest":
        fields: dict[str, object] = {"reason_code": reason}
        if harness == "copilot":
            fields.update(behavior="deny", interrupt=False)
            return ExpectedResponse("permission_deferred", "not_applicable", "permission_continue", fields)
        fields.update({"continue": True, "hookSpecificOutput.hookEventName": event})
        return ExpectedResponse("continue", "not_applicable", "permission_continue", fields)
    if harness == "grok":
        return ExpectedResponse("observation_only", "not_applicable", "availability_continue", {}, exact_empty=True)
    fields = {"reason_code": reason, "policy_action": "allow"}
    if harness in {"hermes", "openclaw", "pi", "omp"}:
        fields["decision"] = "allow"
    else:
        fields.update({"continue": True, "hookSpecificOutput.hookEventName": event})
    return ExpectedResponse(
        "continue",
        "unreviewed_original" if event == "PostToolUse" else "not_applicable",
        "availability_continue",
        fields,
    )


def _native_pre(kind: str, reason: str) -> ExpectedResponse:
    action = "allow" if kind == "benign" else "review" if kind == "review" else "block"
    return ExpectedResponse(
        "allow" if action == "allow" else "deny",
        "not_applicable",
        kind,
        {
            "decision": "allow" if action == "allow" else "deny",
            "minimum_action": action,
            "policy_action": action,
            "reason_code": reason,
        },
    )


def _native_post(kind: str, reason: str, digest: str) -> ExpectedResponse:
    fields: dict[str, object] = {
        "decision": "allow" if kind == "benign" else "deny",
        "model_output_action": "allow_original" if kind == "benign" else "block",
        "policy_action": "allow" if kind == "benign" else "block",
        "reason_code": reason,
    }
    if kind == "benign":
        fields["reviewed_output_sha256"] = digest
    return ExpectedResponse(str(fields["decision"]), str(fields["model_output_action"]), kind, fields)


def _content(size: int, secret: bool) -> bytes:
    # Deliberately synthetic token; no credential or user source is read.
    prefix = (("gh" + "p_" + "b" * 30 + "\n") if secret else "").encode("ascii")
    unit = b"const guard_value = 1;\n"
    return prefix + (unit * ((size + len(unit) - 1) // len(unit)))[: size - len(prefix)]


def source_reference_supported(*, system: str | None = None, runtime: Path | None = None) -> bool:
    """Keep the original Windows refusal unless the exact artifact supports reads."""
    if (platform.system() if system is None else system) != "Windows":
        return True
    if runtime is None:
        return False
    from scripts.native_slo_source_witness import installed_windows_source_reference_supported

    return installed_windows_source_reference_supported(runtime)


def platform_scope_summary(
    cases: tuple[QualificationCase, ...],
    validated: list[str],
) -> dict[str, object]:
    """Keep proved platform denials separate from completed content review."""
    observed = set(validated)
    source_cases = [case for case in cases if case.payload_kind == "source_file_ref"]
    unsupported = [case for case in cases if case.validation_scope == "platform_source_reference_denial"]
    checked = [case for case in unsupported if case.case_id in observed]
    semantic = [case for case in cases if case.case_id in observed and case.semantic_sample]
    return {
        "reference_review_supported": not unsupported if source_cases else source_reference_supported(),
        "reference_review_qualified": any(case.semantic_sample for case in source_cases)
        and not unsupported
        and all(case.case_id in observed for case in source_cases),
        "platform_denial_declared_cases": len(unsupported),
        "platform_denial_validated_cases": len(checked),
        "platform_denial_contract_passed": bool(unsupported) and len(checked) == len(unsupported),
        "platform_denial_case_digests": sorted(hashlib.sha256(case.case_id.encode()).hexdigest() for case in checked),
        "semantic_validated_cases": len(semantic),
        "semantic_coverage": {
            "size": dict(Counter(case.size_class for case in semantic)),
            "representation": dict(
                Counter(
                    "file_reference" if case.payload_kind == "source_file_ref" else case.payload_kind
                    for case in semantic
                )
            ),
        },
        "missing_scopes": ["source_reference_full_content_review", "source_reference_identity_verification"]
        if unsupported
        else [],
        "platform_denial_timing_eligible": False,
    }


def _at_path(response: Mapping[str, object], path: str) -> object:
    current: object = response
    for name in path.split("."):
        if not isinstance(current, Mapping) or name not in current:
            return _MISSING
        current = current[name]
    return current


def _validate_projection(expected: ExpectedResponse, response: Mapping[str, object], case_id: str) -> None:
    if expected.exact_empty and response:
        raise AssertionError(f"native_qualification_mismatch:{case_id}:expected_empty_object")
    for path in set(_SEMANTIC_FIELDS) | set(expected.fields):
        actual = _at_path(response, path)
        wanted = expected.fields.get(path, _MISSING)
        if wanted is _MISSING:
            if actual is not _MISSING:
                raise AssertionError(f"native_qualification_mismatch:{case_id}:unexpected:{path}")
        elif type(actual) is not type(wanted) or actual != wanted:
            # Never log tool output, source paths, or credentials from a response.
            raise AssertionError(f"native_qualification_mismatch:{case_id}:field:{path}")
    for path in expected.nonempty_fields:
        actual = _at_path(response, path)
        if not isinstance(actual, str) or not actual.strip():
            raise AssertionError(f"native_qualification_mismatch:{case_id}:missing:{path}")


def validate_case(
    case: QualificationCase, response: Mapping[str, object], route: str, *, http_status: int = 200
) -> None:
    """Check one daemon-adapter result; every mismatch fails qualification."""

    if route != case.expected_route:
        raise AssertionError(f"native_qualification_mismatch:{case.case_id}:route")
    if type(http_status) is not int or http_status != case.expected_http_status:
        raise AssertionError(f"native_qualification_mismatch:{case.case_id}:http_status")
    _validate_projection(case.expected, response, case.case_id)


def validate_native_result(case: QualificationCase, response: Mapping[str, object] | None) -> None:
    """Independently check engine results before Watch/availability rendering."""

    if case.native_expected is None:
        if response is not None:
            raise AssertionError(f"native_qualification_mismatch:{case.case_id}:unexpected_native_result")
        return
    if response is None:
        raise AssertionError(f"native_qualification_mismatch:{case.case_id}:missing_native_result")
    _validate_projection(case.native_expected, response, case.case_id)


def installed_response_expectation(case: QualificationCase) -> tuple[ExpectedResponse, int]:
    """Frozen stdout/exit projection for Cursor and Cline installed wrappers.

    Other wrappers need their own observed contract and are deliberately not
    inferred from daemon JSON. This function does not execute a wrapper.
    """

    if not case.surface.startswith("installed_"):
        raise ValueError("native_qualification_not_installed_surface")
    if case.harness == "cursor":
        if case.event in {"afterShellExecution", "afterMCPExecution"}:
            return ExpectedResponse("observation_only", "unreviewed_original", "observation", {}, exact_empty=True), 0
        action = case.expected.policy_action
        permission = "deny" if action == "block" else "ask" if action == "review" else "allow"
        if case.event == "beforeReadFile" and permission == "ask":
            permission = "deny"
        required = ()
        if permission != "allow":
            required = ("user_message",) if case.event == "beforeReadFile" else ("user_message", "agent_message")
        return ExpectedResponse(
            permission, "not_applicable", case.expected.reason_class, {"permission": permission}, required
        ), 2 if permission == "deny" else 0
    if case.harness == "cline":
        blocked = case.expected.policy_action in {"review", "block"}
        pre = case.canonical_event == "PreToolUse"
        fields: dict[str, object] = {"cancel": pre and blocked}
        required = ("contextModification",) if blocked else ()
        if not blocked:
            fields["contextModification"] = ""
        if pre:
            if blocked:
                required += ("errorMessage",)
            else:
                fields["errorMessage"] = ""
        return ExpectedResponse(
            "deny" if pre and blocked else "allow" if pre else "observation_only",
            "not_applicable" if pre else "unreviewed_original",
            case.expected.reason_class,
            fields,
            required,
        ), 0
    raise ValueError("native_qualification_wrapper_oracle_unavailable")


def validate_installed_response(case: QualificationCase, response: Mapping[str, object], exit_code: int) -> None:
    """Validate actual wrapper stdout separately from its daemon response."""

    expected, wanted_exit = installed_response_expectation(case)
    if type(exit_code) is not int or exit_code != wanted_exit:
        raise AssertionError(f"native_qualification_mismatch:{case.case_id}:installed_exit")
    _validate_projection(expected, response, case.case_id)


def validate_setup(case: QualificationCase, evidence: Mapping[str, object]) -> None:
    """Require separately witnessed setup; a label alone is not a fault proof."""

    requirements = cast(dict[str, list[str]], corpus_manifest()["setup_requirements"])[case.setup]
    for requirement in requirements:
        if evidence.get(requirement) is not True:
            raise AssertionError(f"native_qualification_setup_unproven:{case.case_id}:{requirement}")


__all__ = [
    "ExpectedResponse",
    "QualificationCase",
    "build_cases",
    "configuration_text",
    "corpus_manifest",
    "installed_response_expectation",
    "oracle_source_digest",
    "platform_scope_summary",
    "source_reference_supported",
    "validate_case",
    "validate_installed_response",
    "validate_native_result",
    "validate_setup",
]
