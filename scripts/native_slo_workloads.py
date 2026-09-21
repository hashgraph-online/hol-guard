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
from dataclasses import dataclass, replace
from pathlib import Path
from typing import cast

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


def source_reference_supported(*, system: str | None = None) -> bool:
    """The audited non-Unix secure opener has no Windows handle-bound walk."""
    return (platform.system() if system is None else system) != "Windows"


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


def build_cases(workspace: Path, *, system: str | None = None) -> tuple[QualificationCase, ...]:
    """Materialize a bounded corpus with shared immutable synthetic source files.

    The caller supplies a private, disposable workspace. Case IDs and output
    bytes are stable; absolute source paths are scoped to that workspace.
    """

    manifest = corpus_manifest()
    sizes = cast(dict[str, int], manifest["size_bytes"])
    routes = cast(dict[str, dict[str, str]], manifest["harness_routes"])
    aliases = cast(dict[str, dict[str, list[str]]], manifest["installed_event_aliases"])
    root = workspace.resolve() / "native-qualification"
    if root.is_symlink():
        raise ValueError("native_qualification_fixture_symlink")
    root.mkdir(parents=True, exist_ok=True)
    contents: dict[tuple[str, bool], tuple[str, str, Path]] = {}
    for size_class, size in sizes.items():
        for secret in (False, True):
            body = _content(size, secret)
            # The native source classifier admits .rs. A .txt file under this
            # neutral directory is intentionally not source-like and blocks
            # before scanning, which cannot qualify either content verdict.
            path = root / f"{'secret' if secret else 'benign'}-{size_class}.rs"
            # Do not follow a pre-existing fixture symlink, even in a caller's
            # purportedly private workspace.
            if path.is_symlink():
                raise ValueError("native_qualification_fixture_symlink")
            if path.exists():
                if path.stat().st_size != len(body) or path.read_bytes() != body:
                    raise ValueError("native_qualification_fixture_changed")
            else:
                with path.open("xb") as stream:
                    stream.write(body)
            contents[size_class, secret] = (body.decode("ascii"), hashlib.sha256(body).hexdigest(), path)
    cases: list[QualificationCase] = []

    def add(
        harness: str,
        event: str,
        canonical: str,
        label: str,
        *,
        payload: Mapping[str, object],
        expected: ExpectedResponse,
        native: ExpectedResponse | None = None,
        setup: str = "normal",
        surface: str = "normalizer_only_not_installed",
        size_class: str = "small",
        content_bytes: int = 0,
        payload_kind: str = "inline",
        route: str = "native_resident",
        status: int = 200,
    ) -> None:
        encoded = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        cases.append(
            QualificationCase(
                f"{harness}/{event}/{label}/{size_class}",
                harness,
                event,
                canonical,
                size_class,
                payload,
                expected,
                route,
                setup,
                surface,
                content_bytes,
                len(encoded),
                payload_kind,
                native,
                expected_http_status=status,
            )
        )

    def pre_payload(event: str, command: str) -> dict[str, object]:
        return {
            "hook_event_name": event,
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "guard_remaining_ms": _REMAINING_MS,
        }

    def post_payload(event: str, size_class: str, secret: bool, source: bool) -> tuple[dict[str, object], str]:
        text, digest, path = contents[size_class, secret]
        payload: dict[str, object] = {
            "hook_event_name": event,
            "tool_name": "Read",
            "guard_remaining_ms": _REMAINING_MS,
        }
        if source:
            payload["tool_input"] = {"file_path": str(path)}
            payload["guard_source_ref"] = {
                "version": 1,
                "path": str(path),
                "output_sha256": digest,
                "output_chars": len(text),
                "tool_input_path": str(path),
            }
        else:
            payload["tool_response"] = [{"type": "text", "text": text}]
        return payload, digest

    for harness, surfaces in sorted(routes.items()):
        pre_surface = surfaces["pre_tool_use"]
        if pre_surface.startswith("installed_"):
            events = aliases.get(harness, {}).get("PreToolUse", ["PreToolUse"])
            for event in events:
                vectors = [
                    ("benign", "pwd", "native_exact_safe_command"),
                    ("dangerous", "rm -rf /", "native_destructive_command"),
                    (
                        "review",
                        "git diff --output=/tmp/guard-qualification.diff README.md",
                        "native_command_review_required",
                    ),
                ]
                if event in {"beforeReadFile", "beforeWriteFile"}:
                    # These are actual file hooks, not shell samples wearing a
                    # different event name. Their intrinsic floor is review.
                    operation = "Read" if event == "beforeReadFile" else "Write"
                    reason = "native_file_read_review" if operation == "Read" else "native_file_write_review"
                    payload = {
                        "hook_event_name": event,
                        "tool_name": operation,
                        "tool_input": {"file_path": "README.md"},
                        "guard_remaining_ms": _REMAINING_MS,
                    }
                    for setup in ("normal", "watch"):
                        add(
                            harness,
                            event,
                            "PreToolUse",
                            setup,
                            payload=payload,
                            expected=_pre_expected(
                                harness,
                                "review" if setup == "normal" else "watch",
                                reason,
                                recording_only=setup == "watch",
                            ),
                            native=_native_pre("review", reason),
                            setup=setup,
                            surface=pre_surface,
                        )
                    continue
                if event == "beforeMCPExecution":
                    reason = "native_mcp_tool_review"
                    payload = {
                        "hook_event_name": event,
                        "tool_name": "mcp__qualification__inspect",
                        "tool_input": {"item": "fixture"},
                        "guard_remaining_ms": _REMAINING_MS,
                    }
                    for setup in ("normal", "watch"):
                        add(
                            harness,
                            event,
                            "PreToolUse",
                            setup,
                            payload=payload,
                            expected=_pre_expected(
                                harness,
                                "review" if setup == "normal" else "watch",
                                reason,
                                recording_only=setup == "watch",
                            ),
                            native=_native_pre("review", reason),
                            setup=setup,
                            surface=pre_surface,
                        )
                    continue
                for label, command, reason in vectors:
                    kind = "block" if label == "dangerous" else label
                    add(
                        harness,
                        event,
                        "PreToolUse",
                        label,
                        payload=pre_payload(event, command),
                        expected=_pre_expected(harness, kind, reason),
                        native=_native_pre(kind, reason),
                        surface=pre_surface,
                    )
                    if kind != "benign":
                        add(
                            harness,
                            event,
                            "PreToolUse",
                            f"watch-{label}",
                            payload=pre_payload(event, command),
                            expected=_pre_expected(harness, "watch", reason, recording_only=True),
                            native=_native_pre(kind, reason),
                            setup="watch",
                            surface=pre_surface,
                        )
                add(
                    harness,
                    event,
                    "PreToolUse",
                    "review-queue-failed",
                    payload=pre_payload(event, vectors[-1][1]),
                    expected=_pre_expected(harness, "block", "native_review_queue_failed"),
                    native=_native_pre("review", vectors[-1][2]),
                    setup="review_queue_failed",
                    surface=pre_surface,
                )
                for setup, reason, route in (
                    ("unavailable", "native_pre_tool_unavailable", "native_fail_safe"),
                    ("watch_unavailable", "native_pre_tool_unavailable", "native_fail_safe"),
                    ("expired", "native_policy_not_ready", "native_fail_safe"),
                    ("revoked", "native_policy_not_ready", "native_fail_safe"),
                    ("off", "native_hook_disabled", "engine_bypassed"),
                    ("integrity", "invalid_hook_payload_reference", "engine_bypassed"),
                    ("queue_bytes", "daemon_hook_queue_bytes", "engine_bypassed"),
                ):
                    payload = pre_payload(event, "curl https://example.test/qualification")
                    if setup == "integrity":
                        payload["guard_payload_ref"] = {"version": 1, "invalid_fixture": True}
                    add(
                        harness,
                        event,
                        "PreToolUse",
                        setup,
                        payload=payload,
                        expected=_availability_expected(harness, "PreToolUse", reason),
                        setup=setup,
                        route=route,
                        surface=pre_surface,
                    )
        post_surface = surfaces["post_tool_use"]
        if not post_surface.startswith("installed_"):
            continue
        for event in aliases.get(harness, {}).get("PostToolUse", ["PostToolUse"]):
            surface = "installed_observation_only" if harness in {"cursor", "cline"} else post_surface
            empty_digest = hashlib.sha256(b"").hexdigest()
            add(
                harness,
                event,
                "PostToolUse",
                "empty-output",
                payload={
                    "hook_event_name": event,
                    "tool_name": "Read",
                    "tool_response": [{"type": "text", "text": ""}],
                    "guard_remaining_ms": _REMAINING_MS,
                },
                expected=_post_expected(harness, "benign", "output_empty_allow", empty_digest),
                native=_native_post("benign", "output_empty_allow", empty_digest),
                surface=surface,
                size_class="empty",
                content_bytes=0,
            )
            for size_class, size in sizes.items():
                source = size_class in {"1m", "max"}
                for kind in ("benign", "block", "watch"):
                    payload, digest = post_payload(event, size_class, kind != "benign", source)
                    reason = (
                        ("source_full_scan_allow" if source else "output_scan_allow")
                        if kind == "benign"
                        else ("source_secret_match" if source else "output_secret_match")
                    )
                    # The resident edge evaluates the intrinsic result with
                    # observe_mode=False. Python Watch delivery changes only
                    # the final action/digest; it preserves the native reason.
                    add(
                        harness,
                        event,
                        "PostToolUse",
                        kind,
                        payload=payload,
                        expected=_post_expected(harness, kind, reason, digest),
                        native=_native_post(kind, reason, digest),
                        setup="watch" if kind == "watch" else "normal",
                        surface=surface,
                        size_class=size_class,
                        content_bytes=size,
                        payload_kind="source_file_ref" if source else "inline",
                    )
            for setup, reason, route in (
                ("unavailable", "native_post_tool_unavailable", "native_fail_safe"),
                ("watch_unavailable", "native_post_tool_unavailable", "native_fail_safe"),
                ("off", "native_hook_disabled", "engine_bypassed"),
            ):
                payload, _ = post_payload(event, "1k", True, False)
                add(
                    harness,
                    event,
                    "PostToolUse",
                    setup,
                    payload=payload,
                    expected=_availability_expected(harness, "PostToolUse", reason),
                    setup=setup,
                    route=route,
                    surface=surface,
                    size_class="1k",
                    content_bytes=sizes["1k"],
                )

    # Keep source identity failures distinct from unavailable native evaluation.
    payload, digest = post_payload("PostToolUse", "1k", False, True)
    reference = cast(dict[str, object], payload["guard_source_ref"])
    reference["output_sha256"] = "0" * 64
    add(
        "pi",
        "PostToolUse",
        "PostToolUse",
        "source-digest-mismatch",
        payload=payload,
        expected=_post_expected("pi", "block", "no_output_to_review"),
        native=_native_post("block", "no_output_to_review", digest),
        surface="installed_canonical_source_ref",
        size_class="1k",
        content_bytes=sizes["1k"],
        payload_kind="source_file_ref",
    )

    # Transport limits use HTTP status and engine bypass, never a semantic deny.
    for size_class in ("1m", "max"):
        payload, _ = post_payload("PostToolUse", size_class, False, False)
        add(
            "pi",
            "PostToolUse",
            "PostToolUse",
            f"inline-http-bound-{size_class}",
            payload=payload,
            expected=ExpectedResponse(
                "transport_rejected", "not_delivered", "http_body_limit", {"error": "request_body_too_large"}
            ),
            route="engine_bypassed",
            status=413,
            surface="transport_boundary",
            size_class=size_class,
            content_bytes=sizes[size_class],
        )

    lifecycle = cast(dict[str, list[str]], manifest["lifecycle_aliases"])
    for canonical, events in lifecycle.items():
        for event in events:
            for harness in ("grok", "claude-code"):
                add(
                    harness,
                    event,
                    canonical,
                    "unavailable",
                    payload={"hook_event_name": event, "guard_remaining_ms": _REMAINING_MS},
                    expected=_availability_expected(harness, canonical, "native_hook_event_unavailable"),
                    route="native_fail_safe",
                    setup="unavailable",
                    surface="lifecycle_observation_only",
                )
    for event in cast(list[str], manifest["permission_aliases"]):
        add(
            "copilot",
            event,
            "PermissionRequest",
            "unavailable",
            payload={"hook_event_name": event, "guard_remaining_ms": _REMAINING_MS},
            expected=_availability_expected("copilot", "PermissionRequest", "native_hook_event_unavailable"),
            route="native_fail_safe",
            setup="unavailable",
            surface="permission_handoff",
        )

    for canonical, events in cast(dict[str, list[str]], manifest["normalizer_only_aliases"]).items():
        for event in events:
            if canonical == "PreToolUse":
                add(
                    "claude-code",
                    event,
                    canonical,
                    "alias",
                    payload=pre_payload(event, "pwd"),
                    expected=_pre_expected("claude-code", "benign", "native_exact_safe_command"),
                    native=_native_pre("benign", "native_exact_safe_command"),
                )
            else:
                payload, digest = post_payload(event, "1k", False, False)
                add(
                    "claude-code",
                    event,
                    canonical,
                    "alias",
                    payload=payload,
                    expected=_post_expected("claude-code", "benign", "output_scan_allow", digest),
                    native=_native_post("benign", "output_scan_allow", digest),
                    size_class="1k",
                    content_bytes=sizes["1k"],
                )
    if len(cases) > _MAX_CASES or len({case.case_id for case in cases}) != len(cases):
        raise ValueError("native_qualification_case_bound_or_duplicate")
    if not source_reference_supported(system=system):
        for index, case in enumerate(cases):
            if case.payload_kind != "source_file_ref":
                continue
            # Both pinned artifacts deliberately reject Windows source opens.
            # This is a separate denial witness, never full-content coverage.
            watch = case.setup == "watch"
            kind = "watch" if watch else "block"
            reason = "no_output_to_review"
            reference = cast(Mapping[str, object], case.payload["guard_source_ref"])
            digest = str(reference["output_sha256"])
            cases[index] = replace(
                case,
                expected=_post_expected(case.harness, kind, reason, digest if watch else None),
                native_expected=_native_post(kind, reason, digest),
                validation_scope="platform_source_reference_denial",
            )
    return tuple(cases)


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
    "platform_scope_summary",
    "source_reference_supported",
    "validate_case",
    "validate_installed_response",
    "validate_native_result",
    "validate_setup",
]
