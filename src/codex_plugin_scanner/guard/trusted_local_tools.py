"""Authenticated, digest-bound grants for read-only local CLI capabilities."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path
from typing import Final, Literal, cast

from .models import GuardAction, PolicyDecision
from .runtime.approval_context import build_runtime_launch_identity, runtime_launch_identity_is_reusable
from .runtime.command_model import CommandSegment, parse_shell_command
from .runtime.command_tokens import executable_name
from .runtime.routine_local_node import routine_local_node_approval_profile
from .trusted_local_tool_jq import safe_jq_arguments
from .trusted_package_tools import _stable_identity_mapping, trusted_package_tool_profile

LocalToolGrantTarget = Literal["capability", "version"]
LocalToolGrantDuration = Literal["15m", "1h", "5h", "version", "always"]

LOCAL_TOOL_GRANT_TARGETS: Final = ("capability", "version")
LOCAL_TOOL_GRANT_DURATIONS: Final = ("15m", "1h", "5h", "version", "always")
_DURATION_SECONDS: Final = {"15m": 900, "1h": 3600, "5h": 18000}
_SELECTOR_PREFIX: Final = "local-tool-grant:v1"
_POLICY_SOURCE: Final = "trusted-local-tool"
_INTERPRETERS: Final = frozenset({"bun", "deno", "node", "nodejs", "python", "python3"})
_READ_ONLY_OPERATIONS: Final = frozenset(
    {
        "check",
        "describe",
        "diff",
        "find",
        "get",
        "inspect",
        "list",
        "query",
        "read",
        "report",
        "search",
        "show",
        "status",
    }
)
_READ_ONLY_HTTP_METHODS: Final = frozenset({"GET", "HEAD", "OPTIONS"})
_HTTP_OPERATIONS: Final = frozenset({"api", "fetch", "query", "request"})
_SIDE_EFFECTING_OPTIONS: Final = frozenset(
    {
        "-o",
        "--apply",
        "--create",
        "--delete",
        "--download",
        "--exec",
        "--execute",
        "--force",
        "--out",
        "--output",
        "--publish",
        "--remove",
        "--save",
        "--send",
        "--update",
        "--upload",
        "--write",
    }
)
_HTTP_METHOD_OPTIONS: Final = frozenset({"-x", "--method", "--request"})
_VARIABLE_READ_SELECTOR_OPTIONS: Final = frozenset({"--path", "--query"})
_HARD_RISK_EXCLUSIONS: Final = (
    "shell_chaining",
    "shell_redirection",
    "embedded_execution",
    "environment_override",
    "unresolved_entrypoint",
    "mutating_capability",
    "untrusted_output_processor",
)


@dataclass(frozen=True, slots=True)
class LocalToolApprovalEligibility:
    tool_name: str
    tool_identity_hash: str
    capability: str
    read_only_reason: str
    trust_basis: Literal["verified-files", "package-profile"] = "verified-files"
    indefinite_allowed: bool = False

    def to_evidence(self) -> dict[str, object]:
        return {
            "source": "trusted_local_tool",
            "version": 1,
            "eligible": True,
            "tool_name": self.tool_name,
            "tool_identity_hash": self.tool_identity_hash,
            "capability": self.capability,
            "read_only_reason": self.read_only_reason,
            "trust_basis": self.trust_basis,
            "indefinite_allowed": self.indefinite_allowed,
        }

    def to_payload(self) -> dict[str, object]:
        package_profile = self.trust_basis == "package-profile"
        reusable_durations = (
            ("15m", "1h", "5h", "always")
            if package_profile and self.indefinite_allowed
            else ("15m", "1h", "5h")
            if package_profile
            else LOCAL_TOOL_GRANT_DURATIONS[:-1]
        )
        return {
            **self.to_evidence(),
            "allowed_targets": ["capability"] if package_profile else list(LOCAL_TOOL_GRANT_TARGETS),
            "allowed_durations": [
                "once",
                *reusable_durations,
            ],
            "hard_risk_exclusions": list(_HARD_RISK_EXCLUSIONS),
        }


@dataclass(frozen=True, slots=True)
class LocalToolGrantSelection:
    target: LocalToolGrantTarget
    duration: LocalToolGrantDuration
    expires_at: str | None
    eligibility: LocalToolApprovalEligibility


def local_tool_approval_eligibility(
    command: str,
    *,
    cwd: Path,
    home_dir: Path | None,
) -> LocalToolApprovalEligibility | None:
    routine_profile = routine_local_node_approval_profile(command, home_dir=home_dir or cwd)
    if routine_profile is not None:
        return LocalToolApprovalEligibility(
            tool_name=routine_profile.tool_name,
            tool_identity_hash=sha256(_canonical_json(routine_profile.identity_material)).hexdigest(),
            capability=routine_profile.capability,
            read_only_reason="Authenticated local developer validation command",
            trust_basis="package-profile",
        )
    model = parse_shell_command(
        command,
        cwd=cwd,
        home_dir=home_dir,
        dialect="posix",
        transport="shell_string",
        extraction_provenance="hook_tool_input",
    )
    if model.confidence != "exact" or model.redirects or model.embedded_commands or len(model.segments) not in {1, 2}:
        return None
    primary = model.segments[0]
    package_profile = trusted_package_tool_profile(primary, cwd=cwd, home_dir=home_dir)
    if package_profile is not None and len(model.segments) == 1:
        identity_hash = sha256(_canonical_json(package_profile.identity_material)).hexdigest()
        return LocalToolApprovalEligibility(
            tool_name=package_profile.tool_name,
            tool_identity_hash=identity_hash,
            capability=package_profile.capability,
            read_only_reason=package_profile.read_only_reason,
            trust_basis="package-profile",
            indefinite_allowed=package_profile.indefinite_allowed,
        )
    if not _safe_top_level_segment(primary, pipeline_index=0):
        return None
    processor_binding: dict[str, object] | None = None
    if len(model.segments) == 2:
        processor = model.segments[1]
        if not _safe_top_level_segment(processor, pipeline_index=1):
            return None
        if executable_name(processor.executable) != "jq":
            return None
        if not safe_jq_arguments(processor.arguments):
            return None
        processor_binding = _reusable_launch_binding(processor, cwd=cwd)
        if processor_binding is None:
            return None
        processor_binding["arguments_sha256"] = sha256(_canonical_json(list(processor.arguments))).hexdigest()

    launch_binding = _reusable_launch_binding(primary, cwd=cwd)
    if launch_binding is None:
        return None
    operation = _local_tool_operation(primary)
    if operation is None:
        return None
    read_only_reason = _read_only_reason(primary.arguments, operation)
    if read_only_reason is None:
        return None
    tool_name = _tool_display_name(primary, launch_binding)
    identity_payload = {
        "version": 1,
        "launch": launch_binding,
        "argument_shape": _argument_shape(primary),
        "output_processor": processor_binding,
    }
    identity_hash = sha256(_canonical_json(identity_payload)).hexdigest()
    return LocalToolApprovalEligibility(
        tool_name=tool_name,
        tool_identity_hash=identity_hash,
        capability=operation,
        read_only_reason=read_only_reason,
    )


def local_tool_approval_payload(request: Mapping[str, object]) -> dict[str, object] | None:
    eligibility = _eligibility_from_request(request)
    return eligibility.to_payload() if eligibility is not None else None


def parse_local_tool_grant_selection(
    request: Mapping[str, object],
    *,
    target: object,
    duration: object,
    now: str,
) -> LocalToolGrantSelection:
    eligibility = _eligibility_from_request(request)
    if eligibility is None:
        raise ValueError("local_tool_approval_ineligible")
    if target not in LOCAL_TOOL_GRANT_TARGETS:
        raise ValueError("invalid_local_tool_grant_target")
    allowed_targets = cast(list[object], eligibility.to_payload()["allowed_targets"])
    if target not in allowed_targets:
        raise ValueError("invalid_local_tool_grant_target")
    if duration not in LOCAL_TOOL_GRANT_DURATIONS:
        raise ValueError("invalid_local_tool_grant_duration")
    allowed_durations = cast(list[object], eligibility.to_payload()["allowed_durations"])
    if duration not in allowed_durations:
        raise ValueError("invalid_local_tool_grant_duration")
    typed_target: LocalToolGrantTarget = target
    typed_duration: LocalToolGrantDuration = duration
    expires_at: str | None = None
    if typed_duration not in {"version", "always"}:
        parsed_now = datetime.fromisoformat(now.replace("Z", "+00:00"))
        if parsed_now.tzinfo is None:
            parsed_now = parsed_now.replace(tzinfo=timezone.utc)
        expires_at = (
            parsed_now.astimezone(timezone.utc) + timedelta(seconds=_DURATION_SECONDS[typed_duration])
        ).isoformat()
    return LocalToolGrantSelection(typed_target, typed_duration, expires_at, eligibility)


def local_tool_grant_decision(
    *,
    harness: str,
    selection: LocalToolGrantSelection,
    reason: str | None,
) -> PolicyDecision:
    return PolicyDecision(
        harness=harness,
        scope="artifact",
        action="allow",
        artifact_id=local_tool_grant_selector(
            selection.eligibility,
            target=selection.target,
        ),
        reason=reason,
        source=_POLICY_SOURCE,
        expires_at=selection.expires_at,
    )


def matching_local_tool_grant(
    *,
    store: object,
    harness: str,
    eligibility: LocalToolApprovalEligibility | None,
    current_action: GuardAction,
) -> dict[str, object] | None:
    if eligibility is None or current_action not in {"review", "require-reapproval"}:
        return None
    resolver = getattr(store, "resolve_policy_decision_lookup", None)
    if not callable(resolver):
        return None
    for target in LOCAL_TOOL_GRANT_TARGETS:
        lookup = resolver(
            harness,
            local_tool_grant_selector(eligibility, target=target),
            consume_one_shot=False,
        )
        if not isinstance(lookup, Mapping):
            continue
        normalized_lookup = dict(cast(Mapping[str, object], lookup))
        decision = normalized_lookup.get("decision")
        if isinstance(decision, Mapping):
            normalized_decision = dict(cast(Mapping[str, object], decision))
            if normalized_decision.get("action") == "allow" and normalized_decision.get("source") == _POLICY_SOURCE:
                return normalized_decision
    return None


def local_tool_grant_selector(
    eligibility: LocalToolApprovalEligibility,
    *,
    target: LocalToolGrantTarget,
) -> str:
    capability = eligibility.capability if target == "capability" else "*"
    capability_hash = sha256(capability.encode("utf-8")).hexdigest()
    return f"{_SELECTOR_PREFIX}:{eligibility.tool_identity_hash}:{target}:{capability_hash}"


def _eligibility_from_request(request: Mapping[str, object]) -> LocalToolApprovalEligibility | None:
    evidence = request.get("scanner_evidence")
    if not isinstance(evidence, Sequence) or isinstance(evidence, str):
        return None
    for item in evidence:
        if not isinstance(item, Mapping):
            continue
        normalized_item = dict(cast(Mapping[str, object], item))
        if normalized_item.get("source") != "trusted_local_tool":
            continue
        tool_name = _nonempty_string(normalized_item.get("tool_name"))
        identity_hash = _nonempty_string(normalized_item.get("tool_identity_hash"))
        capability = _nonempty_string(normalized_item.get("capability"))
        read_only_reason = _nonempty_string(normalized_item.get("read_only_reason"))
        trust_basis = normalized_item.get("trust_basis", "verified-files")
        if (
            normalized_item.get("eligible") is True
            and tool_name is not None
            and identity_hash is not None
            and _is_sha256(identity_hash)
            and capability is not None
            and read_only_reason is not None
            and trust_basis in {"verified-files", "package-profile"}
        ):
            return LocalToolApprovalEligibility(
                tool_name,
                identity_hash,
                capability,
                read_only_reason,
                cast(Literal["verified-files", "package-profile"], trust_basis),
                bool(normalized_item.get("indefinite_allowed", False)),
            )
    return None


def _safe_top_level_segment(segment: CommandSegment, *, pipeline_index: int) -> bool:
    return (
        segment.execution_context == "top:0"
        and segment.pipeline_index == pipeline_index
        and not segment.environment_names
        and not segment.wrapper_chain
        and not segment.path_overridden
        and segment.executable is not None
    )


def _reusable_launch_binding(segment: CommandSegment, *, cwd: Path) -> dict[str, object] | None:
    identity = build_runtime_launch_identity(
        segment.executable,
        args=segment.arguments,
        structured_command=True,
        cwd=cwd,
    )
    if not runtime_launch_identity_is_reusable(identity):
        return None
    executable = identity.get("executable")
    entrypoint = identity.get("entrypoint")
    if not isinstance(executable, Mapping) or not isinstance(entrypoint, Mapping):
        return None
    normalized_executable = dict(cast(Mapping[str, object], executable))
    normalized_entrypoint = dict(cast(Mapping[str, object], entrypoint))
    if normalized_executable.get("status") != "verified":
        return None
    entrypoint_status = normalized_entrypoint.get("status")
    if entrypoint_status not in {"verified", "bound-by-executable"}:
        return None
    if executable_name(segment.executable) in _INTERPRETERS and not str(normalized_entrypoint.get("kind", "")).endswith(
        "-script"
    ):
        return None
    return {
        "executable": _stable_identity_mapping(normalized_executable),
        "entrypoint": _stable_identity_mapping(normalized_entrypoint),
    }


def _local_tool_operation(segment: CommandSegment) -> str | None:
    args = segment.arguments
    if not args:
        return None
    executable = executable_name(segment.executable)
    operation_index = 1 if executable in _INTERPRETERS else 0
    if len(args) <= operation_index:
        return None
    operation = args[operation_index].strip().lower()
    if not operation or operation.startswith("-"):
        return None
    return operation[:80]


def _read_only_reason(arguments: Sequence[str], operation: str) -> str | None:
    if any(_normalized_option(argument) in _SIDE_EFFECTING_OPTIONS for argument in arguments):
        return None
    methods: list[str] = []
    for index, argument in enumerate(arguments):
        option = _normalized_option(argument)
        if option not in _HTTP_METHOD_OPTIONS:
            continue
        if "=" in argument:
            methods.append(argument.split("=", 1)[1].upper())
        elif index + 1 < len(arguments):
            methods.append(arguments[index + 1].upper())
        else:
            return None
    if len(methods) > 1:
        return None
    method = methods[0] if methods else None
    if method in _READ_ONLY_HTTP_METHODS and operation in _HTTP_OPERATIONS:
        return f"http_{method.lower()}"
    if method is not None:
        return None
    return f"operation_{operation}" if operation in _READ_ONLY_OPERATIONS else None


def _argument_shape(segment: CommandSegment) -> list[str]:
    executable = executable_name(segment.executable)
    start = 2 if executable in _INTERPRETERS else 1
    shape: list[str] = []
    arguments = segment.arguments[start:]
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        option = _normalized_option(argument)
        if option is None:
            shape.extend(("<positional>", argument))
            index += 1
            continue
        shape.append(option)
        if "=" in argument:
            value = argument.split("=", 1)[1]
        elif index + 1 < len(arguments) and _normalized_option(arguments[index + 1]) is None:
            index += 1
            value = arguments[index]
        else:
            index += 1
            continue
        shape.append("<selector>" if option in _VARIABLE_READ_SELECTOR_OPTIONS else value)
        index += 1
    return shape


def _normalized_option(argument: str) -> str | None:
    if not argument.startswith("-") or argument == "-":
        return None
    return argument.split("=", 1)[0].lower()


def _tool_display_name(segment: CommandSegment, binding: Mapping[str, object]) -> str:
    entrypoint = binding.get("entrypoint")
    if isinstance(entrypoint, Mapping):
        path = cast(Mapping[str, object], entrypoint).get("path")
        if isinstance(path, str) and path:
            return Path(path).name
    return Path(segment.executable or "local-tool").name


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _nonempty_string(value: object) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


def _is_sha256(value: str | None) -> bool:
    return value is not None and len(value) == 64 and all(character in "0123456789abcdef" for character in value)
