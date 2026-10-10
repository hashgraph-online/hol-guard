"""Transport for the native MCP tool-call policy owner.

Rust decides every non-package MCP tool-call verdict: current floors, provider
and account review, temporary choices, saved reuse, claim disposition, and the
fresh post-claim authority. The resident op is observation driven. It names
the next effect it needs (a store read, the one-shot claim, a fresh authority
refresh); this module runs exactly that effect, appends the result, and asks
again until Rust answers ``ok``. Python never recomputes or overrides a
verdict and never retries an uncertain claim.

Anything but a bound, strictly decoded answer raises
``NativeMcpToolPolicyError`` (a ``ValueError``), so callers fail closed.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Callable, Mapping
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from .native_context import (
    _canonical_request_sha256,
    _resolve_digest_home,
    bind_context_digest_home,
    ensure_resident_prerequisite,
)
from .native_execution import _resident_request
from .native_mcp_tool_evidence import _arguments_dto
from .native_runtime import native_runtime_status
from .native_runtime_resilience import native_record_resident_failure, native_record_resident_success
from .runtime.json_safe_copy import json_safe_copy

if TYPE_CHECKING:
    from .config import GuardConfig
    from .models import GuardArtifact
    from .store import GuardStore

NATIVE_MCP_TOOL_POLICY_FEATURE = "mcp-tool-policy-decide-v1"
_REQUEST_SCHEMA = "guard-mcp-tool-policy-decide-request.v1"
_RESULT_SCHEMA = "guard-mcp-tool-policy-decide-result.v1"
_OPERATION = "mcp_tool_policy_decide"
_UNAVAILABLE = "native_mcp_tool_policy_unavailable"
_RESIDENT_CODE = re.compile(r"^native_mcp_tool_policy_decide_[a-z_]{1,64}$")
_MAX_REQUEST_BYTES = 4 * 1024 * 1024
_MAX_ROUNDS = 64
_TIMEOUT_SECONDS = 5.0
_ACTIONS = frozenset({"allow", "warn", "review", "require-reapproval", "sandbox-required", "block"})
_PAYLOAD_KEYS = frozenset(
    {
        "action",
        "source",
        "signals",
        "summary",
        "risk_categories",
        "normalization_reason_code",
        "original_action",
        "approval_reuse_status",
        "approval_reuse_reason_code",
        "current_action",
        "saved_action",
        "pending_approval_reuse_decision",
        "approval_reuse_claim_disposition",
        "post_claim_revalidated",
        "post_claim_authority",
    }
)

_TEXT = (str,)
_OPTIONAL_TEXT = (str, type(None))
# Required fields (and accepted types) of each effect the resident may name.
_NEED_FIELDS: dict[str, dict[str, tuple[type, ...]]] = {
    "provider_choices": {},
    "provider_authority_hash": {},
    "extension_decision": {"action": _TEXT},
    "grant_lookup": {"harness": _TEXT, "selector": _TEXT},
    "policy_lookup": {
        "harness": _TEXT,
        "artifact_id": _TEXT,
        "artifact_hash": _TEXT,
        "workspace": _OPTIONAL_TEXT,
        "publisher": _OPTIONAL_TEXT,
        "runtime_exact_match_context": _OPTIONAL_TEXT,
        "memory_command": _OPTIONAL_TEXT,
        "memory_artifact_type": _OPTIONAL_TEXT,
        "memory_artifact_name": _OPTIONAL_TEXT,
    },
    "reuse_diagnostic": {
        "harness": _TEXT,
        "artifact_id": _TEXT,
        "artifact_hash": _TEXT,
        "workspace": _OPTIONAL_TEXT,
        "publisher": _OPTIONAL_TEXT,
    },
    "claim": {"decision": (dict,)},
}

FreshAuthority = tuple["GuardConfig", "GuardArtifact", str, object]
FreshAuthorityProvider = Callable[[], FreshAuthority | None]


class NativeMcpToolPolicyError(ValueError):
    """The native owner could not supply a bound MCP tool-call decision."""

    def __init__(self, code: str = "unavailable") -> None:
        super().__init__(f"{_UNAVAILABLE}:{code}" if code else _UNAVAILABLE)
        self.code = code


def _rejected(guard_home: Path, code: str) -> NativeMcpToolPolicyError:
    """Count a reply that arrived but failed binding or validation as a resident failure.

    The shared transport records success once a reply parses, so a resident
    that keeps sending unusable replies would otherwise look healthy.
    """

    status = native_runtime_status()
    if status.identity is not None:
        native_record_resident_failure(status.identity.sha256, guard_home, reason=f"native_mcp_tool_policy_{code}")
    return NativeMcpToolPolicyError(code)


def _accepted(guard_home: Path) -> None:
    """Record resident success once a reply has passed binding and payload validation."""

    status = native_runtime_status()
    if status.identity is not None:
        native_record_resident_success(status.identity.sha256, guard_home)


@dataclass(frozen=True, slots=True)
class NativeToolPolicyResult:
    """Rust's decision DTO plus the authority objects Python supplied."""

    payload: Mapping[str, Any]
    authority: FreshAuthority | None


def _subject(
    config: GuardConfig,
    artifact: GuardArtifact,
    artifact_hash: str,
    arguments: object,
) -> dict[str, object]:
    from .mcp_tool_calls import _tool_call_configuration

    return {
        "config": json_safe_copy(_tool_call_configuration(config)),
        "workspace": str(config.workspace) if config.workspace is not None else None,
        "artifact": json_safe_copy(
            {"name": artifact.name, "command": artifact.command, "metadata": dict(artifact.metadata)}
        ),
        "artifact_type": artifact.artifact_type,
        "artifact_id": artifact.artifact_id,
        "harness": artifact.harness,
        "publisher": artifact.publisher,
        "artifact_hash": artifact_hash,
        "arguments": _arguments_dto(arguments),
    }


def _round_trip(
    guard_home: Path,
    *,
    subject: dict[str, object],
    claim_saved_approval: bool,
    observations: list[dict[str, object]],
) -> dict[str, Any]:
    request: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": f"mcp-tool-policy-{uuid.uuid4().hex}",
        "claim_saved_approval": claim_saved_approval,
        "subject": subject,
        "observations": observations,
    }
    try:
        digest = "sha256:" + _canonical_request_sha256(request)
    except (TypeError, ValueError):
        raise NativeMcpToolPolicyError("request_invalid") from None
    response = _resident_request(
        operation=_OPERATION,
        request=request,
        guard_home=guard_home,
        timeout_seconds=_TIMEOUT_SECONDS,
        required_feature=NATIVE_MCP_TOOL_POLICY_FEATURE,
        response_schema=_RESULT_SCHEMA,
        max_request_bytes=_MAX_REQUEST_BYTES,
        record_success=False,
    )
    if response is None:
        raise NativeMcpToolPolicyError("transport")
    if (
        response.get("schema") != _RESULT_SCHEMA
        or response.get("request_id") != request["request_id"]
        or response.get("request_sha256") != digest
    ):
        raise _rejected(guard_home, "transport")
    status, code = response.get("status"), response.get("code")
    if status == "error":
        _accepted(guard_home)
        raise NativeMcpToolPolicyError(
            code.removeprefix("native_mcp_tool_policy_decide_")
            if isinstance(code, str) and _RESIDENT_CODE.fullmatch(code)
            else "transport"
        )
    if status not in {"ok", "need"} or code != status:
        raise _rejected(guard_home, "transport")
    return response


def _is_action(value: object) -> bool:
    return isinstance(value, str) and value in _ACTIONS


def _validated_decision(payload: object) -> dict[str, Any]:
    invalid = NativeMcpToolPolicyError("payload_invalid")
    if not isinstance(payload, dict) or set(payload) != _PAYLOAD_KEYS:
        raise invalid
    optional_text = ("normalization_reason_code", "original_action", "approval_reuse_reason_code")
    if (
        not _is_action(payload["action"])
        or not isinstance(payload["source"], str)
        or not isinstance(payload["summary"], str)
        or not isinstance(payload["signals"], list)
        or not isinstance(payload["risk_categories"], list)
        or not all(isinstance(item, str) for item in (*payload["signals"], *payload["risk_categories"]))
        or any(payload[key] is not None and not isinstance(payload[key], str) for key in optional_text)
        or payload["approval_reuse_status"] not in (None, "accepted", "rejected", "not-applicable")
        or not all(payload[key] is None or _is_action(payload[key]) for key in ("current_action", "saved_action"))
        or not (
            payload["pending_approval_reuse_decision"] is None
            or isinstance(payload["pending_approval_reuse_decision"], dict)
        )
        or payload["approval_reuse_claim_disposition"] not in (None, "consumed", "retained")
        or not isinstance(payload["post_claim_revalidated"], bool)
        or payload["post_claim_authority"] not in (None, "fresh")
        or (payload["post_claim_authority"] == "fresh") is not payload["post_claim_revalidated"]
    ):
        raise invalid
    return payload


class _Effects:
    """Runs one named effect against the real store, in the correct scope."""

    def __init__(self, store: GuardStore, artifact: GuardArtifact) -> None:
        self.store = store
        self.artifact = artifact
        self.stack = ExitStack()
        self.stack.enter_context(store.connection_scope())

    def close(self) -> None:
        # A fatal or I/O storage failure poisons the connection scope and is
        # re-raised here so storage recovery runs; it is never swallowed.
        self.stack.close()

    def run(self, need: Mapping[str, Any]) -> object:
        kind = need.get("kind")
        fields = _NEED_FIELDS.get(kind) if isinstance(kind, str) else None
        if fields is None:
            raise NativeMcpToolPolicyError("need_unknown")
        for key, types in fields.items():
            if key not in need or not isinstance(need[key], types):
                raise NativeMcpToolPolicyError("need_invalid")
        return getattr(self, f"_need_{kind}")(need)

    def _need_provider_choices(self, _need: Mapping[str, Any]) -> object:
        return json_safe_copy(dict(self.store.read_mcp_provider_choices()))

    def _need_provider_authority_hash(self, _need: Mapping[str, Any]) -> object:
        return {"hash": self.store.read_mcp_provider_authority_hash()}

    def _need_extension_decision(self, need: Mapping[str, Any]) -> object:
        from .local_cli_trust import apply_local_mcp_extension_decision

        decided = apply_local_mcp_extension_decision(self.store, self.artifact, need["action"])
        if decided is None:
            return None
        return {"action": decided[0], "source": decided[1], "summary": decided[2]}

    def _need_grant_lookup(self, need: Mapping[str, Any]) -> object:
        lookup = self.store.resolve_policy_decision_lookup(need["harness"], need["selector"], consume_one_shot=False)
        decision = lookup["decision"]
        return {"decision": None if decision is None else json_safe_copy(dict(decision))}

    def _need_policy_lookup(self, need: Mapping[str, Any]) -> object:
        lookup = self.store.resolve_policy_decision_lookup_with_memory_pattern(
            need["harness"],
            need["artifact_id"],
            artifact_hash=need["artifact_hash"],
            workspace=need["workspace"],
            publisher=need["publisher"],
            runtime_exact_match_context=need["runtime_exact_match_context"],
            memory_command=need["memory_command"],
            memory_artifact_type=need["memory_artifact_type"],
            memory_artifact_name=need["memory_artifact_name"],
            consume_one_shot=False,
        )
        decision = lookup["decision"]
        return {
            "decision": None if decision is None else json_safe_copy(dict(decision)),
            "ignored_local_integrity": lookup["ignored_local_integrity"] is not None,
        }

    def _need_reuse_diagnostic(self, need: Mapping[str, Any]) -> object:
        return {
            "reason": self.store.approval_reuse_validation_reason(
                need["harness"],
                need["artifact_id"],
                need["artifact_hash"],
                need["workspace"],
                need["publisher"],
            )
        }

    def _need_claim(self, need: Mapping[str, Any]) -> object:
        try:
            claimed = self.store.claim_approval_reuse_decision(need["decision"])
        except Exception:
            # Rust decides an uncertain claim and it is never retried. A fatal
            # storage error still poisons the scope and surfaces from close().
            return {"outcome": "uncertain"}
        return {"outcome": "claimed" if claimed is True else "declined"}


def native_evaluate_tool_call(
    *,
    store: GuardStore,
    config: GuardConfig,
    artifact: GuardArtifact,
    artifact_hash: str,
    arguments: object,
    claim_saved_approval: bool,
    fresh_authority_provider: FreshAuthorityProvider | None,
) -> NativeToolPolicyResult:
    """Drive the resident op to a decision; raise ``NativeMcpToolPolicyError`` otherwise."""
    try:
        guard_home = _resolve_digest_home(getattr(store, "guard_home", None))
    except (OSError, RuntimeError, ValueError):
        raise NativeMcpToolPolicyError("home_unbound") from None
    if not ensure_resident_prerequisite(guard_home):
        raise NativeMcpToolPolicyError("home_unprovisioned")
    initial_authority: FreshAuthority = (config, artifact, artifact_hash, arguments)
    subject = _subject(config, artifact, artifact_hash, arguments)
    observations: list[dict[str, object]] = []
    authority: FreshAuthority | None = None
    effects = _Effects(store, artifact)
    try:
        for _ in range(_MAX_ROUNDS):
            reply = _round_trip(
                guard_home,
                subject=subject,
                claim_saved_approval=claim_saved_approval,
                observations=observations,
            )
            if reply["status"] == "ok":
                try:
                    payload = _validated_decision(reply.get("payload"))
                except NativeMcpToolPolicyError as error:
                    raise _rejected(guard_home, error.code) from None
                if payload["post_claim_authority"] == "fresh" and authority is None:
                    raise _rejected(guard_home, "payload_invalid")
                _accepted(guard_home)
                return NativeToolPolicyResult(payload, authority)
            need = reply.get("payload")
            if not isinstance(need, dict):
                raise _rejected(guard_home, "need_invalid")
            _accepted(guard_home)
            if need.get("kind") == "fresh_authority":
                # The claim is committed. Refresh authority without a storage
                # lease, then read policy again in a new scope.
                effects.close()
                bind_context_digest_home(getattr(store, "guard_home", None))
                provided = _fresh_authority(initial_authority, fresh_authority_provider)
                result: object = {"status": "failed"}
                authority = initial_authority
                if provided is not None:
                    authority = provided
                    result = {"status": "provided", "subject": _subject(*provided)}
                effects = _Effects(store, authority[1])
            else:
                result = effects.run(cast("Mapping[str, Any]", need))
            observations.append({"need": need, "result": result})
        raise NativeMcpToolPolicyError("round_limit")
    finally:
        effects.close()


def _fresh_authority(
    initial: FreshAuthority,
    provider: FreshAuthorityProvider | None,
) -> FreshAuthority | None:
    """The refreshed authority, or ``None`` when it cannot be produced."""
    from .mcp_tool_calls import build_tool_call_hash

    config, artifact, _artifact_hash, arguments = initial
    if provider is None:
        try:
            return (
                config,
                artifact,
                build_tool_call_hash(artifact, arguments, workspace=config.workspace or Path.cwd(), config=config),
                arguments,
            )
        except Exception:
            return None
    try:
        return provider()
    except Exception:
        return None


__all__ = [
    "NATIVE_MCP_TOOL_POLICY_FEATURE",
    "FreshAuthority",
    "FreshAuthorityProvider",
    "NativeMcpToolPolicyError",
    "NativeToolPolicyResult",
    "native_evaluate_tool_call",
]
