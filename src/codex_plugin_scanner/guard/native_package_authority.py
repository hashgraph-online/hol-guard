"""Resident transport and DTO adapters for native package operations.

Package evaluation is terminal in ``native_supply_chain_eval``. The older
intent/authority adapters still expose optional transport results; their
production caller cutover remains tracked under RTM-028.
"""

from __future__ import annotations

import json
import os
import time
from collections.abc import Mapping
from dataclasses import asdict
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast, get_args

from .models import GuardAction, GuardArtifact
from .native_context import _canonical_request_sha256, _resolve_digest_home, ensure_resident_prerequisite
from .native_resident_client import native_resident_client_request
from .native_runtime import _isolated_environment, native_runtime_status
from .native_runtime_resilience import (
    native_record_resident_failure,
    native_record_resident_success,
)

if TYPE_CHECKING:
    from .runtime.package_intent_common import PackageIntent

_MAX_REQUEST_BYTES = 256 * 1024
# A workspace audit sends one intent holding every scanned lockfile target, so
# the artifact request takes the same budget as the evaluation it feeds.
_ARTIFACT_MAX_REQUEST_BYTES = 4 * 1024 * 1024
_RESIDENT_PROTOCOL_FEATURE = "resident-protocol-v2"
_PACKAGE_AUTHORITY_FEATURE = "package-authority-v1"
_PACKAGE_EVALUATION_VIEW_FEATURE = "package-evaluation-view-v1"
# Mirrors PACKAGE_EVALUATION_VIEW_MAX_REQUEST_BYTES: the view reads back rows the
# resident answered inside one reply, so its request takes the reply budget.
_EVALUATION_VIEW_MAX_REQUEST_BYTES = 2 * 1024 * 1024
_REQUEST_SCHEMA = "guard-package-authority-request.v1"
_RESULT_SCHEMA = "guard-package-authority-result.v1"
_request_counter = 0


def _request_id() -> str:
    global _request_counter
    _request_counter += 1
    return f"package-authority-{_request_counter}-{time.monotonic_ns()}"


def _unique_response_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate native response field")
        result[key] = value
    return result


def _resident_request(
    *,
    operation: str,
    request: dict[str, object],
    guard_home: Path,
    timeout_seconds: float,
    deadline_monotonic: float | None = None,
    required_features: tuple[str, ...] = (_PACKAGE_AUTHORITY_FEATURE,),
    max_request_bytes: int = _MAX_REQUEST_BYTES,
) -> dict[str, object] | None:
    """Transport shared by package-authority operations; callers own failure handling."""
    if deadline_monotonic is not None:
        now = time.monotonic()
        deadline_monotonic = min(deadline_monotonic, now + timeout_seconds)
        if deadline_monotonic <= now:
            return None
    status = native_runtime_status()
    if not status.available or not status.compatible or status.identity is None or status.capabilities is None:
        return None
    features = set(status.capabilities.features)
    if _RESIDENT_PROTOCOL_FEATURE not in features or any(item not in features for item in required_features):
        return None
    remaining_seconds = timeout_seconds if deadline_monotonic is None else deadline_monotonic - time.monotonic()
    if remaining_seconds <= 0:
        return None

    envelope = {
        "operation": operation,
        "request": request,
        "deadline_budget_ms": max(1, int(remaining_seconds * 1000)),
    }
    try:
        payload = json.dumps(envelope).encode("utf-8")
    except (TypeError, ValueError):
        return None
    if len(payload) > max_request_bytes:
        return None
    environment = _isolated_environment()
    response = native_resident_client_request(
        executable=status.identity.path,
        guard_home=guard_home,
        environment=environment,
        payload=payload,
        timeout_seconds=remaining_seconds,
        deadline_monotonic=deadline_monotonic,
    )
    if response is None:
        native_record_resident_failure(status.identity.sha256, guard_home, reason=f"native_{operation}_transport")
        return None
    try:
        decoded = json.loads(response.decode("utf-8"), object_pairs_hook=_unique_response_object)
    except (UnicodeDecodeError, ValueError):
        native_record_resident_failure(status.identity.sha256, guard_home, reason=f"native_{operation}_malformed")
        return None
    if not isinstance(decoded, dict):
        return None
    if decoded.get("schema") != _RESULT_SCHEMA:
        native_record_resident_failure(status.identity.sha256, guard_home, reason=f"native_{operation}_schema")
        return None
    if decoded.get("status") != "ok":
        # No successful native result. Terminal callers must not reinterpret
        # this as permission to reuse a cached Python decision.
        return None
    native_record_resident_success(status.identity.sha256, guard_home)
    return decoded if isinstance(decoded, dict) else None


def _resident_environment(environment: Mapping[str, str] | None) -> dict[str, str] | None:
    """The environment the resident must resolve the launch in.

    The resident is long-lived, so its own ``PATH`` is the one it was spawned
    with.  A caller that passes no environment still means the ambient one this
    decision is being made in — the Python baseline resolves the manager from
    ``os.environ`` — and a manager the resident cannot reproduce (`npx` absent
    from a spawn-time ``PATH``) makes the launch evidence incomplete and sends
    a contained TypeScript typecheck back to review.  Bind the caller's ``PATH``
    whenever it is not already part of the request.
    """

    ambient_path = os.environ.get("PATH")
    if environment is None:
        return {"PATH": ambient_path} if ambient_path else None
    if "PATH" in environment or not ambient_path:
        return dict(environment)
    return {**environment, "PATH": ambient_path}


class NativePackageIntentUnavailableError(RuntimeError):
    """The resident gave no usable answer to a package intent parse."""


def package_intent_parse_native(
    command_text: str,
    *,
    workspace: Path | None = None,
    home_dir: Path | None = None,
    canonical_command: Mapping[str, object] | None = None,
    environment: Mapping[str, str] | None = None,
    guard_home: Path,
    timeout_seconds: float = 5.0,
    deadline_monotonic: float | None = None,
    require_answer: bool = False,
) -> PackageIntent | None:
    """Hydrate exact intent targets and argv from the bound private channel.

    ``None`` is the resident's "no package intent" answer. With
    ``require_answer``, a missing or malformed answer raises instead of reading
    as no intent, so a caller can fail closed.
    """
    from .runtime.package_intent_common import PackageIntent

    request: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": _request_id(),
        "command_text": command_text,
        "workspace": str(workspace) if workspace is not None else None,
        "home_dir": str(home_dir) if home_dir is not None else None,
        "canonical_command": dict(canonical_command) if canonical_command else None,
        "environment": _resident_environment(environment),
    }
    response = _resident_request(
        operation="package_intent_parse",
        request=request,
        guard_home=guard_home,
        timeout_seconds=timeout_seconds,
        deadline_monotonic=deadline_monotonic,
    )
    if response is None:
        if require_answer:
            raise NativePackageIntentUnavailableError("native_package_intent_unavailable")
        return None
    payload = response.get("payload")
    if not isinstance(payload, dict):
        # An explicit null is the resident's no-intent answer; an omitted field is not.
        if require_answer and (payload is not None or "payload" not in response):
            raise NativePackageIntentUnavailableError("native_package_intent_malformed")
        return None
    runtime_private_metadata = response.get("runtime_private_metadata")
    if not isinstance(runtime_private_metadata, Mapping):
        raise ValueError("native package intent missing private metadata")
    return PackageIntent.from_dict(payload, runtime_private_metadata=runtime_private_metadata)


class NativePackageArtifactUnavailableError(RuntimeError):
    """The resident gave no usable name for a package request review."""


# Every field of the artifact wire. A request artifact never carries a command,
# args, a url, a transport or a publisher, but they are sent as their empty
# forms and must still be present: a reply that quietly grew or lost a field is
# a malformed reply, not an artifact missing a field nobody checked.
_ARTIFACT_WIRE_FIELDS = frozenset(
    {
        "artifact_id",
        "name",
        "harness",
        "artifact_type",
        "source_scope",
        "config_path",
        "command",
        "args",
        "url",
        "transport",
        "publisher",
        "metadata",
        "runtime_private_metadata",
    }
)


def _artifact_from_wire(payload: object) -> GuardArtifact:
    """Rebuild the artifact the resident named, or raise.

    A malformed reply is never read as "no review to name": the caller asked
    because it holds a package request, and an artifact it cannot rebuild
    leaves that request unnamed.
    """

    if not isinstance(payload, Mapping) or set(payload) != _ARTIFACT_WIRE_FIELDS:
        raise NativePackageArtifactUnavailableError("native_package_artifact_malformed")
    metadata = payload["metadata"]
    runtime_private_metadata = payload["runtime_private_metadata"]
    if not isinstance(metadata, Mapping) or not isinstance(runtime_private_metadata, Mapping):
        raise NativePackageArtifactUnavailableError("native_package_artifact_malformed")
    text_fields = ("artifact_id", "name", "harness", "artifact_type", "source_scope", "config_path")
    if any(not isinstance(payload[key], str) for key in text_fields):
        raise NativePackageArtifactUnavailableError("native_package_artifact_malformed")
    # A request artifact launches nothing. A filled launch field is drift, and
    # the model would otherwise drop it for its default without a trace.
    if payload["args"] != [] or any(payload[key] is not None for key in ("command", "url", "transport", "publisher")):
        raise NativePackageArtifactUnavailableError("native_package_artifact_malformed")
    return GuardArtifact(
        artifact_id=str(payload["artifact_id"]),
        name=str(payload["name"]),
        harness=str(payload["harness"]),
        artifact_type=str(payload["artifact_type"]),
        source_scope=str(payload["source_scope"]),
        config_path=str(payload["config_path"]),
        metadata=dict(metadata),
        runtime_private_metadata=dict(runtime_private_metadata),
    )


def package_request_artifact_native(
    intent: PackageIntent,
    *,
    harness: str,
    config_path: str,
    source_scope: str,
    guard_home: Path | None = None,
    timeout_seconds: float = 5.0,
    deadline_monotonic: float | None = None,
) -> GuardArtifact:
    """Ask the resident to name the review ``intent`` earns.

    The request carries the intent exactly as the caller holds it — ``asdict``,
    not the sanitized ``to_dict`` the public metadata carries. The artifact's
    fingerprint hashes the exact ``raw_spec``, ``source_url`` and argv, so an
    intent sent in its redacted spelling would key the review under an id no
    earlier approval was stored under. Those exact values already cross this
    channel in the other direction, as the private metadata of a parsed intent.

    Every outcome other than a well-formed, request-bound ``ok`` reply raises:
    the artifact id is the key a saved approval is matched under, and deriving
    it here instead would put a second implementation in charge of which
    review an approval stands for.
    """

    home = _resolve_digest_home(guard_home)
    if not ensure_resident_prerequisite(home):
        raise NativePackageArtifactUnavailableError("native_package_artifact_unavailable")
    request: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": _request_id(),
        "intent": asdict(intent),
        "harness": harness,
        "config_path": config_path,
        "source_scope": source_scope,
    }
    try:
        request_sha256 = "sha256:" + _canonical_request_sha256(request)
    except (TypeError, ValueError) as error:
        raise NativePackageArtifactUnavailableError("native_package_artifact_unavailable") from error
    response = _resident_request(
        operation="package_request_artifact",
        request=request,
        guard_home=home,
        timeout_seconds=timeout_seconds,
        deadline_monotonic=deadline_monotonic,
        max_request_bytes=_ARTIFACT_MAX_REQUEST_BYTES,
    )
    if response is None:
        raise NativePackageArtifactUnavailableError("native_package_artifact_unavailable")
    if response.get("request_id") != request["request_id"] or response.get("request_sha256") != request_sha256:
        # Another request's artifact id would file this review under an approval
        # it never earned.
        identity = native_runtime_status().identity
        if identity is not None:
            native_record_resident_failure(identity.sha256, home, reason="native_package_request_artifact_unbound")
        raise NativePackageArtifactUnavailableError("native_package_artifact_unbound")
    return _artifact_from_wire(response.get("payload"))


class NativePackageEvaluationViewUnavailableError(RuntimeError):
    """The resident gave no usable view of a stored package evaluation."""


def _view_malformed() -> NativePackageEvaluationViewUnavailableError:
    return NativePackageEvaluationViewUnavailableError("native_package_evaluation_view_malformed")


# Every field of the view wire. The caller reads this reply as a settled
# evaluation, so a field missing here is not a field to default: filling one in
# would put a second answer beside the resident's, which is the duplication
# this route exists to remove.
_EVALUATION_VIEW_WIRE_FIELDS = frozenset(
    {
        "decision",
        "policy_action",
        "enforcement",
        "entitlement_state",
        "cache_status",
        "package_intent_hash",
        "policy_version",
        "bundle_version",
        "workspace_fingerprint",
        "reasons",
        "packages",
        "matched_rule_id",
        "exception_id",
        "risk_summary",
        "record_monitor_evidence",
        "refresh_required",
        "evidence_ids",
        "external_archive_source_hashes",
        "user_copy",
    }
)

_EVALUATION_VIEW_USER_COPY_FIELDS = frozenset({"title", "summary", "next_step", "dashboard_url", "harness_message"})

_EVALUATION_VIEW_TEXT_FIELDS = (
    "decision",
    "policy_action",
    "enforcement",
    "entitlement_state",
    "cache_status",
    "package_intent_hash",
    "policy_version",
    "risk_summary",
)


def _view_optional_text(value: object) -> str | None:
    if value is None or isinstance(value, str):
        return value
    raise _view_malformed()


def _view_text_tuple(value: object) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise _view_malformed()
    return tuple(value)


def _view_row_tuple(value: object) -> tuple[dict[str, object], ...]:
    if not isinstance(value, list) or any(not isinstance(item, Mapping) for item in value):
        raise _view_malformed()
    return tuple(dict(item) for item in value)


def _evaluation_from_view(payload: object) -> Any:
    """Rebuild the typed shape from the resident's view, or raise.

    Local import keeps the module importable without the eval dep.
    """

    from .runtime.package_request_evaluation import PackageRequestEvaluation, SupplyChainUserCopy

    if not isinstance(payload, Mapping) or set(payload) != _EVALUATION_VIEW_WIRE_FIELDS:
        raise _view_malformed()
    user_copy = payload["user_copy"]
    if not isinstance(user_copy, Mapping) or set(user_copy) != _EVALUATION_VIEW_USER_COPY_FIELDS:
        raise _view_malformed()
    if any(not isinstance(payload[key], str) for key in _EVALUATION_VIEW_TEXT_FIELDS):
        raise _view_malformed()
    if any(not isinstance(payload[key], bool) for key in ("record_monitor_evidence", "refresh_required")):
        raise _view_malformed()
    if any(not isinstance(user_copy[key], str) for key in ("title", "summary", "harness_message")):
        raise _view_malformed()
    policy_action = payload["policy_action"]
    # The resident already settled the action; a value outside the lattice means
    # this is not the view it decided, so the reply is refused rather than read.
    if policy_action not in get_args(GuardAction):
        raise _view_malformed()
    return PackageRequestEvaluation(
        decision=str(payload["decision"]),
        policy_action=cast(GuardAction, policy_action),
        enforcement=str(payload["enforcement"]),
        entitlement_state=str(payload["entitlement_state"]),
        cache_status=str(payload["cache_status"]),
        package_intent_hash=str(payload["package_intent_hash"]),
        policy_version=str(payload["policy_version"]),
        bundle_version=_view_optional_text(payload["bundle_version"]),
        workspace_fingerprint=_view_optional_text(payload["workspace_fingerprint"]),
        reasons=_view_row_tuple(payload["reasons"]),
        packages=_view_row_tuple(payload["packages"]),
        risk_summary=str(payload["risk_summary"]),
        user_copy=SupplyChainUserCopy(
            title=str(user_copy["title"]),
            summary=str(user_copy["summary"]),
            next_step=_view_optional_text(user_copy["next_step"]),
            dashboard_url=_view_optional_text(user_copy["dashboard_url"]),
            harness_message=str(user_copy["harness_message"]),
        ),
        matched_rule_id=_view_optional_text(payload["matched_rule_id"]),
        exception_id=_view_optional_text(payload["exception_id"]),
        refresh_required=bool(payload["refresh_required"]),
        record_monitor_evidence=bool(payload["record_monitor_evidence"]),
        evidence_ids=_view_text_tuple(payload["evidence_ids"]),
        external_archive_source_hashes=_view_text_tuple(payload["external_archive_source_hashes"]),
    )


def evaluation_from_native_payload(
    payload: Mapping[str, object],
    *,
    guard_home: Path | None = None,
    timeout_seconds: float = 5.0,
) -> Any:
    """Read a stored or replayed package evaluation back into its typed shape.

    The payload a caller holds is whatever was written at evaluation time, so
    turning it into the view a harness shows means knowing every default, which
    policy actions are recognised, what an unrecognised one costs, and how the
    user copy reads once the local route has no cloud inbox to send anyone to.
    That grammar is the resident's. The caller sends the payload and the four
    identity fields the stored row does not carry, and reads the answer.

    Every outcome other than a well-formed, request-bound ``ok`` reply raises.
    A view composed here instead would be a second reading of a verdict the
    resident already decided.
    """

    data = dict(payload)
    bundle_version = data.get("bundle_version")
    raw_workspace_fingerprint = data.get("workspace_fingerprint")
    home = _resolve_digest_home(guard_home)
    if not ensure_resident_prerequisite(home):
        raise NativePackageEvaluationViewUnavailableError("native_package_evaluation_view_unavailable")
    request: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": _request_id(),
        "payload": data,
        "package_intent_hash": str(data.get("package_intent_hash") or ""),
        "policy_version": str(data.get("policy_version") or ""),
        # Absent identity travels as an explicit null. The reply is bound by the
        # canonical digest of this request, and a key one side omits and the
        # other fills in would unbind every request without a bundle version.
        "bundle_version": bundle_version if isinstance(bundle_version, str) else None,
        "workspace_fingerprint": (raw_workspace_fingerprint if isinstance(raw_workspace_fingerprint, str) else None),
    }
    try:
        request_sha256 = "sha256:" + _canonical_request_sha256(request)
    except (TypeError, ValueError) as error:
        raise NativePackageEvaluationViewUnavailableError("native_package_evaluation_view_unavailable") from error
    response = _resident_request(
        operation="package_evaluation_view",
        request=request,
        guard_home=home,
        timeout_seconds=timeout_seconds,
        required_features=(_PACKAGE_EVALUATION_VIEW_FEATURE,),
        max_request_bytes=_EVALUATION_VIEW_MAX_REQUEST_BYTES,
    )
    if response is None or response.get("code") != "ok":
        # A reply whose code is not ``ok`` did not answer with a view, whatever
        # its status and payload look like.
        raise NativePackageEvaluationViewUnavailableError("native_package_evaluation_view_unavailable")
    if response.get("request_id") != request["request_id"] or response.get("request_sha256") != request_sha256:
        # Another request's view would describe a package this caller never
        # evaluated.
        identity = native_runtime_status().identity
        if identity is not None:
            native_record_resident_failure(identity.sha256, home, reason="native_package_evaluation_view_unbound")
        raise NativePackageEvaluationViewUnavailableError("native_package_evaluation_view_unbound")
    return _evaluation_from_view(response.get("payload"))
