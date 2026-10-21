"""Typed client for the native data-flow exfiltration owner; no Python evaluator."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from . import native_execution
from .models import GuardArtifact
from .native_context import _canonical_request_sha256, _resolve_digest_home, ensure_resident_prerequisite
from .runtime.actions import GuardActionEnvelope
from .runtime.signals import RiskSignalV2

# v2 added the request's ``naming`` and the reply's ``artifact``. A v1 resident
# refuses the first and omits the second, so it must not be picked for this.
_FEATURE = "data-flow-analyze-v2"
_REQUEST_SCHEMA = "guard-data-flow-analyze-request.v1"
_RESULT_SCHEMA = "guard-data-flow-analyze-result.v1"
_RESULT_KEYS = frozenset({"schema", "request_id", "request_sha256", "status", "code", "signals", "artifact"})
_MAX_SIGNALS = 64
# The resident accepts commands up to 256 KiB of UTF-8. ``json.dumps`` escapes
# every control character to six bytes, so the wire envelope can be six times
# larger than the command; leave that room plus the envelope itself.
_MAX_COMMAND_BYTES = 256 * 1024
_MAX_WIRE_BYTES = 6 * _MAX_COMMAND_BYTES + 4096

# Every field of the artifact wire. The ones a request artifact never carries —
# command, args, url, transport, publisher and the runtime-private metadata —
# are sent as their empty forms and must still be present, so a reply that
# quietly grew or lost a field is a malformed reply rather than an artifact
# missing a field nobody checked.
_ARTIFACT_FIELDS = frozenset(
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


class NativeDataFlowError(RuntimeError):
    """The native owner could not supply a complete, request-bound data-flow result."""


@dataclass(frozen=True, slots=True)
class DataFlowArtifactNaming:
    """How the artifact built for an action's signals is named.

    Only a caller that means to review the action supplies this: the harness it
    speaks for, the policy file the review cites, whether the scope is the
    project or the global install, and the tool the action came in on, which
    the artifact is titled after. Callers that want the signals alone — the
    conformance recorder, the smoke tests — leave it out and get no artifact.
    """

    harness: str
    config_path: str
    source_scope: str
    tool_name: str | None = None

    def to_wire(self) -> dict[str, object]:
        return {
            "harness": self.harness,
            "config_path": self.config_path,
            "source_scope": self.source_scope,
            "tool_name": self.tool_name,
        }


def _invalid() -> NativeDataFlowError:
    return NativeDataFlowError("native_data_flow_invalid_result")


def _text(value: object) -> str:
    if not isinstance(value, str):
        raise _invalid()
    return value


def _artifact(value: object) -> GuardArtifact:
    """The Guard artifact the resident built for the signals, or a raise.

    An artifact that will not decode is not an absent artifact: the resident
    raised the signals that earn a review, and reading a malformed reply as
    "nothing to review" would drop it.
    """

    if not isinstance(value, dict) or set(value) != _ARTIFACT_FIELDS:
        raise _invalid()
    wire = cast("dict[str, Any]", value)
    if any(wire[name] is not None for name in ("command", "url", "transport", "publisher")):
        raise _invalid()
    if wire["args"] != [] or wire["runtime_private_metadata"] != {}:
        raise _invalid()
    metadata = wire["metadata"]
    if not isinstance(metadata, dict) or not all(isinstance(key, str) for key in metadata):
        raise _invalid()
    return GuardArtifact(
        artifact_id=_text(wire["artifact_id"]),
        name=_text(wire["name"]),
        harness=_text(wire["harness"]),
        artifact_type=_text(wire["artifact_type"]),
        source_scope=_text(wire["source_scope"]),
        config_path=_text(wire["config_path"]),
        metadata=dict(metadata),
    )


def detect_data_flow_exfiltration(
    action: GuardActionEnvelope,
    *,
    workspace: Path | None,
    guard_home: Path | None = None,
    naming: DataFlowArtifactNaming | None = None,
    timeout_seconds: float = 10.0,
) -> tuple[tuple[RiskSignalV2, ...], GuardArtifact | None]:
    """Return the resident's ordered data-flow signals for ``action``, with the
    artifact they earn when ``naming`` says how to name one.

    The signals and the artifact come back from one question so the two cannot
    drift: the id the artifact carries is the key a later approval is matched
    under, and deriving it a second time here would let this side disagree with
    the side that raised the signals. The artifact is ``None`` when the caller
    passed no naming, or when the command raised no signals and so earns no
    review.

    Every outcome other than a well-formed, request-bound ``ok`` reply raises
    ``NativeDataFlowError``; callers must not substitute a Python evaluation.
    Only shell commands carry shell data flow, so every other action returns no
    signals without contacting the resident, exactly as the native rules do.
    """

    if action.action_type != "shell_command" or action.command is None:
        return (), None
    request: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": native_execution._request_id("data_flow_analyze"),
        "action_type": action.action_type,
        "command": action.command,
        "workspace": str(workspace) if workspace is not None else None,
        "naming": naming.to_wire() if naming is not None else None,
    }
    try:
        home = _resolve_digest_home(guard_home)
        if not ensure_resident_prerequisite(home):
            raise NativeDataFlowError("native_data_flow_unavailable")
        request_sha256 = _canonical_request_sha256(request)
        decoded = native_execution._resident_request(
            operation="data_flow_analyze",
            request=request,
            guard_home=home,
            timeout_seconds=timeout_seconds,
            required_feature=_FEATURE,
            response_schema=_RESULT_SCHEMA,
            max_request_bytes=_MAX_WIRE_BYTES,
        )
    except (OSError, TypeError, ValueError) as error:
        raise NativeDataFlowError("native_data_flow_unavailable") from error
    if decoded is None:
        raise NativeDataFlowError("native_data_flow_unavailable")
    if set(decoded) != _RESULT_KEYS or decoded.get("code") != "ok":
        raise _invalid()
    if decoded.get("request_id") != request["request_id"] or decoded.get("request_sha256") != request_sha256:
        raise NativeDataFlowError("native_data_flow_request_mismatch")
    signals = decoded.get("signals")
    if not isinstance(signals, list) or len(signals) > _MAX_SIGNALS:
        raise _invalid()
    if not all(isinstance(item, dict) for item in signals):
        raise _invalid()
    try:
        found = tuple(RiskSignalV2.from_dict(item) for item in signals)
    except (TypeError, ValueError) as error:
        raise _invalid() from error
    artifact = decoded.get("artifact")
    if artifact is None:
        # A named request whose command raised signals must come back with the
        # artifact for them; anything else is a reply that lost the review.
        if naming is not None and found:
            raise _invalid()
        return found, None
    if naming is None or not found:
        raise _invalid()
    return found, _artifact(artifact)
