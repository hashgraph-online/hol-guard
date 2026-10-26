"""Resident bridge for the ``hook_artifact_facts`` op.

The native configured-policy action reads a small set of per-artifact facts:
whether the prompt asks to bypass Guard, the command-action floor, whether an
explicit catalog permission earned a verified allow, which risk classes the
artifact carries, how strong its evidence is, whether it installs a boot item.
Each of those decides part of the verdict the resident then applies, so the
resident derives them from the artifact itself. This module ships the artifact
type and its metadata unchanged and hands the answer back; nothing is computed
here, so an unavailable resident cannot soften a fact into a quieter action.

``configured_override`` is the one input the caller still supplies: it is the
artifact, publisher or harness setting the config resolves, not a reading of
the artifact, and it rides through the op so the facts leave here complete.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import cast
from uuid import uuid4

from .native_context import _resolve_digest_home, ensure_resident_prerequisite
from .native_execution import _resident_request
from .native_hook_artifact_compose import HOOK_ARTIFACT_COMPOSE_POLICY_TAIL_FEATURE
from .native_store_policy import _payload

# The facts answer ``skip_native_floor`` only once the policy-stack tail is
# served, so the facts are asked for under that feature: a runtime without it
# omits the fact the hook now reads. It ships with ``hook-artifact-facts-v1``.
HOOK_ARTIFACT_FACTS_FEATURE = HOOK_ARTIFACT_COMPOSE_POLICY_TAIL_FEATURE
# A request that asks for ``content_sha256`` is asked under the feature that
# answers it, so a runtime that would return the facts without the digest is
# unavailable to the caller that needs one rather than silently quiet. A
# caller that asks for no digest keeps the feature above.
HOOK_ARTIFACT_FACTS_CONTENT_HASH_FEATURE = "hook-artifact-facts-content-hash-v1"
_REQUEST_SCHEMA = "guard-hook-artifact-facts-request.v1"
_RESULT_SCHEMA = "guard-hook-artifact-facts-result.v1"
_TIMEOUT_SECONDS = 10.0
# Mirrors ``HOOK_ARTIFACT_FACTS_MAX_ARTIFACTS``: the resident refuses a request
# carrying more artifacts than this.
_MAX_ARTIFACTS = 64
_MAX_REQUEST_BYTES = 4 * 1024 * 1024


class HookArtifactFactsUnavailableError(RuntimeError):
    """The resident could not derive the artifact facts."""

    code = "native_hook_artifact_facts_unavailable"


def native_hook_artifact_facts(
    artifacts: Sequence[Mapping[str, object]],
    *,
    guard_home: Path | None = None,
) -> list[dict[str, object]]:
    """Return one resident ``PolicyArtifactFactsV1`` per artifact, in order.

    An evaluation reads facts for more than one artifact, so they are asked for
    together: a hook that asked once per artifact would put the resident on the
    critical path of every tool call more than once.

    Raises ``HookArtifactFactsUnavailableError`` when the resident cannot
    answer, which the hook pipeline's fail-closed handling turns into an
    availability response rather than a verdict.
    """

    if not artifacts:
        return []
    try:
        home = Path(_resolve_digest_home(guard_home))
    except (OSError, RuntimeError, ValueError):
        raise HookArtifactFactsUnavailableError from None
    if not ensure_resident_prerequisite(home):
        raise HookArtifactFactsUnavailableError
    answers: list[dict[str, object]] = []
    for start in range(0, len(artifacts), _MAX_ARTIFACTS):
        answers.extend(_facts_for_batch(artifacts[start : start + _MAX_ARTIFACTS], home))
    return answers


def _wire_artifact(artifact: Mapping[str, object]) -> dict[str, object]:
    """One artifact as the resident reads it.

    A caller that wants the digest its saved approvals are keyed by passes
    ``hash_metadata``: the metadata the artifact carried when that identity was
    fixed, which a hook stamps its runtime posture onto before asking for these
    facts. Only the difference between the two goes on the wire, as
    ``metadata_stamp``; sending the pre-stamp metadata whole would carry a
    second full copy of a field with no size bound of its own, and a command
    long enough to reach the metadata would push an otherwise acceptable
    request past the envelope limit and leave the hook with no facts at all.
    The identity fields the digest covers are sent unredacted, because that
    hash redacts the arguments and the url itself.

    Every field is named on every entry, including the identity ones a caller
    that wants no digest leaves empty. The resident binds its reply to the
    digest of the request as it parsed it, so an entry that omitted a field the
    contract serializes would be answered under a digest this side never
    computed and the reply would read as unbound.
    """

    entry: dict[str, object] = {
        "artifact_type": artifact["artifact_type"],
        "metadata": dict(cast("Mapping[str, object]", artifact.get("metadata") or {})),
        "configured_override": artifact.get("configured_override"),
        "args": list(cast("Sequence[str]", artifact.get("args") or ())),
    }
    for field in ("artifact_id", "name", "harness", "source_scope", "config_path"):
        entry[field] = str(artifact.get(field) or "")
    for field in ("command", "url", "transport", "publisher"):
        value = artifact.get(field)
        entry[field] = value if isinstance(value, str) else None
    hash_metadata = artifact.get("hash_metadata")
    if hash_metadata is not None:
        entry["metadata_stamp"] = _metadata_stamp(
            cast("Mapping[str, object]", entry["metadata"]),
            cast("Mapping[str, object]", hash_metadata),
        )
    return entry


def _metadata_stamp(metadata: Mapping[str, object], identity: Mapping[str, object]) -> dict[str, object]:
    """What the caller stamped onto ``identity`` to reach ``metadata``.

    The resident drops ``added`` from the metadata it was sent and puts
    ``replaced`` back to recover the metadata the digest covers, so the two
    differ on the wire by the keys the stamp touched rather than by a whole
    copy. A key the stamp dropped is restored by ``replaced`` as well, since
    putting a key back is the same operation whether or not it is still there.
    """

    return {
        "added": sorted(key for key in metadata if key not in identity),
        "replaced": {key: value for key, value in identity.items() if key not in metadata or metadata[key] != value},
    }


def _facts_for_batch(
    artifacts: Sequence[Mapping[str, object]],
    home: Path,
) -> list[dict[str, object]]:
    """Ask the resident about one batch the contract is willing to accept."""

    entries = [_wire_artifact(artifact) for artifact in artifacts]
    wire: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": f"hook-artifact-facts-{uuid4().hex}",
        "artifacts": entries,
    }
    required_feature = (
        HOOK_ARTIFACT_FACTS_CONTENT_HASH_FEATURE
        if any("metadata_stamp" in entry for entry in entries)
        else HOOK_ARTIFACT_FACTS_FEATURE
    )
    try:
        response = _resident_request(
            operation="hook_artifact_facts",
            request=wire,
            guard_home=home,
            timeout_seconds=_TIMEOUT_SECONDS,
            required_feature=required_feature,
            response_schema=_RESULT_SCHEMA,
            max_request_bytes=_MAX_REQUEST_BYTES,
            record_success=False,
        )
    except (TypeError, ValueError, OSError, RuntimeError):
        raise HookArtifactFactsUnavailableError from None
    payload = _payload(response, wire, home)
    if not isinstance(payload, dict):
        raise HookArtifactFactsUnavailableError
    facts = payload.get("facts")
    if not isinstance(facts, list) or len(facts) != len(artifacts):
        raise HookArtifactFactsUnavailableError
    if not all(isinstance(item, dict) for item in facts):
        raise HookArtifactFactsUnavailableError
    return cast("list[dict[str, object]]", facts)
