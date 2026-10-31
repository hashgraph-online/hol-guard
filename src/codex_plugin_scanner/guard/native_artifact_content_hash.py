"""Resident bridge for the ``artifact_content_hash`` op.

``GuardStore`` keys every saved decision by the artifact's content hash, so
the hash is an approval key, not a convenience digest: a caller that spelled
it differently would miss every approval the user already granted. The
resident spells it, from the artifact's own fields; this module only ships
those fields and transports the answer back.

The fields travel raw. The hash reads the artifact's own redaction of its
arguments, url and metadata before digesting, so a copy redacted here would
hash differently than the one the stored approval covers.
"""

from __future__ import annotations

import json
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import cast
from uuid import uuid4

from .artifact_native_fields import artifact_native_fields as artifact_content_hash_fields
from .models import GuardArtifact
from .native_context import _resolve_digest_home, ensure_resident_prerequisite
from .native_execution import _resident_request
from .native_store_policy import _payload

ARTIFACT_CONTENT_HASH_FEATURE = "artifact-content-hash-v1"
_REQUEST_SCHEMA = "guard-artifact-content-hash-request.v1"
_RESULT_SCHEMA = "guard-artifact-content-hash-result.v1"
_TIMEOUT_SECONDS = 10.0
# Mirrors ``ARTIFACT_CONTENT_HASH_MAX_ARTIFACTS``: the resident refuses a
# request carrying more artifacts than this.
_MAX_ARTIFACTS = 256
_MAX_REQUEST_BYTES = 4 * 1024 * 1024
# A batch stops short of the request cap so the schema, request id and the
# framing around the artifacts still fit beside them.
_MAX_BATCH_BYTES = _MAX_REQUEST_BYTES - 64 * 1024
# The ``", "`` that joins one artifact to the next in the request's array.
_ARTIFACT_ENVELOPE_BYTES = 2
_HASH_LENGTH = 64
_HASH_ALPHABET = frozenset("0123456789abcdef")


class ArtifactContentHashUnavailableError(RuntimeError):
    """The resident could not spell the artifact content hash."""

    code = "native_artifact_content_hash_unavailable"


def native_artifact_content_hashes(
    artifacts: Sequence[GuardArtifact],
    *,
    guard_home: Path | None = None,
) -> list[str]:
    """Return one content hash per artifact, in the caller's order.

    A scan and a prompt both hash every artifact a harness defines, so they
    are asked for together: one round trip per artifact would put the resident
    on the critical path once per artifact rather than once per batch.

    Raises ``ArtifactContentHashUnavailableError`` when the resident cannot
    answer, so a caller that needs an approval key fails closed rather than
    keying a decision by a hash nothing authoritative spelled.
    """

    if not artifacts:
        return []
    try:
        home = Path(_resolve_digest_home(guard_home))
    except (OSError, RuntimeError, ValueError):
        raise ArtifactContentHashUnavailableError from None
    if not ensure_resident_prerequisite(home):
        raise ArtifactContentHashUnavailableError
    hashes: list[str] = []
    for batch in _batches(artifacts):
        hashes.extend(_hashes_for_batch(batch, home))
    return hashes


def _batches(artifacts: Sequence[GuardArtifact]) -> Iterator[Sequence[GuardArtifact]]:
    """Split the artifacts into batches the resident will accept.

    The contract caps both how many artifacts one request may carry and how
    large it may be, and a harness whose artifacts carry long arguments reaches
    the byte cap first. A batch split only by count would then be refused whole
    and lose every hash in it, so the size is measured as the batch is filled.
    An artifact that is larger than a whole batch still goes on its own: the
    resident refuses it by itself rather than taking the rest down with it.

    The measurement spells the artifact the way the transport does, with the
    separators ``json.dumps`` uses by default and the two bytes that join it to
    the artifact before it. A compact spelling would undercount every comma and
    colon in the request, so a harness carrying many short arguments could fill
    a batch the transport then refuses whole.
    """

    start = 0
    bytes_so_far = 0
    for index, artifact in enumerate(artifacts):
        encoded = _ARTIFACT_ENVELOPE_BYTES + len(
            json.dumps(artifact_content_hash_fields(artifact), default=str).encode()
        )
        if index > start and (index - start >= _MAX_ARTIFACTS or bytes_so_far + encoded > _MAX_BATCH_BYTES):
            yield artifacts[start:index]
            start = index
            bytes_so_far = 0
        bytes_so_far += encoded
    if start < len(artifacts):
        yield artifacts[start:]


def native_artifact_content_hash(
    artifact: GuardArtifact,
    *,
    guard_home: Path | None = None,
) -> str:
    """Return the content hash of one artifact."""

    return native_artifact_content_hashes([artifact], guard_home=guard_home)[0]


def _hashes_for_batch(artifacts: Sequence[GuardArtifact], home: Path) -> list[str]:
    """Ask the resident about one batch the contract is willing to accept."""

    wire: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": f"artifact-content-hash-{uuid4().hex}",
        "artifacts": [artifact_content_hash_fields(artifact) for artifact in artifacts],
    }
    try:
        response = _resident_request(
            operation="artifact_content_hash",
            request=wire,
            guard_home=home,
            timeout_seconds=_TIMEOUT_SECONDS,
            required_feature=ARTIFACT_CONTENT_HASH_FEATURE,
            response_schema=_RESULT_SCHEMA,
            max_request_bytes=_MAX_REQUEST_BYTES,
            record_success=False,
        )
    except (TypeError, ValueError, OSError, RuntimeError):
        raise ArtifactContentHashUnavailableError from None
    payload = _payload(response, wire, home)
    if not isinstance(payload, dict):
        raise ArtifactContentHashUnavailableError
    hashes = payload.get("content_hashes")
    if not isinstance(hashes, list) or len(hashes) != len(artifacts):
        raise ArtifactContentHashUnavailableError
    if not all(_is_content_hash(item) for item in hashes):
        raise ArtifactContentHashUnavailableError
    return cast("list[str]", hashes)


def _is_content_hash(value: object) -> bool:
    """Whether a payload entry is a hash this bridge will hand to a caller."""

    return isinstance(value, str) and len(value) == _HASH_LENGTH and set(value) <= _HASH_ALPHABET
