"""Verify reviewed release provenance with Sigstore's production TUF trust root.

This authenticates data for preparation. Native admission and an atomic control
transaction remain mandatory before the data can enforce any extension policy.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass

REPOSITORY = "hashgraph-online/hol-guard"
REPOSITORY_URI = "https://github.com/" + REPOSITORY
REPOSITORY_ID = "1194748811"
OWNER_ID = "160371962"
SOURCE_REF = "refs/heads/main"
WORKFLOW_PATH = ".github/workflows/extension-artifact-regen.yml"
WORKFLOW_ID = REPOSITORY_URI + "/" + WORKFLOW_PATH + "@refs/heads/main"
ISSUER = "https://token.actions.githubusercontent.com"
MAX_PROVENANCE_BYTES = 1024 * 1024
MAX_ROOT_BYTES = 64 * 1024
SHA = re.compile(r"[0-9a-f]{40}")
DIGEST = re.compile(r"[0-9a-f]{64}")


def decode(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate release provenance field")
            result[key] = value
        return result

    def nonfinite(value):
        raise ValueError("non-finite release provenance value")

    try:
        return json.loads(data, object_pairs_hook=unique, parse_constant=nonfinite)
    except (RecursionError, UnicodeError) as error:
        raise ValueError("invalid release provenance encoding or depth") from error


class ExpiredDistributionError(ValueError):
    """Expired metadata cannot grant authority or seed a new activation."""


# The runtime owns what a root and a provenance statement must contain and
# answers with a stable code. These are the messages callers have always seen.
_REASONS = {
    "distribution_root_too_large": "release root exceeds byte limit",
    "distribution_duplicate_field": "duplicate release provenance field",
    "distribution_nonfinite_value": "non-finite release provenance value",
    "distribution_encoding_invalid": "invalid release provenance encoding or depth",
    "distribution_source_invalid": "release root identity or format invalid",
    "distribution_identity_invalid": "release root identity or format invalid",
    "distribution_epoch_invalid": "release authority epoch invalid",
    "distribution_publication_invalid": "release publication identity invalid",
    "distribution_validity_invalid": "release root is expired or its validity interval is invalid",
    "distribution_preparation_incomplete": "release publication preparation is incomplete",
    "distribution_legacy_status_invalid": "release compatibility status invalid",
    "distribution_legacy_artifact_invalid": "release legacy artifact identity invalid",
    "distribution_legacy_oversize_invalid": "release legacy oversize status invalid",
    "distribution_references_incomplete": "release metadata references are incomplete",
    "distribution_identities_differ": "release policy and directory identities differ",
    "distribution_index_reference_invalid": "release index reference invalid",
    "distribution_location_invalid": "delivery asset location invalid",
    "distribution_location_identity_invalid": "delivery asset identity invalid",
    "distribution_location_container_invalid": "delivery container location invalid",
    "distribution_claim_count_invalid": "release claim index count invalid",
    "distribution_claim_index_reference": "empty release claim index has a reference",
    "distribution_security_count_invalid": "release security index count invalid",
    "distribution_security_index_reference": "empty release security index has a reference",
    "distribution_defaults_exceed": "release defaults exceed complete policy count",
    "distribution_revocation_epoch_invalid": "release revocation epoch invalid",
    "distribution_expired": "release root is expired; refresh before new activation",
    "distribution_statement_payload_invalid": "release provenance payload type or length invalid",
    "distribution_statement_type_invalid": "release provenance statement type invalid",
    "distribution_predicate_invalid": "release provenance predicate invalid",
    "distribution_build_definition_invalid": "release provenance build definition invalid",
    "distribution_builder_differs": "release provenance builder or workflow differs",
    "distribution_dependencies_invalid": "release provenance source dependencies invalid",
    "distribution_source_differs": "release provenance source differs",
    "distribution_subject_count_invalid": "release provenance subject count invalid",
    "distribution_duplicate_subjects": "release provenance has duplicate subjects",
}


def _native(operation, **fields):
    """Ask the runtime to judge authenticated content and keep the legacy errors."""
    from . import lifecycle

    try:
        return lifecycle.invoke("distribution", operation=operation, **fields)
    except ValueError as error:
        # A refusal judges the release data, so it drops the transport error:
        # left in the chain, that error reads as a broken installed runtime.
        for code in re.findall(r"distribution_[a-z_]+", str(error)):
            reason = _REASONS.get(code)
            if code == "distribution_expired":
                raise ExpiredDistributionError(reason) from None
            if reason is not None:
                raise ValueError(reason) from None
        raise


def _text(data):
    try:
        return bytes(data).decode("utf-8")
    except UnicodeError as error:
        raise ValueError(_REASONS["distribution_encoding_invalid"]) from error


def _verify_attested_artifact(data, provenance, subject_name, expected_source_sha, *, offline=False):
    """Verify bytes, source, repository identity, main ref and exact workflow."""
    if not data or len(data) > MAX_PROVENANCE_BYTES:
        raise ValueError("release artifact exceeds byte limit")
    return _verify_attested_digest(
        hashlib.sha256(data).hexdigest(), provenance, subject_name, expected_source_sha, offline=offline
    )


def _verify_attested_digest(digest, provenance, subject_name, expected_source_sha, *, offline=False):
    if not isinstance(expected_source_sha, str) or SHA.fullmatch(expected_source_sha) is None:
        raise ValueError("release source must be a full commit SHA")
    if (
        not isinstance(digest, str)
        or DIGEST.fullmatch(digest) is None
        or not provenance
        or len(provenance) > MAX_PROVENANCE_BYTES
    ):
        raise ValueError("release digest or provenance bounds invalid")
    lines = [line for line in provenance.splitlines() if line.strip()]
    if not 0 < len(lines) <= 16:
        raise ValueError("release provenance bundle count invalid")
    # Import only on update/activation control paths. Never refresh trust or
    # import the verifier as part of a command decision.
    from sigstore.models import Bundle
    from sigstore.verify import Verifier, policy

    from . import lifecycle

    verifier = Verifier.production(offline=offline)
    binding = policy.AllOf(
        [
            policy.Identity(identity=WORKFLOW_ID, issuer=ISSUER),
            policy.OIDCSourceRepositoryURI(REPOSITORY_URI),
            policy.OIDCSourceRepositoryDigest(expected_source_sha),
            policy.OIDCSourceRepositoryRef(SOURCE_REF),
            policy.OIDCSourceRepositoryIdentifier(REPOSITORY_ID),
            policy.OIDCSourceRepositoryOwnerIdentifier(OWNER_ID),
            policy.OIDCBuildSignerURI(WORKFLOW_ID),
        ]
    )
    matched = False
    with lifecycle.session():
        for line in lines:
            decode(line)  # Reject duplicate keys before the library decodes a bundle.
            bundle = Bundle.from_json(line)
            content_type, payload = verifier.verify_dsse(bundle, binding)
            # Sigstore has verified the signature. The runtime decides whether the
            # signed statement binds this subject to this workflow and source.
            attested = _native(
                "provenance-statement",
                content_type=content_type,
                payload=_text(payload),
                subject=subject_name,
                digest=digest,
                source=expected_source_sha,
            )
            matched = matched or attested["attested"] is True
    if not matched:
        raise ValueError("release root digest is not attested")


@dataclass(frozen=True, slots=True, init=False)
class VerifiedDistribution:
    """Immutable authenticated bytes. This is not an installed/active snapshot."""

    data: bytes
    source_sha: str
    digest: str
    expires_at: int

    def manifest(self):
        return decode(self.data)


def verify_distribution(
    data: bytes, provenance: bytes, *, expected_source_sha: str, now: int, offline: bool = False
) -> VerifiedDistribution:
    if not data or len(data) > MAX_ROOT_BYTES:
        raise ValueError("release root exceeds byte limit")
    from . import lifecycle

    with lifecycle.session():
        # A malformed or expired root never reaches the signature verifier.
        root = _native("root", data=_text(data), source=expected_source_sha, now=now)
        _verify_attested_artifact(
            data, provenance, "extension-distribution.v2.json", expected_source_sha, offline=offline
        )
    result = object.__new__(VerifiedDistribution)
    object.__setattr__(result, "data", bytes(data))
    object.__setattr__(result, "source_sha", expected_source_sha)
    object.__setattr__(result, "digest", hashlib.sha256(data).hexdigest())
    object.__setattr__(result, "expires_at", root["expires_at"])
    return result
