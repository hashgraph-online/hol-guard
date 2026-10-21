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
SOURCE_URI = "git+" + REPOSITORY_URI + "@refs/heads/main"
ISSUER = "https://token.actions.githubusercontent.com"
MAX_PROVENANCE_BYTES = 1024 * 1024
MAX_ROOT_BYTES = 64 * 1024
ROOT_VALIDITY_SECONDS = 7 * 24 * 60 * 60
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
    for line in lines:
        decode(line)  # Reject duplicate keys before the library decodes a bundle.
        bundle = Bundle.from_json(line)
        content_type, payload = verifier.verify_dsse(bundle, binding)
        if content_type != "application/vnd.in-toto+json" or len(payload) > MAX_PROVENANCE_BYTES:
            raise ValueError("release provenance payload type or length invalid")
        statement = decode(payload)
        if (
            not isinstance(statement, dict)
            or statement.get("_type") != "https://in-toto.io/Statement/v1"
            or statement.get("predicateType") != "https://slsa.dev/provenance/v1"
        ):
            raise ValueError("release provenance statement type invalid")
        predicate = statement.get("predicate")
        if not isinstance(predicate, dict):
            raise ValueError("release provenance predicate invalid")
        build = predicate.get("buildDefinition")
        run = predicate.get("runDetails")
        if (
            not isinstance(build, dict)
            or not isinstance(run, dict)
            or not isinstance(build.get("externalParameters"), dict)
            or not isinstance(run.get("builder"), dict)
        ):
            raise ValueError("release provenance build definition invalid")
        workflow = build["externalParameters"].get("workflow")
        expected = {"repository": REPOSITORY_URI, "path": WORKFLOW_PATH, "ref": "refs/heads/main"}
        if (
            build.get("buildType") != "https://actions.github.io/buildtypes/workflow/v1"
            or workflow != expected
            or run["builder"].get("id") != WORKFLOW_ID
        ):
            raise ValueError("release provenance builder or workflow differs")
        dependencies = build.get("resolvedDependencies")
        if not isinstance(dependencies, list):
            raise ValueError("release provenance source dependencies invalid")
        sources = [row for row in dependencies if isinstance(row, dict) and row.get("uri") == SOURCE_URI]
        if len(sources) != 1 or sources[0].get("digest") != {"gitCommit": expected_source_sha}:
            raise ValueError("release provenance source differs")
        subjects = statement.get("subject")
        if not isinstance(subjects, list) or not 0 < len(subjects) <= 64:
            raise ValueError("release provenance subject count invalid")
        candidates = [row for row in subjects if isinstance(row, dict) and row.get("name") == subject_name]
        if len(candidates) > 1:
            raise ValueError("release provenance has duplicate subjects")
        if candidates and candidates[0].get("digest") == {"sha256": digest}:
            matched = True
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


def _index_reference(value, *, located):
    fields = {"sha256", "length", "expanded_length", "kind"} | ({"location"} if located else set())
    if (
        not isinstance(value, dict)
        or set(value) != fields
        or not isinstance(value["sha256"], str)
        or DIGEST.fullmatch(value["sha256"]) is None
        or type(value["length"]) is not int
        or not 0 < value["length"] <= MAX_ROOT_BYTES
        or type(value["expanded_length"]) is not int
        or value["expanded_length"] != value["length"]
        or value["kind"] != "data"
    ):
        raise ValueError("release index reference invalid")
    if located:
        from .containers import location

        location(value["location"], value["sha256"], "object")


def _publication_ready(value, source):
    if not isinstance(value, dict):
        raise ValueError("release compatibility status invalid")
    if value.get("status") == "available":
        if (
            set(value) != {"status", "manifest_sha256", "archive_sha256", "tag"}
            or value["tag"] != "extension-artifacts-" + source
            or any(
                not isinstance(value[key], str) or DIGEST.fullmatch(value[key]) is None
                for key in ("manifest_sha256", "archive_sha256")
            )
        ):
            raise ValueError("release legacy artifact identity invalid")
    elif value.get("status") == "unsupported-oversize":
        codes = {
            "extension-count",
            "program-bytes",
            "catalog-bytes",
            "program-rules",
            "program-nodes",
            "source-envelope",
            "manifest-bytes",
            "archive-files",
            "archive-bytes",
            "directory-entries",
            "directory-bytes",
        }
        if set(value) != {"status", "code"} or not isinstance(value["code"], str) or value["code"] not in codes:
            raise ValueError("release legacy oversize status invalid")
    else:
        raise ValueError("release publication preparation is incomplete")


class ExpiredDistributionError(ValueError):
    """Expired metadata cannot grant authority or seed a new activation."""


def verify_distribution(
    data: bytes, provenance: bytes, *, expected_source_sha: str, now: int, offline: bool = False
) -> VerifiedDistribution:
    if not data or len(data) > MAX_ROOT_BYTES:
        raise ValueError("release root exceeds byte limit")
    root = decode(data)
    fields = {
        "schema",
        "source_sha",
        "engine",
        "directory",
        "policy",
        "claim_provenance",
        "legacy",
        "issued_at",
        "expires_at",
        "authority_epoch",
        "publication_id",
    }
    if (
        not isinstance(root, dict)
        or set(root) != fields
        or root.get("schema") != "guard.extension-distribution.v2"
        or root.get("source_sha") != expected_source_sha
        or not isinstance(root.get("engine"), str)
        or DIGEST.fullmatch(root["engine"]) is None
    ):
        raise ValueError("release root identity or format invalid")
    if type(root["authority_epoch"]) is not int or root["authority_epoch"] <= 0:
        raise ValueError("release authority epoch invalid")
    from .selection import PUBLICATION

    if not isinstance(root["publication_id"], str) or PUBLICATION.fullmatch(root["publication_id"]) is None:
        raise ValueError("release publication identity invalid")
    issued, expires = root["issued_at"], root["expires_at"]
    if (
        type(now) is not int
        or now < 0
        or type(issued) is not int
        or type(expires) is not int
        or issued < 0
        or not 0 < expires - issued <= ROOT_VALIDITY_SECONDS
        or issued > now + 300
    ):
        raise ValueError("release root is expired or its validity interval is invalid")
    if root["claim_provenance"] != "resolved":
        raise ValueError("release publication preparation is incomplete")
    _publication_ready(root["legacy"], expected_source_sha)
    directory, policy_data = root["directory"], root["policy"]
    if (
        not isinstance(directory, dict)
        or not isinstance(policy_data, dict)
        or set(directory) != {"count", "index", "claims"}
        or set(policy_data) != {"root", "transport", "defaults", "revocations"}
    ):
        raise ValueError("release metadata references are incomplete")
    native = policy_data["root"]
    if (
        type(directory["count"]) is not int
        or directory["count"] <= 0
        or not isinstance(native, dict)
        or native.get("schema") != "guard.command-pack-release.v1"
        or native.get("engine") != root["engine"]
        or type(native.get("extensions")) is not int
        or native["extensions"] != directory["count"]
    ):
        raise ValueError("release policy and directory identities differ")
    _index_reference(directory["index"], located=True)
    claims = directory["claims"]
    if (
        not isinstance(claims, dict)
        or set(claims) != {"count", "index"}
        or type(claims["count"]) is not int
        or not 0 <= claims["count"] <= directory["count"]
    ):
        raise ValueError("release claim index count invalid")
    if claims["count"]:
        _index_reference(claims["index"], located=True)
    elif claims["index"] is not None:
        raise ValueError("empty release claim index has a reference")
    _index_reference(policy_data["transport"], located=True)
    _index_reference(native.get("index"), located=False)
    for field in ("defaults", "revocations"):
        value = policy_data[field]
        fields = {"count", "index"} | ({"epoch"} if field == "revocations" else set())
        if not isinstance(value, dict) or set(value) != fields or type(value["count"]) is not int or value["count"] < 0:
            raise ValueError("release security index count invalid")
        if value["count"]:
            _index_reference(value["index"], located=True)
        elif value["index"] is not None:
            raise ValueError("empty release security index has a reference")
        if field == "defaults" and value["count"] > directory["count"]:
            raise ValueError("release defaults exceed complete policy count")
        if field == "revocations" and (type(value["epoch"]) is not int or value["epoch"] < 0):
            raise ValueError("release revocation epoch invalid")
    if now >= expires:
        raise ExpiredDistributionError("release root is expired; refresh before new activation")
    _verify_attested_artifact(data, provenance, "extension-distribution.v2.json", expected_source_sha, offline=offline)
    result = object.__new__(VerifiedDistribution)
    object.__setattr__(result, "data", bytes(data))
    object.__setattr__(result, "source_sha", expected_source_sha)
    object.__setattr__(result, "digest", hashlib.sha256(data).hexdigest())
    object.__setattr__(result, "expires_at", expires)
    return result
