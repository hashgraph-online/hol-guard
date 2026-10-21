"""Real public Sigstore provenance and separate bounded root preparation checks."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.catalog_delivery import authority

SOURCE = "ffa0eaa6ac9a1ca8daaa18cc587937dbd501cfd5"
SUBJECT_DIGEST = "cdd0fb6a3cf407fc3947a5423747b7e5409479db5b02b1c3d441d9d9a4b501ac"
VECTOR = Path(__file__).parent / "fixtures/extension-distribution-provenance.sigstore.json"


@pytest.fixture
def trust_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    return VECTOR.read_bytes()


def test_real_published_manifest_signature_verifies_offline(trust_environment):
    authority._verify_attested_digest(
        SUBJECT_DIGEST, trust_environment, "extension-artifacts.v1.json", SOURCE, offline=True
    )
    with pytest.raises(ValueError, match="digest is not attested"):
        authority._verify_attested_digest(
            "0" * 64, trust_environment, "extension-artifacts.v1.json", SOURCE, offline=True
        )


@pytest.mark.parametrize(
    "field,value,message",
    [
        ("REPOSITORY_URI", "https://github.com/example/other", "OIDCSourceRepositoryURI"),
        ("REPOSITORY_ID", "0", "OIDCSourceRepositoryIdentifier"),
        ("OWNER_ID", "0", "OIDCSourceRepositoryOwnerIdentifier"),
        ("SOURCE_REF", "refs/heads/untrusted", "OIDCSourceRepositoryRef"),
        ("WORKFLOW_ID", "https://github.com/example/other/.github/workflows/build.yml@refs/heads/main", "SAN"),
    ],
)
def test_valid_signature_cannot_substitute_publisher_identity(trust_environment, monkeypatch, field, value, message):
    from sigstore.errors import VerificationError

    monkeypatch.setattr(authority, field, value)
    with pytest.raises(VerificationError, match=message):
        authority._verify_attested_digest(
            SUBJECT_DIGEST, trust_environment, "extension-artifacts.v1.json", SOURCE, offline=True
        )


def test_wrong_commit_and_modified_signed_payload_are_rejected(trust_environment):
    import base64

    from sigstore.errors import VerificationError

    with pytest.raises(VerificationError, match="OIDCSourceRepositoryDigest"):
        authority._verify_attested_digest(
            SUBJECT_DIGEST, trust_environment, "extension-artifacts.v1.json", "0" * 40, offline=True
        )
    bundle = json.loads(trust_environment)
    payload = base64.b64decode(bundle["dsseEnvelope"]["payload"])
    bundle["dsseEnvelope"]["payload"] = base64.b64encode(payload + b" ").decode()
    with pytest.raises(VerificationError):
        authority._verify_attested_digest(
            SUBJECT_DIGEST, json.dumps(bundle).encode(), "extension-artifacts.v1.json", SOURCE, offline=True
        )


def root_value():
    reference = {"sha256": "2" * 64, "length": 100, "expanded_length": 100, "kind": "data"}
    located = {
        **reference,
        "location": {"tag": "extension-data-" + SOURCE + "-0.0-000000", "asset": "object-" + "2" * 64 + ".json"},
    }
    return {
        "schema": "guard.extension-distribution.v2",
        "source_sha": SOURCE,
        "engine": "1" * 64,
        "authority_epoch": 1,
        "publication_id": "12.1",
        "issued_at": 1000,
        "expires_at": 2000,
        "directory": {"count": 1, "index": located, "claims": {"count": 0, "index": None}},
        "policy": {
            "root": {
                "schema": "guard.command-pack-release.v1",
                "engine": "1" * 64,
                "extensions": 1,
                "index": reference,
            },
            "transport": located,
            "defaults": {"count": 0, "index": None},
            "revocations": {"epoch": 0, "count": 0, "index": None},
        },
        "claim_provenance": "resolved",
        "legacy": {"status": "unsupported-oversize", "code": "program-bytes"},
    }


def test_authenticated_bytes_are_immutable_and_do_not_imply_activation(monkeypatch):
    verified = []
    monkeypatch.setattr(authority, "_verify_attested_artifact", lambda *args, **kwargs: verified.append(args))
    data = json.dumps(root_value()).encode()
    result = authority.verify_distribution(data, b"unit-structure-proof", expected_source_sha=SOURCE, now=1500)
    assert verified[0][0] == data
    assert result.digest == hashlib.sha256(data).hexdigest()
    copy = result.manifest()
    copy["policy"]["defaults"]["count"] = 100
    assert result.manifest()["policy"]["defaults"]["count"] == 0
    assert not hasattr(result, "active")
    with pytest.raises(TypeError):
        authority.VerifiedDistribution(data)


@pytest.mark.parametrize(
    "change",
    [
        {"expires_at": 1499},
        {"issued_at": 1801},
        {"expires_at": 1000 + authority.ROOT_VALIDITY_SECONDS + 1},
        {"issued_at": True},
        {"authority_epoch": 0},
        {"source_sha": "0" * 40},
        {"engine": "invalid"},
        {"claim_provenance": "not-resolved"},
        {"legacy": {"status": "not-generated"}},
        {"legacy": {"status": "unsupported-oversize", "code": "unreviewed-error"}},
        {"directory": {"count": 2, "index": None}},
    ],
)
def test_invalid_expired_or_unprepared_root_never_reaches_crypto(monkeypatch, change):
    def unexpected(*args, **kwargs):
        raise AssertionError("invalid metadata reached cryptographic verification")

    monkeypatch.setattr(authority, "_verify_attested_artifact", unexpected)
    value = root_value()
    value.update(change)
    with pytest.raises(ValueError):
        authority.verify_distribution(json.dumps(value).encode(), b"proof", expected_source_sha=SOURCE, now=1500)


def test_duplicate_keys_and_oversized_metadata_are_rejected_without_verifier():
    with pytest.raises(ValueError, match="duplicate"):
        authority.verify_distribution(b'{"schema":1,"schema":2}', b"proof", expected_source_sha=SOURCE, now=1500)
    with pytest.raises(ValueError, match="byte limit"):
        authority.verify_distribution(b"x" * (65536 + 1), b"proof", expected_source_sha=SOURCE, now=1500)
