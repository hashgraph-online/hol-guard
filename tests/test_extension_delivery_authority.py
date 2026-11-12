"""Real public Sigstore provenance and separate bounded root preparation checks."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.catalog_delivery import authority, lifecycle

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
        {"expires_at": 1000 + 7 * 24 * 60 * 60 + 1},
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


def test_expired_root_keeps_its_type_and_a_malformed_root_is_never_called_expired(monkeypatch):
    monkeypatch.setattr(authority, "_verify_attested_artifact", lambda *args, **kwargs: None)
    value = root_value()
    value["expires_at"] = 1499
    with pytest.raises(authority.ExpiredDistributionError, match="refresh before new activation"):
        authority.verify_distribution(json.dumps(value).encode(), b"proof", expected_source_sha=SOURCE, now=1500)
    value["authority_epoch"] = 0
    with pytest.raises(ValueError, match="authority epoch invalid") as raised:
        authority.verify_distribution(json.dumps(value).encode(), b"proof", expected_source_sha=SOURCE, now=1500)
    assert not isinstance(raised.value, authority.ExpiredDistributionError)


def test_accepted_root_reports_the_expiry_it_was_judged_against(monkeypatch):
    monkeypatch.setattr(authority, "_verify_attested_artifact", lambda *args, **kwargs: None)
    result = authority.verify_distribution(
        json.dumps(root_value()).encode(), b"proof", expected_source_sha=SOURCE, now=1500
    )
    assert result.expires_at == 2000 and result.source_sha == SOURCE


def test_root_that_is_not_utf8_is_an_encoding_failure_without_the_verifier():
    with pytest.raises(ValueError, match="invalid release provenance encoding or depth"):
        authority.verify_distribution(b"\xff\xfe{}", b"proof", expected_source_sha=SOURCE, now=1500)


RUNTIME = Path(__file__).parents[1] / "rust/crates/guard-runtime/src/pack_lifecycle"
UNMAPPED = {"distribution_request_invalid", "distribution_operation_invalid"}


def native_reasons():
    sources = [RUNTIME / "distribution.rs", *sorted((RUNTIME / "distribution").glob("*.rs"))]
    return {code for path in sources for code in re.findall(r'"(distribution_[a-z_]+)"', path.read_text())}


def test_every_native_reason_has_a_caller_message_and_none_is_dead():
    codes = native_reasons()
    assert codes - UNMAPPED == set(authority._REASONS)


@pytest.mark.parametrize("code,message", sorted(authority._REASONS.items()))
def test_native_reason_surfaces_as_the_legacy_error(monkeypatch, code, message):
    def refuse(kind, **fields):
        raise ValueError(f"native_pack_lifecycle_unavailable: source compiler returned invalid JSON: {code}")

    monkeypatch.setattr(lifecycle, "invoke", refuse)
    expected = authority.ExpiredDistributionError if code == "distribution_expired" else ValueError
    with pytest.raises(expected) as raised:
        authority._native("root", data="{}", source=SOURCE, now=1)
    assert str(raised.value) == message
    assert type(raised.value) is expected


def test_an_unavailable_runtime_is_not_rewritten_as_a_root_failure(monkeypatch):
    def unavailable(kind, **fields):
        raise ValueError("native_pack_lifecycle_unavailable: packaged native resources are unavailable")

    monkeypatch.setattr(lifecycle, "invoke", unavailable)
    with pytest.raises(ValueError, match="native_pack_lifecycle_unavailable"):
        authority.verify_distribution(json.dumps(root_value()).encode(), b"proof", expected_source_sha=SOURCE, now=1500)


def statement(**changes):
    value = {
        "_type": "https://in-toto.io/Statement/v1",
        "predicateType": "https://slsa.dev/provenance/v1",
        "subject": [{"name": "extension-distribution.v2.json", "digest": {"sha256": SUBJECT_DIGEST}}],
        "predicate": {
            "buildDefinition": {
                "buildType": "https://actions.github.io/buildtypes/workflow/v1",
                "externalParameters": {
                    "workflow": {
                        "repository": authority.REPOSITORY_URI,
                        "path": authority.WORKFLOW_PATH,
                        "ref": authority.SOURCE_REF,
                    }
                },
                "resolvedDependencies": [
                    {
                        "uri": "git+" + authority.REPOSITORY_URI + "@" + authority.SOURCE_REF,
                        "digest": {"gitCommit": SOURCE},
                    }
                ],
            },
            "runDetails": {"builder": {"id": authority.WORKFLOW_ID}},
        },
    }
    value.update(changes)
    return value


def attested(value, *, subject="extension-distribution.v2.json", source=SOURCE):
    return authority._native(
        "provenance-statement",
        content_type="application/vnd.in-toto+json",
        payload=json.dumps(value),
        subject=subject,
        digest=SUBJECT_DIGEST,
        source=source,
    )["attested"]


def test_runtime_statement_policy_names_the_publisher_the_signature_policy_names():
    # The signature policy reads these constants and the runtime holds its own
    # copy of the same identity. A drift between them fails here, not in a release.
    assert attested(statement()) is True
    assert attested(statement(), subject="another-asset.json") is False
    with pytest.raises(ValueError, match="source differs"):
        attested(statement(), source="0" * 40)
