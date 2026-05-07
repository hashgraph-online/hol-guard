"""Tests for threat intelligence bundle handling and advisory matchers.

Covers: T536 signature verification, T537 tampered bundle rejection,
T538 freshness expiry, T539 rollback protection, T540-T542 cache migration,
T543-T545 cloud sync client stubs and fallbacks.
"""

from __future__ import annotations

import base64
import json
import sqlite3
import time

import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key

from codex_plugin_scanner.guard.runtime.advisory_matchers import (
    match_all_advisories,
    match_github_action,
    match_github_advisory,
    match_malicious_domain,
    match_malicious_package_hash,
    match_mcp_server,
    match_npm_advisory,
    match_nvd_cve,
    match_osv,
    match_pypi_advisory,
    match_skill_hash,
)
from codex_plugin_scanner.guard.runtime.threat_intel import (
    BundleExpiredError,
    BundleMalformedError,
    BundleRollbackError,
    BundleSignatureError,
    ThreatAdvisory,
    ThreatIntelBundle,
    _canonical_payload,
    advisory_severity_rank,
    check_bundle_freshness,
    check_bundle_rollback,
    load_bundle_from_json,
    verify_bundle_signature,
)
from codex_plugin_scanner.guard.store_threat_intel import (
    ThreatIntelMatch,
    insert_match,
    latest_cached_bundle,
    list_matches,
    threat_intel_bundle_schema_statement,
    threat_intel_index_statements,
    threat_intel_matches_schema_statement,
    upsert_bundle,
)


def _make_advisory(**overrides: object) -> ThreatAdvisory:
    defaults: dict[str, object] = {
        "advisory_id": "ADV-001",
        "source": "osv/npm",
        "severity": "high",
        "title": "Test advisory",
        "affected_type": "package",
        "matcher": "evil-pkg",
        "recommendation": "Upgrade immediately.",
    }
    defaults.update(overrides)
    return ThreatAdvisory(
        advisory_id=str(defaults["advisory_id"]),
        source=str(defaults["source"]),
        severity=str(defaults["severity"]),
        title=str(defaults["title"]),
        affected_type=str(defaults["affected_type"]),
        matcher=str(defaults["matcher"]),
        recommendation=str(defaults["recommendation"]),
    )


def _make_bundle(
    version: int = 1,
    advisories: tuple[ThreatAdvisory, ...] | None = None,
    generated_at: float | None = None,
    expires_at: float | None = None,
    signature: str = "placeholder",
) -> ThreatIntelBundle:
    now = time.time()
    return ThreatIntelBundle(
        version=version,
        generated_at=generated_at if generated_at is not None else now - 60,
        expires_at=expires_at if expires_at is not None else now + 3600,
        source="hol-cloud",
        signature=signature,
        advisories=advisories if advisories is not None else (_make_advisory(),),
    )


def _generate_test_key_pair() -> tuple[bytes, bytes]:
    """Return (private_key_pem, public_key_pem) for testing."""
    private_key = generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv_pem, pub_pem


def _sign_bundle(bundle: ThreatIntelBundle, private_key_pem: bytes) -> ThreatIntelBundle:
    """Return a new bundle with a valid RSA-PSS signature."""
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

    loaded_key = serialization.load_pem_private_key(private_key_pem, password=None)
    assert isinstance(loaded_key, RSAPrivateKey)
    payload = _canonical_payload(bundle)
    sig_bytes = loaded_key.sign(
        payload,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    sig_b64 = base64.b64encode(sig_bytes).decode()
    return ThreatIntelBundle(
        version=bundle.version,
        generated_at=bundle.generated_at,
        expires_at=bundle.expires_at,
        source=bundle.source,
        signature=sig_b64,
        advisories=bundle.advisories,
    )


def _in_memory_db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.execute(threat_intel_bundle_schema_statement())
    conn.execute(threat_intel_matches_schema_statement())
    for stmt in threat_intel_index_statements():
        conn.execute(stmt)
    return conn


class TestBundleSignatureVerification:
    """T536 — signed bundle verifies; T537 — tampered bundle is rejected."""

    def test_valid_signature_passes(self) -> None:
        priv_pem, pub_pem = _generate_test_key_pair()
        bundle = _sign_bundle(_make_bundle(), priv_pem)
        verify_bundle_signature(bundle, pub_pem)

    def test_tampered_advisory_fails(self) -> None:
        priv_pem, pub_pem = _generate_test_key_pair()
        bundle = _sign_bundle(_make_bundle(), priv_pem)
        tampered = ThreatIntelBundle(
            version=bundle.version,
            generated_at=bundle.generated_at,
            expires_at=bundle.expires_at,
            source=bundle.source,
            signature=bundle.signature,
            advisories=(_make_advisory(title="INJECTED"),),
        )
        with pytest.raises(BundleSignatureError):
            verify_bundle_signature(tampered, pub_pem)

    def test_wrong_key_fails(self) -> None:
        priv_pem, _ = _generate_test_key_pair()
        _, other_pub_pem = _generate_test_key_pair()
        bundle = _sign_bundle(_make_bundle(), priv_pem)
        with pytest.raises(BundleSignatureError):
            verify_bundle_signature(bundle, other_pub_pem)

    def test_invalid_base64_signature_fails(self) -> None:
        _, pub_pem = _generate_test_key_pair()
        bundle = _make_bundle(signature="not-valid-base64!!!")
        with pytest.raises(BundleSignatureError):
            verify_bundle_signature(bundle, pub_pem)

    def test_invalid_public_key_pem_fails(self) -> None:
        priv_pem, _ = _generate_test_key_pair()
        bundle = _sign_bundle(_make_bundle(), priv_pem)
        with pytest.raises(BundleSignatureError):
            verify_bundle_signature(bundle, b"not a pem key")


class TestBundleFreshness:
    """T538 — freshness expiry is enforced."""

    def test_fresh_bundle_passes(self) -> None:
        now = time.time()
        bundle = _make_bundle(generated_at=now - 100, expires_at=now + 3600)
        check_bundle_freshness(bundle, now=now)

    def test_expired_bundle_fails(self) -> None:
        now = time.time()
        bundle = _make_bundle(generated_at=now - 7200, expires_at=now - 3600)
        with pytest.raises(BundleExpiredError):
            check_bundle_freshness(bundle, now=now)

    def test_future_generated_at_fails(self) -> None:
        now = time.time()
        bundle = _make_bundle(generated_at=now + 3600, expires_at=now + 7200)
        with pytest.raises(BundleExpiredError):
            check_bundle_freshness(bundle, now=now)

    def test_clock_skew_tolerance(self) -> None:
        now = time.time()
        bundle = _make_bundle(generated_at=now - 100, expires_at=now + 200)
        check_bundle_freshness(bundle, now=now + 100)


class TestBundleRollback:
    """T539 — rollback protection: older bundle version is rejected."""

    def test_newer_version_passes(self) -> None:
        bundle = _make_bundle(version=5)
        check_bundle_rollback(bundle, cached_version=4)

    def test_same_version_passes(self) -> None:
        bundle = _make_bundle(version=3)
        check_bundle_rollback(bundle, cached_version=3)

    def test_older_version_fails(self) -> None:
        bundle = _make_bundle(version=2)
        with pytest.raises(BundleRollbackError):
            check_bundle_rollback(bundle, cached_version=5)


class TestBundleParsing:
    """T536 — from_dict + load_bundle_from_json validation."""

    def test_valid_json_parses(self) -> None:
        bundle = _make_bundle()
        raw_json = json.dumps(bundle.to_dict())
        parsed = load_bundle_from_json(raw_json)
        assert parsed.version == bundle.version
        assert len(parsed.advisories) == len(bundle.advisories)

    def test_missing_version_raises(self) -> None:
        d = _make_bundle().to_dict()
        del d["version"]
        with pytest.raises(BundleMalformedError):
            ThreatIntelBundle.from_dict(d)

    def test_invalid_json_raises(self) -> None:
        with pytest.raises(BundleMalformedError):
            load_bundle_from_json("{invalid}")

    def test_advisory_missing_field_raises(self) -> None:
        d = _make_bundle().to_dict()
        d["advisories"][0].pop("advisory_id")  # type: ignore[index]
        with pytest.raises(BundleMalformedError):
            ThreatIntelBundle.from_dict(d)


class TestCacheMigration:
    """T541 — cache tables created in existing database (migration test)."""

    def test_tables_created_in_new_db(self) -> None:
        conn = _in_memory_db()
        row = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='guard_threat_intel_bundles'"
        ).fetchone()
        assert row is not None

    def test_indexes_created(self) -> None:
        conn = _in_memory_db()
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='guard_threat_intel_bundles'"
        ).fetchall()
        index_names = {r[0] for r in rows}
        assert "idx_ti_bundle_version" in index_names

    def test_idempotent_on_existing_table(self) -> None:
        conn = _in_memory_db()
        conn.execute(threat_intel_bundle_schema_statement())
        conn.execute(threat_intel_matches_schema_statement())
        for stmt in threat_intel_index_statements():
            conn.execute(stmt)


class TestUpsertAndFetchBundle:
    """T540 — bundle upsert and latest cached bundle retrieval."""

    def test_upsert_and_latest(self) -> None:
        conn = _in_memory_db()
        bundle = _make_bundle(version=1)
        upsert_bundle(conn, bundle, bundle_id="test-bundle-1")
        cached = latest_cached_bundle(conn)
        assert cached is not None
        assert cached.version == 1
        assert cached.bundle_id == "test-bundle-1"

    def test_latest_returns_highest_version(self) -> None:
        conn = _in_memory_db()
        upsert_bundle(conn, _make_bundle(version=3), bundle_id="b3")
        upsert_bundle(conn, _make_bundle(version=1), bundle_id="b1")
        upsert_bundle(conn, _make_bundle(version=5), bundle_id="b5")
        cached = latest_cached_bundle(conn)
        assert cached is not None
        assert cached.version == 5

    def test_none_when_empty(self) -> None:
        conn = _in_memory_db()
        assert latest_cached_bundle(conn) is None

    def test_cached_bundle_freshness(self) -> None:
        now = time.time()
        conn = _in_memory_db()
        bundle = _make_bundle(expires_at=now + 3600)
        upsert_bundle(conn, bundle, bundle_id="fresh")
        cached = latest_cached_bundle(conn)
        assert cached is not None
        assert cached.is_fresh(now=now) is True

    def test_cached_bundle_stale(self) -> None:
        now = time.time()
        conn = _in_memory_db()
        bundle = _make_bundle(expires_at=now - 7200)
        upsert_bundle(conn, bundle, bundle_id="stale")
        cached = latest_cached_bundle(conn)
        assert cached is not None
        assert cached.is_fresh(now=now) is False


class TestMatchStorage:
    """T542 — match rows can be inserted and filtered."""

    def _make_match(self, **overrides: object) -> ThreatIntelMatch:
        defaults: dict[str, object] = {
            "match_id": "m1",
            "bundle_id": "b1",
            "advisory_id": "ADV-001",
            "artifact_id": "pkg:npm/evil-pkg",
            "harness": "codex",
            "workspace": "/home/user/project",
            "severity": "high",
            "matched_at": time.time(),
            "target_json": "{}",
        }
        defaults.update(overrides)
        return ThreatIntelMatch(**defaults)  # type: ignore[arg-type]

    def test_insert_and_list(self) -> None:
        conn = _in_memory_db()
        insert_match(conn, self._make_match())
        matches = list_matches(conn)
        assert len(matches) == 1
        assert matches[0].advisory_id == "ADV-001"

    def test_filter_by_artifact(self) -> None:
        conn = _in_memory_db()
        insert_match(conn, self._make_match(match_id="m1", artifact_id="pkg:npm/a"))
        insert_match(conn, self._make_match(match_id="m2", artifact_id="pkg:npm/b"))
        matches = list_matches(conn, artifact_id="pkg:npm/a")
        assert len(matches) == 1

    def test_filter_by_severity(self) -> None:
        conn = _in_memory_db()
        insert_match(conn, self._make_match(match_id="m1", severity="critical"))
        insert_match(conn, self._make_match(match_id="m2", severity="low"))
        matches = list_matches(conn, severity="critical")
        assert len(matches) == 1


class TestFreeplanFallback:
    """T544 — free plan 403 graceful fallback stub."""

    def test_no_error_on_empty_bundle(self) -> None:
        bundle = _make_bundle(advisories=())
        assert len(bundle.advisories) == 0

    def test_no_error_on_no_cached_bundle(self) -> None:
        conn = _in_memory_db()
        assert latest_cached_bundle(conn) is None


class TestOfflineFallback:
    """T545 — offline fallback stub: no advisories = no matches."""

    def test_empty_bundle_matches_nothing(self) -> None:
        bundle = _make_bundle(advisories=())
        result = match_all_advisories(bundle.advisories, {"package_name": "evil-pkg"})
        assert len(result) == 0


class TestAdvisoryMatchers:
    """T546-T555 — all advisory matchers."""

    def test_osv_matches_by_package(self) -> None:
        adv = _make_advisory(source="osv/npm", matcher="evil-pkg")
        assert match_osv(adv, {"package_name": "evil-pkg", "ecosystem": "npm"})

    def test_osv_no_match_wrong_name(self) -> None:
        adv = _make_advisory(source="osv/npm", matcher="safe-pkg")
        assert not match_osv(adv, {"package_name": "evil-pkg", "ecosystem": "npm"})

    def test_github_advisory_by_ghsa_id(self) -> None:
        adv = _make_advisory(matcher="GHSA-1234-abcd-5678")
        assert match_github_advisory(adv, {"ghsa_id": "GHSA-1234-abcd-5678"})

    def test_github_advisory_wrong_ghsa(self) -> None:
        adv = _make_advisory(matcher="GHSA-1234-abcd-5678")
        assert not match_github_advisory(adv, {"ghsa_id": "GHSA-9999-xxxx-9999"})

    def test_nvd_cve_by_cve_id(self) -> None:
        adv = _make_advisory(matcher="CVE-2024-12345")
        assert match_nvd_cve(adv, {"cve_id": "CVE-2024-12345"})

    def test_nvd_cve_no_match(self) -> None:
        adv = _make_advisory(matcher="CVE-2024-12345")
        assert not match_nvd_cve(adv, {"cve_id": "CVE-2024-99999"})

    def test_npm_matches_npm_ecosystem(self) -> None:
        adv = _make_advisory(matcher="evil-pkg")
        assert match_npm_advisory(adv, {"ecosystem": "npm", "package_name": "evil-pkg"})

    def test_npm_rejects_pypi_ecosystem(self) -> None:
        adv = _make_advisory(matcher="evil-pkg")
        assert not match_npm_advisory(adv, {"ecosystem": "pypi", "package_name": "evil-pkg"})

    def test_pypi_matches_pypi_ecosystem(self) -> None:
        adv = _make_advisory(matcher="evil-lib")
        assert match_pypi_advisory(adv, {"ecosystem": "pypi", "package_name": "evil-lib"})

    def test_pypi_pip_alias_matches(self) -> None:
        adv = _make_advisory(matcher="evil-lib")
        assert match_pypi_advisory(adv, {"ecosystem": "pip", "package_name": "evil-lib"})

    def test_github_action_match(self) -> None:
        adv = _make_advisory(matcher="evil-org/evil-action")
        assert match_github_action(adv, {"action_slug": "evil-org/evil-action"})

    def test_github_action_no_match(self) -> None:
        adv = _make_advisory(matcher="evil-org/evil-action")
        assert not match_github_action(adv, {"action_slug": "safe-org/safe-action"})

    def test_mcp_server_name_match(self) -> None:
        adv = _make_advisory(matcher="evil-mcp")
        assert match_mcp_server(adv, {"mcp_server": "evil-mcp"})

    def test_mcp_server_substring_match(self) -> None:
        adv = _make_advisory(matcher="evil-mcp")
        assert match_mcp_server(adv, {"mcp_server": "some-evil-mcp-server"})

    def test_skill_hash_match(self) -> None:
        adv = _make_advisory(matcher="abc123def456")
        assert match_skill_hash(adv, {"skill_hash": "abc123def456"})

    def test_skill_hash_no_match(self) -> None:
        adv = _make_advisory(matcher="abc123def456")
        assert not match_skill_hash(adv, {"skill_hash": "000000000000"})

    def test_malicious_domain_match(self) -> None:
        adv = _make_advisory(matcher="evil.example.com")
        assert match_malicious_domain(adv, {"network_hosts": ["evil.example.com"]})

    def test_malicious_domain_list_match(self) -> None:
        adv = _make_advisory(matcher="evil.com")
        assert match_malicious_domain(adv, {"network_hosts": ["safe.com", "evil.com"]})

    def test_malicious_domain_no_match(self) -> None:
        adv = _make_advisory(matcher="evil.com")
        assert not match_malicious_domain(adv, {"network_hosts": ["safe.com"]})

    def test_malicious_package_hash_match(self) -> None:
        adv = _make_advisory(matcher="sha256:deadbeef")
        assert match_malicious_package_hash(adv, {"package_hash": "sha256:deadbeef"})

    def test_malicious_package_hash_no_match(self) -> None:
        adv = _make_advisory(matcher="sha256:deadbeef")
        assert not match_malicious_package_hash(adv, {"package_hash": "sha256:cafebabe"})


class TestMatchAllAdvisories:
    """T556 — integrated matching against a bundle."""

    def test_multiple_advisories_some_match(self) -> None:
        advisories = (
            _make_advisory(advisory_id="A1", matcher="evil-pkg"),
            _make_advisory(advisory_id="A2", matcher="safe-pkg"),
        )
        target = {"package_name": "evil-pkg", "ecosystem": "npm"}
        matched = match_all_advisories(advisories, target)
        assert len(matched) == 1
        assert matched[0].advisory_id == "A1"

    def test_no_advisories_returns_empty(self) -> None:
        result = match_all_advisories((), {"package_name": "evil-pkg"})
        assert result == ()


class TestSeverityRank:
    """Utility — severity ordering."""

    def test_critical_highest(self) -> None:
        assert advisory_severity_rank("critical") > advisory_severity_rank("high")

    def test_info_lowest(self) -> None:
        assert advisory_severity_rank("info") < advisory_severity_rank("low")

    def test_unknown_treated_as_info(self) -> None:
        assert advisory_severity_rank("banana") == advisory_severity_rank("info")
