"""Tests for reading a HOL Guard supply-chain bundle onto its transport types.

Verifying a bundle and deciding what it says about a package belong to the
native runtime; those live in the `guard-command` and `guard-runtime` suites.
"""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, generate_private_key

from codex_plugin_scanner.guard.runtime.supply_chain_bundle import (
    SupplyChainBundleMalformedError,
    canonical_supply_chain_bundle_payload,
    load_supply_chain_bundle_response,
)

WORKSPACE_ID = "workspace-alpha"


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _generate_key_pair() -> tuple[bytes, bytes]:
    private_key = generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def _fingerprint(public_key_pem: bytes) -> str:
    return hashlib.sha256(public_key_pem.decode("utf-8").strip().encode("utf-8")).hexdigest()


def _bundle_dict(
    *,
    bundle_version: str = "1747612800000-deadbeef",
    default_action: str = "block",
    exploit_level: str = "active",
    expires_at: datetime | None = None,
    generated_at: datetime | None = None,
    known_exploited: bool = True,
    malware_state: str = "known",
    normalized_severity: str = "critical",
    risk_score: int = 980,
) -> dict[str, object]:
    generated = generated_at or datetime(2026, 5, 19, tzinfo=timezone.utc)
    expires = expires_at or (generated + timedelta(hours=12))
    return {
        "advisories": [
            {
                "advisoryId": "GHSA-vh95-rmgr-6w4m",
                "aliases": ["CVE-2020-7598"],
                "confidence": 990,
                "exploitLevel": exploit_level,
                "knownExploited": known_exploited,
                "malwareState": "none",
                "normalizedSeverity": normalized_severity,
                "recommendedFixVersion": "1.2.9",
                "sourceKey": "ghsa",
                "summary": "Prototype pollution in minimist",
                "title": "Prototype pollution in minimist",
            }
        ],
        "bundleVersion": bundle_version,
        "expiresAt": _iso(expires),
        "feedSnapshotHash": "feed-snapshot-1",
        "generatedAt": _iso(generated),
        "keyId": "guard-bundle-key-2026-05",
        "packages": [
            {
                "confidence": 990,
                "defaultAction": default_action,
                "ecosystem": "npm",
                "exploitLevel": exploit_level,
                "knownExploited": known_exploited,
                "malwareState": malware_state,
                "name": "minimist",
                "namespace": None,
                "normalizedSeverity": normalized_severity,
                "packageAgeState": "watch",
                "purl": "pkg:npm/minimist@1.2.8",
                "reachability": "reachable",
                "recommendedFixVersion": "1.2.9",
                "relatedAdvisoryIds": ["GHSA-vh95-rmgr-6w4m"],
                "riskScore": risk_score,
                "sourceIntegrityState": "high-risk",
                "version": "1.2.8",
            }
        ],
        "policyHash": "policy-hash-1",
        "policyRules": [],
        "scoringVersion": "scf-v1",
        "sourceHashes": [
            {
                "payloadHash": "ghsa-feed-hash",
                "sourceKey": "ghsa",
                "staleStatus": "fresh",
            }
        ],
        "tier": "premium",
        "workspaceId": WORKSPACE_ID,
    }


def _package_record(
    *,
    ecosystem: str = "npm",
    name: str,
    namespace: str | None,
    version: str = "1.2.3",
    default_action: str = "block",
) -> dict[str, object]:
    record = dict(_bundle_dict()["packages"][0])  # type: ignore[index]
    qualified_name = f"{namespace}/{name}" if namespace is not None else name
    record.update(
        {
            "defaultAction": default_action,
            "ecosystem": ecosystem,
            "name": name,
            "namespace": namespace,
            "purl": f"pkg:{ecosystem}/{qualified_name}@{version}",
            "version": version,
        }
    )
    return record


def _sign_bundle_response(
    bundle: dict[str, object],
    *,
    private_key_pem: bytes,
    previous_keys: list[dict[str, object]] | None = None,
    signing_key_state: str = "active",
    signing_key_valid_until: str | None = None,
) -> dict[str, object]:
    loaded_key = serialization.load_pem_private_key(private_key_pem, password=None)
    assert isinstance(loaded_key, RSAPrivateKey)
    canonical_payload = canonical_supply_chain_bundle_payload(bundle)
    payload_hash = hashlib.sha256(canonical_payload).hexdigest()
    signature = loaded_key.sign(
        canonical_payload,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    public_key_pem = loaded_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    verification_keys = [
        {
            "fingerprintSha256": _fingerprint(public_key_pem),
            "keyId": str(bundle["keyId"]),
            "publicKeyPem": public_key_pem.decode("utf-8").strip(),
            "state": signing_key_state,
            "validUntil": signing_key_valid_until,
        }
    ]
    if previous_keys:
        verification_keys.extend(previous_keys)
    return {
        "bundle": bundle,
        "payloadHash": payload_hash,
        "signature": base64.b64encode(signature).decode("utf-8"),
        "signatureAlgorithm": "rsa-pss-sha256",
        "verificationKeys": verification_keys,
    }


def test_supply_chain_bundle_deduplicates_identical_canonical_package_records() -> None:
    private_key, _public_key = _generate_key_pair()
    bundle = _bundle_dict()
    package = _package_record(name="pkg", namespace="@scope")
    bundle["packages"] = [package, dict(package)]

    response = load_supply_chain_bundle_response(json.dumps(_sign_bundle_response(bundle, private_key_pem=private_key)))

    assert response.bundle.packages == (response.bundle.packages[0],)
    assert response.bundle.packages[0].namespace == "@scope"


def test_supply_chain_bundle_normalizes_legacy_qualified_packagist_name() -> None:
    private_key, _public_key = _generate_key_pair()
    bundle = _bundle_dict()
    bundle["packages"] = [
        _package_record(
            ecosystem="packagist",
            name="Laravel/Framework",
            namespace=None,
            version="11.1.0",
        )
    ]

    response = load_supply_chain_bundle_response(json.dumps(_sign_bundle_response(bundle, private_key_pem=private_key)))

    package = response.bundle.packages[0]
    assert package.ecosystem == "packagist"
    assert package.namespace == "laravel"
    assert package.name == "framework"


@pytest.mark.parametrize(
    ("first", "second"),
    [
        (
            _package_record(name="pkg", namespace="@scope", default_action="block"),
            _package_record(name="pkg", namespace="@scope", default_action="warn"),
        ),
        (
            _package_record(name="Pkg", namespace="@Scope", default_action="block"),
            _package_record(name="pkg", namespace="@scope", default_action="warn"),
        ),
    ],
)
def test_supply_chain_bundle_rejects_conflicting_canonical_package_records(
    first: dict[str, object],
    second: dict[str, object],
) -> None:
    private_key, _public_key = _generate_key_pair()
    bundle = _bundle_dict()
    bundle["packages"] = [first, second]

    with pytest.raises(SupplyChainBundleMalformedError, match=r"Conflicting package records.*npm:@scope/pkg@1\.2\.3"):
        load_supply_chain_bundle_response(json.dumps(_sign_bundle_response(bundle, private_key_pem=private_key)))


@pytest.mark.parametrize(
    "package",
    [
        _package_record(name="pkg", namespace="scope"),
        _package_record(name="pkg", namespace="@scope@"),
        _package_record(name="@scope/pkg", namespace=None),
        _package_record(ecosystem="pypi", name="org/pkg", namespace=None),
        _package_record(ecosystem="packagist", name="pkg", namespace=None),
    ],
)
def test_supply_chain_bundle_rejects_malformed_ecosystem_identity_fields(
    package: dict[str, object],
) -> None:
    private_key, _public_key = _generate_key_pair()
    bundle = _bundle_dict()
    bundle["packages"] = [package]

    with pytest.raises(SupplyChainBundleMalformedError, match="Invalid package identity"):
        load_supply_chain_bundle_response(json.dumps(_sign_bundle_response(bundle, private_key_pem=private_key)))


def test_supply_chain_bundle_reads_a_portal_signed_payload_with_an_emergency_denylist() -> None:
    private_key, _public_key = _generate_key_pair()
    bundle = _bundle_dict()
    bundle["emergencyDenylist"] = [
        {
            "ecosystem": "npm",
            "name": "minimist",
            "namespace": None,
            "reason": "known_malware",
            "recommendedFixVersion": "1.2.9",
        }
    ]
    response = load_supply_chain_bundle_response(json.dumps(_sign_bundle_response(bundle, private_key_pem=private_key)))

    assert len(response.bundle.emergency_denylist) == 1
    assert response.bundle.emergency_denylist[0].reason == "known_malware"


def test_supply_chain_bundle_reads_a_portal_signed_payload_with_sparse_policy_rules() -> None:
    private_key, _public_key = _generate_key_pair()
    bundle = _bundle_dict()
    bundle["policyRules"] = [{"action": "block", "ruleId": "rule-1"}]
    response = load_supply_chain_bundle_response(json.dumps(_sign_bundle_response(bundle, private_key_pem=private_key)))

    assert len(response.bundle.policy_rules) == 1
    assert response.bundle.policy_rules[0].rule_id == "rule-1"


def test_verify_refuses_a_request_larger_than_the_resident_accepts(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    # An oversized request is dropped by the transport with no explanation,
    # which reads as an unreachable verifier. The bridge measures it first so
    # the failure names the size instead.
    from codex_plugin_scanner.guard import native_supply_chain_bundle as bridge

    monkeypatch.setattr(bridge, "ensure_resident_prerequisite", lambda home, **kwargs: True)

    def _unreachable(**kwargs: object) -> None:
        raise AssertionError("an oversized request must not reach the transport")

    monkeypatch.setattr(bridge, "_resident_request", _unreachable)
    oversized = {"filler": "a" * (bridge._MAX_REQUEST_BYTES + 1)}

    with pytest.raises(bridge.SupplyChainBundleTooLargeError) as raised:
        bridge.native_verify_supply_chain_bundle_response(oversized, guard_home=tmp_path)

    assert "over the" in str(raised.value)
    assert str(bridge._MAX_REQUEST_BYTES) in str(raised.value)


def test_verify_measures_the_bytes_the_transport_actually_sends(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    # The transport wraps the request in an envelope and encodes it with the
    # default separators, so a compact encoding of the request on its own is
    # smaller than what goes over the wire. A request between those two sizes
    # would pass the pre-check and then be dropped by the transport, which is
    # the unexplained unreachable verifier this check exists to rule out.
    from codex_plugin_scanner.guard import native_supply_chain_bundle as bridge

    monkeypatch.setattr(bridge, "ensure_resident_prerequisite", lambda home, **kwargs: True)

    def _unreachable(**kwargs: object) -> None:
        raise AssertionError("an oversized request must not reach the transport")

    monkeypatch.setattr(bridge, "_resident_request", _unreachable)
    response = {"records": [{"name": f"record-{index}", "digest": "0" * 16} for index in range(64)]}
    wire = {
        "schema": bridge._REQUEST_SCHEMA,
        "request_id": "supply-chain-bundle-verify-" + "0" * 32,
        "response": dict(response),
        "trusted_keys": None,
        "cached_bundle_version": None,
        "now": None,
    }
    compact_bytes = len(json.dumps(wire, separators=(",", ":")).encode("utf-8"))
    sent_bytes = len(
        json.dumps(
            {
                "operation": "supply_chain_bundle_verify",
                "request": wire,
                "deadline_budget_ms": max(1, int(bridge._TIMEOUT_SECONDS * 1000)),
            }
        ).encode("utf-8")
    )
    assert compact_bytes < sent_bytes
    monkeypatch.setattr(bridge, "_MAX_REQUEST_BYTES", (compact_bytes + sent_bytes) // 2)

    with pytest.raises(bridge.SupplyChainBundleTooLargeError):
        bridge.native_verify_supply_chain_bundle_response(response, guard_home=tmp_path)


def test_verify_provisions_the_resident_against_the_caller_s_own_store(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The verifier key is derived from the policy-integrity master, so
    # provisioning has to read the store the caller already opened rather than
    # whatever secret store a freshly opened default store resolves.
    from codex_plugin_scanner.guard import native_supply_chain_bundle as bridge

    seen: dict[str, object] = {}

    def _record(home: object, **kwargs: object) -> bool:
        seen.update(kwargs)
        return True

    monkeypatch.setattr(bridge, "ensure_resident_prerequisite", _record)
    monkeypatch.setattr(bridge, "_resident_request", lambda **kwargs: None)
    monkeypatch.setattr(bridge, "_payload", lambda *args, **kwargs: {"outcome": "verified"})
    sentinel = object()

    bridge.native_verify_supply_chain_bundle_response({}, guard_home=tmp_path, store=sentinel)

    assert seen["store"] is sentinel
