"""Tests for the bridge that asks the native runtime to verify a supply-chain bundle.

Reading and verifying a bundle, and deciding what it says about a package,
belong to the native runtime; those live in the `guard-command` and
`guard-runtime` suites.
"""

from __future__ import annotations

import json

import pytest


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
    monkeypatch.setattr(bridge, "_payload", lambda *args, **kwargs: {"outcome": "verified", "summary": {}})
    sentinel = object()

    bridge.native_verify_supply_chain_bundle_response({}, guard_home=tmp_path, store=sentinel)

    assert seen["store"] is sentinel


def test_verify_returns_the_cache_form_with_the_resident_summary(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard import native_supply_chain_bundle as bridge

    key = {
        "fingerprintSha256": "0" * 64,
        "keyId": "guard-bundle-key",
        "publicKeyPem": "-----BEGIN PUBLIC KEY-----",
        "state": "active",
        "validUntil": None,
    }
    response = {
        "bundle": {"bundleVersion": "v1", "packages": [{}, {}], "advisories": [{}]},
        "payloadHash": "0" * 64,
        "signature": "c2ln",
        "signatureAlgorithm": "rsa-pss-sha256",
        "verificationKeys": [key],
        "cached_at": 1.0,
    }
    summary = {"bundle_version": "v1", "package_count": 2}
    monkeypatch.setattr(bridge, "ensure_resident_prerequisite", lambda home, **kwargs: True)
    monkeypatch.setattr(bridge, "_resident_request", lambda **kwargs: None)
    monkeypatch.setattr(bridge, "_payload", lambda *args, **kwargs: {"outcome": "verified", "summary": summary})

    verified = bridge.native_verify_supply_chain_bundle_response(response, guard_home=tmp_path)

    assert verified.response == {key: value for key, value in response.items() if key != "cached_at"}
    assert [item.to_dict() for item in verified.verification_keys] == [key]
    assert verified.summary == summary

    # A verified reply without the parsed summary is not trusted for one
    # counted from the raw bundle, which the parser would have merged.
    monkeypatch.setattr(bridge, "_payload", lambda *args, **kwargs: {"outcome": "verified"})

    with pytest.raises(bridge.SupplyChainBundleUnavailableError):
        bridge.native_verify_supply_chain_bundle_response(response, guard_home=tmp_path)
