"""Network protection bundle verification, sync, and the saved form the runtime reads."""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, generate_private_key

from codex_plugin_scanner.guard.cli.oauth_client import generate_dpop_key_pair
from codex_plugin_scanner.guard.runtime import network_protection_bundle as npb
from codex_plugin_scanner.guard.runtime import runner as guard_runner
from codex_plugin_scanner.guard.runtime.network_protection_bundle import (
    NETWORK_PROTECTION_SYNC_STATE_KEY,
    NetworkProtectionBundleError,
    network_protection_status,
    verify_network_protection_response,
)
from codex_plugin_scanner.guard.store import GuardStore

WORKSPACE_ID = "workspace-alpha"
NOW = datetime(2026, 10, 21, 12, 0, tzinfo=timezone.utc)


def _iso(value: datetime) -> str:
    return value.isoformat(timespec="milliseconds").replace("+00:00", "Z")


@pytest.fixture(scope="module")
def signing_key() -> RSAPrivateKey:
    return generate_private_key(public_exponent=65537, key_size=2048)


def _public_pem(key: RSAPrivateKey) -> str:
    return (
        key.public_key()
        .public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode("utf-8")
    )


def _verification_key(key: RSAPrivateKey, *, key_id: str = "key-1", state: str = "active") -> dict[str, object]:
    pem = _public_pem(key)
    return {
        "keyId": key_id,
        "publicKeyPem": pem,
        "fingerprintSha256": hashlib.sha256(pem.replace("\r\n", "\n").strip().encode("utf-8")).hexdigest(),
        "state": state,
        "validUntil": None,
    }


def _response(
    key: RSAPrivateKey,
    *,
    generated_at: datetime = NOW,
    version_ms: int | None = None,
    workspace_id: str = WORKSPACE_ID,
    **overrides: object,
) -> dict[str, object]:
    ms = version_ms if version_ms is not None else int(generated_at.timestamp() * 1000)
    bundle: dict[str, object] = {
        "contractVersion": "guard-network-protection-bundle.v1",
        "workspaceId": workspace_id,
        "bundleVersion": f"network-{ms}-0123456789abcdef",
        "generatedAt": _iso(generated_at),
        "expiresAt": _iso(generated_at + timedelta(hours=6)),
        "keyId": "key-1",
        "workspaceRules": [
            {"action": "block", "matchKind": "domain", "pattern": "blocked.example"},
            {"action": "allow", "matchKind": "url_prefix", "pattern": "docs.example/guide/"},
        ],
        "threatUrls": {"malware_distribution": ["0" * 32]},
        "threatHosts": {"phishing": ["login-verify.pages.dev"]},
        "sources": [{"source": "urlhaus", "fetchedAt": _iso(generated_at)}],
        **overrides,
    }
    payload = json.dumps(bundle, sort_keys=True, separators=(",", ":")).encode("utf-8")
    signature = key.sign(
        payload,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    return {
        "bundle": bundle,
        "payloadHash": hashlib.sha256(payload).hexdigest(),
        "signature": base64.b64encode(signature).decode("ascii"),
        "signatureAlgorithm": "rsa-pss-sha256",
        "verificationKeys": [_verification_key(key)],
    }


def _verify(response: dict[str, object], key: RSAPrivateKey, **kwargs: object) -> dict[str, object]:
    trusted = npb.load_supply_chain_verification_keys([_verification_key(key)])
    options: dict[str, object] = {"workspace_id": WORKSPACE_ID, "trusted_keys": trusted, "now": NOW.timestamp()}
    options.update(kwargs)
    return verify_network_protection_response(response, **options)


def test_verified_bundle_is_saved_in_the_form_the_runtime_reads(signing_key: RSAPrivateKey) -> None:
    response = _response(signing_key)
    saved = _verify(response, signing_key)
    assert saved["bundle"] == response["bundle"]
    assert saved["expiresAtEpoch"] == int((NOW + timedelta(hours=6)).timestamp())
    status = network_protection_status(saved, now=NOW.timestamp())
    assert status["block_rules"] == 1
    assert status["allow_rules"] == 1
    assert status["known_bad_urls"] == 1
    assert status["known_bad_hosts"] == 1
    assert status["indicators_applied"] is True


def test_tampered_bundle_is_rejected(signing_key: RSAPrivateKey) -> None:
    response = _response(signing_key)
    response["bundle"]["workspaceRules"] = []
    with pytest.raises(NetworkProtectionBundleError, match="payloadHash"):
        _verify(response, signing_key)
    forged = _response(signing_key)
    forged["bundle"]["workspaceRules"] = []
    canonical = json.dumps(forged["bundle"], sort_keys=True, separators=(",", ":")).encode("utf-8")
    forged["payloadHash"] = hashlib.sha256(canonical).hexdigest()
    with pytest.raises(NetworkProtectionBundleError, match="signature"):
        _verify(forged, signing_key)


def test_bundle_for_another_workspace_is_rejected(signing_key: RSAPrivateKey) -> None:
    with pytest.raises(NetworkProtectionBundleError, match="different workspace"):
        _verify(_response(signing_key, workspace_id="workspace-other"), signing_key)


def test_older_bundle_cannot_replace_a_newer_saved_one(signing_key: RSAPrivateKey) -> None:
    response = _response(signing_key, version_ms=1_000)
    with pytest.raises(NetworkProtectionBundleError, match="older than saved"):
        _verify(response, signing_key, cached_bundle_version="network-2000-0123456789abcdef")


def test_expired_bundle_is_rejected(signing_key: RSAPrivateKey) -> None:
    response = _response(signing_key, generated_at=NOW - timedelta(hours=7))
    with pytest.raises(NetworkProtectionBundleError, match="expired"):
        _verify(response, signing_key)


def test_signing_key_must_be_anchored(signing_key: RSAPrivateKey) -> None:
    other = generate_private_key(public_exponent=65537, key_size=2048)
    response = _response(signing_key)
    with pytest.raises(NetworkProtectionBundleError, match="not trusted"):
        verify_network_protection_response(
            response,
            workspace_id=WORKSPACE_ID,
            trusted_keys=npb.load_supply_chain_verification_keys([_verification_key(other)]),
            now=NOW.timestamp(),
        )
    # Before any keyring is saved, only the pinned production key is trusted.
    with pytest.raises(NetworkProtectionBundleError, match="not trusted"):
        verify_network_protection_response(response, workspace_id=WORKSPACE_ID, now=NOW.timestamp())


def test_revoked_trusted_key_no_longer_anchors(signing_key: RSAPrivateKey) -> None:
    revoked = npb.load_supply_chain_verification_keys([_verification_key(signing_key, state="revoked")])
    with pytest.raises(NetworkProtectionBundleError, match="not trusted"):
        verify_network_protection_response(
            _response(signing_key), workspace_id=WORKSPACE_ID, trusted_keys=revoked, now=NOW.timestamp()
        )


def test_invalid_workspace_rule_is_rejected(signing_key: RSAPrivateKey) -> None:
    response = _response(signing_key, workspaceRules=[{"action": "ignore", "matchKind": "domain", "pattern": "x"}])
    with pytest.raises(NetworkProtectionBundleError, match="workspace rule"):
        _verify(response, signing_key)


def _connected_store(tmp_path, monkeypatch: pytest.MonkeyPatch) -> GuardStore:
    store = GuardStore(tmp_path / "guard-home")
    dpop = generate_dpop_key_pair()
    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token="demo-token",
        dpop_private_key_pem=dpop.private_key_pem,
        dpop_public_jwk=dpop.public_jwk,
        dpop_public_jwk_thumbprint=dpop.public_jwk_thumbprint,
        grant_id="grant-1",
        machine_id="machine-1",
        workspace_id=WORKSPACE_ID,
        now="2026-10-21T00:00:00Z",
    )
    monkeypatch.setattr(
        guard_runner,
        "_test_sync_auth_context_override",
        {
            "sync_url": "https://hol.org/api/guard/receipts/sync",
            "access_token": "demo-token",
            "dpop_key_material": None,
        },
        raising=False,
    )
    return store


@pytest.mark.usefixtures("native_approval_reuse_runtime")
def test_sync_fetches_the_derived_route_and_saves_the_verified_bundle(
    tmp_path, monkeypatch: pytest.MonkeyPatch, signing_key: RSAPrivateKey
) -> None:
    store = _connected_store(tmp_path, monkeypatch)
    store.set_sync_payload(
        "supply_chain_bundle_keyring",
        {"workspace_id": WORKSPACE_ID, "keys": [_verification_key(signing_key)]},
        "2026-10-21T00:00:00Z",
    )
    response = _response(signing_key, generated_at=datetime.now(timezone.utc) - timedelta(minutes=1))
    requested: list[str] = []

    def fake_fetch(request: object) -> dict[str, object]:
        requested.append(getattr(request, "full_url", ""))
        return response

    monkeypatch.setattr(guard_runner, "_fetch_supply_chain_bundle_payload", fake_fetch)
    summary = guard_runner.sync_network_protection_bundle(store)
    assert requested == ["https://hol.org/api/guard/network/bundle?workspaceId=workspace-alpha"]
    assert summary["status"] == "synced"
    saved = store.get_sync_payload(NETWORK_PROTECTION_SYNC_STATE_KEY)
    assert saved["bundle"] == response["bundle"]
    assert isinstance(saved["expiresAtEpoch"], int)


@pytest.mark.usefixtures("native_approval_reuse_runtime")
def test_failed_sync_keeps_the_saved_bundle(
    tmp_path, monkeypatch: pytest.MonkeyPatch, signing_key: RSAPrivateKey
) -> None:
    store = _connected_store(tmp_path, monkeypatch)
    kept = {"bundle": {"kept": True, "workspaceId": WORKSPACE_ID}}
    store.set_sync_payload(NETWORK_PROTECTION_SYNC_STATE_KEY, kept, "2026-10-21T00:00:00Z")
    forged = _response(signing_key, generated_at=datetime.now(timezone.utc))
    forged["signature"] = base64.b64encode(b"x" * 256).decode("ascii")
    monkeypatch.setattr(guard_runner, "_fetch_supply_chain_bundle_payload", lambda request: forged)
    with pytest.raises(RuntimeError, match="network protection bundle sync failed"):
        guard_runner.sync_network_protection_bundle(store)
    failed = guard_runner.sync_network_protection_bundle_best_effort(store)
    assert failed is not None
    assert failed["status"] == "failed"
    assert "network protection bundle sync failed" in str(failed["error"])
    assert store.get_sync_payload(NETWORK_PROTECTION_SYNC_STATE_KEY) == kept


@pytest.mark.usefixtures("native_approval_reuse_runtime")
def test_sync_drops_another_workspaces_bundle(
    tmp_path, monkeypatch: pytest.MonkeyPatch, signing_key: RSAPrivateKey
) -> None:
    store = _connected_store(tmp_path, monkeypatch)
    other = {"bundle": {"workspaceId": "other-workspace", "bundleVersion": "network-9999999999999-0123456789abcdef"}}
    store.set_sync_payload(NETWORK_PROTECTION_SYNC_STATE_KEY, other, "2026-10-21T00:00:00Z")

    def unreachable(request: object) -> object:
        raise RuntimeError("bundle endpoint unreachable")

    monkeypatch.setattr(guard_runner, "_fetch_supply_chain_bundle_payload", unreachable)
    assert guard_runner.sync_network_protection_bundle_best_effort(store) == {
        "status": "failed",
        "error": "bundle endpoint unreachable",
    }
    assert store.get_sync_payload(NETWORK_PROTECTION_SYNC_STATE_KEY) is None

    store.set_sync_payload(
        "supply_chain_bundle_keyring",
        {"workspace_id": WORKSPACE_ID, "keys": [_verification_key(signing_key)]},
        "2026-10-21T00:00:00Z",
    )
    response = _response(signing_key, generated_at=datetime.now(timezone.utc) - timedelta(minutes=1))
    monkeypatch.setattr(guard_runner, "_fetch_supply_chain_bundle_payload", lambda request: response)
    assert guard_runner.sync_network_protection_bundle(store)["status"] == "synced"


def test_cloud_reconnect_clears_the_network_bundle() -> None:
    from codex_plugin_scanner.guard.store_base import _GUARD_CLOUD_RESET_STATE_KEYS

    assert NETWORK_PROTECTION_SYNC_STATE_KEY in _GUARD_CLOUD_RESET_STATE_KEYS


@pytest.mark.usefixtures("native_approval_reuse_runtime")
def test_network_check_reports_the_saved_bundle_decision(
    tmp_path, monkeypatch: pytest.MonkeyPatch, signing_key: RSAPrivateKey
) -> None:
    import argparse

    from codex_plugin_scanner.guard.cli import commands_dispatch_local
    from codex_plugin_scanner.guard.cli.commands_parser import add_guard_parser

    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home)
    store.set_sync_payload(
        NETWORK_PROTECTION_SYNC_STATE_KEY, _verify(_response(signing_key), signing_key), "2026-10-21T00:00:00Z"
    )
    emitted: list[dict[str, object]] = []
    monkeypatch.setattr(
        commands_dispatch_local,
        "_emit",
        lambda _title, payload, _as_json: emitted.append(payload),
        raising=False,
    )
    parser = argparse.ArgumentParser()
    add_guard_parser(parser.add_subparsers(dest="command"))

    def check(url: str) -> tuple[int, dict[str, object]]:
        args = parser.parse_args(["guard", "network", "check", url, "--json"])
        code = commands_dispatch_local._run_guard_network_command(args, guard_home=guard_home, store=store)
        return code, emitted[-1]

    code, blocked = check("https://api.blocked.example/install.sh")
    assert code == 0
    assert blocked["configured"] is True
    assert blocked["decision"] == "block"
    assert blocked["reason_code"] == "network_workspace_block"
    assert check("https://login-verify.pages.dev/")[1]["decision"] == "review"
    assert check("https://docs.example/guide/intro")[1]["decision"] == "allow"
    code, invalid = check("not a url")
    assert code == 2
    assert invalid["valid_url"] is False
