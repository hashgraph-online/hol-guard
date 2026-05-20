"""Tests for HOL Guard supply-chain bundle sync and local cache persistence."""

from __future__ import annotations

import base64
import hashlib
import json
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import ClassVar

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, generate_private_key

from codex_plugin_scanner.guard.runtime.runner import sync_supply_chain_bundle
from codex_plugin_scanner.guard.runtime.supply_chain_bundle import canonical_supply_chain_bundle_payload
from codex_plugin_scanner.guard.store import GuardStore

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


def _bundle_response(private_key_pem: bytes, public_key_pem: bytes) -> dict[str, object]:
    generated_at = datetime.now(timezone.utc) - timedelta(minutes=5)
    expires_at = generated_at + timedelta(hours=12)
    bundle = {
        "advisories": [
            {
                "advisoryId": "GHSA-vh95-rmgr-6w4m",
                "aliases": ["CVE-2020-7598"],
                "confidence": 990,
                "exploitLevel": "active",
                "knownExploited": True,
                "malwareState": "none",
                "normalizedSeverity": "critical",
                "recommendedFixVersion": "1.2.9",
                "sourceKey": "ghsa",
                "summary": "Prototype pollution in minimist",
                "title": "Prototype pollution in minimist",
            }
        ],
        "bundleVersion": "1747612800000-deadbeef",
        "expiresAt": _iso(expires_at),
        "feedSnapshotHash": "feed-snapshot-1",
        "generatedAt": _iso(generated_at),
        "keyId": "guard-bundle-key-2026-05",
        "packages": [
            {
                "confidence": 990,
                "defaultAction": "block",
                "ecosystem": "npm",
                "exploitLevel": "active",
                "knownExploited": True,
                "malwareState": "known",
                "name": "minimist",
                "namespace": None,
                "normalizedSeverity": "critical",
                "packageAgeState": "watch",
                "purl": "pkg:npm/minimist@1.2.8",
                "reachability": "reachable",
                "recommendedFixVersion": "1.2.9",
                "relatedAdvisoryIds": ["GHSA-vh95-rmgr-6w4m"],
                "riskScore": 980,
                "sourceIntegrityState": "high-risk",
                "version": "1.2.8",
            }
        ],
        "policyHash": "policy-hash-1",
        "policyRules": [],
        "scoringVersion": "scf-v1",
        "sourceHashes": [{"payloadHash": "ghsa-feed-hash", "sourceKey": "ghsa", "staleStatus": "fresh"}],
        "tier": "premium",
        "workspaceId": WORKSPACE_ID,
    }
    canonical_payload = canonical_supply_chain_bundle_payload(bundle)
    payload_hash = hashlib.sha256(canonical_payload).hexdigest()
    loaded_key = serialization.load_pem_private_key(private_key_pem, password=None)
    assert isinstance(loaded_key, RSAPrivateKey)
    signature = loaded_key.sign(
        canonical_payload,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    return {
        "bundle": bundle,
        "payloadHash": payload_hash,
        "signature": base64.b64encode(signature).decode("utf-8"),
        "signatureAlgorithm": "rsa-pss-sha256",
        "verificationKeys": [
            {
                "fingerprintSha256": _fingerprint(public_key_pem),
                "keyId": "guard-bundle-key-2026-05",
                "publicKeyPem": public_key_pem.decode("utf-8").strip(),
                "state": "active",
                "validUntil": None,
            }
        ],
    }


class _BundleSyncHandler(BaseHTTPRequestHandler):
    captured_accept_encodings: ClassVar[list[str | None]] = []
    response_payload: ClassVar[dict[str, object]] = {}

    def do_GET(self) -> None:
        self.__class__.captured_accept_encodings.append(self.headers.get("Accept-Encoding"))
        if self.path.startswith("/api/guard/supply-chain/bundle"):
            body = json.dumps(self.__class__.response_payload).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self.end_headers()

    def log_message(self, message_format: str, *args: object) -> None:
        del message_format, args
        return


def test_sync_supply_chain_bundle_fetches_and_caches_bundle(tmp_path: Path) -> None:
    private_key_pem, public_key_pem = _generate_key_pair()
    _BundleSyncHandler.captured_accept_encodings = []
    _BundleSyncHandler.response_payload = _bundle_response(private_key_pem, public_key_pem)
    server = HTTPServer(("127.0.0.1", 0), _BundleSyncHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        store = GuardStore(tmp_path / "guard-home")
        store.set_sync_credentials(
            f"http://127.0.0.1:{server.server_port}/api/guard/receipts/sync",
            "demo-token",
            "2026-05-19T00:00:00Z",
            workspace_id=WORKSPACE_ID,
        )

        summary = sync_supply_chain_bundle(store)
    finally:
        server.shutdown()
        thread.join(timeout=5)

    assert summary["status"] == "synced"
    assert summary["bundle_version"] == "1747612800000-deadbeef"
    assert summary["workspace_id"] == WORKSPACE_ID
    assert store.get_cached_supply_chain_bundle(WORKSPACE_ID)["bundle"]["bundleVersion"] == "1747612800000-deadbeef"
    assert store.get_sync_payload("supply_chain_bundle_entitlement") == {
        "bundle_version": "1747612800000-deadbeef",
        "key_id": "guard-bundle-key-2026-05",
        "policy_hash": "policy-hash-1",
        "tier": "premium",
        "workspace_id": WORKSPACE_ID,
    }
    keyring = store.get_sync_payload("supply_chain_bundle_keyring")
    assert isinstance(keyring, dict)
    assert keyring["workspace_id"] == WORKSPACE_ID
    assert _BundleSyncHandler.captured_accept_encodings[0] == "identity"


def test_supply_chain_cache_and_eval_cache_clear_on_sync_token_rotation(tmp_path: Path) -> None:
    private_key_pem, public_key_pem = _generate_key_pair()
    response_payload = _bundle_response(private_key_pem, public_key_pem)
    store = GuardStore(tmp_path / "guard-home")
    store.set_sync_credentials(
        "https://hol.org/api/guard/receipts/sync",
        "token-one",
        "2026-05-19T00:00:00Z",
        workspace_id=WORKSPACE_ID,
    )
    store.cache_supply_chain_bundle(WORKSPACE_ID, response_payload, "2026-05-19T00:00:00Z")
    store.cache_supply_chain_evaluation(
        workspace_id=WORKSPACE_ID,
        package_intent_hash="intent-1",
        feed_snapshot_hash="feed-snapshot-1",
        policy_hash="policy-hash-1",
        scoring_version="scf-v1",
        bundle_version="1747612800000-deadbeef",
        decision={"action": "block", "reason": "known_malware_or_kev"},
        now="2026-05-19T00:00:00Z",
    )
    store.set_sync_payload("supply_chain_bundle_keyring", {"workspace_id": WORKSPACE_ID}, "2026-05-19T00:00:00Z")

    assert store.get_cached_supply_chain_bundle(WORKSPACE_ID) is not None
    assert (
        store.get_cached_supply_chain_evaluation(
            workspace_id=WORKSPACE_ID,
            package_intent_hash="intent-1",
            feed_snapshot_hash="feed-snapshot-1",
            policy_hash="policy-hash-1",
            scoring_version="scf-v1",
            bundle_version="1747612800000-deadbeef",
        )
        is not None
    )

    store.set_sync_credentials(
        "https://hol.org/api/guard/receipts/sync",
        "token-two",
        "2026-05-19T00:01:00Z",
    )

    assert store.get_cached_supply_chain_bundle(WORKSPACE_ID) is None
    assert (
        store.get_cached_supply_chain_evaluation(
            workspace_id=WORKSPACE_ID,
            package_intent_hash="intent-1",
            feed_snapshot_hash="feed-snapshot-1",
            policy_hash="policy-hash-1",
            scoring_version="scf-v1",
            bundle_version="1747612800000-deadbeef",
        )
        is None
    )
    assert store.get_sync_payload("supply_chain_bundle_keyring") is None
