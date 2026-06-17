"""Tests for HOL Guard supply-chain bundle sync and local cache persistence."""

from __future__ import annotations

import base64
import hashlib
import json
import threading
import urllib.parse
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import ClassVar

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, generate_private_key

from codex_plugin_scanner.guard.runtime import runner as guard_runner
from codex_plugin_scanner.guard.runtime.runner import sync_supply_chain_bundle
from codex_plugin_scanner.guard.runtime.supply_chain_bundle import canonical_supply_chain_bundle_payload
from codex_plugin_scanner.guard.store import GuardStore


def _seed_guard_cloud(store, *, workspace_id=None, sync_url=None, token="demo-token", now="2026-05-19T00:00:00Z"):
    """Seed OAuth credentials (replaces legacy set_sync_credentials scaffolding).

    Also installs a test-only resolver override so sync-path exercises stay hermetic
    (no OAuth token refresh against the network). Tests that need real sync against a
    local server pass sync_url=<url>.
    """
    from codex_plugin_scanner.guard.cli.oauth_client import generate_dpop_key_pair
    from codex_plugin_scanner.guard.runtime import runner as guard_runner_module

    dpop_key_material = generate_dpop_key_pair()
    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token=token,
        dpop_private_key_pem=dpop_key_material.private_key_pem,
        dpop_public_jwk=dpop_key_material.public_jwk,
        dpop_public_jwk_thumbprint=dpop_key_material.public_jwk_thumbprint,
        grant_id="grant-1",
        machine_id="machine-1",
        workspace_id=workspace_id,
        now=now,
    )
    effective_sync_url = sync_url if sync_url is not None else "https://hol.org/api/guard/receipts/sync"
    guard_runner_module._test_sync_auth_context_override = {
        "sync_url": effective_sync_url,
        "access_token": token,
        "dpop_key_material": None,
    }


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


def _bundle_response(
    private_key_pem: bytes,
    public_key_pem: bytes,
    *,
    bundle_version: str = "1747612800000-deadbeef",
) -> dict[str, object]:
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
        "bundleVersion": bundle_version,
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


def _partition_bundle_response(
    private_key_pem: bytes,
    public_key_pem: bytes,
    *,
    advisory_id: str,
    bundle_version: str,
    ecosystem: str,
    package_name: str,
    partition: int,
    partition_count: int,
) -> dict[str, object]:
    generated_at = datetime.now(timezone.utc) - timedelta(minutes=5)
    expires_at = generated_at + timedelta(hours=12)
    bundle = {
        "advisories": [
            {
                "advisoryId": advisory_id,
                "aliases": [],
                "confidence": 990,
                "exploitLevel": "active",
                "knownExploited": True,
                "malwareState": "none",
                "normalizedSeverity": "critical",
                "recommendedFixVersion": "1.0.1",
                "sourceKey": "ghsa",
                "summary": f"{advisory_id} summary",
                "title": f"{advisory_id} title",
            }
        ],
        "bundleVersion": bundle_version,
        "expiresAt": _iso(expires_at),
        "feedSnapshotHash": "feed-snapshot-2",
        "generatedAt": _iso(generated_at),
        "keyId": "guard-bundle-key-2026-05",
        "packages": [
            {
                "confidence": 990,
                "defaultAction": "block",
                "ecosystem": ecosystem,
                "exploitLevel": "active",
                "knownExploited": True,
                "malwareState": "known",
                "name": package_name,
                "namespace": None,
                "normalizedSeverity": "critical",
                "packageAgeState": "watch",
                "purl": f"pkg:{ecosystem}/{package_name}@1.0.0",
                "reachability": "reachable",
                "recommendedFixVersion": "1.0.1",
                "relatedAdvisoryIds": [advisory_id],
                "riskScore": 980,
                "sourceIntegrityState": "high-risk",
                "version": "1.0.0",
            }
        ],
        "policyHash": "policy-hash-2",
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
        "partitionDescriptor": {
            "advisoryCount": 1,
            "ecosystem": ecosystem,
            "packageCount": 1,
            "partition": partition,
            "partitionCount": partition_count,
            "payloadHash": payload_hash,
        },
    }


def _tamper_signature(payload: dict[str, object]) -> dict[str, object]:
    cloned = json.loads(json.dumps(payload))
    cloned["signature"] = base64.b64encode(b"tampered-signature").decode("utf-8")
    return cloned


class _BundleSyncHandler(BaseHTTPRequestHandler):
    captured_accept_encodings: ClassVar[list[str | None]] = []
    captured_paths: ClassVar[list[str]] = []
    index_payload: ClassVar[dict[str, object] | None] = None
    partition_payloads: ClassVar[dict[tuple[str, int], dict[str, object]]] = {}
    response_payload: ClassVar[dict[str, object]] = {}

    def do_GET(self) -> None:
        self.__class__.captured_paths.append(self.path)
        self.__class__.captured_accept_encodings.append(self.headers.get("Accept-Encoding"))
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path.startswith("/api/guard/supply-chain/bundle/index"):
            if self.__class__.index_payload is None:
                self.send_response(404)
                self.end_headers()
                return
            body = json.dumps(self.__class__.index_payload).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)
            return
        if parsed.path.startswith("/api/guard/supply-chain/bundle"):
            query = urllib.parse.parse_qs(parsed.query)
            ecosystem = query.get("ecosystem", [None])[0]
            partition_raw = query.get("partition", [None])[0]
            if isinstance(ecosystem, str) and isinstance(partition_raw, str):
                key = (ecosystem, int(partition_raw))
                partition_payload = self.__class__.partition_payloads.get(key)
                if partition_payload is not None:
                    body = json.dumps(partition_payload).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(body)
                    return
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
    _BundleSyncHandler.captured_paths = []
    _BundleSyncHandler.index_payload = None
    _BundleSyncHandler.partition_payloads = {}
    _BundleSyncHandler.response_payload = _bundle_response(private_key_pem, public_key_pem)
    server = HTTPServer(("127.0.0.1", 0), _BundleSyncHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        store = GuardStore(tmp_path / "guard-home")
        _seed_guard_cloud(
            store,
            workspace_id=WORKSPACE_ID,
            sync_url=f"http://127.0.0.1:{server.server_port}/api/guard/receipts/sync",
            token="demo-token",
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
    assert store.list_approval_requests() == []


def test_supply_chain_bundle_cache_persists_across_store_restart(tmp_path: Path) -> None:
    private_key_pem, public_key_pem = _generate_key_pair()
    response_payload = _bundle_response(private_key_pem, public_key_pem)
    guard_home = tmp_path / "guard-home"
    first_store = GuardStore(guard_home)
    first_store.cache_supply_chain_bundle(WORKSPACE_ID, response_payload, "2026-05-19T00:00:00Z")

    restarted_store = GuardStore(guard_home)
    cached = restarted_store.get_cached_supply_chain_bundle(WORKSPACE_ID)

    assert isinstance(cached, dict)
    bundle = cached.get("bundle")
    assert isinstance(bundle, dict)
    assert bundle["bundleVersion"] == "1747612800000-deadbeef"


def test_supply_chain_bundle_refresh_keeps_approval_queue_quiet(tmp_path: Path) -> None:
    private_key_pem, public_key_pem = _generate_key_pair()
    _BundleSyncHandler.captured_accept_encodings = []
    _BundleSyncHandler.response_payload = _bundle_response(
        private_key_pem,
        public_key_pem,
        bundle_version="1747616400000-refresh",
    )
    server = HTTPServer(("127.0.0.1", 0), _BundleSyncHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        store = GuardStore(tmp_path / "guard-home")
        _seed_guard_cloud(
            store,
            workspace_id=WORKSPACE_ID,
            sync_url=f"http://127.0.0.1:{server.server_port}/api/guard/receipts/sync",
            token="demo-token",
        )
        store.cache_supply_chain_bundle(
            WORKSPACE_ID,
            _bundle_response(private_key_pem, public_key_pem),
            "2026-05-19T00:00:00Z",
        )

        summary = sync_supply_chain_bundle(store)
    finally:
        server.shutdown()
        thread.join(timeout=5)

    assert summary["bundle_version"] == "1747616400000-refresh"
    assert store.get_cached_supply_chain_bundle(WORKSPACE_ID)["bundle"]["bundleVersion"] == "1747616400000-refresh"
    assert store.list_approval_requests() == []


def test_sync_supply_chain_bundle_refresh_downloads_only_changed_partitions(tmp_path: Path) -> None:
    private_key_pem, public_key_pem = _generate_key_pair()
    unchanged_partition = _partition_bundle_response(
        private_key_pem,
        public_key_pem,
        advisory_id="GHSA-unchanged",
        bundle_version="1747612800000-old",
        ecosystem="npm",
        package_name="minimist",
        partition=1,
        partition_count=1,
    )
    changed_partition = _partition_bundle_response(
        private_key_pem,
        public_key_pem,
        advisory_id="GHSA-changed",
        bundle_version="1747616400000-refresh",
        ecosystem="pypi",
        package_name="requests",
        partition=1,
        partition_count=1,
    )
    _BundleSyncHandler.captured_accept_encodings = []
    _BundleSyncHandler.captured_paths = []
    _BundleSyncHandler.response_payload = _bundle_response(
        private_key_pem,
        public_key_pem,
        bundle_version="1747616400000-refresh",
    )
    _BundleSyncHandler.partition_payloads = {
        ("pypi", 1): changed_partition,
    }
    _BundleSyncHandler.index_payload = {
        "bundleVersion": "1747616400000-refresh",
        "emergencyDenyCount": 0,
        "expiresAt": changed_partition["bundle"]["expiresAt"],
        "feedSnapshotHash": "feed-snapshot-2",
        "generatedAt": changed_partition["bundle"]["generatedAt"],
        "partitions": [
            {
                "advisoryCount": 1,
                "ecosystem": "npm",
                "packageCount": 1,
                "partition": 1,
                "partitionCount": 1,
                "payloadHash": unchanged_partition["payloadHash"],
            },
            {
                "advisoryCount": 1,
                "ecosystem": "pypi",
                "packageCount": 1,
                "partition": 1,
                "partitionCount": 1,
                "payloadHash": changed_partition["payloadHash"],
            },
        ],
        "policyHash": "policy-hash-2",
        "sourceHashes": [{"payloadHash": "ghsa-feed-hash", "sourceKey": "ghsa", "staleStatus": "fresh"}],
        "tier": "premium",
        "workspaceId": WORKSPACE_ID,
    }
    server = HTTPServer(("127.0.0.1", 0), _BundleSyncHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        store = GuardStore(tmp_path / "guard-home")
        _seed_guard_cloud(
            store,
            workspace_id=WORKSPACE_ID,
            sync_url=f"http://127.0.0.1:{server.server_port}/api/guard/receipts/sync",
            token="demo-token",
        )
        store.cache_supply_chain_bundle(WORKSPACE_ID, unchanged_partition, "2026-05-19T00:00:00Z")
        store.set_sync_payload(
            "supply_chain_bundle_partition_cache",
            {
                "bundle_version": "1747612800000-old",
                "partitions": {
                    "npm:1": {
                        "payload_hash": unchanged_partition["payloadHash"],
                        "response": unchanged_partition,
                    }
                },
                "workspace_id": WORKSPACE_ID,
            },
            "2026-05-19T00:00:00Z",
        )

        summary = sync_supply_chain_bundle(store)
    finally:
        server.shutdown()
        thread.join(timeout=5)

    requested_paths = "".join(_BundleSyncHandler.captured_paths)
    assert "/api/guard/supply-chain/bundle/index" in requested_paths
    assert "ecosystem=pypi&partition=1" in requested_paths
    assert "ecosystem=npm&partition=1" not in requested_paths
    assert any(
        path.startswith("/api/guard/supply-chain/bundle?") and "ecosystem=" not in path
        for path in _BundleSyncHandler.captured_paths
    )
    assert summary["status"] == "synced"
    assert summary["partition_sync"] == {"enabled": True, "refreshed": 1, "total": 2}


def test_sync_supply_chain_bundle_reuses_cached_partitions_without_full_refresh(tmp_path: Path) -> None:
    private_key_pem, public_key_pem = _generate_key_pair()
    npm_partition = _partition_bundle_response(
        private_key_pem,
        public_key_pem,
        advisory_id="GHSA-npm",
        bundle_version="1747616400000-refresh",
        ecosystem="npm",
        package_name="minimist",
        partition=1,
        partition_count=1,
    )
    pypi_partition = _partition_bundle_response(
        private_key_pem,
        public_key_pem,
        advisory_id="GHSA-pypi",
        bundle_version="1747616400000-refresh",
        ecosystem="pypi",
        package_name="requests",
        partition=1,
        partition_count=1,
    )
    _BundleSyncHandler.captured_accept_encodings = []
    _BundleSyncHandler.captured_paths = []
    _BundleSyncHandler.response_payload = {}
    _BundleSyncHandler.partition_payloads = {}
    _BundleSyncHandler.index_payload = {
        "bundleVersion": "1747616400000-refresh",
        "emergencyDenyCount": 0,
        "expiresAt": npm_partition["bundle"]["expiresAt"],
        "feedSnapshotHash": "feed-snapshot-2",
        "generatedAt": npm_partition["bundle"]["generatedAt"],
        "partitions": [
            {
                "advisoryCount": 1,
                "ecosystem": "npm",
                "packageCount": 1,
                "partition": 1,
                "partitionCount": 1,
                "payloadHash": npm_partition["payloadHash"],
            },
            {
                "advisoryCount": 1,
                "ecosystem": "pypi",
                "packageCount": 1,
                "partition": 1,
                "partitionCount": 1,
                "payloadHash": pypi_partition["payloadHash"],
            },
        ],
        "policyHash": "policy-hash-2",
        "sourceHashes": [{"payloadHash": "ghsa-feed-hash", "sourceKey": "ghsa", "staleStatus": "fresh"}],
        "tier": "premium",
        "workspaceId": WORKSPACE_ID,
    }
    server = HTTPServer(("127.0.0.1", 0), _BundleSyncHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        store = GuardStore(tmp_path / "guard-home")
        _seed_guard_cloud(
            store,
            workspace_id=WORKSPACE_ID,
            sync_url=f"http://127.0.0.1:{server.server_port}/api/guard/receipts/sync",
            token="demo-token",
        )
        store.cache_supply_chain_bundle(WORKSPACE_ID, npm_partition, "2026-05-19T00:00:00Z")
        store.set_sync_payload(
            "supply_chain_bundle_partition_cache",
            {
                "bundle_version": "1747616400000-refresh",
                "partitions": {
                    "npm:1": {
                        "payload_hash": npm_partition["payloadHash"],
                        "response": npm_partition,
                    },
                    "pypi:1": {
                        "payload_hash": pypi_partition["payloadHash"],
                        "response": pypi_partition,
                    },
                },
                "workspace_id": WORKSPACE_ID,
            },
            "2026-05-19T00:00:00Z",
        )

        summary = sync_supply_chain_bundle(store)
    finally:
        server.shutdown()
        thread.join(timeout=5)

    requested_paths = "".join(_BundleSyncHandler.captured_paths)
    assert "/api/guard/supply-chain/bundle/index" in requested_paths
    assert "ecosystem=" not in requested_paths
    assert not any(
        path.startswith("/api/guard/supply-chain/bundle?") and "ecosystem=" not in path
        for path in _BundleSyncHandler.captured_paths
    )
    assert summary["partition_sync"] == {"enabled": True, "refreshed": 0, "total": 2}


def test_sync_supply_chain_bundle_refetches_tampered_cached_partition(tmp_path: Path) -> None:
    private_key_pem, public_key_pem = _generate_key_pair()
    valid_partition = _partition_bundle_response(
        private_key_pem,
        public_key_pem,
        advisory_id="GHSA-npm",
        bundle_version="1747616400000-refresh",
        ecosystem="npm",
        package_name="minimist",
        partition=1,
        partition_count=1,
    )
    tampered_partition = _tamper_signature(valid_partition)
    _BundleSyncHandler.captured_accept_encodings = []
    _BundleSyncHandler.captured_paths = []
    _BundleSyncHandler.response_payload = _bundle_response(
        private_key_pem,
        public_key_pem,
        bundle_version="1747616400000-refresh",
    )
    _BundleSyncHandler.partition_payloads = {("npm", 1): valid_partition}
    _BundleSyncHandler.index_payload = {
        "bundleVersion": "1747616400000-refresh",
        "emergencyDenyCount": 0,
        "expiresAt": valid_partition["bundle"]["expiresAt"],
        "feedSnapshotHash": "feed-snapshot-2",
        "generatedAt": valid_partition["bundle"]["generatedAt"],
        "partitions": [
            {
                "advisoryCount": 1,
                "ecosystem": "npm",
                "packageCount": 1,
                "partition": 1,
                "partitionCount": 1,
                "payloadHash": valid_partition["payloadHash"],
            }
        ],
        "policyHash": "policy-hash-2",
        "sourceHashes": [{"payloadHash": "ghsa-feed-hash", "sourceKey": "ghsa", "staleStatus": "fresh"}],
        "tier": "premium",
        "workspaceId": WORKSPACE_ID,
    }
    server = HTTPServer(("127.0.0.1", 0), _BundleSyncHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        store = GuardStore(tmp_path / "guard-home")
        _seed_guard_cloud(
            store,
            workspace_id=WORKSPACE_ID,
            sync_url=f"http://127.0.0.1:{server.server_port}/api/guard/receipts/sync",
            token="demo-token",
        )
        store.cache_supply_chain_bundle(
            WORKSPACE_ID,
            _bundle_response(
                private_key_pem,
                public_key_pem,
                bundle_version="1747616400000-refresh",
            ),
            "2026-05-19T00:00:00Z",
        )
        store.set_sync_payload(
            "supply_chain_bundle_partition_cache",
            {
                "bundle_version": "1747616400000-refresh",
                "partitions": {
                    "npm:1": {
                        "payload_hash": valid_partition["payloadHash"],
                        "response": tampered_partition,
                    }
                },
                "workspace_id": WORKSPACE_ID,
            },
            "2026-05-19T00:00:00Z",
        )
        summary = sync_supply_chain_bundle(store)
    finally:
        server.shutdown()
        thread.join(timeout=5)

    assert summary["status"] == "synced"
    requested_paths = "".join(_BundleSyncHandler.captured_paths)
    assert "ecosystem=npm&partition=1" in requested_paths


def test_sync_supply_chain_bundle_refetches_full_bundle_for_tampered_cached_signature(tmp_path: Path) -> None:
    private_key_pem, public_key_pem = _generate_key_pair()
    npm_partition = _partition_bundle_response(
        private_key_pem,
        public_key_pem,
        advisory_id="GHSA-npm",
        bundle_version="1747616400000-refresh",
        ecosystem="npm",
        package_name="minimist",
        partition=1,
        partition_count=1,
    )
    pypi_partition = _partition_bundle_response(
        private_key_pem,
        public_key_pem,
        advisory_id="GHSA-pypi",
        bundle_version="1747616400000-refresh",
        ecosystem="pypi",
        package_name="requests",
        partition=1,
        partition_count=1,
    )
    _BundleSyncHandler.captured_accept_encodings = []
    _BundleSyncHandler.captured_paths = []
    _BundleSyncHandler.response_payload = _bundle_response(
        private_key_pem,
        public_key_pem,
        bundle_version="1747616400000-refresh",
    )
    _BundleSyncHandler.partition_payloads = {}
    _BundleSyncHandler.index_payload = {
        "bundleVersion": "1747616400000-refresh",
        "emergencyDenyCount": 0,
        "expiresAt": npm_partition["bundle"]["expiresAt"],
        "feedSnapshotHash": "feed-snapshot-2",
        "generatedAt": npm_partition["bundle"]["generatedAt"],
        "partitions": [
            {
                "advisoryCount": 1,
                "ecosystem": "npm",
                "packageCount": 1,
                "partition": 1,
                "partitionCount": 1,
                "payloadHash": npm_partition["payloadHash"],
            },
            {
                "advisoryCount": 1,
                "ecosystem": "pypi",
                "packageCount": 1,
                "partition": 1,
                "partitionCount": 1,
                "payloadHash": pypi_partition["payloadHash"],
            },
        ],
        "policyHash": "policy-hash-2",
        "sourceHashes": [{"payloadHash": "ghsa-feed-hash", "sourceKey": "ghsa", "staleStatus": "fresh"}],
        "tier": "premium",
        "workspaceId": WORKSPACE_ID,
    }
    server = HTTPServer(("127.0.0.1", 0), _BundleSyncHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        store = GuardStore(tmp_path / "guard-home")
        _seed_guard_cloud(
            store,
            workspace_id=WORKSPACE_ID,
            sync_url=f"http://127.0.0.1:{server.server_port}/api/guard/receipts/sync",
            token="demo-token",
        )
        store.cache_supply_chain_bundle(
            WORKSPACE_ID,
            _tamper_signature(
                _bundle_response(
                    private_key_pem,
                    public_key_pem,
                    bundle_version="1747616400000-refresh",
                )
            ),
            "2026-05-19T00:00:00Z",
        )
        store.set_sync_payload(
            "supply_chain_bundle_partition_cache",
            {
                "bundle_version": "1747616400000-refresh",
                "partitions": {
                    "npm:1": {
                        "payload_hash": npm_partition["payloadHash"],
                        "response": npm_partition,
                    },
                    "pypi:1": {
                        "payload_hash": pypi_partition["payloadHash"],
                        "response": pypi_partition,
                    },
                },
                "workspace_id": WORKSPACE_ID,
            },
            "2026-05-19T00:00:00Z",
        )
        summary = sync_supply_chain_bundle(store)
    finally:
        server.shutdown()
        thread.join(timeout=5)

    assert summary["status"] == "synced"
    assert any(
        path.startswith("/api/guard/supply-chain/bundle?") and "ecosystem=" not in path
        for path in _BundleSyncHandler.captured_paths
    )


def test_sync_supply_chain_bundle_wraps_runtime_error_when_cached_bundle_refetch_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_key_pem, public_key_pem = _generate_key_pair()
    npm_partition = _partition_bundle_response(
        private_key_pem,
        public_key_pem,
        advisory_id="GHSA-npm",
        bundle_version="1747616400000-refresh",
        ecosystem="npm",
        package_name="minimist",
        partition=1,
        partition_count=1,
    )
    index_payload = {
        "bundleVersion": "1747616400000-refresh",
        "emergencyDenyCount": 0,
        "expiresAt": npm_partition["bundle"]["expiresAt"],
        "feedSnapshotHash": "feed-snapshot-2",
        "generatedAt": npm_partition["bundle"]["generatedAt"],
        "partitions": [
            {
                "advisoryCount": 1,
                "ecosystem": "npm",
                "packageCount": 1,
                "partition": 1,
                "partitionCount": 1,
                "payloadHash": npm_partition["payloadHash"],
            }
        ],
        "policyHash": "policy-hash-2",
        "sourceHashes": [{"payloadHash": "ghsa-feed-hash", "sourceKey": "ghsa", "staleStatus": "fresh"}],
        "tier": "premium",
        "workspaceId": WORKSPACE_ID,
    }
    store = GuardStore(tmp_path / "guard-home")
    _seed_guard_cloud(store, workspace_id=WORKSPACE_ID)
    store.cache_supply_chain_bundle(
        WORKSPACE_ID,
        _tamper_signature(
            _bundle_response(
                private_key_pem,
                public_key_pem,
                bundle_version="1747616400000-refresh",
            )
        ),
        "2026-05-19T00:00:00Z",
    )
    store.set_sync_payload(
        "supply_chain_bundle_partition_cache",
        {
            "bundle_version": "1747616400000-refresh",
            "partitions": {
                "npm:1": {
                    "payload_hash": npm_partition["payloadHash"],
                    "response": npm_partition,
                }
            },
            "workspace_id": WORKSPACE_ID,
        },
        "2026-05-19T00:00:00Z",
    )

    def fake_fetch(request: object) -> dict[str, object]:
        request_url = getattr(request, "full_url", "")
        if isinstance(request_url, str) and request_url.endswith("/index?workspaceId=workspace-alpha"):
            return index_payload
        raise RuntimeError("simulated network failure")

    monkeypatch.setattr(guard_runner, "_fetch_supply_chain_bundle_payload", fake_fetch)

    with pytest.raises(RuntimeError, match="Guard supply-chain bundle sync failed: simulated network failure"):
        sync_supply_chain_bundle(store)
