"""Phase 11 JavaScript package-hook proofs for exec flows."""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, generate_private_key

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.cli import commands as guard_commands_module
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


def _bundle_response(*, package_name: str, version: str, namespace: str | None = None) -> dict[str, object]:
    generated_at = datetime(2026, 5, 19, tzinfo=timezone.utc)
    expires_at = generated_at + timedelta(hours=12)
    purl_name = f"{namespace}/{package_name}" if namespace is not None else package_name
    bundle = {
        "advisories": [
            {
                "advisoryId": "GHSA-vh95-rmgr-6w4m",
                "aliases": ["CVE-2020-7598"],
                "confidence": 990,
                "exploitLevel": "active",
                "knownExploited": True,
                "malwareState": "known",
                "normalizedSeverity": "critical",
                "recommendedFixVersion": None,
                "sourceKey": "ghsa",
                "summary": "Remote execution package risk",
                "title": "Remote execution package risk",
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
                "name": package_name,
                "namespace": namespace,
                "normalizedSeverity": "critical",
                "packageAgeState": "watch",
                "purl": f"pkg:npm/{purl_name}@{version}",
                "reachability": "reachable",
                "recommendedFixVersion": None,
                "relatedAdvisoryIds": ["GHSA-vh95-rmgr-6w4m"],
                "riskScore": 980,
                "sourceIntegrityState": "high-risk",
                "version": version,
            }
        ],
        "policyHash": "policy-hash-1",
        "policyRules": [],
        "scoringVersion": "scf-v1",
        "sourceHashes": [{"payloadHash": "ghsa-feed-hash", "sourceKey": "ghsa", "staleStatus": "fresh"}],
        "tier": "premium",
        "workspaceId": WORKSPACE_ID,
    }
    private_key_pem, public_key_pem = _generate_key_pair()
    loaded_key = serialization.load_pem_private_key(private_key_pem, password=None)
    assert isinstance(loaded_key, RSAPrivateKey)
    canonical_payload = json.dumps(bundle, sort_keys=True, separators=(",", ":")).encode("utf-8")
    payload_hash = hashlib.sha256(canonical_payload).hexdigest()
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


def _write_codex_pre_tool_payload(path: Path, workspace_dir: Path, command: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "session_id": "session-1",
                "turn_id": "turn-1",
                "cwd": str(workspace_dir),
                "hook_event_name": "PreToolUse",
                "model": "gpt-5.4",
                "permission_mode": "bypassPermissions",
                "tool_name": "Bash",
                "tool_input": {"command": command},
                "tool_use_id": "call-1",
            }
        ),
        encoding="utf-8",
    )


@pytest.mark.parametrize(
    ("command", "package_name", "version", "namespace"),
    [
        ("npx create-vite@5.1.0", "create-vite", "5.1.0", None),
        ("npm exec --package=create-vite@5.1.0 create-vite", "create-vite", "5.1.0", None),
        ("pnpm dlx create-next-app@14.2.0", "create-next-app", "14.2.0", None),
        ("yarn dlx @redwoodjs/create-redwood-app@6.0.0", "create-redwood-app", "6.0.0", "@redwoodjs"),
        ("bunx @angular/cli@19.0.0", "cli", "19.0.0", "@angular"),
    ],
)
def test_guard_hook_blocks_js_exec_flows_before_subprocess(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    command: str,
    package_name: str,
    version: str,
    namespace: str | None,
) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    payload_path = workspace_dir / "hook-event.json"
    _write_codex_pre_tool_payload(payload_path, workspace_dir, command)
    store = GuardStore(home_dir)
    store.set_sync_credentials(
        "https://hol.org/api/guard/receipts/sync", "demo-token", "2026-05-19T00:00:00Z", workspace_id=WORKSPACE_ID
    )
    store.cache_supply_chain_bundle(
        WORKSPACE_ID,
        _bundle_response(package_name=package_name, version=version, namespace=namespace),
        "2026-05-19T00:00:00Z",
    )
    (home_dir / "config.toml").write_text("approval_wait_timeout_seconds = 0\n", encoding="utf-8")
    monkeypatch.setenv("CODEX_MANAGED_BY_BUN", "1")
    monkeypatch.setattr(guard_commands_module, "ensure_guard_daemon", lambda _home: "http://127.0.0.1:5474")

    def fail_daemon(_home: Path) -> object:
        raise RuntimeError("no daemon client")

    monkeypatch.setattr(guard_commands_module, "load_guard_surface_daemon_client", fail_daemon)

    def fail_subprocess(*args: object, **kwargs: object) -> object:
        raise AssertionError("blocked exec flow must not launch a subprocess")

    monkeypatch.setattr(guard_commands_module.subprocess, "run", fail_subprocess)

    rc = main(
        [
            "guard",
            "hook",
            "--harness",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--event-file",
            str(payload_path),
        ]
    )
    captured = capsys.readouterr()

    assert rc == 2
    assert "blocked" in captured.err.lower()
    evidence = store.list_evidence()
    assert evidence
    assert evidence[0]["category"] == "supply-chain"
