"""Phase 15 local supply-chain CLI and runtime coverage."""

from __future__ import annotations

import base64
import hashlib
import json
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, generate_private_key

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard import local_supply_chain as local_supply_chain_module
from codex_plugin_scanner.guard.approvals import build_runtime_snapshot
from codex_plugin_scanner.guard.cli import commands as commands_module
from codex_plugin_scanner.guard.protect import build_protect_payload
from codex_plugin_scanner.guard.store import GuardStore

WORKSPACE_ID = "workspace-alpha"


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


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


def _package(
    *,
    name: str,
    version: str,
    default_action: str,
    normalized_severity: str = "critical",
    recommended_fix_version: str | None = "1.2.9",
) -> dict[str, object]:
    return {
        "confidence": 990,
        "defaultAction": default_action,
        "ecosystem": "npm",
        "exploitLevel": "active",
        "knownExploited": True,
        "malwareState": "known",
        "name": name,
        "namespace": None,
        "normalizedSeverity": normalized_severity,
        "packageAgeState": "watch",
        "purl": f"pkg:npm/{name}@{version}",
        "reachability": "reachable",
        "recommendedFixVersion": recommended_fix_version,
        "relatedAdvisoryIds": ["GHSA-vh95-rmgr-6w4m"],
        "riskScore": 980,
        "sourceIntegrityState": "high-risk",
        "version": version,
    }


def _bundle_response(*, packages: list[dict[str, object]]) -> dict[str, object]:
    generated_at = datetime.now(timezone.utc)
    expires_at = generated_at + timedelta(days=7)
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
        "packages": packages,
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


def _seed_supply_chain_bundle(store: GuardStore, *, packages: list[dict[str, object]], now: str) -> None:
    response = _bundle_response(packages=packages)
    store.set_sync_credentials(
        "https://hol.org/api/guard/receipts/sync",
        "token-one",
        now,
        workspace_id=WORKSPACE_ID,
    )
    store.cache_supply_chain_bundle(WORKSPACE_ID, response, now)
    store.set_sync_payload(
        "supply_chain_bundle_summary",
        {
            "advisory_count": 1,
            "bundle_version": "1747612800000-deadbeef",
            "ecosystem_support": [
                {"ecosystem": "npm", "support_level": "protected", "label": "Protected"},
                {"ecosystem": "pypi", "support_level": "protected", "label": "Protected"},
            ],
            "feed_snapshot_hash": "feed-snapshot-1",
            "package_count": len(packages),
            "policy_hash": "policy-hash-1",
            "status": "synced",
            "synced_at": now,
            "tier": "premium",
            "workspace_id": WORKSPACE_ID,
        },
        now,
    )
    store.set_sync_payload(
        "supply_chain_bundle_entitlement",
        {
            "bundle_version": "1747612800000-deadbeef",
            "key_id": "guard-bundle-key-2026-05",
            "policy_hash": "policy-hash-1",
            "tier": "premium",
            "workspace_id": WORKSPACE_ID,
        },
        now,
    )


def test_guard_protect_without_command_returns_supply_chain_status(tmp_path: Path, capsys) -> None:
    home_dir = tmp_path / "guard-home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    store = GuardStore(home_dir)
    _seed_supply_chain_bundle(
        store,
        packages=[_package(name="minimist", version="1.2.5", default_action="block")],
        now="2026-05-19T12:00:00+00:00",
    )

    rc = main(
        [
            "guard",
            "protect",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    output = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert output["mode"] == "status"
    assert output["supply_chain"]["status"] == "synced"
    assert output["supply_chain"]["bundle"]["tier"] == "premium"
    assert output["supply_chain"]["policy"]["cloud_advisory_action"] == "warn"


def test_guard_protect_routes_package_requests_through_supply_chain_eval_and_redacts_command(tmp_path: Path) -> None:
    home_dir = tmp_path / "guard-home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    store = GuardStore(home_dir)
    _seed_supply_chain_bundle(
        store,
        packages=[_package(name="minimist", version="1.2.5", default_action="block")],
        now="2026-05-19T12:00:00+00:00",
    )

    payload, exit_code = build_protect_payload(
        command=[
            "npm",
            "install",
            "minimist@1.2.5",
            "--registry=https://npm.pkg.github.com/?_authToken=super-secret-token",
            "--token=another-secret-token",
        ],
        store=store,
        workspace_dir=workspace_dir,
        dry_run=True,
        now="2026-05-19T12:00:00+00:00",
        unsafe_raw_output=False,
    )
    serialized = json.dumps(payload, sort_keys=True)

    assert exit_code == 2
    assert payload["supply_chain_evaluation"]["decision"] == "block"
    assert "super-secret-token" not in serialized
    assert "another-secret-token" not in serialized


def test_guard_doctor_includes_supply_chain_posture(tmp_path: Path, capsys) -> None:
    home_dir = tmp_path / "guard-home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    store = GuardStore(home_dir)
    _seed_supply_chain_bundle(
        store,
        packages=[_package(name="minimist", version="1.2.5", default_action="block")],
        now="2026-05-19T12:00:00+00:00",
    )

    rc = main(
        [
            "guard",
            "doctor",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    output = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert output["supply_chain"]["status"] == "synced"
    assert output["supply_chain"]["bundle"]["workspace_id"] == WORKSPACE_ID
    assert output["supply_chain"]["policy"]["security_level"] == "balanced"


def test_guard_supply_chain_scan_uses_manifest_and_lockfile_context(tmp_path: Path, capsys) -> None:
    home_dir = tmp_path / "guard-home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    _write_text(workspace_dir / "package.json", '{"name":"demo","dependencies":{"minimist":"^1.2.0"}}\n')
    _write_text(
        workspace_dir / "package-lock.json",
        json.dumps(
            {
                "name": "demo",
                "lockfileVersion": 3,
                "packages": {
                    "": {"dependencies": {"minimist": "^1.2.0"}},
                    "node_modules/minimist": {"version": "1.2.5"},
                },
            }
        )
        + "\n",
    )
    store = GuardStore(home_dir)
    _seed_supply_chain_bundle(
        store,
        packages=[_package(name="minimist", version="1.2.5", default_action="block")],
        now="2026-05-19T12:00:00+00:00",
    )

    rc = main(
        [
            "guard",
            "supply-chain",
            "scan",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    output = json.loads(capsys.readouterr().out)

    assert rc == 2
    assert output["manifest_paths"] == ["package.json"]
    assert output["lockfile_paths"] == ["package-lock.json"]
    assert output["evaluation"]["decision"] == "block"
    assert output["evaluation"]["packages"][0]["name"] == "minimist"


def test_guard_supply_chain_scan_without_supported_manifests_returns_zero(tmp_path: Path, capsys) -> None:
    home_dir = tmp_path / "guard-home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    store = GuardStore(home_dir)
    _seed_supply_chain_bundle(
        store,
        packages=[_package(name="minimist", version="1.2.5", default_action="block")],
        now="2026-05-19T12:00:00+00:00",
    )

    rc = main(
        [
            "guard",
            "supply-chain",
            "scan",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    output = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert output["manifest_paths"] == []
    assert output["lockfile_paths"] == []
    assert output["message"] == "No supported manifests or lockfiles found in this workspace."


def test_guard_supply_chain_sync_alias_uses_bundle_sync(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys
) -> None:
    home_dir = tmp_path / "guard-home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()

    monkeypatch.setattr(
        commands_module,
        "sync_supply_chain_bundle",
        lambda _store: {
            "status": "synced",
            "bundle_version": "1747612800000-deadbeef",
            "workspace_id": WORKSPACE_ID,
            "synced_at": "2026-05-19T12:00:00+00:00",
            "tier": "premium",
            "advisory_count": 1,
            "package_count": 1,
            "policy_hash": "policy-hash-1",
            "feed_snapshot_hash": "feed-snapshot-1",
            "ecosystem_support": [{"ecosystem": "npm", "support_level": "protected", "label": "Protected"}],
        },
    )

    rc = main(
        [
            "guard",
            "supply-chain",
            "sync",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    output = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert output["status"] == "synced"
    assert output["bundle_version"] == "1747612800000-deadbeef"


def test_guard_supply_chain_sync_alias_rejects_invalid_payload(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys
) -> None:
    home_dir = tmp_path / "guard-home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()

    monkeypatch.setattr(commands_module, "sync_supply_chain_bundle", lambda _store: None)

    rc = main(
        [
            "guard",
            "supply-chain",
            "sync",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    output = json.loads(capsys.readouterr().out)

    assert rc == 1
    assert output["synced"] is False
    assert output["error"] == "Guard Cloud sync returned an invalid response."


def test_guard_supply_chain_explain_reuses_cached_bundle_context(tmp_path: Path, capsys) -> None:
    home_dir = tmp_path / "guard-home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    store = GuardStore(home_dir)
    _seed_supply_chain_bundle(
        store,
        packages=[_package(name="minimist", version="1.2.5", default_action="block")],
        now="2026-05-19T12:00:00+00:00",
    )

    rc = main(
        [
            "guard",
            "supply-chain",
            "explain",
            "minimist@1.2.5",
            "--ecosystem",
            "npm",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    output = json.loads(capsys.readouterr().out)

    assert rc == 2
    assert output["request"]["package"] == "minimist@1.2.5"
    assert output["request"]["ecosystem"] == "npm"
    assert output["evaluation"]["decision"] == "block"
    assert output["evaluation"]["user_copy"]["harness_message"].startswith("HOL Guard blocked")


def test_runtime_snapshot_includes_supply_chain_block(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _seed_supply_chain_bundle(
        store,
        packages=[_package(name="minimist", version="1.2.5", default_action="block")],
        now="2026-05-19T12:00:00+00:00",
    )

    snapshot = build_runtime_snapshot(store=store, approval_center_url="http://127.0.0.1:4874")

    assert snapshot["supply_chain"]["status"] == "synced"
    assert snapshot["supply_chain"]["bundle"]["bundle_version"] == "1747612800000-deadbeef"
    assert snapshot["supply_chain"]["policy"]["cloud_advisory_action"] == "warn"
    assert snapshot["supply_chain"]["policy"]["managed_by_cloud"] is False


def test_runtime_snapshot_marks_supply_chain_policy_as_cloud_managed(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    now = "2026-05-19T12:00:00+00:00"
    _seed_supply_chain_bundle(
        store,
        packages=[_package(name="minimist", version="1.2.5", default_action="block")],
        now=now,
    )
    store.set_sync_payload(
        "team_policy_pack",
        {
            "name": "Security team default",
            "updatedAt": "2026-05-19T11:55:00Z",
        },
        now,
    )

    snapshot = build_runtime_snapshot(store=store, approval_center_url="http://127.0.0.1:4874")

    assert snapshot["supply_chain"]["policy"]["managed_by_cloud"] is True
    assert snapshot["supply_chain"]["policy"]["team_policy_active"] is True
    assert snapshot["supply_chain"]["policy"]["managed_label"] == "Security team default"


@pytest.mark.parametrize(
    ("raised_error", "expected_fragment"),
    [
        (subprocess.TimeoutExpired(cmd=["npm", "install"], timeout=45), "timed out"),
        (OSError("missing executable"), "missing executable"),
    ],
)
def test_guard_protect_returns_controlled_execution_error_for_install_subprocess_failures(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    raised_error: subprocess.TimeoutExpired | OSError,
    expected_fragment: str,
) -> None:
    home_dir = tmp_path / "guard-home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    store = GuardStore(home_dir)
    _seed_supply_chain_bundle(
        store,
        packages=[
            _package(
                name="lodash",
                version="4.17.21",
                default_action="allow",
                normalized_severity="low",
                recommended_fix_version=None,
            )
        ],
        now="2026-05-19T12:00:00+00:00",
    )

    def raise_error(*_args: object, **_kwargs: object) -> object:
        raise raised_error

    monkeypatch.setattr(local_supply_chain_module.subprocess, "run", raise_error)

    payload, exit_code = build_protect_payload(
        command=["npm", "install", "lodash@4.17.21"],
        store=store,
        workspace_dir=workspace_dir,
        dry_run=False,
        now="2026-05-19T12:00:00+00:00",
        unsafe_raw_output=False,
    )

    execution = payload["execution"]
    assert exit_code == 1
    assert payload["executed"] is True
    assert isinstance(execution, dict)
    assert execution["returncode"] == -1
    assert expected_fragment in str(execution["stderr"]).lower()
