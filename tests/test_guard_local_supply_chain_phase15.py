"""Phase 15 local supply-chain CLI and runtime coverage."""

from __future__ import annotations

import base64
import hashlib
import json
import os
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
from codex_plugin_scanner.guard.config import load_guard_config
from codex_plugin_scanner.guard.protect import build_protect_payload
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


pytest_plugins = ["tests.bundle_first_cloud"]
pytestmark = pytest.mark.usefixtures("bundle_first_cloud")

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


def _bundle_response(
    *,
    packages: list[dict[str, object]],
    policy_rules: list[dict[str, object]] | None = None,
) -> dict[str, object]:
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
        "policyRules": policy_rules or [],
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


def _seed_supply_chain_bundle(
    store: GuardStore,
    *,
    packages: list[dict[str, object]],
    now: str,
    policy_rules: list[dict[str, object]] | None = None,
) -> None:
    response = _bundle_response(packages=packages, policy_rules=policy_rules)
    _seed_guard_cloud(store, workspace_id=WORKSPACE_ID)
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
    assert payload["receipt"]["action_envelope_json"]["policy_version"] == "policy-hash-1"
    redacted_command = payload["receipt"]["action_envelope_json"]["redacted_command"]
    assert isinstance(redacted_command, str)
    assert "npm install minimist@1.2.5" in redacted_command
    assert "super-secret-token" not in redacted_command
    assert "another-secret-token" not in redacted_command
    stored_receipt = store.list_receipts(limit=1)[0]
    assert stored_receipt["action_envelope_json"]["policy_version"] == "policy-hash-1"
    assert stored_receipt["action_envelope_json"]["matched_rule_id"] is None
    assert "super-secret-token" not in json.dumps(stored_receipt)
    assert "another-secret-token" not in json.dumps(stored_receipt)


def test_guard_protect_receipt_keeps_matched_policy_rule_metadata(tmp_path: Path) -> None:
    home_dir = tmp_path / "guard-home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    store = GuardStore(home_dir)
    _seed_supply_chain_bundle(
        store,
        packages=[_package(name="minimist", version="1.2.5", default_action="block")],
        now="2026-05-19T12:00:00+00:00",
        policy_rules=[
            {
                "action": "warn",
                "ruleId": "policy-rule-1",
                "ecosystemSelector": "npm",
                "enabled": True,
                "expiresAt": "2099-01-01T00:00:00Z",
                "harnessSelector": "guard-cli",
                "packageSelector": "minimist",
                "priority": 1,
                "severityThreshold": "low",
                "versionRangeSelector": "1.2.5",
            }
        ],
    )

    payload, exit_code = build_protect_payload(
        command=["npm", "install", "minimist@1.2.5"],
        store=store,
        workspace_dir=workspace_dir,
        dry_run=True,
        now="2026-05-19T12:00:00+00:00",
        unsafe_raw_output=False,
    )

    assert exit_code == 0
    assert payload["supply_chain_evaluation"]["matched_rule_id"] == "policy-rule-1"
    assert payload["receipt"]["action_envelope_json"] == {
        "bundle_version": "1747612800000-deadbeef",
        "matched_rule_id": "policy-rule-1",
        "package_manager": "npm",
        "package_targets": ["minimist@1.2.5"],
        "policy_version": "policy-hash-1",
        "redacted_command": "npm install minimist@1.2.5",
    }
    stored_receipt = store.list_receipts(limit=1)[0]
    assert stored_receipt["action_envelope_json"]["matched_rule_id"] == "policy-rule-1"


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


def test_supply_chain_posture_reports_protected_degraded_stale_and_next_refresh(tmp_path: Path) -> None:
    home_dir = tmp_path / "guard-home"
    store = GuardStore(home_dir)
    _seed_supply_chain_bundle(
        store,
        packages=[_package(name="minimist", version="1.2.5", default_action="block")],
        now="2026-05-19T12:00:00+00:00",
    )
    config = load_guard_config(home_dir)

    protected_posture = local_supply_chain_module.build_local_supply_chain_posture(
        store,
        config,
        now="2026-05-19T12:04:00+00:00",
    )
    stale_posture = local_supply_chain_module.build_local_supply_chain_posture(
        store,
        config,
        now="2026-05-19T12:25:01+00:00",
    )
    degraded_store = GuardStore(tmp_path / "guard-home-degraded")
    degraded_posture = local_supply_chain_module.build_local_supply_chain_posture(
        degraded_store,
        load_guard_config(degraded_store.guard_home),
        now="2026-05-19T12:04:00+00:00",
    )

    assert protected_posture["health_status"] == "protected"
    assert protected_posture["bundle"]["next_refresh_at"] == "2026-05-19T12:15:00+00:00"
    assert stale_posture["health_status"] == "stale"
    assert degraded_posture["health_status"] == "degraded"


def test_supply_chain_posture_reports_package_shim_path_and_unprotected_managers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home_dir = tmp_path / "guard-home"
    store = GuardStore(home_dir)
    _seed_supply_chain_bundle(
        store,
        packages=[_package(name="minimist", version="1.2.5", default_action="block")],
        now="2026-05-19T12:00:00+00:00",
    )
    shim_root = home_dir / "package-shims"
    shim_dir = shim_root / "bin"
    shim_dir.mkdir(parents=True, exist_ok=True)
    (shim_dir / "npm").write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
    (shim_dir / "npm").chmod(0o755)
    (shim_root / "manifest.json").write_text(
        json.dumps({"installed_managers": ["npm", "pnpm"], "shim_dir": str(shim_dir)}, sort_keys=True),
        encoding="utf-8",
    )
    monkeypatch.setenv("PATH", f"{shim_dir}{os.pathsep}{tmp_path}")

    posture = local_supply_chain_module.build_local_supply_chain_posture(
        store,
        load_guard_config(home_dir),
        now="2026-05-19T12:04:00+00:00",
    )

    protection = posture["package_manager_protection"]
    assert protection["path_status"] == "in_path"
    assert protection["path_contains_shim_dir"] is True
    assert protection["protected_managers"] == ["npm"]
    assert "pnpm" in protection["unprotected_managers"]
    assert protection["missing_shims"] == ["pnpm"]


def test_supply_chain_posture_marks_shim_path_missing_from_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home_dir = tmp_path / "guard-home"
    store = GuardStore(home_dir)
    _seed_supply_chain_bundle(
        store,
        packages=[_package(name="minimist", version="1.2.5", default_action="block")],
        now="2026-05-19T12:00:00+00:00",
    )
    shim_root = home_dir / "package-shims"
    shim_dir = shim_root / "bin"
    shim_dir.mkdir(parents=True, exist_ok=True)
    (shim_dir / "npm").write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
    (shim_dir / "npm").chmod(0o755)
    (shim_root / "manifest.json").write_text(
        json.dumps({"installed_managers": ["npm"], "shim_dir": str(shim_dir)}, sort_keys=True),
        encoding="utf-8",
    )
    monkeypatch.setenv("PATH", str(tmp_path))

    posture = local_supply_chain_module.build_local_supply_chain_posture(
        store,
        load_guard_config(home_dir),
        now="2026-05-19T12:04:00+00:00",
    )

    protection = posture["package_manager_protection"]
    assert protection["path_status"] == "missing_from_path"
    assert protection["path_contains_shim_dir"] is False
    assert "npm" in protection["unprotected_managers"]


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


def test_guard_supply_chain_scan_without_supported_manifests_returns_nonzero(tmp_path: Path, capsys) -> None:
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

    assert rc == 1
    assert output["manifest_paths"] == []
    assert output["lockfile_paths"] == []
    assert output["audit_status"] == "incomplete"
    assert output["audit_outcome"] == "no_project_files"
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
    assert "package_manager_protection" in snapshot["supply_chain"]


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
