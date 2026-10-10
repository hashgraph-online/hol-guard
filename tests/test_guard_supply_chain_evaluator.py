"""Behavior tests for local supply-chain package evaluation."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import tarfile
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import ClassVar

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, generate_private_key

from codex_plugin_scanner.guard.cli.oauth_client import generate_dpop_key_pair
from codex_plugin_scanner.guard.local_supply_chain import evaluate_package_request_artifact
from codex_plugin_scanner.guard.runtime.package_intent_common import (
    PackageIntent,
    build_package_request_artifact,
    js_target,
    python_target,
)
from codex_plugin_scanner.guard.runtime.package_request_evaluation import (
    _evidence_id,
)
from codex_plugin_scanner.guard.runtime.restricted_archive_download import RestrictedArchiveDownload
from codex_plugin_scanner.guard.store import GuardStore
from tests.native_workspace import bind_workspace
from tests.silent_cloud_server import silent_cloud_sync_url
from tests.support.network import stub_authenticated_urlopen


def _seed_guard_cloud(
    store,
    *,
    workspace_id=None,
    sync_url=None,
    token="demo-token",
    now="2026-05-19T00:00:00Z",
    plan_id="free",
):
    """Seed OAuth credentials (replaces legacy set_sync_credentials scaffolding).

    Also installs a test-only resolver override so sync-path exercises stay hermetic
    (no OAuth token refresh against the network). Tests that need real sync against a
    local server pass sync_url=<url>.
    """
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
        supply_chain_entitlement_expires_at=("2099-01-01T00:00:00Z" if plan_id != "free" else None),
        supply_chain_firewall=plan_id != "free",
        supply_chain_plan_id=plan_id,
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
    # The resident evaluates Cloud requests itself, so point its sync endpoint at
    # a loopback server that never answers and let the real timeout fire.
    monkeypatch.setenv("HOL_GUARD_TEST_CLOUD_UNREACHABLE_URL", silent_cloud_sync_url())


def _force_unpaid_entitlement(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(
        "HOL_GUARD_TEST_PACKAGE_ENTITLEMENT_JSON",
        json.dumps({"allowed": False, "reason": "paid_guard_cloud_required", "tier": "free"}),
    )


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
    # No package.json in the fixture workspace, so omit null manifestHash (Cloud zod rejects null).
    assert set(request_payload["lockfileContext"]) == {
        "dependencyCount",
        "fileName",
        "lockfileHash",
        "repository",
    }
    assert "manifestHash" not in request_payload["lockfileContext"]
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


def test_evaluate_package_request_artifact_keeps_policy_metadata_on_winning_package(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    bind_workspace(store, WORKSPACE_ID)
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


def test_evaluate_package_request_artifact_handles_invalid_lockfile_bytes_without_crashing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    bind_workspace(store, WORKSPACE_ID)
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
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, request: pytest.FixtureRequest
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    bind_workspace(store, WORKSPACE_ID)
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
    lockfile_path.chmod(0o000)
    request.addfinalizer(lambda: lockfile_path.chmod(0o600))

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

    stub_authenticated_urlopen(monkeypatch, timeout_urlopen)
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
