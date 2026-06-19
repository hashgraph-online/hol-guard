"""Regression coverage for package-manager shim lifecycle commands."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import threading
from datetime import datetime, timedelta, timezone
from http.server import HTTPServer
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, generate_private_key

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard import shims as guard_shims_module
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.approvals import apply_approval_resolution
from codex_plugin_scanner.guard.cli import commands as guard_commands_module
from codex_plugin_scanner.guard.models import PolicyDecision
from codex_plugin_scanner.guard.package_shim_gate import package_shim_command_requires_guard
from codex_plugin_scanner.guard.protect import build_protect_payload
from codex_plugin_scanner.guard.runtime import supply_chain_package_eval as supply_chain_package_eval_module
from codex_plugin_scanner.guard.shim_probe import SHIM_PROBE_ENV_VALUE, SHIM_PROBE_ENV_VAR
from codex_plugin_scanner.guard.shims import build_shim_content_hash, install_package_shims, package_shim_status
from codex_plugin_scanner.guard.store import GuardStore
from tests.shim_execution_helpers import write_fake_manager_script
from tests.test_guard_protect import _seed_bundle_cache_only, _SyncAndEvaluateHandler
from tests.test_guard_supply_chain_evaluator import _cloud_response, _EvaluateHandler


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


def _seed_paid_bundle_entitlement(home_dir: Path) -> None:
    GuardStore(home_dir).set_sync_payload(
        "supply_chain_bundle_entitlement",
        {
            "bundle_version": "bundle-version-test",
            "key_id": "bundle-key-test",
            "policy_hash": "policy-hash-test",
            "tier": "pro",
            "workspace_id": WORKSPACE_ID,
        },
        "2026-06-05T01:39:51+00:00",
    )


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


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


_PRIVATE_KEY_PEM, _PUBLIC_KEY_PEM = _generate_key_pair()
_LOADED_PRIVATE_KEY = serialization.load_pem_private_key(_PRIVATE_KEY_PEM, password=None)
assert isinstance(_LOADED_PRIVATE_KEY, RSAPrivateKey)


def _bundle_response(
    *,
    action: str,
    ecosystem: str,
    package_name: str,
    package_version: str,
    feed_snapshot_hash: str = "feed-snapshot-shim-proof",
    policy_hash: str = "policy-hash-shim-proof",
    bundle_version: str = "1747612800000-shim-proof",
) -> dict[str, object]:
    generated_at = datetime.now(timezone.utc).replace(microsecond=0)
    expires_at = generated_at + timedelta(hours=12)
    advisory_id = f"GHSA-{ecosystem}-{package_name}"
    bundle = {
        "advisories": [
            {
                "advisoryId": advisory_id,
                "aliases": [],
                "confidence": 990,
                "exploitLevel": "active",
                "knownExploited": True,
                "malwareState": "known",
                "normalizedSeverity": "critical",
                "recommendedFixVersion": None,
                "sourceKey": "ghsa",
                "summary": f"High-risk package: {package_name}",
                "title": f"High-risk package: {package_name}",
            }
        ],
        "bundleVersion": bundle_version,
        "expiresAt": _iso(expires_at),
        "feedSnapshotHash": feed_snapshot_hash,
        "generatedAt": _iso(generated_at),
        "keyId": "guard-bundle-key-2026-05",
        "packages": [
            {
                "confidence": 990,
                "defaultAction": action,
                "ecosystem": ecosystem,
                "exploitLevel": "active",
                "knownExploited": True,
                "malwareState": "known",
                "name": package_name,
                "namespace": None,
                "normalizedSeverity": "critical",
                "packageAgeState": "watch",
                "purl": f"pkg:{ecosystem}/{package_name}@{package_version}",
                "reachability": "reachable",
                "recommendedFixVersion": None,
                "relatedAdvisoryIds": [advisory_id],
                "riskScore": 980,
                "sourceIntegrityState": "high-risk",
                "version": package_version,
            }
        ],
        "policyHash": policy_hash,
        "policyRules": [],
        "scoringVersion": "scf-v1",
        "sourceHashes": [{"payloadHash": "ghsa-feed-hash", "sourceKey": "ghsa", "staleStatus": "fresh"}],
        "tier": "premium",
        "workspaceId": WORKSPACE_ID,
    }
    canonical_payload = json.dumps(bundle, sort_keys=True, separators=(",", ":")).encode("utf-8")
    payload_hash = hashlib.sha256(canonical_payload).hexdigest()
    signature = _LOADED_PRIVATE_KEY.sign(
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
                "fingerprintSha256": _fingerprint(_PUBLIC_KEY_PEM),
                "keyId": "guard-bundle-key-2026-05",
                "publicKeyPem": _PUBLIC_KEY_PEM.decode("utf-8").strip(),
                "state": "active",
                "validUntil": None,
            }
        ],
    }


def _seed_bundle(
    *,
    home_dir: Path,
    ecosystem: str,
    package_name: str,
    package_version: str,
    action: str,
) -> None:
    _seed_bundle_cache_only(
        home_dir=home_dir,
        ecosystem=ecosystem,
        package_name=package_name,
        package_version=package_version,
        action=action,
    )


def _seed_workspace_sync_credentials(home_dir: Path, sync_url: str, *, now: str = "2026-05-19T00:00:00Z") -> None:
    _seed_guard_cloud(GuardStore(home_dir), workspace_id=WORKSPACE_ID, sync_url=sync_url, now=now)


def _with_subprocess_sync_auth(env: dict[str, str], sync_url: str) -> dict[str, str]:
    env["HOL_GUARD_TEST_SYNC_AUTH_CONTEXT_JSON"] = json.dumps(
        {
            "sync_url": sync_url,
            "access_token": "demo-token",
        }
    )
    return env


def _start_cloud_eval_server(
    *,
    decision: str,
    package_name: str,
    evaluate_status: int = 200,
) -> tuple[HTTPServer, threading.Thread, str]:
    if evaluate_status == 200:
        _EvaluateHandler.response_payload = _cloud_response(
            decision=decision,
            enforcement="premium_cloud",
            entitlement_state="premium",
            package_name=package_name,
        )
        handler = _EvaluateHandler
    else:
        _SyncAndEvaluateHandler.sync_payload = {"syncedAt": "2026-05-19T00:00:00Z", "receiptsStored": 0}
        _SyncAndEvaluateHandler.evaluate_status = evaluate_status
        handler = _SyncAndEvaluateHandler
    server = HTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    sync_url = f"http://127.0.0.1:{server.server_port}/api/guard/receipts/sync"
    return server, thread, sync_url


def _stop_cloud_eval_server(server: HTTPServer, thread: threading.Thread) -> None:
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)


def _install_single_manager_shim(
    *,
    home_dir: Path,
    workspace_dir: Path,
    manager: str,
    capsys,
) -> Path:
    _seed_paid_bundle_entitlement(home_dir)
    rc = main(
        [
            "guard",
            "package-shims",
            "install",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--manager",
            manager,
            "--json",
        ]
    )
    payload = json.loads(capsys.readouterr().out)
    assert rc == 0
    return Path(str(payload["shim_dir"])) / manager


def _write_npm_ci_workspace(workspace_dir: Path, *, package_name: str, package_version: str) -> None:
    (workspace_dir / "package.json").write_text(
        json.dumps(
            {
                "dependencies": {
                    package_name: package_version,
                },
                "lockfileVersion": 3,
                "name": "ci-fixture",
            }
        ),
        encoding="utf-8",
    )
    (workspace_dir / "package-lock.json").write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "name": "ci-fixture",
                "packages": {
                    "": {
                        "dependencies": {
                            package_name: package_version,
                        },
                        "name": "ci-fixture",
                    },
                    f"node_modules/{package_name}": {
                        "version": package_version,
                    },
                },
            }
        ),
        encoding="utf-8",
    )


def test_trusted_python_flags_omit_dash_p_before_python_311(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(guard_shims_module.sys, "version_info", (3, 10, 20, "final", 0))
    assert guard_shims_module._trusted_python_flags() == ["-I"]

    monkeypatch.setattr(guard_shims_module.sys, "version_info", (3, 11, 0, "final", 0))
    assert guard_shims_module._trusted_python_flags() == ["-I", "-P"]


def test_package_manager_shim_uses_trusted_guard_import_path(tmp_path: Path, capsys) -> None:
    home_dir = tmp_path / "guard-home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir(parents=True, exist_ok=True)
    malicious_package = workspace_dir / "codex_plugin_scanner"
    malicious_package.mkdir()
    (malicious_package / "__init__.py").write_text("", encoding="utf-8")
    (malicious_package / "cli.py").write_text(
        "\n".join(
            [
                "from pathlib import Path",
                f"Path({str(tmp_path / 'malicious-imported')!r}).write_text('owned', encoding='utf-8')",
                "raise SystemExit(66)",
                "",
            ]
        ),
        encoding="utf-8",
    )
    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir()
    marker_path = tmp_path / "npm-ran.json"
    write_fake_manager_script(fake_bin=fake_bin, manager="npm", marker_path=marker_path, exit_code=0)
    shim_path = _install_single_manager_shim(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        manager="npm",
        capsys=capsys,
    )
    env = dict(os.environ)
    env["PATH"] = f"{shim_path.parent}{os.pathsep}{fake_bin}{os.pathsep}{env.get('PATH', '')}"
    env["PYTHONPATH"] = os.pathsep.join(filter(None, [".", env.get("PYTHONPATH", "")]))

    result = subprocess.run(
        [str(shim_path), "install", "guard-github@git+https://example.com/guard.git"],
        cwd=workspace_dir,
        env=env,
        capture_output=True,
        check=False,
        text=True,
        timeout=30,
    )

    assert result.returncode == 2
    assert (tmp_path / "malicious-imported").exists() is False
    assert marker_path.exists() is False


@pytest.mark.parametrize(
    "command",
    [
        ["npm", "install", "guard-github@git+https://example.com/guard.git"],
        ["npm", "install", "guard-tarball@https://example.com/guard.tgz"],
        ["npm", "install", "file:./vendor/guard"],
    ],
)
def test_guard_protect_requires_review_for_untrusted_package_sources_without_cloud(
    tmp_path: Path,
    command: list[str],
) -> None:
    home_dir = tmp_path / "guard-home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir(parents=True, exist_ok=True)
    store = GuardStore(home_dir)

    payload, exit_code = build_protect_payload(
        command=command,
        store=store,
        workspace_dir=workspace_dir,
        dry_run=False,
        now="2026-05-25T00:00:00Z",
    )

    assert exit_code == 2
    assert payload["executed"] is False
    assert payload["verdict"]["blocking"] is True
    assert payload["verdict"]["action"] == "review"


def test_package_manager_shim_runs_allowed_command_once_when_shim_dir_is_on_path(tmp_path: Path, capsys) -> None:
    home_dir = tmp_path / "guard-home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir(parents=True, exist_ok=True)
    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir()
    marker_path = tmp_path / "npm-allowed.json"
    write_fake_manager_script(fake_bin=fake_bin, manager="npm", marker_path=marker_path, exit_code=0)
    server, thread, sync_url = _start_cloud_eval_server(decision="allow", package_name="minimist")
    try:
        _seed_bundle(
            home_dir=home_dir,
            ecosystem="npm",
            package_name="minimist",
            package_version="1.2.9",
            action="allow",
        )
        _seed_workspace_sync_credentials(home_dir, sync_url)
        shim_path = _install_single_manager_shim(
            home_dir=home_dir,
            workspace_dir=workspace_dir,
            manager="npm",
            capsys=capsys,
        )
        env = dict(os.environ)
        env["PATH"] = f"{shim_path.parent}{os.pathsep}{fake_bin}{os.pathsep}{env.get('PATH', '')}"

        result = subprocess.run(
            [str(shim_path), "install", "minimist@1.2.9"],
            cwd=workspace_dir,
            env=env,
            capture_output=True,
            check=False,
            text=True,
            timeout=30,
        )
    finally:
        _stop_cloud_eval_server(server, thread)
    assert marker_path.exists(), f"stdout={result.stdout!r} stderr={result.stderr!r} returncode={result.returncode}"
    marker_payload = json.loads(marker_path.read_text(encoding="utf-8"))

    assert result.returncode == 0
    assert marker_payload["argv"][1:] == ["install", "minimist@1.2.9"]
    assert marker_payload["cwd"] == str(workspace_dir)


@pytest.mark.parametrize(
    ("manager", "argv", "expected"),
    [
        ("bun", ("add", "minimist@1.2.9"), True),
        ("pip", ("install", "requests==2.32.3"), True),
        ("npm", ("install", "minimist@1.2.9"), True),
        ("npm", ("run", "dev"), False),
        ("pnpm", ("add", "minimist@1.2.9"), True),
        ("pnpm", ("install",), True),
        ("pnpm", ("run", "dev"), False),
        ("yarn", ("add", "minimist@1.2.9"), True),
    ],
)
def test_package_shim_command_requires_guard_only_for_supply_chain_actions(
    tmp_path: Path,
    manager: str,
    argv: tuple[str, ...],
    expected: bool,
) -> None:
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir(parents=True, exist_ok=True)

    assert package_shim_command_requires_guard(manager, argv, workspace=workspace_dir) is expected


def test_package_manager_shim_bypasses_guard_for_pnpm_run_commands(tmp_path: Path, capsys) -> None:
    home_dir = tmp_path / "guard-home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir(parents=True, exist_ok=True)
    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir(parents=True, exist_ok=True)
    marker_path = tmp_path / "pnpm-run-marker.json"
    write_fake_manager_script(
        fake_bin=fake_bin,
        manager="pnpm",
        marker_path=marker_path,
        exit_code=7,
        stdout_text="pnpm-run-stdout",
        stderr_text="pnpm-run-stderr",
    )
    shim_path = _install_single_manager_shim(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        manager="pnpm",
        capsys=capsys,
    )
    baseline_receipt_count = len(GuardStore(home_dir).list_receipts(limit=20))

    env = dict(os.environ)
    env["PATH"] = f"{shim_path.parent}{os.pathsep}{fake_bin}{os.pathsep}{env.get('PATH', '')}"
    env["SHIM_TEST_VAR"] = "shim-value"
    result = subprocess.run(
        [str(shim_path), "run", "dev"],
        cwd=workspace_dir,
        env=env,
        capture_output=True,
        check=False,
        text=True,
        timeout=30,
    )
    marker_payload = json.loads(marker_path.read_text(encoding="utf-8"))

    assert result.returncode == 7
    assert result.stdout.strip() == "pnpm-run-stdout"
    assert result.stderr.strip().endswith("pnpm-run-stderr")
    assert marker_payload["argv"][1:] == ["run", "dev"]
    assert marker_payload["cwd"] == str(workspace_dir)
    assert marker_payload["shim_var"] == "shim-value"
    assert len(GuardStore(home_dir).list_receipts(limit=20)) == baseline_receipt_count


_BLOCKING_SHIM_CASES = (
    ("npm", ("install", "minimist@1.2.8"), "npm", "minimist", "1.2.8"),
    ("pnpm", ("add", "minimist@1.2.8"), "npm", "minimist", "1.2.8"),
    ("yarn", ("add", "minimist@1.2.8"), "npm", "minimist", "1.2.8"),
    ("bun", ("add", "minimist@1.2.8"), "npm", "minimist", "1.2.8"),
    ("pip", ("install", "requests==2.32.0"), "pypi", "requests", "2.32.0"),
    ("uv", ("add", "requests==2.32.0"), "pypi", "requests", "2.32.0"),
    ("poetry", ("add", "requests@2.32.0"), "pypi", "requests", "2.32.0"),
    ("pipenv", ("install", "requests==2.32.0"), "pypi", "requests", "2.32.0"),
    ("pipx", ("install", "requests==2.32.0"), "pypi", "requests", "2.32.0"),
    ("uvx", ("requests==2.32.0",), "pypi", "requests", "2.32.0"),
    ("cargo", ("add", "serde@1.0.203"), "cargo", "serde", "1.0.203"),
    ("go", ("install", "github.com/pkg/errors@v0.9.1"), "go", "github.com/pkg/errors", "v0.9.1"),
    ("composer", ("require", "monolog/monolog:3.6.0"), "packagist", "monolog/monolog", "3.6.0"),
    ("bundle", ("add", "rails", "--version", "7.1.3"), "rubygems", "rails", "7.1.3"),
)


def test_guard_package_shims_install_status_uninstall_roundtrip(tmp_path: Path, capsys) -> None:
    home_dir = tmp_path / "guard-home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir(parents=True, exist_ok=True)
    _seed_paid_bundle_entitlement(home_dir)

    install_rc = main(
        [
            "guard",
            "package-shims",
            "install",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--manager",
            "npm",
            "--manager",
            "pip",
            "--json",
        ]
    )
    install_payload = json.loads(capsys.readouterr().out)

    assert install_rc == 0
    assert install_payload["installed_count"] == 2
    assert install_payload["installed_managers"] == ["npm", "pip"]
    assert install_payload["installed_now"] == ["npm", "pip"]
    shim_dir = Path(str(install_payload["shim_dir"]))
    manifest_path = Path(str(install_payload["manifest_path"]))
    assert (shim_dir / "npm").exists()
    assert (shim_dir / "pip").exists()
    assert manifest_path.exists()

    status_rc = main(
        [
            "guard",
            "package-shims",
            "status",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    status_payload = json.loads(capsys.readouterr().out)

    assert status_rc == 0
    assert status_payload["installed_managers"] == ["npm", "pip"]
    assert status_payload["active_managers"] == ["npm", "pip"]
    assert status_payload["missing_managers"] == []

    uninstall_rc = main(
        [
            "guard",
            "package-shims",
            "uninstall",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    uninstall_payload = json.loads(capsys.readouterr().out)

    assert uninstall_rc == 0
    assert sorted(uninstall_payload["removed_managers"]) == ["npm", "pip"]
    assert uninstall_payload["remaining_managers"] == []
    assert manifest_path.exists() is False


def test_guard_package_shims_install_merges_manifest_entries(tmp_path: Path, capsys) -> None:
    home_dir = tmp_path / "guard-home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir(parents=True, exist_ok=True)
    _seed_paid_bundle_entitlement(home_dir)

    first_rc = main(
        [
            "guard",
            "package-shims",
            "install",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--manager",
            "npm",
            "--json",
        ]
    )
    first_payload = json.loads(capsys.readouterr().out)
    second_rc = main(
        [
            "guard",
            "package-shims",
            "install",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--manager",
            "pip",
            "--json",
        ]
    )
    second_payload = json.loads(capsys.readouterr().out)

    assert first_rc == 0
    assert second_rc == 0
    assert first_payload["installed_managers"] == ["npm"]
    assert second_payload["installed_managers"] == ["npm", "pip"]
    assert second_payload["installed_now"] == ["pip"]


def test_guard_package_shims_repair_command_restores_selected_manager(tmp_path: Path, capsys) -> None:
    home_dir = tmp_path / "guard-home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir(parents=True, exist_ok=True)
    _seed_paid_bundle_entitlement(home_dir)

    install_rc = main(
        [
            "guard",
            "package-shims",
            "install",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--manager",
            "npm",
            "--manager",
            "pip",
            "--json",
        ]
    )
    install_payload = json.loads(capsys.readouterr().out)
    assert install_rc == 0
    shim_dir = Path(str(install_payload["shim_dir"]))
    (shim_dir / "npm").unlink()
    (shim_dir / "pip").unlink()

    repair_rc = main(
        [
            "guard",
            "package-shims",
            "repair",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--manager",
            "npm",
            "--json",
        ]
    )
    repair_payload = json.loads(capsys.readouterr().out)

    assert repair_rc == 0
    assert repair_payload["repaired"] == ["npm"]
    assert (shim_dir / "npm").exists()
    assert not (shim_dir / "pip").exists()


def test_guard_package_shims_repair_command_regenerates_stale_manager(tmp_path: Path, capsys) -> None:
    home_dir = tmp_path / "guard-home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir(parents=True, exist_ok=True)
    _seed_paid_bundle_entitlement(home_dir)

    install_rc = main(
        [
            "guard",
            "package-shims",
            "install",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--manager",
            "npm",
            "--json",
        ]
    )
    install_payload = json.loads(capsys.readouterr().out)
    assert install_rc == 0
    shim_path = Path(str(install_payload["shim_dir"])) / "npm"
    manifest_path = Path(str(install_payload["manifest_path"]))
    current_content = shim_path.read_text(encoding="utf-8")
    stale_content = '#!/bin/sh\nexec npm "$@"\n'
    shim_path.write_text(stale_content, encoding="utf-8")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["content_hashes"]["npm"] = build_shim_content_hash(stale_content.encode("utf-8"))
    manifest_path.write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")

    status_rc = main(
        [
            "guard",
            "package-shims",
            "status",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    status_payload = json.loads(capsys.readouterr().out)
    repair_rc = main(
        [
            "guard",
            "package-shims",
            "repair",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--manager",
            "npm",
            "--json",
        ]
    )
    repair_payload = json.loads(capsys.readouterr().out)

    assert status_rc == 0
    assert status_payload["manager_details"][0]["integrity"] == "stale"
    assert repair_rc == 0
    assert repair_payload["repaired"] == ["npm"]
    assert shim_path.read_text(encoding="utf-8") == current_content


def test_guard_package_shims_status_ignores_dynamic_generated_paths(tmp_path: Path) -> None:
    home_dir = tmp_path / "guard-home"
    install_workspace = tmp_path / "workspace-a"
    status_workspace = tmp_path / "workspace-b"
    install_workspace.mkdir(parents=True, exist_ok=True)
    status_workspace.mkdir(parents=True, exist_ok=True)
    install_package_shims(
        HarnessContext(home_dir=home_dir, workspace_dir=install_workspace, guard_home=home_dir),
        managers=("npm",),
    )

    status = package_shim_status(
        HarnessContext(home_dir=home_dir, workspace_dir=status_workspace, guard_home=home_dir),
    )

    assert status["manager_details"][0]["integrity"] == "ok"


def test_guard_package_shims_install_does_not_mutate_path_environment(
    tmp_path: Path,
    capsys,
    monkeypatch,
) -> None:
    home_dir = tmp_path / "guard-home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir(parents=True, exist_ok=True)
    _seed_paid_bundle_entitlement(home_dir)
    original_path = os.pathsep.join(["guard-a", "guard-b"])
    monkeypatch.setenv("PATH", original_path)

    rc = main(
        [
            "guard",
            "package-shims",
            "install",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--manager",
            "npm",
            "--json",
        ]
    )
    capsys.readouterr()

    assert rc == 0
    assert os.environ["PATH"] == original_path


def test_guard_package_shim_wrapper_routes_commands_through_guard_protect(tmp_path: Path, capsys) -> None:
    home_dir = tmp_path / "guard-home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir(parents=True, exist_ok=True)
    _seed_paid_bundle_entitlement(home_dir)

    rc = main(
        [
            "guard",
            "package-shims",
            "install",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--manager",
            "npm",
            "--json",
        ]
    )
    payload = json.loads(capsys.readouterr().out)

    assert rc == 0
    shim_path = Path(str(payload["shim_dir"])) / "npm"
    shim_source = shim_path.read_text(encoding="utf-8")
    assert "guard" in shim_source
    assert "protect" in shim_source
    assert "'npm'" in shim_source


def test_guard_package_shim_status_reports_protected_managers_when_shims_win_on_path(
    tmp_path: Path,
    monkeypatch,
) -> None:
    home_dir = tmp_path / "guard-home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir(parents=True, exist_ok=True)
    context = HarnessContext(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        guard_home=home_dir,
    )

    install_payload = install_package_shims(context, managers=("npm", "pip"))
    shim_dir = Path(str(install_payload["shim_dir"]))
    original_path = os.environ.get("PATH", "")
    monkeypatch.setenv("PATH", f"{shim_dir}{os.pathsep}{original_path}")

    status_payload = package_shim_status(context)

    assert status_payload["protected_managers"] == ["npm", "pip"]
    assert status_payload["path_active"] is True
    assert status_payload["bypasses"] == []


def test_guard_package_shim_status_reports_bypasses_when_system_binary_beats_shim(
    tmp_path: Path,
    monkeypatch,
) -> None:
    home_dir = tmp_path / "guard-home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir(parents=True, exist_ok=True)
    context = HarnessContext(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        guard_home=home_dir,
    )

    install_payload = install_package_shims(context, managers=("npm",))
    shim_dir = Path(str(install_payload["shim_dir"]))
    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir(parents=True, exist_ok=True)
    fake_npm = fake_bin / "npm"
    fake_npm.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    fake_npm.chmod(0o755)
    original_path = os.environ.get("PATH", "")
    monkeypatch.setenv("PATH", f"{fake_bin}{os.pathsep}{shim_dir}{os.pathsep}{original_path}")

    status_payload = package_shim_status(context)

    assert status_payload["protected_managers"] == []
    assert status_payload["path_active"] is False
    assert status_payload["bypasses"] == [
        {
            "manager": "npm",
            "reason": "path_inactive",
        }
    ]


def test_guard_package_shim_status_reports_foreign_shim_bypass(
    tmp_path: Path,
    monkeypatch,
) -> None:
    home_dir = tmp_path / "guard-home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir(parents=True, exist_ok=True)
    context = HarnessContext(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        guard_home=home_dir,
    )

    install_payload = install_package_shims(context, managers=("npm",))
    shim_dir = Path(str(install_payload["shim_dir"]))
    evil_shim_dir = tmp_path / "evil" / "package-shims" / "bin"
    evil_shim_dir.mkdir(parents=True)
    evil_shim = evil_shim_dir / "npm"
    evil_shim.write_text("#!/bin/sh\nevil npm\n", encoding="utf-8")
    evil_shim.chmod(0o755)
    real_dir = tmp_path / "usr" / "bin"
    real_dir.mkdir(parents=True, exist_ok=True)
    real_npm = real_dir / "npm"
    real_npm.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    real_npm.chmod(0o755)
    monkeypatch.setenv("PATH", f"{evil_shim_dir}{os.pathsep}{shim_dir}{os.pathsep}{real_dir}")

    status_payload = package_shim_status(context)

    assert status_payload["protected_managers"] == []
    assert status_payload["path_active"] is False
    assert status_payload["bypasses"] == [
        {
            "manager": "npm",
            "reason": "foreign_shim_bypass",
        }
    ]
    npm_detail = next(
        (entry for entry in status_payload["manager_details"] if entry["manager"] == "npm"),
        None,
    )
    assert npm_detail is not None
    path_status = npm_detail["path_status"]
    assert isinstance(path_status, dict)
    assert path_status["foreign_shim_bypass"] is True


@pytest.mark.parametrize(
    "manager,shim_args,ecosystem,package_name,package_version",
    _BLOCKING_SHIM_CASES,
)
def test_guard_package_shims_block_before_manager_execution(
    tmp_path: Path,
    capsys,
    manager: str,
    shim_args: tuple[str, ...],
    ecosystem: str,
    package_name: str,
    package_version: str,
) -> None:
    home_dir = tmp_path / "guard-home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir(parents=True, exist_ok=True)
    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir(parents=True, exist_ok=True)
    marker_path = tmp_path / f"{manager}-marker.json"
    write_fake_manager_script(fake_bin=fake_bin, manager=manager, marker_path=marker_path, exit_code=0)
    sync_url = "http://127.0.0.1:9/api/guard/receipts/sync"
    _seed_bundle(
        home_dir=home_dir,
        ecosystem=ecosystem,
        package_name=package_name,
        package_version=package_version,
        action="block",
    )
    _seed_workspace_sync_credentials(home_dir, sync_url)
    shim_path = _install_single_manager_shim(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        manager=manager,
        capsys=capsys,
    )

    env = _with_subprocess_sync_auth(dict(os.environ), sync_url)
    env["HOL_GUARD_TEST_SKIP_LOCAL_APPROVAL_QUEUE"] = "1"
    env["PATH"] = os.pathsep.join(filter(None, [str(fake_bin), env.get("PATH")]))
    result = subprocess.run(
        [str(shim_path), *shim_args],
        cwd=workspace_dir,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )

    assert result.returncode != 0
    assert marker_path.exists() is False
    assert '"verdict"' not in result.stdout
    assert "HOL Guard" in result.stdout


def test_guard_package_shim_preserves_argv_cwd_env_exitcode_and_stdio(tmp_path: Path, capsys) -> None:
    home_dir = tmp_path / "guard-home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir(parents=True, exist_ok=True)
    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir(parents=True, exist_ok=True)
    marker_path = tmp_path / "npm-allow-marker.json"
    write_fake_manager_script(
        fake_bin=fake_bin,
        manager="npm",
        marker_path=marker_path,
        exit_code=7,
        stdout_text="fake-manager-stdout",
        stderr_text="fake-manager-stderr",
    )
    server, thread, sync_url = _start_cloud_eval_server(decision="allow", package_name="minimist")
    try:
        _seed_bundle(
            home_dir=home_dir,
            ecosystem="npm",
            package_name="minimist",
            package_version="1.2.8",
            action="allow",
        )
        _seed_workspace_sync_credentials(home_dir, sync_url)
        shim_path = _install_single_manager_shim(
            home_dir=home_dir,
            workspace_dir=workspace_dir,
            manager="npm",
            capsys=capsys,
        )

        env = dict(os.environ)
        env["PATH"] = os.pathsep.join(filter(None, [str(fake_bin), env.get("PATH")]))
        env["SHIM_TEST_VAR"] = "shim-value"
        result = subprocess.run(
            [str(shim_path), "ci"],
            cwd=workspace_dir,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
    finally:
        _stop_cloud_eval_server(server, thread)
    marker_payload = json.loads(marker_path.read_text(encoding="utf-8"))

    assert result.returncode == 7
    assert marker_payload["argv"][1:] == ["ci"]
    assert marker_payload["cwd"] == str(workspace_dir)
    assert marker_payload["shim_var"] == "shim-value"
    assert result.stdout.strip() == "fake-manager-stdout"


def test_guard_protect_json_queues_local_approval_link_on_cloud_auth_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys,
) -> None:
    home_dir = tmp_path / "guard-home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir(parents=True, exist_ok=True)
    server, thread, sync_url = _start_cloud_eval_server(
        decision="allow",
        package_name="minimist",
        evaluate_status=401,
    )
    monkeypatch.setattr(guard_commands_module, "ensure_guard_daemon", lambda _home: "http://127.0.0.1:5474")
    try:
        _seed_bundle(
            home_dir=home_dir,
            ecosystem="npm",
            package_name="minimist",
            package_version="1.2.8",
            action="block",
        )
        _seed_workspace_sync_credentials(home_dir, sync_url)

        rc = main(
            [
                "guard",
                "protect",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
                "--dry-run",
                "npm",
                "install",
                "minimist@1.2.8",
            ]
        )
    finally:
        _stop_cloud_eval_server(server, thread)

    payload = json.loads(capsys.readouterr().out)
    stored_receipt = GuardStore(home_dir).list_receipts(limit=1)[0]

    assert rc == 2
    assert payload["approval_center_url"] == "http://127.0.0.1:5474"
    assert payload["primary_approval_request_id"]
    assert payload["primary_approval_url"].startswith("http://127.0.0.1:5474/requests/")
    assert payload["approval_request_ids"] == [payload["primary_approval_request_id"]]
    assert payload["receipt"]["approval_request_id"] == payload["primary_approval_request_id"]
    assert stored_receipt["approval_request_id"] == payload["primary_approval_request_id"]
    assert payload["supply_chain_evaluation"]["user_copy"]["dashboard_url"] == payload["primary_approval_url"]
    assert (
        "Open HOL Guard to approve or keep this blocked:"
        in payload["supply_chain_evaluation"]["user_copy"]["harness_message"]
    )


def test_guard_protect_probe_skips_local_approval_queue_on_block(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys,
) -> None:
    home_dir = tmp_path / "guard-home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir(parents=True, exist_ok=True)
    server, thread, sync_url = _start_cloud_eval_server(
        decision="allow",
        package_name="minimist",
        evaluate_status=401,
    )
    monkeypatch.setattr(guard_commands_module, "ensure_guard_daemon", lambda _home: "http://127.0.0.1:5474")
    monkeypatch.setenv(SHIM_PROBE_ENV_VAR, SHIM_PROBE_ENV_VALUE)
    try:
        _seed_bundle(
            home_dir=home_dir,
            ecosystem="npm",
            package_name="minimist",
            package_version="1.2.8",
            action="block",
        )
        _seed_workspace_sync_credentials(home_dir, sync_url)
        rc = main(
            [
                "guard",
                "protect",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
                "--dry-run",
                "npm",
                "install",
                "minimist@1.2.8",
            ]
        )
    finally:
        _stop_cloud_eval_server(server, thread)

    payload = json.loads(capsys.readouterr().out)
    store = GuardStore(home_dir)

    assert rc == 2
    assert payload["verdict"]["action"] == "block"
    assert "primary_approval_request_id" not in payload
    assert store.list_approval_requests(limit=None) == []


def test_guard_protect_retry_runs_after_local_package_approval(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys,
) -> None:
    home_dir = tmp_path / "guard-home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir(parents=True, exist_ok=True)
    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir(parents=True, exist_ok=True)
    marker_path = tmp_path / "npm-approved-marker.json"
    write_fake_manager_script(fake_bin=fake_bin, manager="npm", marker_path=marker_path, exit_code=0)
    server, thread, sync_url = _start_cloud_eval_server(
        decision="allow",
        package_name="minimist",
        evaluate_status=401,
    )
    monkeypatch.setattr(guard_commands_module, "ensure_guard_daemon", lambda _home: "http://127.0.0.1:5474")
    try:
        _seed_bundle(
            home_dir=home_dir,
            ecosystem="npm",
            package_name="minimist",
            package_version="1.2.8",
            action="block",
        )
        _seed_workspace_sync_credentials(home_dir, sync_url)
        rc = main(
            [
                "guard",
                "protect",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
                "--dry-run",
                "npm",
                "install",
                "minimist@1.2.8",
            ]
        )
        payload = json.loads(capsys.readouterr().out)
        assert rc == 2

        store = GuardStore(home_dir)
        apply_approval_resolution(
            store=store,
            request_id=str(payload["primary_approval_request_id"]),
            action="allow",
            scope="artifact",
            workspace=None,
            reason="reviewed",
        )

        original_path = os.environ.get("PATH", "")
        monkeypatch.setenv("PATH", os.pathsep.join(filter(None, [str(fake_bin), original_path])))
        retry_payload, retry_exit_code = build_protect_payload(
            command=["npm", "install", "minimist@1.2.8"],
            store=store,
            workspace_dir=workspace_dir,
            dry_run=False,
            now="2026-05-19T00:00:00Z",
        )
    finally:
        _stop_cloud_eval_server(server, thread)

    assert retry_exit_code == 0
    assert retry_payload["executed"] is True
    assert retry_payload["verdict"]["action"] == "allow"
    assert marker_path.exists()


def test_guard_protect_denied_retry_does_not_requeue_local_package_approval(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys,
) -> None:
    home_dir = tmp_path / "guard-home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir(parents=True, exist_ok=True)
    server, thread, sync_url = _start_cloud_eval_server(
        decision="allow",
        package_name="minimist",
        evaluate_status=401,
    )
    monkeypatch.setattr(guard_commands_module, "ensure_guard_daemon", lambda _home: "http://127.0.0.1:5474")
    try:
        _seed_bundle(
            home_dir=home_dir,
            ecosystem="npm",
            package_name="minimist",
            package_version="1.2.8",
            action="block",
        )
        _seed_workspace_sync_credentials(home_dir, sync_url)
        rc = main(
            [
                "guard",
                "protect",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
                "--dry-run",
                "npm",
                "install",
                "minimist@1.2.8",
            ]
        )
        payload = json.loads(capsys.readouterr().out)
        store = GuardStore(home_dir)
        assert rc == 2
        apply_approval_resolution(
            store=store,
            request_id=str(payload["primary_approval_request_id"]),
            action="block",
            scope="artifact",
            workspace=None,
            reason="keep blocked",
        )
        retry_rc = main(
            [
                "guard",
                "protect",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
                "--dry-run",
                "npm",
                "install",
                "minimist@1.2.8",
            ]
        )
    finally:
        _stop_cloud_eval_server(server, thread)

    retry_payload = json.loads(capsys.readouterr().out)
    store = GuardStore(home_dir)
    pending = store.list_approval_requests(status="pending", limit=None)
    resolved = store.list_approval_requests(status="resolved", limit=None)

    assert retry_rc == 2
    assert retry_payload["verdict"]["action"] == "block"
    assert any(
        isinstance(reason, dict) and reason.get("code") == "saved_package_block"
        for reason in retry_payload["supply_chain_evaluation"]["reasons"]
    )
    assert "primary_approval_request_id" not in retry_payload
    assert pending == []
    assert len(resolved) == 1


def test_guard_protect_json_queues_local_approval_when_cached_advisory_overrides_bundle_allow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys,
) -> None:
    home_dir = tmp_path / "guard-home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir(parents=True, exist_ok=True)
    store = GuardStore(home_dir)
    _seed_bundle_cache_only(
        home_dir=home_dir,
        ecosystem="npm",
        package_name="badpkg",
        package_version="1.0.0",
        action="allow",
    )
    store.cache_advisories(
        [
            {
                "id": "adv-cached-block",
                "ecosystem": "npm",
                "package": "badpkg",
                "severity": "high",
                "action": "block",
                "headline": "Locally cached malicious package block.",
            }
        ],
        "2026-05-19T00:00:00Z",
    )
    monkeypatch.setattr(guard_commands_module, "ensure_guard_daemon", lambda _home: "http://127.0.0.1:5474")

    rc = main(
        [
            "guard",
            "protect",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
            "--dry-run",
            "npm",
            "install",
            "badpkg@1.0.0",
        ]
    )

    payload = json.loads(capsys.readouterr().out)
    pending = store.list_approval_requests(limit=None)

    assert rc == 2
    assert payload["verdict"]["action"] == "block"
    assert payload["primary_approval_request_id"]
    assert payload["primary_approval_url"].startswith("http://127.0.0.1:5474/requests/")
    assert pending[0]["risk_summary"] == payload["verdict"]["reason"]
    assert pending[0]["risk_summary"] != payload["supply_chain_evaluation"]["risk_summary"]


def test_guard_protect_denied_retry_with_cloud_block_does_not_requeue_local_package_approval(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys,
) -> None:
    home_dir = tmp_path / "guard-home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir(parents=True, exist_ok=True)
    store = GuardStore(home_dir)
    server, thread, sync_url = _start_cloud_eval_server(
        decision="block",
        package_name="badpkg",
    )
    monkeypatch.setattr(guard_commands_module, "ensure_guard_daemon", lambda _home: "http://127.0.0.1:5474")
    try:
        _seed_bundle(
            home_dir=home_dir,
            ecosystem="npm",
            package_name="badpkg",
            package_version="1.0.0",
            action="block",
        )
        _seed_workspace_sync_credentials(home_dir, sync_url)
        rc = main(
            [
                "guard",
                "protect",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
                "--dry-run",
                "npm",
                "install",
                "badpkg@1.0.0",
            ]
        )
        payload = json.loads(capsys.readouterr().out)

        assert rc == 2
        apply_approval_resolution(
            store=store,
            request_id=str(payload["primary_approval_request_id"]),
            action="block",
            scope="artifact",
            workspace=None,
            reason="keep blocked",
        )

        retry_rc = main(
            [
                "guard",
                "protect",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
                "--dry-run",
                "npm",
                "install",
                "badpkg@1.0.0",
            ]
        )
    finally:
        _stop_cloud_eval_server(server, thread)

    retry_payload = json.loads(capsys.readouterr().out)
    pending = store.list_approval_requests(status="pending", limit=None)
    resolved = store.list_approval_requests(status="resolved", limit=None)

    assert retry_rc == 2
    assert retry_payload["verdict"]["action"] == "block"
    assert any(
        isinstance(reason, dict) and reason.get("code") == "saved_package_block"
        for reason in retry_payload["supply_chain_evaluation"]["reasons"]
    )
    assert "primary_approval_request_id" not in retry_payload
    assert pending == []
    assert len(resolved) == 1


def test_guard_protect_saved_approval_does_not_bypass_new_bundle_block_for_unpinned_package(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys,
) -> None:
    home_dir = tmp_path / "guard-home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir(parents=True, exist_ok=True)
    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir(parents=True, exist_ok=True)
    marker_path = tmp_path / "npm-somepkg-marker.json"
    write_fake_manager_script(fake_bin=fake_bin, manager="npm", marker_path=marker_path, exit_code=0)
    package_name = "somepkg"
    original_resolved_target_version = supply_chain_package_eval_module._resolved_target_version

    def _resolve_somepkg_version(**kwargs: object) -> str | None:
        target = kwargs.get("target")
        if isinstance(target, dict) and str(target.get("normalized_name")) == package_name:
            return "1.0.0"
        return original_resolved_target_version(**kwargs)

    monkeypatch.setattr(
        supply_chain_package_eval_module,
        "_resolved_target_version",
        _resolve_somepkg_version,
    )
    server, thread, sync_url = _start_cloud_eval_server(
        decision="allow",
        package_name=package_name,
        evaluate_status=401,
    )
    monkeypatch.setattr(guard_commands_module, "ensure_guard_daemon", lambda _home: "http://127.0.0.1:5474")
    try:
        store = GuardStore(home_dir)
        _seed_bundle_cache_only(
            home_dir=home_dir,
            ecosystem="npm",
            package_name=package_name,
            package_version="1.0.0",
            action="allow",
        )
        _seed_workspace_sync_credentials(home_dir, sync_url)

        first_payload, first_exit_code = build_protect_payload(
            command=["npm", "install", package_name],
            store=store,
            workspace_dir=workspace_dir,
            dry_run=True,
            now="2026-05-19T00:00:00Z",
        )

        assert first_exit_code == 2
        assert first_payload["verdict"]["action"] in {"block", "review"}
        receipt = first_payload["receipt"]
        assert isinstance(receipt, dict)
        store.upsert_policy(
            PolicyDecision(
                harness="guard-cli",
                scope="artifact",
                action="allow",
                artifact_id=str(receipt["artifact_id"]),
                artifact_hash=str(receipt["artifact_hash"]),
                workspace=None,
                publisher=None,
                reason="reviewed",
            ),
            "2026-05-19T00:00:00Z",
        )

        response = _bundle_response(
            action="block",
            ecosystem="npm",
            package_name=package_name,
            package_version="1.0.0",
            feed_snapshot_hash="feed-snapshot-block-2",
            policy_hash="policy-hash-block-2",
            bundle_version="1747612801000-shim-proof",
        )
        store.cache_supply_chain_bundle(WORKSPACE_ID, response, "2026-05-19T01:00:00Z")
        bundle = response["bundle"]
        assert isinstance(bundle, dict)
        store.set_sync_payload(
            "supply_chain_bundle_entitlement",
            {
                "bundle_version": bundle["bundleVersion"],
                "key_id": bundle["keyId"],
                "policy_hash": bundle["policyHash"],
                "tier": bundle["tier"],
                "workspace_id": WORKSPACE_ID,
            },
            "2026-05-19T01:00:00Z",
        )

        original_path = os.environ.get("PATH", "")
        monkeypatch.setenv("PATH", os.pathsep.join(filter(None, [str(fake_bin), original_path])))
        retry_payload, retry_exit_code = build_protect_payload(
            command=["npm", "install", package_name],
            store=store,
            workspace_dir=workspace_dir,
            dry_run=False,
            now="2026-05-19T01:00:00Z",
        )
    finally:
        _stop_cloud_eval_server(server, thread)

    assert retry_exit_code == 2
    assert retry_payload["executed"] is False
    assert retry_payload["verdict"]["action"] == "block"
    assert marker_path.exists() is False
    assert not any(
        isinstance(reason, dict) and reason.get("code") == "saved_package_approval"
        for reason in retry_payload["supply_chain_evaluation"]["reasons"]
    )


def test_guard_protect_retry_runs_after_cached_advisory_package_approval(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys,
) -> None:
    home_dir = tmp_path / "guard-home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir(parents=True, exist_ok=True)
    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir(parents=True, exist_ok=True)
    marker_path = tmp_path / "npm-cached-approval-marker.json"
    write_fake_manager_script(fake_bin=fake_bin, manager="npm", marker_path=marker_path, exit_code=0)
    store = GuardStore(home_dir)
    _seed_bundle_cache_only(
        home_dir=home_dir,
        ecosystem="npm",
        package_name="badpkg",
        package_version="1.0.0",
        action="allow",
    )
    store.cache_advisories(
        [
            {
                "id": "adv-cached-block",
                "ecosystem": "npm",
                "package": "badpkg",
                "severity": "high",
                "action": "block",
                "headline": "Locally cached malicious package block.",
            }
        ],
        "2026-05-19T00:00:00Z",
    )
    monkeypatch.setattr(guard_commands_module, "ensure_guard_daemon", lambda _home: "http://127.0.0.1:5474")

    rc = main(
        [
            "guard",
            "protect",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
            "--dry-run",
            "npm",
            "install",
            "badpkg@1.0.0",
        ]
    )
    payload = json.loads(capsys.readouterr().out)

    assert rc == 2
    apply_approval_resolution(
        store=store,
        request_id=str(payload["primary_approval_request_id"]),
        action="allow",
        scope="artifact",
        workspace=None,
        reason="reviewed",
    )

    original_path = os.environ.get("PATH", "")
    monkeypatch.setenv("PATH", os.pathsep.join(filter(None, [str(fake_bin), original_path])))
    retry_payload, retry_exit_code = build_protect_payload(
        command=["npm", "install", "badpkg@1.0.0"],
        store=store,
        workspace_dir=workspace_dir,
        dry_run=False,
        now="2026-05-19T00:00:00Z",
    )

    assert retry_exit_code == 0
    assert retry_payload["executed"] is True
    assert retry_payload["verdict"]["action"] == "allow"
    assert any(
        isinstance(reason, dict) and reason.get("code") == "saved_package_approval"
        for reason in retry_payload["supply_chain_evaluation"]["reasons"]
    )
    assert marker_path.exists()


def test_guard_protect_blocks_npm_ci_before_install_from_lockfile(tmp_path: Path) -> None:
    home_dir = tmp_path / "guard-home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir(parents=True, exist_ok=True)
    _write_npm_ci_workspace(workspace_dir, package_name="minimist", package_version="1.2.8")
    server, thread, sync_url = _start_cloud_eval_server(decision="block", package_name="minimist")
    try:
        _seed_bundle(
            home_dir=home_dir,
            ecosystem="npm",
            package_name="minimist",
            package_version="1.2.8",
            action="block",
        )
        _seed_workspace_sync_credentials(home_dir, sync_url)
        store = GuardStore(home_dir)

        payload, exit_code = build_protect_payload(
            command=["npm", "ci"],
            store=store,
            workspace_dir=workspace_dir,
            dry_run=True,
            now="2026-05-19T00:00:00Z",
            unsafe_raw_output=False,
        )
    finally:
        _stop_cloud_eval_server(server, thread)

    assert exit_code == 2
    assert payload["executed"] is False
    assert payload["supply_chain_evaluation"]["decision"] == "block"
    assert any(package["name"] == "minimist" for package in payload["supply_chain_evaluation"]["packages"])


def test_guard_protect_npm_ci_requires_fresh_approval_after_lockfile_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys,
) -> None:
    home_dir = tmp_path / "guard-home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir(parents=True, exist_ok=True)
    _write_npm_ci_workspace(workspace_dir, package_name="badpkg", package_version="1.0.0")
    store = GuardStore(home_dir)
    server, thread, sync_url = _start_cloud_eval_server(
        decision="block",
        package_name="badpkg",
    )
    monkeypatch.setattr(guard_commands_module, "ensure_guard_daemon", lambda _home: "http://127.0.0.1:5474")
    try:
        _seed_bundle(
            home_dir=home_dir,
            ecosystem="npm",
            package_name="badpkg",
            package_version="1.0.0",
            action="block",
        )
        _seed_workspace_sync_credentials(home_dir, sync_url)

        first_rc = main(
            [
                "guard",
                "protect",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
                "--dry-run",
                "npm",
                "ci",
            ]
        )
        first_payload = json.loads(capsys.readouterr().out)

        assert first_rc == 2
        apply_approval_resolution(
            store=store,
            request_id=str(first_payload["primary_approval_request_id"]),
            action="allow",
            scope="artifact",
            workspace=None,
            reason="reviewed",
        )

        _write_npm_ci_workspace(workspace_dir, package_name="badpkg", package_version="2.0.0")

        second_rc = main(
            [
                "guard",
                "protect",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
                "--dry-run",
                "npm",
                "ci",
            ]
        )
    finally:
        _stop_cloud_eval_server(server, thread)

    second_payload = json.loads(capsys.readouterr().out)
    pending = store.list_approval_requests(status="pending", limit=None)
    resolved = store.list_approval_requests(status="resolved", limit=None)

    assert second_rc == 2
    assert second_payload["verdict"]["action"] == "block"
    assert second_payload["primary_approval_request_id"] != first_payload["primary_approval_request_id"]
    assert second_payload["receipt"]["artifact_hash"] != first_payload["receipt"]["artifact_hash"]
    assert len(pending) == 1
    assert len(resolved) == 1


def test_guard_package_shims_block_npm_ci_before_manager_execution_from_lockfile(tmp_path: Path, capsys) -> None:
    home_dir = tmp_path / "guard-home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir(parents=True, exist_ok=True)
    _write_npm_ci_workspace(workspace_dir, package_name="minimist", package_version="1.2.8")
    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir(parents=True, exist_ok=True)
    marker_path = tmp_path / "npm-ci-marker.json"
    write_fake_manager_script(fake_bin=fake_bin, manager="npm", marker_path=marker_path, exit_code=0)
    server, thread, sync_url = _start_cloud_eval_server(decision="block", package_name="minimist")
    try:
        _seed_bundle(
            home_dir=home_dir,
            ecosystem="npm",
            package_name="minimist",
            package_version="1.2.8",
            action="block",
        )
        _seed_workspace_sync_credentials(home_dir, sync_url)
        shim_path = _install_single_manager_shim(
            home_dir=home_dir,
            workspace_dir=workspace_dir,
            manager="npm",
            capsys=capsys,
        )

        env = dict(os.environ)
        env["PATH"] = os.pathsep.join(filter(None, [str(fake_bin), env.get("PATH")]))
        result = subprocess.run(
            [str(shim_path), "ci"],
            cwd=workspace_dir,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
    finally:
        _stop_cloud_eval_server(server, thread)

    assert result.returncode != 0
    assert marker_path.exists() is False
