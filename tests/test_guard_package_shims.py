"""Regression coverage for package-manager shim lifecycle commands."""

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
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.protect import build_protect_payload
from codex_plugin_scanner.guard.shims import install_package_shims, package_shim_status
from codex_plugin_scanner.guard.store import GuardStore

WORKSPACE_ID = "workspace-alpha"


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
) -> dict[str, object]:
    generated_at = datetime(2026, 5, 19, tzinfo=timezone.utc)
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
        "bundleVersion": "1747612800000-shim-proof",
        "expiresAt": _iso(expires_at),
        "feedSnapshotHash": "feed-snapshot-shim-proof",
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
        "policyHash": "policy-hash-shim-proof",
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
    store = GuardStore(home_dir)
    now = "2026-05-19T00:00:00Z"
    store.set_sync_credentials("https://hol.org/api/guard/receipts/sync", "demo-token", now, workspace_id=WORKSPACE_ID)
    store.cache_supply_chain_bundle(
        WORKSPACE_ID,
        _bundle_response(
            action=action,
            ecosystem=ecosystem,
            package_name=package_name,
            package_version=package_version,
        ),
        now,
    )


def _install_single_manager_shim(
    *,
    home_dir: Path,
    workspace_dir: Path,
    manager: str,
    capsys,
) -> Path:
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
    _write_fake_manager_script(fake_bin=fake_bin, manager="npm", marker_path=marker_path, exit_code=0)
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
    _write_fake_manager_script(fake_bin=fake_bin, manager="npm", marker_path=marker_path, exit_code=0)
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
    marker_payload = json.loads(marker_path.read_text(encoding="utf-8"))

    assert result.returncode == 0
    assert marker_payload["argv"][1:] == ["install", "minimist@1.2.9"]
    assert marker_payload["cwd"] == str(workspace_dir)


def _write_fake_manager_script(
    *,
    fake_bin: Path,
    manager: str,
    marker_path: Path,
    exit_code: int,
    stdout_text: str | None = None,
    stderr_text: str | None = None,
) -> None:
    script_path = fake_bin / manager
    script_path.write_text(
        "\n".join(
            [
                "#!/usr/bin/env python3",
                "from __future__ import annotations",
                "import json",
                "import os",
                "import sys",
                f"marker_path = {str(marker_path)!r}",
                "payload = {",
                "    'argv': sys.argv,",
                "    'cwd': os.getcwd(),",
                "    'path': os.environ.get('PATH', ''),",
                "    'shim_var': os.environ.get('SHIM_TEST_VAR'),",
                "}",
                "with open(marker_path, 'w', encoding='utf-8') as handle:",
                "    json.dump(payload, handle)",
                f"if {stdout_text!r} is not None:",
                f"    print({stdout_text!r})",
                f"if {stderr_text!r} is not None:",
                f"    print({stderr_text!r}, file=sys.stderr)",
                f"raise SystemExit({exit_code})",
                "",
            ]
        ),
        encoding="utf-8",
    )
    script_path.chmod(script_path.stat().st_mode | 0o755)


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


def test_guard_package_shims_install_does_not_mutate_path_environment(
    tmp_path: Path,
    capsys,
    monkeypatch,
) -> None:
    home_dir = tmp_path / "guard-home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir(parents=True, exist_ok=True)
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
    _write_fake_manager_script(fake_bin=fake_bin, manager=manager, marker_path=marker_path, exit_code=0)
    _seed_bundle(
        home_dir=home_dir,
        ecosystem=ecosystem,
        package_name=package_name,
        package_version=package_version,
        action="block",
    )
    shim_path = _install_single_manager_shim(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        manager=manager,
        capsys=capsys,
    )

    env = dict(os.environ)
    env["PATH"] = os.pathsep.join(filter(None, [str(fake_bin), env.get("PATH")]))
    result = subprocess.run(
        [str(shim_path), *shim_args],
        cwd=workspace_dir,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode != 0
    assert marker_path.exists() is False


def test_guard_package_shim_preserves_argv_cwd_env_exitcode_and_stdio(tmp_path: Path, capsys) -> None:
    home_dir = tmp_path / "guard-home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir(parents=True, exist_ok=True)
    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir(parents=True, exist_ok=True)
    marker_path = tmp_path / "npm-allow-marker.json"
    _write_fake_manager_script(
        fake_bin=fake_bin,
        manager="npm",
        marker_path=marker_path,
        exit_code=7,
        stdout_text="fake-manager-stdout",
        stderr_text="fake-manager-stderr",
    )
    _seed_bundle(home_dir=home_dir, ecosystem="npm", package_name="minimist", package_version="1.2.8", action="allow")
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
    marker_payload = json.loads(marker_path.read_text(encoding="utf-8"))

    assert result.returncode == 7
    assert marker_payload["argv"][1:] == ["ci"]
    assert marker_payload["cwd"] == str(workspace_dir)
    assert marker_payload["shim_var"] == "shim-value"
    assert "fake-manager-stdout" in result.stdout
