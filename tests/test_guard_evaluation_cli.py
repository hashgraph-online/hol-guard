from __future__ import annotations

import copy
import json
import os
import platform
from hashlib import sha256
from pathlib import Path

from codex_plugin_scanner.guard.evaluation_cli import main
from codex_plugin_scanner.guard.evaluation_contracts import EVALUATION_PROFILE_SCHEMA_VERSION
from codex_plugin_scanner.guard.evaluation_evidence_package import build_evaluation_evidence_package


def _host_os() -> str:
    value = platform.system().lower()
    return "macos" if value == "darwin" else value


def _host_architecture() -> str:
    value = platform.machine().lower().replace("-", "_")
    return {"amd64": "x86_64", "aarch64": "arm64"}.get(value, value)


def _profile(tmp_path: Path, executable: Path) -> dict[str, object]:
    root = tmp_path
    artifact_digest = "sha256:" + sha256(b"synthetic artifact").hexdigest()
    endpoint = "http://127.0.0.1:8765/receiver"
    return {
        "schemaVersion": EVALUATION_PROFILE_SCHEMA_VERSION,
        "profileId": "synthetic-cli-v1",
        "buildIdentity": {
            "product": "hol-guard-core",
            "version": "3.5.0",
            "commit": "a" * 40,
            "artifactDigest": artifact_digest,
        },
        "hostIdentity": {
            "product": "synthetic-agent",
            "version": "0.1.0",
            "os": _host_os(),
            "architecture": _host_architecture(),
            "runtimeLocation": "local",
            "requiredPrivilege": (
                "administrator" if hasattr(os, "geteuid") and os.geteuid() == 0 else "standard_user"
            ),
            "executable": str(executable),
        },
        "installedArtifacts": [
            {
                "artifactId": "core-fixture",
                "kind": "core",
                "version": "3.5.0",
                "digest": artifact_digest,
            }
        ],
        "policyIdentity": {
            "policyId": "synthetic-policy-v1",
            "version": "1",
            "digest": "sha256:" + "b" * 64,
        },
        "network": {
            "mode": "local_only",
            "allowedEndpoints": [endpoint],
            "proxyUrl": None,
        },
        "fixture": {
            "fixtureId": "synthetic-fixture-v1",
            "version": "1",
            "digest": "sha256:" + "c" * 64,
        },
        "targetScope": {
            "rootPath": str(root),
            "allowedPaths": [str(root)],
            "allowedEndpoints": [endpoint],
        },
        "resourceLimits": {
            "maxDurationSeconds": 60,
            "maxOutputBytes": 1024 * 1024,
            "maxMemoryBytes": 128 * 1024 * 1024,
            "maxConcurrency": 2,
        },
        "expectedCapabilities": [
            {"capabilityId": "synthetic.read", "expectedAction": "allow"},
        ],
    }


def _write_profile(tmp_path: Path) -> tuple[Path, Path, dict[str, object]]:
    executable = tmp_path / "synthetic-agent"
    marker = tmp_path / "host-ran"
    executable.write_text(
        "#!/bin/sh\n"
        f"if [ \"$1\" = \"--version\" ]; then touch '{marker}'; printf '%s\\n' 'synthetic-agent 0.1.0'; exit 0; fi\n"
        "exit 64\n",
        encoding="utf-8",
    )
    executable.chmod(0o755)
    artifact = tmp_path / "core-fixture.bin"
    artifact.write_bytes(b"synthetic artifact")
    profile = _profile(tmp_path, executable)
    profile_path = tmp_path / "profile.json"
    profile_path.write_text(json.dumps(profile), encoding="utf-8")
    return profile_path, marker, profile


def _payload(capsys) -> dict[str, object]:
    return json.loads(capsys.readouterr().out)


def test_preflight_is_json_and_does_not_run_host_by_default(tmp_path: Path, capsys) -> None:
    profile_path, marker, _ = _write_profile(tmp_path)

    status = main(
        [
            "preflight",
            "--profile",
            str(profile_path),
            "--artifact",
            f"core-fixture={tmp_path / 'core-fixture.bin'}",
        ]
    )

    payload = _payload(capsys)
    assert status == 2
    assert payload["command"] == "preflight"
    assert payload["status"] == "not_run"
    assert payload["report"]["reason"] == "isolated_host_execution_not_enabled"  # type: ignore[index]
    assert not marker.exists()


def test_setup_and_cleanup_keep_marker_token_out_of_json(tmp_path: Path, capsys) -> None:
    profile_path, _, _ = _write_profile(tmp_path)
    artifact = tmp_path / "core-fixture.bin"
    status = main(
        [
            "preflight",
            str(profile_path),
            "--artifact",
            f"core-fixture={artifact}",
            "--allow-host-execution",
            "--setup",
        ]
    )
    setup_payload = _payload(capsys)
    assert status == 0
    assert setup_payload["status"] == "passed"
    assert "markerToken" not in json.dumps(setup_payload)
    report = setup_payload["report"]
    owned_root = Path(report["scope"]["ownedRoot"])  # type: ignore[index]
    token_path = owned_root.parent / f".hol-guard-evaluation-recovery-{owned_root.name}.token"
    assert token_path.is_file()
    assert not (owned_root / token_path.name).exists()

    cleanup_status = main(
        [
            "cleanup",
            "--profile",
            str(profile_path),
            "--owned-root",
            str(owned_root),
        ]
    )
    cleanup_payload = _payload(capsys)
    assert cleanup_status == 0
    assert cleanup_payload == {
        "cleanup": {"removed": True},
        "command": "cleanup",
        "schemaVersion": "guard.evaluation-cli.v1",
        "status": "passed",
    }
    assert not owned_root.exists()
    assert not token_path.exists()


def test_verify_evidence_reports_canonical_manifest(tmp_path: Path, capsys) -> None:
    profile_path, _, profile = _write_profile(tmp_path)
    artifact = profile["installedArtifacts"][0]  # type: ignore[index]
    result = {
        "schemaVersion": "guard.evaluation-result.v1",
        "resultId": "result-1",
        "profileId": profile["profileId"],
        "buildIdentity": copy.deepcopy(profile["buildIdentity"]),
        "artifactIdentity": copy.deepcopy(artifact),
        "evidenceIdentity": {
            "evidenceId": "evidence-1",
            "proofRunId": "run-1",
            "evidenceType": "unit_test",
            "artifactDigest": artifact["digest"],  # type: ignore[index]
        },
        "status": "passed",
        "startedAt": "2026-09-23T12:00:00Z",
        "finishedAt": "2026-09-23T12:00:01Z",
        "cases": [
            {
                "caseId": "synthetic.read",
                "status": "passed",
                "expectedAction": "allow",
                "observedAction": "allow",
                "proofType": "unit_test",
                "witness": {"kind": "none"},
            }
        ],
        "summary": {"passed": 1, "failed": 0, "unsupported": 0, "blockedEnvironment": 0, "notRun": 0},
    }
    package_path = tmp_path / "evidence.zip"
    package_path.write_bytes(build_evaluation_evidence_package(profile, result))

    status = main(["verify-evidence", str(package_path)])

    payload = _payload(capsys)
    assert status == 0
    assert payload["status"] == "passed"
    assert payload["manifest"]["proofBoundary"] == "caller_supplied_unverified"  # type: ignore[index]
    assert payload["manifest"]["profileId"] == profile["profileId"]  # type: ignore[index]
    assert profile_path.is_file()


def test_invalid_profile_error_does_not_echo_input_value(tmp_path: Path, capsys) -> None:
    secret_marker = "private-evaluation-marker"
    profile_path = tmp_path / "invalid-profile.json"
    profile_path.write_text(json.dumps({"status": secret_marker}), encoding="utf-8")

    status = main(["preflight", str(profile_path)])

    payload = _payload(capsys)
    assert status == 2
    assert payload["error"] == {"code": "profile_invalid", "message": "evaluation profile is invalid"}
    assert secret_marker not in json.dumps(payload)


def test_argument_errors_are_machine_readable(capsys) -> None:
    status = main([])

    payload = _payload(capsys)
    assert status == 2
    assert payload == {
        "command": "cli",
        "error": {"code": "usage_error", "message": "invalid evaluation command arguments"},
        "schemaVersion": "guard.evaluation-cli.v1",
        "status": "not_run",
    }
