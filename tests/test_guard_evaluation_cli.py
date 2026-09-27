from __future__ import annotations

import copy
import json
import os
import platform
import shutil
from hashlib import sha256
from pathlib import Path

import pytest

import codex_plugin_scanner.guard.evaluation_cli_recovery as recovery
from codex_plugin_scanner.guard.evaluation_cli import (
    _CliError,
    _remove_recovery_token,
    _write_recovery_token,
    main,
)
from codex_plugin_scanner.guard.evaluation_contracts import EVALUATION_PROFILE_SCHEMA_VERSION
from codex_plugin_scanner.guard.evaluation_evidence_package import build_evaluation_evidence_package
from codex_plugin_scanner.guard.evaluation_preflight import EvaluationPreflightReport, EvaluationSetup


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
            "requiredPrivilege": ("administrator" if hasattr(os, "geteuid") and os.geteuid() == 0 else "standard_user"),
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


@pytest.mark.skipif(os.name == "nt", reason="CLI recovery storage requires POSIX ownership checks")
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


@pytest.mark.skipif(os.name == "nt", reason="CLI recovery storage requires POSIX ownership checks")
def test_cleanup_accepts_equivalent_owned_root_path(tmp_path: Path, capsys) -> None:
    profile_path, _, _ = _write_profile(tmp_path)
    status = main(
        [
            "preflight",
            str(profile_path),
            "--artifact",
            f"core-fixture={tmp_path / 'core-fixture.bin'}",
            "--allow-host-execution",
            "--setup",
        ]
    )
    setup_payload = _payload(capsys)
    assert status == 0
    owned_root = Path(setup_payload["report"]["scope"]["ownedRoot"])  # type: ignore[index]
    token_path = owned_root.parent / f".hol-guard-evaluation-recovery-{owned_root.name}.token"
    alias = tmp_path / "alias"
    alias.mkdir()
    equivalent_root = alias / ".." / owned_root.name

    cleanup_status = main(["cleanup", str(profile_path), str(equivalent_root)])
    cleanup_payload = _payload(capsys)
    assert cleanup_status == 0
    assert cleanup_payload["status"] == "passed"
    assert not owned_root.exists()
    assert not token_path.exists()


@pytest.mark.skipif(os.name == "nt", reason="CLI recovery storage requires POSIX ownership checks")
def test_cleanup_removes_token_when_owned_root_is_missing(tmp_path: Path, capsys) -> None:
    profile_path, _, _ = _write_profile(tmp_path)
    status = main(
        [
            "preflight",
            str(profile_path),
            "--artifact",
            f"core-fixture={tmp_path / 'core-fixture.bin'}",
            "--allow-host-execution",
            "--setup",
        ]
    )
    setup_payload = _payload(capsys)
    assert status == 0
    owned_root = Path(setup_payload["report"]["scope"]["ownedRoot"])  # type: ignore[index]
    token_path = owned_root.parent / f".hol-guard-evaluation-recovery-{owned_root.name}.token"
    shutil.rmtree(owned_root)

    cleanup_status = main(["cleanup", str(profile_path), str(owned_root)])
    cleanup_payload = _payload(capsys)
    assert cleanup_status == 2
    assert cleanup_payload["status"] == "not_run"
    assert cleanup_payload["cleanup"] == {"removed": False, "reason": "setup_missing"}
    assert not token_path.exists()


@pytest.mark.skipif(os.name == "nt", reason="CLI recovery storage requires POSIX ownership checks")
@pytest.mark.parametrize(
    ("tamper", "expected_code"),
    [
        ("missing", "recovery_token_missing"),
        ("permissive", "recovery_token_invalid"),
        ("symlink", "recovery_token_invalid"),
        ("malformed", "recovery_token_invalid"),
        ("nonascii", "recovery_token_invalid"),
        ("oversized", "recovery_token_invalid"),
    ],
)
def test_cleanup_rejects_tampered_token_without_removing_setup(
    tmp_path: Path, capsys, tamper: str, expected_code: str
) -> None:
    profile_path, _, _ = _write_profile(tmp_path)
    assert (
        main(
            [
                "preflight",
                str(profile_path),
                "--artifact",
                f"core-fixture={tmp_path / 'core-fixture.bin'}",
                "--allow-host-execution",
                "--setup",
            ]
        )
        == 0
    )
    setup_payload = _payload(capsys)
    owned_root = Path(setup_payload["report"]["scope"]["ownedRoot"])  # type: ignore[index]
    token_path = owned_root.parent / f".hol-guard-evaluation-recovery-{owned_root.name}.token"
    if tamper == "missing":
        token_path.unlink()
    elif tamper == "permissive":
        token_path.chmod(0o644)
    elif tamper == "symlink":
        token_path.unlink()
        replacement = tmp_path / "replacement-token"
        replacement.write_bytes(b"a" * 32)
        token_path.symlink_to(replacement)
    else:
        token_path.write_bytes({"malformed": b"invalid", "nonascii": b"\xff", "oversized": b"a" * 129}[tamper])

    assert main(["cleanup", str(profile_path), str(owned_root)]) == 2
    cleanup_payload = _payload(capsys)
    assert cleanup_payload["status"] == "blocked_environment"
    assert cleanup_payload["error"]["code"] == expected_code
    assert owned_root.is_dir()


@pytest.mark.skipif(os.name != "nt", reason="Windows filesystem access semantics")
def test_windows_recovery_token_fails_closed(tmp_path: Path) -> None:
    owned_root = tmp_path / "hol-guard-eval-windows-test"
    owned_root.mkdir()
    setup = EvaluationSetup(
        report=EvaluationPreflightReport(status="passed", phase="setup", profile_id="test", checks=()),
        root_path=owned_root,
        marker_token="a" * 32,
    )
    with pytest.raises(_CliError) as error:
        _write_recovery_token(setup, declared_parent=tmp_path)
    assert error.value.status == "blocked_environment"
    token_path = tmp_path / f".hol-guard-evaluation-recovery-{owned_root.name}.token"
    assert not token_path.exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows filesystem access semantics")
def test_windows_setup_and_cleanup_report_blocked_environment(tmp_path: Path, capsys) -> None:
    profile_path, _, _ = _write_profile(tmp_path)
    assert main(["preflight", str(profile_path), "--setup"]) == 2
    setup_payload = _payload(capsys)
    assert setup_payload["status"] == "blocked_environment"
    assert setup_payload["error"]["code"] == "recovery_windows_unavailable"
    assert not list(tmp_path.glob("hol-guard-eval-*"))

    owned_root = tmp_path / "hol-guard-eval-missing"
    assert main(["cleanup", str(profile_path), str(owned_root)]) == 2
    cleanup_payload = _payload(capsys)
    assert cleanup_payload["status"] == "blocked_environment"
    assert cleanup_payload["error"]["code"] == "recovery_windows_unavailable"


@pytest.mark.skipif(os.name == "nt", reason="CLI recovery storage requires POSIX ownership checks")
def test_recovery_token_write_checks_declared_parent(tmp_path: Path) -> None:
    owned_root = tmp_path / "hol-guard-eval-scope-test"
    owned_root.mkdir()
    setup = EvaluationSetup(
        report=EvaluationPreflightReport(status="passed", phase="setup", profile_id="test", checks=()),
        root_path=owned_root,
        marker_token="a" * 32,
    )
    with pytest.raises(_CliError) as error:
        _write_recovery_token(setup, declared_parent=tmp_path / "other")
    assert error.value.code == "recovery_path_invalid"
    assert not list(tmp_path.glob(".hol-guard-evaluation-recovery-*.token"))


@pytest.mark.skipif(os.name == "nt", reason="CLI recovery storage requires POSIX ownership checks")
def test_recovery_token_write_does_not_replace_an_existing_token(tmp_path: Path) -> None:
    owned_root = tmp_path / "hol-guard-eval-collision-test"
    owned_root.mkdir()
    setup = EvaluationSetup(
        report=EvaluationPreflightReport(status="passed", phase="setup", profile_id="test", checks=()),
        root_path=owned_root,
        marker_token="a" * 32,
    )
    _write_recovery_token(setup, declared_parent=tmp_path)
    token_path = tmp_path / f".hol-guard-evaluation-recovery-{owned_root.name}.token"
    original = token_path.read_bytes()

    with pytest.raises(_CliError) as error:
        _write_recovery_token(setup, declared_parent=tmp_path)
    assert error.value.code == "cleanup_token_unavailable"
    assert token_path.read_bytes() == original

    with pytest.raises(_CliError) as error:
        _remove_recovery_token(token_path, expected_parent=tmp_path / "other")
    assert error.value.code == "recovery_path_invalid"
    assert token_path.read_bytes() == original


@pytest.mark.skipif(os.name == "nt", reason="CLI recovery storage requires POSIX directory descriptors")
def test_recovery_token_removal_rejects_a_replaced_symlink(tmp_path: Path) -> None:
    owned_root = tmp_path / "hol-guard-eval-removal-test"
    owned_root.mkdir()
    setup = EvaluationSetup(
        report=EvaluationPreflightReport(status="passed", phase="setup", profile_id="test", checks=()),
        root_path=owned_root,
        marker_token="a" * 32,
    )
    _write_recovery_token(setup, declared_parent=tmp_path)
    token_path = tmp_path / f".hol-guard-evaluation-recovery-{owned_root.name}.token"
    token_path.unlink()
    target = tmp_path / "unrelated"
    target.write_bytes(b"preserve")
    token_path.symlink_to(target)

    with pytest.raises(_CliError) as error:
        _remove_recovery_token(token_path, expected_parent=tmp_path)
    assert error.value.code == "recovery_token_invalid"
    assert target.read_bytes() == b"preserve"


@pytest.mark.skipif(os.name == "nt", reason="CLI recovery storage requires POSIX ownership checks")
@pytest.mark.parametrize("unsafe_parent", ["permissive", "symlink"])
def test_recovery_token_write_rejects_unsafe_parent(tmp_path: Path, unsafe_parent: str) -> None:
    parent = tmp_path
    if unsafe_parent == "symlink":
        private_parent = tmp_path / "private"
        private_parent.mkdir(mode=0o700)
        parent = tmp_path / "alias"
        parent.symlink_to(private_parent, target_is_directory=True)
    owned_root = parent / "hol-guard-eval-unsafe-parent"
    owned_root.mkdir()
    setup = EvaluationSetup(
        report=EvaluationPreflightReport(status="passed", phase="setup", profile_id="test", checks=()),
        root_path=owned_root,
        marker_token="a" * 32,
    )
    original_mode = tmp_path.stat().st_mode & 0o777
    if unsafe_parent == "permissive":
        tmp_path.chmod(0o755)
    try:
        with pytest.raises(_CliError) as error:
            _write_recovery_token(setup, declared_parent=parent)
    finally:
        tmp_path.chmod(original_mode)
    assert error.value.code == "recovery_path_invalid"
    assert not list(tmp_path.rglob(".hol-guard-evaluation-recovery-*.token"))


@pytest.mark.skipif(os.name == "nt", reason="CLI recovery storage requires POSIX directory descriptors")
def test_recovery_token_write_stays_in_opened_parent_after_path_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    private_parent = tmp_path / "private"
    private_parent.mkdir(mode=0o700)
    owned_root = private_parent / "hol-guard-eval-race-test"
    owned_root.mkdir()
    attacker_parent = tmp_path / "attacker"
    attacker_parent.mkdir(mode=0o700)
    moved_parent = tmp_path / "moved"
    setup = EvaluationSetup(
        report=EvaluationPreflightReport(status="passed", phase="setup", profile_id="test", checks=()),
        root_path=owned_root,
        marker_token="a" * 32,
    )
    open_parent = recovery._open_private_recovery_parent

    def replace_parent_after_open(parent: Path) -> int:
        descriptor = open_parent(parent)
        private_parent.rename(moved_parent)
        private_parent.symlink_to(attacker_parent, target_is_directory=True)
        return descriptor

    monkeypatch.setattr(recovery, "_open_private_recovery_parent", replace_parent_after_open)
    _write_recovery_token(setup, declared_parent=private_parent)

    token_name = f".hol-guard-evaluation-recovery-{owned_root.name}.token"
    assert (moved_parent / token_name).read_bytes() == b"a" * 32
    assert not (attacker_parent / token_name).exists()


@pytest.mark.skipif(os.name == "nt", reason="CLI recovery storage requires POSIX ownership checks")
@pytest.mark.parametrize("relative_path", ["unowned-root", "other/hol-guard-eval-foreign"])
def test_cleanup_rejects_a_root_outside_declared_scope(tmp_path: Path, capsys, relative_path: str) -> None:
    profile_path, _, _ = _write_profile(tmp_path)
    outside_root = tmp_path / relative_path
    outside_root.mkdir(parents=True)

    assert main(["cleanup", str(profile_path), str(outside_root)]) == 2
    payload = _payload(capsys)
    assert payload["status"] == "blocked_environment"
    assert payload["error"]["code"] == "recovery_path_invalid"
    assert outside_root.is_dir()


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


@pytest.mark.parametrize(
    ("arguments", "expected_code"),
    [
        (["verify-evidence"], "evidence_package_argument_required"),
        (["cleanup", "profile.json"], "owned_root_argument_required"),
    ],
)
def test_missing_paths_use_argument_specific_codes(capsys, arguments: list[str], expected_code: str) -> None:
    assert main(arguments) == 2
    payload = _payload(capsys)
    assert payload["status"] == "not_run"
    assert payload["error"]["code"] == expected_code
