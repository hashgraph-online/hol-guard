from __future__ import annotations

import os
import platform
import stat
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace
from urllib.request import Request, urlopen

import pytest

from codex_plugin_scanner.guard import evaluation_preflight as preflight_module
from codex_plugin_scanner.guard.evaluation_contracts import EvaluationResult
from codex_plugin_scanner.guard.evaluation_preflight import (
    EvaluationSetup,
    cleanup_interrupted_evaluation_setup,
    preflight_evaluation,
    setup_evaluation,
)
from codex_plugin_scanner.guard.evaluation_witness import LocalSideEffectWitness


def _host_os() -> str:
    value = platform.system().lower()
    return "macos" if value == "darwin" else value


def _host_architecture() -> str:
    value = platform.machine().lower().replace("-", "_")
    return {"amd64": "x86_64", "aarch64": "arm64"}.get(value, value)


def _fake_host(tmp_path: Path, *, version: str = "0.1.0") -> Path:
    executable = tmp_path / "synthetic-agent"
    executable.write_text(
        "#!/bin/sh\n"
        'if [ "$1" = "--version" ]; then\n'
        f"  printf '%s\\n' 'synthetic-agent {version}'\n"
        "  exit 0\n"
        "fi\n"
        "exit 64\n",
        encoding="utf-8",
    )
    executable.chmod(0o755)
    return executable


def _profile(tmp_path: Path, executable: Path | None = None) -> dict[str, object]:
    root = tmp_path
    endpoint = "http://127.0.0.1:8765/receiver"
    artifact_digest = "sha256:" + sha256(b"synthetic artifact").hexdigest()
    host_identity: dict[str, object] = {
        "product": "synthetic-agent",
        "version": "0.1.0",
        "os": _host_os(),
        "architecture": _host_architecture(),
        "runtimeLocation": "local",
        "requiredPrivilege": "administrator" if hasattr(os, "geteuid") and os.geteuid() == 0 else "standard_user",
    }
    if executable is not None:
        host_identity["executable"] = str(executable)
    return {
        "schemaVersion": "guard.evaluation-profile.v1",
        "profileId": "synthetic-local-v1",
        "buildIdentity": {
            "product": "hol-guard-core",
            "version": "3.4.2",
            "commit": "a" * 40,
            "artifactDigest": artifact_digest,
        },
        "hostIdentity": host_identity,
        "installedArtifacts": [
            {
                "artifactId": "core-fixture",
                "kind": "core",
                "version": "3.4.2",
                "digest": artifact_digest,
            }
        ],
        "policyIdentity": {
            "policyId": "synthetic-policy-v1",
            "version": "1",
            "digest": "sha256:" + "c" * 64,
        },
        "network": {
            "mode": "local_only",
            "allowedEndpoints": [endpoint],
            "proxyUrl": None,
        },
        "fixture": {
            "fixtureId": "synthetic-fixture-v1",
            "version": "1",
            "digest": "sha256:" + "d" * 64,
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
            {"capabilityId": "synthetic.shell", "expectedAction": "block"},
            {"capabilityId": "synthetic.read", "expectedAction": "allow"},
        ],
    }


def _artifact(tmp_path: Path) -> Path:
    path = tmp_path / "core-fixture.bin"
    path.write_bytes(b"synthetic artifact")
    return path


def _artifact_paths(path: Path) -> dict[str, Path]:
    return {"core-fixture": path}


def test_preflight_validates_host_and_artifact_without_running_scenarios(tmp_path: Path) -> None:
    executable = _fake_host(tmp_path)
    artifact = _artifact(tmp_path)
    report = preflight_evaluation(
        _profile(tmp_path, executable),
        artifact_paths=_artifact_paths(artifact),
        allow_host_execution=True,
    )

    assert report.status == "passed"
    assert report.phase == "preflight"
    assert report.owned_root is None
    assert report.to_dict()["status"] == "passed"
    assert all(check["status"] == "passed" for check in report.checks)
    assert any(check["name"] == "network_scope_declaration" for check in report.checks)
    assert any(check["name"] == "privilege" for check in report.checks)


def test_preflight_rejects_unavailable_required_privilege(tmp_path: Path) -> None:
    executable = _fake_host(tmp_path)
    artifact = _artifact(tmp_path)
    profile = _profile(tmp_path, executable)
    host = profile["hostIdentity"]
    assert isinstance(host, dict)
    host["requiredPrivilege"] = "standard_user" if host["requiredPrivilege"] == "administrator" else "administrator"
    report = preflight_evaluation(profile, artifact_paths=_artifact_paths(artifact))
    assert report.status == "blocked_environment"
    assert report.reason == "privilege_mismatch"


@pytest.mark.parametrize(("elevated", "expected"), [(False, "standard_user"), (True, "administrator")])
def test_windows_privilege_detection(monkeypatch: pytest.MonkeyPatch, elevated: bool, expected: str) -> None:
    import ctypes

    monkeypatch.setattr(preflight_module, "os", SimpleNamespace(name="nt"))
    shell = SimpleNamespace(IsUserAnAdmin=lambda: int(elevated))
    monkeypatch.setattr(ctypes, "windll", SimpleNamespace(shell32=shell), raising=False)
    assert preflight_module._observed_privilege() == expected


def test_unobservable_privilege_is_not_reported_as_a_mismatch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    executable = _fake_host(tmp_path)
    artifact = _artifact(tmp_path)
    monkeypatch.setattr(preflight_module, "_observed_privilege", lambda: "unknown")
    report = preflight_evaluation(_profile(tmp_path, executable), artifact_paths=_artifact_paths(artifact))
    assert report.status == "not_run"
    assert report.reason == "privilege_unobservable"


def test_host_binary_is_not_executed_by_default(tmp_path: Path) -> None:
    executable = _fake_host(tmp_path)
    marker = tmp_path / "host-ran"
    executable.write_text(f"#!/bin/sh\ntouch '{marker}'\n", encoding="utf-8")
    artifact = _artifact(tmp_path)
    report = preflight_evaluation(_profile(tmp_path, executable), artifact_paths=_artifact_paths(artifact))
    assert report.status == "not_run"
    assert report.reason == "isolated_host_execution_not_enabled"
    assert not marker.exists()


def test_missing_host_is_blocked_without_reading_or_creating_setup(tmp_path: Path) -> None:
    artifact = _artifact(tmp_path)
    profile = _profile(tmp_path, tmp_path / "does-not-exist")
    report = preflight_evaluation(profile, artifact_paths=_artifact_paths(artifact), allow_host_execution=True)

    assert report.status == "blocked_environment"
    assert report.reason == "host_executable_missing"
    assert report.to_dict()["status"] == "blocked_environment"
    assert report.owned_root is None


def test_undeclared_host_returns_not_run(tmp_path: Path) -> None:
    artifact = _artifact(tmp_path)
    profile = _profile(tmp_path)
    report = preflight_evaluation(profile, artifact_paths=_artifact_paths(artifact))

    assert report.status == "not_run"
    assert report.reason == "host_executable_not_declared"


def test_mismatched_os_is_blocked_before_host_execution(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    executable = _fake_host(tmp_path)
    artifact = _artifact(tmp_path)
    profile = _profile(tmp_path, executable)
    expected_os = str(profile["hostIdentity"]["os"])  # type: ignore[index]
    mismatch = "windows" if expected_os != "windows" else "linux"
    monkeypatch.setattr("codex_plugin_scanner.guard.evaluation_preflight.platform.system", lambda: mismatch)

    report = preflight_evaluation(profile, artifact_paths=_artifact_paths(artifact))

    assert report.status == "blocked_environment"
    assert report.reason == "os_mismatch"
    assert any(check.get("name") == "os" and check.get("status") == "blocked_environment" for check in report.checks)


def test_mismatched_host_version_is_blocked(tmp_path: Path) -> None:
    executable = _fake_host(tmp_path)
    artifact = _artifact(tmp_path)
    profile = _profile(tmp_path, executable)
    profile["hostIdentity"]["version"] = "9.9.9"  # type: ignore[index]

    report = preflight_evaluation(profile, artifact_paths=_artifact_paths(artifact), allow_host_execution=True)

    assert report.status == "blocked_environment"
    assert report.reason == "host_version_mismatch"


@pytest.mark.parametrize("printed,expected", [("v0.1.0", "0.1.0"), ("0.1.0", "v0.1.0")])
def test_common_v_prefixed_host_versions_match(tmp_path: Path, printed: str, expected: str) -> None:
    executable = _fake_host(tmp_path, version=printed)
    artifact = _artifact(tmp_path)
    profile = _profile(tmp_path, executable)
    profile["hostIdentity"]["version"] = expected  # type: ignore[index]
    report = preflight_evaluation(profile, artifact_paths=_artifact_paths(artifact), allow_host_execution=True)
    assert report.status == "passed"


def test_missing_artifact_is_blocked_after_host_checks(tmp_path: Path) -> None:
    executable = _fake_host(tmp_path)
    report = preflight_evaluation(_profile(tmp_path, executable), artifact_paths={}, allow_host_execution=True)

    assert report.status == "blocked_environment"
    assert report.reason == "artifact_missing"
    assert any(check.get("name") == "artifact:core-fixture" for check in report.checks)


def test_missing_artifact_mapping_is_not_run(tmp_path: Path) -> None:
    executable = _fake_host(tmp_path)
    report = preflight_evaluation(_profile(tmp_path, executable), allow_host_execution=True)

    assert report.status == "not_run"
    assert report.reason == "artifact_paths_not_supplied"


def test_wrong_artifact_bytes_block_setup(tmp_path: Path) -> None:
    executable = _fake_host(tmp_path)
    artifact = _artifact(tmp_path)
    artifact.write_bytes(b"different artifact")
    report = preflight_evaluation(
        _profile(tmp_path, executable), artifact_paths=_artifact_paths(artifact), allow_host_execution=True
    )
    assert report.status == "blocked_environment"
    assert report.reason == "artifact_digest_mismatch"


def test_setup_is_private_and_cleanup_preserves_unrelated_files(tmp_path: Path) -> None:
    executable = _fake_host(tmp_path)
    artifact = _artifact(tmp_path)
    unrelated = tmp_path / "unrelated.txt"
    unrelated.write_bytes(b"keep this file")
    profile = _profile(tmp_path, executable)

    setup = setup_evaluation(
        profile,
        artifact_paths=_artifact_paths(artifact),
        parent_dir=tmp_path,
        allow_host_execution=True,
    )

    assert isinstance(setup, EvaluationSetup)
    assert setup.report.status == "passed"
    assert setup.root_path is not None
    assert setup.root_path.is_relative_to(tmp_path)
    assert setup.guard_home is not None and setup.guard_home.is_dir()
    assert setup.workspace is not None and setup.workspace.is_dir()
    assert stat.S_IMODE(setup.root_path.stat().st_mode) == 0o700
    assert stat.S_IMODE(setup.guard_home.stat().st_mode) == 0o700
    assert stat.S_IMODE(setup.workspace.stat().st_mode) == 0o700
    owned_root = setup.root_path
    assert owned_root.name.startswith("hol-guard-eval-")
    assert unrelated.read_bytes() == b"keep this file"

    assert setup.cleanup() is True
    assert not owned_root.exists()
    assert unrelated.read_bytes() == b"keep this file"


def test_cleanup_rejects_a_tampered_ownership_marker(tmp_path: Path) -> None:
    executable = _fake_host(tmp_path)
    artifact = _artifact(tmp_path)
    setup = setup_evaluation(
        _profile(tmp_path, executable),
        artifact_paths=_artifact_paths(artifact),
        parent_dir=tmp_path,
        allow_host_execution=True,
    )
    assert setup.root_path is not None
    marker = setup.root_path / ".hol-guard-evaluation-owned"
    marker.write_text("foreign", encoding="utf-8")

    with pytest.raises(ValueError, match="ownership marker"):
        setup.cleanup()
    assert setup.root_path.exists()
    setup.root_path.joinpath(".hol-guard-evaluation-owned").write_text(  # type: ignore[union-attr]
        setup.marker_token or "", encoding="utf-8"
    )
    assert setup.cleanup() is True


def test_interrupted_cleanup_requires_retained_token_and_preserves_unrelated_files(tmp_path: Path) -> None:
    executable = _fake_host(tmp_path)
    artifact = _artifact(tmp_path)
    profile = _profile(tmp_path, executable)
    unrelated = tmp_path / "user-config.json"
    unrelated.write_bytes(b'{"keep":"unchanged"}\n')
    setup = setup_evaluation(
        profile,
        artifact_paths=_artifact_paths(artifact),
        parent_dir=tmp_path,
        allow_host_execution=True,
    )
    assert setup.root_path is not None and setup.marker_token is not None
    owned_root, token = setup.root_path, setup.marker_token
    del setup  # Model process loss: only the separately retained handle survives.

    wrong_token = ("0" if token[0] != "0" else "1") + token[1:]
    with pytest.raises(ValueError, match="ownership marker"):
        cleanup_interrupted_evaluation_setup(profile, owned_root=owned_root, marker_token=wrong_token)
    assert owned_root.is_dir()
    assert unrelated.read_bytes() == b'{"keep":"unchanged"}\n'

    assert cleanup_interrupted_evaluation_setup(profile, owned_root=owned_root, marker_token=token) is True
    assert not owned_root.exists()
    assert unrelated.read_bytes() == b'{"keep":"unchanged"}\n'
    assert cleanup_interrupted_evaluation_setup(profile, owned_root=owned_root, marker_token=token) is False


def test_interrupted_cleanup_rejects_another_profile_parent(tmp_path: Path) -> None:
    executable = _fake_host(tmp_path)
    artifact = _artifact(tmp_path)
    profile = _profile(tmp_path, executable)
    setup = setup_evaluation(
        profile,
        artifact_paths=_artifact_paths(artifact),
        parent_dir=tmp_path,
        allow_host_execution=True,
    )
    assert setup.root_path is not None and setup.marker_token is not None
    other_parent = tmp_path / "other-private-parent"
    other_parent.mkdir(mode=0o700)
    other_profile = _profile(tmp_path, executable)
    scope = other_profile["targetScope"]
    assert isinstance(scope, dict)
    scope["rootPath"] = str(other_parent)
    scope["allowedPaths"] = [str(other_parent)]

    with pytest.raises(ValueError, match="outside the profile target scope"):
        cleanup_interrupted_evaluation_setup(other_profile, owned_root=setup.root_path, marker_token=setup.marker_token)
    assert setup.root_path.exists()
    assert setup.cleanup() is True


def test_interrupted_cleanup_rejects_a_symlink_to_unrelated_state(tmp_path: Path) -> None:
    if os.name == "nt":
        pytest.skip("symlink creation may require elevated Windows privileges")
    unrelated = tmp_path / "unrelated-state"
    unrelated.mkdir()
    marker = unrelated / "user-config.json"
    marker.write_bytes(b"preserve")
    link = tmp_path / "hol-guard-eval-link"
    link.symlink_to(unrelated, target_is_directory=True)

    with pytest.raises(ValueError, match="must not be a symlink"):
        cleanup_interrupted_evaluation_setup(_profile(tmp_path), owned_root=link, marker_token="0" * 32)
    assert marker.read_bytes() == b"preserve"


def test_setup_rejects_non_temporary_parent_without_touching_it(tmp_path: Path) -> None:
    executable = _fake_host(tmp_path)
    artifact = _artifact(tmp_path)
    unrelated = tmp_path / "unrelated.txt"
    unrelated.write_text("preserve", encoding="utf-8")
    profile = _profile(tmp_path, executable)
    unsafe_parent = Path(os.environ.get("HOME", "/"))

    setup = setup_evaluation(
        profile,
        artifact_paths=_artifact_paths(artifact),
        parent_dir=unsafe_parent,
        allow_host_execution=True,
    )

    assert setup.report.status == "blocked_environment"
    assert setup.report.reason == "setup_parent_outside_profile_scope"
    assert unrelated.read_text(encoding="utf-8") == "preserve"


def test_setup_rejects_publicly_writable_temporary_parent(tmp_path: Path) -> None:
    if os.name == "nt":
        pytest.skip("POSIX mode check")
    executable = _fake_host(tmp_path)
    artifact = _artifact(tmp_path)
    parent = tmp_path / "public-parent"
    parent.mkdir()
    parent.chmod(0o777)
    profile = _profile(tmp_path, executable)
    scope = profile["targetScope"]
    assert isinstance(scope, dict)
    scope["rootPath"] = str(parent)
    scope["allowedPaths"] = [str(parent / "workspace")]

    setup = setup_evaluation(
        profile,
        artifact_paths=_artifact_paths(artifact),
        parent_dir=parent,
        allow_host_execution=True,
    )
    assert setup.report.status == "blocked_environment"
    assert setup.report.reason == "setup_parent_outside_profile_scope"
    assert list(parent.iterdir()) == []


def test_witness_uses_owned_setup_workspace_and_rejects_tampered_owner(tmp_path: Path) -> None:
    executable = _fake_host(tmp_path)
    artifact = _artifact(tmp_path)
    setup = setup_evaluation(
        _profile(tmp_path, executable),
        artifact_paths=_artifact_paths(artifact),
        parent_dir=tmp_path,
        allow_host_execution=True,
    )
    assert setup.workspace is not None and setup.root_path is not None and setup.marker_token is not None
    with LocalSideEffectWitness(setup=setup) as witness:
        assert witness.root.parent == setup.workspace
        assert witness.check_file_ready()
    marker = setup.root_path / ".hol-guard-evaluation-owned"
    marker.write_text("tampered", encoding="utf-8")
    with pytest.raises(ValueError, match="owned evaluation setup"), LocalSideEffectWitness(setup=setup):
        pass
    marker.write_text(setup.marker_token, encoding="utf-8")
    assert setup.cleanup() is True


def test_predeclared_network_pair_can_bind_a_profile_and_setup(tmp_path: Path) -> None:
    executable = _fake_host(tmp_path)
    artifact_path = _artifact(tmp_path)
    with LocalSideEffectWitness() as witness:
        pair = witness.new_network_pair()
        profile = _profile(tmp_path, executable)
        profile["expectedCapabilities"] = [{"capabilityId": "synthetic.network", "expectedAction": "block"}]
        profile["network"]["allowedEndpoints"] = [pair.denied_url, pair.allowed_url]  # type: ignore[index]
        profile["targetScope"]["allowedEndpoints"] = [pair.denied_url, pair.allowed_url]  # type: ignore[index]
        setup = setup_evaluation(
            profile,
            artifact_paths=_artifact_paths(artifact_path),
            parent_dir=tmp_path,
            allow_host_execution=True,
        )
        assert setup.report.status == "passed"
        try:
            assert witness.check_network_ready()
            with urlopen(Request(pair.allowed_url, data=b"", method="POST"), timeout=2) as response:
                assert response.status == 204
            observation = witness.observe_network_pair(pair)
            assert observation.receiver_conditions_met
            artifact = profile["installedArtifacts"][0]  # type: ignore[index]
            result = {
                "schemaVersion": "guard.evaluation-result.v1",
                "resultId": "network-result",
                "profileId": profile["profileId"],
                "buildIdentity": profile["buildIdentity"],
                "artifactIdentity": artifact,
                "evidenceIdentity": {
                    "evidenceId": "network-evidence",
                    "proofRunId": "network-run",
                    "evidenceType": "live_installed_host_test",
                    "artifactDigest": artifact["digest"],
                },
                "status": "passed",
                "startedAt": "2026-09-23T12:00:00Z",
                "finishedAt": "2026-09-23T12:00:01Z",
                "cases": [
                    {
                        "caseId": "synthetic.network",
                        "status": "passed",
                        "expectedAction": "block",
                        "observedAction": "block",
                        "proofType": "live_installed_host_test",
                        "witness": {
                            "kind": "loopback_receiver",
                            "endpoint": pair.denied_url,
                            "allowedEndpoint": pair.allowed_url,
                            "receiverReady": observation.receiver_ready,
                            "deniedReached": observation.denied_reached,
                            "allowedReached": observation.allowed_reached,
                        },
                    }
                ],
            }
            assert EvaluationResult.from_dict(result, profile=profile).to_dict() == result
        finally:
            assert setup.cleanup() is True
