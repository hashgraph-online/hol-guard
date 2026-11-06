from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

import codex_plugin_scanner.guard.evaluation_cli_recovery as recovery
from codex_plugin_scanner.guard import evaluation_cli as cli_module
from codex_plugin_scanner.guard import evaluation_cli_run as cli_run_module
from codex_plugin_scanner.guard import evaluation_preflight as preflight_module
from codex_plugin_scanner.guard.evaluation_cli import _CliError, main
from codex_plugin_scanner.guard.evaluation_contracts import EvaluationContractError

from .evaluation_cli_fixtures import _payload, _write_profile


@pytest.mark.skipif(os.name == "nt", reason="CLI recovery storage requires POSIX ownership checks")
@pytest.mark.parametrize("command", ["preflight", "run"])
def test_pre_marker_failure_stays_blocked_without_recovery_authority(
    tmp_path: Path, capsys, monkeypatch: pytest.MonkeyPatch, command: str
) -> None:
    profile_path, _, _ = _write_profile(tmp_path)
    original_chmod = Path.chmod
    allocated_roots: list[Path] = []

    def fail_root_chmod(path: Path, *args, **kwargs) -> None:
        if path.name.startswith("hol-guard-eval-"):
            allocated_roots.append(path)
            raise OSError("synthetic permission failure")
        original_chmod(path, *args, **kwargs)

    argv = [command, "--profile", str(profile_path)]
    if command == "preflight":
        argv.extend(
            ["--artifact", f"core-fixture={tmp_path / 'core-fixture.bin'}", "--allow-host-execution", "--setup"]
        )
    with monkeypatch.context() as patch:
        patch.setattr(preflight_module, "check_host_version", lambda *_args, **_kwargs: (True, "host_version_match"))
        patch.setattr(Path, "chmod", fail_root_chmod)
        assert main(argv) != 0
    payload = _payload(capsys)
    assert payload["status"] == "blocked_environment"
    report = payload["report"] if command == "preflight" else payload["run"]
    assert report["reason"] == "setup_recovery_unavailable"
    assert payload["cleanup"]["removed"] is False
    assert payload["cleanup"]["recoveryTokenRetained"] is False
    assert payload["cleanup"]["reason"] == "setup_recovery_unavailable"
    assert len(allocated_roots) == 1
    assert allocated_roots[0].is_dir()
    assert not (allocated_roots[0] / ".hol-guard-evaluation-owned").exists()
    assert not recovery._recovery_token_path(allocated_roots[0], declared_parent=tmp_path).exists()


@pytest.mark.skipif(os.name == "nt", reason="CLI recovery storage requires POSIX ownership checks")
@pytest.mark.parametrize("command", ["preflight", "run"])
def test_partial_setup_keeps_owned_path_when_token_storage_and_cleanup_fail(
    tmp_path: Path, capsys, monkeypatch: pytest.MonkeyPatch, command: str
) -> None:
    profile_path, _, _ = _write_profile(tmp_path)
    original_mkdir = Path.mkdir
    allocated_roots: list[Path] = []

    def fail_workspace(path: Path, *args, **kwargs) -> None:
        if path.name == "workspace" and path.parent.name.startswith("hol-guard-eval-"):
            allocated_roots.append(path.parent)
            raise OSError("synthetic allocation failure")
        original_mkdir(path, *args, **kwargs)

    def unavailable_cleanup(*args, **kwargs) -> bool:
        raise EvaluationContractError("synthetic cleanup interruption")

    def unavailable_token(*args, **kwargs) -> None:
        raise _CliError("cleanup_token_unavailable", "synthetic storage failure")

    argv = [command, "--profile", str(profile_path)]
    if command == "preflight":
        argv.extend(
            ["--artifact", f"core-fixture={tmp_path / 'core-fixture.bin'}", "--allow-host-execution", "--setup"]
        )
    with monkeypatch.context() as patch:
        patch.setattr(preflight_module, "check_host_version", lambda *_args, **_kwargs: (True, "host_version_match"))
        patch.setattr(Path, "mkdir", fail_workspace)
        patch.setattr(preflight_module._cleanup, "remove_owned_root", unavailable_cleanup)
        patch.setattr(cli_module, "_write_recovery_token", unavailable_token)
        patch.setattr(cli_run_module, "_write_recovery_token", unavailable_token)
        assert main(argv) != 0
    payload = _payload(capsys)
    assert payload["status"] == "blocked_environment"
    assert payload["error"]["code"] == "cleanup_token_unavailable"
    assert payload["cleanup"]["removed"] is False
    assert payload["cleanup"]["recoveryTokenRetained"] is False
    assert payload["cleanup"]["reason"] == "cleanup_incomplete"
    assert payload["cleanup"]["ownedRoot"] == str(allocated_roots[0])
    assert (allocated_roots[0] / ".hol-guard-evaluation-owned").is_file()


@pytest.mark.skipif(os.name == "nt", reason="CLI recovery storage requires POSIX ownership checks")
@pytest.mark.parametrize("command", ["preflight", "run"])
def test_partial_setup_retains_private_token_and_can_be_recovered(
    tmp_path: Path, capsys, monkeypatch: pytest.MonkeyPatch, command: str
) -> None:
    profile_path, _, _ = _write_profile(tmp_path)
    unrelated = tmp_path / "user-config.json"
    unrelated.write_bytes(b"unrelated user bytes")
    original_mkdir = Path.mkdir
    partial_roots: list[Path] = []

    def fail_workspace(path: Path, *args, **kwargs) -> None:
        if path.name == "workspace" and path.parent.name.startswith("hol-guard-eval-"):
            partial_roots.append(path.parent)
            (path.parent / "guard-home" / "partial.bin").write_bytes(b"retained partial setup")
            raise OSError("synthetic allocation failure")
        original_mkdir(path, *args, **kwargs)

    def unavailable_cleanup(*args, **kwargs) -> bool:
        raise EvaluationContractError("synthetic cleanup interruption")

    argv = [command, "--profile", str(profile_path)]
    if command == "preflight":
        argv.extend(
            ["--artifact", f"core-fixture={tmp_path / 'core-fixture.bin'}", "--allow-host-execution", "--setup"]
        )
    with monkeypatch.context() as patch:
        # Version probing has separate contracts; this test faults allocation
        # only after its prerequisites have succeeded.
        patch.setattr(preflight_module, "check_host_version", lambda *_args, **_kwargs: (True, "host_version_match"))
        patch.setattr(Path, "mkdir", fail_workspace)
        patch.setattr(preflight_module._cleanup, "remove_owned_root", unavailable_cleanup)
        status = main(argv)
    payload = _payload(capsys)
    assert status != 0
    assert payload["status"] == "blocked_environment"
    assert len(partial_roots) == 1, payload.get("report", {}).get("reason")
    assert payload["cleanup"]["recoveryTokenRetained"] is True
    owned_root = partial_roots[0]
    token_path = recovery._recovery_token_path(owned_root, declared_parent=tmp_path)
    token = recovery._read_recovery_token(owned_root, declared_parent=tmp_path)
    assert token not in json.dumps(payload)
    assert token_path.stat().st_mode & 0o777 == 0o600
    assert (owned_root / "guard-home" / "partial.bin").read_bytes() == b"retained partial setup"
    assert (owned_root / ".hol-guard-evaluation-owned").read_text() == token
    assert unrelated.read_bytes() == b"unrelated user bytes"

    assert main(["cleanup", "--profile", str(profile_path), "--owned-root", str(owned_root)]) == 0
    recovered = _payload(capsys)
    assert recovered["cleanup"]["removed"] is True
    assert not owned_root.exists()
    assert not token_path.exists()
    assert unrelated.read_bytes() == b"unrelated user bytes"


@pytest.mark.skipif(os.name == "nt", reason="CLI recovery storage requires POSIX ownership checks")
@pytest.mark.parametrize("command", ["preflight", "run"])
def test_partial_setup_token_write_failure_retries_owned_cleanup(
    tmp_path: Path, capsys, monkeypatch: pytest.MonkeyPatch, command: str
) -> None:
    profile_path, _, _ = _write_profile(tmp_path)
    original_mkdir = Path.mkdir
    original_cleanup = preflight_module._cleanup.remove_owned_root
    partial_roots: list[Path] = []
    cleanup_calls = 0
    unrelated = tmp_path / "unrelated-config"
    unrelated.write_bytes(b"preserve")

    def fail_workspace(path: Path, *args, **kwargs) -> None:
        if path.name == "workspace" and path.parent.name.startswith("hol-guard-eval-"):
            partial_roots.append(path.parent)
            raise OSError("synthetic allocation failure")
        original_mkdir(path, *args, **kwargs)

    def interrupted_cleanup(*args, **kwargs) -> bool:
        nonlocal cleanup_calls
        cleanup_calls += 1
        if cleanup_calls == 1:
            raise EvaluationContractError("synthetic cleanup interruption")
        return original_cleanup(*args, **kwargs)

    def unavailable_token(*args, **kwargs) -> None:
        raise _CliError("cleanup_token_unavailable", "synthetic storage failure", status="blocked_environment")

    argv = [command, "--profile", str(profile_path)]
    if command == "preflight":
        argv.extend(
            ["--artifact", f"core-fixture={tmp_path / 'core-fixture.bin'}", "--allow-host-execution", "--setup"]
        )
    with monkeypatch.context() as patch:
        patch.setattr(preflight_module, "check_host_version", lambda *_args, **_kwargs: (True, "host_version_match"))
        patch.setattr(Path, "mkdir", fail_workspace)
        patch.setattr(preflight_module._cleanup, "remove_owned_root", interrupted_cleanup)
        patch.setattr(cli_module, "_write_recovery_token", unavailable_token)
        patch.setattr(cli_run_module, "_write_recovery_token", unavailable_token)
        assert main(argv) != 0
    payload = _payload(capsys)
    assert payload["cleanup"]["removed"] is True
    assert payload["cleanup"]["recoveryTokenRetained"] is False
    assert cleanup_calls == 2
    assert len(partial_roots) == 1
    assert not partial_roots[0].exists()
    assert unrelated.read_bytes() == b"preserve"
