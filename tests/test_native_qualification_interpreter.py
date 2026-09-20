"""Qualification-only interpreter repair preserves bytes and real ownership gates."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import sys
import time
import venv
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.codex_hook_file_integrity import CodexHookIntegrityError, validate_regular_file
from scripts import native_qualification_interpreter as provision

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux qualification provisioning only")


def _layout(tmp_path: Path, *, mode: int = 0o777) -> tuple[Path, Path]:
    source = tmp_path / "shared-python"
    source.write_bytes(b"synthetic interpreter bytes: no executable or authority claim")
    source.chmod(mode)
    invocation = tmp_path / "venv" / "bin" / "python"
    invocation.parent.mkdir(parents=True)
    invocation.symlink_to(source)
    return source, invocation


def test_world_writable_original_is_rejected_then_identical_owned_copy_passes_unchanged_validator(
    tmp_path: Path,
) -> None:
    source, invocation = _layout(tmp_path)
    original_bytes, original_stat = source.read_bytes(), provision._stamp(source.stat())
    with pytest.raises(CodexHookIntegrityError) as rejected:
        validate_regular_file(source, role="interpreter", executable_required=True)
    assert rejected.value.reason == "codex_hook_interpreter_permissions_unsafe"
    proof = {}
    provision._copy(source, invocation, evidence=proof)
    validate_regular_file(invocation, role="interpreter", executable_required=True)
    assert source.read_bytes() == invocation.read_bytes() == original_bytes
    assert provision._stamp(source.stat()) == original_stat
    assert proof["source"]["mode"] == 0o777
    assert proof["source"]["world_writable"] is True
    assert proof["source_sha256"] == proof["copied_sha256"] == hashlib.sha256(original_bytes).hexdigest()
    assert proof["original_target_preserved"] is proof["identical_bytes"] is True
    assert proof["owned"]["mode"] == 0o755 and proof["owned"]["owner_current"] is True
    assert not invocation.is_symlink()


@pytest.mark.parametrize("unsafe", ["source_growth", "invocation_replaced", "symlink_target"])
def test_copy_rejects_changed_identity_and_does_not_replace_the_live_invocation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, unsafe: str
) -> None:
    source, invocation = _layout(tmp_path)
    other = tmp_path / "other"
    other.write_bytes(b"different fixture")
    if unsafe == "symlink_target":
        source.unlink()
        source.symlink_to(other)
    else:
        original_fsync = os.fsync

        def change(fd: int) -> None:
            original_fsync(fd)
            if unsafe == "source_growth":
                with source.open("ab") as handle:
                    handle.write(b"grew")
            else:
                invocation.unlink()
                invocation.symlink_to(other)

        monkeypatch.setattr(provision.os, "fsync", change)
    with pytest.raises(RuntimeError, match="qualification_interpreter_source_"):
        provision._copy(source, invocation, evidence={})
    assert invocation.is_symlink()
    assert not list(invocation.parent.glob(".qualification-python-*"))
    if unsafe == "invocation_replaced":
        assert invocation.resolve() == other


@pytest.mark.parametrize("unsafe", ["oversize", "symlink", "writable", "fifo"])
def test_configuration_reader_rejects_unsafe_or_unbounded_files(tmp_path: Path, unsafe: str) -> None:
    configuration = tmp_path / "pyvenv.cfg"
    configuration.write_bytes(b"home = synthetic\n")
    if unsafe == "oversize":
        configuration.write_bytes(b"x" * (provision._MAX_CONFIG_BYTES + 1))
    elif unsafe == "symlink":
        original = tmp_path / "original"
        configuration.rename(original)
        configuration.symlink_to(original)
    elif unsafe == "writable":
        configuration.chmod(0o666)
    else:
        configuration.unlink()
        os.mkfifo(configuration)
    with pytest.raises(RuntimeError, match="qualification_interpreter_venv_config_invalid"):
        provision._configuration(configuration)


def test_configuration_replace_after_lstat_cannot_follow_a_new_symlink(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    configuration = tmp_path / "pyvenv.cfg"
    configuration.write_bytes(b"home = synthetic\n")
    other = tmp_path / "other"
    other.write_bytes(b"private fixture bytes must not be followed")
    original_open = os.open

    def replaced(path: Path, flags: int) -> int:
        configuration.unlink()
        configuration.symlink_to(other)
        return original_open(path, flags)

    monkeypatch.setattr(provision.os, "open", replaced)
    with pytest.raises(OSError):
        provision._configuration(configuration)


@pytest.mark.parametrize("output", ["stdout", "stderr"])
def test_real_probe_output_is_bounded_during_collection(monkeypatch: pytest.MonkeyPatch, output: str) -> None:
    monkeypatch.setattr(provision, "_PROBE", f"import sys; sys.{output}.write('x' * 1000000); sys.{output}.flush()")
    with pytest.raises(RuntimeError, match="qualification_interpreter_probe_output_limit"):
        provision._probe_output(Path(sys.executable), dict(os.environ), managed=False)


def test_real_probe_deadline_does_not_wait_for_eof(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(provision, "_PROBE", "import time; time.sleep(30)")
    monkeypatch.setattr(provision, "_PROBE_SECONDS", 0.1)
    with pytest.raises(RuntimeError, match="qualification_interpreter_probe_deadline"):
        provision._probe_output(Path(sys.executable), dict(os.environ), managed=False)


def test_failed_probe_retires_descendant_pipe_holder_after_leader_exits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    witness = tmp_path / "descendant.json"
    source = f"""
import json, os, subprocess, sys
from pathlib import Path
child = subprocess.Popen([sys.executable, '-I', '-c', 'import time; time.sleep(30)'])
Path({str(witness)!r}).write_text(json.dumps({{"pid": child.pid, "group": os.getpgrp()}}))
os._exit(0)
"""
    monkeypatch.setattr(provision, "_PROBE", source)
    monkeypatch.setattr(provision, "_PROBE_SECONDS", 0.3)
    with pytest.raises(RuntimeError, match="qualification_interpreter_probe_deadline"):
        provision._probe_output(Path(sys.executable), dict(os.environ), managed=False)
    record = json.loads(witness.read_text())
    assert record["pid"] != record["group"]
    state = Path(f"/proc/{record['pid']}/stat")
    deadline = time.monotonic() + 1
    while state.exists():
        try:
            status = state.read_text().split(")", 1)[1].split()[0]
        except FileNotFoundError:
            break
        if status == "Z":
            break  # Retired; its adopting parent owns the zombie reap.
        if time.monotonic() >= deadline:
            pytest.fail("failed probe left a live descendant after its leader exited")
        time.sleep(0.01)


def test_nonzero_probe_leader_is_not_reaped_before_owned_group_retirement(monkeypatch: pytest.MonkeyPatch) -> None:
    original_killpg = os.killpg
    retired = []

    def retire(group: int, signum: int) -> None:
        status = os.waitid(os.P_PID, group, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        assert status is not None and status.si_pid == group and status.si_status == 7
        retired.append(group)
        original_killpg(group, signum)

    monkeypatch.setattr(provision.os, "killpg", retire)
    monkeypatch.setattr(provision, "_PROBE", "import sys; sys.exit(7)")
    with pytest.raises(RuntimeError, match="qualification_interpreter_isolated_probe_failed"):
        provision._probe_output(Path(sys.executable), dict(os.environ), managed=False)
    assert len(retired) == 1
    with pytest.raises(ChildProcessError):
        os.waitpid(retired[0], os.WNOHANG)


@pytest.mark.parametrize("revision", ["current", "2e672d2"])
def test_real_cpython_copy_retains_venv_stdlib_and_exact_baseline_or_candidate_integrity_module(
    tmp_path: Path, revision: str
) -> None:
    # This is a source fixture: only the exact unchanged validator module is
    # installed in a minimal package. It is not installed-native qualification.
    environment = tmp_path / "venv"
    venv.EnvBuilder(with_pip=False, symlinks=True).create(environment)
    python = environment / "bin/python"
    # The workspace toolchain is owned by another uid. Build a disposable,
    # current-user-owned source fixture; never relax the helper's source-owner
    # gate or chmod the shared runtime to make this regression pass.
    fixture_base = tmp_path / "owned-toolcache"
    (fixture_base / "bin").mkdir(parents=True)
    fixture_source = fixture_base / "bin" / "python3.12"
    shutil.copyfile(python.resolve(strict=True), fixture_source)
    fixture_source.chmod(0o755)
    (fixture_base / "lib").symlink_to(Path(sys.base_prefix) / "lib", target_is_directory=True)
    python.unlink()
    python.symlink_to(fixture_source)
    configuration = environment / "pyvenv.cfg"
    configuration.write_text(
        "\n".join(
            "home = " + str(fixture_base / "bin") if line.startswith("home = ") else line
            for line in configuration.read_text().splitlines()
        )
        + "\n"
    )
    source = python.resolve(strict=True)
    original_stat = provision._stamp(source.stat())
    with source.open("rb") as handle:
        original_bytes_digest = hashlib.file_digest(handle, "sha256").hexdigest()
    original_configuration = configuration.read_bytes()
    site_packages = next((environment / "lib").glob("python*/site-packages"))
    package = site_packages / "codex_plugin_scanner"
    guard = package / "guard"
    guard.mkdir(parents=True)
    (package / "__init__.py").write_text("")
    (guard / "__init__.py").write_text("")
    relative = "src/codex_plugin_scanner/guard/codex_hook_file_integrity.py"
    root = Path(__file__).resolve().parents[1]
    validator_bytes = (
        root / relative
        if revision == "current"
        else root / "tests/fixtures/native_qualification/baseline_codex_hook_file_integrity.py.txt"
    ).read_bytes()
    if revision == "2e672d2":
        assert (
            hashlib.sha256(validator_bytes).hexdigest()
            == "ba1375f80db3a8121091e330a8cd1c3c0b36250789267209f8972e23c141ba42"
        )
    (guard / "codex_hook_file_integrity.py").write_bytes(validator_bytes)
    proof = provision.provision_venv_interpreter(python)
    assert proof["passed"] is proof["runtime_compatible"] is proof["managed_integrity_validated"] is True
    assert proof["managed_validator_inside_venv"] is True
    assert proof["managed_validator_sha256"] == hashlib.sha256(validator_bytes).hexdigest()
    assert proof["source_sha256"] == proof["copied_sha256"] == original_bytes_digest
    assert proof["pyvenv_cfg_unchanged"] is proof["base_prefix_unchanged"] is True
    assert provision._stamp(source.stat()) == original_stat
    assert configuration.read_bytes() == original_configuration
    assert stat.S_IMODE(python.stat().st_mode) == 0o755
    assert proof["runtime"]["sqlite_version"] and proof["runtime"]["openssl_version"]
    assert str(tmp_path) not in json.dumps(proof)


def test_failed_runtime_probe_retains_original_mode_digest_and_cannot_claim_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, invocation = _layout(tmp_path)
    (invocation.parent.parent / "pyvenv.cfg").write_bytes(b"home = synthetic\n")

    def probe(_python: Path, *, managed: bool) -> dict[str, object]:
        if managed:
            raise OSError("private path and diagnostic material")
        return {"version": "3.12.14"}

    monkeypatch.setattr(provision, "_probe", probe)
    with pytest.raises(provision.InterpreterProvisioningError) as caught:
        provision.provision_venv_interpreter(invocation)
    proof = caught.value.evidence
    assert proof["passed"] is False
    assert proof["source"]["mode"] == 0o777
    assert proof["source_sha256"] == proof["copied_sha256"] == hashlib.sha256(source.read_bytes()).hexdigest()
    assert proof["failure"]["code"] == "unclassified_failure"
    assert "private path" not in json.dumps(proof)


@pytest.mark.parametrize("failure", ["baseline_failed", "different_bytes", "none"])
def test_pair_driver_retains_both_attempts_and_fails_incompatible_or_incomplete_setup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], failure: str
) -> None:
    from scripts import provision_native_qualification_interpreters as driver

    attempted = []

    def prepare(python: Path) -> dict[str, object]:
        attempted.append(python.name)
        if python.name == "baseline" and failure == "baseline_failed":
            raise provision.InterpreterProvisioningError({"passed": False, "failure": {"code": "bounded_failure"}})
        return {"passed": True, "source_sha256": (python.name if failure == "different_bytes" else "a") * 64}

    destination = tmp_path / "aggregate/provision.json"
    monkeypatch.setattr(driver, "provision_venv_interpreter", prepare)
    monkeypatch.setattr(
        driver.sys,
        "argv",
        ["provision", "--baseline-python", "baseline", "--candidate-python", "candidate", "--json", str(destination)],
    )
    assert driver.main() == (0 if failure == "none" else 1)
    result = json.loads(destination.read_text())
    assert json.loads(capsys.readouterr().out) == result
    assert attempted == ["baseline", "candidate"]
    assert result["attempted"] == 2
    assert result["passed"] is (failure == "none")
    assert result["same_original_interpreter_bytes"] is (failure == "none")
    assert result["installed_native_qualification_claimed"] is False
    if failure == "baseline_failed":
        assert result["arms"]["baseline"]["failure"]["code"] == "bounded_failure"
        assert result["arms"]["candidate"]["passed"] is True
