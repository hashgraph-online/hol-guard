"""Platform dispatch and real private-file copies, without claiming macOS execution."""

from __future__ import annotations

import hashlib
import json
import sys
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.codex_hook_file_integrity import CodexHookIntegrityError, validate_regular_file
from scripts import native_qualification_interpreter as provision
from scripts import provision_native_qualification_interpreters as pair


def _entrypoint():
    # Exercise the same behavior before and after the platform-neutral rename.
    return getattr(provision, "provision_venv_interpreter", None) or provision.provision_linux_venv_interpreter


@pytest.mark.skipif(sys.platform != "linux", reason="real owned-file source witness on Linux")
@pytest.mark.parametrize("failure", ["none", "runtime_changed", "validator_failed"])
def test_macos_dispatch_keeps_real_copy_identity_and_rejects_failed_runtime_proof(tmp_path, monkeypatch, failure):
    source = tmp_path / "owned-source-fixture"
    original = b"synthetic executable fixture; no interpreter execution claim"
    source.write_bytes(original)
    source.chmod(0o777)
    invocation = tmp_path / "venv" / "bin" / "python"
    invocation.parent.mkdir(parents=True)
    invocation.symlink_to(source)
    config = invocation.parent.parent / "pyvenv.cfg"
    config.write_bytes(b"home = synthetic\n")
    stamp = provision._stamp(source.stat())
    with pytest.raises(CodexHookIntegrityError, match="writable by another user"):
        validate_regular_file(source, role="interpreter", executable_required=True)
    calls = []

    def probe(python, *, managed):
        assert python == invocation
        calls.append(managed)
        if not managed:
            assert python.is_symlink()
            return {"version": "3.12.10"}
        assert not python.is_symlink() and python.read_bytes() == original
        validate_regular_file(python, role="interpreter", executable_required=True)
        if failure == "validator_failed":
            raise RuntimeError("qualification_interpreter_validator_not_installed")
        return {
            "version": "3.12.11" if failure == "runtime_changed" else "3.12.10",
            "managed_integrity_validated": True,
            "managed_validator_sha256": "a" * 64,
            "managed_validator_inside_venv": True,
        }

    monkeypatch.setattr(provision, "sys", SimpleNamespace(platform="darwin"))
    monkeypatch.setattr(provision, "_probe", probe)
    if failure == "none":
        evidence = _entrypoint()(invocation)
        assert evidence["passed"] is True
    else:
        with pytest.raises(provision.InterpreterProvisioningError) as caught:
            _entrypoint()(invocation)
        evidence = caught.value.evidence
        assert evidence["passed"] is False
        assert evidence["failure"]["code"] == (
            "qualification_interpreter_runtime_changed"
            if failure == "runtime_changed"
            else "qualification_interpreter_validator_not_installed"
        )
    assert calls == [False, True]
    assert evidence["scope"] == "disposable_macos_venv_interpreter_only"
    assert evidence["source_sha256"] == evidence["copied_sha256"] == hashlib.sha256(original).hexdigest()
    assert evidence["identical_bytes"] is evidence["original_target_preserved"] is True
    assert evidence["owned"]["mode"] == 0o755 and evidence["owned"]["owner_current"] is True
    assert provision._stamp(source.stat()) == stamp and source.read_bytes() == original
    assert config.read_bytes() == b"home = synthetic\n"
    assert evidence["shared_interpreter_chmodded"] is evidence["production_integrity_checks_relaxed"] is False
    assert str(tmp_path) not in json.dumps(evidence)


@pytest.mark.parametrize("platform", ["win32", "freebsd14"])
def test_unsupported_platform_cannot_reach_copy_or_probe(tmp_path, monkeypatch, platform):
    monkeypatch.setattr(provision, "sys", SimpleNamespace(platform=platform))
    monkeypatch.setattr(provision, "_probe", lambda *a, **k: pytest.fail("unsupported probe"))
    monkeypatch.setattr(provision, "_copy", lambda *a, **k: pytest.fail("unsupported copy"))
    with pytest.raises(provision.InterpreterProvisioningError) as caught:
        _entrypoint()(tmp_path / "venv/bin/python")
    assert caught.value.evidence["passed"] is False
    assert caught.value.evidence["failure"]["code"] == "qualification_interpreter_platform_unsupported"


@pytest.mark.parametrize("failed_arm", ["none", "baseline", "candidate"])
def test_macos_pair_retains_both_attempts_and_truthful_scope(tmp_path, monkeypatch, failed_arm):
    attempts = []

    def prepare(python):
        attempts.append(python.name)
        value = {
            "scope": "disposable_macos_venv_interpreter_only",
            "passed": python.name != failed_arm,
            "source_sha256": "a" * 64,
        }
        if not value["passed"]:
            raise provision.InterpreterProvisioningError(value)
        return value

    name = (
        "provision_venv_interpreter"
        if hasattr(pair, "provision_venv_interpreter")
        else "provision_linux_venv_interpreter"
    )
    monkeypatch.setattr(pair, name, prepare)
    monkeypatch.setattr(pair, "sys", SimpleNamespace(platform="darwin"))
    result = pair.provision_pair(tmp_path / "baseline", tmp_path / "candidate")
    assert attempts == ["baseline", "candidate"]
    assert result["scope"] == "disposable_macos_venv_interpreters_only"
    assert result["passed"] is (failed_arm == "none")
    assert result["same_original_interpreter_bytes"] is (failed_arm == "none")
    assert result["headline_timing_eligible"] is result["installed_native_qualification_claimed"] is False
