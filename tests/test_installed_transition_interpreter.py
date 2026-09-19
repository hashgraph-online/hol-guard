"""The transition's own interpreter is provisioned only after its pinned wheel."""

from __future__ import annotations

import hashlib
import json

import pytest

from scripts.ci import verify_installed_artifact_transitions as driver
from scripts.native_slo_contract import assert_privacy_safe
from tests.test_installed_artifact_transitions import _report, _result, _wheel


def _proof(*, passed=True, platform="linux"):
    return {
        "schema": "hol-guard.qualification-interpreter-copy.v1",
        "scope": f"disposable_{'macos' if platform == 'darwin' else 'linux'}_venv_interpreter_only",
        "passed": passed,
        "source": {"bytes": 1024, "mode": 0o777, "world_writable": True},
        "owned": {"bytes": 1024, "mode": 0o755, "world_writable": False},
        "source_sha256": "a" * 64,
        "copied_sha256": "a" * 64,
        "source_invocation_symlink": True,
        "identical_bytes": True,
        "original_target_preserved": True,
        "pyvenv_cfg_unchanged": True,
        "runtime_compatible": True,
        "managed_integrity_validated": passed,
        "managed_validator_inside_venv": passed,
        "managed_validator_sha256": "b" * 64,
        "shared_interpreter_chmodded": False,
        "wheel_bytes_modified": False,
        "production_integrity_checks_relaxed": False,
        "runtime": {"version": "3.12.10", "openssl_version": "OpenSSL 3.0.16 11 Feb 2025"},
    }


def test_original_and_owned_identity_survive_the_complete_nested_sanitizer():
    proof = _proof()
    receipt = driver._interpreter_receipt(proof)
    report = {"compatible_rollback": {"interpreter_provisioning": {"evidence": receipt}}}
    assert assert_privacy_safe(report) == report
    assert receipt["original"] == proof["source"]
    assert receipt["owned"] == proof["owned"]
    assert receipt["original_sha256"] == receipt["copied_sha256"] == "a" * 64
    assert receipt["original_invocation_symlink"] is True
    assert receipt["managed_integrity_validated"] is True
    assert receipt["managed_validator_sha256"] == "b" * 64
    assert (
        receipt["receipt_sha256"]
        == hashlib.sha256(json.dumps(proof, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    )
    assert receipt["runtime"]["openssl_version"] == "redacted"
    assert receipt["runtime_labels_sanitized"] is True


@pytest.mark.parametrize("platform", ["freebsd14", "win32"])
def test_unsupported_hosts_do_not_copy_or_claim_interpreter_provisioning(platform, monkeypatch, tmp_path):
    monkeypatch.setattr(driver.sys, "platform", platform)
    monkeypatch.setattr(driver, "provision_venv_interpreter", lambda *_: pytest.fail("unsupported copy must not run"))
    report = {}
    driver._prepare_interpreter(tmp_path / "python", report)
    assert report["interpreter_provisioning"] == {
        "required": False,
        "attempted": False,
        "status": "platform_not_selected",
    }


@pytest.mark.parametrize("failed", [False, True])
@pytest.mark.parametrize("platform", ["linux", "darwin"])
def test_each_disposable_prefix_is_prepared_after_install_before_registration(failed, platform, monkeypatch, tmp_path):
    baseline = _wheel(tmp_path / "baseline.whl", "baseline")
    candidate = _wheel(tmp_path / "candidate.whl", "candidate")
    prior = _wheel(tmp_path / "prior.whl", "prior")
    (tmp_path / "uv.lock").write_text("pinned")
    monkeypatch.setattr(driver.sys, "platform", platform)
    monkeypatch.setattr(driver.shutil, "which", lambda _: "/usr/bin/uv")
    events, prepared = {}, set()

    def required(argv, root):
        events.setdefault(root, []).append("install" if argv[1] == "pip" else argv[1])

    def provision(python):
        root = python.parent.parent.parent
        assert events[root] == ["venv", "sync", "install"]
        assert root not in prepared
        prepared.add(root)
        events[root].append("provision")
        proof = _proof(passed=not failed, platform=platform)
        if failed:
            proof["failure"] = {"category": "RuntimeError", "code": "qualification_interpreter_runtime_changed"}
            raise driver.InterpreterProvisioningError(proof)
        return proof

    def run(argv, root):
        assert root in prepared
        events[root].append("worker")
        expected = json.loads((root / "expected.json").read_text())
        return _result(_report(expected, argv[-1]))

    monkeypatch.setattr(driver, "_required_command", required)
    monkeypatch.setattr(driver, "provision_venv_interpreter", provision)
    monkeypatch.setattr(driver, "_run", run)
    monkeypatch.setattr(driver, "_run_phase", lambda argv, root, _prior: run(argv, root))
    result = driver.verify(
        tmp_path / "paired-python",
        baseline,
        candidate,
        driver.AUDITED_BASELINE_SHA,
        "a" * 40,
        dependency_root=tmp_path,
        prior_candidate_wheel=prior,
        prior_candidate_sha="b" * 40,
    )
    assert len(prepared) == 2
    assert result["passed"] is (not failed)
    assert result["compatible_artifact_rollback_qualified"] is (not failed)
    for collection in (result, result["compatible_rollback"]):
        observed = collection["interpreter_provisioning"]
        assert observed["attempted"] is observed["required"] is True
        assert observed["evidence"]["passed"] is (not failed)
        assert observed["evidence"]["original_sha256"] == "a" * 64
        if failed:
            assert collection["phases"] == []
            assert collection["failure"]
            assert observed["evidence"]["failure"]["code"] == "qualification_interpreter_runtime_changed"
    if failed:
        assert result["suite_acceptance"]["passed"] is False
        assert all(sequence == ["venv", "sync", "install", "provision"] for sequence in events.values())
    else:
        assert sorted(sequence.count("worker") for sequence in events.values()) == [3, 5]
        assert all(sequence.count("provision") == 1 for sequence in events.values())


@pytest.mark.parametrize("platform", ["linux", "darwin"])
def test_nonthrowing_failed_helper_receipt_cannot_start_a_phase(monkeypatch, tmp_path, platform):
    monkeypatch.setattr(driver.sys, "platform", platform)
    monkeypatch.setattr(driver, "provision_venv_interpreter", lambda _: _proof(passed=False, platform=platform))
    report = {}
    with pytest.raises(driver.InterpreterProvisioningError):
        driver._prepare_interpreter(tmp_path / "python", report)
    assert report["interpreter_provisioning"]["evidence"]["passed"] is False
