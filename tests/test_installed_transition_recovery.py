"""A rejected old build never supplies a successful functional rollback."""

from __future__ import annotations

import hashlib
import json
from types import SimpleNamespace
from zipfile import ZipFile

import pytest

from scripts.ci import installed_artifact_transition_probe as probe
from scripts.ci import installed_transition_diagnostics as diagnostic
from scripts.ci import installed_transition_entry as entry
from scripts.ci import installed_transition_prior as prior
from scripts.ci import verify_installed_artifact_transitions as driver
from scripts.native_slo_contract import assert_privacy_safe
from tests.test_installed_artifact_transitions import _report, _result, _wheel


def _state():
    return {
        "scope": "private_file_bytes",
        "authentication_qualified": False,
        **{
            key: {"status": "read", "sha256": "d" * 64, "bytes": 123, "generation": 4}
            for key in ("authority", "publisher", "generation")
        },
    } | {"authority": {"status": "read", "sha256": "e" * 64, "binding_present": True}}


def _rejection(expected):
    report = _report(expected, "baseline_rollback")
    report.update(
        passed=False,
        registered_native_cases=0,
        last_stage="native_start",
        persistent_authority_preserved=True,
        prior_policy_checkpoint_verified=True,
        rejected_legacy_start_verified=True,
        policy_before=_state(),
        policy_after=_state(),
        publisher_at_failure={"ready": False, "reason": "native_policy_snapshot_unknown_field"},
        retirement_verification={
            "verified": True,
            "return_code": 0,
            "timed_out": False,
            "containment_failed": False,
            "limit_exceeded": False,
            "publisher_after_close": {"thread_alive": False},
        },
        failure={"reason": "native_installed_slo_failed:_native_policy_was_not_ready"},
    )
    report["identity"]["native_program_supported"] = False
    return report


@pytest.mark.parametrize(
    "mutation",
    [
        None,
        "candidate_build",
        "floor",
        "reason",
        "ready",
        "cleanup",
        "receipt",
        "timeout",
        "stop_exit",
        "stop_containment",
        "history",
        "stage",
    ],
)
def test_rejected_baseline_needs_every_independent_witness(mutation):
    expected = {
        "build_sha": driver.AUDITED_BASELINE_SHA,
        "wheel_sha256": "b" * 64,
        "installed_package_sha256": "c" * 64,
    }
    report = _rejection(expected)
    changes = {"returncode": 1}
    if mutation == "candidate_build":
        expected = expected | {"build_sha": "f" * 40}
        report["identity"].update(expected)
    elif mutation == "floor":
        report["policy_after"]["authority"]["sha256"] = "f" * 64
    elif mutation == "reason":
        report["publisher_at_failure"]["reason"] = "native_resident_client_timeout"
    elif mutation == "ready":
        report["publisher_at_failure"]["ready"] = True
    elif mutation == "cleanup":
        report["cleanup_confirmed"] = False
    elif mutation == "receipt":
        report["prior_receipts_verified"] = 4
    elif mutation == "timeout":
        changes["timed_out"] = True
    elif mutation == "stop_exit":
        report["retirement_verification"]["return_code"] = 1
    elif mutation == "stop_containment":
        report["retirement_verification"]["containment_failed"] = True
    elif mutation == "history":
        report["prior_policy_checkpoint_verified"] = False
    elif mutation == "stage":
        report["last_stage"] = "registered_hooks"
    result = driver.worker_evidence(_result(report, **changes), expected, "baseline_rollback")
    assert result["passed"] is False
    assert result["verified_legacy_rejection"] is (mutation is None)
    assert assert_privacy_safe(result) == result


@pytest.mark.parametrize("verified_stop", [True, False])
def test_restore_after_rejection_retains_failure_and_six_prior_receipts(verified_stop, monkeypatch, tmp_path):
    baseline = _wheel(tmp_path / "baseline.whl", "baseline")
    candidate = _wheel(tmp_path / "candidate.whl", "candidate")
    (tmp_path / "uv.lock").write_text("pinned")
    monkeypatch.setattr(driver.shutil, "which", lambda _: "/usr/bin/uv")
    monkeypatch.setattr(driver, "_required_command", lambda *_: None)
    monkeypatch.setattr(driver, "provision_venv_interpreter", lambda _python: {"passed": True})
    phases = []

    def run(argv, root):
        phase = argv[-1]
        phases.append(phase)
        expected = json.loads((root / "expected.json").read_text())
        if phase == "baseline_rollback":
            report = _rejection(expected)
            report["retirement_verification"]["verified"] = verified_stop
            return _result(report, returncode=1)
        report = _report(expected, phase)
        if phase == "candidate_restore":
            report.update(prior_receipts_verified=6, restored_after_rejected_legacy=True)
        return _result(report)

    monkeypatch.setattr(driver, "_run", run)
    result = driver.verify(
        tmp_path / "python", baseline, candidate, driver.AUDITED_BASELINE_SHA, "a" * 40, dependency_root=tmp_path
    )
    assert result["passed"] is False
    assert result["completed_phase_count"] == (4 if verified_stop else 3)
    assert result["candidate_restored_after_rejected_legacy"] is verified_stop
    assert ("candidate_restore" in phases) is verified_stop
    assert result["phases"][3]["passed"] is False
    assert result["native_program_downgrade_qualified"] is False


def test_compatible_rollback_uses_distinct_prior_bytes_and_fresh_history(monkeypatch, tmp_path):
    baseline = _wheel(tmp_path / "baseline.whl", "baseline")
    candidate = _wheel(tmp_path / "candidate.whl", "candidate")
    old = _wheel(tmp_path / "prior.whl", "prior")
    (tmp_path / "uv.lock").write_text("pinned")
    monkeypatch.setattr(driver.shutil, "which", lambda _: "/usr/bin/uv")
    installs, roots, identities = [], [], []
    monkeypatch.setattr(driver, "_required_command", lambda argv, _: installs.append(argv))
    monkeypatch.setattr(driver, "provision_venv_interpreter", lambda _python: {"passed": True})

    def run(argv, root):
        roots.append(root)
        expected = json.loads((root / "expected.json").read_text())
        identities.append(expected["build_sha"])
        return _result(_report(expected, argv[-1]))

    monkeypatch.setattr(driver, "_run", run)
    result = driver.verify(
        tmp_path / "python",
        baseline,
        candidate,
        driver.AUDITED_BASELINE_SHA,
        "a" * 40,
        dependency_root=tmp_path,
        prior_candidate_wheel=old,
        prior_candidate_sha="b" * 40,
    )
    assert result["compatible_artifact_rollback_qualified"] is True
    assert identities[:3] == ["a" * 40, "b" * 40, "a" * 40]
    assert roots[0] == roots[1] == roots[2] and roots[3] != roots[0]
    assert result["compatible_rollback"]["completed_phase_count"] == 3
    assert result["native_program_downgrade_qualified"] is False
    assert any(str(old) == argv[-1] for argv in installs)


def test_policy_readback_never_exports_or_removes_binding(tmp_path):
    tmp_path.chmod(0o700)
    (tmp_path / "native-runtime").mkdir(mode=0o700)
    documents = {
        "native-runtime/policy-snapshot-v3.json": {"generation_floor": 4, "command_control_floor": {"revision": 3}},
        "native-runtime/policy-snapshot-publisher-v3.json": {
            "generation": 4,
            "command_extensions": {"sensitive": "kept"},
        },
        "native-policy-snapshot-generation-v3.json": {"generation": 4},
    }
    for name, document in documents.items():
        file = tmp_path / name
        file.write_text(json.dumps(document))
        file.chmod(0o600)
    observed = diagnostic.policy_state(tmp_path)
    assert diagnostic.state_preserved(observed, diagnostic.policy_state(tmp_path))
    assert assert_privacy_safe(observed) == observed
    assert "kept" not in json.dumps(observed)
    assert {name: json.loads((tmp_path / name).read_text()) for name in documents} == documents
    (tmp_path / "native-runtime/policy-snapshot-v3.json").write_text('{"generation_floor":3}')
    assert not diagnostic.state_preserved(observed, diagnostic.policy_state(tmp_path))


def test_unreadable_or_absent_policy_state_never_proves_preservation(tmp_path):
    state = diagnostic.policy_state(tmp_path)
    assert not diagnostic.state_preserved(state, state)


@pytest.mark.parametrize("failure", ["busy_publisher", "exit", "timeout", "containment", "client_cleanup", None])
def test_failed_start_requires_native_stop_and_quiescent_publisher(failure, monkeypatch, tmp_path):
    session = object.__new__(probe.RetainedSession)
    session.runtime, session.root, session.guard_home = tmp_path / "runtime", tmp_path, tmp_path / "guard"
    session.retirement_confirmed = False
    session.last_stop_diagnostic = {
        "status": "contained_client_cleanup_failed" if failure == "client_cleanup" else "failed"
    }
    session.daemon = SimpleNamespace(
        _server=SimpleNamespace(
            active_hook_requests=0,
            hook_worker=SimpleNamespace(
                policy_snapshot_publisher=SimpleNamespace(
                    last_error=None,
                    is_ready=False,
                    _thread=SimpleNamespace(is_alive=lambda: failure == "busy_publisher"),
                )
            ),
        )
    )
    calls = []

    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        return _result(
            {},
            returncode=int(failure == "exit"),
            timed_out=failure == "timeout",
            containment_failed=failure == "containment",
        )

    monkeypatch.setattr(probe, "run_isolated_hook_process", run)
    result = session.verify_failed_start_retirement()
    assert result["verified"] is (failure is None)
    if failure == "busy_publisher":
        assert not calls
    else:
        assert calls[0][0][1:3] == ("resident-stop", "--state-dir")
        assert calls[0][1]["timeout_seconds"] == 2


def test_pre_json_import_error_is_bounded_and_retained(monkeypatch, capsys):
    def fail(*_args):
        raise ImportError("private-fixture-secret-path")

    monkeypatch.setattr(entry.importlib.util, "spec_from_file_location", fail)
    assert entry.main() == 1
    out = capsys.readouterr()
    report = json.loads(out.out)
    assert report["failure"]["category"] == "ImportError"
    assert report["last_stage"] == "import_probe"
    assert "private-fixture-secret-path" not in out.out
    result = driver.worker_evidence(_result({}, stdout=out.out, stderr=out.err, returncode=1), {}, "clean_baseline")
    assert result["process"]["last_stage"] == "import_probe"
    assert result["passed"] is False


@pytest.mark.parametrize("readiness, expected", [(True, True), (False, False), (None, None), (1, None)])
def test_publisher_metadata_calls_real_method_shape_and_preserves_unknown(readiness, expected):
    publisher = SimpleNamespace(
        is_ready=lambda: readiness, last_error="native_policy_snapshot_unknown_field", _thread=None
    )
    assert diagnostic.publisher_metadata(publisher)["ready"] is expected
    publisher.is_ready = readiness
    assert diagnostic.publisher_metadata(publisher)["ready"] is None


def test_pinned_prior_wheel_rejects_changed_bytes_and_ignores_universal_wheel(monkeypatch, tmp_path):
    wheel = tmp_path / "selected.whl"
    with ZipFile(wheel, "w") as archive:
        archive.writestr(
            "codex_plugin_scanner/_native/runtime-manifest.json",
            json.dumps(
                {
                    "schema": "hol-guard-native-runtime.v1",
                    "source_sha": prior.PRIOR_BUILD_SHA,
                    "target": "test",
                }
            ),
        )
    (tmp_path / "unused-any.whl").write_bytes(b"unselected")
    pin = {
        "wheel_name": wheel.name,
        "wheel_sha256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
        "artifact_id": 1,
        "archive_sha256": "a" * 64,
    }
    monkeypatch.setitem(prior.PRIOR_ARTIFACTS, "test", pin)
    selected, metadata = prior.prior_artifact(tmp_path, "test")
    assert selected == wheel and metadata["build_sha"] == prior.PRIOR_BUILD_SHA
    assert metadata["build_sha"] != metadata["pr_head_sha"]
    assert metadata["rebuilt"] is False
    wheel.write_bytes(b"changed")
    with pytest.raises(ValueError, match="digest_mismatch"):
        prior.prior_artifact(tmp_path, "test")


@pytest.mark.parametrize("build,target", [(prior.PRIOR_PR_HEAD_SHA, "test"), (prior.PRIOR_BUILD_SHA, "wrong")])
def test_pinned_archive_cannot_replace_actual_build_with_pr_head_or_wrong_platform(
    build, target, monkeypatch, tmp_path
):
    wheel = tmp_path / "selected.whl"
    with ZipFile(wheel, "w") as archive:
        archive.writestr(
            "codex_plugin_scanner/_native/runtime-manifest.json",
            json.dumps(
                {
                    "schema": "hol-guard-native-runtime.v1",
                    "source_sha": build,
                    "target": target,
                }
            ),
        )
    monkeypatch.setitem(
        prior.PRIOR_ARTIFACTS,
        "test",
        {
            "wheel_name": wheel.name,
            "wheel_sha256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
            "artifact_id": 1,
            "archive_sha256": "a" * 64,
        },
    )
    with pytest.raises(ValueError, match="embedded_identity_mismatch"):
        prior.prior_artifact(tmp_path, "test")
