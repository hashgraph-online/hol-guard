"""Replacement evidence binds actual artifacts, persistent floors and failures."""

from __future__ import annotations

import json
import zipfile
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.approval_gate import update_settings
from codex_plugin_scanner.guard.runtime.extension_control_authority import ExtensionControlAuthorityError
from codex_plugin_scanner.guard.store import GuardStore
from scripts.ci import installed_artifact_transition_probe as probe
from scripts.ci import verify_installed_artifact_transitions as driver
from scripts.native_slo_command_fixture import prepare_empty_command_authority
from scripts.native_slo_contract import assert_privacy_safe


def _result(report, **changes):
    fields = dict(
        returncode=0, timed_out=False, containment_failed=False, output_limit_exceeded=False, stdout=json.dumps(report)
    )
    return SimpleNamespace(**(fields | changes))


def _report(expected, phase="clean_baseline"):
    plan = driver._COMPATIBLE_PHASES if phase.startswith("compatible_") else driver._PHASES
    return {
        "schema": "hol-guard.installed-artifact-transition-phase.v1",
        "phase": phase,
        "passed": True,
        "cleanup_confirmed": True,
        "registered_native_cases": 2,
        "prior_receipts_verified": next(index for index, item in enumerate(plan) if item[0] == phase) * 2,
        "control_revision": 1,
        "stale_control_write_rejected": True,
        "registration_preserved": phase not in {"clean_baseline", "compatible_candidate_start"},
        "authority_health": "protected",
        "identity": {
            **expected,
            "runtime_sha256": "c" * 64,
            "installed_origin_verified": True,
            "native_program_supported": True,
        },
    }


@pytest.mark.parametrize(
    "mutation",
    [
        "build",
        "runtime",
        "origin",
        "cleanup",
        "receipt_count",
        "registration",
        "boolean_revision",
        "timeout",
        "containment",
        "exit",
        "missing_stdout",
    ],
)
def test_worker_success_needs_complete_artifact_process_and_floor_evidence(mutation) -> None:
    expected = {"build_sha": "a" * 40, "wheel_sha256": "b" * 64, "installed_package_sha256": "d" * 64}
    report = _report(expected)
    changes = {}
    if mutation == "build":
        report["identity"]["build_sha"] = "0" * 40
    elif mutation == "runtime":
        del report["identity"]["runtime_sha256"]
    elif mutation == "origin":
        report["identity"]["installed_origin_verified"] = False
    elif mutation == "cleanup":
        report["cleanup_confirmed"] = False
    elif mutation == "receipt_count":
        report["prior_receipts_verified"] = 2
    elif mutation == "registration":
        report["registration_preserved"] = True
    elif mutation == "boolean_revision":
        report["control_revision"] = True
    elif mutation == "timeout":
        changes["timed_out"] = True
    elif mutation == "containment":
        changes["containment_failed"] = True
    elif mutation == "exit":
        changes["returncode"] = 1
    elif mutation == "missing_stdout":
        changes["stdout"] = ""
    assert driver.worker_evidence(_result(report, **changes), expected, "clean_baseline")["passed"] is False


def test_successful_worker_metadata_survives_complete_outer_sanitizer() -> None:
    expected = {"build_sha": "a" * 40, "wheel_sha256": "b" * 64, "installed_package_sha256": "d" * 64}
    result = assert_privacy_safe(
        {"phases": [driver.worker_evidence(_result(_report(expected)), expected, "clean_baseline")]}
    )
    assert result["phases"][0]["passed"] is True
    assert result["phases"][0]["worker"]["identity"]["native_program_supported"] is True
    assert result["phases"][0]["worker"]["identity"]["build_sha"] == "a" * 40


@pytest.mark.parametrize("executable", ["uv", "uv.exe", "uv.EXE", "UV.ExE", "python"])
def test_child_environment_cannot_select_the_paired_prefix_or_runtime_override(executable, monkeypatch, tmp_path):
    for key in ("VIRTUAL_ENV", "UV_PROJECT_ENVIRONMENT", "UV_PYTHON", "PYTHONHOME", "PYTHONPATH", "HOL_GUARD_NATIVE"):
        monkeypatch.setenv(key, "untrusted-inherited-value")
    observed = {}

    def run(*_args, **kwargs):
        observed.update(kwargs["environment"])
        return _result({})

    monkeypatch.setattr(driver, "run_isolated_hook_process", run)
    driver._run((executable, "--version"), tmp_path)
    assert all(
        key not in observed for key in ("VIRTUAL_ENV", "UV_PYTHON", "PYTHONHOME", "PYTHONPATH", "HOL_GUARD_NATIVE")
    )
    if executable.casefold() in {"uv", "uv.exe"}:
        assert observed["UV_PROJECT_ENVIRONMENT"] == str(tmp_path / "installation")
    else:
        assert "UV_PROJECT_ENVIRONMENT" not in observed


def test_failure_receipt_survives_missing_installed_package(monkeypatch):
    def missing(_error):
        raise ModuleNotFoundError("No module named 'codex_plugin_scanner.guard.codex_hook_file_integrity'")

    monkeypatch.setattr(driver, "failure_evidence", missing)
    original = RuntimeError("qualification_transition_prior_cleanup_unverified")
    evidence = assert_privacy_safe(driver._failure_evidence(original))
    assert evidence["reason"] == "qualification_transition_prior_cleanup_unverified"
    assert evidence["category"] == "RuntimeError"
    assert evidence["reporting_failure"]["category"] == "ModuleNotFoundError"
    assert "codex_plugin_scanner" not in json.dumps(evidence)


@pytest.mark.parametrize("message", ["private/path/" + "x" * 300, "qualification_customer_private_alphanumeric123"])
def test_fallback_failure_receipt_does_not_export_unknown_exception_text(monkeypatch, message):
    monkeypatch.setattr(driver, "failure_evidence", lambda _error: (_ for _ in ()).throw(ImportError("missing")))
    original = RuntimeError(message)
    evidence = assert_privacy_safe(driver._failure_evidence(original))
    assert "reason" not in evidence
    assert message not in json.dumps(evidence)
    assert "private/path" not in json.dumps(evidence)


def _wheel(path, text):
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("codex_plugin_scanner/__init__.py", text)
    return path


@pytest.mark.parametrize("fail_phase", [None, "candidate_upgrade"])
def test_replacement_uses_only_third_prefix_and_stops_after_failed_worker(fail_phase, monkeypatch, tmp_path) -> None:
    baseline = _wheel(tmp_path / "baseline.whl", "baseline")
    candidate = _wheel(tmp_path / "candidate.whl", "candidate")
    installs, workers = [], []
    source_python = tmp_path / "candidate-env/bin/python"
    (tmp_path / "uv.lock").write_text("pinned-test-lock")
    monkeypatch.setattr(driver.shutil, "which", lambda _name: "/usr/bin/uv")

    def required(argv, root):
        installs.append(argv)
        if argv[1] == "pip":
            target = argv[argv.index("--python") + 1]
            assert target != str(source_python) and str(root / "installation") in target
            assert "--no-index" in argv and "--no-deps" in argv

    def run(argv, root):
        assert argv[1] == "-I"
        phase = argv[-1]
        workers.append(phase)
        expected = json.loads((root / "expected.json").read_text())
        report = _report(expected, phase)
        if phase == fail_phase:
            report["cleanup_confirmed"] = False
        return _result(report)

    monkeypatch.setattr(driver, "_required_command", required)
    monkeypatch.setattr(driver, "provision_venv_interpreter", lambda _python: {"passed": True})
    monkeypatch.setattr(driver, "_run", run)
    result = driver.verify(source_python, baseline, candidate, "a" * 40, "b" * 40, dependency_root=tmp_path)
    assert result["passed"] is (fail_phase is None)
    assert workers == [item[0] for item in driver._PHASES][: 5 if fail_phase is None else 2]
    assert len(installs) == 2 + len(workers)
    assert installs[1][1:7] == ("sync", "--frozen", "--extra", "dev", "--no-install-project", "--project")
    assert all(
        result[field] is False
        for field in (
            "version_downgrade_qualified",
            "native_program_downgrade_qualified",
            "in_progress_replacement_qualified",
            "signing_changes_qualified",
            "program_qualification_complete",
        )
    )


def test_same_artifact_cannot_supply_an_upgrade_or_rollback(monkeypatch, tmp_path) -> None:
    wheel = _wheel(tmp_path / "same.whl", "unchanged")
    monkeypatch.setattr(
        driver, "_required_command", lambda *_args: pytest.fail("same artifact must fail before installation")
    )
    assert (
        driver.verify(tmp_path / "python", wheel, wheel, "a" * 40, "b" * 40, dependency_root=tmp_path)["passed"]
        is False
    )


def test_dependency_change_retains_completed_phases_but_cannot_qualify(monkeypatch, tmp_path) -> None:
    baseline = _wheel(tmp_path / "baseline.whl", "baseline")
    candidate = _wheel(tmp_path / "candidate.whl", "candidate")
    lock = tmp_path / "uv.lock"
    lock.write_text("original-lock")
    monkeypatch.setattr(driver.shutil, "which", lambda _name: "/usr/bin/uv")
    monkeypatch.setattr(driver, "_required_command", lambda *_args: None)
    monkeypatch.setattr(driver, "provision_venv_interpreter", lambda _python: {"passed": True})

    def run(argv, root):
        if argv[-1] == "candidate_restore":
            lock.write_text("changed-lock")
        expected = json.loads((root / "expected.json").read_text())
        return _result(_report(expected, argv[-1]))

    monkeypatch.setattr(driver, "_run", run)
    result = driver.verify(tmp_path / "python", baseline, candidate, "a" * 40, "b" * 40, dependency_root=tmp_path)
    assert result["passed"] is False
    assert result["completed_phase_count"] == 5
    assert "failure" in result


def test_private_journal_is_bounded_and_retains_exact_records(tmp_path) -> None:
    path = tmp_path / "journal.json"
    record = {"password": "private-fixture-password", "receipts": [{"decision_id": "a" * 64}]}
    probe.write_private(path, record)
    assert probe.read_private(path) == record
    with pytest.raises(RuntimeError, match="private_state_limit"):
        probe.write_private(path, {"value": "x" * (64 * 1024)})
    assert probe.read_private(path) == record


def test_preserved_authority_cannot_regress_or_drop_existing_control(tmp_path) -> None:
    store = GuardStore(tmp_path)
    prepare_empty_command_authority(store)
    password = "private-fixture-password"
    update_settings(
        tmp_path, {"enabled": True, "new_password": password, "confirm_password": password, "cooldown_seconds": 0}
    )
    probe.commit_layer(store, password, revision=0, enabled=False)
    previous = {"revision": 1, "ollama_state": "disabled"}
    assert probe.authority_view(store, previous).revision == 1
    with pytest.raises(RuntimeError, match="revision_regressed"):
        probe.authority_view(store, {**previous, "revision": 2})
    with pytest.raises(RuntimeError, match="control_not_preserved"):
        probe.authority_view(store, {**previous, "ollama_state": "enabled"})
    with pytest.raises(ExtensionControlAuthorityError):
        probe.commit_layer(store, password, revision=0, enabled=True)
    assert probe.authority_view(store, previous).revision == 1


def test_mismatched_installation_never_constructs_a_daemon(monkeypatch, tmp_path) -> None:
    def identity(_expected):
        raise RuntimeError("private-fixture-path")

    monkeypatch.setattr(probe, "installed_identity", identity)
    monkeypatch.setattr(probe, "GuardStore", lambda *_args: pytest.fail("unverified wheel cannot open authority"))
    result = probe.run_phase({}, tmp_path, "clean_baseline")
    assert result["passed"] is result["cleanup_confirmed"] is False
    assert "identity" not in result and "private-fixture-path" not in json.dumps(result)


@pytest.mark.parametrize("final_status", ["failed", "contained_client_cleanup_failed", "already-stopped"])
def test_final_cleanup_can_withdraw_earlier_native_retirement(final_status, monkeypatch) -> None:
    session = object.__new__(probe.RetainedSession)
    session.retirement_confirmed = True

    def close(self):
        self.last_stop_diagnostic = {"status": final_status}

    monkeypatch.setattr(probe.AdapterSession, "close", close)
    session.close()
    assert session.retirement_confirmed is (final_status == "already-stopped")


def test_changed_prior_registration_fails_without_repair_or_native_launch(monkeypatch, tmp_path) -> None:
    settings = tmp_path / "settings.json"
    settings.write_text('{"changed":true}')
    monkeypatch.setattr(probe, "claude_managed_settings_path", lambda _context: settings)
    monkeypatch.setattr(
        probe.ClaudeCodeHarnessAdapter,
        "install",
        lambda *_args: pytest.fail("later phases must not repair registration"),
    )
    session = SimpleNamespace(root=tmp_path, workspace=tmp_path / "workspace", guard_home=tmp_path / ".hol-guard")
    with pytest.raises(RuntimeError, match="registration_changed"):
        probe.observe_registered(session, {}, {"registration_sha256": "0" * 64}, None)
