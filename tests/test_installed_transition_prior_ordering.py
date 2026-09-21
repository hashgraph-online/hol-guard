"""Historical artifact failure is mandatory but cannot suppress other probes."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from zipfile import ZipFile

import pytest

from scripts import build_native_qualification_artifacts as builds
from scripts.ci import installed_transition_prior as prior
from scripts.ci import verify_installed_artifact_transitions as driver


def _arguments(tmp_path: Path) -> list[str]:
    return [
        "transition",
        "--python",
        sys.executable,
        "--baseline-wheel",
        "base.whl",
        "--candidate-wheel",
        "current.whl",
        "--baseline-sha",
        driver.AUDITED_BASELINE_SHA,
        "--candidate-sha",
        "a" * 40,
        "--dependency-root",
        str(tmp_path),
        "--output",
        str(tmp_path / "report.json"),
    ]


def _selected_wheel(tmp_path: Path, monkeypatch):
    wheel = tmp_path / "selected.whl"
    with ZipFile(wheel, "w") as archive:
        archive.writestr(
            "codex_plugin_scanner/_native/runtime-manifest.json",
            json.dumps(
                {"schema": "hol-guard-native-runtime.v1", "source_sha": prior.PRIOR_BUILD_SHA, "target": "test"}
            ),
        )
    monkeypatch.setitem(
        prior.PRIOR_ARTIFACTS,
        "test",
        {
            "wheel_name": wheel.name,
            "wheel_sha256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
            "artifact_id": 1,
            "archive_sha256": "b" * 64,
        },
    )
    return prior.prior_artifact(tmp_path, "test")


def _child(value, **changes):
    return SimpleNamespace(
        stdout=json.dumps(value),
        returncode=changes.get("returncode", 0),
        timed_out=changes.get("timed_out", False),
        containment_failed=changes.get("containment_failed", False),
        output_limit_exceeded=changes.get("output_limit_exceeded", False),
    )


@pytest.mark.parametrize("download", ["missing", "changed_bytes"])
def test_missing_prior_download_fails_only_its_independent_required_check(monkeypatch, tmp_path, download):
    baseline = tmp_path / "baseline"
    candidate = tmp_path / "candidate"
    baseline.mkdir()
    candidate.mkdir()
    prior_root = tmp_path / "private-prior-fixture"
    if download == "changed_bytes":
        prior_root.mkdir()
        (prior_root / prior.PRIOR_ARTIFACTS["x86_64-unknown-linux-musl"]["wheel_name"]).write_bytes(b"changed")
    (candidate / "uv.lock").write_text('[[package]]\nname = "psutil"\nversion = "7.2.2"\n')
    seen = []

    def build(source, **kwargs):
        return (
            Path(sys.executable),
            source / "example.whl",
            {"source_sha": "b" * 40 if source == baseline else "a" * 40},
        )

    def forbidden_verify(*args, **kwargs):
        raise AssertionError("No transition may start with absent prior bytes")

    def run(argv, **kwargs):
        if argv[0] == "uv":
            return ""
        script_index = 2 if argv[1] == "-I" else 1
        name = Path(argv[script_index]).name
        seen.append(name)
        if name == "verify_installed_artifact_transitions.py":
            monkeypatch.setattr(driver.sys, "argv", argv[script_index:])
            code = driver.main()
            assert code == 1
            raise subprocess.CalledProcessError(code, argv)
        return ""

    required = builds._run_required_checks

    def checks_with_later_independent_probe(checks, **kwargs):
        # Exercise the existing extensible check tuple with a later scanner
        # probe even before that independent implementation is integrated.
        if not any(name == "installed_offline_secrets" for name, _argv in checks):
            checks += (("installed_offline_secrets", [sys.executable, "probe_installed_offline_secrets.py"]),)
        return required(checks, **kwargs)

    monkeypatch.setattr(builds, "_build", build)
    monkeypatch.setattr(builds, "_run", run)
    monkeypatch.setattr(builds, "_run_required_checks", checks_with_later_independent_probe)
    monkeypatch.setattr(driver, "verify", forbidden_verify)
    monkeypatch.setattr(
        builds.sys,
        "argv",
        [
            "builder",
            "--baseline",
            str(baseline),
            "--candidate",
            str(candidate),
            "--target",
            "x86_64-unknown-linux-musl",
            "--platform-tag",
            "test",
            "--output-dir",
            str(tmp_path / "evidence"),
            "--prior-artifact-root",
            str(prior_root),
        ],
    )
    with pytest.raises(RuntimeError, match="installed_artifact_transitions"):
        builds.main()
    assert seen == [
        "provision_native_qualification_interpreters.py",
        "qualify_guard_native.py",
        "verify_native_ollama_install.py",
        "verify_installed_artifact_transitions.py",
        "probe_installed_offline_secrets.py",
        "bench_claude_native_launcher_pilot.py",
    ]
    report = json.loads((tmp_path / "evidence/aggregate/installed-artifact-transitions.json").read_text())
    assert report["passed"] is False and report["prior_candidate_requested"] is True
    assert report["suite_acceptance"]["passed"] is False and report["phases"] == []
    assert report["failure"]["reason"] == (
        "qualification_transition_prior_artifact_missing"
        if download == "missing"
        else "qualification_transition_prior_wheel_digest_mismatch"
    )
    assert "private-prior-fixture" not in json.dumps(report)


@pytest.mark.parametrize(
    "flags",
    [
        ["--prior-artifact-root", "missing"],
        ["--prior-artifact-target", "test"],
        ["--prior-artifact-root", "missing", "--prior-artifact-target", "test", "--prior-candidate-sha", "a" * 40],
    ],
)
def test_incomplete_or_conflicting_prior_input_cannot_fall_back(monkeypatch, tmp_path, flags):
    monkeypatch.setattr(driver.sys, "argv", _arguments(tmp_path) + flags)
    monkeypatch.setattr(driver, "verify", lambda *args, **kwargs: pytest.fail("unexpected transition"))
    assert driver.main() == 1
    result = json.loads((tmp_path / "report.json").read_text())
    assert result["prior_candidate_requested"] is True and result["suite_acceptance"]["passed"] is False


@pytest.mark.parametrize(
    "flags",
    [
        {"timed_out": True},
        {"containment_failed": True},
        {"output_limit_exceeded": True},
    ],
)
def test_selector_deadline_output_and_containment_are_mandatory(monkeypatch, tmp_path, flags):
    monkeypatch.setattr(driver, "_run", lambda *args, **kwargs: _child({"passed": True}, **flags))
    with pytest.raises(RuntimeError, match="selection_not_contained"):
        driver.select_prior_artifact(Path(sys.executable), tmp_path, "test")


@pytest.mark.parametrize("change", [None, "wheel_sha256", "artifact_id", "build_sha", "target", "wheel_bytes_verified"])
def test_selector_is_bounded_and_rechecks_child_pin_metadata(monkeypatch, tmp_path, change):
    wheel, evidence = _selected_wheel(tmp_path, monkeypatch)
    if change is not None:
        evidence[change] = "invalid"

    def run(argv, root, **kwargs):
        assert argv[:2] == (sys.executable, "-I")
        assert Path(argv[2]).name == "installed_transition_prior.py"
        assert kwargs == {"timeout_seconds": 15}
        return _child({"passed": True, "selected_wheel": str(wheel), "evidence": evidence})

    monkeypatch.setattr(driver, "_run", run)
    if change is None:
        selected, retained = driver.select_prior_artifact(Path(sys.executable), tmp_path, "test")
        assert selected == wheel and retained["build_sha"] == prior.PRIOR_BUILD_SHA
        assert str(tmp_path) not in json.dumps(retained)
    else:
        with pytest.raises(ValueError, match="selection_identity_invalid"):
            driver.select_prior_artifact(Path(sys.executable), tmp_path, "test")


@pytest.mark.parametrize("changed, earlier_failure", [(False, False), (True, False), (True, True)])
def test_prior_pin_remains_bound_to_final_transition_identities(monkeypatch, tmp_path, changed, earlier_failure):
    wheel, evidence = _selected_wheel(tmp_path, monkeypatch)
    monkeypatch.setattr(driver, "select_prior_artifact", lambda *args: (wheel, evidence))

    def verify(*args, **kwargs):
        assert kwargs["prior_candidate_wheel"] == wheel
        assert kwargs["prior_candidate_sha"] == prior.PRIOR_BUILD_SHA
        report = {
            "passed": False,
            "prior_candidate_requested": True,
            "identities": {"prior_candidate": {"wheel_sha256": "a" * 64 if changed else evidence["wheel_sha256"]}},
            "suite_acceptance": {"passed": True},
        }
        if earlier_failure:
            report["failure"] = {"reason": "qualification_original_observation_failed"}
        return report

    monkeypatch.setattr(driver, "verify", verify)
    monkeypatch.setattr(
        driver.sys,
        "argv",
        [
            *_arguments(tmp_path),
            "--prior-artifact-root",
            str(tmp_path),
            "--prior-artifact-target",
            "test",
        ],
    )
    assert driver.main() == (1 if changed else 0)
    report = json.loads((tmp_path / "report.json").read_text())
    assert report["prior_artifact"]["wheel_sha256"] == evidence["wheel_sha256"]
    if changed:
        assert report["prior_artifact_validation_failure"]["reason"] == "qualification_transition_prior_wheel_changed"
        assert report["failure"]["reason"] == (
            "qualification_original_observation_failed"
            if earlier_failure
            else "qualification_transition_prior_wheel_changed"
        )
        assert report["suite_acceptance"]["passed"] is False
