"""Exercise real wheel replacements after paired timing, in a third environment.

The paired installations are never changed. The third virtual environment
installs candidate locked dependencies, then each exact local wheel, and
runs fresh isolated workers against one private home. Every replacement waits
for the prior worker's witnessed native generation retirement.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
from collections.abc import Mapping
from pathlib import Path
from types import SimpleNamespace

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.append(str(_ROOT))

from codex_plugin_scanner.guard.codex_hook_launch_runtime import run_isolated_hook_process  # noqa: E402
from scripts.ci.installed_transition_diagnostics import (  # noqa: E402
    LEGACY_REJECTION_REASONS,
    exception_metadata,
    process_metadata,
    state_preserved,
)
from scripts.ci.installed_transition_prior import PRIOR_ARTIFACTS, PRIOR_BUILD_SHA  # noqa: E402
from scripts.ci.installed_transition_receipts import AUDITED_BASELINE_SHA  # noqa: E402
from scripts.native_qualification_interpreter import (  # noqa: E402
    InterpreterProvisioningError,
    provision_venv_interpreter,
)
from scripts.native_slo_artifact import wheel_package_digest  # noqa: E402
from scripts.native_slo_contract import assert_privacy_safe, clear_proof_environment  # noqa: E402
from scripts.native_slo_failure import failure_evidence  # noqa: E402

_PHASES = (
    ("clean_baseline", "baseline"),
    ("candidate_upgrade", "candidate"),
    ("candidate_reinstall", "candidate"),
    ("baseline_rollback", "baseline"),
    ("candidate_restore", "candidate"),
)
_COMPATIBLE_PHASES = (
    ("compatible_candidate_start", "candidate"),
    ("compatible_candidate_rollback", "prior_candidate"),
    ("compatible_candidate_restore", "candidate"),
)
_FALLBACK_FAILURE_REASONS = frozenset(
    {
        "qualification_transition_dependency_lock_changed",
        "qualification_transition_installation_command_failed",
        "qualification_transition_installer_unavailable",
        "qualification_transition_prior_artifact_missing",
        "qualification_transition_prior_artifact_pair_missing",
        "qualification_transition_prior_cleanup_unverified",
        "qualification_transition_prior_selection_identity_invalid",
        "qualification_transition_prior_selection_invalid",
        "qualification_transition_prior_selection_not_contained",
        "qualification_transition_prior_selection_path_invalid",
        "qualification_transition_prior_wheel_changed",
        "qualification_transition_requires_distinct_artifacts",
        "qualification_transition_requires_distinct_prior_artifact",
        "qualification_transition_wheel_changed",
    }
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for value in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(value)
    return digest.hexdigest()


def artifact_contract(wheel: Path, build_sha: str) -> dict:
    if not isinstance(build_sha, str) or re.fullmatch(r"[0-9a-f]{40}", build_sha) is None:
        raise ValueError("qualification_transition_build_identity_invalid")
    return {
        "build_sha": build_sha,
        "wheel_sha256": sha256(wheel),
        "installed_package_sha256": wheel_package_digest(wheel),
    }


def _run(arguments: tuple[str, ...], root: Path, *, timeout_seconds: float = 180):
    environment = dict(os.environ)
    clear_proof_environment(environment)
    for key in ("PYTHONHOME", "VIRTUAL_ENV", "UV_PROJECT_ENVIRONMENT", "UV_PYTHON"):
        environment.pop(key, None)
    # uv sync must target only this disposable prefix, never the paired
    # candidate project's default environment.
    if Path(arguments[0]).name.casefold() in {"uv", "uv.exe"}:
        environment["UV_PROJECT_ENVIRONMENT"] = str(root / "installation")
    return run_isolated_hook_process(
        arguments,
        cwd=root,
        environment=environment,
        input_text="",
        timeout_seconds=timeout_seconds,
        output_limit=256 * 1024,
    )


def _failure_evidence(error: Exception) -> dict:
    """Keep the first failure even if installed package imports were lost."""
    try:
        return failure_evidence(error)
    except Exception as reporting_error:
        reason = str(error)
        evidence = {
            "schema": "hol-guard.native-qualification-failure.v1",
            **exception_metadata(error),
            "reporting_failure": exception_metadata(reporting_error),
        }
        if reason in _FALLBACK_FAILURE_REASONS:
            evidence["reason"] = reason
        return evidence


def _process_ok(result) -> bool:
    return (
        result.returncode == 0
        and not result.timed_out
        and not result.containment_failed
        and not result.output_limit_exceeded
    )


def _required_command(arguments: tuple[str, ...], root: Path) -> None:
    result = _run(arguments, root)
    if not _process_ok(result):
        raise RuntimeError("qualification_transition_installation_command_failed")


def _interpreter_receipt(proof: dict) -> dict:
    """Keep original/copy identities without relaxing the aggregate privacy filter."""
    encoded = json.dumps(proof, sort_keys=True, separators=(",", ":")).encode("utf-8")
    renamed = {
        {
            "source": "original",
            "source_sha256": "original_sha256",
            "source_invocation_symlink": "original_invocation_symlink",
        }.get(key, key): value
        for key, value in proof.items()
    }
    # Identifier-like runtime fields survive normally. Free-form runtime labels
    # (for example OpenSSL's build description) retain their complete receipt
    # digest while the existing sanitizer controls the exported label.
    renamed["receipt_sha256"] = hashlib.sha256(encoded).hexdigest()
    renamed["runtime_labels_sanitized"] = True
    return assert_privacy_safe(renamed)


def _prepare_interpreter(python: Path, report: dict) -> None:
    """Provision only the disposable Linux/macOS interpreter after wheel install."""
    record: dict = {"required": sys.platform in {"linux", "darwin"}, "attempted": False}
    report["interpreter_provisioning"] = record
    if not record["required"]:
        record["status"] = "platform_not_selected"
        return
    record["attempted"] = True
    try:
        proof = provision_venv_interpreter(python)
    except InterpreterProvisioningError as error:
        record["evidence"] = _interpreter_receipt(error.evidence)
        raise
    record["evidence"] = _interpreter_receipt(proof)
    if proof.get("passed") is not True:
        raise InterpreterProvisioningError(proof)


def select_prior_artifact(python: Path, root: Path, target: str) -> tuple[Path, dict]:
    """Bound filesystem discovery and hashing separately from other probes."""
    result = _run(
        (
            str(python),
            "-I",
            str(Path(__file__).with_name("installed_transition_prior.py")),
            "--root",
            str(root),
            "--target",
            target,
        ),
        _ROOT,
        timeout_seconds=15,
    )
    if result.timed_out or result.containment_failed or result.output_limit_exceeded:
        raise RuntimeError("qualification_transition_prior_selection_not_contained")
    try:
        value = json.loads(result.stdout)
        if not isinstance(value, dict):
            raise ValueError("qualification_transition_prior_selection_invalid")
        if not _process_ok(result) or value.get("passed") is not True:
            reason = value.get("reason", "")
            if isinstance(reason, str) and re.fullmatch(r"qualification_transition_prior_[a-z_]{1,64}", reason):
                raise RuntimeError(reason)
            raise ValueError("qualification_transition_prior_selection_failed")
        evidence = value["evidence"]
        pin = PRIOR_ARTIFACTS[target]
        if (
            not isinstance(evidence, dict)
            or evidence.get("wheel_sha256") != pin["wheel_sha256"]
            or evidence.get("artifact_id") != pin["artifact_id"]
            or evidence.get("build_sha") != PRIOR_BUILD_SHA
            or evidence.get("target") != target
            or evidence.get("wheel_bytes_verified") is not True
        ):
            raise ValueError("qualification_transition_prior_selection_identity_invalid")
        wheel = Path(value["selected_wheel"]).resolve(strict=True)
        if not wheel.is_relative_to(root.resolve(strict=True)) or wheel.name != pin["wheel_name"]:
            raise ValueError("qualification_transition_prior_selection_path_invalid")
        return wheel, assert_privacy_safe(evidence)
    except (KeyError, TypeError, AttributeError, json.JSONDecodeError) as error:
        raise ValueError("qualification_transition_prior_selection_invalid") from error


def worker_evidence(result, expected: dict, phase: str, *, prior_receipts: int | None = None) -> dict:
    try:
        report = assert_privacy_safe(json.loads(result.stdout))
        if not isinstance(report, Mapping):
            raise ValueError("worker_evidence_invalid")
    except (ValueError, TypeError, RecursionError):
        report = {"passed": False, "failure": {"reason": "worker_evidence_invalid"}}
    identity = report.get("identity")
    plan = _COMPATIBLE_PHASES if phase.startswith("compatible_") else _PHASES
    expected_prior_receipts = (
        prior_receipts
        if prior_receipts is not None
        else 2 * next(index for index, item in enumerate(plan) if item[0] == phase)
    )
    common = (
        report.get("schema") == "hol-guard.installed-artifact-transition-phase.v1"
        and report.get("phase") == phase
        and report.get("cleanup_confirmed") is True
        and type(report.get("control_revision")) is int
        and report["control_revision"] >= 1
        and type(report.get("prior_receipts_verified")) is int
        and report["prior_receipts_verified"] == expected_prior_receipts
        and report.get("stale_control_write_rejected") is True
        and report.get("registration_preserved") is (phase not in {"clean_baseline", "compatible_candidate_start"})
        and report.get("authority_health") == "protected"
        and isinstance(identity, Mapping)
        and identity.get("installed_origin_verified") is True
        and isinstance(identity.get("runtime_sha256"), str)
        and re.fullmatch(r"[0-9a-f]{64}", identity["runtime_sha256"]) is not None
        and all(identity.get(key) == value for key, value in expected.items())
    )
    complete = (
        common
        and _process_ok(result)
        and report.get("passed") is True
        and type(report.get("registered_native_cases")) is int
        and report["registered_native_cases"] == 2
        and (not phase.startswith("compatible_") or identity.get("native_program_supported") is True)
    )
    verified_rejection = (
        common
        and phase == "baseline_rollback"
        and expected.get("build_sha") == AUDITED_BASELINE_SHA
        and result.returncode == 1
        and not result.timed_out
        and not result.containment_failed
        and not result.output_limit_exceeded
        and report.get("passed") is False
        and identity.get("native_program_supported") is False
        and report.get("rejected_legacy_start_verified") is True
        and report.get("persistent_authority_preserved") is True
        and report.get("prior_policy_checkpoint_verified") is True
        and report.get("last_stage") == "native_start"
        and not report.get("registered_native_cases", 0)
        and state_preserved(report.get("policy_before", {}), report.get("policy_after", {}))
        and isinstance(report.get("publisher_at_failure"), Mapping)
        and report.get("publisher_at_failure", {}).get("reason") in LEGACY_REJECTION_REASONS
        and report.get("publisher_at_failure", {}).get("ready") is False
        and report.get("retirement_verification", {}).get("verified") is True
        and report.get("retirement_verification", {}).get("return_code") == 0
        and report.get("retirement_verification", {}).get("timed_out") is False
        and report.get("retirement_verification", {}).get("containment_failed") is False
        and report.get("retirement_verification", {}).get("limit_exceeded") is False
        and "continuation_failure" not in report
    )
    return {
        "phase": phase,
        "passed": complete,
        "verified_legacy_rejection": verified_rejection,
        "worker": report,
        "process": process_metadata(result),
        "worker_timed_out": result.timed_out,
        "worker_containment_failed": result.containment_failed,
        "worker_limit_exceeded": result.output_limit_exceeded,
    }


def suite_acceptance(report: dict) -> dict:
    """Verify seven positive phases and one explicitly expected legacy rejection.

    This contract never changes the legacy phase's failure or the original
    sequence's all-positive result. Recheck retained worker evidence instead of
    trusting a caller-provided success flag or completed counter.
    """
    acceptance = {
        "schema": "hol-guard.installed-transition-acceptance.v1",
        "contract": "compatible_rollback_and_rejected_legacy_restore",
        "available": False,
        "passed": False,
        "required_positive_count": 7,
        "verified_positive_count": 0,
        "required_expected_negative_count": 1,
        "verified_expected_negative_count": 0,
        "original_baseline_functional_downgrade_passed": False,
        "program_qualification_complete": False,
    }
    compatible = report.get("compatible_rollback")
    if report.get("prior_candidate_requested") is not True or not isinstance(compatible, Mapping):
        return acceptance
    acceptance["available"] = True
    try:
        contracts = report["identities"]
        if (
            not isinstance(contracts, Mapping)
            or set(contracts) != {"baseline", "candidate", "prior_candidate"}
            or compatible["identities"] != contracts
            or contracts["baseline"]["build_sha"] != AUDITED_BASELINE_SHA
            or len({item["build_sha"] for item in contracts.values()}) != 3
            or len({item["wheel_sha256"] for item in contracts.values()}) != 3
            or compatible.get("dependency_lock_sha256") != report.get("dependency_lock_sha256")
            or not re.fullmatch(r"[0-9a-f]{64}", report.get("dependency_lock_sha256", ""))
        ):
            return acceptance
        for contract in contracts.values():
            if (
                set(contract) != {"build_sha", "wheel_sha256", "installed_package_sha256"}
                or not re.fullmatch(r"[0-9a-f]{40}", contract["build_sha"])
                or any(
                    not re.fullmatch(r"[0-9a-f]{64}", contract[key])
                    for key in ("wheel_sha256", "installed_package_sha256")
                )
            ):
                return acceptance
        for collection, plan, completed in ((compatible, _COMPATIBLE_PHASES, 3), (report, _PHASES, 4)):
            rows = collection["phases"]
            if (
                not isinstance(rows, list)
                or len(rows) != len(plan)
                or [row["phase"] for row in rows] != [phase for phase, _arm in plan]
                or collection.get("artifact_integrity_verified") is not True
                or collection.get("dependency_integrity_verified") is not True
                or type(collection.get("completed_phase_count")) is not int
                or collection["completed_phase_count"] != completed
                or type(collection.get("required_phase_count")) is not int
                or collection["required_phase_count"] != len(plan)
                or "failure" in collection
                or any(
                    collection.get(key) is not False
                    for key in (
                        "interactive_enrollment_qualified",
                        "live_mixed_generations_qualified",
                        "in_progress_replacement_qualified",
                        "signing_changes_qualified",
                        "version_downgrade_qualified",
                        "native_program_downgrade_qualified",
                        "headline_timing_eligible",
                        "program_qualification_complete",
                    )
                )
            ):
                return acceptance
            prior_receipts = 0
            prior_revision = 0
            for row, (phase, arm) in zip(rows, plan, strict=True):
                worker = row["worker"]
                process = row["process"]
                if (
                    type(process["return_code"]) is not int
                    or any(
                        row.get(key) is not False
                        for key in (
                            "worker_timed_out",
                            "worker_containment_failed",
                            "worker_limit_exceeded",
                        )
                    )
                    or type(worker.get("control_revision")) is not int
                    or worker["control_revision"] < prior_revision
                ):
                    return acceptance
                result = SimpleNamespace(
                    stdout=json.dumps(worker),
                    stderr="",
                    returncode=process["return_code"],
                    timed_out=False,
                    containment_failed=False,
                    output_limit_exceeded=False,
                )
                checked = worker_evidence(result, contracts[arm], phase, prior_receipts=prior_receipts)
                if phase == "baseline_rollback":
                    acceptance["original_baseline_functional_downgrade_passed"] = row.get("passed") is True
                    if (
                        row.get("passed") is not False
                        or not checked["verified_legacy_rejection"]
                        or not isinstance(worker.get("failure"), Mapping)
                        or worker["failure"].get("reason") != "native_installed_slo_failed:_native_policy_was_not_ready"
                        or worker["retirement_verification"].get("publisher_after_close", {}).get("thread_alive")
                        is not False
                    ):
                        return acceptance
                    acceptance["verified_expected_negative_count"] += 1
                else:
                    if (
                        row.get("passed") is not True
                        or not checked["passed"]
                        or "failure" in worker
                        or "failure" in row
                    ):
                        return acceptance
                    if phase == "candidate_restore" and worker.get("restored_after_rejected_legacy") is not True:
                        return acceptance
                    acceptance["verified_positive_count"] += 1
                    prior_receipts += 2
                prior_revision = worker["control_revision"]
        acceptance["passed"] = (
            compatible.get("passed") is True
            and report.get("passed") is False
            and report.get("compatible_artifact_rollback_qualified") is True
            and report.get("original_baseline_downgrade_rejected") is True
            and report.get("candidate_restored_after_rejected_legacy") is True
            and acceptance["verified_positive_count"] == 7
            and acceptance["verified_expected_negative_count"] == 1
        )
    except (KeyError, TypeError, ValueError, AttributeError, RecursionError):
        # Malformed/incomplete evidence remains unaccepted, even if a nested
        # record already declares a successful phase or acceptance result.
        pass
    return acceptance


def public_transition_report(report: Mapping[str, object]) -> dict[str, object]:
    """Omit optional observations when they alone exceed the original bound."""
    try:
        return assert_privacy_safe(report)
    except ValueError:
        phases = report.get("phases")
        if not isinstance(phases, list) or not any(
            isinstance(phase, dict) and "producer_observation" in phase for phase in phases
        ):
            raise
        original = dict(report)
        original["phases"] = [
            {key: value for key, value in phase.items() if key != "producer_observation"}
            if isinstance(phase, dict)
            else phase
            for phase in phases
        ]
        # Reapply the unchanged validation; an oversized original still fails.
        return assert_privacy_safe(original)


def verify(
    python: Path,
    baseline_wheel: Path,
    candidate_wheel: Path,
    baseline_sha: str,
    candidate_sha: str,
    *,
    dependency_root: Path,
    prior_candidate_wheel: Path | None = None,
    prior_candidate_sha: str | None = None,
    compatible_only: bool = False,
) -> dict:
    contracts = {
        "baseline": artifact_contract(baseline_wheel, baseline_sha),
        "candidate": artifact_contract(candidate_wheel, candidate_sha),
    }
    report = {
        "schema": "hol-guard.installed-artifact-transitions.v1",
        "passed": False,
        "identities": contracts,
        "phases": [],
        "scope": "stopped_artifact_replacement_shared_fixture_authority",
        "dependency_environment": "candidate_locked_dependencies",
        "registered_scope": "claude-code.PostToolUse.benign_and_block",
        "paired_installations_modified": False,
        "shared_fixture_state": True,
        "interactive_enrollment_qualified": False,
        "live_mixed_generations_qualified": False,
        "in_progress_replacement_qualified": False,
        "signing_changes_qualified": False,
        "version_downgrade_qualified": False,
        "native_program_downgrade_qualified": False,
        "headline_timing_eligible": False,
        "program_qualification_complete": False,
        "compatible_artifact_rollback_qualified": False,
        "original_baseline_downgrade_rejected": False,
        "candidate_restored_after_rejected_legacy": False,
        "prior_candidate_requested": prior_candidate_wheel is not None or prior_candidate_sha is not None,
        "artifact_integrity_verified": False,
        "dependency_integrity_verified": False,
    }
    try:
        if (prior_candidate_wheel is None) != (prior_candidate_sha is None):
            raise ValueError("qualification_transition_prior_artifact_pair_missing")
        plan = _COMPATIBLE_PHASES if compatible_only else _PHASES
        if prior_candidate_wheel is not None:
            contracts["prior_candidate"] = artifact_contract(prior_candidate_wheel, prior_candidate_sha)
            if (
                prior_candidate_sha == candidate_sha
                or contracts["prior_candidate"]["wheel_sha256"] == contracts["candidate"]["wheel_sha256"]
            ):
                raise ValueError("qualification_transition_requires_distinct_prior_artifact")
        if compatible_only:
            if prior_candidate_wheel is None:
                raise ValueError("qualification_transition_prior_artifact_missing")
            report["scope"] = "stopped_compatible_artifact_rollback_shared_fixture_authority"
        elif prior_candidate_wheel is not None:
            report["compatible_rollback"] = verify(
                python,
                baseline_wheel,
                candidate_wheel,
                baseline_sha,
                candidate_sha,
                dependency_root=dependency_root,
                prior_candidate_wheel=prior_candidate_wheel,
                prior_candidate_sha=prior_candidate_sha,
                compatible_only=True,
            )
            report["compatible_artifact_rollback_qualified"] = report["compatible_rollback"]["passed"] is True
            if any(
                not row["worker"].get("cleanup_confirmed", False) for row in report["compatible_rollback"]["phases"]
            ):
                raise RuntimeError("qualification_transition_prior_cleanup_unverified")
        if (
            baseline_sha == candidate_sha
            or contracts["baseline"]["wheel_sha256"] == contracts["candidate"]["wheel_sha256"]
        ):
            raise ValueError("qualification_transition_requires_distinct_artifacts")
        uv = shutil.which("uv")
        if uv is None:
            raise RuntimeError("qualification_transition_installer_unavailable")
        wheels = {"baseline": baseline_wheel, "candidate": candidate_wheel}
        if prior_candidate_wheel is not None:
            wheels["prior_candidate"] = prior_candidate_wheel
        dependency_lock = sha256(dependency_root / "uv.lock")
        report["dependency_lock_sha256"] = dependency_lock
        with tempfile.TemporaryDirectory(prefix="hol-guard-artifact-transition-") as temporary:
            root = Path(temporary).resolve()
            prefix = root / "installation"
            _required_command((uv, "venv", "--python", str(python), str(prefix)), root)
            worker_python = prefix / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
            _required_command(
                (
                    uv,
                    "sync",
                    "--frozen",
                    "--extra",
                    "dev",
                    "--no-install-project",
                    "--project",
                    str(dependency_root),
                    "--python",
                    str(worker_python),
                ),
                root,
            )
            fixture = root / "fixture"
            fixture.mkdir(mode=0o700)
            prior_receipts = 0
            interpreter_prepared = False
            for phase, arm in plan:
                if sha256(wheels[arm]) != contracts[arm]["wheel_sha256"]:
                    raise RuntimeError("qualification_transition_wheel_changed")
                _required_command(
                    (
                        uv,
                        "pip",
                        "install",
                        "--python",
                        str(worker_python),
                        "--no-index",
                        "--no-deps",
                        "--force-reinstall",
                        str(wheels[arm]),
                    ),
                    root,
                )
                if not interpreter_prepared:
                    # The helper validates against this exact installed wheel's
                    # unchanged managed-file validator. Dependency-only sync is
                    # insufficient, and later replacements reuse the same copy.
                    _prepare_interpreter(worker_python, report)
                    interpreter_prepared = True
                expected = root / "expected.json"
                expected.write_text(json.dumps(contracts[arm]), encoding="utf-8")
                expected.chmod(0o600)
                result = _run(
                    (
                        str(worker_python),
                        "-I",
                        str(Path(__file__).with_name("installed_transition_entry.py")),
                        "--expected",
                        str(expected),
                        "--fixture-root",
                        str(fixture),
                        "--phase",
                        phase,
                    ),
                    root,
                )
                observed = worker_evidence(result, contracts[arm], phase, prior_receipts=prior_receipts)
                if phase == "baseline_rollback":
                    try:
                        from scripts.ci.installed_transition_observer_receipt import collect

                        observed["producer_observation"] = collect(fixture)
                    except Exception:
                        observed["producer_observation"] = {
                            "diagnostic_only": True,
                            "proof_verified": False,
                            "incomplete": ["observation_collector_unavailable"],
                        }
                report["phases"].append(observed)
                # Never overwrite the installation after an unverified native
                # shutdown, even if a malformed worker claims successful work.
                if observed["passed"]:
                    prior_receipts += 2
                elif not observed["verified_legacy_rejection"]:
                    break
            report["passed"] = len(report["phases"]) == len(plan) and all(row["passed"] for row in report["phases"])
            report["original_baseline_downgrade_rejected"] = any(
                row["verified_legacy_rejection"] for row in report["phases"]
            )
            report["candidate_restored_after_rejected_legacy"] = (
                report["original_baseline_downgrade_rejected"]
                and len(report["phases"]) == len(_PHASES)
                and report["phases"][-1]["passed"]
                and report["phases"][-1]["worker"].get("restored_after_rejected_legacy") is True
            )
        if any(sha256(wheels[arm]) != contracts[arm]["wheel_sha256"] for arm in wheels):
            raise RuntimeError("qualification_transition_wheel_changed")
        if sha256(dependency_root / "uv.lock") != dependency_lock:
            raise RuntimeError("qualification_transition_dependency_lock_changed")
        report["artifact_integrity_verified"] = True
        report["dependency_integrity_verified"] = True
    except Exception as error:
        report["passed"] = False
        report["failure"] = _failure_evidence(error)
    report["completed_phase_count"] = sum(row["passed"] for row in report["phases"])
    report["required_phase_count"] = len(_COMPATIBLE_PHASES if compatible_only else _PHASES)
    if compatible_only:
        report["compatible_artifact_rollback_qualified"] = report["passed"]
    report["suite_acceptance"] = suite_acceptance(report)
    return public_transition_report(report)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python", type=Path, required=True)
    parser.add_argument("--baseline-wheel", type=Path, required=True)
    parser.add_argument("--candidate-wheel", type=Path, required=True)
    parser.add_argument("--baseline-sha", required=True)
    parser.add_argument("--candidate-sha", required=True)
    parser.add_argument("--prior-candidate-wheel", type=Path)
    parser.add_argument("--prior-candidate-sha")
    parser.add_argument("--prior-artifact-root", type=Path)
    parser.add_argument("--prior-artifact-target")
    parser.add_argument("--dependency-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    requested = any(
        value is not None
        for value in (
            args.prior_candidate_wheel,
            args.prior_candidate_sha,
            args.prior_artifact_root,
            args.prior_artifact_target,
        )
    )
    prior_evidence = None
    try:
        if (args.prior_artifact_root is None) != (args.prior_artifact_target is None):
            raise ValueError("qualification_transition_prior_artifact_pair_missing")
        if args.prior_artifact_root is not None:
            if args.prior_candidate_wheel is not None or args.prior_candidate_sha is not None:
                raise ValueError("qualification_transition_prior_artifact_inputs_conflict")
            args.prior_candidate_wheel, prior_evidence = select_prior_artifact(
                args.python.absolute(), args.prior_artifact_root.absolute(), args.prior_artifact_target
            )
            args.prior_candidate_sha = PRIOR_BUILD_SHA
        result = verify(
            args.python.absolute(),
            args.baseline_wheel.resolve(),
            args.candidate_wheel.resolve(),
            args.baseline_sha,
            args.candidate_sha,
            dependency_root=args.dependency_root.resolve(),
            prior_candidate_wheel=args.prior_candidate_wheel.resolve() if args.prior_candidate_wheel else None,
            prior_candidate_sha=args.prior_candidate_sha,
        )
        if prior_evidence is not None and (
            result.get("identities", {}).get("prior_candidate", {}).get("wheel_sha256")
            != prior_evidence["wheel_sha256"]
        ):
            result["passed"] = False
            mismatch = _failure_evidence(ValueError("qualification_transition_prior_wheel_changed"))
            result["prior_artifact_validation_failure"] = mismatch
            result.setdefault("failure", mismatch)
            result["suite_acceptance"] = suite_acceptance(result)
    except Exception as error:
        result = {
            "schema": "hol-guard.installed-artifact-transitions.v1",
            "passed": False,
            "prior_candidate_requested": requested,
            "phases": [],
            "completed_phase_count": 0,
            "failure": _failure_evidence(error),
        }
        result["suite_acceptance"] = suite_acceptance(result)
    if prior_evidence is not None:
        result["prior_artifact"] = prior_evidence
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, sort_keys=True), flush=True)
    accepted = (
        result.get("suite_acceptance", {}).get("passed") is True
        if requested or result.get("prior_candidate_requested") is True
        else result["passed"] is True
    )
    return 0 if accepted else 1


if __name__ == "__main__":
    raise SystemExit(main())
