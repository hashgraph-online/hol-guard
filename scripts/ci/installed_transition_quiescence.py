"""Bind stopped legacy rejection to a separately owned descendant boundary.

The installed worker may prepare a private continuation, but only this outer
supervisor can commit it after normal worker exit, kernel child exhaustion,
and unchanged fixture and executable bytes. No installed production code is
patched. Unsupported platforms retain their unverified negative result.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.append(str(_ROOT))

from scripts.ci.installed_transition_owner import run_owned  # noqa: E402
from scripts.native_slo_artifact import _digest  # noqa: E402

AUDITED_BASELINE_SHA = "2e672d2d950c6ec471005ddba46e49bba16dc23b"
_SCHEMA = "hol-guard.installed-transition-quiescence.v1"
_REJECTION = "native_policy_snapshot_unknown_field"
_START_FAILURE = "native_installed_slo_failed:_native_policy_was_not_ready"
_STATE_LIMIT = 256 * 1024
_PENDING = "rejected-legacy-pending.json"


def digest_json(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _mapping(value: object) -> Mapping[str, Any]:
    return cast(Mapping[str, Any], value) if isinstance(value, Mapping) else {}


def enrollment_records_absent(fixture: Path) -> bool:
    # In audited 2e672d2, both load_locked entry points return before secure
    # platform-store access when these signed public records are absent.
    for name in ("approval-authority.v1.json", "approval-authority-v4.json"):
        try:
            (fixture / ".hol-guard" / "native-runtime" / name).lstat()
        except FileNotFoundError:
            continue
        return False
    return True


def private_json(path: Path, *, maximum_bytes: int = _STATE_LIMIT) -> dict[str, Any]:
    if not 0 < maximum_bytes <= _STATE_LIMIT:
        raise ValueError("transition_quiescence_private_file_limit")
    if os.name == "nt":
        from scripts.ci.installed_transition_windows_api import private_file_api

        api = private_file_api()
        if api._windows_path_has_reparse_component(path):
            raise ValueError("transition_quiescence_private_parent_invalid")
        value = api._windows_read_snapshot_bytes(path, maximum_bytes=maximum_bytes)
        if value is None:
            raise FileNotFoundError(path)
        document = json.loads(value)
        if not isinstance(document, dict):
            raise ValueError("transition_quiescence_private_document_invalid")
        return document
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            raise ValueError("transition_quiescence_private_file_invalid")
        value = stream.read(maximum_bytes + 1)
    if len(value) > maximum_bytes:
        raise ValueError("transition_quiescence_private_file_limit")
    document = json.loads(value)
    if not isinstance(document, dict):
        raise ValueError("transition_quiescence_private_document_invalid")
    return document


def write_private(path: Path, value: Mapping[str, Any]) -> None:
    value_bytes = json.dumps(value, sort_keys=True).encode()
    if len(value_bytes) > _STATE_LIMIT:
        raise ValueError("transition_quiescence_private_file_limit")
    pending = path.with_suffix(".pending")
    if os.name == "nt":
        from scripts.ci.installed_transition_windows_api import private_file_api

        api = private_file_api()
        # These are disposable qualification files, not baseline production
        # state. Protect new files through the shipped private handle writer.
        with api._windows_private_directory_binding(path.parent) as binding:
            api._windows_write_private_file_atomic(
                parent_path=binding.path,
                parent_handle=binding.handle,
                temporary_name=pending.name,
                destination_name=path.name,
                payload=value_bytes,
                maximum_bytes=_STATE_LIMIT,
                kind="transition_quiescence_state",
                directory_handles=binding.handles,
            )
        return
    descriptor = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(value_bytes)
        stream.flush()
        os.fsync(stream.fileno())
    pending.replace(path)


def file_pin(path: Path) -> dict[str, Any]:
    if os.name == "nt":
        from scripts.ci.installed_transition_windows_api import source_module

        descriptor = source_module("guard.windows_paths").open_windows_locked_regular_descriptor(path)
    else:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > 256 * 1024 * 1024:
            raise ValueError("transition_quiescence_file_invalid")
        digest = hashlib.sha256()
        total = 0
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            total += len(chunk)
            if total > before.st_size:
                raise ValueError("transition_quiescence_file_grew")
            digest.update(chunk)
        after = os.fstat(stream.fileno())
    fields = ("st_dev", "st_ino", "st_uid", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
    if total != before.st_size or any(getattr(before, field) != getattr(after, field) for field in fields):
        raise ValueError("transition_quiescence_file_changed")
    return {field.removeprefix("st_"): getattr(before, field) for field in fields} | {"sha256": digest.hexdigest()}


def tree_digest(root: Path, *, package: bool = False, identities: bool = False) -> str:
    """Hash a bounded tree, rejecting links and special files instead of omitting them."""
    entries: list[tuple[str, Any]] = []
    total = 0
    for directory, names, files in os.walk(root, followlinks=False):
        if package:
            names[:] = [name for name in names if name != "__pycache__"]
        for name in sorted((*names, *files)):
            path = Path(directory) / name
            relative = path.relative_to(root).as_posix()
            metadata = path.lstat()
            if package and (relative.endswith(".pyc") or name == "__pycache__"):
                continue
            if getattr(metadata, "st_file_attributes", 0) & 0x400:
                raise ValueError("transition_quiescence_tree_member_invalid")
            if stat.S_ISDIR(metadata.st_mode):
                continue
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError("transition_quiescence_tree_member_invalid")
            total += metadata.st_size
            if len(entries) >= 20_000 or total > 256 * 1024 * 1024:
                raise ValueError("transition_quiescence_tree_limit")
            pin = file_pin(path)
            entries.append((relative, pin if identities else pin["sha256"]))
    if package and not identities:
        return _digest(
            ("codex_plugin_scanner/" + name for name, _digest_value in entries),
            lambda name: (root.parent / name).open("rb"),
        )
    return digest_json(sorted(entries))


def code_digest() -> str:
    selected = [
        path
        for base in (_ROOT / "scripts", _ROOT / "ci", _ROOT / "src")
        for path in base.rglob("*.py")
        if "__pycache__" not in path.parts
    ]
    if not 0 < len(selected) < 3000:
        raise ValueError("transition_quiescence_code_inventory_invalid")
    return digest_json([(path.relative_to(_ROOT).as_posix(), file_pin(path)) for path in sorted(selected)])


def installation_pin(python: Path) -> dict[str, Any]:
    prefix = python.parent.parent
    packages = [
        path
        for pattern in ("lib/python*/site-packages/codex_plugin_scanner", "Lib/site-packages/codex_plugin_scanner")
        for path in prefix.glob(pattern)
    ]
    if len(packages) != 1:
        raise ValueError("transition_quiescence_package_inventory_invalid")
    runtime = packages[0] / "_native" / ("hol-guard-runtime.exe" if os.name == "nt" else "hol-guard-runtime")
    return {
        "interpreter": file_pin(python),
        "runtime": file_pin(runtime),
        "installed_package_sha256": tree_digest(packages[0], package=True),
        "package_identity_sha256": tree_digest(packages[0], package=True, identities=True),
    }


def exact_rejection(report: Mapping[str, Any]) -> bool:
    publisher = _mapping(report.get("publisher_at_failure"))
    retirement = _mapping(report.get("retirement_verification"))
    closed = _mapping(retirement.get("publisher_after_close"))
    if any(
        not isinstance(value, Mapping)
        for value in (
            publisher,
            retirement,
            report.get("identity"),
            report.get("failure"),
            retirement.get("publisher_after_close", {}) if isinstance(retirement, Mapping) else None,
        )
    ):
        return False
    return (
        report.get("schema") == "hol-guard.installed-artifact-transition-phase.v1"
        and report.get("phase") == "baseline_rollback"
        and report.get("passed") is False
        and report.get("identity", {}).get("build_sha") == AUDITED_BASELINE_SHA
        and report.get("identity", {}).get("native_program_supported") is False
        and report.get("last_stage") == "native_start"
        and report.get("failure", {}).get("reason") == _START_FAILURE
        and type(report.get("registered_native_cases")) is int
        and report["registered_native_cases"] == 0
        and report.get("native_review_started") is False
        and publisher.get("reason") == _REJECTION
        and publisher.get("ready") is False
        and closed.get("thread_alive") is False
        and closed.get("ready") is False
        and type(retirement.get("active_hook_requests")) is int
        and retirement["active_hook_requests"] == 0
        and retirement.get("return_code") == 2
        and retirement.get("timed_out") is False
        and retirement.get("containment_failed") is False
        and retirement.get("limit_exceeded") is False
        and report.get("legacy_postcheck_verified") is True
        and report.get("persistent_authority_preserved") is True
        and report.get("registration_preserved") is True
        and "continuation_failure" not in report
    )


def certificate_valid(report: Mapping[str, Any], *, prior_retirement_sha256: str | None = None) -> bool:
    proof = _mapping(report.get("quiescence"))
    identity = report.get("identity", {})
    expected = proof.get("artifact", {}) if isinstance(proof, Mapping) else {}
    try:
        return (
            exact_rejection(report)
            and proof.get("schema") == _SCHEMA
            and proof.get("verified") is True
            and _kernel_valid(proof)
            and all(
                proof.get(key) is True
                for key in (
                    "initial_children_empty",
                    "enabled_before_spawn",
                    "worker_exit_observed",
                    "descendants_exhausted",
                    "fixture_unchanged",
                    "installation_unchanged",
                    "code_unchanged",
                    "enrollment_records_absent_before",
                    "enrollment_records_absent_after",
                )
            )
            and all(proof.get(key) is False for key in ("timed_out", "limit_exceeded", "containment_failed"))
            and proof.get("worker_return_code") == 1
            and type(proof.get("worker_return_code")) is int
            and isinstance(proof.get("worker_birth"), str)
            and re.fullmatch(r"[0-9]{1,24}", proof["worker_birth"]) is not None
            and type(proof.get("worker_pid")) is int
            and proof["worker_pid"] > 0
            and all(
                isinstance(proof.get(key), str) and re.fullmatch(r"[0-9a-f]{64}", proof[key])
                for key in (
                    "nonce",
                    "argv_sha256",
                    "code_sha256",
                    "installation_sha256",
                    "fixture_sha256",
                    "worker_report_sha256",
                    "prior_retirement_sha256",
                    "exit_statuses_sha256",
                    "request_sha256",
                )
            )
            and (prior_retirement_sha256 is None or proof["prior_retirement_sha256"] == prior_retirement_sha256)
            and expected == {key: identity[key] for key in ("build_sha", "wheel_sha256", "installed_package_sha256")}
            and proof.get("runtime_sha256") == identity.get("runtime_sha256")
            and proof.get("worker_report_sha256")
            == digest_json(
                {
                    key: value
                    for key, value in report.items()
                    if key not in {"quiescence", "cleanup_confirmed", "rejected_legacy_start_verified"}
                }
                | {"cleanup_confirmed": False}
            )
        )
    except (AttributeError, KeyError, TypeError, ValueError):
        return False


def _kernel_valid(proof: Mapping[str, Any]) -> bool:
    if proof.get("platform") == "linux" and proof.get("mechanism") == "linux_child_subreaper":
        return (
            type(proof.get("reaped_process_count")) is int
            and 1 <= proof["reaped_process_count"] <= 256
            and all(
                type(proof.get(key)) is int and proof[key] == 0
                for key in (
                    "termination_signals_sent",
                    "adopted_signalled_exits",
                )
            )
        )
    if proof.get("platform") == "win32" and proof.get("mechanism") == "windows_job_object":
        return (
            proof.get("job_empty_before_close") is True
            and proof.get("breakaway_disabled") is True
            and type(proof.get("total_process_count")) is int
            and 1 <= proof["total_process_count"] <= 256
            and all(
                type(proof.get(key)) is int and proof[key] == 0
                for key in (
                    "termination_requests",
                    "limit_terminated_count",
                )
            )
        )
    return False


def supervise(request: dict[str, Any], root: Path) -> tuple[dict[str, Any], bytes, int]:
    arguments = tuple(request["arguments"])
    expected = private_json(Path(arguments[arguments.index("--expected") + 1]))
    fixture = Path(arguments[arguments.index("--fixture-root") + 1])
    pins = installation_pin(Path(arguments[0]))
    code = code_digest()
    if (
        request["argv_sha256"] != digest_json(arguments)
        or pins["installed_package_sha256"] != expected["installed_package_sha256"]
        or pins != request["installation"]
        or code != request["code_sha256"]
        or not enrollment_records_absent(fixture)
    ):
        raise ValueError("transition_quiescence_request_binding_invalid")
    environment = dict(os.environ)
    environment["HOL_GUARD_TRANSITION_OWNED_NONCE"] = request["nonce"]
    result = run_owned(arguments, cwd=root, environment=environment)
    try:
        report = json.loads(result.stdout)
        if not isinstance(report, dict):
            raise ValueError("transition_quiescence_worker_document_invalid")
    except (ValueError, TypeError):
        report = {"passed": False, "cleanup_confirmed": False, "failure": {"reason": "worker_evidence_invalid"}}
    evidence = dict(result.evidence)
    evidence.update(
        schema=_SCHEMA,
        nonce=request["nonce"],
        artifact=expected,
        argv_sha256=request["argv_sha256"],
        code_sha256=code,
        installation_sha256=digest_json(pins),
        runtime_sha256=pins["runtime"]["sha256"],
        prior_retirement_sha256=request["prior_retirement_sha256"],
        request_sha256=digest_json(request),
        enrollment_records_absent_before=True,
    )
    evidence["verified"] = False
    try:
        if result.evidence["verified"] and result.returncode == 1 and exact_rejection(report):
            _commit_continuation(report, evidence, request, root, fixture, pins, arguments)
    except (OSError, ValueError, KeyError, TypeError, RuntimeError) as error:
        # A post-worker verification error must not erase the original failure
        # prefix or leave an in-memory success flag after a failed checkpoint.
        evidence.update(verified=False, verification_failure=type(error).__name__)
        report["cleanup_confirmed"] = False
        report.pop("rejected_legacy_start_verified", None)
    report["quiescence"] = evidence
    return report, result.stderr, result.returncode if result.returncode is not None else 1


def _commit_continuation(
    report: dict[str, Any],
    evidence: dict[str, Any],
    request: dict[str, Any],
    root: Path,
    fixture: Path,
    pins: dict[str, Any],
    arguments: tuple[str, ...],
) -> None:
    pending = private_json(root / _PENDING)
    previous = private_json(fixture / "transition-state.json")
    checkpoint = {
        **previous,
        "phase": "baseline_rollback",
        "revision": report["control_revision"],
        "rejected_legacy": True,
        "policy_state": report["policy_before"],
    }
    evidence.update(
        worker_report_sha256=digest_json(report),
        fixture_sha256=tree_digest(fixture),
        installation_unchanged=installation_pin(Path(arguments[0])) == pins,
        code_unchanged=code_digest() == request["code_sha256"],
        enrollment_records_absent_after=enrollment_records_absent(fixture),
    )
    evidence["fixture_unchanged"] = pending["fixture_sha256"] == evidence["fixture_sha256"]
    if (
        evidence["fixture_unchanged"]
        and evidence["installation_unchanged"]
        and evidence["code_unchanged"]
        and evidence["enrollment_records_absent_after"]
        and pending["nonce"] == request["nonce"]
        and pending["worker_report_sha256"] == evidence["worker_report_sha256"]
        and pending["previous_sha256"] == digest_json(previous)
        and pending["checkpoint"] == checkpoint
    ):
        evidence["verified"] = True
        report.update(quiescence=evidence, cleanup_confirmed=True, rejected_legacy_start_verified=True)
        if not certificate_valid(report, prior_retirement_sha256=request["prior_retirement_sha256"]):
            raise ValueError("transition_quiescence_certificate_invalid")
        write_private(fixture / "transition-state.json", pending["checkpoint"])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request", type=Path, required=True)
    args = parser.parse_args()
    report, stderr, returncode = supervise(private_json(args.request), args.request.parent)
    sys.stderr.buffer.write(stderr)
    print(json.dumps(report, sort_keys=True), flush=True)
    return returncode


if __name__ == "__main__":
    raise SystemExit(main())
