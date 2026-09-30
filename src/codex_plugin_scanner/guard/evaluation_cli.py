"""Bounded command line stages for local evaluation records.

The evaluator CLI is deliberately a preparation surface.  It validates a declared
profile, optionally allocates the private setup owned by the existing
preflight module, runs fixed synthetic adapter cases, packages validated
records, and verifies an evidence archive's canonical bytes.  The synthetic
runner does not produce installed-host proof.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import NoReturn, cast

from ..version import __version__
from .evaluation_cli_package_errors import package_write_error
from .evaluation_cli_recovery import (
    _CliError,
    _read_recovery_token,
    _recovery_token_path,
    _remove_recovery_token,
    _write_recovery_token,
)
from .evaluation_cli_run import run_synthetic_command
from .evaluation_contracts import EvaluationContractError, EvaluationProfile, EvaluationResult
from .evaluation_evidence_package import (
    EVALUATION_PROOF_BOUNDARY,
    MAX_EVIDENCE_PACKAGE_BYTES,
    verify_evaluation_evidence_package,
    write_evaluation_evidence_package,
)
from .evaluation_json import reject_duplicate_keys
from .evaluation_preflight import (
    cleanup_interrupted_evaluation_setup,
    preflight_evaluation,
    setup_evaluation,
)
from .evaluation_runner import BUILT_IN_CASE_IDS

CLI_SCHEMA_VERSION = "guard.evaluation-cli.v1"
_MAX_PROFILE_BYTES = 1 * 1024 * 1024
_MAX_RESULT_BYTES = 1 * 1024 * 1024


class _EvaluationArgumentParser(argparse.ArgumentParser):
    """Keep command-line failures on the same JSON status surface."""

    def error(self, message: str) -> NoReturn:
        del message
        raise _CliError("usage_error", "invalid evaluation command arguments")


def _error_payload(error: _CliError) -> dict[str, object]:
    return {"code": error.code, "message": error.message}


def _result(
    command: str,
    status: str,
    *,
    report: Mapping[str, object] | None = None,
    manifest: Mapping[str, object] | None = None,
    package: Mapping[str, object] | None = None,
    cleanup: Mapping[str, object] | None = None,
    run: Mapping[str, object] | None = None,
    error: _CliError | None = None,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "schemaVersion": CLI_SCHEMA_VERSION,
        "command": command,
        "status": status,
    }
    if report is not None:
        payload["report"] = dict(report)
    if manifest is not None:
        payload["manifest"] = dict(manifest)
    if package is not None:
        payload["package"] = dict(package)
    if cleanup is not None:
        payload["cleanup"] = dict(cleanup)
    if run is not None:
        payload["run"] = dict(run)
    if error is not None:
        payload["error"] = _error_payload(error)
    return payload


def _emit(payload: Mapping[str, object]) -> None:
    print(json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True))


def _exit_code(status: str) -> int:
    return 0 if status == "passed" else 2


def _read_bounded(path: Path, limit: int, *, too_large_code: str, read_code: str, label: str) -> bytes:
    try:
        with path.open("rb") as stream:
            data = stream.read(limit + 1)
    except (OSError, ValueError):
        raise _CliError(read_code, f"unable to read {label}", status="blocked_environment") from None
    if len(data) > limit:
        raise _CliError(too_large_code, f"{label} exceeds the configured input limit", status="blocked_environment")
    return data


def _reject_json_constant(value: str) -> NoReturn:
    del value
    raise ValueError("non-standard JSON constant")


def _load_json(data: bytes) -> object:
    return json.loads(
        data.decode("utf-8"),
        object_pairs_hook=reject_duplicate_keys,
        parse_constant=_reject_json_constant,
    )


def _load_profile(path: Path) -> EvaluationProfile:
    data = _read_bounded(
        path,
        _MAX_PROFILE_BYTES,
        too_large_code="profile_too_large",
        read_code="profile_read_failed",
        label="evaluation profile",
    )
    try:
        payload = _load_json(data)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
        raise _CliError("profile_json_invalid", "evaluation profile is not valid JSON") from None
    if not isinstance(payload, Mapping):
        raise _CliError("profile_invalid", "evaluation profile is invalid")
    try:
        return EvaluationProfile.from_dict(cast(Mapping[str, object], payload))
    except (EvaluationContractError, KeyError, TypeError, ValueError):
        raise _CliError("profile_invalid", "evaluation profile is invalid") from None


def _load_result(path: Path, profile: EvaluationProfile) -> EvaluationResult:
    data = _read_bounded(
        path,
        _MAX_RESULT_BYTES,
        too_large_code="result_too_large",
        read_code="result_read_failed",
        label="evaluation result",
    )
    try:
        payload = _load_json(data)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
        raise _CliError("result_json_invalid", "evaluation result is not valid JSON") from None
    if not isinstance(payload, Mapping):
        raise _CliError("result_invalid", "evaluation result is invalid")
    try:
        return EvaluationResult.from_dict(cast(Mapping[str, object], payload), profile=profile)
    except (EvaluationContractError, KeyError, TypeError, ValueError):
        # Contract diagnostics may include caller-controlled values. Keep the
        # CLI response stable and value-free.
        raise _CliError("result_invalid", "evaluation result is invalid") from None


def _path_argument(args: argparse.Namespace, positional: str, option: str, label: str, *, code: str) -> Path:
    positional_value = cast(str | None, getattr(args, positional, None))
    option_value = cast(str | None, getattr(args, option, None))
    if (positional_value is None) == (option_value is None):
        raise _CliError(code, f"provide exactly one {label} path")
    value = positional_value if positional_value is not None else option_value
    assert value is not None
    try:
        return Path(value)
    except (TypeError, ValueError):
        raise _CliError("path_invalid", f"{label} path is invalid") from None


def _artifact_paths(specs: Sequence[str], profile: EvaluationProfile) -> dict[str, Path]:
    declared = {
        str(cast(Mapping[str, object], item)["artifactId"])
        for item in cast(list[object], profile.data["installedArtifacts"])
    }
    paths: dict[str, Path] = {}
    for spec in specs:
        artifact_id, separator, raw_path = spec.partition("=")
        if not separator or not artifact_id or not raw_path:
            raise _CliError("artifact_argument_invalid", "artifact must use ARTIFACT_ID=ABSOLUTE_PATH")
        if artifact_id not in declared:
            raise _CliError("artifact_not_declared", "artifact is not declared by the evaluation profile")
        if artifact_id in paths:
            raise _CliError("artifact_argument_duplicate", "artifact was supplied more than once")
        try:
            path = Path(raw_path)
        except (TypeError, ValueError):
            raise _CliError("artifact_argument_invalid", "artifact must use ARTIFACT_ID=ABSOLUTE_PATH") from None
        if not path.is_absolute():
            raise _CliError("artifact_argument_invalid", "artifact must use ARTIFACT_ID=ABSOLUTE_PATH")
        paths[artifact_id] = path
    return paths


def _run_preflight(args: argparse.Namespace) -> int:
    try:
        profile_path = _path_argument(
            args, "profile_path", "profile_option", "evaluation profile", code="profile_argument_required"
        )
        profile = _load_profile(profile_path)
        artifacts = _artifact_paths(cast(list[str], args.artifact), profile)
        if args.setup:
            if os.name == "nt":
                raise _CliError(
                    "recovery_windows_unavailable",
                    "private recovery token storage is unavailable on Windows",
                    status="blocked_environment",
                )
            setup = setup_evaluation(
                profile,
                host_executable=args.host_executable,
                artifact_paths=artifacts or None,
                allow_host_execution=bool(args.allow_host_execution),
            )
            report = setup.to_dict()
            cleanup: dict[str, object] | None = None
            if setup.report.status == "passed":
                try:
                    target_scope = cast(Mapping[str, object], profile.data["targetScope"])
                    declared_parent = Path(cast(str, target_scope["rootPath"]))
                    _write_recovery_token(setup, declared_parent=declared_parent)
                except _CliError as error:
                    with contextlib.suppress(EvaluationContractError):
                        setup.cleanup()
                    _emit(_result("preflight", error.status, report=report, error=error))
                    return _exit_code(error.status)
                cleanup = {"available": True, "tokenLocation": "declared_parent"}
            _emit(_result("preflight", setup.report.status, report=report, cleanup=cleanup))
            return _exit_code(setup.report.status)
        report = preflight_evaluation(
            profile,
            host_executable=args.host_executable,
            artifact_paths=artifacts or None,
            allow_host_execution=bool(args.allow_host_execution),
        )
        _emit(_result("preflight", report.status, report=report.to_dict()))
        return _exit_code(report.status)
    except _CliError as error:
        _emit(_result("preflight", error.status, error=error))
        return _exit_code(error.status)


def _run_synthetic(args: argparse.Namespace) -> int:
    """Run fixed local adapters while keeping recovery outside the setup root."""

    if os.name == "nt":
        error = _CliError(
            "recovery_windows_unavailable",
            "private recovery token storage is unavailable on Windows",
            status="blocked_environment",
        )
        _emit(_result("run", error.status, error=error))
        return _exit_code(error.status)
    try:
        profile_path = _path_argument(
            args, "profile_path", "profile_option", "evaluation profile", code="profile_argument_required"
        )
        profile = _load_profile(profile_path)
        requested = tuple(cast(list[str], args.case)) if args.case else None
        result = run_synthetic_command(profile, requested)
    except _CliError as error:
        _emit(_result("run", error.status, error=error))
        return _exit_code(error.status)
    _emit(_result("run", result.status, run=result.run, cleanup=result.cleanup, error=result.error))
    return _exit_code(result.status)


def _run_verify_evidence(args: argparse.Namespace) -> int:
    try:
        package_path = _path_argument(
            args,
            "package_path",
            "package_option",
            "evidence package",
            code="evidence_package_argument_required",
        )
        data = _read_bounded(
            package_path,
            MAX_EVIDENCE_PACKAGE_BYTES,
            too_large_code="evidence_package_too_large",
            read_code="evidence_package_read_failed",
            label="evaluation evidence package",
        )
        try:
            manifest = verify_evaluation_evidence_package(data)
        except (EvaluationContractError, OSError, RecursionError, RuntimeError):
            error = _CliError(
                "evidence_package_invalid",
                "evaluation evidence package is invalid",
                status="failed",
            )
            _emit(_result("verify-evidence", error.status, error=error))
            return _exit_code(error.status)
        _emit(_result("verify-evidence", "passed", manifest=manifest))
        return 0
    except _CliError as error:
        _emit(_result("verify-evidence", error.status, error=error))
        return _exit_code(error.status)


def _run_package_evidence(args: argparse.Namespace) -> int:
    try:
        profile_path = _path_argument(
            args, "profile_path", "profile_option", "evaluation profile", code="profile_argument_required"
        )
        result_path = _path_argument(
            args, "result_path", "result_option", "evaluation result", code="result_argument_required"
        )
        output_dir = _path_argument(
            args,
            "output_dir_path",
            "output_dir_option",
            "evidence output directory",
            code="output_dir_argument_required",
        )
        profile = _load_profile(profile_path)
        result = _load_result(result_path, profile)
        try:
            package = write_evaluation_evidence_package(profile, result, output_dir=output_dir)
        except EvaluationContractError as error:
            mapped = package_write_error(error)
            _emit(_result("package-evidence", mapped.status, error=mapped))
            return _exit_code(mapped.status)
        _emit(
            _result(
                "package-evidence",
                "passed",
                package={
                    "digest": package.digest,
                    "path": str(package.path),
                    "proofBoundary": EVALUATION_PROOF_BOUNDARY,
                    "sizeBytes": package.size_bytes,
                },
            )
        )
        return 0
    except _CliError as error:
        _emit(_result("package-evidence", error.status, error=error))
        return _exit_code(error.status)


def _run_cleanup(args: argparse.Namespace) -> int:
    try:
        profile_path = _path_argument(
            args, "profile_path", "profile_option", "evaluation profile", code="profile_argument_required"
        )
        root_path = _path_argument(
            args, "owned_root_path", "owned_root_option", "owned setup", code="owned_root_argument_required"
        )
        profile = _load_profile(profile_path)
        if os.name == "nt":
            raise _CliError(
                "recovery_windows_unavailable",
                "private recovery token storage is unavailable on Windows",
                status="blocked_environment",
            )
        target_scope = cast(Mapping[str, object], profile.data["targetScope"])
        declared_parent = Path(cast(str, target_scope["rootPath"]))
        token_path = _recovery_token_path(root_path, declared_parent=declared_parent)
        token = _read_recovery_token(root_path, declared_parent=declared_parent)
        try:
            removed = cleanup_interrupted_evaluation_setup(
                profile,
                owned_root=root_path,
                marker_token=token,
            )
        except EvaluationContractError as exc:
            error = _CliError("cleanup_rejected", str(exc), status="blocked_environment")
            _emit(_result("cleanup", error.status, error=error))
            return _exit_code(error.status)
        _remove_recovery_token(token_path, expected_parent=Path(os.path.realpath(declared_parent)))
        status = "passed" if removed else "not_run"
        cleanup: dict[str, object] = {"removed": removed}
        if not removed:
            cleanup["reason"] = "setup_missing"
        _emit(_result("cleanup", status, cleanup=cleanup))
        return _exit_code(status)
    except _CliError as error:
        _emit(_result("cleanup", error.status, error=error))
        return _exit_code(error.status)


def build_parser() -> argparse.ArgumentParser:
    """Build the bounded evaluation parser."""

    parser = _EvaluationArgumentParser(
        prog="hol-guard-eval",
        description="Validate bounded local evaluation stages and fixed synthetic adapters.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
        parser_class=_EvaluationArgumentParser,
    )

    preflight = subparsers.add_parser(
        "preflight",
        help="validate a profile and declared local prerequisites",
    )
    preflight.add_argument("profile_path", nargs="?", help="evaluation profile JSON path")
    preflight.add_argument("--profile", dest="profile_option", help="evaluation profile JSON path")
    preflight.add_argument(
        "--artifact",
        action="append",
        default=[],
        metavar="ARTIFACT_ID=ABSOLUTE_PATH",
        help="artifact bytes to hash; may be supplied once per declared artifact",
    )
    preflight.add_argument("--host-executable", help="override the profile's host executable path")
    preflight.add_argument(
        "--allow-host-execution",
        action="store_true",
        help="enable the bounded host --version probe; use only inside an isolated evaluation VM",
    )
    preflight.add_argument(
        "--setup",
        action="store_true",
        help="allocate an owned setup after a passed preflight and retain a private cleanup token",
    )

    run = subparsers.add_parser(
        "run",
        help="run built-in disposable shell/file and loopback synthetic adapters",
    )
    run.add_argument("profile_path", nargs="?", help="evaluation profile JSON path")
    run.add_argument("--profile", dest="profile_option", help="evaluation profile JSON path")
    run.add_argument(
        "--case",
        action="append",
        choices=BUILT_IN_CASE_IDS,
        default=[],
        help="built-in case ID; repeat only to cover the profile capabilities",
    )

    verify_evidence = subparsers.add_parser(
        "verify-evidence",
        help="verify canonical hashes and contracts in an evidence package",
    )
    verify_evidence.add_argument("package_path", nargs="?", help="evaluation evidence ZIP path")
    verify_evidence.add_argument("--package", dest="package_option", help="evaluation evidence ZIP path")

    package_evidence = subparsers.add_parser(
        "package-evidence",
        help="package validated profile and result records in a private temporary root",
    )
    package_evidence.add_argument("profile_path", nargs="?", help="evaluation profile JSON path")
    package_evidence.add_argument("result_path", nargs="?", help="evaluation result JSON path")
    package_evidence.add_argument("output_dir_path", nargs="?", help="private evidence output directory")
    package_evidence.add_argument("--profile", dest="profile_option", help="evaluation profile JSON path")
    package_evidence.add_argument("--result", dest="result_option", help="evaluation result JSON path")
    package_evidence.add_argument("--output-dir", dest="output_dir_option", help="private evidence output directory")

    cleanup = subparsers.add_parser(
        "cleanup",
        help="remove one setup previously allocated by preflight --setup",
    )
    cleanup.add_argument("profile_path", nargs="?", help="evaluation profile JSON path")
    cleanup.add_argument("owned_root_path", nargs="?", help="owned setup root reported by preflight --setup")
    cleanup.add_argument("--profile", dest="profile_option", help="evaluation profile JSON path")
    cleanup.add_argument("--owned-root", dest="owned_root_option", help="owned setup root path")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run one staged evaluation command and emit exactly one JSON result."""

    parser = build_parser()
    try:
        args = parser.parse_args(list(argv) if argv is not None else None)
    except _CliError as error:
        _emit(_result("cli", error.status, error=error))
        return _exit_code(error.status)
    except SystemExit as exc:
        return int(exc.code) if isinstance(exc.code, int) else 2
    if args.command == "preflight":
        return _run_preflight(args)
    if args.command == "run":
        return _run_synthetic(args)
    if args.command == "verify-evidence":
        return _run_verify_evidence(args)
    if args.command == "package-evidence":
        return _run_package_evidence(args)
    if args.command == "cleanup":
        return _run_cleanup(args)
    _emit(
        _result(
            str(args.command),
            "not_run",
            error=_CliError("command_unsupported", "evaluation command is unsupported"),
        )
    )
    return 2


__all__ = ["CLI_SCHEMA_VERSION", "build_parser", "main"]


if __name__ == "__main__":
    raise SystemExit(main())
