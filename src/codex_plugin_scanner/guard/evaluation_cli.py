"""Bounded command line stages for local evaluation records.

The evaluator CLI is deliberately a staging surface.  It validates a declared
profile, optionally allocates the private setup owned by the existing
preflight module, and verifies an evidence archive's canonical bytes.  It does
not run evaluation scenarios or produce installed-host proof.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import re
import stat
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import NoReturn, cast

from ..version import __version__
from .evaluation_contracts import EvaluationContractError, EvaluationProfile
from .evaluation_evidence_package import verify_evaluation_evidence_package
from .evaluation_preflight import (
    EvaluationSetup,
    cleanup_interrupted_evaluation_setup,
    preflight_evaluation,
    setup_evaluation,
)

CLI_SCHEMA_VERSION = "guard.evaluation-cli.v1"
_MAX_PROFILE_BYTES = 1 * 1024 * 1024
_MAX_EVIDENCE_BYTES = 64 * 1024 * 1024
_MAX_RECOVERY_TOKEN_BYTES = 128
_RECOVERY_TOKEN_PREFIX = ".hol-guard-evaluation-recovery-"
_RECOVERY_TOKEN_SUFFIX = ".token"
_RECOVERY_TOKEN_PATTERN = re.compile(r"[0-9a-f]{32}")


class _CliError(ValueError):
    """An expected input or environment failure with a stable public code."""

    def __init__(self, code: str, message: str, *, status: str = "not_run") -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status


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
    cleanup: Mapping[str, object] | None = None,
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
    if cleanup is not None:
        payload["cleanup"] = dict(cleanup)
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


def _load_profile(path: Path) -> EvaluationProfile:
    data = _read_bounded(
        path,
        _MAX_PROFILE_BYTES,
        too_large_code="profile_too_large",
        read_code="profile_read_failed",
        label="evaluation profile",
    )
    try:
        payload = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        raise _CliError("profile_json_invalid", "evaluation profile is not valid JSON") from None
    if not isinstance(payload, Mapping):
        raise _CliError("profile_invalid", "evaluation profile is invalid")
    try:
        return EvaluationProfile.from_dict(cast(Mapping[str, object], payload))
    except (EvaluationContractError, KeyError, TypeError, ValueError):
        raise _CliError("profile_invalid", "evaluation profile is invalid") from None


def _path_argument(args: argparse.Namespace, positional: str, option: str, label: str) -> Path:
    positional_value = cast(str | None, getattr(args, positional, None))
    option_value = cast(str | None, getattr(args, option, None))
    if (positional_value is None) == (option_value is None):
        raise _CliError("profile_argument_required", f"provide exactly one {label} path")
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


def _private_recovery_parent(path: Path) -> bool:
    try:
        if "\x00" in os.fspath(path) or path.is_symlink() or not path.is_dir():
            return False
        details = path.stat()
        if not stat.S_ISDIR(details.st_mode):
            return False
        if hasattr(os, "getuid") and details.st_uid != os.getuid():
            return False
        return stat.S_IMODE(details.st_mode) & 0o077 == 0
    except (OSError, RuntimeError, ValueError):
        return False


def _recovery_token_path(owned_root: Path, *, declared_parent: Path | None = None) -> Path:
    if not owned_root.is_absolute() or not owned_root.name.startswith("hol-guard-eval-"):
        raise _CliError("recovery_path_invalid", "evaluation recovery path is invalid", status="blocked_environment")
    parent = owned_root.parent
    if declared_parent is not None:
        try:
            same_parent = os.path.normcase(os.path.realpath(parent)) == os.path.normcase(
                os.path.realpath(declared_parent)
            )
        except (OSError, RuntimeError, ValueError):
            same_parent = False
        if not same_parent:
            raise _CliError(
                "recovery_path_invalid",
                "evaluation recovery path is outside the profile target scope",
                status="blocked_environment",
            )
    if not _private_recovery_parent(parent):
        raise _CliError(
            "recovery_path_invalid",
            "evaluation recovery parent is not a private directory",
            status="blocked_environment",
        )
    return parent / f"{_RECOVERY_TOKEN_PREFIX}{owned_root.name}{_RECOVERY_TOKEN_SUFFIX}"


def _validate_recovery_token_file(token_path: Path, *, expected_parent: Path) -> None:
    try:
        if token_path.parent != expected_parent or token_path.is_symlink() or not token_path.is_file():
            raise _CliError(
                "recovery_token_invalid", "evaluation recovery token is invalid", status="blocked_environment"
            )
        details = token_path.stat()
        if not stat.S_ISREG(details.st_mode):
            raise _CliError(
                "recovery_token_invalid", "evaluation recovery token is invalid", status="blocked_environment"
            )
        if hasattr(os, "getuid") and details.st_uid != os.getuid():
            raise _CliError(
                "recovery_token_invalid", "evaluation recovery token is invalid", status="blocked_environment"
            )
        if stat.S_IMODE(details.st_mode) != 0o600:
            raise _CliError(
                "recovery_token_invalid", "evaluation recovery token is invalid", status="blocked_environment"
            )
    except (OSError, RuntimeError, ValueError):
        raise _CliError(
            "recovery_token_invalid", "evaluation recovery token is invalid", status="blocked_environment"
        ) from None


def _write_recovery_token(setup: EvaluationSetup) -> None:
    if setup.root_path is None or setup.marker_token is None:
        raise _CliError("cleanup_token_unavailable", "evaluation setup did not produce a cleanup token")
    token_path = _recovery_token_path(setup.root_path)
    descriptor: int | None = None
    created = False
    completed = False
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(os.fspath(token_path), flags, 0o600)
        created = True
        details = os.fstat(descriptor)
        if not stat.S_ISREG(details.st_mode) or (
            hasattr(os, "getuid") and details.st_uid != os.getuid()
        ) or stat.S_IMODE(details.st_mode) != 0o600:
            raise OSError("recovery token file ownership or mode is unsafe")
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = None
            stream.write(setup.marker_token.encode("ascii"))
            stream.flush()
            os.fsync(stream.fileno())
        completed = True
    except (OSError, UnicodeError, ValueError):
        raise _CliError("cleanup_token_unavailable", "unable to retain the private cleanup token") from None
    finally:
        if descriptor is not None:
            with contextlib.suppress(OSError):
                os.close(descriptor)
        if created and not completed:
            with contextlib.suppress(OSError, RuntimeError, ValueError):
                token_path.unlink()


def _read_recovery_token(owned_root: Path, *, declared_parent: Path) -> str:
    try:
        token_path = _recovery_token_path(owned_root, declared_parent=declared_parent)
        if not token_path.exists() and not token_path.is_symlink():
            raise _CliError(
                "recovery_token_missing", "evaluation recovery token is missing", status="blocked_environment"
            )
        _validate_recovery_token_file(token_path, expected_parent=owned_root.parent)
        descriptor = os.open(os.fspath(token_path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except _CliError:
        raise
    except FileNotFoundError:
        raise _CliError(
            "recovery_token_missing", "evaluation recovery token is missing", status="blocked_environment"
        ) from None
    except (OSError, RuntimeError, ValueError):
        raise _CliError(
            "recovery_token_invalid", "evaluation recovery token is invalid", status="blocked_environment"
        ) from None
    try:
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            data = stream.read(_MAX_RECOVERY_TOKEN_BYTES + 1)
    except (OSError, ValueError):
        raise _CliError(
            "recovery_token_invalid", "evaluation recovery token is invalid", status="blocked_environment"
        ) from None
    finally:
        if descriptor >= 0:
            with contextlib.suppress(OSError):
                os.close(descriptor)
    if len(data) > _MAX_RECOVERY_TOKEN_BYTES:
        raise _CliError("recovery_token_invalid", "evaluation recovery token is invalid", status="blocked_environment")
    try:
        token = data.decode("ascii")
    except UnicodeDecodeError:
        raise _CliError(
            "recovery_token_invalid", "evaluation recovery token is invalid", status="blocked_environment"
        ) from None
    if _RECOVERY_TOKEN_PATTERN.fullmatch(token) is None:
        raise _CliError("recovery_token_invalid", "evaluation recovery token is invalid", status="blocked_environment")
    return token


def _remove_recovery_token(token_path: Path, *, expected_parent: Path) -> None:
    _validate_recovery_token_file(token_path, expected_parent=expected_parent)
    try:
        token_path.unlink()
    except (OSError, RuntimeError, ValueError):
        raise _CliError(
            "cleanup_failed", "unable to remove the private cleanup token", status="blocked_environment"
        ) from None


def _run_preflight(args: argparse.Namespace) -> int:
    try:
        profile_path = _path_argument(args, "profile_path", "profile_option", "evaluation profile")
        profile = _load_profile(profile_path)
        artifacts = _artifact_paths(cast(list[str], args.artifact), profile)
        if args.setup:
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
                    _write_recovery_token(setup)
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


def _run_verify_evidence(args: argparse.Namespace) -> int:
    try:
        package_path = _path_argument(args, "package_path", "package_option", "evidence package")
        data = _read_bounded(
            package_path,
            _MAX_EVIDENCE_BYTES,
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


def _run_cleanup(args: argparse.Namespace) -> int:
    try:
        profile_path = _path_argument(args, "profile_path", "profile_option", "evaluation profile")
        root_path = _path_argument(args, "owned_root_path", "owned_root_option", "owned setup")
        profile = _load_profile(profile_path)
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
        if removed:
            _remove_recovery_token(token_path, expected_parent=declared_parent)
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
    """Build the standalone staged evaluation parser."""

    parser = _EvaluationArgumentParser(
        prog="hol-guard-eval",
        description="Validate bounded local evaluation stages without running scenarios.",
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

    verify_evidence = subparsers.add_parser(
        "verify-evidence",
        help="verify canonical hashes and contracts in an evidence package",
    )
    verify_evidence.add_argument("package_path", nargs="?", help="evaluation evidence ZIP path")
    verify_evidence.add_argument("--package", dest="package_option", help="evaluation evidence ZIP path")

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
    if args.command == "verify-evidence":
        return _run_verify_evidence(args)
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
