"""CLI preflight and durable setup-recovery orchestration."""

from __future__ import annotations

import argparse
import contextlib
import os
from collections.abc import Mapping
from pathlib import Path
from typing import cast

from . import evaluation_cli as _cli


def run_preflight(args: argparse.Namespace) -> int:
    try:
        profile_path = _cli._path_argument(
            args, "profile_path", "profile_option", "evaluation profile", code="profile_argument_required"
        )
        profile = _cli._load_profile(profile_path)
        artifacts = _cli._artifact_paths(cast(list[str], args.artifact), profile)
        if args.setup:
            if os.name == "nt":
                raise _cli._CliError(
                    "recovery_windows_unavailable",
                    "private recovery token storage is unavailable on Windows",
                    status="blocked_environment",
                )
            setup = _cli.setup_evaluation(
                profile,
                host_executable=args.host_executable,
                artifact_paths=artifacts or None,
                allow_host_execution=bool(args.allow_host_execution),
            )
            report = setup.to_dict()
            cleanup: dict[str, object] | None = None
            if setup.root_path is not None and setup.marker_token is None:
                cleanup = {
                    "removed": False,
                    "recoveryTokenRetained": False,
                    "available": False,
                    "reason": setup.report.reason,
                }
            if setup.root_path is not None and setup.marker_token is not None:
                try:
                    target_scope = cast(Mapping[str, object], profile.data["targetScope"])
                    declared_parent = Path(cast(str, target_scope["rootPath"]))
                    _cli._write_recovery_token(setup, declared_parent=declared_parent)
                except _cli._CliError as error:
                    removed = False
                    with contextlib.suppress(_cli.EvaluationContractError):
                        removed = setup.cleanup()
                    failed_cleanup: dict[str, object] = {
                        "removed": removed,
                        "recoveryTokenRetained": False,
                        "available": False,
                    }
                    if not removed:
                        failed_cleanup.update(ownedRoot=str(setup.root_path), reason="cleanup_incomplete")
                    _cli._emit(
                        _cli._result(
                            "preflight",
                            setup.report.status if setup.report.status != "passed" else "blocked_environment",
                            report=report,
                            error=error,
                            cleanup=failed_cleanup,
                        )
                    )
                    return _cli._exit_code(
                        setup.report.status if setup.report.status != "passed" else "blocked_environment"
                    )
                cleanup = {"available": True, "tokenLocation": "declared_parent", "recoveryTokenRetained": True}
                if setup.report.status != "passed":
                    cleanup.update(removed=False, recoveryTokenRetained=True)
            _cli._emit(_cli._result("preflight", setup.report.status, report=report, cleanup=cleanup))
            return _cli._exit_code(setup.report.status)
        report = _cli.preflight_evaluation(
            profile,
            host_executable=args.host_executable,
            artifact_paths=artifacts or None,
            allow_host_execution=bool(args.allow_host_execution),
        )
        _cli._emit(_cli._result("preflight", report.status, report=report.to_dict()))
        return _cli._exit_code(report.status)
    except _cli._CliError as error:
        _cli._emit(_cli._result("preflight", error.status, error=error))
        return _cli._exit_code(error.status)
