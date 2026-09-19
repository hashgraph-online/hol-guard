"""Qualify retained Python Secrets through a supplied wheel's real launchers.

Run using that installation's Python with -I. All scan inputs are generated
locally. Receipts contain identities, dimensions and result digests, never
input credentials, full CLI payloads, private paths or raw exception text.
The optional mutation worker loads the installed distribution's entrypoint
under a deterministic filesystem race; ordinary cases execute its launcher.
"""

from __future__ import annotations

import argparse as argparse
import ast as ast
import base64 as base64
import csv as csv
import errno as errno
import hashlib as hashlib
import hmac as hmac
import importlib as importlib
import importlib.metadata
import io as io
import json as json
import math as math
import ntpath as ntpath
import os as os
import platform as platform
import re as re
import subprocess as subprocess
import sys as sys
import sysconfig as sysconfig
import tempfile as tempfile
import time as time
import zipfile as zipfile
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

if not __package__:
    # Match the other installed probes while retaining wheel import attestation.
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    sys.modules["ci.native_runtime.probe_installed_offline_secrets"] = sys.modules[__name__]

from ci.native_runtime.probe_installed_offline_secrets_cases import (
    _exercise as _exercise,
)
from ci.native_runtime.probe_installed_offline_secrets_cases import (
    _links_fixture as _links_fixture,
)
from ci.native_runtime.probe_installed_offline_secrets_cases import (
    _rich_fixture as _rich_fixture,
)
from ci.native_runtime.probe_installed_offline_secrets_cases import (
    _write_files as _write_files,
)
from ci.native_runtime.probe_installed_offline_secrets_identity import (
    _attest as _attest,
)
from ci.native_runtime.probe_installed_offline_secrets_identity import (
    _launcher_binding as _launcher_binding,
)
from ci.native_runtime.probe_installed_offline_secrets_identity import (
    _launcher_wrapper as _launcher_wrapper,
)
from ci.native_runtime.probe_installed_offline_secrets_identity import (
    _windows_launcher_resources as _windows_launcher_resources,
)
from ci.native_runtime.probe_installed_offline_secrets_identity import (
    _wrapper_templates as _wrapper_templates,
)

_BODY = "7tH3mZ5qP9vC2xL4nR6sB8wF1jK0dE5uA7iY"
_PROVIDERS = (
    ("github-token", "GITHUB_TOKEN", "ghp_" + _BODY),
    ("gitlab-token", "GITLAB_TOKEN", "glpat-" + _BODY),
    ("aws-access-key", "AWS_ACCESS_KEY_ID", "AKIA" + "7H3MZ5QP9VC2XL4N"),
    ("slack-token", "SLACK_TOKEN", "xoxb-" + _BODY),
    ("slack-webhook", "SLACK_WEBHOOK", "https://hooks.slack.com/services/" + _BODY),
    ("stripe-secret-key", "STRIPE_SECRET_KEY", "sk_live_" + _BODY),
    ("openai-api-key", "OPENAI_API_KEY", "sk-proj-" + _BODY),
    ("anthropic-api-key", "ANTHROPIC_API_KEY", "sk-ant-" + _BODY),
    ("huggingface-token", "HF_TOKEN", "hf_" + _BODY),
    ("npm-token", "NPM_TOKEN", "npm_" + _BODY),
    ("pypi-token", "PYPI_TOKEN", "pypi-" + _BODY),
    ("google-api-key", "GOOGLE_API_KEY", "AIza" + _BODY[:35]),
    ("sendgrid-api-key", "SENDGRID_API_KEY", "SG." + _BODY + "." + _BODY[::-1]),
    ("pem-private-key", "PRIVATE_KEY", "-----BEGIN " + "PRIVATE KEY-----"),
    ("database-url-password", "DATABASE_PASSWORD_URL", "postgres://service:" + _BODY + "@localhost/app"),
    ("basic-auth-url-password", "AUTH_PASSWORD_URL", "https://service:" + _BODY + "@localhost/api"),
    ("jwt-token", "AUTH_TOKEN", "eyJ" + _BODY + "." + _BODY[::-1] + "." + _BODY),
)
_PUBLIC_KEYS = {
    "schema",
    "detector_version",
    "files_scanned",
    "commits_scanned",
    "bytes_scanned",
    "history_enabled",
    "truncated",
    "truncation_reasons",
    "finding_count",
    "findings",
    "errors",
}
_FINDING_KEYS = {
    "rule_id",
    "family",
    "severity",
    "confidence",
    "confidence_score",
    "line",
    "path",
    "source",
    "commit",
    "validation",
    "entropy",
    "context_reasons",
}
_MODULES = (
    "codex_plugin_scanner.cli",
    "codex_plugin_scanner.path_support",
    "codex_plugin_scanner.guard.secrets.cli",
    "codex_plugin_scanner.guard.secrets.secret_detection",
    "codex_plugin_scanner.guard.secrets.secret_repository_scanner",
    "codex_plugin_scanner.guard.secrets.secret_staged_scanner",
    "codex_plugin_scanner.guard.secrets.git_blob_scan_cache",
    "codex_plugin_scanner.guard.secrets.git_object_reader",
)
_MAX_OUTPUT = 2 * 1024 * 1024
_MAX_LAUNCHER = 4 * 1024 * 1024
_MAX_WRAPPER = 8192


class ProbeError(RuntimeError):
    """Only fixed, non-sensitive codes may be included in a receipt."""


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise ProbeError(code)


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _probe_source_digests() -> dict[str, str]:
    """Bind the entry point and every partition that supplies its executable code."""
    root = Path(__file__).parent
    return {
        name: _digest((root / name).read_bytes())
        for name in (
            "probe_installed_offline_secrets.py",
            "probe_installed_offline_secrets_api.py",
            "probe_installed_offline_secrets_identity.py",
            "probe_installed_offline_secrets_cases.py",
        )
    }


def _public_digest(value: object) -> str:
    return _digest(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


def _unsupported_link(error: OSError | NotImplementedError) -> bool:
    return (
        isinstance(error, NotImplementedError)
        or error.errno
        in {
            errno.EACCES,
            errno.EPERM,
            errno.ENOSYS,
            errno.EOPNOTSUPP,
        }
        or getattr(error, "winerror", None) == 1314
    )


def _environment() -> dict[str, str]:
    prefixes = ("HOL_GUARD_", "GUARD_", "PYTEST_", "PYTHON", "GIT_")
    environment = {key: value for key, value in os.environ.items() if not key.startswith(prefixes)}
    environment.update(
        {
            "PYTHONSAFEPATH": "1",
            "PYTHONNOUSERSITE": "1",
            "PYTHONUTF8": "1",
            "NO_COLOR": "1",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
        }
    )
    return environment


def _validate_public(
    public: object,
    *,
    expected: list[tuple[str, str, int]] | None,
    source: str = "working_tree",
    files: int | None = None,
    size: int | None = None,
    truncated: bool = False,
    errors: list[str] | None = None,
) -> dict[str, Any]:
    _require(isinstance(public, dict) and set(public) == _PUBLIC_KEYS, "public_schema_fields")
    assert isinstance(public, dict)
    _require(public["schema"] == "guard-repository-secret-scan.v1", "public_schema")
    _require(public["truncated"] is truncated and public["errors"] == (errors or []), "completeness")
    findings = public["findings"]
    _require(isinstance(findings, list) and public["finding_count"] == len(findings), "finding_count")
    if files is not None:
        _require(public["files_scanned"] == files, "file_coverage")
    if size is not None:
        _require(public["bytes_scanned"] == size, "byte_coverage")
    actual = []
    for finding in findings:
        _require(set(finding) == _FINDING_KEYS, "finding_public_fields")
        _require(finding["source"] == source, "finding_source")
        _require(finding["commit"] is None or source == "git_history", "finding_commit")
        _require(isinstance(finding["family"], str) and bool(finding["family"]), "finding_family")
        _require(finding["severity"] in {"medium", "high", "critical"}, "finding_severity")
        _require(finding["confidence"] in {"low", "medium", "high"}, "finding_confidence")
        _require(0 <= finding["confidence_score"] <= 1 and math.isfinite(finding["entropy"]), "finding_scores")
        _require(isinstance(finding["context_reasons"], list), "finding_context")
        actual.append((finding["rule_id"], finding["path"], finding["line"]))
    if expected is not None:
        _require(actual == sorted(expected, key=lambda item: (item[1], item[2], item[0])), "independent_occurrences")
    return public


class Probe:
    def __init__(self, launchers: dict[str, Path], root: Path, checkpoint: Callable[[], None]):
        self.launchers, self.root, self.checkpoint = launchers, root, checkpoint
        self.cases: list[dict[str, object]] = []
        self.deadline = time.monotonic() + 180

    def command(self, argv: list[str], *, expected_exit: int, label: str) -> bytes:
        remaining = self.deadline - time.monotonic()
        _require(remaining > 0, "probe_deadline")
        row: dict[str, object] = {"case": label, "status": "running"}
        self.cases.append(row)
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            try:
                result = subprocess.run(
                    argv,
                    cwd=self.root,
                    env=_environment(),
                    stdout=stdout,
                    stderr=stderr,
                    timeout=min(25, remaining),
                    check=False,
                )
            except subprocess.TimeoutExpired:
                row.update(status="failed", reason="command_timeout")
                raise ProbeError("command_timeout") from None
            finally:
                stdout_size, stderr_size = stdout.seek(0, 2), stderr.seek(0, 2)
                stdout.seek(0)
                stderr.seek(0)
                output, error = stdout.read(_MAX_OUTPUT + 1), stderr.read(_MAX_OUTPUT + 1)
                row.update(
                    stdout_bytes=stdout_size,
                    stderr_bytes=stderr_size,
                    stdout_sha256=_digest(output),
                    stderr_sha256=_digest(error),
                    digest_scope="complete" if max(stdout_size, stderr_size) <= _MAX_OUTPUT else "bounded_prefix",
                )
                self.checkpoint()
        row["exit_code"] = result.returncode
        try:
            _require(len(output) <= _MAX_OUTPUT and len(error) <= _MAX_OUTPUT, "command_output_limit")
            _require(
                all(value.encode() not in output + error for value in (_BODY, *(item[2] for item in _PROVIDERS))),
                "candidate_disclosure",
            )
            _require(str(self.root).encode() not in output + error, "private_path_disclosure")
            _require(result.returncode == expected_exit, "unexpected_exit")
        except ProbeError as failure:
            row.update(status="failed", reason=str(failure))
            self.checkpoint()
            raise
        row["status"] = "command_completed"
        self.checkpoint()
        return output

    def public_result(self, raw: bytes, **expectations: Any) -> dict[str, Any]:
        try:
            public = json.loads(raw)
            result = _validate_public(public, **expectations)
        except Exception as failure:
            reason = str(failure) if isinstance(failure, ProbeError) else "invalid_public_payload"
            self.cases[-1].update(status="failed", reason=reason)
            self.checkpoint()
            raise ProbeError(reason) from None
        self.cases[-1].update(
            status="passed",
            validation="full_public_contract",
            public_sha256=_public_digest(result),
            findings=result["finding_count"],
            files=result["files_scanned"],
            bytes=result["bytes_scanned"],
        )
        self.checkpoint()
        return result

    def git(self, root: Path, *arguments: str) -> str:
        # Repository metadata is local test input; do not retain its output.
        operation = arguments[0] if arguments and arguments[0] in {"init", "config", "add", "commit"} else "other"
        row: dict[str, object] = {
            "case": "fixture_git_setup",
            "stage": "fixture_setup",
            "operation": operation,
            "fixture": root.name if root.name in {"rich", "bounds", "many", "history", "links"} else "other",
            "status": "failed",
        }
        try:
            result = subprocess.run(
                ["git", "-C", str(root), *arguments],
                cwd=self.root,
                env=_environment(),
                capture_output=True,
                check=False,
                timeout=20,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            row.update(error_type=type(error).__name__, reason="fixture_git_setup")
            self.cases.append(row)
            self.checkpoint()
            raise ProbeError("fixture_git_setup") from None
        if result.returncode != 0:
            row.update(
                exit_code=result.returncode,
                reason="fixture_git_setup",
                stdout_bytes=len(result.stdout),
                stderr_bytes=len(result.stderr),
                stdout_sha256=_digest(result.stdout[:_MAX_OUTPUT]),
                stderr_sha256=_digest(result.stderr[:_MAX_OUTPUT]),
                digest_scope="complete"
                if max(len(result.stdout), len(result.stderr)) <= _MAX_OUTPUT
                else "bounded_prefix",
            )
            self.cases.append(row)
            self.checkpoint()
            raise ProbeError("fixture_git_setup")
        return result.stdout.decode().strip()

    def repository(self, root: Path, files: dict[str, bytes]) -> None:
        _write_files(root, files)
        self.git(root, "init")
        self.git(root, "config", "core.autocrlf", "false")
        self.git(root, "config", "user.name", "Guard Qualification")
        self.git(root, "config", "user.email", "guard-qualification@example.invalid")
        self.git(root, "add", ".")

    def scan(
        self,
        label: str,
        target: Path,
        *,
        arguments: tuple[str, ...] = (),
        exit_code: int = 0,
        alias: bool = False,
        **expectations: Any,
    ) -> dict[str, Any]:
        name = "hol-guard-secrets" if alias else "hol-guard"
        argv = [str(self.launchers[name]), *([] if alias else ["secrets"]), "scan", str(target), "--json", *arguments]
        raw = self.command(argv, expected_exit=exit_code, label=label)
        return self.public_result(raw, **expectations)


def _mutation_worker(arguments: argparse.Namespace) -> int:
    _, launchers = _attest(arguments.wheel, arguments.source_sha)
    root = arguments.mutation_worker.resolve()
    victim = root / "a-changed.ts"
    original_path_open, original_os_open = Path.open, os.open
    triggered = False

    def mutate(path: object, readable: bool) -> None:
        nonlocal triggered
        if readable and isinstance(path, (str, Path)) and Path(path) == victim and not triggered:
            triggered = True
            if arguments.mutation_kind == "growth":
                victim.write_bytes(b"X" * 2048)
            else:
                victim.unlink()
                if arguments.mutation_kind == "symlink":
                    victim.symlink_to(root.parent / "outside.ts")
                else:
                    victim.write_bytes(b"replacement")

    def path_open(path: Path, *args: Any, **kwargs: Any) -> Any:
        mutate(path, kwargs.get("mode", args[0] if args else "r") == "rb")
        return original_path_open(path, *args, **kwargs)

    def os_open(path: object, flags: int, *args: Any, **kwargs: Any) -> int:
        access_mask = getattr(os, "O_ACCMODE", os.O_WRONLY | os.O_RDWR)
        mutate(path, flags & access_mask == os.O_RDONLY)
        return original_os_open(path, flags, *args, **kwargs)

    entry = next(
        entry
        for entry in importlib.metadata.distribution("hol-guard").entry_points
        if entry.group == "console_scripts" and entry.name == "hol-guard"
    )
    sys.argv = [
        str(launchers["hol-guard"]),
        "secrets",
        "scan",
        str(root),
        "--json",
        "--max-file-bytes",
        "1024",
        "--fail-on-findings",
    ]
    Path.open, os.open = path_open, os_open
    try:
        code = entry.load()()
    finally:
        Path.open, os.open = original_path_open, original_os_open
    _require(triggered, "mutation_not_triggered")
    return code


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel", required=True, type=Path)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--json", type=Path)
    parser.add_argument("--mutation-worker", type=Path)
    parser.add_argument("--mutation-kind", choices=("growth", "replacement", "symlink"))
    arguments = parser.parse_args()
    if arguments.mutation_worker is not None:
        try:
            return _mutation_worker(arguments)
        except Exception:
            print("installed_secrets_mutation_failed", file=sys.stderr)
            return 1
    _require(arguments.json is not None, "receipt_path_required")
    destination = arguments.json.resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    receipt: dict[str, object] = {
        "schema": "hol-guard.installed-offline-secrets.v1",
        "run_complete": False,
        "platform": sys.platform,
        "machine": platform.machine(),
        "python": platform.python_version(),
        "scope": "installed retained Python; no native detector activation",
        "output_capture": "temporary files; post-exit 2MiB parser/buffer limit; no active child-output disk limit",
        "cases": [],
        "probe_sha256": _digest(Path(__file__).read_bytes()),
        "probe_source_sha256": _probe_source_digests(),
        "started_utc": datetime.now(UTC).isoformat(),
    }

    def checkpoint() -> None:
        temporary = destination.with_suffix(destination.suffix + ".partial")
        temporary.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.replace(temporary, destination)

    checkpoint()
    failure_stage = "initial_attestation"
    try:
        identity, launchers = _attest(arguments.wheel.resolve(), arguments.source_sha)
        receipt["identity"] = identity
        failure_stage = "fixture_setup"
        with tempfile.TemporaryDirectory(prefix="guard-installed-secrets-") as temporary:
            probe = Probe(launchers, Path(temporary).resolve(), checkpoint)
            receipt["cases"] = probe.cases
            failure_stage = "exercise"
            _exercise(probe, arguments.wheel.resolve(), arguments.source_sha)
            failure_stage = "final_attestation"
            final_identity, _ = _attest(arguments.wheel.resolve(), arguments.source_sha)
            _require(final_identity == identity, "installed_artifact_changed_during_probe")
            failure_stage = "fixture_cleanup"
        receipt.update(run_complete=True, status="passed", finished_utc=datetime.now(UTC).isoformat())
    except Exception as error:
        reason = str(error) if isinstance(error, ProbeError) else "unexpected_probe_error"
        cases = receipt["cases"]
        if cases and cases[-1]["status"] in {"running", "command_completed"}:
            cases[-1].update(status="failed", reason=reason)
        elif not cases or cases[-1]["status"] != "failed":
            cases.append(
                {"case": "probe_" + failure_stage, "stage": failure_stage, "status": "failed", "reason": reason}
            )
        receipt.update(
            status="failed",
            reason=reason,
            error_type=type(error).__name__,
            failure_stage=failure_stage,
        )
        checkpoint()
        print("installed_offline_secrets_failed", file=sys.stderr)
        return 1
    checkpoint()
    print(json.dumps({"schema": receipt["schema"], "status": "passed", "case_count": len(receipt["cases"])}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
