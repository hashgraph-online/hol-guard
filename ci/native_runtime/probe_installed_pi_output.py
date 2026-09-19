"""Exercise the installed Pi/OMP extension against a scoped Guard daemon.

The native-wheel workflow already builds and installs the wheel. This probe
checks the generated extension boundary through the installed daemon's native
resident route; negative cases deliberately inject malformed CLI results to
prove the extension remains fail-closed.
"""

from __future__ import annotations

import argparse as argparse
import base64 as base64
import hashlib as hashlib
import importlib as importlib
import json as json
import os as os
import shutil as shutil
import signal as signal
import stat as stat
import subprocess as subprocess
import sys as sys
import tempfile as tempfile
import textwrap as textwrap
import threading as threading
import time as time
from collections.abc import Mapping as Mapping
from importlib import metadata as metadata
from pathlib import Path as Path
from typing import Any as Any

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    sys.modules["ci.native_runtime.probe_installed_pi_output"] = sys.modules[__name__]

_runtime = importlib.import_module("ci.native_runtime.probe_installed_pi_runtime")
_is_source_checkout_package = _runtime._is_source_checkout_package
_installed_package_path = _runtime._installed_package_path
_short_temp_parent = _runtime._short_temp_parent
_short = _runtime._short
_run = _runtime._run
_isolated_env = _runtime._isolated_env
_probe_python_path = _runtime._probe_python_path
_node_command = _runtime._node_command
_probe_native_identity = _runtime._probe_native_identity

_payloads = importlib.import_module("ci.native_runtime.probe_installed_pi_payloads")
_cases = _payloads._cases
_negative_cases = _payloads._negative_cases
_text_digest = _payloads._text_digest
_canonical_content_digest = _payloads._canonical_content_digest
_write_cli_wrapper = _payloads._write_cli_wrapper
_write_node_runner = _payloads._write_node_runner
_generate_extension = _payloads._generate_extension
_run_node_cases = _payloads._run_node_cases

_results = importlib.import_module("ci.native_runtime.probe_installed_pi_results")
_read_records = _results._read_records
_payload_from_record = _results._payload_from_record
_response_from_record = _results._response_from_record
_assert_real_results = _results._assert_real_results
_assert_fetch_evidence = _results._assert_fetch_evidence
_assert_native_route_metrics = _results._assert_native_route_metrics
_wait_for_native_route_metrics = _results._wait_for_native_route_metrics
_assert_no_positive_cli_fallback = _results._assert_no_positive_cli_fallback
_assert_negative_results = _results._assert_negative_results

_daemon = importlib.import_module("ci.native_runtime.probe_installed_pi_daemon")
_close_startup_resource = _daemon._close_startup_resource
_start_installed_daemon = _daemon._start_installed_daemon
_prepare_installed_daemon_workspace = _daemon._prepare_installed_daemon_workspace
_restore_alarm_state = _daemon._restore_alarm_state
_bounded_daemon_call = _daemon._bounded_daemon_call
_bounded_daemon_finish = _daemon._bounded_daemon_finish
_cleanup_installed_daemon = _daemon._cleanup_installed_daemon

_cleanup = importlib.import_module("ci.native_runtime.probe_installed_pi_cleanup")
_native_state_files = _cleanup._native_state_files
_native_cleanup_environment = _cleanup._native_cleanup_environment
_cleanup_native = _cleanup._cleanup_native
_remove_probe_path = _cleanup._remove_probe_path
_scrub_probe_root = _cleanup._scrub_probe_root
_remaining_probe_paths = _cleanup._remaining_probe_paths
_retain_private_native_retry_state = _cleanup._retain_private_native_retry_state
_retain_cleanup_receipt = _cleanup._retain_cleanup_receipt
_retain_unsafe_cleanup_marker = _cleanup._retain_unsafe_cleanup_marker
_remove_probe_root = _cleanup._remove_probe_root

_REPO_ROOT = Path(__file__).resolve().parents[2]
_TEXT_LIMIT = 12_000
_NODE_PROBE_TIMEOUT = 5.0
_DAEMON_READINESS_TIMEOUT = 5.0
_DAEMON_CLEANUP_TIMEOUT = 10.0
_NODE_PROBE_SOURCE = 'const typedValue: string = "node-capability-probe";\nprocess.stdout.write(typedValue);\n'
_ENV_ALLOWLIST = {
    "COMSPEC",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "PATH",
    "PATHEXT",
    "SYSTEMROOT",
    "TEMP",
    "TMPDIR",
    "USERPROFILE",
}


class ProbeError(RuntimeError):
    """Raised when the installed Pi/native boundary cannot be proven."""


class ProbeCleanupError(ProbeError):
    """Raised when startup cleanup must be retained for a bounded retry."""


class ProbeCleanupUnsafeError(ProbeCleanupError):
    """Raised when daemon containment is unproven and the scratch root may be mutable."""


class _DaemonCallTimeoutError(ProbeCleanupUnsafeError):
    """Internal signal interruption for a bounded daemon lifecycle call."""


def _run_probe(*, json_path: Path | None = None) -> dict[str, Any]:
    if os.name == "nt":
        raise ProbeError("installed Pi/native output probe is POSIX-only")
    _installed_package_path(_REPO_ROOT)
    status, identity, capabilities = _probe_native_identity()
    node = _node_command()
    python_path = _probe_python_path()

    root = Path(tempfile.mkdtemp(prefix="hg-pi-native-", dir=_short_temp_parent()))
    daemon: Any | None = None
    native_started = False
    startup_cleanup_failure: ProbeError | None = None
    receipt: dict[str, Any] | None = None
    try:
        # Admit the private root once before direct worker policy registration.
        root = root.resolve()
        home = root / "home"
        guard_home = root / "guard-home"
        workspace = root / "workspace"
        for directory in (home, guard_home, workspace):
            directory.mkdir(mode=0o700)
        settings = root / "settings.json"
        settings.write_text("{}\n", encoding="utf-8")
        runner = root / "run-extension.mjs"
        _write_node_runner(runner)
        cases = _cases()
        cases_path = root / "cases.json"
        cases_path.write_text(json.dumps(cases, ensure_ascii=True), encoding="utf-8")
        real_log = root / "real-cli.jsonl"
        real_cli = home / ".local" / "bin" / "hol-guard"
        real_cli.parent.mkdir(mode=0o700, parents=True)
        _write_cli_wrapper(real_cli, python_path=python_path, log_path=real_log, negative=False)
        extension = root / "extension.ts"
        _generate_extension(
            extension,
            guard_home=guard_home,
            home=home,
            settings_path=settings,
        )
        version_module = importlib.import_module("codex_plugin_scanner.version")
        package_version = str(getattr(version_module, "__version__", "unknown"))
        try:
            daemon = _start_installed_daemon(
                guard_home=guard_home,
                home=home,
                workspace=workspace,
                identity=identity,
            )
        except ProbeCleanupError as exc:
            startup_cleanup_failure = exc
            raise
        native_started = True
        _prepare_installed_daemon_workspace(daemon, workspace)
        real_results, real_fetches = _run_node_cases(
            node=node,
            extension=extension,
            runner=runner,
            cases=cases_path,
            cwd=workspace,
            env=_isolated_env(home=home, python_path=python_path),
        )
        _assert_no_positive_cli_fallback(real_log)
        real_output_evidence = _assert_real_results(real_results, cases)
        real_fetch_evidence = _assert_fetch_evidence(real_fetches, real_results, cases)
        native_routes = _wait_for_native_route_metrics(daemon, len(cases))
        negative_home = root / "negative-home"
        negative_guard_home = root / "negative-guard-home"
        negative_workspace = root / "negative-workspace"
        for directory in (negative_home, negative_guard_home, negative_workspace):
            directory.mkdir(mode=0o700)
        negative_log = root / "negative-cli.jsonl"
        negative_cli = negative_home / ".local" / "bin" / "hol-guard"
        negative_cli.parent.mkdir(mode=0o700, parents=True)
        _write_cli_wrapper(negative_cli, python_path=python_path, log_path=negative_log, negative=True)
        negative_extension = root / "negative-extension.ts"
        _generate_extension(
            negative_extension,
            guard_home=negative_guard_home,
            home=negative_home,
            settings_path=root / "negative-settings.json",
        )
        negative_cases_path = root / "negative-cases.json"
        negative_cases = _negative_cases()
        negative_cases_path.write_text(json.dumps(negative_cases, ensure_ascii=True), encoding="utf-8")
        negative_results, _ = _run_node_cases(
            node=node,
            extension=negative_extension,
            runner=runner,
            cases=negative_cases_path,
            cwd=negative_workspace,
            env=_isolated_env(home=negative_home, python_path=python_path),
        )
        negative_evidence = _assert_negative_results(negative_results, _read_records(negative_log))
        receipt = {
            "schema": "hol-guard.installed-pi-native-output.v1",
            "package_version": package_version,
            "source_sha": getattr(capabilities, "build_sha", None),
            "package_origin_kind": "non-editable-distribution-manifest",
            "source_checkout_import": False,
            "execution_path": "unmodified-generated-extension-via-scoped-installed-daemon-native-resident",
            "native_prerequisite": "default-auto-status-checked",
            "workflow_order": "after-native-default-auto-probe",
            "daemon": "scoped-installed-GuardDaemonServer",
            "runtime": {
                "mode": status.mode,
                "reason": status.reason,
                "target": getattr(capabilities, "target", None),
                "runtime_version": getattr(capabilities, "runtime_version", None),
                "build_sha": getattr(capabilities, "build_sha", None),
                "runtime_sha256": getattr(identity, "sha256", None),
            },
            "generated_extension": {
                "harness": "omp",
                "real_cases": {
                    case_id: {
                        **real_output_evidence[case_id],
                        "daemon_response": real_fetch_evidence[case_id],
                    }
                    for case_id in real_output_evidence
                },
                "malformed_result_cases": negative_evidence,
            },
            "native_route_metrics": {"native_resident": native_routes["native_resident"]},
            "cleanup": "authenticated_daemon_stop_then_native_resident_stop",
        }
    finally:
        cleanup_failure: ProbeError | None = startup_cleanup_failure
        cleanup_unsafe = isinstance(cleanup_failure, ProbeCleanupUnsafeError)
        if daemon is not None:
            try:
                _cleanup_installed_daemon(daemon)
            except ProbeError as exc:
                cleanup_failure = exc
                cleanup_unsafe = isinstance(exc, ProbeCleanupUnsafeError)
        if native_started and not cleanup_unsafe:
            try:
                _cleanup_native(identity, guard_home)
            except ProbeError as exc:
                cleanup_failure = cleanup_failure or exc
        if cleanup_failure is not None:
            try:
                if cleanup_unsafe:
                    _retain_unsafe_cleanup_marker(root, cleanup_failure)
                else:
                    _retain_cleanup_receipt(root, cleanup_failure)
            except ProbeError as scrub_failure:
                raise scrub_failure from cleanup_failure
            raise cleanup_failure
        _remove_probe_root(root)

    if receipt is None:
        raise ProbeError("installed Pi/native probe did not produce a receipt")
    if json_path is not None:
        json_path.write_text(json.dumps(receipt, sort_keys=True) + "\n", encoding="utf-8")
    return receipt


def main(*, json_path: Path | None = None) -> int:
    receipt = _run_probe(json_path=json_path)
    print(json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()
    try:
        raise SystemExit(main(json_path=args.json))
    except (ProbeError, OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
