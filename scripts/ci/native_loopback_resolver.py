"""Run both qualification arms inside an optional exact-zone macOS DNS fixture.

Only the fixed loopback PTR resolver may be created. Both immutable wheels use
the same environment. Failed setup still runs the actual measurements and keeps
their outcome; no runtime patch, hosts rewrite, cache flush, or deadline change
is applied. Cleanup refuses to remove bytes that this run does not own.
"""

from __future__ import annotations

import argparse
import json
import secrets
import signal
import subprocess
import sys
import time
from pathlib import Path

if __package__:
    from .native_loopback_diagnostics import owned_configuration, responder_probe, system_configuration
    from .native_loopback_dns import LoopbackPTRResponder
    from .native_loopback_lookup import lookup_witness
else:
    from native_loopback_diagnostics import owned_configuration, responder_probe, system_configuration
    from native_loopback_dns import LoopbackPTRResponder
    from native_loopback_lookup import lookup_witness

_QUERY = (
    "import json,socket; name=socket.getfqdn('127.0.0.1'); "
    "print(json.dumps({'loopback_label':name in "
    "('127.0.0.1','localhost','hol-guard-qualification.localhost')}))"
)


def resolver_probe() -> dict[str, object]:
    started = time.monotonic()
    result: dict[str, object] = {"status": "failed", "loopback_label": False}
    try:
        completed = subprocess.run(
            [sys.executable, "-I", "-c", _QUERY], capture_output=True, text=True, timeout=5, check=False
        )
        if completed.returncode == 0 and len(completed.stdout) <= 128:
            value = json.loads(completed.stdout)
            if isinstance(value, dict) and type(value.get("loopback_label")) is bool:
                result.update(status="completed", loopback_label=value["loopback_label"])
    except subprocess.TimeoutExpired:
        result["status"] = "deadline_exceeded"
    except (OSError, ValueError):
        pass
    result["elapsed_ms"] = round((time.monotonic() - started) * 1000, 3)
    return result


def _run_helper(operation: str, port: int, owner: str) -> str:
    arguments = [
        "sudo",
        "-n",
        sys.executable,
        "-I",
        str(Path(__file__).with_name("native_loopback_dns.py").resolve()),
        "--operation",
        operation,
        "--port",
        str(port),
        "--owner",
        owner,
    ]
    try:
        completed = subprocess.run(arguments, capture_output=True, timeout=10, check=False)
        return {0: "completed", 2: "existing_configuration", 3: "refused_unowned"}.get(completed.returncode, "failed")
    except subprocess.TimeoutExpired:
        return "deadline_exceeded"
    except OSError:
        return "failed"


def _base_report() -> dict[str, object]:
    return {
        "schema": "hol-guard.native-loopback-resolver.v2",
        "environment_scope": "disposable_ci_runner_both_arms",
        "baseline_artifact_modified": False,
        "runtime_patched": False,
        "fixture_deadline_changed": False,
        "qualification_pass": False,
        "mechanism": "exact_loopback_ptr_resolver",
        "experiment_attempted": False,
    }


def _write_report(output: Path, report: dict[str, object]) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def _run_command(command: list[str]) -> int:
    return subprocess.run(command, check=False).returncode


def _terminate(signum: int, _frame: object) -> None:
    raise SystemExit(128 + signum)


def run_wrapped(command: list[str], output: Path) -> int:
    """Hold the exact DNS fixture around the entire paired build/measure command."""
    report = _base_report()
    if sys.platform != "darwin":
        report["status"] = "not_macos"
        _write_report(output, report)
        return _run_command(command)
    before = resolver_probe()
    report["before"] = before
    if before["status"] == "completed":
        report["status"] = "resolver_already_completed"
        _write_report(output, report)
        try:
            return _run_command(command)
        finally:
            report["after"] = resolver_probe()
            _write_report(output, report)
    report["experiment_attempted"] = True
    owner = secrets.token_hex(16)
    cleanup = "not_installed"
    returncode = 1
    try:
        responder = LoopbackPTRResponder()
    except OSError:
        report["status"] = "responder_unavailable"
        _write_report(output, report)
        return _run_command(command)
    with responder:
        # This packet is a transport self-check, never evidence that macOS
        # selected the configuration. Keep its count out of resolver traffic.
        report["responder_self_probe"] = responder_probe(responder.port)
        self_probe_received = responder.snapshot()["received"]
        # Removal is attempted even after helper timeout/failure: an interrupted
        # helper may have completed its exclusive create. Exact bytes guard it.
        try:
            report["configuration_install"] = _run_helper("install", responder.port, owner)
            report["configuration_readback"] = owned_configuration(responder.port, owner)
            report["system_configuration_after_install"] = system_configuration(responder.port)
            report["after"] = resolver_probe()
            report["status"] = "experiment_running"
            _write_report(output, report)
            returncode = _run_command(command)
            report["command_returncode"] = returncode
            # Keep the original qualification resolver counter separate from
            # these later diagnostic lookups. The exact resolver still exists.
            counts = responder.snapshot()
            report["resolver_packets_received"] = max(0, counts["received"] - self_probe_received)
            report["responder_before_lookup_witness"] = counts
            report["rejected_packets_before_lookup_witness"] = responder.rejection_snapshot()
            report["configuration_before_lookup_witness"] = owned_configuration(responder.port, owner)
            try:
                report["lookup_witness"] = lookup_witness(responder)
            except Exception as error:
                report["lookup_witness"] = {"status": "failed", "category": type(error).__name__}
            report["configuration_after_lookup_witness"] = owned_configuration(responder.port, owner)
        finally:
            report["system_configuration_after_command"] = system_configuration(responder.port)
            cleanup = (
                "not_owned"
                if report.get("configuration_install") == "existing_configuration"
                else _run_helper("remove", responder.port, owner)
            )
            report["configuration_cleanup"] = cleanup
            counts = responder.snapshot()
            report["responder"] = counts
            report["rejected_packets"] = responder.rejection_snapshot()
            report.setdefault("resolver_packets_received", max(0, counts["received"] - self_probe_received))
            report["status"] = "experiment_finished"
            _write_report(output, report)
    report["after_cleanup"] = resolver_probe()
    _write_report(output, report)
    return returncode if cleanup in {"completed", "not_owned"} or returncode else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if command:
        previous = signal.signal(signal.SIGTERM, _terminate)
        try:
            return run_wrapped(command, args.output)
        finally:
            signal.signal(signal.SIGTERM, previous)
    report = _base_report()
    report["before"] = resolver_probe()
    report["status"] = "diagnostic_only"
    _write_report(args.output, report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
