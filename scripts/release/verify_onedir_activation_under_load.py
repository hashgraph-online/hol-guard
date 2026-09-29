#!/usr/bin/env python3
"""Prove a onedir Core activates inside the Desktop budget while onefile processes flood Gatekeeper.

Build-mode contract test for the Desktop Core feed: times a warm ``--version`` and a
``desktop bootstrap --json`` against a scratch Guard home while N concurrent onefile
``--version`` loops reproduce the production Gatekeeper load. Counts syspolicyd
``GK performScan``/``GK evaluateScanResult`` events for evidence only.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import re
import shlex
import signal
import subprocess
import time
from pathlib import Path

BOOTSTRAP_SCHEMA = "guard-desktop-bootstrap.v1"
_EVALUATE_RESULT = re.compile(r"GK evaluateScanResult.*\(id:\s*([^,\s)]+)")
_GK_PREDICATE = 'process == "syspolicyd" AND subsystem == "com.apple.syspolicy.exec" AND eventMessage CONTAINS "GK "'


def parse_gk_events(lines: list[str]) -> dict[str, int]:
    """Count Gatekeeper events; evaluateScanResult ids name the scanned binary."""
    perform_scan = 0
    evaluate_launcher = 0
    for line in lines:
        if "GK performScan" in line:
            perform_scan += 1
        if "GK evaluateScanResult" in line:
            match = _EVALUATE_RESULT.search(line)
            if match is not None and Path(match.group(1)).name == "hol-guard":
                evaluate_launcher += 1
    return {"gk_perform_scan": perform_scan, "gk_evaluate_launcher": evaluate_launcher}


def decide_within_budget(activation_seconds: float, budget_seconds: float) -> bool:
    return activation_seconds < budget_seconds


def format_markdown_summary(record: dict[str, object]) -> str:
    rows = [
        "| metric | value |",
        "| --- | --- |",
    ]
    for key in (
        "warm_seconds",
        "activation_seconds",
        "budget_seconds",
        "within_budget",
        "noise_processes",
        "gk_perform_scan",
        "gk_evaluate_launcher",
        "gk_check",
        "core_version",
        "verdict",
    ):
        if key in record:
            rows.append(f"| {key} | {record[key]} |")
    return "## Onedir activation under onefile load\n\n" + "\n".join(rows) + "\n"


def _local_timestamp() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _gk_scan_counts(start: str, end: str) -> dict[str, object]:
    try:
        result = subprocess.run(
            ["log", "show", "--start", start, "--end", end, "--style", "compact", "--predicate", _GK_PREDICATE],
            check=False,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return {"gk_check": f"skipped ({error})"}
    if result.returncode != 0:
        reason = result.stderr.strip() or f"log show exited {result.returncode}"
        return {"gk_check": f"skipped ({reason})"}
    counts: dict[str, object] = dict(parse_gk_events(result.stdout.splitlines()))
    counts["gk_check"] = "ok"
    return counts


def _stop_scratch_processes(home: Path) -> list[int]:
    stopped: list[int] = []
    needle = str(home)
    result = subprocess.run(
        ["/bin/ps", "-axww", "-o", "pid=,ppid=,command="],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return stopped
    parents: dict[int, int] = {}
    candidates: list[int] = []
    for line in result.stdout.splitlines():
        parts = line.strip().split(None, 2)
        if len(parts) != 3:
            continue
        try:
            pid = int(parts[0])
            ppid = int(parts[1])
        except ValueError:
            continue
        parents[pid] = ppid
        if needle in parts[2]:
            candidates.append(pid)
    protected = {os.getpid()}
    walker = os.getppid()
    for _ in range(16):
        if walker <= 1 or walker in protected:
            break
        protected.add(walker)
        walker = parents.get(walker, 0)
    for pid in candidates:
        if pid in protected:
            continue
        try:
            os.kill(pid, signal.SIGTERM)
            stopped.append(pid)
        except OSError:
            continue
    return stopped


def _signal_group(process: subprocess.Popen[bytes], signum: signal.Signals) -> None:
    with contextlib.suppress(ProcessLookupError):
        os.killpg(process.pid, signum)


def _noise_loop_script(onefile: Path, flag: Path) -> str:
    return f"while [ -e {shlex.quote(str(flag))} ]; do {shlex.quote(str(onefile))} --version >/dev/null 2>&1; done"


def _timed(argv: list[str], *, env: dict[str, str] | None = None, timeout: float) -> tuple[int, float, str, str]:
    started = time.monotonic()
    try:
        result = subprocess.run(
            argv,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )
    except subprocess.TimeoutExpired as error:
        out = error.stdout or ""
        err = error.stderr or ""
        return (
            124,
            time.monotonic() - started,
            out.decode("utf-8", errors="replace") if isinstance(out, bytes) else out,
            err.decode("utf-8", errors="replace") if isinstance(err, bytes) else err,
        )
    return result.returncode, time.monotonic() - started, result.stdout, result.stderr


def run_contract(
    *,
    onedir_launcher: Path,
    onefile: Path,
    noise: int,
    budget_seconds: float,
    home: Path,
    expected_version: str,
) -> dict[str, object]:
    if not onedir_launcher.is_file():
        raise SystemExit(f"Onedir launcher does not exist: {onedir_launcher}")
    if not onefile.is_file():
        raise SystemExit(f"Onefile noise binary does not exist: {onefile}")

    _version_rc, warm_seconds, _version_out, _version_err = _timed([str(onedir_launcher), "--version"], timeout=120)

    home.mkdir(parents=True, exist_ok=True)
    flag = home.parent / f".{home.name}-onedir-noise.flag"
    flag.touch()
    noise_processes: list[subprocess.Popen[bytes]] = []
    record: dict[str, object] = {}
    try:
        for _ in range(noise):
            noise_processes.append(
                subprocess.Popen(
                    ["bash", "-c", _noise_loop_script(onefile, flag)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True,
                )
            )
        time.sleep(5)

        env = dict(os.environ)
        env["HOME"] = str(home)
        env["HOL_GUARD_HOME"] = str(home / ".hol-guard")
        env["HOL_GUARD_DESKTOP"] = "1"
        start_ts = _local_timestamp()
        rc, activation_seconds, stdout, stderr = _timed(
            [str(onedir_launcher), "desktop", "bootstrap", "--json"],
            env=env,
            timeout=budget_seconds + 120,
        )
        end_ts = _local_timestamp()

        record.update(
            {
                "warm_seconds": round(warm_seconds, 2),
                "warm_rc": _version_rc,
                "activation_seconds": round(activation_seconds, 2),
                "activation_rc": rc,
                "budget_seconds": budget_seconds,
                "noise_processes": noise,
            }
        )
        if rc != 0:
            record["error"] = f"bootstrap exited {rc}: {(stderr or stdout).strip()[:400]}"
            record["verdict"] = "fail"
            return record
        try:
            payload = json.loads(stdout)
        except json.JSONDecodeError:
            record["error"] = "bootstrap did not emit a JSON payload"
            record["verdict"] = "fail"
            return record
        record["bootstrap_schema"] = payload.get("schema")
        record["core_version"] = payload.get("coreVersion")
        if payload.get("schema") != BOOTSTRAP_SCHEMA:
            record["error"] = f"bootstrap schema mismatch: {payload.get('schema')!r}"
            record["verdict"] = "fail"
            return record
        if payload.get("coreVersion") != expected_version:
            record["error"] = f"bootstrap coreVersion mismatch: {payload.get('coreVersion')!r}"
            record["verdict"] = "fail"
            return record
        record["within_budget"] = decide_within_budget(activation_seconds, budget_seconds)
        record.update(_gk_scan_counts(start_ts, end_ts))
        record["verdict"] = "pass" if record["within_budget"] and _version_rc == 0 else "fail"
        if not record["within_budget"]:
            record["error"] = f"activation_seconds {activation_seconds:.2f} exceeded budget {budget_seconds}"
        elif _version_rc != 0:
            record["error"] = f"warm --version exited {_version_rc}"
        return record
    finally:
        flag.unlink(missing_ok=True)
        for process in noise_processes:
            try:
                process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                _signal_group(process, signal.SIGTERM)
        for process in noise_processes:
            try:
                process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                _signal_group(process, signal.SIGKILL)
        stopped = _stop_scratch_processes(home)
        if stopped:
            record["stopped_scratch_pids"] = stopped


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--onedir-launcher", type=Path, required=True)
    parser.add_argument("--onefile", type=Path, required=True)
    parser.add_argument("--noise", type=int, default=8)
    parser.add_argument("--budget-seconds", type=float, default=150.0)
    parser.add_argument("--home", type=Path, required=True)
    parser.add_argument("--summary", type=Path)
    parser.add_argument("--version", required=True, help="expected coreVersion in the bootstrap payload")
    args = parser.parse_args(argv)

    record = run_contract(
        onedir_launcher=args.onedir_launcher,
        onefile=args.onefile,
        noise=args.noise,
        budget_seconds=args.budget_seconds,
        home=args.home,
        expected_version=args.version,
    )
    rendered = json.dumps(record, indent=2, sort_keys=True) + "\n"
    print(rendered, end="")
    if args.summary is not None:
        args.summary.write_text(rendered, encoding="utf-8")
    step_summary = os.environ.get("GITHUB_STEP_SUMMARY", "").strip()
    if step_summary:
        with open(step_summary, "a", encoding="utf-8") as handle:
            handle.write(format_markdown_summary(record))
    return 0 if record.get("verdict") == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
