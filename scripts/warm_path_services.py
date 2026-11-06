"""Guard process accounting and service setup for the warm-path probes (measurement only).

Counts every live process an installed Guard started after a baseline, labels
each one with a short role derived from its argv, and brings a target to the
installed steady state (daemon running) before a timed phase. Only the derived
role is recorded, never the argv itself, which may carry paths or tokens.

Linux only for resource accounting; nothing here changes product behavior.
"""

from __future__ import annotations

import os
import signal
import subprocess
import time
from collections import Counter
from collections.abc import Sequence
from pathlib import Path

_CLK_TCK = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100
_ENSURE_TIMEOUT_SECONDS = 120
# Exact argv tokens naming a resident runtime subcommand, mapped to its role.
_RESIDENT_ROLES = {
    "serve": "resident-serve",
    "serve-managed": "resident-serve",
    "supervise-managed": "resident-supervise",
    "resident-client-stream": "resident-client-stream",
    "resident-client": "resident-client",
}
_HOOK_TOKENS = frozenset({"hook", "hook-client", "pre-tool"})


def alive_pids() -> set[int]:
    return {int(entry) for entry in os.listdir("/proc") if entry.isdigit()}


def _ancestors() -> set[int]:
    chain: set[int] = {os.getpid()}
    pid = os.getppid()
    while pid > 1 and pid not in chain:
        chain.add(pid)
        try:
            pid = int(Path(f"/proc/{pid}/stat").read_text(encoding="utf-8").rsplit(")", 1)[1].split()[1])
        except (OSError, ValueError, IndexError):
            break
    return chain


def guard_pids(baseline: set[int], root: Path) -> set[int]:
    """Return live processes started since ``baseline`` that belong to the installed Guard."""

    markers = (b"hol-guard", b"hol_guard", b"codex_plugin_scanner", str(root).encode())
    excluded = _ancestors()
    found: set[int] = set()
    for pid in alive_pids() - baseline - excluded:
        try:
            command = Path(f"/proc/{pid}/cmdline").read_bytes()
        except OSError:
            continue
        # The canary fixture is the measured workload's upstream, not Guard. Identify it by its own
        # script argument (argv[1]), since its path may legitimately contain a Guard marker.
        argv = command.split(b"\0")
        if len(argv) > 1 and argv[1].endswith(b"mcp-canary-server.py"):
            continue
        if any(marker in command for marker in markers):
            found.add(pid)
    return found


def process_role(argv: Sequence[str]) -> str:
    """Short role for a Guard process from exact argv tokens; never echoes the argv."""

    tokens = set(argv)
    # The relay's argv embeds the proxy argv it may hand the session to, so it is checked first.
    if "mcp-relay" in tokens:
        return "mcp-relay"
    if any(token.endswith("mcp-proxy") and "/" not in token for token in argv):
        return "mcp-proxy"
    for token in argv:
        if token in _RESIDENT_ROLES:
            return _RESIDENT_ROLES[token]
    if "daemon" in tokens:
        if "--serve" in tokens:
            return "daemon"
        return "daemon-ensure" if "ensure" in tokens else "daemon-cli"
    if tokens & _HOOK_TOKENS:
        return "hook"
    return "other"


def _pss_kb(pid: int) -> int:
    """Proportional set size: shared pages (the one native binary every resident role maps) split
    between the processes that map them. Zero when the kernel does not expose it."""

    try:
        rollup = Path(f"/proc/{pid}/smaps_rollup").read_text(encoding="utf-8")
    except OSError:
        return 0
    for line in rollup.splitlines():
        if line.startswith("Pss:"):
            return int(line.split()[1])
    return 0


def _process_snapshot(pid: int) -> dict[str, object] | None:
    try:
        status = Path(f"/proc/{pid}/status").read_text(encoding="utf-8")
        stat = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
        command = Path(f"/proc/{pid}/cmdline").read_bytes()
        fds = len(os.listdir(f"/proc/{pid}/fd"))
    except OSError:
        return None
    fields = {line.split(":", 1)[0]: line.split(":", 1)[1].strip() for line in status.splitlines() if ":" in line}
    after_name = stat.rsplit(")", 1)[1].split()
    ticks = int(after_name[11]) + int(after_name[12])
    argv = [token.decode("utf-8", "replace") for token in command.split(b"\0") if token]
    return {
        "pid": pid,
        "name": fields.get("Name", "?"),
        "role": process_role(argv),
        "rss_kb": int(fields.get("VmRSS", "0 kB").split()[0]),
        "rss_anon_kb": int(fields.get("RssAnon", "0 kB").split()[0]),
        "pss_kb": _pss_kb(pid),
        "threads": int(fields.get("Threads", "0")),
        "fds": fds,
        "cpu_s": ticks / _CLK_TCK,
    }


def summarize_roles(rows: Sequence[dict[str, object]]) -> dict[str, dict[str, float]]:
    """Process count, RSS, anonymous RSS and PSS MB and CPU seconds per role.

    RSS counts a shared page in every process that maps it; anonymous RSS and PSS show how much
    of a role's RSS is its own memory rather than shared binary text.
    """

    roles: dict[str, dict[str, float]] = {}
    for row in rows:
        entry = roles.setdefault(
            str(row["role"]), {"processes": 0, "rss_mb": 0.0, "anon_mb": 0.0, "pss_mb": 0.0, "cpu_s": 0.0}
        )
        entry["processes"] += 1
        entry["rss_mb"] += int(row["rss_kb"]) / 1024  # type: ignore[call-overload]
        entry["anon_mb"] += int(row.get("rss_anon_kb", 0)) / 1024  # type: ignore[call-overload]
        entry["pss_mb"] += int(row.get("pss_kb", 0)) / 1024  # type: ignore[call-overload]
        entry["cpu_s"] += float(row["cpu_s"])  # type: ignore[arg-type]
    return {
        role: {
            "processes": e["processes"],
            "rss_mb": round(e["rss_mb"], 2),
            "anon_mb": round(e["anon_mb"], 2),
            "pss_mb": round(e["pss_mb"], 2),
            "cpu_s": round(e["cpu_s"], 4),
        }
        for role, e in sorted(roles.items())
    }


def role_cpu_ms_per_call(before: dict[str, object], after: dict[str, object], calls: int) -> dict[str, float]:
    """CPU milliseconds per call each role spent between two snapshots.

    A role's processes are summed in each snapshot; a role absent before (started during the
    timed phase) counts from zero, and one that exited is not counted, like the service total.
    """

    before_roles: dict[str, dict[str, float]] = before["roles"]  # type: ignore[assignment]
    after_roles: dict[str, dict[str, float]] = after["roles"]  # type: ignore[assignment]
    return {
        role: round(
            (float(values.get("cpu_s", 0.0)) - float(before_roles.get(role, {}).get("cpu_s", 0.0)))
            * 1000
            / max(1, calls),
            3,
        )
        for role, values in after_roles.items()
    }


def service_snapshot(baseline: set[int], root: Path) -> dict[str, object]:
    """Summarize Guard processes that appeared after ``baseline`` and are still alive."""

    rows = [row for pid in sorted(guard_pids(baseline, root)) if (row := _process_snapshot(pid)) is not None]
    return {
        "processes": len(rows),
        "names": sorted(Counter(str(row["name"]) for row in rows).items()),
        "roles": summarize_roles(rows),
        "rss_mb": round(sum(int(row["rss_kb"]) for row in rows) / 1024, 2),  # type: ignore[call-overload]
        "pss_mb": round(sum(int(row.get("pss_kb", 0)) for row in rows) / 1024, 2),  # type: ignore[call-overload]
        "threads": sum(int(row["threads"]) for row in rows),  # type: ignore[call-overload]
        "fds": sum(int(row["fds"]) for row in rows),  # type: ignore[call-overload]
        "cpu_s": round(sum(float(row["cpu_s"]) for row in rows), 4),  # type: ignore[arg-type]
    }


def ensure_daemon(cli: Path, env: dict[str, str], home: Path, guard_home: Path, workspace: Path) -> dict[str, object]:
    """Start the Guard daemon through the target's own CLI; record, never raise, when it cannot.

    Every target since the frozen baseline ships ``guard daemon ensure``. A version that lacks it
    reports ``unsupported`` and is measured in whatever state its install left behind.
    """

    started = time.perf_counter_ns()
    try:
        result = subprocess.run(
            [str(cli), "guard", "daemon", "ensure", "--home", str(home), "--guard-home", str(guard_home)],
            env=env,
            cwd=workspace,
            capture_output=True,
            text=True,
            timeout=_ENSURE_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "elapsed_ms": (time.perf_counter_ns() - started) / 1e6}
    elapsed_ms = (time.perf_counter_ns() - started) / 1e6
    if result.returncode == 0:
        status = "still_starting" if "still starting" in result.stdout else "ok"
    elif result.returncode == 2 and "invalid choice" in result.stderr:
        status = "unsupported"
    else:
        status = f"exit_{result.returncode}"
    return {"status": status, "elapsed_ms": elapsed_ms}


def stop_services(cli: Path, env: dict[str, str], home: Path, guard_home: Path, baseline: set[int], root: Path) -> None:
    subprocess.run(
        [str(cli), "guard", "daemon", "stop", "--home", str(home), "--guard-home", str(guard_home), "--json"],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    leftovers = sorted(guard_pids(baseline, root))
    for pid in leftovers:
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            continue
    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline and (alive_pids() & set(leftovers)):
        time.sleep(0.1)
    for pid in alive_pids() & set(leftovers):
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            continue
