"""Black-box warm-path probes for an installed Guard wheel (measurement only).

Both probes drive the installed product through its public command line, so the
same probe code runs unchanged against any source revision:

* ``hook``: install the Claude Code hooks into a throwaway home, then execute the
  installed PreToolUse handler exactly as the harness would (one process per
  call, benign Bash payload on stdin) and time spawn to exit.
* ``mcp``: install the Codex MCP proxy around a stdlib canary server, keep one
  proxy session open, and time each non-package ``tools/call`` round trip.

Linux only for resource accounting; nothing here changes product behavior.
"""

from __future__ import annotations

import json
import os
import queue
import resource
import signal
import subprocess
import threading
import time
from collections import Counter
from pathlib import Path

import tomllib
from warm_path_stats import describe

_CLK_TCK = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100
_CALL_TIMEOUT_SECONDS = 30
_BENIGN_HOOK_PAYLOAD = {
    "session_id": "warm-path-probe",
    "hook_event_name": "PreToolUse",
    "tool_name": "Bash",
    "tool_input": {"command": "printf guard"},
    "tool_use_id": "toolu_warm_path_probe",
}
_HOOK_ALLOW_CLASSES = frozenset({"permission_allow", "empty", "empty_object"})


def clean_env(python: Path, home: Path) -> dict[str, str]:
    """Return an environment with no Guard, Python or pytest overrides."""

    env = {key: value for key, value in os.environ.items() if not key.startswith(("HOL_GUARD_", "GUARD_", "PYTEST"))}
    for key in ("PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV"):
        env.pop(key, None)
    env["HOME"] = str(home)
    env["XDG_CONFIG_HOME"] = str(home / ".config")
    env["XDG_STATE_HOME"] = str(home / ".local" / "state")
    env["XDG_DATA_HOME"] = str(home / ".local" / "share")
    env["PATH"] = f"{python.parent}{os.pathsep}{env.get('PATH', '')}"
    return env


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


def _process_snapshot(pid: int) -> dict[str, object] | None:
    try:
        status = Path(f"/proc/{pid}/status").read_text(encoding="utf-8")
        stat = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
        fds = len(os.listdir(f"/proc/{pid}/fd"))
    except OSError:
        return None
    fields = {line.split(":", 1)[0]: line.split(":", 1)[1].strip() for line in status.splitlines() if ":" in line}
    after_name = stat.rsplit(")", 1)[1].split()
    ticks = int(after_name[11]) + int(after_name[12])
    return {
        "pid": pid,
        "name": fields.get("Name", "?"),
        "rss_kb": int(fields.get("VmRSS", "0 kB").split()[0]),
        "threads": int(fields.get("Threads", "0")),
        "fds": fds,
        "cpu_s": ticks / _CLK_TCK,
    }


def service_snapshot(baseline: set[int], root: Path) -> dict[str, object]:
    """Summarize Guard processes that appeared after ``baseline`` and are still alive."""

    rows = [row for pid in sorted(guard_pids(baseline, root)) if (row := _process_snapshot(pid)) is not None]
    return {
        "processes": len(rows),
        "names": sorted(Counter(str(row["name"]) for row in rows).items()),
        "rss_mb": round(sum(int(row["rss_kb"]) for row in rows) / 1024, 2),
        "threads": sum(int(row["threads"]) for row in rows),
        "fds": sum(int(row["fds"]) for row in rows),
        "cpu_s": round(sum(float(row["cpu_s"]) for row in rows), 4),
    }


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


def _describe_interpreter(cli: Path) -> str:
    """Owner and mode of the target interpreter chain, to explain an install integrity refusal."""

    parts = [f"uid={os.getuid()}"]
    candidate = cli.parent / "python"
    for _ in range(3):
        try:
            metadata = candidate.lstat()
        except OSError as error:
            parts.append(f"{candidate}: {error.__class__.__name__}")
            break
        parts.append(f"{candidate}: uid={metadata.st_uid} gid={metadata.st_gid} mode={oct(metadata.st_mode)}")
        if not candidate.is_symlink():
            break
        candidate = candidate.parent / os.readlink(candidate)
    return "; ".join(parts)


def _run_install(cli: Path, harness: str, env: dict[str, str], home: Path, guard_home: Path, workspace: Path) -> None:
    result = subprocess.run(
        [
            str(cli),
            "install",
            harness,
            "--home",
            str(home),
            "--guard-home",
            str(guard_home),
            "--workspace",
            str(workspace),
            "--json",
        ],
        env=env,
        cwd=workspace,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"guard install {harness} failed rc={result.returncode}: {result.stderr[-1500:]} "
            f"[interpreter {_describe_interpreter(cli)}]"
        )


def classify_hook_output(returncode: int, stdout: str) -> str:
    if returncode != 0:
        return f"exit_{returncode}"
    text = stdout.strip()
    if not text:
        return "empty"
    try:
        payload = json.loads(text)
    except ValueError:
        return "non_json"
    if not isinstance(payload, dict):
        return "other_json"
    if not payload:
        return "empty_object"
    specific = payload.get("hookSpecificOutput")
    permission = specific.get("permissionDecision") if isinstance(specific, dict) else None
    if isinstance(permission, str):
        return f"permission_{permission}"
    decision = payload.get("decision")
    return f"decision_{decision}" if isinstance(decision, str) else "other_json"


def _claude_pretool_handler(home: Path, workspace: Path) -> list[str] | str:
    for candidate in (
        home / ".claude" / "settings.json",
        workspace / ".claude" / "settings.json",
        workspace / ".claude" / "settings.local.json",
    ):
        if not candidate.is_file():
            continue
        hooks = json.loads(candidate.read_text(encoding="utf-8")).get("hooks", {})
        for group in hooks.get("PreToolUse", []):
            for handler in group.get("hooks", []):
                if handler.get("type") == "command" and handler.get("command"):
                    if "args" in handler:
                        return [str(handler["command"]), *map(str, handler["args"])]
                    return str(handler["command"])
    raise RuntimeError("installed Claude settings carry no PreToolUse command handler")


def run_hook_phase(cli: Path, env: dict[str, str], root: Path, *, warmup: int, samples: int) -> dict[str, object]:
    home, guard_home, workspace = root / "home", root / "guard-home", root / "workspace"
    for directory in (home, guard_home, workspace):
        directory.mkdir(parents=True, exist_ok=True)
    baseline = alive_pids()
    try:
        _run_install(cli, "claude-code", env, home, guard_home, workspace)
        handler = _claude_pretool_handler(home, workspace)
        payload = json.dumps({**_BENIGN_HOOK_PAYLOAD, "cwd": str(workspace)})

        def call() -> tuple[float, str]:
            started = time.perf_counter_ns()
            result = subprocess.run(
                handler,
                input=payload,
                shell=isinstance(handler, str),
                env=env,
                cwd=workspace,
                capture_output=True,
                text=True,
                timeout=_CALL_TIMEOUT_SECONDS,
                check=False,
            )
            elapsed = (time.perf_counter_ns() - started) / 1e6
            return elapsed, classify_hook_output(result.returncode, result.stdout)

        warmup_ms = [call()[0] for _ in range(warmup)]
        before_service = service_snapshot(baseline, root)
        before_children = resource.getrusage(resource.RUSAGE_CHILDREN)
        observed = [call() for _ in range(samples)]
        after_children = resource.getrusage(resource.RUSAGE_CHILDREN)
        after_service = service_snapshot(baseline, root)
    finally:
        stop_services(cli, env, home, guard_home, baseline, root)
    latencies = [elapsed for elapsed, _ in observed]
    classes = Counter(label for _, label in observed)
    client_cpu_ms = (
        (after_children.ru_utime + after_children.ru_stime) - (before_children.ru_utime + before_children.ru_stime)
    ) * 1000
    service_cpu_ms = (float(after_service["cpu_s"]) - float(before_service["cpu_s"])) * 1000
    return {
        "samples_ms": latencies,
        "stats_ms": describe(latencies),
        "classes": dict(classes),
        "non_allow": sum(count for label, count in classes.items() if label not in _HOOK_ALLOW_CLASSES),
        "warmup_ms": warmup_ms,
        "client_cpu_ms_per_call": client_cpu_ms / max(1, samples),
        "service_cpu_ms_per_call": service_cpu_ms / max(1, samples),
        "service": after_service,
        "handler_shape": {"kind": "shell" if isinstance(handler, str) else "argv", "length": len(handler)},
    }


class _ProxySession:
    def __init__(self, argv: list[str], env: dict[str, str], cwd: Path, stderr_path: Path) -> None:
        self._stderr = stderr_path.open("wb")
        self.process = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=self._stderr,
            env=env,
            cwd=cwd,
            bufsize=0,
        )
        self._lines: queue.Queue[bytes] = queue.Queue()
        self.server_requests = 0
        self._stderr_path = stderr_path
        threading.Thread(target=self._pump, daemon=True).start()

    def _pump(self) -> None:
        assert self.process.stdout is not None
        for line in iter(self.process.stdout.readline, b""):
            self._lines.put(line)
        self._lines.put(b"")

    def notify(self, message: dict[str, object]) -> None:
        assert self.process.stdin is not None
        self.process.stdin.write((json.dumps(message) + "\n").encode("utf-8"))

    def request(self, message: dict[str, object]) -> tuple[float, dict[str, object]]:
        started = time.perf_counter_ns()
        self.notify(message)
        while True:
            try:
                line = self._lines.get(timeout=_CALL_TIMEOUT_SECONDS)
            except queue.Empty as error:
                raise TimeoutError(f"proxy did not answer request {message.get('id')}") from error
            if not line:
                tail = self._stderr_path.read_text(encoding="utf-8", errors="replace")[-1500:]
                raise RuntimeError(f"proxy closed stdout before answering request {message.get('id')}: {tail}")
            elapsed = (time.perf_counter_ns() - started) / 1e6
            try:
                decoded = json.loads(line)
            except ValueError:
                continue
            if isinstance(decoded, dict) and decoded.get("id") == message.get("id") and "method" not in decoded:
                return elapsed, decoded
            if isinstance(decoded, dict) and "method" in decoded and "id" in decoded:
                # A server-to-client request is not the answer to ours: decline it and keep waiting.
                self.notify(
                    {
                        "jsonrpc": "2.0",
                        "id": decoded["id"],
                        "error": {"code": -32601, "message": "method not supported by the probe client"},
                    }
                )
                self.server_requests += 1

    def close(self) -> None:
        try:
            if self.process.stdin is not None:
                self.process.stdin.close()
            self.process.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            self.process.kill()
        self._stderr.close()


def classify_mcp_response(response: dict[str, object], *, expected_text: str = "safe_echo") -> str:
    error = response.get("error")
    if isinstance(error, dict):
        return f"error_{error.get('code')}"
    result = response.get("result")
    if isinstance(result, dict):
        if result.get("isError"):
            return "tool_error"
        content = result.get("content")
        texts = (
            [str(item.get("text", "")) for item in content if isinstance(item, dict)]
            if isinstance(content, list)
            else []
        )
        # The canary echoes ``<label>:<tool>``; anything else is not the requested tool's reply.
        return "ok" if any(text.endswith(f":{expected_text}") for text in texts) else "unexpected_result"
    return "unknown"


def _codex_proxy_command(home: Path) -> tuple[list[str], dict[str, str]]:
    with (home / ".codex" / "config.toml").open("rb") as handle:
        entry = tomllib.load(handle)["mcp_servers"]["canary"]
    return [str(entry["command"]), *map(str, entry["args"])], {
        str(k): str(v) for k, v in dict(entry.get("env", {})).items()
    }


def run_mcp_phase(
    cli: Path, env: dict[str, str], root: Path, *, canary: Path, interpreter: str, warmup: int, samples: int
) -> dict[str, object]:
    home, guard_home, workspace = root / "home", root / "guard-home", root / "workspace"
    for directory in (home, guard_home, workspace / ".codex"):
        directory.mkdir(parents=True, exist_ok=True)
    (workspace / ".codex" / "config.toml").write_text(
        "[mcp_servers.canary]\n"
        f"command = {json.dumps(interpreter)}\n"
        f'args = [{json.dumps(str(canary))}, "--marker-path", {json.dumps(str(root / "marker.json"))}]\n',
        encoding="utf-8",
    )
    baseline = alive_pids()
    session: _ProxySession | None = None
    try:
        _run_install(cli, "codex", env, home, guard_home, workspace)
        argv, proxy_env = _codex_proxy_command(home)
        started = time.perf_counter_ns()
        session = _ProxySession(argv, {**env, **proxy_env}, workspace, root / "proxy.stderr")
        _, init = session.request(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "warm-path-probe", "version": "1"},
                },
            }
        )
        session_ready_ms = (time.perf_counter_ns() - started) / 1e6
        session.notify({"jsonrpc": "2.0", "method": "notifications/initialized"})
        session.request({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        next_id = 3

        def call() -> tuple[float, str]:
            nonlocal next_id
            message = {
                "jsonrpc": "2.0",
                "id": next_id,
                "method": "tools/call",
                "params": {"name": "safe_echo", "arguments": {"text": "guard"}},
            }
            next_id += 1
            elapsed, response = session.request(message)  # type: ignore[union-attr]
            return elapsed, classify_mcp_response(response)

        warmup_ms = [call()[0] for _ in range(warmup)]
        before_service = service_snapshot(baseline, root)
        observed = [call() for _ in range(samples)]
        after_service = service_snapshot(baseline, root)
    finally:
        if session is not None:
            session.close()
        stop_services(cli, env, home, guard_home, baseline, root)
    latencies = [elapsed for elapsed, _ in observed]
    classes = Counter(label for _, label in observed)
    return {
        "samples_ms": latencies,
        "stats_ms": describe(latencies),
        "classes": dict(classes),
        "non_allow": sum(count for label, count in classes.items() if label != "ok"),
        "server_requests_declined": session.server_requests if session is not None else 0,
        "warmup_ms": warmup_ms,
        "session_ready_ms": session_ready_ms,
        "initialize_class": "ok" if isinstance(init.get("result"), dict) else classify_mcp_response(init),
        "service_cpu_ms_per_call": (float(after_service["cpu_s"]) - float(before_service["cpu_s"]))
        * 1000
        / max(1, samples),
        "service": after_service,
    }
