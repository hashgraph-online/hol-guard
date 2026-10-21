"""Black-box warm-path probes for an installed Guard wheel (measurement only).

Both probes drive the installed product through its public command line, so the
same probe code runs unchanged against any source revision:

* ``hook``: install the Claude Code hooks into a throwaway home, then execute the
  installed PreToolUse handler exactly as the harness would (one process per
  call, benign Bash payload on stdin) and time spawn to exit.
* ``mcp``: install the Codex MCP proxy around a stdlib canary server, ensure the
  daemon and run one untimed warm-up session so every version reaches its
  installed steady state, then keep one proxy session open and time each
  non-package ``tools/call`` round trip.

Linux only for resource accounting; nothing here changes product behavior.
"""

from __future__ import annotations

import json
import os
import queue
import resource
import subprocess
import threading
import time
from collections import Counter
from pathlib import Path

import tomllib
from warm_path_services import alive_pids, ensure_daemon, role_cpu_ms_per_call, service_snapshot, stop_services
from warm_path_stats import describe

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
        "service_cpu_ms_per_call_by_role": role_cpu_ms_per_call(before_service, after_service, samples),
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


def _open_mcp_session(
    argv: list[str], env: dict[str, str], cwd: Path, stderr_path: Path
) -> tuple[_ProxySession, dict[str, object], float]:
    """Spawn the installed launcher, initialize and list tools; return the session, init reply and ready ms."""

    started = time.perf_counter_ns()
    session = _ProxySession(argv, env, cwd, stderr_path)
    try:
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
        ready_ms = (time.perf_counter_ns() - started) / 1e6
        session.notify({"jsonrpc": "2.0", "method": "notifications/initialized"})
        session.request({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    except BaseException:
        session.close()
        raise
    return session, init, ready_ms


def _tool_call(session: _ProxySession, request_id: int) -> tuple[float, str]:
    message = {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {"name": "safe_echo", "arguments": {"text": "guard"}},
    }
    elapsed, response = session.request(message)
    return elapsed, classify_mcp_response(response)


def _warm_up_mcp(argv: list[str], env: dict[str, str], cwd: Path, stderr_path: Path) -> dict[str, object]:
    """One untimed session (initialize, list, one call, close) before the timed one.

    A server's first session may run under a different launcher than its later ones (the native
    relay hands an unreported server to the Python proxy, which reports its catalog), so the timed
    session must not be the first one any version sees.
    """

    started = time.perf_counter_ns()
    session, init, _ = _open_mcp_session(argv, env, cwd, stderr_path)
    try:
        _, call_class = _tool_call(session, 3)
    finally:
        session.close()
    return {
        "initialize_class": "ok" if isinstance(init.get("result"), dict) else classify_mcp_response(init),
        "call_class": call_class,
        "elapsed_ms": (time.perf_counter_ns() - started) / 1e6,
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
        # Same installed steady state for every target: daemon up, and the server seen once.
        daemon = ensure_daemon(cli, env, home, guard_home, workspace)
        argv, proxy_env = _codex_proxy_command(home)
        session_env = {**env, **proxy_env}
        warmup_session = _warm_up_mcp(argv, session_env, workspace, root / "warmup-session.stderr")
        session, init, session_ready_ms = _open_mcp_session(argv, session_env, workspace, root / "proxy.stderr")
        next_id = 3

        def call() -> tuple[float, str]:
            nonlocal next_id
            request_id, next_id = next_id, next_id + 1
            return _tool_call(session, request_id)  # type: ignore[arg-type]

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
        "service_cpu_ms_per_call_by_role": role_cpu_ms_per_call(before_service, after_service, samples),
        "service": after_service,
        "setup": {"daemon_ensure": daemon, "warmup_session": warmup_session},
    }


_SAVED_STATE_PROBE = """
import json, sys
from pathlib import Path
from codex_plugin_scanner.guard import native_policy_snapshot_direct_lane_saved as saved
from codex_plugin_scanner.guard.store import GuardStore
state = saved._integrity_state(GuardStore(Path(sys.argv[1]), prime_policy_integrity=False))
print(json.dumps({"environment": saved._environment() is not None, "integrity_state": state}))
"""


def saved_decision_inputs(python: Path, env: dict[str, str], guard_home: Path) -> str:
    """What the publisher reads to bind saved decisions, which MCP relay decisions require (informational)."""

    probe = [str(python), "-c", _SAVED_STATE_PROBE, str(guard_home)]
    result = subprocess.run(probe, env=env, capture_output=True, text=True, timeout=60, check=False)
    return (result.stdout or result.stderr).strip()[-400:]
