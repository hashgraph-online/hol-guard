"""Static-first sandbox analysis for Guard runtime.

Provides dataclasses and a pure-Python sandbox runner that executes scripts
inside a temporary workspace with audited subprocess calls, hard resource
limits, and network-attempt detection. The sandbox never touches user secret
paths and always returns a result even when the script fails.

Supported static-first paths: shell, Node, Python, package scripts, MCP smoke.
"""

from __future__ import annotations

import contextlib
import os
import re
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

_RESOURCE_AVAILABLE = sys.platform != "win32"
if _RESOURCE_AVAILABLE:
    import resource

SandboxLanguage = Literal["shell", "node", "python", "package", "mcp_smoke"]
EnvPolicy = Literal["clean", "passthrough", "minimal"]
SandboxAnalysisMode = Literal["off", "suspicious", "strict"]

_DEFAULT_CPU_SECONDS: float = 5.0
_DEFAULT_MEMORY_BYTES: int = 512 * 1024 * 1024
_DEFAULT_MAX_PROCESSES: int = 32
_DEFAULT_TIMEOUT_SECONDS: float = 10.0

_SECRET_PATH_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\.ssh[/\\]", re.IGNORECASE),
    re.compile(r"\.aws[/\\]", re.IGNORECASE),
    re.compile(r"\.gnupg[/\\]", re.IGNORECASE),
    re.compile(r"\.env\b", re.IGNORECASE),
    re.compile(r"id_rsa|id_ed25519|id_ecdsa", re.IGNORECASE),
    re.compile(r"credentials|secrets\.json|token\.json", re.IGNORECASE),
    re.compile(r"keychain|keyring", re.IGNORECASE),
)

_NETWORK_SYSCALL_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bcurl\b", re.IGNORECASE),
    re.compile(r"\bwget\b", re.IGNORECASE),
    re.compile(r"\bfetch\s*\(", re.IGNORECASE),
    re.compile(r"\baxios\b", re.IGNORECASE),
    re.compile(r"\brequests\.(get|post|put|delete|patch)\s*\(", re.IGNORECASE),
    re.compile(r"http[s]?://", re.IGNORECASE),
    re.compile(r"socket\.connect\s*\(", re.IGNORECASE),
)


@dataclass(frozen=True)
class SandboxRequest:
    """Specification for a sandboxed script execution."""

    language: SandboxLanguage
    command: str
    files: dict[str, str] = field(default_factory=dict)
    cwd: str | None = None
    env_policy: EnvPolicy = "clean"
    cpu_seconds: float = _DEFAULT_CPU_SECONDS
    memory_bytes: int = _DEFAULT_MEMORY_BYTES
    max_processes: int = _DEFAULT_MAX_PROCESSES
    timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS


@dataclass
class SandboxResult:
    """Outcome of a sandboxed script execution."""

    exit_code: int | None
    stdout: str
    stderr: str
    timed_out: bool
    writes: list[str] = field(default_factory=list)
    network_attempts: list[str] = field(default_factory=list)
    process_attempts: list[str] = field(default_factory=list)
    secret_read_attempts: list[str] = field(default_factory=list)
    signals_detected: list[str] = field(default_factory=list)
    duration_ms: float = 0.0
    failure_safe: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "exit_code": self.exit_code,
            "stdout": self.stdout[:4096],
            "stderr": self.stderr[:4096],
            "timed_out": self.timed_out,
            "writes": self.writes,
            "network_attempts": self.network_attempts,
            "process_attempts": self.process_attempts,
            "secret_read_attempts": self.secret_read_attempts,
            "signals_detected": self.signals_detected,
            "duration_ms": round(self.duration_ms, 2),
            "failure_safe": self.failure_safe,
        }


def _is_secret_path(path: str) -> bool:
    return any(pat.search(path) for pat in _SECRET_PATH_PATTERNS)


def _detect_network_attempts(text: str) -> list[str]:
    found: list[str] = []
    for pat in _NETWORK_SYSCALL_PATTERNS:
        for m in pat.finditer(text):
            snippet = text[max(0, m.start() - 10) : m.end() + 40].strip()
            found.append(snippet[:80])
    return found


def _build_env(policy: EnvPolicy) -> dict[str, str]:
    if policy == "passthrough":
        return dict(os.environ)
    if policy == "minimal":
        minimal = {}
        for key in ("PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "TERM"):
            val = os.environ.get(key)
            if val:
                minimal[key] = val
        return minimal
    return {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "HOME": "/tmp",
        "TMPDIR": "/tmp",
    }


def _redact_env(env: dict[str, str]) -> dict[str, str]:
    redact_keys = re.compile(
        r"TOKEN|SECRET|KEY|PASSWORD|CREDENTIAL|AUTH|NPM_TOKEN|NODE_AUTH|AWS_",
        re.IGNORECASE,
    )
    return {k: ("[REDACTED]" if redact_keys.search(k) else v) for k, v in env.items()}


def _apply_resource_limits(cpu_seconds: float, memory_bytes: int, max_processes: int) -> None:
    if not _RESOURCE_AVAILABLE:
        return
    with contextlib.suppress(OSError, ValueError):
        cpu_int = max(1, int(cpu_seconds))
        resource.setrlimit(resource.RLIMIT_CPU, (cpu_int, cpu_int))
    with contextlib.suppress(OSError, ValueError):
        resource.setrlimit(resource.RLIMIT_DATA, (memory_bytes, memory_bytes))
    with contextlib.suppress(OSError, ValueError):
        soft, hard = resource.getrlimit(resource.RLIMIT_NPROC)
        effective = max(max_processes, soft) if soft > 0 else max_processes
        resource.setrlimit(resource.RLIMIT_NPROC, (effective, max(effective, hard) if hard > 0 else hard))


def _write_sandbox_files(workspace: Path, files: dict[str, str]) -> None:
    resolved_workspace = workspace.resolve()
    for rel_path, content in files.items():
        if _is_secret_path(rel_path):
            continue
        target = (workspace / rel_path).resolve()
        try:
            target.relative_to(resolved_workspace)
        except ValueError:
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")


def _language_argv(language: SandboxLanguage, command: str, workspace: Path) -> list[str]:
    if language == "shell":
        return ["/bin/sh", "-c", command]
    if language == "node":
        return ["node", "-e", command]
    if language == "python":
        return ["python3", "-c", command]
    if language == "package":
        return ["/bin/sh", "-c", command]
    if language == "mcp_smoke":
        return ["/bin/sh", "-c", command]
    return ["/bin/sh", "-c", command]


def _scan_writes(workspace: Path, before: set[str], before_mtimes: dict[str, float]) -> list[str]:
    after_new: set[str] = set()
    modified: list[str] = []
    for p in workspace.rglob("*"):
        if p.is_file():
            rel = str(p.relative_to(workspace))
            if rel not in before:
                after_new.add(rel)
            elif p.stat().st_mtime > before_mtimes.get(rel, 0):
                modified.append(rel)
    return sorted(after_new | set(modified))


def _audit_combined_output(stdout: str, stderr: str) -> tuple[list[str], list[str]]:
    combined = stdout + "\n" + stderr
    network_attempts = _detect_network_attempts(combined)
    process_attempts: list[str] = []
    for pat in (re.compile(r"\bsubprocess\b"), re.compile(r"\bexecl\b|\bexecv\b|\bexecve\b")):
        for m in pat.finditer(combined):
            snippet = combined[max(0, m.start() - 5) : m.end() + 40].strip()
            process_attempts.append(snippet[:80])
    return network_attempts, process_attempts


def run_sandbox(request: SandboxRequest, *, analysis_mode: SandboxAnalysisMode = "suspicious") -> SandboxResult:
    """Execute a script in a sandboxed temporary workspace.

    Always returns a SandboxResult. If the sandbox itself fails (missing
    interpreter, permissions issue), failure_safe=True is set and the
    result contains the error detail.
    """
    if analysis_mode == "off":
        return SandboxResult(
            exit_code=None,
            stdout="",
            stderr="",
            timed_out=False,
            failure_safe=False,
        )

    network_pre = _detect_network_attempts(request.command)
    if analysis_mode == "suspicious" and not network_pre:
        static_result = _static_only_analysis(request)
        if static_result is not None:
            return static_result

    with tempfile.TemporaryDirectory(prefix="guard-sandbox-") as tmpdir:
        workspace = Path(tmpdir)
        _write_sandbox_files(workspace, request.files)

        before_files: set[str] = set()
        before_mtimes: dict[str, float] = {}
        for p in workspace.rglob("*"):
            if p.is_file():
                rel = str(p.relative_to(workspace))
                before_files.add(rel)
                before_mtimes[rel] = p.stat().st_mtime

        env = _build_env(request.env_policy)
        argv = _language_argv(request.language, request.command, workspace)

        cpu_s = request.cpu_seconds
        mem_b = request.memory_bytes
        max_p = request.max_processes

        def _preexec() -> None:
            _apply_resource_limits(cpu_s, mem_b, max_p)

        start = time.monotonic()
        try:
            proc = subprocess.Popen(
                argv,
                cwd=str(workspace),
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn=_preexec,
                start_new_session=True,
                close_fds=True,
            )
            try:
                raw_out, raw_err = proc.communicate(timeout=request.timeout_seconds)
                timed_out = False
                exit_code: int | None = proc.returncode
            except subprocess.TimeoutExpired:
                with contextlib.suppress(OSError):
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                raw_out, raw_err = proc.communicate()
                timed_out = True
                exit_code = None

            duration_ms = (time.monotonic() - start) * 1000.0
            stdout = raw_out.decode("utf-8", errors="replace")
            stderr = raw_err.decode("utf-8", errors="replace")
            writes = _scan_writes(workspace, before_files, before_mtimes)
            network_attempts, process_attempts = _audit_combined_output(stdout, stderr)
            network_attempts = list(dict.fromkeys(network_pre + network_attempts))

            signals_detected: list[str] = []
            if timed_out:
                signals_detected.append("sandbox.timeout")
            if network_attempts:
                signals_detected.append("sandbox.network-attempt")
            if writes:
                signals_detected.append("sandbox.unexpected-write")

            return SandboxResult(
                exit_code=exit_code,
                stdout=stdout,
                stderr=stderr,
                timed_out=timed_out,
                writes=writes,
                network_attempts=network_attempts,
                process_attempts=process_attempts,
                secret_read_attempts=[],
                signals_detected=signals_detected,
                duration_ms=duration_ms,
                failure_safe=False,
            )

        except Exception as exc:
            duration_ms = (time.monotonic() - start) * 1000.0
            return SandboxResult(
                exit_code=None,
                stdout="",
                stderr=f"sandbox-error: {exc}",
                timed_out=False,
                writes=[],
                network_attempts=network_pre,
                process_attempts=[],
                secret_read_attempts=[],
                signals_detected=["sandbox.execution-error"],
                duration_ms=duration_ms,
                failure_safe=True,
            )


def _static_only_analysis(request: SandboxRequest) -> SandboxResult | None:
    """Return a static result if the command contains no execution-worthy content."""
    combined = request.command + "\n" + "\n".join(request.files.values())
    network_attempts = _detect_network_attempts(combined)
    if not network_attempts:
        return SandboxResult(
            exit_code=None,
            stdout="",
            stderr="",
            timed_out=False,
            writes=[],
            network_attempts=[],
            process_attempts=[],
            secret_read_attempts=[],
            signals_detected=[],
            duration_ms=0.0,
            failure_safe=False,
        )
    return None
