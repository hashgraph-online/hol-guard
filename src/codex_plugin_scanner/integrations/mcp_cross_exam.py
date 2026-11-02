from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
import socket
import sys
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, TextIO, TypeGuard
from urllib.parse import urlsplit

from packaging.version import InvalidVersion, Version

from ..guard.config import resolve_guard_home
from ..path_support import read_text_file_within_root
from ..version import __version__
from .scanner_subprocess import MAX_SCANNER_OUTPUT_BYTES, run_bounded_scanner_process, scrubbed_scanner_env

AUDITOR_NAME = "mcp-cross-exam"
MIN_AUDITOR_VERSION = Version("0.1.0")
DEFAULT_TIMEOUT_SECONDS = 180.0
DEFAULT_JOBS = 1
MAX_JOBS = 4
MAX_STORED_RESULTS = 20
VERSION_TIMEOUT_SECONDS = 10.0
_SETTINGS_NAME = "settings.json"
_RESULTS_NAME = "results.json"
_VERSION_RE = re.compile(r"\d+\.\d+(?:\.\d+)?")
_WRAPPERS = frozenset(
    {
        "bash",
        "bunx",
        "cmd",
        "cmd.exe",
        "dash",
        "fish",
        "npm",
        "npx",
        "pipx",
        "pnpm",
        "powershell",
        "powershell.exe",
        "pwsh",
        "sh",
        "uvx",
        "yarn",
        "zsh",
    }
)
AuditStatus = Literal["cancelled", "completed", "failed", "incomplete", "unreachable"]
_EXIT_STATUS: dict[int, AuditStatus] = {
    0: "completed",
    1: "failed",
    2: "failed",
    3: "completed",
    4: "unreachable",
    130: "cancelled",
}


class MCPCrossExamError(ValueError):
    exit_code: int

    def __init__(self, message: str, exit_code: int = 2) -> None:
        super().__init__(message)
        self.exit_code = exit_code


@dataclass(frozen=True, slots=True)
class MCPCrossExamFinding:
    finding_id: str
    probe_id: str
    family: str
    severity: str
    affected_tool: str | None
    title: str
    description: str | None
    evidence_reference: str | None
    score_penalty: int | None


@dataclass(frozen=True, slots=True)
class MCPCrossExamAuditResult:
    integration_version: str
    auditor_version: str | None
    run_id: str | None
    target: str
    transport: str
    status: AuditStatus
    score: int | None
    coverage: str | None
    findings: tuple[MCPCrossExamFinding, ...]
    errors: tuple[str, ...]
    artifact_paths: tuple[str, ...]
    allow_writes: bool
    finished_at: str


def integration_root(guard_home: Path) -> Path:
    return Path(guard_home) / AUDITOR_NAME


def mcp_cross_exam_enabled(guard_home: Path) -> bool:
    try:
        payload = _json_dict((integration_root(guard_home) / _SETTINGS_NAME).read_text(encoding="utf-8"))
    except OSError:
        return False
    return payload is not None and payload.get("enabled") is True


def set_mcp_cross_exam_enabled(guard_home: Path, enabled: bool) -> None:
    root = integration_root(guard_home)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    _write_private(root / _SETTINGS_NAME, {"enabled": bool(enabled)})


def load_mcp_cross_exam_results(guard_home: Path) -> dict[str, object]:
    root = integration_root(guard_home)
    payload: dict[str, object] = {"enabled": mcp_cross_exam_enabled(guard_home), "runs": []}
    path = root / _RESULTS_NAME
    if not path.is_file():
        return payload
    try:
        raw = _json_dict(read_text_file_within_root(root, path, max_bytes=MAX_SCANNER_OUTPUT_BYTES))
    except OSError:
        return payload
    if raw is not None and _is_list(raw.get("runs")):
        payload["runs"] = raw["runs"]
    return payload


def resolve_auditor_path() -> Path:
    found = shutil.which(AUDITOR_NAME)
    if found is None:
        raise MCPCrossExamError(f"{AUDITOR_NAME} is not installed. Install it independently with pipx, then retry.")
    path = Path(found)
    if not path.is_absolute():
        raise MCPCrossExamError("auditor executable must use an absolute path")
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise MCPCrossExamError("auditor executable could not be resolved") from exc
    if not resolved.is_file() or not os.access(path, os.X_OK):
        raise MCPCrossExamError("auditor executable must be an executable file")
    return path


def auditor_version(executable: Path) -> Version:
    result = run_bounded_scanner_process(
        [str(executable), "--version"], env=scrubbed_scanner_env(), timeout_seconds=VERSION_TIMEOUT_SECONDS
    )
    if result.timed_out or result.returncode != 0:
        raise MCPCrossExamError("could not read the mcp-cross-exam version")
    match = _VERSION_RE.search(f"{result.stdout}\n{result.stderr}")
    if match is None:
        raise MCPCrossExamError("could not parse the mcp-cross-exam version")
    try:
        version = Version(match.group(0))
    except InvalidVersion as exc:
        raise MCPCrossExamError("could not parse the mcp-cross-exam version") from exc
    if version < MIN_AUDITOR_VERSION:
        raise MCPCrossExamError(f"mcp-cross-exam {version} is unsupported; install {MIN_AUDITOR_VERSION} or newer.")
    return version


def validate_http_target(url: str, *, allow_remote: bool) -> None:
    parsed = urlsplit(url)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise MCPCrossExamError("target must be an http(s) URL")
    if parsed.username is not None or parsed.password is not None or parsed.fragment:
        raise MCPCrossExamError("target must not contain credentials or a fragment")
    if not allow_remote and not all(_loopback(item) for item in _addresses(parsed.hostname.rstrip("."))):
        raise MCPCrossExamError("remote targets require --not-production")


def resolve_stdio_command(command: Sequence[str]) -> list[str]:
    if not command or any("\x00" in item for item in command):
        raise MCPCrossExamError("stdio command is missing or contains NUL")
    first = command[0]
    name = Path(first).name.lower()
    if name in _WRAPPERS or name.rsplit(".", 1)[0] in _WRAPPERS:
        raise MCPCrossExamError("stdio audits cannot start from a shell wrapper")
    if Path(first).is_absolute():
        resolved = first
    elif "/" in first or "\\" in first:
        raise MCPCrossExamError("stdio executable must be an absolute path")
    else:
        found = shutil.which(first)
        if found is None:
            raise MCPCrossExamError("stdio executable could not be resolved")
        resolved = found
    path = Path(resolved)
    try:
        path = path.resolve(strict=True)
    except OSError as exc:
        raise MCPCrossExamError("stdio executable could not be resolved") from exc
    if not path.is_file() or not os.access(path, os.X_OK):
        raise MCPCrossExamError("stdio executable must be an executable file")
    return [str(path), *command[1:]]


def build_auditor_argv(
    executable: Path,
    out_dir: Path,
    jobs: int,
    *,
    target: str | None,
    stdio_command: Sequence[str],
    sse: bool,
    allow_writes: bool,
    not_production: bool,
    families: Sequence[str],
    probes: Sequence[str],
    skip: Sequence[str],
    tool: str | None,
    config: Path | None,
    snapshot: Path | None,
    fail_on: str | None,
    fail_on_incomplete: bool,
    cwd: Path | None,
    env_from: Sequence[str],
    bearer_env: str | None,
    expired_bearer_env: str | None,
    header_env: Sequence[str],
) -> list[str]:
    argv = [str(executable), "--allow-writes" if allow_writes else "--read-only"]
    if sse:
        argv.append("--sse")
    if not_production:
        argv.append("--target-is-not-production")
    argv.extend(["--json", "--out-dir", str(out_dir), "--jobs", str(jobs)])
    _flags(argv, "--family", families)
    _flags(argv, "--probe", probes)
    _flags(argv, "--skip", skip)
    if tool:
        argv.extend(["--tool", tool])
    if config is not None:
        argv.extend(["--config", str(config)])
    if snapshot is not None:
        argv.extend(["--snapshot", str(snapshot)])
    if fail_on:
        argv.extend(["--fail-on", fail_on])
    if fail_on_incomplete:
        argv.append("--fail-on-incomplete")
    if cwd is not None:
        argv.extend(["--cwd", str(cwd)])
    _flags(argv, "--env-from", env_from)
    if bearer_env:
        argv.extend(["--bearer-env", bearer_env])
    if expired_bearer_env:
        argv.extend(["--expired-bearer-env", expired_bearer_env])
    _flags(argv, "--header-env", header_env)
    if stdio_command:
        argv.extend(["--", *stdio_command])
    elif target is None:
        raise MCPCrossExamError("mcp audit requires an http(s) target or a stdio command")
    else:
        argv.append(target)
    return argv


def result_payload(result: MCPCrossExamAuditResult) -> dict[str, object]:
    payload = asdict(result)
    payload["findings"] = [asdict(item) for item in result.findings]
    payload["note"] = (
        "Protocol and schema findings from MCP Cross Exam. They are not Guard policy verdicts "
        "and a passing score does not bypass Guard."
    )
    if result.allow_writes:
        payload["write_warning"] = (
            "Write probes ran because --allow-writes was set. Tool annotations are not verified side-effect guarantees."
        )
    return payload


def run_mcp_cross_exam_audit(
    guard_home: Path,
    *,
    target: str | None = None,
    stdio_command: Sequence[str] = (),
    sse: bool = False,
    allow_writes: bool = False,
    not_production: bool = False,
    out_dir: str | None = None,
    families: Sequence[str] = (),
    probes: Sequence[str] = (),
    skip: Sequence[str] = (),
    tool: str | None = None,
    jobs: int = DEFAULT_JOBS,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    config: str | None = None,
    snapshot: str | None = None,
    fail_on: str | None = None,
    fail_on_incomplete: bool = False,
    cwd: str | None = None,
    env_from: Sequence[str] = (),
    bearer_env: str | None = None,
    expired_bearer_env: str | None = None,
    header_env: Sequence[str] = (),
) -> tuple[MCPCrossExamAuditResult, int]:
    if not mcp_cross_exam_enabled(guard_home):
        raise MCPCrossExamError("MCP Cross Exam is off. Run: hol-guard settings set mcp-cross-exam on")
    if timeout_seconds <= 0:
        raise MCPCrossExamError("timeout must be positive")
    jobs = min(max(jobs, 1), MAX_JOBS)
    workdir = Path(cwd).expanduser().resolve() if cwd else Path.cwd()
    if cwd:
        _reject_symlink(Path(cwd).expanduser(), "--cwd")
        if not workdir.is_dir():
            raise MCPCrossExamError("--cwd must be an existing directory")
    executable = resolve_auditor_path()
    version = str(auditor_version(executable))
    if stdio_command:
        resolved_stdio = resolve_stdio_command(stdio_command)
        transport, requested, http_target = "stdio", "stdio", None
    else:
        if target is None:
            raise MCPCrossExamError("mcp audit requires an http(s) target or a stdio command")
        validate_http_target(target, allow_remote=not_production)
        transport, requested, resolved_stdio, http_target = ("sse" if sse else "http"), target, (), target
    output = _prepare_out_dir(out_dir)
    argv = build_auditor_argv(
        executable,
        output,
        jobs,
        target=http_target,
        stdio_command=resolved_stdio,
        sse=sse,
        allow_writes=allow_writes,
        not_production=not_production,
        families=families,
        probes=probes,
        skip=skip,
        tool=tool,
        config=_existing_file(config, label="--config"),
        snapshot=_existing_file(snapshot, label="--snapshot"),
        fail_on=fail_on,
        fail_on_incomplete=fail_on_incomplete,
        cwd=workdir if cwd else None,
        env_from=env_from,
        bearer_env=bearer_env,
        expired_bearer_env=expired_bearer_env,
        header_env=header_env,
    )
    spawned = run_bounded_scanner_process(
        argv,
        env=scrubbed_scanner_env(
            allowed_secret_names=_secret_names(env_from, bearer_env, expired_bearer_env, header_env)
        ),
        timeout_seconds=timeout_seconds,
    )
    if spawned.timed_out:
        raise MCPCrossExamError("audit timed out", 1)
    exit_code = spawned.returncode
    status = _EXIT_STATUS.get(exit_code, "failed")
    if exit_code == 2:
        raise MCPCrossExamError(spawned.stderr.strip() or "auditor rejected the configuration", 2)
    if exit_code in {4, 130}:
        result = _result(
            target=requested,
            transport=transport,
            status=status,
            version=version,
            allow_writes=allow_writes,
            errors=(spawned.stderr.strip() or ("target unreachable" if exit_code == 4 else "audit interrupted"),),
        )
        _store_summary(guard_home, result)
        return result, exit_code
    try:
        report = _json_dict(
            read_text_file_within_root(output, output / "report.json", max_bytes=MAX_SCANNER_OUTPUT_BYTES)
        )
    except OSError as exc:
        raise MCPCrossExamError("report.json is missing or invalid", 1) from exc
    if report is None:
        raise MCPCrossExamError("report.json is missing or invalid", 1)
    result = _normalize_report(
        report,
        requested=requested,
        stdio_command=resolved_stdio,
        transport=transport,
        allow_writes=allow_writes,
        auditor_version=version,
        out_dir=output,
        status=status,
    )
    _store_summary(guard_home, result)
    if exit_code in {0, 3}:
        return result, exit_code
    return result, 1 if result.status == "failed" else exit_code


def split_mcp_audit_target(target: str | None, remainder: Sequence[str]) -> tuple[str | None, tuple[str, ...]]:
    leftover = tuple(item for item in remainder if item != "--")
    http = bool(target and target.lower().startswith(("http://", "https://")))
    if leftover:
        if target and not http:
            return None, (target, *leftover)
        return target, leftover
    if target and not http:
        raise MCPCrossExamError("stdio audits require a remainder command")
    return target, ()


def format_audit_summary(result: MCPCrossExamAuditResult) -> str:
    findings = [
        f"  {item.severity.upper():<8} {item.probe_id}{f'    {item.affected_tool}' if item.affected_tool else ''}"
        for item in result.findings
    ] or ["  none"]
    lines = [
        "MCP Cross Exam Audit",
        f"Target:    {result.target}",
        f"Transport: {result.transport}",
        f"Mode:      {'writes' if result.allow_writes else 'read-only'}",
        f"Status:    {result.status}",
        f"Score:     {result.score if result.score is not None else 'n/a'}",
        f"Auditor:   {AUDITOR_NAME} {result.auditor_version or 'unknown'}",
        "",
        "Findings:",
        *findings,
        "",
        f"Coverage: {result.coverage or 'n/a'}",
        "Artifacts:",
        *([f"  {path}" for path in result.artifact_paths] or ["  none"]),
        "",
        "These are protocol and schema findings, not Guard policy verdicts.",
        "A passing score does not bypass Guard.",
    ]
    if result.allow_writes:
        lines.append("Write probes ran. Tool annotations are not verified side-effect guarantees.")
    return "\n".join([*lines, *(f"Warning: {error}" for error in result.errors)]) + "\n"


def run_guard_mcp_audit_command(args: object, *, output_stream: TextIO | None = None) -> int:
    try:
        target, stdio_command = split_mcp_audit_target(_attr_str(args, "target"), _attr_seq(args, "stdio_command"))
        result, code = run_mcp_cross_exam_audit(
            resolve_guard_home(_attr_str(args, "guard_home") or _attr_str(args, "home")),
            target=target,
            stdio_command=stdio_command,
            sse=_attr_bool(args, "sse"),
            allow_writes=_attr_bool(args, "allow_writes"),
            not_production=_attr_bool(args, "not_production"),
            out_dir=_attr_str(args, "out_dir"),
            families=_attr_seq(args, "families"),
            probes=_attr_seq(args, "probes"),
            skip=_attr_seq(args, "skip"),
            tool=_attr_str(args, "tool"),
            jobs=_attr_int(args, "jobs", DEFAULT_JOBS),
            timeout_seconds=_attr_float(args, "timeout", DEFAULT_TIMEOUT_SECONDS),
            config=_attr_str(args, "config"),
            snapshot=_attr_str(args, "snapshot"),
            fail_on=_attr_str(args, "fail_on"),
            fail_on_incomplete=_attr_bool(args, "fail_on_incomplete"),
            cwd=_attr_str(args, "cwd"),
            env_from=_attr_seq(args, "env_from"),
            bearer_env=_attr_str(args, "bearer_env"),
            expired_bearer_env=_attr_str(args, "expired_bearer_env"),
            header_env=_attr_seq(args, "header_env"),
        )
    except MCPCrossExamError as error:
        print(f"Error: {error}", file=sys.stderr)
        return error.exit_code
    except KeyboardInterrupt:
        print("Error: audit interrupted", file=sys.stderr)
        return 130
    stream = sys.stdout if output_stream is None else output_stream
    text = (
        json.dumps(result_payload(result), indent=2) + "\n"
        if _attr_bool(args, "json")
        else format_audit_summary(result)
    )
    print(text, end="", file=stream)
    return code


def _loopback(address: str) -> bool:
    try:
        parsed = ipaddress.ip_address(address.split("%", 1)[0])
    except ValueError:
        return False
    mapped = parsed.ipv4_mapped if isinstance(parsed, ipaddress.IPv6Address) else None
    return bool((mapped or parsed).is_loopback)


def _addresses(host: str) -> tuple[str, ...]:
    try:
        return (str(ipaddress.ip_address(host)),)
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise MCPCrossExamError(f"target host did not resolve: {host}") from exc
    found: list[str] = []
    for info in infos:
        address = info[4][0]
        if isinstance(address, str) and (bare := address.split("%", 1)[0]) not in found:
            found.append(bare)
    if not found:
        raise MCPCrossExamError(f"target host did not resolve: {host}")
    return tuple(found)


def _reject_symlink(path: Path, label: str) -> None:
    if path.is_symlink():
        raise MCPCrossExamError(f"{label} must not be a symlink")


def _existing_file(value: str | None, *, label: str) -> Path | None:
    if value is None:
        return None
    path = Path(value).expanduser()
    path = path if path.is_absolute() else Path.cwd() / path
    _reject_symlink(path, label)
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise MCPCrossExamError(f"{label} could not be resolved") from exc
    if not resolved.is_file():
        raise MCPCrossExamError(f"{label} must be an existing file")
    return resolved


def _prepare_out_dir(value: str | None) -> Path:
    path = Path(value).expanduser() if value else Path.cwd() / "mcp-cross-exam-results"
    path = path if path.is_absolute() else Path.cwd() / path
    if path.exists():
        _reject_symlink(path, "--out-dir")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    return path.resolve()


def _flags(argv: list[str], flag: str, values: Sequence[str]) -> None:
    for value in values:
        if not value or "\x00" in value:
            raise MCPCrossExamError(f"invalid {flag} value")
        argv.extend([flag, value])


def _attr_str(args: object, name: str) -> str | None:
    value = getattr(args, name, None)
    return value if isinstance(value, str) and value else None


def _attr_bool(args: object, name: str) -> bool:
    return bool(getattr(args, name, False))


def _attr_seq(args: object, name: str) -> tuple[str, ...]:
    raw: object = getattr(args, name, ())
    if isinstance(raw, str) or not _is_list(raw):
        return ()
    return tuple(str(item) for item in raw)


def _attr_int(args: object, name: str, default: int) -> int:
    value = getattr(args, name, default)
    return value if isinstance(value, int) and not isinstance(value, bool) else default


def _attr_float(args: object, name: str, default: float) -> float:
    value = getattr(args, name, default)
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else default


def _text(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _int(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _is_mapping(value: object) -> TypeGuard[dict[str, object]]:
    return isinstance(value, dict)


def _is_list(value: object) -> TypeGuard[list[object]]:
    return isinstance(value, list)


def _json_dict(text: str) -> dict[str, object] | None:
    if not text.lstrip().startswith("{"):
        return None
    objects: list[dict[str, object]] = []

    def hook(pairs: list[tuple[str, object]]) -> dict[str, object]:
        payload = dict(pairs)
        objects.append(payload)
        return payload

    try:
        json.loads(text, object_pairs_hook=hook)
    except json.JSONDecodeError:
        return None
    return objects[-1] if objects else None


def _command_matches(reported: object, requested: Sequence[str]) -> bool:
    if not _is_list(reported) or len(reported) != len(requested):
        return False
    values = [str(item) for item in reported]
    return values == list(requested) or (
        Path(values[0]).name == Path(requested[0]).name and values[1:] == list(requested[1:])
    )


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _result(
    *,
    target: str,
    transport: str,
    status: AuditStatus,
    version: str | None,
    allow_writes: bool,
    errors: tuple[str, ...] = (),
    findings: tuple[MCPCrossExamFinding, ...] = (),
    score: int | None = None,
    coverage: str | None = None,
    run_id: str | None = None,
    artifacts: tuple[str, ...] = (),
) -> MCPCrossExamAuditResult:
    return MCPCrossExamAuditResult(
        integration_version=__version__,
        auditor_version=version,
        run_id=run_id,
        target=target,
        transport=transport,
        status=status,
        score=score,
        coverage=coverage,
        findings=findings,
        errors=errors,
        artifact_paths=artifacts,
        allow_writes=allow_writes,
        finished_at=_now(),
    )


def _normalize_report(
    report: Mapping[str, object],
    *,
    requested: str,
    stdio_command: Sequence[str],
    transport: str,
    allow_writes: bool,
    auditor_version: str,
    out_dir: Path,
    status: AuditStatus,
) -> MCPCrossExamAuditResult:
    if any(key not in report for key in ("tool", "target", "server", "run", "coverage", "score", "findings")):
        raise MCPCrossExamError("report.json is missing required fields", 1)
    target_record = report.get("target")
    target_map = target_record if _is_mapping(target_record) else {}
    if transport == "stdio" and not _command_matches(target_map.get("command"), stdio_command):
        raise MCPCrossExamError("report target does not match this audit", 1)
    if transport != "stdio" and _text(target_map.get("url")) != requested:
        raise MCPCrossExamError("report target does not match this audit", 1)
    coverage = report.get("coverage")
    coverage_status = _text(coverage.get("status") if _is_mapping(coverage) else None)
    if status == "completed" and coverage_status == "partial":
        status = "incomplete"
    findings: list[MCPCrossExamFinding] = []
    raw_findings = report.get("findings")
    if _is_list(raw_findings):
        for item in raw_findings:
            if not _is_mapping(item):
                continue
            probe_id = _text(item.get("probe_id")) or "unknown"
            evidence = item.get("evidence")
            first = evidence[0] if _is_list(evidence) and evidence else None
            findings.append(
                MCPCrossExamFinding(
                    finding_id=_text(item.get("fingerprint")) or probe_id,
                    probe_id=probe_id,
                    family=_text(item.get("family")) or "",
                    severity=_text(item.get("severity")) or "",
                    affected_tool=_text(item.get("tool")),
                    title=_text(item.get("title")) or probe_id,
                    description=_text(item.get("detail")),
                    evidence_reference=first if isinstance(first, str) else None,
                    score_penalty=_int(item.get("penalty")),
                )
            )
    names = ("report.json", "report.html", "evidence.jsonl")
    artifacts = tuple(str(out_dir / name) for name in names if (out_dir / name).is_file())
    tool = report.get("tool")
    run = report.get("run")
    return _result(
        target="stdio" if transport == "stdio" else requested,
        transport=transport,
        status=status,
        version=_text(tool.get("version") if _is_mapping(tool) else None) or auditor_version,
        allow_writes=allow_writes,
        findings=tuple(findings),
        score=_int(report.get("score")),
        coverage=coverage_status,
        run_id=_text(run.get("run_id") if _is_mapping(run) else None),
        artifacts=artifacts,
    )


def _write_private(path: Path, payload: dict[str, object]) -> None:
    text = json.dumps(payload, indent=2) + "\n"
    with path.open("w", encoding="utf-8") as handle:
        print(text, end="", file=handle)
    os.chmod(path, 0o600)


def _store_summary(guard_home: Path, result: MCPCrossExamAuditResult) -> None:
    root = integration_root(guard_home)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    stored = load_mcp_cross_exam_results(guard_home).get("runs")
    runs: list[object] = list(stored) if _is_list(stored) else []
    runs.insert(
        0,
        {
            "run_id": result.run_id,
            "target": result.target,
            "transport": result.transport,
            "status": result.status,
            "score": result.score,
            "coverage": result.coverage,
            "finding_count": len(result.findings),
            "severities": sorted({item.severity for item in result.findings if item.severity}),
            "probes": [item.probe_id for item in result.findings],
            "tools": sorted({item.affected_tool for item in result.findings if item.affected_tool}),
            "artifacts": list(result.artifact_paths),
            "auditor_version": result.auditor_version,
            "finished_at": result.finished_at,
        },
    )
    _write_private(
        root / _RESULTS_NAME,
        {"enabled": mcp_cross_exam_enabled(guard_home), "runs": runs[:MAX_STORED_RESULTS]},
    )


def _secret_names(*groups: Sequence[str] | str | None) -> frozenset[str]:
    names: set[str] = set()
    for group in groups:
        if group is None:
            continue
        for item in (group,) if isinstance(group, str) else group:
            names.add(item.split("=", 1)[1] if "=" in item else item)
    return frozenset(name for name in names if name)
