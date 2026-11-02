"""Optional MCP Cross Exam CLI adapter for HOL Guard."""

# fmt: off
from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
import socket
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from packaging.version import InvalidVersion, Version

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
_WRAPPERS = frozenset({
    "bash", "bunx", "cmd", "cmd.exe", "dash", "fish", "npm", "npx", "pipx", "pnpm",
    "powershell", "powershell.exe", "pwsh", "sh", "uvx", "yarn", "zsh",
})
AuditStatus = Literal["cancelled", "completed", "failed", "incomplete", "unreachable"]
_EXIT_STATUS: dict[int, AuditStatus] = {
    0: "completed", 1: "failed", 2: "failed", 3: "completed", 4: "unreachable", 130: "cancelled",
}


class McpCrossExamError(ValueError):
    def __init__(self, message: str, exit_code: int = 2) -> None:
        super().__init__(message)
        self.exit_code = exit_code


@dataclass(frozen=True, slots=True)
class McpCrossExamFinding:
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
class McpCrossExamAuditResult:
    integration_version: str
    auditor_version: str | None
    run_id: str | None
    target: str
    transport: str
    status: AuditStatus
    score: int | None
    coverage: str | None
    findings: tuple[McpCrossExamFinding, ...]
    errors: tuple[str, ...]
    artifact_paths: tuple[str, ...]
    allow_writes: bool
    finished_at: str


def integration_root(guard_home: Path) -> Path:
    return Path(guard_home) / AUDITOR_NAME


def mcp_cross_exam_enabled(guard_home: Path) -> bool:
    try:
        payload = json.loads((integration_root(guard_home) / _SETTINGS_NAME).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    return isinstance(payload, dict) and payload.get("enabled") is True


def set_mcp_cross_exam_enabled(guard_home: Path, enabled: bool) -> None:
    root = integration_root(guard_home)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = root / _SETTINGS_NAME
    path.write_text(json.dumps({"enabled": bool(enabled)}, indent=2) + "\n", encoding="utf-8")
    os.chmod(path, 0o600)


def load_mcp_cross_exam_results(guard_home: Path) -> dict[str, object]:
    root = integration_root(guard_home)
    payload: dict[str, object] = {"enabled": mcp_cross_exam_enabled(guard_home), "runs": []}
    path = root / _RESULTS_NAME
    if not path.is_file():
        return payload
    try:
        raw = json.loads(read_text_file_within_root(root, path, max_bytes=MAX_SCANNER_OUTPUT_BYTES))
    except (OSError, json.JSONDecodeError):
        return payload
    if isinstance(raw, dict) and isinstance(raw.get("runs"), list):
        payload["runs"] = raw["runs"]
    return payload


def resolve_auditor_path() -> Path:
    found = shutil.which(AUDITOR_NAME)
    if found is None:
        raise McpCrossExamError(f"{AUDITOR_NAME} is not installed. Install it independently with pipx, then retry.")
    path = Path(found)
    if not path.is_absolute():
        raise McpCrossExamError("auditor executable must use an absolute path")
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise McpCrossExamError("auditor executable could not be resolved") from exc
    if not resolved.is_file() or not os.access(path, os.X_OK):
        raise McpCrossExamError("auditor executable must be an executable file")
    return path


def auditor_version(executable: Path) -> Version:
    result = run_bounded_scanner_process(
        [str(executable), "--version"], env=scrubbed_scanner_env(), timeout_seconds=VERSION_TIMEOUT_SECONDS
    )
    if result.timed_out or result.returncode not in {0, None}:
        raise McpCrossExamError("could not read the mcp-cross-exam version")
    match = _VERSION_RE.search(f"{result.stdout}\n{result.stderr}")
    if match is None:
        raise McpCrossExamError("could not parse the mcp-cross-exam version")
    try:
        version = Version(match.group(0))
    except InvalidVersion as exc:
        raise McpCrossExamError("could not parse the mcp-cross-exam version") from exc
    if version < MIN_AUDITOR_VERSION:
        raise McpCrossExamError(f"mcp-cross-exam {version} is unsupported; install {MIN_AUDITOR_VERSION} or newer.")
    return version


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
        raise McpCrossExamError(f"target host did not resolve: {host}") from exc
    found: list[str] = []
    for info in infos:
        address = info[4][0]
        if isinstance(address, str) and (bare := address.split("%", 1)[0]) not in found:
            found.append(bare)
    if not found:
        raise McpCrossExamError(f"target host did not resolve: {host}")
    return tuple(found)


def validate_http_target(url: str, *, allow_remote: bool) -> str:
    parsed = urlsplit(url)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise McpCrossExamError("target must be an http(s) URL")
    if parsed.username is not None or parsed.password is not None or parsed.fragment:
        raise McpCrossExamError("target must not contain credentials or a fragment")
    if not allow_remote and not all(_loopback(item) for item in _addresses(parsed.hostname.rstrip("."))):
        raise McpCrossExamError("remote targets require --not-production")
    return url


def resolve_stdio_command(command: Sequence[str]) -> list[str]:
    if not command or any("\x00" in item for item in command):
        raise McpCrossExamError("stdio command is missing or contains NUL")
    first = command[0]
    name = Path(first).name.lower()
    if name in _WRAPPERS or name.rsplit(".", 1)[0] in _WRAPPERS:
        raise McpCrossExamError("stdio audits cannot start from a shell wrapper")
    if Path(first).is_absolute():
        resolved = first
    elif "/" in first or "\\" in first:
        raise McpCrossExamError("stdio executable must be an absolute path")
    else:
        found = shutil.which(first)
        if found is None:
            raise McpCrossExamError("stdio executable could not be resolved")
        resolved = found
    path = Path(resolved)
    try:
        path = path.resolve(strict=True)
    except OSError as exc:
        raise McpCrossExamError("stdio executable could not be resolved") from exc
    if not path.is_file() or not os.access(path, os.X_OK):
        raise McpCrossExamError("stdio executable must be an executable file")
    return [str(path), *command[1:]]


def _reject_symlink(path: Path, label: str) -> Path:
    if path.is_symlink():
        raise McpCrossExamError(f"{label} must not be a symlink")
    return path


def _existing_file(value: str | None, *, label: str) -> Path | None:
    if value is None:
        return None
    path = Path(value).expanduser()
    path = path if path.is_absolute() else Path.cwd() / path
    _reject_symlink(path, label)
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise McpCrossExamError(f"{label} could not be resolved") from exc
    if not resolved.is_file():
        raise McpCrossExamError(f"{label} must be an existing file")
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
            raise McpCrossExamError(f"invalid {flag} value")
        argv.extend([flag, value])


def build_auditor_argv(executable: Path, out_dir: Path, jobs: int, **opts: object) -> list[str]:
    argv = [str(executable), "--allow-writes" if opts.get("allow_writes") else "--read-only"]
    if opts.get("sse"):
        argv.append("--sse")
    if opts.get("not_production"):
        argv.append("--target-is-not-production")
    argv.extend(["--json", "--out-dir", str(out_dir), "--jobs", str(jobs)])
    _flags(argv, "--family", _seq(opts.get("families")))
    _flags(argv, "--probe", _seq(opts.get("probes")))
    _flags(argv, "--skip", _seq(opts.get("skip")))
    if tool := _opt(opts, "tool"):
        argv.extend(["--tool", tool])
    if (config := opts.get("config")) is not None:
        argv.extend(["--config", str(config)])
    if (snapshot := opts.get("snapshot")) is not None:
        argv.extend(["--snapshot", str(snapshot)])
    if fail_on := _opt(opts, "fail_on"):
        argv.extend(["--fail-on", fail_on])
    if opts.get("fail_on_incomplete"):
        argv.append("--fail-on-incomplete")
    if (cwd := opts.get("cwd")) is not None:
        argv.extend(["--cwd", str(cwd)])
    _flags(argv, "--env-from", _seq(opts.get("env_from")))
    if bearer := _opt(opts, "bearer_env"):
        argv.extend(["--bearer-env", bearer])
    if expired := _opt(opts, "expired_bearer_env"):
        argv.extend(["--expired-bearer-env", expired])
    _flags(argv, "--header-env", _seq(opts.get("header_env")))
    stdio = _seq(opts.get("stdio_command"))
    target = _opt(opts, "target")
    if stdio:
        argv.extend(["--", *stdio])
    elif target is None:
        raise McpCrossExamError("mcp audit requires an http(s) target or a stdio command")
    else:
        argv.append(target)
    return argv


def _seq(value: object) -> tuple[str, ...]:
    return tuple(str(item) for item in value) if isinstance(value, Sequence) and not isinstance(value, str) else ()


def _opt(opts: Mapping[str, object], key: str) -> str | None:
    value = opts.get(key)
    return value if isinstance(value, str) and value else None


def _text(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _int(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _mapping(value: object) -> Mapping[str, object] | None:
    return value if isinstance(value, dict) else None


def _command_matches(reported: object, requested: Sequence[str]) -> bool:
    if not isinstance(reported, list) or len(reported) != len(requested):
        return False
    values = [str(item) for item in reported]
    return values == list(requested) or (
        Path(values[0]).name == Path(requested[0]).name and values[1:] == list(requested[1:])
    )


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _result(
    *, target: str, transport: str, status: AuditStatus, version: str | None, allow_writes: bool,
    errors: tuple[str, ...] = (), findings: tuple[McpCrossExamFinding, ...] = (), score: int | None = None,
    coverage: str | None = None, run_id: str | None = None, artifacts: tuple[str, ...] = (),
) -> McpCrossExamAuditResult:
    return McpCrossExamAuditResult(
        integration_version=__version__, auditor_version=version, run_id=run_id, target=target,
        transport=transport, status=status, score=score, coverage=coverage, findings=findings,
        errors=errors, artifact_paths=artifacts, allow_writes=allow_writes, finished_at=_now(),
    )


def _normalize_report(
    report: Mapping[str, object], *, requested: str, stdio_command: Sequence[str], transport: str,
    allow_writes: bool, auditor_version: str, out_dir: Path, status: AuditStatus,
) -> McpCrossExamAuditResult:
    if any(key not in report for key in ("tool", "target", "server", "run", "coverage", "score", "findings")):
        raise McpCrossExamError("report.json is missing required fields", 1)
    target_record = _mapping(report.get("target")) or {}
    if transport == "stdio" and not _command_matches(target_record.get("command"), stdio_command):
        raise McpCrossExamError("report target does not match this audit", 1)
    if transport != "stdio" and _text(target_record.get("url")) != requested:
        raise McpCrossExamError("report target does not match this audit", 1)
    coverage_status = _text((_mapping(report.get("coverage")) or {}).get("status"))
    if status == "completed" and coverage_status == "partial":
        status = "incomplete"
    findings: list[McpCrossExamFinding] = []
    raw_findings = report.get("findings")
    if isinstance(raw_findings, list):
        for item in raw_findings:
            row = _mapping(item)
            if row is None:
                continue
            probe_id = _text(row.get("probe_id")) or "unknown"
            evidence = row.get("evidence")
            has_ref = isinstance(evidence, list) and evidence and isinstance(evidence[0], str)
            reference = evidence[0] if has_ref else None
            findings.append(McpCrossExamFinding(
                finding_id=_text(row.get("fingerprint")) or probe_id, probe_id=probe_id,
                family=_text(row.get("family")) or "", severity=_text(row.get("severity")) or "",
                affected_tool=_text(row.get("tool")), title=_text(row.get("title")) or probe_id,
                description=_text(row.get("detail")), evidence_reference=reference,
                score_penalty=_int(row.get("penalty")),
            ))
    names = ("report.json", "report.html", "evidence.jsonl")
    artifacts = tuple(str(out_dir / name) for name in names if (out_dir / name).is_file())
    return _result(
        target="stdio" if transport == "stdio" else requested, transport=transport, status=status,
        version=_text((_mapping(report.get("tool")) or {}).get("version")) or auditor_version,
        allow_writes=allow_writes, findings=tuple(findings), score=_int(report.get("score")),
        coverage=coverage_status, run_id=_text((_mapping(report.get("run")) or {}).get("run_id")), artifacts=artifacts,
    )


def result_payload(result: McpCrossExamAuditResult) -> dict[str, object]:
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


def _store_summary(guard_home: Path, result: McpCrossExamAuditResult) -> None:
    root = integration_root(guard_home)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    runs = list(load_mcp_cross_exam_results(guard_home).get("runs") or [])
    if not isinstance(runs, list):
        runs = []
    runs.insert(0, {
        "run_id": result.run_id, "target": result.target, "transport": result.transport, "status": result.status,
        "score": result.score, "coverage": result.coverage, "finding_count": len(result.findings),
        "severities": sorted({item.severity for item in result.findings if item.severity}),
        "probes": [item.probe_id for item in result.findings],
        "tools": sorted({item.affected_tool for item in result.findings if item.affected_tool}),
        "artifacts": list(result.artifact_paths), "auditor_version": result.auditor_version,
        "finished_at": result.finished_at,
    })
    path = root / _RESULTS_NAME
    payload = {"enabled": mcp_cross_exam_enabled(guard_home), "runs": runs[:MAX_STORED_RESULTS]}
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    os.chmod(path, 0o600)


def _secret_names(*groups: Sequence[str] | str | None) -> frozenset[str]:
    names: set[str] = set()
    for group in groups:
        if group is None:
            continue
        for item in (group,) if isinstance(group, str) else group:
            names.add(item.split("=", 1)[1] if "=" in item else item)
    return frozenset(name for name in names if name)


def run_mcp_cross_exam_audit(guard_home: Path, **opts: object) -> tuple[McpCrossExamAuditResult, int]:
    if not mcp_cross_exam_enabled(guard_home):
        raise McpCrossExamError("MCP Cross Exam is off. Run: hol-guard settings set mcp-cross-exam on")
    timeout_seconds = float(opts.get("timeout_seconds") or DEFAULT_TIMEOUT_SECONDS)
    if timeout_seconds <= 0:
        raise McpCrossExamError("timeout must be positive")
    jobs = min(max(int(opts.get("jobs") or DEFAULT_JOBS), 1), MAX_JOBS)
    allow_writes = bool(opts.get("allow_writes"))
    not_production = bool(opts.get("not_production"))
    sse = bool(opts.get("sse"))
    cwd_value, stdio = _opt(opts, "cwd"), _seq(opts.get("stdio_command"))
    workdir = Path(cwd_value).expanduser().resolve() if cwd_value else Path.cwd()
    if cwd_value:
        _reject_symlink(Path(cwd_value).expanduser(), "--cwd")
        if not workdir.is_dir():
            raise McpCrossExamError("--cwd must be an existing directory")
    executable = resolve_auditor_path()
    version = str(auditor_version(executable))
    if stdio:
        resolved_stdio = resolve_stdio_command(stdio)
        transport, requested, target = "stdio", "stdio", None
    else:
        target = _opt(opts, "target")
        if target is None:
            raise McpCrossExamError("mcp audit requires an http(s) target or a stdio command")
        validate_http_target(target, allow_remote=not_production)
        transport, requested, resolved_stdio = ("sse" if sse else "http"), target, []
    output = _prepare_out_dir(_opt(opts, "out_dir"))
    argv = build_auditor_argv(
        executable, output, jobs, target=target, stdio_command=resolved_stdio, sse=sse,
        allow_writes=allow_writes, not_production=not_production, families=_seq(opts.get("families")),
        probes=_seq(opts.get("probes")), skip=_seq(opts.get("skip")), tool=_opt(opts, "tool"),
        config=_existing_file(_opt(opts, "config"), label="--config"),
        snapshot=_existing_file(_opt(opts, "snapshot"), label="--snapshot"), fail_on=_opt(opts, "fail_on"),
        fail_on_incomplete=bool(opts.get("fail_on_incomplete")), cwd=workdir if cwd_value else None,
        env_from=_seq(opts.get("env_from")), bearer_env=_opt(opts, "bearer_env"),
        expired_bearer_env=_opt(opts, "expired_bearer_env"), header_env=_seq(opts.get("header_env")),
    )
    spawned = run_bounded_scanner_process(
        argv,
        env=scrubbed_scanner_env(allowed_secret_names=_secret_names(
            _seq(opts.get("env_from")), _opt(opts, "bearer_env"), _opt(opts, "expired_bearer_env"),
            _seq(opts.get("header_env")),
        )),
        timeout_seconds=timeout_seconds,
    )
    if spawned.timed_out:
        raise McpCrossExamError("audit timed out", 1)
    exit_code = spawned.returncode if spawned.returncode is not None else 1
    status = _EXIT_STATUS.get(exit_code, "failed")
    if exit_code == 2:
        raise McpCrossExamError(spawned.stderr.strip() or "auditor rejected the configuration", 2)
    if exit_code in {4, 130}:
        result = _result(
            target=requested, transport=transport, status=status, version=version, allow_writes=allow_writes,
            errors=(spawned.stderr.strip() or ("target unreachable" if exit_code == 4 else "audit interrupted"),),
        )
        _store_summary(guard_home, result)
        return result, exit_code
    try:
        report_text = read_text_file_within_root(output, output / "report.json", max_bytes=MAX_SCANNER_OUTPUT_BYTES)
        report = json.loads(report_text)
    except (OSError, json.JSONDecodeError) as exc:
        raise McpCrossExamError("report.json is missing or invalid", 1) from exc
    if not isinstance(report, dict):
        raise McpCrossExamError("report.json is missing or invalid", 1)
    result = _normalize_report(
        report, requested=requested, stdio_command=resolved_stdio, transport=transport,
        allow_writes=allow_writes, auditor_version=version, out_dir=output, status=status,
    )
    _store_summary(guard_home, result)
    return result, exit_code if exit_code in {0, 3} else (1 if result.status == "failed" else exit_code)


def split_mcp_audit_target(target: str | None, remainder: Sequence[str]) -> tuple[str | None, tuple[str, ...]]:
    leftover = tuple(item for item in remainder if item != "--")
    http = bool(target and target.lower().startswith(("http://", "https://")))
    if leftover:
        if target and not http:
            return None, (target, *leftover)
        return target, leftover
    if target and not http:
        raise McpCrossExamError("stdio audits require a command after --")
    return target, ()


def format_audit_summary(result: McpCrossExamAuditResult) -> str:
    findings = [
        f"  {item.severity.upper():<8} {item.probe_id}{f'    {item.affected_tool}' if item.affected_tool else ''}"
        for item in result.findings
    ] or ["  none"]
    lines = [
        "MCP Cross Exam Audit", f"Target:    {result.target}", f"Transport: {result.transport}",
        f"Mode:      {'writes' if result.allow_writes else 'read-only'}", f"Status:    {result.status}",
        f"Score:     {result.score if result.score is not None else 'n/a'}",
        f"Auditor:   {AUDITOR_NAME} {result.auditor_version or 'unknown'}", "", "Findings:", *findings, "",
        f"Coverage: {result.coverage or 'n/a'}", "Artifacts:",
        *([f"  {path}" for path in result.artifact_paths] or ["  none"]), "",
        "These are protocol and schema findings, not Guard policy verdicts.",
        "A passing score does not bypass Guard.",
    ]
    if result.allow_writes:
        lines.append("Write probes ran. Tool annotations are not verified side-effect guarantees.")
    return "\n".join([*lines, *(f"Warning: {error}" for error in result.errors)]) + "\n"


def run_guard_mcp_audit_command(args: object, *, output_stream: object | None = None) -> int:
    import sys

    from ..guard.config import resolve_guard_home

    g = getattr
    try:
        target, stdio_command = split_mcp_audit_target(g(args, "target", None), g(args, "stdio_command", []) or [])
        result, code = run_mcp_cross_exam_audit(
            resolve_guard_home(g(args, "guard_home", None) or g(args, "home", None)),
            target=target, stdio_command=stdio_command, sse=bool(g(args, "sse", False)),
            allow_writes=bool(g(args, "allow_writes", False)), not_production=bool(g(args, "not_production", False)),
            out_dir=g(args, "out_dir", None), families=tuple(g(args, "families", []) or ()),
            probes=tuple(g(args, "probes", []) or ()), skip=tuple(g(args, "skip", []) or ()),
            tool=g(args, "tool", None),
            jobs=int(g(args, "jobs", DEFAULT_JOBS) or DEFAULT_JOBS),
            timeout_seconds=float(g(args, "timeout", DEFAULT_TIMEOUT_SECONDS) or DEFAULT_TIMEOUT_SECONDS),
            config=g(args, "config", None), snapshot=g(args, "snapshot", None), fail_on=g(args, "fail_on", None),
            fail_on_incomplete=bool(g(args, "fail_on_incomplete", False)), cwd=g(args, "cwd", None),
            env_from=tuple(g(args, "env_from", []) or ()), bearer_env=g(args, "bearer_env", None),
            expired_bearer_env=g(args, "expired_bearer_env", None), header_env=tuple(g(args, "header_env", []) or ()),
        )
    except McpCrossExamError as error:
        print(f"Error: {error}", file=sys.stderr)
        return error.exit_code
    except KeyboardInterrupt:
        print("Error: audit interrupted", file=sys.stderr)
        return 130
    stream = sys.stdout if output_stream is None else output_stream
    if bool(g(args, "json", False)):
        text = json.dumps(result_payload(result), indent=2) + "\n"
    else:
        text = format_audit_summary(result)
    stream.write(text)
    return code
