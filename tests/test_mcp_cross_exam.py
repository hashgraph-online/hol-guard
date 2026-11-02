from __future__ import annotations

import argparse
import json
import shutil
import socket
from collections.abc import Sequence
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.cli.commands_parser import add_guard_root_parser
from codex_plugin_scanner.integrations import mcp_cross_exam as adapter
from codex_plugin_scanner.integrations.scanner_subprocess import ScannerProcessResult

LOOPBACK = "http://127.0.0.1:8765/mcp"
REMOTE = "https://example.test/mcp"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    add_guard_root_parser(parser)
    return parser


def _enable(home: Path) -> None:
    adapter.set_mcp_cross_exam_enabled(home, True)


def _audit(
    home: Path,
    *,
    target: str | None = None,
    stdio_command: Sequence[str] = (),
    sse: bool = False,
    allow_writes: bool = False,
    not_production: bool = False,
    jobs: int = adapter.DEFAULT_JOBS,
    bearer_env: str | None = None,
    out_dir: str | None = None,
) -> tuple[adapter.MCPCrossExamAuditResult, int]:
    return adapter.run_mcp_cross_exam_audit(
        home,
        target=target,
        stdio_command=stdio_command,
        sse=sse,
        allow_writes=allow_writes,
        not_production=not_production,
        jobs=jobs,
        bearer_env=bearer_env,
        out_dir=out_dir if out_dir is not None else str(home / "out"),
    )


def _auditor(tmp_path: Path) -> Path:
    path = tmp_path / "bin" / "mcp-cross-exam"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    path.chmod(0o755)
    return path


def _report(
    *,
    url: str = LOOPBACK,
    command: list[str] | None = None,
    score: int = 90,
    coverage: str = "complete",
    findings: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    target: dict[str, object] = {"command": command} if command is not None else {"url": url}
    return {
        "tool": {"name": "mcp-cross-exam", "version": "0.1.0"},
        "target": target,
        "server": {},
        "run": {"run_id": "run-1"},
        "coverage": {"status": coverage},
        "score": score,
        "findings": findings or [],
    }


def _spawn(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    returncode: int = 0,
    stderr: str = "",
    timed_out: bool = False,
    report: dict[str, object] | None = None,
    captured: dict[str, object] | None = None,
) -> Path:
    executable = _auditor(tmp_path)
    monkeypatch.setattr(adapter.shutil, "which", lambda name: str(executable) if name == "mcp-cross-exam" else None)

    def fake_run(
        argv: list[str], env: dict[str, str] | None = None, timeout_seconds: float | None = None
    ) -> ScannerProcessResult:
        if captured is not None:
            captured["argv"] = list(argv)
            captured["env"] = dict(env or {})
            captured["timeout"] = timeout_seconds
        if argv[1:] == ["--version"]:
            return ScannerProcessResult(0, "mcp-cross-exam 0.1.0", "", False)
        if timed_out:
            return ScannerProcessResult(1, "", "", True)
        if returncode in {0, 3} and report is not None:
            out_dir = Path(argv[argv.index("--out-dir") + 1])
            (out_dir / "report.json").write_text(json.dumps(report), encoding="utf-8")
            (out_dir / "report.html").write_text("<html></html>", encoding="utf-8")
        return ScannerProcessResult(returncode, "", stderr, False)

    monkeypatch.setattr(adapter, "run_bounded_scanner_process", fake_run)
    return executable


def test_disabled_by_default(tmp_path: Path) -> None:
    assert adapter.mcp_cross_exam_enabled(tmp_path) is False
    with pytest.raises(adapter.MCPCrossExamError, match="off"):
        _audit(tmp_path, target=LOOPBACK)


def test_settings_on_missing_binary(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _enable(tmp_path)
    monkeypatch.setattr(adapter.shutil, "which", lambda _name: None)
    with pytest.raises(adapter.MCPCrossExamError, match="not installed") as error:
        _audit(tmp_path, target=LOOPBACK)
    assert error.value.exit_code == 2


def test_loopback_http_is_allowed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _enable(tmp_path)
    captured: dict[str, object] = {}
    _spawn(monkeypatch, tmp_path, report=_report(), captured=captured)
    result, code = _audit(tmp_path, target=LOOPBACK)
    assert code == 0
    assert result.status == "completed"
    assert result.score == 90
    argv = captured["argv"]
    assert isinstance(argv, list)
    assert "--read-only" in argv
    assert "--allow-writes" not in argv
    assert "--target-is-not-production" not in argv


@pytest.mark.parametrize("host", ["127.0.0.1", "::1"])
def test_loopback_literals(host: str) -> None:
    url = f"http://[{host}]:9/mcp" if ":" in host else f"http://{host}:9/mcp"
    adapter.validate_http_target(url, allow_remote=False)


def test_localhost_requires_loopback_resolution(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        adapter.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))],
    )
    adapter.validate_http_target("http://localhost:8765/mcp", allow_remote=False)


def test_remote_without_not_production_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        adapter.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))],
    )
    with pytest.raises(adapter.MCPCrossExamError, match="not-production"):
        adapter.validate_http_target(REMOTE, allow_remote=False)


def test_remote_with_not_production_sets_auditor_flag(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _enable(tmp_path)
    captured: dict[str, object] = {}
    _spawn(monkeypatch, tmp_path, report=_report(url=REMOTE), captured=captured)
    monkeypatch.setattr(
        adapter.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))],
    )
    _result, code = _audit(tmp_path, target=REMOTE, not_production=True)
    assert code == 0
    argv = captured["argv"]
    assert isinstance(argv, list)
    assert "--target-is-not-production" in argv
    assert not any(item == "allow" or str(item).endswith("allow") for item in argv)


def test_stdio_without_separator_is_refused() -> None:
    with pytest.raises(adapter.MCPCrossExamError, match="remainder command"):
        adapter.split_mcp_audit_target("python", [])


def test_stdio_with_separator_resolves_executable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _enable(tmp_path)
    script = tmp_path / "server.py"
    script.write_text("print('ok')\n", encoding="utf-8")
    python = Path(shutil.which("python3") or shutil.which("python") or "/usr/bin/python3")
    captured: dict[str, object] = {}
    command = [str(python.resolve()), str(script)]
    _spawn(monkeypatch, tmp_path, report=_report(command=command), captured=captured)
    result, code = _audit(tmp_path, stdio_command=command)
    assert code == 0
    assert result.transport == "stdio"
    argv = captured["argv"]
    assert isinstance(argv, list)
    assert argv[argv.index("--") + 1 :] == command
    assert "--read-only" in argv[: argv.index("--")]


def test_sse_reuses_http_gates(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _enable(tmp_path)
    captured: dict[str, object] = {}
    _spawn(monkeypatch, tmp_path, report=_report(), captured=captured)
    _, code = _audit(tmp_path, target=LOOPBACK, sse=True)
    assert code == 0
    argv = captured["argv"]
    assert isinstance(argv, list)
    assert "--sse" in argv


def test_allow_writes_is_opt_in(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _enable(tmp_path)
    captured: dict[str, object] = {}
    _spawn(monkeypatch, tmp_path, report=_report(), captured=captured)
    result, _code = _audit(tmp_path, target=LOOPBACK, allow_writes=True)
    argv = captured["argv"]
    assert isinstance(argv, list)
    assert "--allow-writes" in argv
    assert "--read-only" not in argv
    assert "Write probes" in adapter.format_audit_summary(result)


def test_shell_metacharacters_stay_one_argv_element(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _enable(tmp_path)
    captured: dict[str, object] = {}
    python = Path(shutil.which("python3") or shutil.which("python") or "/usr/bin/python3").resolve()
    command = [str(python), "-c", "print('a; rm -rf /')"]
    _spawn(monkeypatch, tmp_path, report=_report(command=command), captured=captured)
    _audit(tmp_path, stdio_command=command)
    argv = captured["argv"]
    assert isinstance(argv, list)
    assert "print('a; rm -rf /')" in argv


def test_relative_stdio_executable_is_rejected() -> None:
    with pytest.raises(adapter.MCPCrossExamError, match="absolute path"):
        adapter.resolve_stdio_command(["./server.py"])
    with pytest.raises(adapter.MCPCrossExamError, match="could not be resolved"):
        adapter.resolve_stdio_command(["not-a-real-binary-xyz"])


def test_env_scrub_forwards_named_secrets_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _enable(tmp_path)
    captured: dict[str, object] = {}
    monkeypatch.setenv("AMBIENT_TOKEN", "secret-value")
    monkeypatch.setenv("MCP_BEARER", "bearer-secret")
    _spawn(monkeypatch, tmp_path, report=_report(), captured=captured)
    _audit(tmp_path, target=LOOPBACK, bearer_env="MCP_BEARER")
    env = captured["env"]
    assert isinstance(env, dict)
    assert env.get("MCP_BEARER") == "bearer-secret"
    assert "AMBIENT_TOKEN" not in env
    result, _code = _audit(tmp_path, target=LOOPBACK, bearer_env="MCP_BEARER")
    rendered = adapter.format_audit_summary(result) + json.dumps(adapter.result_payload(result))
    assert "bearer-secret" not in rendered
    assert "secret-value" not in rendered


def test_exit_zero_is_parsed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _enable(tmp_path)
    findings: list[dict[str, object]] = [
        {"probe_id": "schema.undeclared-required-arg", "severity": "high", "tool": "search", "title": "undeclared"}
    ]
    _spawn(monkeypatch, tmp_path, returncode=0, report=_report(findings=findings, score=40))
    result, code = _audit(tmp_path, target=LOOPBACK)
    assert code == 0
    assert result.findings[0].probe_id == "schema.undeclared-required-arg"


def test_exit_three_shows_findings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _enable(tmp_path)
    findings: list[dict[str, object]] = [
        {"probe_id": "session.expired-empty-success", "severity": "high", "title": "expired"}
    ]
    _spawn(monkeypatch, tmp_path, returncode=3, report=_report(findings=findings))
    result, code = _audit(tmp_path, target=LOOPBACK)
    assert code == 3
    assert "session.expired-empty-success" in adapter.format_audit_summary(result)


def test_exit_four_is_unreachable_not_score_zero(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _enable(tmp_path)
    _spawn(monkeypatch, tmp_path, returncode=4, stderr="connection refused")
    result, code = _audit(tmp_path, target=LOOPBACK)
    assert code == 4
    assert result.status == "unreachable"
    assert result.score is None


def test_cancelled_exit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _enable(tmp_path)
    _spawn(monkeypatch, tmp_path, returncode=130, stderr="interrupted")
    result, code = _audit(tmp_path, target=LOOPBACK)
    assert code == 130
    assert result.status == "cancelled"


def test_timeout_is_guard_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _enable(tmp_path)
    _spawn(monkeypatch, tmp_path, timed_out=True)
    with pytest.raises(adapter.MCPCrossExamError, match="timed out") as error:
        _audit(tmp_path, target=LOOPBACK)
    assert error.value.exit_code == 1


def test_missing_report_after_success_is_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _enable(tmp_path)
    _spawn(monkeypatch, tmp_path, returncode=0, report=None)
    with pytest.raises(adapter.MCPCrossExamError, match=r"report\.json") as error:
        _audit(tmp_path, target=LOOPBACK)
    assert error.value.exit_code == 1


def test_corrupt_report_is_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _enable(tmp_path)
    executable = _auditor(tmp_path)
    monkeypatch.setattr(adapter.shutil, "which", lambda name: str(executable) if name == "mcp-cross-exam" else None)

    def fake_run(
        argv: list[str], env: dict[str, str] | None = None, timeout_seconds: float | None = None
    ) -> ScannerProcessResult:
        if argv[1:] == ["--version"]:
            return ScannerProcessResult(0, "mcp-cross-exam 0.1.0", "", False)
        Path(argv[argv.index("--out-dir") + 1], "report.json").write_text("{not-json", encoding="utf-8")
        return ScannerProcessResult(0, "", "", False)

    monkeypatch.setattr(adapter, "run_bounded_scanner_process", fake_run)
    with pytest.raises(adapter.MCPCrossExamError, match=r"report\.json"):
        _audit(tmp_path, target=LOOPBACK)


def test_target_mismatch_is_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _enable(tmp_path)
    _spawn(monkeypatch, tmp_path, report=_report(url="http://127.0.0.1:9/other"))
    with pytest.raises(adapter.MCPCrossExamError, match="does not match"):
        _audit(tmp_path, target=LOOPBACK)


def test_partial_coverage_is_incomplete(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _enable(tmp_path)
    _spawn(monkeypatch, tmp_path, report=_report(coverage="partial"))
    result, _code = _audit(tmp_path, target=LOOPBACK)
    assert result.status == "incomplete"


def test_config_symlink_is_rejected(tmp_path: Path) -> None:
    target = tmp_path / "real.json"
    target.write_text("{}", encoding="utf-8")
    link = tmp_path / "config.json"
    link.symlink_to(target)
    with pytest.raises(adapter.MCPCrossExamError, match="symlink"):
        adapter._existing_file(str(link), label="--config")


def test_out_dir_symlink_is_rejected(tmp_path: Path) -> None:
    real = tmp_path / "real-out"
    real.mkdir()
    link = tmp_path / "out"
    link.symlink_to(real)
    with pytest.raises(adapter.MCPCrossExamError, match="symlink"):
        adapter._prepare_out_dir(str(link))


def test_mcp_serve_and_list_parser_unchanged() -> None:
    parser = _parser()
    serve = parser.parse_args(["mcp", "serve"])
    listed = parser.parse_args(["mcp", "list"])
    audit = parser.parse_args(["mcp", "audit", LOOPBACK, "--json"])
    assert serve.mcp_command == "serve"
    assert listed.mcp_command == "list"
    assert audit.mcp_command == "audit"
    assert audit.target == LOOPBACK
    assert audit.json is True


def test_cli_handler_json(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    _enable(tmp_path)
    _spawn(monkeypatch, tmp_path, report=_report())
    args = _parser().parse_args(
        ["mcp", "audit", "--json", "--home", str(tmp_path), "--out-dir", str(tmp_path / "out"), LOOPBACK]
    )
    code = adapter.run_guard_mcp_audit_command(args)
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "completed"
    assert "not Guard policy" in payload["note"]


def test_userinfo_and_fragment_rejected() -> None:
    with pytest.raises(adapter.MCPCrossExamError, match="credentials"):
        adapter.validate_http_target("http://user:pass@127.0.0.1:9/mcp", allow_remote=False)
    with pytest.raises(adapter.MCPCrossExamError, match="fragment"):
        adapter.validate_http_target("http://127.0.0.1:9/mcp#frag", allow_remote=False)


def test_results_are_capped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _enable(tmp_path)
    _spawn(monkeypatch, tmp_path, report=_report())
    for _ in range(adapter.MAX_STORED_RESULTS + 3):
        _audit(tmp_path, target=LOOPBACK)
    stored = adapter.load_mcp_cross_exam_results(tmp_path)
    assert stored["enabled"] is True
    assert isinstance(stored["runs"], list)
    assert len(stored["runs"]) == adapter.MAX_STORED_RESULTS


def test_settings_cli_persists_local_file(tmp_path: Path) -> None:
    args = _parser().parse_args(["settings", "set", "mcp-cross-exam", "on", "--home", str(tmp_path)])
    assert args.mcp_cross_exam == "on"
    adapter.set_mcp_cross_exam_enabled(tmp_path, True)
    assert adapter.mcp_cross_exam_enabled(tmp_path) is True
    adapter.set_mcp_cross_exam_enabled(tmp_path, False)
    assert adapter.mcp_cross_exam_enabled(tmp_path) is False
    settings = json.loads((tmp_path / "mcp-cross-exam" / "settings.json").read_text(encoding="utf-8"))
    assert settings == {"enabled": False}


def test_cli_namespace_stdio_split() -> None:
    args = SimpleNamespace(target="python", stdio_command=["--", "server.py"])
    target, command = adapter.split_mcp_audit_target(args.target, args.stdio_command)
    assert target is None
    assert command == ("python", "server.py")


def test_jobs_are_capped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _enable(tmp_path)
    captured: dict[str, object] = {}
    _spawn(monkeypatch, tmp_path, report=_report(), captured=captured)
    _audit(tmp_path, target=LOOPBACK, jobs=9)
    argv = captured["argv"]
    assert isinstance(argv, list)
    assert argv[argv.index("--jobs") + 1] == "4"


def test_ipv4_mapped_loopback_is_allowed() -> None:
    adapter.validate_http_target("http://[::ffff:127.0.0.1]:9/mcp", allow_remote=False)


def test_production_guard_exit_is_config_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _enable(tmp_path)
    _spawn(monkeypatch, tmp_path, returncode=2, stderr="refused: host is not loopback")
    with pytest.raises(adapter.MCPCrossExamError, match="refused") as error:
        _audit(tmp_path, target=LOOPBACK)
    assert error.value.exit_code == 2


def test_oversized_report_is_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _enable(tmp_path)
    executable = _auditor(tmp_path)
    monkeypatch.setattr(adapter.shutil, "which", lambda name: str(executable) if name == "mcp-cross-exam" else None)

    def fake_run(
        argv: list[str], env: dict[str, str] | None = None, timeout_seconds: float | None = None
    ) -> ScannerProcessResult:
        if argv[1:] == ["--version"]:
            return ScannerProcessResult(0, "mcp-cross-exam 0.1.0", "", False)
        Path(argv[argv.index("--out-dir") + 1], "report.json").write_bytes(b"{" + (b"a" * (8 * 1024 * 1024)))
        return ScannerProcessResult(0, "", "", False)

    monkeypatch.setattr(adapter, "run_bounded_scanner_process", fake_run)
    with pytest.raises(adapter.MCPCrossExamError, match=r"report\.json"):
        _audit(tmp_path, target=LOOPBACK)


def test_report_symlink_escape_is_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _enable(tmp_path)
    executable = _auditor(tmp_path)
    outside = tmp_path / "outside.json"
    outside.write_text(json.dumps(_report()), encoding="utf-8")
    monkeypatch.setattr(adapter.shutil, "which", lambda name: str(executable) if name == "mcp-cross-exam" else None)

    def fake_run(
        argv: list[str], env: dict[str, str] | None = None, timeout_seconds: float | None = None
    ) -> ScannerProcessResult:
        if argv[1:] == ["--version"]:
            return ScannerProcessResult(0, "mcp-cross-exam 0.1.0", "", False)
        report = Path(argv[argv.index("--out-dir") + 1]) / "report.json"
        report.symlink_to(outside)
        return ScannerProcessResult(0, "", "", False)

    monkeypatch.setattr(adapter, "run_bounded_scanner_process", fake_run)
    with pytest.raises(adapter.MCPCrossExamError, match=r"report\.json"):
        _audit(tmp_path, target=LOOPBACK)


def test_stdio_wrapper_is_rejected() -> None:
    with pytest.raises(adapter.MCPCrossExamError, match="wrapper"):
        adapter.resolve_stdio_command(["bash", "-c", "python server.py"])
    with pytest.raises(adapter.MCPCrossExamError, match="wrapper"):
        adapter.resolve_stdio_command(["npx", "mcp-server"])
