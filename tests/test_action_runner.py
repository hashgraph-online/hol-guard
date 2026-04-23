"""Behavior checks for the GitHub Action runner output contract."""

from __future__ import annotations

import json
import shutil
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import ClassVar
from urllib.parse import parse_qs, urlsplit

import yaml

from codex_plugin_scanner.action_runner import _build_scan_args, main
from codex_plugin_scanner.github_reporting import GitHubPrCommentResult, upsert_pr_comment

FIXTURES = Path(__file__).parent / "fixtures"


class _GitHubHandler(BaseHTTPRequestHandler):
    comments: ClassVar[list[dict[str, object]]] = []
    comment_pages: ClassVar[dict[int, list[dict[str, object]]] | None] = None

    def do_GET(self) -> None:
        if urlsplit(self.path).path.endswith("/repos/hashgraph-online/example-good-plugin/issues/12/comments"):
            self._write_comments()
            return
        self.send_error(404)

    def do_POST(self) -> None:
        if self.path.endswith("/repos/hashgraph-online/example-good-plugin/issues/12/comments"):
            payload = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))).decode("utf-8"))
            body = payload.get("body")
            if not isinstance(body, str):
                self.send_error(400)
                return
            comment = {
                "id": 101,
                "html_url": "https://github.com/hashgraph-online/example-good-plugin/pull/12#issuecomment-101",
                "body": body,
            }
            type(self).comments = [comment]
            self._write_json(201, comment)
            return
        self.send_error(404)

    def do_PATCH(self) -> None:
        if self.path.endswith("/repos/hashgraph-online/example-good-plugin/issues/comments/101"):
            payload = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))).decode("utf-8"))
            body = payload.get("body")
            if not isinstance(body, str):
                self.send_error(400)
                return
            comment = {
                "id": 101,
                "html_url": "https://github.com/hashgraph-online/example-good-plugin/pull/12#issuecomment-101",
                "body": body,
            }
            type(self).comments = [comment]
            self._write_json(200, comment)
            return
        self.send_error(404)

    def log_message(self, message: str, *args: object) -> None:
        return None

    def _write_json(self, status_code: int, payload: object) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _write_comments(self) -> None:
        query = parse_qs(urlsplit(self.path).query)
        page = int(query.get("page", ["1"])[0])
        pages = type(self).comment_pages
        comments = self.comments if pages is None else pages.get(page, [])
        body = json.dumps(comments).encode("utf-8")
        self.send_response(200)
        if pages is not None and page < max(pages):
            next_page = page + 1
            host, port = self.server.server_address[:2]
            next_url = (
                f"http://{host}:{port}"
                "/repos/hashgraph-online/example-good-plugin/issues/12/comments"
                f"?per_page=100&page={next_page}"
            )
            self.send_header("Link", f'<{next_url}>; rel="next"')
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _start_github_server() -> tuple[ThreadingHTTPServer, str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _GitHubHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    return server, f"http://{host}:{port}"


def test_action_runner_writes_all_outputs(monkeypatch, tmp_path, capsys) -> None:
    output_path = tmp_path / "github-output.txt"

    monkeypatch.setenv("PLUGIN_DIR", str(FIXTURES / "good-plugin"))
    monkeypatch.setenv("FORMAT", "json")
    monkeypatch.setenv("OUTPUT", "")
    monkeypatch.setenv("MIN_SCORE", "0")
    monkeypatch.setenv("FAIL_ON", "none")
    monkeypatch.setenv("CISCO_SCAN", "off")
    monkeypatch.setenv("CISCO_POLICY", "balanced")
    monkeypatch.setenv("SUBMISSION_ENABLED", "false")
    monkeypatch.setenv("SUBMISSION_SCORE_THRESHOLD", "80")
    monkeypatch.setenv("SUBMISSION_REPOS", "hashgraph-online/awesome-codex-plugins")
    monkeypatch.setenv("SUBMISSION_TOKEN", "")
    monkeypatch.setenv("SUBMISSION_LABELS", "plugin-submission")
    monkeypatch.setenv("SUBMISSION_CATEGORY", "Community Plugins")
    monkeypatch.setenv("SUBMISSION_PLUGIN_NAME", "")
    monkeypatch.setenv("SUBMISSION_PLUGIN_URL", "")
    monkeypatch.setenv("SUBMISSION_PLUGIN_DESCRIPTION", "")
    monkeypatch.setenv("SUBMISSION_AUTHOR", "")
    monkeypatch.setenv("WRITE_STEP_SUMMARY", "false")
    monkeypatch.setenv("REGISTRY_PAYLOAD_OUTPUT", "")
    monkeypatch.setenv("GITHUB_OUTPUT", str(output_path))

    exit_code = main()

    assert exit_code == 0
    output_lines = output_path.read_text(encoding="utf-8").splitlines()
    assert "score=100" in output_lines
    assert "grade=A" in output_lines
    assert "grade_label=Excellent" in output_lines
    assert "max_severity=none" in output_lines
    assert "findings_total=0" in output_lines
    assert "report_path=" in output_lines
    assert "registry_payload_path=" in output_lines
    assert "policy_pass=true" in output_lines
    assert "verify_pass=" in output_lines
    assert "submission_eligible=false" in output_lines
    assert "submission_performed=false" in output_lines
    assert "submission_issue_urls=" in output_lines
    assert "submission_issue_numbers=" in output_lines
    assert "action_exit_code=0" in output_lines
    assert "pr_comment_status=skipped" in output_lines
    assert "pr_comment_id=" in output_lines
    assert "pr_comment_url=" in output_lines

    stdout = capsys.readouterr().out
    assert '"score": 100' in stdout


def test_build_scan_args_propagates_cisco_mcp_scan() -> None:
    args = _build_scan_args(
        plugin_dir=str(FIXTURES / "good-plugin"),
        profile="default",
        config="",
        baseline="",
        min_score=0,
        fail_on_severity="none",
        cisco_scan="auto",
        cisco_mcp_scan="on",
        cisco_policy="balanced",
    )

    assert args.cisco_mcp_scan == "on"


def test_action_runner_writes_step_summary_and_registry_payload(monkeypatch, tmp_path) -> None:
    output_path = tmp_path / "github-output.txt"
    report_path = tmp_path / "scan-report.json"
    summary_path = tmp_path / "step-summary.md"
    registry_payload_path = tmp_path / "registry-payload.json"

    monkeypatch.setenv("PLUGIN_DIR", str(FIXTURES / "good-plugin"))
    monkeypatch.setenv("FORMAT", "json")
    monkeypatch.setenv("OUTPUT", str(report_path))
    monkeypatch.setenv("MIN_SCORE", "0")
    monkeypatch.setenv("FAIL_ON", "none")
    monkeypatch.setenv("CISCO_SCAN", "off")
    monkeypatch.setenv("CISCO_POLICY", "balanced")
    monkeypatch.setenv("SUBMISSION_ENABLED", "false")
    monkeypatch.setenv("SUBMISSION_SCORE_THRESHOLD", "80")
    monkeypatch.setenv("SUBMISSION_REPOS", "hashgraph-online/awesome-codex-plugins")
    monkeypatch.setenv("SUBMISSION_TOKEN", "")
    monkeypatch.setenv("SUBMISSION_LABELS", "plugin-submission")
    monkeypatch.setenv("SUBMISSION_CATEGORY", "Community Plugins")
    monkeypatch.setenv("SUBMISSION_PLUGIN_NAME", "")
    monkeypatch.setenv("SUBMISSION_PLUGIN_URL", "")
    monkeypatch.setenv("SUBMISSION_PLUGIN_DESCRIPTION", "")
    monkeypatch.setenv("SUBMISSION_AUTHOR", "")
    monkeypatch.setenv("WRITE_STEP_SUMMARY", "true")
    monkeypatch.setenv("REGISTRY_PAYLOAD_OUTPUT", str(registry_payload_path))
    monkeypatch.setenv("GITHUB_OUTPUT", str(output_path))
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary_path))
    monkeypatch.setenv("GITHUB_REPOSITORY", "hashgraph-online/example-good-plugin")
    monkeypatch.setenv("GITHUB_SERVER_URL", "https://github.com")
    monkeypatch.setenv("GITHUB_SHA", "abc123")
    monkeypatch.setenv("GITHUB_RUN_ID", "77")

    exit_code = main()

    assert exit_code == 0
    output_lines = output_path.read_text(encoding="utf-8").splitlines()
    assert f"report_path={report_path}" in output_lines
    assert f"registry_payload_path={registry_payload_path}" in output_lines

    payload_text = registry_payload_path.read_text(encoding="utf-8")
    assert '"pluginName": "Example Good Plugin"' in payload_text
    assert '"sourceRepository": "hashgraph-online/example-good-plugin"' in payload_text

    summary_text = summary_path.read_text(encoding="utf-8")
    assert "## HOL AI Plugin Scanner" in summary_text
    assert "- Score: 100/100" in summary_text
    assert "- Grade: A - Excellent" in summary_text
    assert f"- Registry payload: `{registry_payload_path}`" in summary_text


def test_action_runner_verify_mode_writes_human_report(monkeypatch, tmp_path, capsys) -> None:
    output_path = tmp_path / "verify-report.txt"
    github_output = tmp_path / "github-output.txt"

    monkeypatch.setenv("MODE", "verify")
    monkeypatch.setenv("PLUGIN_DIR", str(FIXTURES / "good-plugin"))
    monkeypatch.setenv("FORMAT", "text")
    monkeypatch.setenv("OUTPUT", str(output_path))
    monkeypatch.setenv("PROFILE", "default")
    monkeypatch.setenv("CONFIG", "")
    monkeypatch.setenv("BASELINE", "")
    monkeypatch.setenv("ONLINE", "false")
    monkeypatch.setenv("MIN_SCORE", "0")
    monkeypatch.setenv("FAIL_ON", "none")
    monkeypatch.setenv("CISCO_SCAN", "off")
    monkeypatch.setenv("CISCO_POLICY", "balanced")
    monkeypatch.setenv("SUBMISSION_ENABLED", "false")
    monkeypatch.setenv("SUBMISSION_SCORE_THRESHOLD", "80")
    monkeypatch.setenv("SUBMISSION_REPOS", "hashgraph-online/awesome-codex-plugins")
    monkeypatch.setenv("SUBMISSION_TOKEN", "")
    monkeypatch.setenv("SUBMISSION_LABELS", "plugin-submission")
    monkeypatch.setenv("SUBMISSION_CATEGORY", "Community Plugins")
    monkeypatch.setenv("SUBMISSION_PLUGIN_NAME", "")
    monkeypatch.setenv("SUBMISSION_PLUGIN_URL", "")
    monkeypatch.setenv("SUBMISSION_PLUGIN_DESCRIPTION", "")
    monkeypatch.setenv("SUBMISSION_AUTHOR", "")
    monkeypatch.setenv("WRITE_STEP_SUMMARY", "false")
    monkeypatch.setenv("REGISTRY_PAYLOAD_OUTPUT", "")
    monkeypatch.setenv("GITHUB_OUTPUT", str(github_output))

    exit_code = main()

    assert exit_code == 0
    assert "Verification: PASS" in output_path.read_text(encoding="utf-8")
    assert "mode=verify" in github_output.read_text(encoding="utf-8")
    assert "verify_pass=true" in github_output.read_text(encoding="utf-8")
    assert "Report written to" in capsys.readouterr().out


def test_action_runner_repository_scan_defaults_to_marketplace_root(monkeypatch, tmp_path) -> None:
    output_path = tmp_path / "github-output.txt"
    summary_path = tmp_path / "step-summary.md"

    monkeypatch.setenv("PLUGIN_DIR", str(FIXTURES / "multi-plugin-repo"))
    monkeypatch.setenv("FORMAT", "json")
    monkeypatch.setenv("OUTPUT", "")
    monkeypatch.setenv("MIN_SCORE", "0")
    monkeypatch.setenv("FAIL_ON", "none")
    monkeypatch.setenv("CISCO_SCAN", "off")
    monkeypatch.setenv("CISCO_POLICY", "balanced")
    monkeypatch.setenv("SUBMISSION_ENABLED", "false")
    monkeypatch.setenv("SUBMISSION_SCORE_THRESHOLD", "80")
    monkeypatch.setenv("SUBMISSION_REPOS", "hashgraph-online/awesome-codex-plugins")
    monkeypatch.setenv("SUBMISSION_TOKEN", "")
    monkeypatch.setenv("SUBMISSION_LABELS", "plugin-submission")
    monkeypatch.setenv("SUBMISSION_CATEGORY", "Community Plugins")
    monkeypatch.setenv("SUBMISSION_PLUGIN_NAME", "")
    monkeypatch.setenv("SUBMISSION_PLUGIN_URL", "")
    monkeypatch.setenv("SUBMISSION_PLUGIN_DESCRIPTION", "")
    monkeypatch.setenv("SUBMISSION_AUTHOR", "")
    monkeypatch.setenv("WRITE_STEP_SUMMARY", "true")
    monkeypatch.setenv("REGISTRY_PAYLOAD_OUTPUT", "")
    monkeypatch.setenv("GITHUB_OUTPUT", str(output_path))
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary_path))

    exit_code = main()

    assert exit_code == 0
    summary_text = summary_path.read_text(encoding="utf-8")
    assert "- Scope: repository" in summary_text
    assert "- Local plugins scanned: 2" in summary_text
    assert "- Skipped marketplace entries: 1" in summary_text
    output_lines = output_path.read_text(encoding="utf-8").splitlines()
    assert any(line.startswith("score=") for line in output_lines)


def test_action_runner_default_scan_does_not_open_network_connections(monkeypatch, tmp_path) -> None:
    output_path = tmp_path / "github-output.txt"

    def _forbid_network(*args, **kwargs):
        raise AssertionError("default scan mode should not open network connections")

    monkeypatch.setenv("PLUGIN_DIR", str(FIXTURES / "good-plugin"))
    monkeypatch.setenv("FORMAT", "json")
    monkeypatch.setenv("OUTPUT", "")
    monkeypatch.setenv("MIN_SCORE", "0")
    monkeypatch.setenv("FAIL_ON", "none")
    monkeypatch.setenv("CISCO_SCAN", "off")
    monkeypatch.setenv("CISCO_POLICY", "balanced")
    monkeypatch.setenv("SUBMISSION_ENABLED", "false")
    monkeypatch.setenv("SUBMISSION_SCORE_THRESHOLD", "80")
    monkeypatch.setenv("SUBMISSION_REPOS", "hashgraph-online/awesome-codex-plugins")
    monkeypatch.setenv("SUBMISSION_TOKEN", "")
    monkeypatch.setenv("SUBMISSION_LABELS", "plugin-submission")
    monkeypatch.setenv("SUBMISSION_CATEGORY", "Community Plugins")
    monkeypatch.setenv("SUBMISSION_PLUGIN_NAME", "")
    monkeypatch.setenv("SUBMISSION_PLUGIN_URL", "")
    monkeypatch.setenv("SUBMISSION_PLUGIN_DESCRIPTION", "")
    monkeypatch.setenv("SUBMISSION_AUTHOR", "")
    monkeypatch.setenv("ONLINE", "false")
    monkeypatch.setenv("WRITE_STEP_SUMMARY", "false")
    monkeypatch.setenv("REGISTRY_PAYLOAD_OUTPUT", "")
    monkeypatch.setenv("GITHUB_OUTPUT", str(output_path))
    monkeypatch.setattr(socket, "create_connection", _forbid_network)
    monkeypatch.setattr(socket.socket, "connect", _forbid_network)

    exit_code = main()

    assert exit_code == 0


def test_action_runner_preserves_output_paths_on_gate_failure(monkeypatch, tmp_path) -> None:
    github_output = tmp_path / "github-output.txt"
    report_path = tmp_path / "scan-report.json"
    registry_payload_path = tmp_path / "registry-payload.json"

    monkeypatch.setenv("PLUGIN_DIR", str(FIXTURES / "good-plugin"))
    monkeypatch.setenv("FORMAT", "json")
    monkeypatch.setenv("OUTPUT", str(report_path))
    monkeypatch.setenv("MIN_SCORE", "101")
    monkeypatch.setenv("FAIL_ON", "none")
    monkeypatch.setenv("CISCO_SCAN", "off")
    monkeypatch.setenv("CISCO_POLICY", "balanced")
    monkeypatch.setenv("SUBMISSION_ENABLED", "false")
    monkeypatch.setenv("SUBMISSION_SCORE_THRESHOLD", "80")
    monkeypatch.setenv("SUBMISSION_REPOS", "hashgraph-online/awesome-codex-plugins")
    monkeypatch.setenv("SUBMISSION_TOKEN", "")
    monkeypatch.setenv("SUBMISSION_LABELS", "plugin-submission")
    monkeypatch.setenv("SUBMISSION_CATEGORY", "Community Plugins")
    monkeypatch.setenv("SUBMISSION_PLUGIN_NAME", "")
    monkeypatch.setenv("SUBMISSION_PLUGIN_URL", "")
    monkeypatch.setenv("SUBMISSION_PLUGIN_DESCRIPTION", "")
    monkeypatch.setenv("SUBMISSION_AUTHOR", "")
    monkeypatch.setenv("WRITE_STEP_SUMMARY", "false")
    monkeypatch.setenv("REGISTRY_PAYLOAD_OUTPUT", str(registry_payload_path))
    monkeypatch.setenv("GITHUB_OUTPUT", str(github_output))
    monkeypatch.setenv("GITHUB_REPOSITORY", "hashgraph-online/example-good-plugin")
    monkeypatch.setenv("GITHUB_SERVER_URL", "https://github.com")
    monkeypatch.setenv("GITHUB_SHA", "abc123")
    monkeypatch.setenv("GITHUB_RUN_ID", "77")

    exit_code = main()

    assert exit_code == 1
    assert report_path.exists()
    assert registry_payload_path.exists()
    output_lines = github_output.read_text(encoding="utf-8").splitlines()
    assert f"report_path={report_path}" in output_lines
    assert f"registry_payload_path={registry_payload_path}" in output_lines
    assert "action_exit_code=1" in output_lines


def test_action_runner_creates_pr_comment_for_pull_request_event(monkeypatch, tmp_path) -> None:
    output_path = tmp_path / "github-output.txt"
    event_path = tmp_path / "event.json"
    event_path.write_text(json.dumps({"pull_request": {"number": 12}}), encoding="utf-8")
    captured: dict[str, str] = {}

    def _capture_comment(**kwargs: object) -> GitHubPrCommentResult:
        body = kwargs.get("body")
        if isinstance(body, str):
            captured["body"] = body
        return GitHubPrCommentResult(
            status="created",
            comment_id="101",
            comment_url="https://github.com/hashgraph-online/example-good-plugin/pull/12#issuecomment-101",
        )

    monkeypatch.setenv("PLUGIN_DIR", str(FIXTURES / "good-plugin"))
    monkeypatch.setenv("FORMAT", "json")
    monkeypatch.setenv("OUTPUT", "")
    monkeypatch.setenv("MIN_SCORE", "0")
    monkeypatch.setenv("FAIL_ON", "none")
    monkeypatch.setenv("CISCO_SCAN", "off")
    monkeypatch.setenv("CISCO_POLICY", "balanced")
    monkeypatch.setenv("SUBMISSION_ENABLED", "false")
    monkeypatch.setenv("SUBMISSION_SCORE_THRESHOLD", "80")
    monkeypatch.setenv("SUBMISSION_REPOS", "hashgraph-online/awesome-codex-plugins")
    monkeypatch.setenv("SUBMISSION_TOKEN", "")
    monkeypatch.setenv("SUBMISSION_LABELS", "plugin-submission")
    monkeypatch.setenv("SUBMISSION_CATEGORY", "Community Plugins")
    monkeypatch.setenv("SUBMISSION_PLUGIN_NAME", "")
    monkeypatch.setenv("SUBMISSION_PLUGIN_URL", "")
    monkeypatch.setenv("SUBMISSION_PLUGIN_DESCRIPTION", "")
    monkeypatch.setenv("SUBMISSION_AUTHOR", "")
    monkeypatch.setenv("WRITE_STEP_SUMMARY", "false")
    monkeypatch.setenv("REGISTRY_PAYLOAD_OUTPUT", "")
    monkeypatch.setenv("GITHUB_OUTPUT", str(output_path))
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")
    monkeypatch.setenv("GITHUB_EVENT_NAME", "pull_request")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event_path))
    monkeypatch.setenv("GITHUB_REPOSITORY", "hashgraph-online/example-good-plugin")
    monkeypatch.setattr("codex_plugin_scanner.action_runner.upsert_pr_comment", _capture_comment)

    exit_code = main()

    assert exit_code == 0
    output_lines = output_path.read_text(encoding="utf-8").splitlines()
    assert "pr_comment_status=created" in output_lines
    assert "pr_comment_id=101" in output_lines
    assert (
        "pr_comment_url=https://github.com/hashgraph-online/example-good-plugin/pull/12#issuecomment-101"
        in output_lines
    )
    assert "## Guard repo scan" in captured["body"]


def test_action_runner_pr_comment_failure_is_nonfatal(monkeypatch, tmp_path, capsys) -> None:
    output_path = tmp_path / "github-output.txt"
    event_path = tmp_path / "event.json"
    event_path.write_text(json.dumps({"pull_request": {"number": 12}}), encoding="utf-8")

    monkeypatch.setenv("PLUGIN_DIR", str(FIXTURES / "good-plugin"))
    monkeypatch.setenv("FORMAT", "json")
    monkeypatch.setenv("OUTPUT", "")
    monkeypatch.setenv("MIN_SCORE", "0")
    monkeypatch.setenv("FAIL_ON", "none")
    monkeypatch.setenv("CISCO_SCAN", "off")
    monkeypatch.setenv("CISCO_POLICY", "balanced")
    monkeypatch.setenv("SUBMISSION_ENABLED", "false")
    monkeypatch.setenv("SUBMISSION_SCORE_THRESHOLD", "80")
    monkeypatch.setenv("SUBMISSION_REPOS", "hashgraph-online/awesome-codex-plugins")
    monkeypatch.setenv("SUBMISSION_TOKEN", "")
    monkeypatch.setenv("SUBMISSION_LABELS", "plugin-submission")
    monkeypatch.setenv("SUBMISSION_CATEGORY", "Community Plugins")
    monkeypatch.setenv("SUBMISSION_PLUGIN_NAME", "")
    monkeypatch.setenv("SUBMISSION_PLUGIN_URL", "")
    monkeypatch.setenv("SUBMISSION_PLUGIN_DESCRIPTION", "")
    monkeypatch.setenv("SUBMISSION_AUTHOR", "")
    monkeypatch.setenv("WRITE_STEP_SUMMARY", "false")
    monkeypatch.setenv("REGISTRY_PAYLOAD_OUTPUT", "")
    monkeypatch.setenv("GITHUB_OUTPUT", str(output_path))
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")
    monkeypatch.setenv("GITHUB_EVENT_NAME", "pull_request")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event_path))
    monkeypatch.setenv("GITHUB_REPOSITORY", "hashgraph-online/example-good-plugin")
    monkeypatch.setenv("GITHUB_API_URL", "https://api.github.com")
    monkeypatch.setattr(
        "codex_plugin_scanner.action_runner.upsert_pr_comment",
        lambda **_kwargs: (_ for _ in ()).throw(RuntimeError("boom")),
    )

    exit_code = main()
    output_lines = output_path.read_text(encoding="utf-8").splitlines()
    stderr = capsys.readouterr().err

    assert exit_code == 0
    assert "pr_comment_status=failed" in output_lines
    assert "Warning: failed to update PR comment" in stderr


def test_action_runner_invalid_pr_comment_max_findings_falls_back_to_default(
    monkeypatch,
    tmp_path,
) -> None:
    output_path = tmp_path / "github-output.txt"

    monkeypatch.setenv("PLUGIN_DIR", str(FIXTURES / "good-plugin"))
    monkeypatch.setenv("FORMAT", "json")
    monkeypatch.setenv("OUTPUT", "")
    monkeypatch.setenv("MIN_SCORE", "0")
    monkeypatch.setenv("FAIL_ON", "none")
    monkeypatch.setenv("CISCO_SCAN", "off")
    monkeypatch.setenv("CISCO_POLICY", "balanced")
    monkeypatch.setenv("SUBMISSION_ENABLED", "false")
    monkeypatch.setenv("SUBMISSION_SCORE_THRESHOLD", "80")
    monkeypatch.setenv("SUBMISSION_REPOS", "hashgraph-online/awesome-codex-plugins")
    monkeypatch.setenv("SUBMISSION_TOKEN", "")
    monkeypatch.setenv("SUBMISSION_LABELS", "plugin-submission")
    monkeypatch.setenv("SUBMISSION_CATEGORY", "Community Plugins")
    monkeypatch.setenv("SUBMISSION_PLUGIN_NAME", "")
    monkeypatch.setenv("SUBMISSION_PLUGIN_URL", "")
    monkeypatch.setenv("SUBMISSION_PLUGIN_DESCRIPTION", "")
    monkeypatch.setenv("SUBMISSION_AUTHOR", "")
    monkeypatch.setenv("WRITE_STEP_SUMMARY", "false")
    monkeypatch.setenv("REGISTRY_PAYLOAD_OUTPUT", "")
    monkeypatch.setenv("GITHUB_OUTPUT", str(output_path))
    monkeypatch.setenv("PR_COMMENT_MAX_FINDINGS", "not-a-number")

    exit_code = main()

    assert exit_code == 0
    assert "pr_comment_status=skipped" in output_path.read_text(encoding="utf-8")


def test_action_runner_verify_mode_ignores_invalid_repo_pr_comment_config(
    monkeypatch,
    tmp_path,
    capsys,
) -> None:
    output_path = tmp_path / "github-output.txt"
    event_path = tmp_path / "event.json"
    plugin_dir = tmp_path / "repo"
    shutil.copytree(FIXTURES / "good-plugin", plugin_dir)
    (plugin_dir / ".plugin-scanner.toml").write_text("[github\npr_comment = \"off\"\n", encoding="utf-8")
    event_path.write_text(json.dumps({"pull_request": {"number": 12}}), encoding="utf-8")

    monkeypatch.setenv("MODE", "verify")
    monkeypatch.setenv("PLUGIN_DIR", str(plugin_dir))
    monkeypatch.setenv("FORMAT", "text")
    monkeypatch.setenv("OUTPUT", "")
    monkeypatch.setenv("ONLINE", "false")
    monkeypatch.setenv("WRITE_STEP_SUMMARY", "false")
    monkeypatch.setenv("REGISTRY_PAYLOAD_OUTPUT", "")
    monkeypatch.setenv("GITHUB_OUTPUT", str(output_path))
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")
    monkeypatch.setenv("GITHUB_EVENT_NAME", "pull_request")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event_path))
    monkeypatch.setenv("GITHUB_REPOSITORY", "hashgraph-online/example-good-plugin")
    monkeypatch.setenv("PR_COMMENT", "auto")
    monkeypatch.setenv("PR_COMMENT_STYLE", "concise")
    monkeypatch.setenv("PR_COMMENT_MAX_FINDINGS", "5")
    monkeypatch.setattr(
        "codex_plugin_scanner.action_runner.upsert_pr_comment",
        lambda **_kwargs: GitHubPrCommentResult(status="created", comment_id="101", comment_url="https://example.com"),
    )

    exit_code = main()
    stderr = capsys.readouterr().err

    assert exit_code == 0
    assert "pr_comment_status=created" in output_path.read_text(encoding="utf-8")
    assert "Warning: failed to load scanner config for PR comment settings" in stderr


def test_action_runner_updates_pr_comment_before_gate_failure(monkeypatch, tmp_path) -> None:
    output_path = tmp_path / "github-output.txt"
    event_path = tmp_path / "event.json"
    event_path.write_text(json.dumps({"pull_request": {"number": 12}}), encoding="utf-8")
    captured: dict[str, str] = {}

    monkeypatch.setenv("PLUGIN_DIR", str(FIXTURES / "good-plugin"))
    monkeypatch.setenv("FORMAT", "json")
    monkeypatch.setenv("OUTPUT", "")
    monkeypatch.setenv("MIN_SCORE", "101")
    monkeypatch.setenv("FAIL_ON", "none")
    monkeypatch.setenv("CISCO_SCAN", "off")
    monkeypatch.setenv("CISCO_POLICY", "balanced")
    monkeypatch.setenv("SUBMISSION_ENABLED", "false")
    monkeypatch.setenv("SUBMISSION_SCORE_THRESHOLD", "80")
    monkeypatch.setenv("SUBMISSION_REPOS", "hashgraph-online/awesome-codex-plugins")
    monkeypatch.setenv("SUBMISSION_TOKEN", "")
    monkeypatch.setenv("SUBMISSION_LABELS", "plugin-submission")
    monkeypatch.setenv("SUBMISSION_CATEGORY", "Community Plugins")
    monkeypatch.setenv("SUBMISSION_PLUGIN_NAME", "")
    monkeypatch.setenv("SUBMISSION_PLUGIN_URL", "")
    monkeypatch.setenv("SUBMISSION_PLUGIN_DESCRIPTION", "")
    monkeypatch.setenv("SUBMISSION_AUTHOR", "")
    monkeypatch.setenv("WRITE_STEP_SUMMARY", "false")
    monkeypatch.setenv("REGISTRY_PAYLOAD_OUTPUT", "")
    monkeypatch.setenv("GITHUB_OUTPUT", str(output_path))
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")
    monkeypatch.setenv("GITHUB_EVENT_NAME", "pull_request")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event_path))
    monkeypatch.setenv("GITHUB_REPOSITORY", "hashgraph-online/example-good-plugin")
    monkeypatch.setenv("GITHUB_API_URL", "https://api.github.com")

    def _capture_comment(**kwargs: object) -> GitHubPrCommentResult:
        body = kwargs.get("body")
        if isinstance(body, str):
            captured["body"] = body
        return GitHubPrCommentResult(status="created", comment_id="101", comment_url="https://example.com")

    monkeypatch.setattr("codex_plugin_scanner.action_runner.upsert_pr_comment", _capture_comment)

    exit_code = main()

    assert exit_code == 1
    assert "## Guard repo scan" in captured["body"]
    assert "pr_comment_status=created" in output_path.read_text(encoding="utf-8")


def test_upsert_pr_comment_finds_existing_comment_on_later_page() -> None:
    _GitHubHandler.comments = []
    _GitHubHandler.comment_pages = {
        1: [
            {
                "id": 88,
                "html_url": "https://github.com/hashgraph-online/example-good-plugin/pull/12#issuecomment-88",
                "body": "other",
            }
        ],
        2: [
            {
                "id": 101,
                "html_url": "https://github.com/hashgraph-online/example-good-plugin/pull/12#issuecomment-101",
                "body": "<!-- hol-guard-pr-comment -->\nold",
            }
        ],
    }
    server, api_base_url = _start_github_server()
    try:
        result = upsert_pr_comment(
            repository="hashgraph-online/example-good-plugin",
            pull_request_number=12,
            token="test-token",
            api_base_url=api_base_url,
            body="<!-- hol-guard-pr-comment -->\nnew",
        )
    finally:
        server.shutdown()
        server.server_close()
        _GitHubHandler.comment_pages = None

    assert result.status == "updated"
    assert result.comment_id == "101"
    assert _GitHubHandler.comments[0]["body"] == "<!-- hol-guard-pr-comment -->\nnew"


def test_action_runner_uses_repo_config_to_disable_pr_comment(monkeypatch, tmp_path) -> None:
    output_path = tmp_path / "github-output.txt"
    plugin_dir = tmp_path / "repo"
    shutil.copytree(FIXTURES / "good-plugin", plugin_dir)
    (plugin_dir / ".plugin-scanner.toml").write_text(
        """
[github]
pr_comment = "off"
""",
        encoding="utf-8",
    )

    monkeypatch.setenv("PLUGIN_DIR", str(plugin_dir))
    monkeypatch.setenv("FORMAT", "json")
    monkeypatch.setenv("OUTPUT", "")
    monkeypatch.setenv("MIN_SCORE", "0")
    monkeypatch.setenv("FAIL_ON", "none")
    monkeypatch.setenv("CISCO_SCAN", "off")
    monkeypatch.setenv("CISCO_POLICY", "balanced")
    monkeypatch.setenv("SUBMISSION_ENABLED", "false")
    monkeypatch.setenv("SUBMISSION_SCORE_THRESHOLD", "80")
    monkeypatch.setenv("SUBMISSION_REPOS", "hashgraph-online/awesome-codex-plugins")
    monkeypatch.setenv("SUBMISSION_TOKEN", "")
    monkeypatch.setenv("SUBMISSION_LABELS", "plugin-submission")
    monkeypatch.setenv("SUBMISSION_CATEGORY", "Community Plugins")
    monkeypatch.setenv("SUBMISSION_PLUGIN_NAME", "")
    monkeypatch.setenv("SUBMISSION_PLUGIN_URL", "")
    monkeypatch.setenv("SUBMISSION_PLUGIN_DESCRIPTION", "")
    monkeypatch.setenv("SUBMISSION_AUTHOR", "")
    monkeypatch.setenv("WRITE_STEP_SUMMARY", "false")
    monkeypatch.setenv("REGISTRY_PAYLOAD_OUTPUT", "")
    monkeypatch.setenv("GITHUB_OUTPUT", str(output_path))
    monkeypatch.setenv("PR_COMMENT", "auto")
    monkeypatch.setenv("PR_COMMENT_STYLE", "concise")
    monkeypatch.setenv("PR_COMMENT_MAX_FINDINGS", "5")

    exit_code = main()

    assert exit_code == 0
    output_lines = output_path.read_text(encoding="utf-8").splitlines()
    assert "pr_comment_status=disabled" in output_lines


def test_main_rejects_invalid_github_api_url_before_submission(monkeypatch, capsys) -> None:
    def fail_submission_lookup(*args, **kwargs):
        raise AssertionError("submission lookup should not run with an invalid GITHUB_API_URL")

    monkeypatch.setattr("codex_plugin_scanner.action_runner.find_existing_submission_issue", fail_submission_lookup)
    monkeypatch.setenv("MODE", "scan")
    monkeypatch.setenv("PLUGIN_DIR", str(FIXTURES / "good-plugin"))
    monkeypatch.setenv("FORMAT", "json")
    monkeypatch.setenv("WRITE_STEP_SUMMARY", "false")
    monkeypatch.setenv("SUBMISSION_ENABLED", "true")
    monkeypatch.setenv("SUBMISSION_SCORE_THRESHOLD", "0")
    monkeypatch.setenv("SUBMISSION_REPOS", "hashgraph-online/awesome-codex-plugins")
    monkeypatch.setenv("SUBMISSION_TOKEN", "token-123")
    monkeypatch.setenv("GITHUB_API_URL", "https://evil.example/api/v3")

    return_code = main()

    captured = capsys.readouterr()
    assert return_code == 1
    assert "Invalid GITHUB_API_URL" in captured.err


def test_publish_workflow_does_not_inline_version_output_in_shell_scripts() -> None:
    workflow = yaml.safe_load((Path(__file__).parent.parent / ".github" / "workflows" / "publish.yml").read_text())

    run_blocks = [
        step["run"]
        for job in workflow["jobs"].values()
        for step in job.get("steps", [])
        if isinstance(step, dict) and isinstance(step.get("run"), str)
    ]

    assert all("${{ needs.build.outputs.version }}" not in run for run in run_blocks)
