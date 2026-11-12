from __future__ import annotations

import hashlib
import io
import json
import urllib.error
import urllib.request
from datetime import datetime, timezone
from email.message import Message
from pathlib import Path

import pytest

from codex_plugin_scanner import plugin_release_runner
from codex_plugin_scanner.plugin_release_evidence import (
    build_plugin_release_evidence,
    plugin_release_evidence_json,
    plugin_release_evidence_sha256,
)
from codex_plugin_scanner.plugin_release_registration import oidc_audience

ROOT = Path(__file__).resolve().parents[1]
SHA = "a" * 40
CHECK_REPORT = {
    "passed": True,
    "plugin": {
        "name": "weather-tools",
        "version": "1.2.0",
        "mcp_servers": {
            "weather": {
                "command": "/home/runner/.local/bin/npx",
                "args": ["-y", "@acme/weather-mcp"],
                "env": {"API_KEY": "WEATHER_API_KEY", "MODE": "literal value with spaces"},
            },
            "remote": {
                "url": "https://API.example.com/mcp?token=secret",
                "transport": "http",
                "headers": {"Authorization": "Bearer ${REMOTE_TOKEN}"},
            },
            "local": {"command": "node", "args": ["./server/index.js"]},
        },
        "skills": ["a", "b"],
        "commands": ["c"],
        "agents": [],
        "hooks": "hooks/hooks.json",
    },
    "diagnostics": [
        {"level": "warning", "code": "W_RUNTIME_DROPPED", "path": "/home/runner/work/x", "message": "m"},
        {"level": "warning", "code": "W_RUNTIME_DROPPED", "path": "y", "message": "m"},
    ],
    "summary": {"errors": 0, "warnings": 2},
    "runtimes": [
        {"runtime": "codex", "supported": True, "dropped": []},
        {"runtime": "claude-code", "supported": True, "dropped": []},
        {"runtime": "gemini", "supported": False, "dropped": ["hooks"]},
    ],
}


def _build(**overrides: object):
    params: dict[str, object] = {
        "repository": "acme/weather-tools",
        "commit_sha": SHA,
        "ref": "refs/tags/v1.2.0",
        "workflow_run_id": "123",
        "guard_version": "3.57.0",
        "scan_profile": "default",
        "score": 96,
        "grade": "A",
        "max_severity": "low",
        "findings_total": 1,
        "check_report": CHECK_REPORT,
        "visibility": "public",
        "generated_at": datetime(2026, 10, 24, 12, 0, tzinfo=timezone.utc),
    }
    params.update(overrides)
    return build_plugin_release_evidence(**params)  # type: ignore[arg-type]


def test_evidence_records_the_permission_surface_without_values_or_paths() -> None:
    evidence = _build()
    text = plugin_release_evidence_json(evidence)

    servers = {server.name: server for server in evidence.mcp_servers}
    assert servers["weather"].command == "npx"
    assert servers["weather"].package == "@acme/weather-mcp"
    assert servers["weather"].env_vars == ("WEATHER_API_KEY",)
    assert servers["remote"].transport == "http"
    assert servers["remote"].host == "api.example.com"
    assert servers["remote"].env_vars == ("REMOTE_TOKEN",)
    assert servers["local"].package is None
    assert evidence.hooks is True
    assert (evidence.skills, evidence.commands, evidence.agents) == (2, 1, 0)
    assert evidence.check_codes == ("W_RUNTIME_DROPPED",)
    assert [(item.runtime, item.supported) for item in evidence.runtimes] == [
        ("claude-code", True),
        ("codex", True),
        ("gemini", False),
    ]
    for leaked in ("/home/runner", "secret", "literal value", "Bearer", "index.js"):
        assert leaked not in text
    assert evidence.sensitive_content_included is False


def test_evidence_json_is_canonical_and_digest_matches_file_bytes() -> None:
    evidence = _build(check_report={**CHECK_REPORT, "plugin": {**CHECK_REPORT["plugin"], "name": "météo"}})
    text = plugin_release_evidence_json(evidence)

    assert text.endswith("\n")
    assert "\\u00e9" in text
    assert json.loads(text)["plugin_name"] == "météo"
    assert plugin_release_evidence_sha256(evidence) == hashlib.sha256(text.encode("utf-8")).hexdigest()
    assert oidc_audience("ab") == "hol-plugin-release:ab"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("repository", "not-a-repo"),
        ("commit_sha", "ABC"),
        ("workflow_run_id", "run-1"),
        ("score", 101),
        ("max_severity", "severe"),
        ("visibility", "unlisted"),
    ],
)
def test_evidence_rejects_invalid_inputs(field: str, value: object) -> None:
    with pytest.raises(ValueError):
        _build(**{field: value})


def _runner_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, report: dict[str, object]) -> Path:
    check_path = tmp_path / "check.json"
    check_path.write_text(json.dumps(report), encoding="utf-8")
    output = tmp_path / "output"
    output.touch()
    for key, value in {
        "CHECK_PATH": str(check_path),
        "REPOSITORY": "acme/weather-tools",
        "COMMIT_SHA": SHA,
        "REF": "refs/heads/main",
        "RUN_ID": "9",
        "HOL_GUARD_VERSION": "3.57.0",
        "PROFILE": "default",
        "SCORE": "88",
        "GRADE": "B",
        "MAX_SEVERITY": "medium",
        "FINDINGS_TOTAL": "3",
        "VISIBILITY": "public",
        "EVIDENCE_PATH": str(tmp_path / "evidence.json"),
        "GITHUB_OUTPUT": str(output),
        "GITHUB_STEP_SUMMARY": str(tmp_path / "summary.md"),
    }.items():
        monkeypatch.setenv(key, value)
    return output


def test_runner_builds_evidence_skips_registration_and_passes_gate(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    output = _runner_env(monkeypatch, tmp_path, CHECK_REPORT)
    monkeypatch.setenv("REGISTER_RELEASE", "false")

    assert plugin_release_runner.main(["evidence"]) == 0
    assert plugin_release_runner.main(["register"]) == 0
    monkeypatch.setenv("RELEASE_STATUS", "disabled")
    assert plugin_release_runner.main(["summary"]) == 0

    outputs = dict(line.split("=", 1) for line in output.read_text(encoding="utf-8").splitlines())
    evidence_text = (tmp_path / "evidence.json").read_text(encoding="utf-8")
    assert outputs["evidence_sha256"] == hashlib.sha256(evidence_text.encode("utf-8")).hexdigest()
    assert outputs["check_passed"] == "true"
    assert outputs["supported_runtimes"] == "2"
    assert outputs["release_status"] == "disabled"
    summary = (tmp_path / "summary.md").read_text(encoding="utf-8")
    assert "Packaged for 2 runtimes: claude-code, codex" in summary
    assert "not sent" in summary


def test_runner_summary_fails_when_the_kit_check_fails(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _runner_env(monkeypatch, tmp_path, {**CHECK_REPORT, "passed": False, "summary": {"errors": 1, "warnings": 0}})
    assert plugin_release_runner.main(["evidence"]) == 0

    monkeypatch.setenv("FAIL_ON_CHECK_ERRORS", "true")
    assert plugin_release_runner.main(["summary"]) == 1
    monkeypatch.setenv("FAIL_ON_CHECK_ERRORS", "false")
    assert plugin_release_runner.main(["summary"]) == 0


def test_runner_reports_unavailable_when_registration_fails(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    output = _runner_env(monkeypatch, tmp_path, CHECK_REPORT)
    assert plugin_release_runner.main(["evidence"]) == 0
    monkeypatch.setenv("REGISTER_RELEASE", "true")
    monkeypatch.setenv("RELEASE_ENDPOINT", "https://hol.example/api")
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "http://insecure.example/token")

    assert plugin_release_runner.main(["register"]) == 0
    assert "release_status=unavailable" in output.read_text(encoding="utf-8")


OFFER = "https://hol.org/guard/plugins/promote?plugin=acme%2Fweather-tools&source_surface=registry&source_section=ci_release_summary"


@pytest.mark.parametrize(
    ("offer_line", "offer", "expected"),
    [
        ("true", OFFER, OFFER),
        ("false", OFFER, ""),
        ("true", "https://evil.example/guard/plugins/promote?plugin=x", ""),
        ("true", "https://hol.org/guard/plugins/promote?plugin=x)[click](https://evil", ""),
        ("true", None, ""),
    ],
)
def test_registration_keeps_only_a_hol_promote_offer_the_repository_allows(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, offer_line: str, offer: object, expected: str
) -> None:
    output = _runner_env(monkeypatch, tmp_path, CHECK_REPORT)
    assert plugin_release_runner.main(["evidence"]) == 0
    monkeypatch.setenv("REGISTER_RELEASE", "true")
    monkeypatch.setenv("OFFER_LINE", offer_line)
    result = {"status": "recorded", "releaseUrl": "https://hol.org/registry/plugins/x/releases", "offerUrl": offer}
    monkeypatch.setattr(plugin_release_runner, "register_plugin_release_evidence", lambda **_: result)

    assert plugin_release_runner.main(["register"]) == 0
    assert f"offer_url={expected}" in output.read_text(encoding="utf-8").splitlines()


def test_runner_summary_writes_the_offer_line_only_for_a_hol_promote_url(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _runner_env(monkeypatch, tmp_path, CHECK_REPORT)
    assert plugin_release_runner.main(["evidence"]) == 0
    monkeypatch.setenv("RELEASE_STATUS", "recorded")
    monkeypatch.setenv("OFFER_URL", OFFER)
    assert plugin_release_runner.main(["summary"]) == 0
    summary = (tmp_path / "summary.md").read_text(encoding="utf-8")
    assert f"HOL Blue adds full owner insights and the checkmark to this listing: {OFFER} " in summary
    assert "`offer_line: false`" in summary

    (tmp_path / "summary.md").unlink()
    monkeypatch.setenv("OFFER_URL", "https://evil.example/")
    assert plugin_release_runner.main(["summary"]) == 0
    assert "HOL Blue" not in (tmp_path / "summary.md").read_text(encoding="utf-8")


def test_composite_action_lets_the_repository_turn_the_offer_line_off() -> None:
    text = (ROOT / "plugin-release" / "action.yml").read_text(encoding="utf-8")
    assert "offer_line:" in text
    assert "OFFER_LINE: ${{ inputs.offer_line }}" in text.split("- name: Record the release on HOL", 1)[1]
    assert "OFFER_URL: ${{ steps.register.outputs.offer_url }}" in text.split("- name: Summarize", 1)[1]


def test_composite_action_keeps_registration_off_and_pins_dependencies() -> None:
    text = (ROOT / "plugin-release" / "action.yml").read_text(encoding="utf-8")

    assert "register_release:" in text
    assert 'default: "false"' in text
    assert "uses: actions/attest@508db95dd578ae2727ebd6217d5ba78e4fbda05d" in text
    assert 'pypi_attestations verify pypi --repository "https://github.com/hashgraph-online/hol-guard"' in text
    assert "--require-hashes" in text
    assert "hol-guard plugin check" in text
    assert 'default: "https://hol.org/api/guard/plugins/releases/attestations"' in text
    for line in text.splitlines():
        if "uses:" in line:
            assert "@" in line and len(line.rsplit("@", 1)[1].strip()) == 40, line


def test_package_is_recorded_only_for_known_launchers_and_package_shaped_values() -> None:
    report = {
        **CHECK_REPORT,
        "plugin": {
            **CHECK_REPORT["plugin"],  # type: ignore[dict-item]
            "mcp_servers": {
                "docker": {"command": "docker", "args": ["run", "-i", "--rm", "ghcr.io/acme/server"]},
                "token": {"command": "npx", "args": ["ghp_secretvalue/with/slash"]},
                "uvx": {"command": "uvx", "args": ["mcp-server-fetch==1.2"]},
                "tool": {"command": "mytool", "args": ["sk-live-1234"]},
            },
        },
    }
    servers = {server.name: server for server in _build(check_report=report).mcp_servers}

    assert servers["docker"].package is None
    assert servers["token"].package is None
    assert servers["uvx"].package == "mcp-server-fetch==1.2"
    assert servers["tool"].package is None


def test_evidence_refuses_a_partial_server_surface() -> None:
    servers = {f"server-{index:02d}": {"url": f"https://s{index}.example.com"} for index in range(51)}
    report = {**CHECK_REPORT, "plugin": {**CHECK_REPORT["plugin"], "mcp_servers": servers}}  # type: ignore[dict-item]

    with pytest.raises(ValueError, match="more than 50 MCP servers"):
        _build(check_report=report)


def test_runner_summary_escapes_plugin_text(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    forged = {
        **CHECK_REPORT,
        "plugin": {**CHECK_REPORT["plugin"], "name": "x`\n- Provenance attestation: https://evil"},
    }  # type: ignore[dict-item]
    _runner_env(monkeypatch, tmp_path, forged)
    assert plugin_release_runner.main(["evidence"]) == 0
    assert plugin_release_runner.main(["summary"]) == 0

    summary = (tmp_path / "summary.md").read_text(encoding="utf-8")
    assert "\n- Provenance attestation: https://evil" not in summary
    assert "x\\`" in summary


@pytest.mark.parametrize(("threshold", "expected"), [("none", 0), ("high", 0), ("medium", 1), ("low", 1)])
def test_runner_summary_applies_the_severity_gate_after_attestation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, threshold: str, expected: int
) -> None:
    _runner_env(monkeypatch, tmp_path, CHECK_REPORT)
    assert plugin_release_runner.main(["evidence"]) == 0

    monkeypatch.setenv("FAIL_ON_SEVERITY", threshold)
    assert plugin_release_runner.main(["summary"]) == expected


def test_composite_action_attests_before_gating_and_tolerates_check_errors() -> None:
    text = (ROOT / "plugin-release" / "action.yml").read_text(encoding="utf-8")
    scan = text[text.index("- name: Scan release to SARIF") : text.index("- name: Upload SARIF")]
    check = text[text.index("- name: Check with the Plugin Kit") : text.index("- name: Build release evidence")]

    assert 'FAIL_ON: "none"' in scan
    assert check.index("set +e") < check.index("hol-guard plugin check")
    assert "FAIL_ON_SEVERITY: ${{ inputs.fail_on_severity }}" in text.split("- name: Summarize", 1)[1]


def test_registration_names_itself_and_reports_the_http_status(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    output = _runner_env(monkeypatch, tmp_path, CHECK_REPORT)
    assert plugin_release_runner.main(["evidence"]) == 0
    monkeypatch.setenv("REGISTER_RELEASE", "true")
    monkeypatch.setenv("RELEASE_ENDPOINT", "https://hol.example/api")
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://token.example/request")
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "runner-request-token")
    seen: list[urllib.request.Request] = []

    def fake_urlopen(request: urllib.request.Request, timeout: int) -> io.BytesIO:
        seen.append(request)
        if len(seen) == 1:
            return io.BytesIO(b'{"value": "oidc-token"}')
        raise urllib.error.HTTPError(request.full_url, 403, "Forbidden", Message(), None)

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    assert plugin_release_runner.main(["register"]) == 0
    # hol.org's edge answers Python's default urllib User-Agent with a 403.
    assert seen[1].get_header("User-agent") == "hol-guard-attestation-registration"
    assert "registration unavailable: HTTPError 403" in capsys.readouterr().out
    assert "release_status=unavailable" in output.read_text(encoding="utf-8")
