"""The concise job summary links public repositories to their HOL Plugins listing."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

import codex_plugin_scanner.action_runner as action_runner
from codex_plugin_scanner.models import ScanResult, build_severity_counts

CONNECT_LINK = "https://hol.org/plugins/connect?repo=acme%2Ftool&utm_source=hol-scanner-action&utm_medium=job-summary"


def _run_scan(monkeypatch, tmp_path, *, event: object, publish_hint: str | None = None, **env: str) -> str:
    result = ScanResult(
        score=97,
        grade="A",
        categories=(),
        timestamp="2026-10-24T00:00:00Z",
        plugin_dir=str(tmp_path),
        findings=(),
        severity_counts=build_severity_counts(()),
    )

    def _fake_scan(*_args, **_kwargs):
        return result, result, "default", SimpleNamespace(policy_pass=True), 97, None, None

    event_path = tmp_path / "event.json"
    event_path.write_text(json.dumps(event), encoding="utf-8")
    summary_path = tmp_path / "step-summary.md"
    monkeypatch.setattr(action_runner, "_scan_with_policy", _fake_scan)
    for name, value in {
        "MODE": "scan",
        "PLUGIN_DIR": str(tmp_path),
        "FORMAT": "text",
        "OUTPUT": "",
        "WRITE_STEP_SUMMARY": "true",
        "GITHUB_STEP_SUMMARY": str(summary_path),
        "GITHUB_OUTPUT": str(tmp_path / "github-output.txt"),
        "GITHUB_EVENT_PATH": str(event_path),
        "GITHUB_EVENT_NAME": "push",
        "GITHUB_REPOSITORY": "acme/tool",
        "GITHUB_SERVER_URL": "https://github.com",
        "PR_COMMENT": "off",
        "CISCO_SCAN": "off",
        "SUBMISSION_ENABLED": "false",
        "REGISTRY_PAYLOAD_OUTPUT": "",
        **env,
    }.items():
        monkeypatch.setenv(name, value)
    if publish_hint is None:
        monkeypatch.delenv("PUBLISH_HINT", raising=False)
    else:
        monkeypatch.setenv("PUBLISH_HINT", publish_hint)

    assert action_runner.main() == 0
    return summary_path.read_text(encoding="utf-8")


PUBLIC_EVENT = {"repository": {"full_name": "acme/tool", "private": False}}


def test_public_repository_summary_links_to_hol_plugins(monkeypatch, tmp_path) -> None:
    summary = _run_scan(monkeypatch, tmp_path, event=PUBLIC_EVENT)

    assert "### Publish on HOL Plugins" in summary
    assert f"({CONNECT_LINK})" in summary
    assert "Set `publish_hint: false` to hide it." in summary


@pytest.mark.parametrize(
    ("event", "publish_hint", "env"),
    [
        pytest.param({"repository": {"full_name": "acme/tool", "private": True}}, None, {}, id="private"),
        pytest.param({"repository": {"full_name": "acme/tool"}}, None, {}, id="visibility-unknown"),
        pytest.param({"repository": {"full_name": "other/tool", "private": False}}, None, {}, id="other-repo"),
        pytest.param(PUBLIC_EVENT, "false", {}, id="opted-out"),
        pytest.param(PUBLIC_EVENT, None, {"GITHUB_SERVER_URL": "https://ghe.example.com"}, id="enterprise-server"),
        pytest.param(["not", "an", "object"], None, {}, id="malformed-event"),
    ],
)
def test_summary_omits_publish_hint(monkeypatch, tmp_path, event, publish_hint, env) -> None:
    summary = _run_scan(monkeypatch, tmp_path, event=event, publish_hint=publish_hint, **env)

    assert "## HOL AI Plugin Scanner" in summary
    assert "Publish on HOL Plugins" not in summary
    assert "hol.org/plugins/connect" not in summary


def test_submit_mode_summary_omits_publish_hint() -> None:
    lines = action_runner._build_step_summary_lines(
        mode="submit",
        score="97",
        grade="A",
        grade_label="Excellent",
        max_severity="none",
        findings_total="0",
        report_path="",
        registry_payload_path="",
        submission_issues=[],
        submission_eligible=True,
        publish_hint_repository="acme/tool",
    )

    assert "### Publish on HOL Plugins" not in lines
