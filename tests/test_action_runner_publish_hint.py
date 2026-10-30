"""The concise job summary links public repositories to their HOL Plugins listing."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

import codex_plugin_scanner.action_runner as action_runner
from codex_plugin_scanner.github_reporting import GitHubPrCommentResult, build_verify_pr_comment_body
from codex_plugin_scanner.models import ScanResult, build_severity_counts

CONNECT_LINK = "https://hol.org/plugins/connect?repo=acme%2Ftool&utm_source=hol-scanner-action&utm_medium=job-summary"
PREFLIGHT_LINK = (
    "https://hol.org/plugins/preflight?repo=acme%2Ftool&utm_source=hol-scanner-action&utm_medium=job-summary"
)


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
    assert f"({PREFLIGHT_LINK})" in summary
    assert "Set `publish_hint: false` to hide it." in summary


@pytest.mark.parametrize(
    ("plugin_dir", "expected_path"),
    [
        pytest.param("plugins/acme-tool", "&path=plugins%2Facme-tool", id="subfolder"),
        pytest.param("./plugins/acme-tool/", "&path=plugins%2Facme-tool", id="dot-prefixed"),
        pytest.param(".", "", id="root"),
        pytest.param("plugins/../secret", "", id="traversal"),
        pytest.param("/home/runner/work/tool", "", id="absolute"),
        pytest.param("\\\\server\\share\\plugin", "", id="unc"),
        pytest.param("C:\\work\\tool", "", id="drive-letter"),
        pytest.param("plugins/$(id)", "", id="shell-characters"),
    ],
)
def test_preflight_link_carries_only_a_plain_relative_folder(plugin_dir, expected_path) -> None:
    lines = action_runner._build_publish_hint_lines("acme/tool", plugin_dir)
    expected = f"https://hol.org/plugins/preflight?repo=acme%2Ftool{expected_path}&utm_source=hol-scanner-action"
    assert any(f"({expected}&utm_medium=job-summary)" in line for line in lines)


def test_marketplace_scope_preflight_link_omits_the_folder() -> None:
    lines = action_runner._build_step_summary_lines(
        mode="scan",
        score="90",
        grade="A",
        grade_label="Excellent",
        max_severity="none",
        findings_total="0",
        report_path="",
        registry_payload_path="",
        submission_issues=[],
        submission_eligible=False,
        scope="marketplace",
        publish_hint_repository="acme/tool",
        publish_hint_plugin_dir="plugins/acme-tool",
    )
    assert any(f"({PREFLIGHT_LINK})" in line for line in lines)


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
    assert "hol.org/plugins/preflight" not in summary


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


PR_COMMENT_LINK = (
    "https://hol.org/plugins/connect?repo=acme%2Ftool&utm_source=hol_marketplace&utm_medium=plugins_pr_comment"
)
SCAN_LIMITS_LINK = (
    "https://hol.org/plugins/trust-score/scan-limits"
    "?utm_source=hol_marketplace&utm_medium=plugins_pr_comment&utm_content=scan_limits"
)


def _scan_comment_body(monkeypatch, tmp_path, *, event: object, publish_hint: str | None = None) -> str:
    bodies: list[str] = []

    def _fake_upsert(**kwargs):
        bodies.append(kwargs["body"])
        return GitHubPrCommentResult(status="created")

    monkeypatch.setattr(action_runner, "upsert_pr_comment", _fake_upsert)
    _run_scan(
        monkeypatch,
        tmp_path,
        event={**event, "pull_request": {"number": 7}} if isinstance(event, dict) else event,
        publish_hint=publish_hint,
        PR_COMMENT="always",
        GITHUB_EVENT_NAME="pull_request",
        GITHUB_TOKEN="test-token",
    )
    assert len(bodies) == 1
    return bodies[0]


def test_public_repository_pr_comment_links_to_listing(monkeypatch, tmp_path) -> None:
    body = _scan_comment_body(monkeypatch, tmp_path, event=PUBLIC_EVENT)

    assert PR_COMMENT_LINK in body
    assert "published advisories matched to it" in body
    assert f"[What it checks and cannot catch]({SCAN_LIMITS_LINK})" in body
    assert "safe" not in body.lower()


@pytest.mark.parametrize(
    ("event", "publish_hint"),
    [
        ({"repository": {"full_name": "acme/tool", "private": True}}, None),
        (PUBLIC_EVENT, "false"),
    ],
)
def test_pr_comment_omits_listing_link(monkeypatch, tmp_path, event, publish_hint) -> None:
    body = _scan_comment_body(monkeypatch, tmp_path, event=event, publish_hint=publish_hint)

    assert "hol.org/plugins" not in body


def test_verify_pr_comment_carries_listing_link_only_when_given() -> None:
    payload = {"verify_pass": True, "cases": []}

    with_link = build_verify_pr_comment_body(
        verification_payload=payload,
        style="concise",
        max_findings_to_render=5,
        listing_hint_repository="acme/tool",
    )
    without_link = build_verify_pr_comment_body(
        verification_payload=payload,
        style="concise",
        max_findings_to_render=5,
    )

    assert PR_COMMENT_LINK in with_link
    assert SCAN_LIMITS_LINK in with_link
    assert "hol.org/plugins" not in without_link


def _capture_ci_report(monkeypatch) -> list[str]:
    sent: list[str] = []

    def _fake_send(body: str, **_kwargs: object) -> str:
        sent.append(body)
        return "sent"

    monkeypatch.setattr(action_runner, "send_ci_report", _fake_send)
    return sent


def test_report_to_hol_sends_the_summary_for_public_repositories(monkeypatch, tmp_path) -> None:
    sent = _capture_ci_report(monkeypatch)
    _run_scan(
        monkeypatch,
        tmp_path,
        event=PUBLIC_EVENT,
        REPORT_TO_HOL="true",
        GITHUB_SHA="b" * 40,
        GITHUB_RUN_ID="42",
    )
    assert len(sent) == 1
    payload = json.loads(sent[0])
    assert payload["repository"] == "acme/tool"
    assert payload["workflow_run_id"] == "42"
    assert payload["score"] == 97


@pytest.mark.parametrize(
    ("event", "report_to_hol"),
    [
        (PUBLIC_EVENT, "false"),
        ({"repository": {"full_name": "acme/tool", "private": True}}, "true"),
    ],
)
def test_report_to_hol_stays_off_by_default_and_for_private_repositories(
    monkeypatch, tmp_path, event, report_to_hol
) -> None:
    sent = _capture_ci_report(monkeypatch)
    _run_scan(
        monkeypatch,
        tmp_path,
        event=event,
        REPORT_TO_HOL=report_to_hol,
        GITHUB_SHA="b" * 40,
        GITHUB_RUN_ID="42",
    )
    assert sent == []
