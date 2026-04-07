"""Tests for native sticky pull request comment support."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from codex_plugin_scanner.pr_comments import (
    PRCommentConfig,
    PRCommentSnapshot,
    PullRequestContext,
    compute_comment_header,
    publish_pr_comment,
    resolve_pr_context,
)


def _build_snapshot(*, gate_pass: bool = True) -> PRCommentSnapshot:
    return PRCommentSnapshot(
        mode="scan",
        profile="default",
        plugin_dir="/repo",
        scope="plugin",
        score=92,
        grade="A",
        grade_label="Excellent",
        max_severity="medium",
        findings_total=2,
        severity_counts={"critical": 0, "high": 0, "medium": 2, "low": 0, "info": 0},
        min_score=80,
        fail_on_severity="high",
        score_gate_pass=True,
        severity_gate_pass=True,
        policy_pass=True,
        verify_pass=True,
        gate_pass=gate_pass,
        gate_reasons=() if gate_pass else ("policy profile failed",),
        top_findings=(),
        categories=(),
        integrations=(),
        submission_eligible=False,
        submission_issues=(),
        workflow_url="https://github.com/hashgraph-online/codex-plugin-scanner/actions/runs/1",
        full_report_markdown="",
    )


def test_compute_comment_header_is_stable() -> None:
    header_a = compute_comment_header(
        mode="scan",
        profile="default",
        plugin_dir="/repo",
        configured_header="",
    )
    header_b = compute_comment_header(
        mode="scan",
        profile="default",
        plugin_dir="/repo",
        configured_header="",
    )
    assert header_a == header_b
    assert header_a.startswith("mode=scan;profile=default;target=")


def test_resolve_pr_context_reads_event_payload(tmp_path: Path) -> None:
    event_payload = {
        "pull_request": {
            "number": 45,
            "head": {"sha": "abc123"},
        }
    }
    event_file = tmp_path / "event.json"
    event_file.write_text(json.dumps(event_payload), encoding="utf-8")

    context = resolve_pr_context(
        event_name="pull_request",
        event_path=str(event_file),
        ref="refs/pull/45/merge",
        repository="hashgraph-online/codex-plugin-scanner",
        head_sha="fallback",
        workflow_url="",
    )

    assert context is not None
    assert context.owner == "hashgraph-online"
    assert context.repo == "codex-plugin-scanner"
    assert context.number == 45
    assert context.head_sha == "abc123"


def test_publish_pr_comment_auto_skips_when_not_pr_event() -> None:
    outcome = publish_pr_comment(
        config=PRCommentConfig(
            mode="auto",
            style="concise",
            header="",
            max_findings=3,
            token="token",
            skip_if_unchanged=True,
            compare_to_previous=True,
        ),
        snapshot=_build_snapshot(),
        event_name="push",
        event_path="",
        ref="refs/heads/main",
        repository="hashgraph-online/codex-plugin-scanner",
        head_sha="abc123",
    )

    assert outcome.status == "skipped"
    assert outcome.reason == "not a pull request event"


def test_publish_pr_comment_creates_new_comment(monkeypatch) -> None:
    create_calls: list[tuple[PullRequestContext, str]] = []

    monkeypatch.setattr("codex_plugin_scanner.pr_comments._list_issue_comments", lambda **_: [])

    def _create_stub(*, context, token, body, api_base_url):
        create_calls.append((context, body))
        return SimpleNamespace(
            comment_id=10,
            url="https://github.com/comment/10",
            body=body,
            updated_at="",
        )

    monkeypatch.setattr("codex_plugin_scanner.pr_comments._create_issue_comment", _create_stub)

    outcome = publish_pr_comment(
        config=PRCommentConfig(
            mode="auto",
            style="concise",
            header="",
            max_findings=3,
            token="token",
            skip_if_unchanged=True,
            compare_to_previous=True,
        ),
        snapshot=_build_snapshot(),
        event_name="pull_request",
        event_path="",
        ref="refs/pull/123/merge",
        repository="hashgraph-online/codex-plugin-scanner",
        head_sha="abc123",
    )

    assert outcome.status == "created"
    assert outcome.comment_id == 10
    assert outcome.url == "https://github.com/comment/10"
    assert len(create_calls) == 1
    assert "Compared with the previous scan on this PR" in create_calls[0][1]
    assert "| Score gate | `min_score=80 ✅` |" in create_calls[0][1]
    assert "| Severity gate | `fail_on_severity=high ✅` |" in create_calls[0][1]
