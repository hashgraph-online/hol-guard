"""Dispatch scans cannot overwrite main or borrow another PR's provenance."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import Mock

import pytest

from scripts.ci import sonar_scan_context as context_module
from scripts.ci.sonar_scan_context import REPOSITORY, read_context, select_context

SHA = "a" * 40


def environment(branch: str = "fix/coverage") -> dict[str, str]:
    return {
        "GITHUB_REPOSITORY": REPOSITORY,
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REF": f"refs/heads/{branch}",
        "GITHUB_REF_NAME": branch,
        "GITHUB_SHA": SHA,
        "GITHUB_RUN_ID": "37749437932",
        "GITHUB_RUN_ATTEMPT": "1",
    }


def pull(number: int = 3701, branch: str = "fix/coverage", state: str = "open") -> dict:
    return {
        "id": number,
        "number": number,
        "state": state,
        "head": {"sha": SHA, "ref": branch, "repo": {"full_name": REPOSITORY}},
        "base": {"ref": "main", "repo": {"full_name": REPOSITORY}},
    }


def test_main_stays_a_branch_scan_without_a_pull_request_lookup():
    fetch = Mock(side_effect=AssertionError("Main must not be relabeled as a pull request"))
    context = select_context(environment("main"), SHA, fetch)
    assert context["kind"] == "branch"
    assert "pull_request" not in context


@pytest.mark.parametrize("change", ["checkout", "sha", "repository", "ref", "event", "run", "attempt"])
def test_an_unbound_source_cannot_select_a_sonar_context(change):
    source = environment()
    checkout = SHA
    if change == "checkout":
        checkout = "b" * 40
    elif change == "sha":
        source["GITHUB_SHA"] = "0" * 40
    elif change == "repository":
        source["GITHUB_REPOSITORY"] = "someone/hol-guard"
    elif change == "ref":
        source["GITHUB_REF"] = "refs/heads/main"
    elif change == "event":
        source["GITHUB_EVENT_NAME"] = "pull_request_target"
    elif change == "run":
        source["GITHUB_RUN_ID"] = "0"
    else:
        source.pop("GITHUB_RUN_ATTEMPT")
    with pytest.raises(ValueError):
        select_context(source, checkout, Mock(return_value=[pull()]))


@pytest.mark.parametrize("change", ["sha", "head-ref", "head-repo", "base-repo", "base-ref", "number"])
def test_association_is_not_enough_without_exact_head_repository_and_main_target(change):
    associated = pull()
    if change == "sha":
        associated["head"]["sha"] = "b" * 40
    elif change == "head-ref":
        associated["head"]["ref"] = "fix/another"
    elif change == "head-repo":
        associated["head"]["repo"]["full_name"] = "fork/hol-guard"
    elif change == "base-repo":
        associated["base"]["repo"]["full_name"] = "fork/hol-guard"
    elif change == "base-ref":
        associated["base"]["ref"] = "release/3.2"
    else:
        associated["number"] = True
    with pytest.raises(ValueError, match="exact source"):
        select_context(environment(), SHA, Mock(return_value=[associated]))


@pytest.mark.parametrize("associations", [[], [pull(state="closed")], [pull(), pull(3702)]])
def test_missing_or_ambiguous_open_associations_never_fall_back_to_main(associations):
    with pytest.raises(ValueError, match="exactly one open"):
        select_context(environment(), SHA, Mock(return_value=associations))


def test_open_association_on_a_later_page_is_selected_after_complete_inventory():
    closed = [pull(number=index, state="closed") for index in range(1, 101)]
    fetch = Mock(side_effect=[closed, [pull()]])
    context = select_context(environment(), SHA, fetch)
    assert context["kind"] == "pull_request"
    assert context["pull_request"] == "3701"


def test_later_page_can_make_the_first_open_association_ambiguous():
    first_page = [pull()] + [pull(number=index, state="closed") for index in range(1, 100)]
    with pytest.raises(ValueError, match="exactly one open"):
        select_context(environment(), SHA, Mock(side_effect=[first_page, [pull(3702)]]))


def test_repeated_rows_across_pages_cannot_hide_an_unstable_pr_inventory():
    first_page = [pull(number=index, state="closed") for index in range(1, 101)]
    with pytest.raises(ValueError, match="pagination"):
        select_context(environment(), SHA, Mock(side_effect=[first_page, [first_page[0], pull()]]))


def test_a_full_final_page_cannot_be_treated_as_a_complete_inventory():
    pages = [[pull(number=page * 100 + index, state="closed") for index in range(1, 101)] for page in range(10)]
    with pytest.raises(ValueError, match="pagination limit"):
        select_context(environment(), SHA, Mock(side_effect=pages))


def test_main_cannot_be_used_as_a_fallback_for_a_non_dispatch_branch():
    source = environment()
    source["GITHUB_EVENT_NAME"] = "push"
    with pytest.raises(ValueError, match="verified pull request"):
        select_context(source, SHA, Mock(return_value=[pull()]))


@pytest.mark.parametrize("change", ["revision", "branch", "run", "attempt", "main-as-pr", "pr-as-main"])
def test_saved_context_from_another_source_or_execution_is_not_reusable(tmp_path, monkeypatch, change):
    monkeypatch.chdir(tmp_path)
    source = environment()
    context = select_context(source, SHA, Mock(return_value=[pull()]))
    context["prepared_at"] = "2026-10-08T07:49:00Z"
    if change == "revision":
        context["revision"] = "b" * 40
    elif change == "branch":
        context["branch"] = "fix/another"
    elif change == "run":
        context["GITHUB_RUN_ID"] = "37749437933"
    elif change == "attempt":
        context["GITHUB_RUN_ATTEMPT"] = "2"
    elif change == "main-as-pr":
        source = environment("main")
        context.update(branch="main")
    else:
        context["kind"] = "branch"
        context.pop("pull_request")
    Path("sonar-scan-context.json").write_text(json.dumps(context), encoding="utf-8")
    with pytest.raises(ValueError):
        read_context(source, SHA)


def test_preparing_a_new_scan_removes_metadata_from_a_previous_task(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    Path("sonar-project.properties").write_text("sonar.projectKey=hashgraph-online_hol-guard\n", encoding="utf-8")
    stale = Path(".scannerwork/report-task.txt")
    stale.parent.mkdir()
    stale.write_text("ceTaskId=previous-task\n", encoding="utf-8")
    monkeypatch.setattr(context_module, "checkout_revision", lambda: SHA)
    monkeypatch.setattr(context_module, "github_json", Mock(return_value=[pull()]))
    context_module.prepare(environment())
    assert not stale.exists()


@pytest.mark.parametrize(("status", "exit_code"), [("OK", 0), ("ERROR", 1), ("WARN", 1), ("NONE", 1), (None, 1)])
def test_correct_scan_identity_does_not_waive_a_failed_standard_gate(tmp_path, monkeypatch, status, exit_code):
    import sys

    from scripts.ci.sonar_quality_client import SonarClient

    monkeypatch.chdir(tmp_path)
    source = environment()
    context = select_context(source, SHA, Mock(return_value=[pull()]))
    context["prepared_at"] = "2026-10-08T07:49:00Z"
    Path("sonar-scan-context.json").write_text(json.dumps(context), encoding="utf-8")
    task = Path(".scannerwork/report-task.txt")
    task.parent.mkdir()
    task.write_text(
        "projectKey=hashgraph-online_hol-guard\nserverUrl=https://sonarcloud.io\nceTaskId=task-id\n",
        encoding="utf-8",
    )
    responses = iter(
        [
            {
                "task": {
                    "id": "task-id",
                    "componentKey": "hashgraph-online_hol-guard",
                    "status": "SUCCESS",
                    "analysisId": "analysis-id",
                    "submittedAt": "2026-10-08T07:55:00+0000",
                    "pullRequest": "3701",
                }
            },
            {
                "pullRequests": [
                    {
                        "key": "3701",
                        "branch": "fix/coverage",
                        "base": "main",
                        "commit": {"sha": SHA},
                        "analysisDate": "2026-10-08T07:49:41+0000",
                    }
                ]
            },
            {"projectStatus": {"status": status}},
        ]
    )
    for key, value in source.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv("SONAR_TOKEN", "test-only-token")
    monkeypatch.setattr(context_module, "checkout_revision", lambda: SHA)
    monkeypatch.setattr(SonarClient, "read", lambda *_args, **_kwargs: next(responses))
    monkeypatch.setattr(sys, "argv", ["sonar_scan_context", "--verify"])
    assert context_module.main() == exit_code
