"""The privileged cleanup workflow may cancel only obsolete runs of the same PR."""

from __future__ import annotations

import copy
from pathlib import Path
from types import ModuleType
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlsplit

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = yaml.safe_load((ROOT / ".github/workflows/ci-superseded-runs.yml").read_text())
SCRIPT = WORKFLOW["jobs"]["retire"]["steps"][0]["run"]
MODULE = ModuleType("superseded_workflow_test")
exec(compile(SCRIPT, "ci-superseded-runs.yml", "exec"), MODULE.__dict__)
REPO = "hashgraph-online/hol-guard"
NUMBER = 3216
HEAD = "b" * 40


def _pr():
    return {
        "state": "open",
        "head": {"sha": HEAD, "ref": "feature", "repo": {"id": 123}},
        "base": {"repo": {"id": 123}},
    }


def _run():
    return {
        "id": 42,
        "status": "in_progress",
        "event": "pull_request",
        "path": ".github/workflows/ci.yml",
        "repository": {"full_name": REPO},
        "head_repository": {"id": 123},
        "head_branch": "feature",
        "head_sha": "a" * 40,
        "pull_requests": [{"number": NUMBER}],
    }


class FakeAPI:
    def __init__(self, run=None):
        self.run = _run() if run is None else run
        self.pr = _pr()
        self.writes = []
        self.pages = []
        self.finish_on_cancel = False
        self.error = None
        self.second_page = False

    def __call__(self, method, path):
        if method == "POST":
            self.writes.append(path)
            if self.error:
                raise HTTPError(path, self.error, "test error", {}, None)
            if self.finish_on_cancel:
                self.run["status"] = "completed"
            return None
        if path == f"pulls/{NUMBER}":
            return copy.deepcopy(self.pr)
        if path == "actions/runs/42":
            return copy.deepcopy(self.run)
        query = parse_qs(urlsplit(path).query)
        assert query["event"] == ["pull_request"]
        assert query["branch"] == ["feature"]
        page = int(query["page"][0])
        self.pages.append(page)
        if not path.startswith("actions/workflows/ci.yml/") or query["status"] != ["in_progress"]:
            return {"workflow_runs": []}
        if self.second_page and page == 1:
            other = {**self.run, "pull_requests": [{"number": 999}]}
            return {"workflow_runs": [other] * 100}
        return {"workflow_runs": [copy.deepcopy(self.run)]}


def test_unresponsive_old_run_gets_normal_then_force_cancel():
    api = FakeAPI()
    pauses = []
    MODULE.retire(REPO, NUMBER, HEAD, api, pauses.append)
    assert api.writes == ["actions/runs/42/cancel", "actions/runs/42/force-cancel"]
    assert pauses == [15]


def test_normal_cancellation_does_not_force_cancel_completed_run():
    api = FakeAPI()
    api.finish_on_cancel = True
    MODULE.retire(REPO, NUMBER, HEAD, api, lambda _seconds: None)
    assert api.writes == ["actions/runs/42/cancel"]


def test_fork_run_without_pull_requests_is_cancelled():
    api = FakeAPI()
    api.pr["base"]["repo"]["id"] = 456
    api.run.pop("pull_requests")
    MODULE.retire(REPO, NUMBER, HEAD, api, lambda _seconds: None)
    assert api.writes == ["actions/runs/42/cancel", "actions/runs/42/force-cancel"]


@pytest.mark.parametrize(
    "field,value",
    [
        ("status", "completed"),
        ("event", "push"),
        ("path", ".github/workflows/publish.yml"),
        ("repository", {"full_name": "another/repo"}),
        ("head_repository", {"id": 456}),
        ("head_branch", "other-branch"),
        ("head_sha", HEAD),
        ("head_sha", ""),
        ("pull_requests", []),
        ("pull_requests", [{"number": 999}]),
    ],
)
def test_unrelated_or_current_runs_are_never_cancelled(field, value):
    run = _run()
    run[field] = value
    api = FakeAPI(run)
    MODULE.retire(REPO, NUMBER, HEAD, api, lambda _seconds: None)
    assert api.writes == []


@pytest.mark.parametrize("change", ["closed", "new-head", "deleted-fork"])
def test_stale_cleanup_event_does_nothing(change):
    api = FakeAPI()
    if change == "closed":
        api.pr["state"] = "closed"
    elif change == "new-head":
        api.pr["head"]["sha"] = "c" * 40
    else:
        api.pr["head"]["repo"] = None
    MODULE.retire(REPO, NUMBER, HEAD, api, lambda _seconds: None)
    assert api.writes == []
    assert api.pages == []


def test_head_change_during_grace_period_prevents_force_cancel():
    api = FakeAPI()

    def advance(_seconds):
        api.pr["head"]["sha"] = api.run["head_sha"]

    MODULE.retire(REPO, NUMBER, HEAD, api, advance)
    assert api.writes == ["actions/runs/42/cancel"]


def test_pagination_finds_an_older_active_run():
    api = FakeAPI()
    api.second_page = True
    MODULE.retire(REPO, NUMBER, HEAD, api, lambda _seconds: None)
    assert 2 in api.pages
    assert api.writes == ["actions/runs/42/cancel", "actions/runs/42/force-cancel"]


def test_permission_errors_are_not_treated_as_successful_cancellation():
    api = FakeAPI()
    api.error = 403
    with pytest.raises(HTTPError):
        MODULE.retire(REPO, NUMBER, HEAD, api, lambda _seconds: None)
    assert api.writes == ["actions/runs/42/cancel"]


def test_privileged_workflow_never_executes_pull_request_code():
    workflow = yaml.load((ROOT / ".github/workflows/ci-superseded-runs.yml").read_text(), Loader=yaml.BaseLoader)
    assert workflow["on"]["pull_request_target"]["types"] == ["opened", "reopened", "synchronize"]
    assert workflow["permissions"] == {"actions": "write", "pull-requests": "read"}
    assert workflow["concurrency"]["cancel-in-progress"] == "true"
    steps = workflow["jobs"]["retire"]["steps"]
    assert len(steps) == 1 and "uses" not in steps[0]
    assert steps[0]["shell"] == "python"
    assert "${{" not in steps[0]["run"]
    assert "checkout" not in SCRIPT and "subprocess" not in SCRIPT
    assert "artifacts" not in SCRIPT and '"DELETE"' not in SCRIPT
