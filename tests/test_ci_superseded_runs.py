"""Privileged cleanup must retain every current-head or ambiguously identified run."""

from __future__ import annotations

import copy
import json
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
REPLACEMENT_ID = 43


def _pr():
    return {
        "state": "open",
        "head": {"sha": HEAD, "ref": "feature", "repo": {"id": 123}},
        "base": {"repo": {"id": 123, "full_name": REPO}},
    }


def _run():
    return {
        "id": 42,
        "workflow_id": 17,
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
        self.replacement = {**_run(), "id": REPLACEMENT_ID, "head_sha": HEAD, "status": "queued"}
        self.pr = _pr()
        self.writes = []
        self.pages = []
        self.finish_on_cancel = False
        self.error = None
        self.second_page = False
        self.full_pages = False
        self.missing_replacement = False
        self.on_old_read = None

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
        if path == f"actions/runs/{REPLACEMENT_ID}":
            if self.missing_replacement:
                raise HTTPError(path, 404, "missing replacement", {}, None)
            return copy.deepcopy(self.replacement)
        if path == f"actions/runs/{self.run['id']}":
            if self.on_old_read:
                self.on_old_read()
            return copy.deepcopy(self.run)
        assert path.startswith("actions/workflows/17/runs?")
        query = parse_qs(urlsplit(path).query)
        assert query["event"] == ["pull_request"]
        assert query["branch"] == ["feature"]
        page = int(query["page"][0])
        self.pages.append(page)
        if self.full_pages or (self.second_page and page == 1):
            other = {**self.run, "pull_requests": [{"number": 999}]}
            return {"workflow_runs": [other] * 100}
        return {"workflow_runs": [copy.deepcopy(self.run), copy.deepcopy(self.replacement)]}


def _retire(api, pause=lambda _seconds: None):
    MODULE.retire(REPO, NUMBER, REPLACEMENT_ID, api, pause)


def test_unresponsive_old_run_gets_normal_then_force_cancel():
    api = FakeAPI()
    pauses = []
    _retire(api, pauses.append)
    assert api.writes == ["actions/runs/42/cancel", "actions/runs/42/force-cancel"]
    assert pauses == [15]


def test_normal_cancellation_does_not_force_cancel_completed_run():
    api = FakeAPI()
    api.finish_on_cancel = True
    _retire(api)
    assert api.writes == ["actions/runs/42/cancel"]


def test_fork_with_explicit_matching_pr_is_supported():
    api = FakeAPI()
    api.pr["base"]["repo"]["id"] = 456
    _retire(api)
    assert api.writes == ["actions/runs/42/cancel", "actions/runs/42/force-cancel"]


def test_fork_without_pr_association_is_not_guessed_from_branch():
    api = FakeAPI()
    api.pr["base"]["repo"]["id"] = 456
    api.run.pop("pull_requests")
    _retire(api)
    assert api.writes == []


@pytest.mark.parametrize(
    "field,value",
    [
        ("status", "completed"),
        ("event", "push"),
        ("event", "workflow_dispatch"),
        ("event", "schedule"),
        ("path", ".github/workflows/publish.yml"),
        ("path", ".github/workflows/native-wheel-ci.yml"),
        ("workflow_id", 99),
        ("repository", {"full_name": "another/repo"}),
        ("head_repository", {"id": 456}),
        ("head_branch", "other-branch"),
        ("head_sha", HEAD),
        ("head_sha", ""),
        ("pull_requests", []),
        ("pull_requests", [{"number": 999}]),
        ("id", 44),
        ("id", True),
    ],
)
def test_unrelated_newer_or_current_runs_are_never_cancelled(field, value):
    run = _run()
    run[field] = value
    api = FakeAPI(run)
    _retire(api)
    assert api.writes == []


@pytest.mark.parametrize(
    "field,value",
    [
        ("head_sha", "c" * 40),
        ("event", "push"),
        ("pull_requests", []),
        ("head_repository", {"id": 999}),
        ("status", "completed"),
        ("path", ".github/workflows/publish.yml"),
    ],
)
def test_missing_or_ineligible_current_head_replacement_prevents_cancellation(field, value):
    api = FakeAPI()
    api.replacement[field] = value
    _retire(api)
    assert api.pages == []
    assert api.writes == []


def test_missing_replacement_api_response_never_cancels_old_run():
    api = FakeAPI()
    api.missing_replacement = True
    with pytest.raises(HTTPError):
        _retire(api)
    assert api.writes == []


@pytest.mark.parametrize("change", ["closed", "new-head", "deleted-fork", "different-base-repo"])
def test_stale_cleanup_event_does_nothing(change):
    api = FakeAPI()
    if change == "closed":
        api.pr["state"] = "closed"
    elif change == "new-head":
        api.pr["head"]["sha"] = "c" * 40
    elif change == "deleted-fork":
        api.pr["head"]["repo"] = None
    else:
        api.pr["base"]["repo"]["full_name"] = "other/repo"
    _retire(api)
    assert api.writes == []
    assert api.pages == []


def test_head_revert_during_grace_period_prevents_force_cancel():
    api = FakeAPI()

    def revert(_seconds):
        api.pr["head"]["sha"] = api.run["head_sha"]

    _retire(api, revert)
    assert api.writes == ["actions/runs/42/cancel"]


def test_head_change_after_listing_prevents_normal_cancel():
    api = FakeAPI()
    api.on_old_read = lambda: api.pr["head"].update(sha=api.run["head_sha"])
    _retire(api)
    assert api.writes == []


def test_replacement_cancelled_during_grace_period_prevents_force_cancel():
    api = FakeAPI()

    def finish(_seconds):
        api.replacement.update(status="completed", conclusion="cancelled")

    _retire(api, finish)
    assert api.writes == ["actions/runs/42/cancel"]


def test_pagination_finds_an_older_active_run():
    api = FakeAPI()
    api.second_page = True
    _retire(api)
    assert api.pages == [1, 2]
    assert api.writes == ["actions/runs/42/cancel", "actions/runs/42/force-cancel"]


def test_pagination_is_bounded_when_api_keeps_returning_full_pages():
    api = FakeAPI()
    api.full_pages = True
    _retire(api)
    assert api.pages == list(range(1, MODULE.MAX_PAGES + 1))
    assert api.writes == []


@pytest.mark.parametrize("code", [401, 403, 500])
def test_api_errors_are_not_treated_as_successful_cancellation(code):
    api = FakeAPI()
    api.error = code
    with pytest.raises(HTTPError):
        _retire(api)
    assert api.writes == ["actions/runs/42/cancel"]


def test_cancellation_conflict_still_rechecks_live_head():
    api = FakeAPI()
    api.error = 409
    _retire(api, lambda _seconds: api.pr["head"].update(sha="c" * 40))
    assert api.writes == ["actions/runs/42/cancel"]


@pytest.mark.parametrize("associations", [[], [{"number": 1}, {"number": 2}]])
def test_entrypoint_does_not_guess_an_ambiguous_pr(monkeypatch, tmp_path, associations):
    event = tmp_path / "event.json"
    event.write_text(json.dumps({"workflow_run": {"id": 43, "event": "pull_request", "pull_requests": associations}}))
    monkeypatch.setenv("GITHUB_REPOSITORY", REPO)
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event))
    monkeypatch.setattr(MODULE, "retire", lambda *args: pytest.fail("ambiguous PR must not trigger cleanup"))
    MODULE.main()


def test_privileged_workflow_only_executes_trusted_inline_code():
    workflow = yaml.load((ROOT / ".github/workflows/ci-superseded-runs.yml").read_text(), Loader=yaml.BaseLoader)
    assert workflow["on"] == {"workflow_run": {"workflows": ["CI", "Native wheel CI"], "types": ["requested", "in_progress"]}}
    assert workflow["permissions"] == {}
    assert workflow["concurrency"]["cancel-in-progress"] == "false"
    assert "workflow_run.id" in workflow["concurrency"]["group"]
    assert set(workflow["jobs"]) == {"retire"}
    job = workflow["jobs"]["retire"]
    assert job["permissions"] == {"actions": "write", "pull-requests": "read"}
    assert job["if"] == "github.event.workflow_run.event == 'pull_request'"
    steps = job["steps"]
    assert len(steps) == 1 and "uses" not in steps[0]
    assert steps[0]["shell"] == "python"
    assert "${{" not in SCRIPT
    assert "checkout" not in SCRIPT and "subprocess" not in SCRIPT
    assert "artifacts" not in SCRIPT and '"DELETE"' not in SCRIPT
