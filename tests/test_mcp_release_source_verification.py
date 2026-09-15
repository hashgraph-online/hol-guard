"""Reject untrusted workflow_run sources before checkout or publication."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
import yaml

from scripts.ci import verify_release_workflow_run as verifier

ROOT = Path(__file__).resolve().parents[1]
SHA = "a" * 40
OTHER_SHA = "b" * 40
REPOSITORY = "hashgraph-online/hol-guard"
IDENTITY = {"id": 1194748811, "full_name": REPOSITORY}
WORKFLOW = {"id": 253056808, "path": ".github/workflows/publish.yml", "state": "active"}
RUN = {
    "id": 12345,
    "repository": IDENTITY,
    "head_repository": IDENTITY,
    "workflow_id": WORKFLOW["id"],
    "path": WORKFLOW["path"],
    "status": "completed",
    "conclusion": "success",
    "event": "push",
    "run_attempt": 1,
    "head_branch": "main",
    "head_sha": SHA,
    "head_commit": {"id": SHA, "message": "Release Guard"},
}


class GitHubFixture:
    """Supply independent event, run, workflow, and branch evidence without network access."""

    def __init__(self) -> None:
        """Start from a successful first-attempt release already on its canonical branch."""
        self.event = {"repository": copy.deepcopy(IDENTITY), "workflow_run": copy.deepcopy(RUN)}
        self.run = copy.deepcopy(RUN)
        self.workflow = copy.deepcopy(WORKFLOW)
        self.comparison = {"status": "ahead", "base_commit": {"sha": SHA}, "merge_base_commit": {"sha": SHA}}
        self.calls: list[str] = []

    def fetch(self, path: str) -> object:
        """Reject unexpected endpoints so event data cannot redirect the verifier."""
        self.calls.append(path)
        prefix = f"/repos/{REPOSITORY}"
        if path == f"{prefix}/actions/workflows/publish.yml":
            return self.workflow
        if path == f"{prefix}/actions/runs/12345":
            return self.run
        if path.startswith(f"{prefix}/compare/{SHA}...refs%2Fheads%2F"):
            return self.comparison
        raise AssertionError(f"Unexpected API request: {path}")

    def verify(self, event_name: str = "workflow_run") -> tuple[str, str]:
        """Exercise the same verifier used by the reusable Actions gate."""
        return verifier.verify_release_source(
            self.event, event_name=event_name, repository=REPOSITORY, fetch_json=self.fetch
        )


@pytest.mark.parametrize("branch", ["main", "release/3.0"])
@pytest.mark.parametrize("event", ["push", "workflow_dispatch"])
@pytest.mark.parametrize("status", ["ahead", "identical"])
def test_canonical_releases_keep_the_exact_original_sha(branch: str, event: str, status: str) -> None:
    """A newer branch tip is allowed without switching to a newer, unbuilt source commit."""
    fixture = GitHubFixture()
    for run in (fixture.run, fixture.event["workflow_run"]):
        run.update(head_branch=branch, event=event)
    fixture.comparison["status"] = status
    assert fixture.verify() == (SHA, branch)
    assert len(fixture.calls) == 3
    assert fixture.calls[-1].endswith("refs%2Fheads%2F" + branch.replace("/", "%2F") + "?per_page=1")


@pytest.mark.parametrize("origin", ["pull_request", "pull_request_target", "workflow_dispatch", "push", ""])
def test_only_workflow_run_can_enter_the_verifier(origin: str) -> None:
    """PR validation and manually invoked workflows cannot fabricate a release authorization."""
    fixture = GitHubFixture()
    with pytest.raises(ValueError):
        fixture.verify(origin)
    assert fixture.calls == []


@pytest.mark.parametrize("location", ["event", "live"])
@pytest.mark.parametrize(
    "field,value",
    [
        ("head_sha", "refs/pull/123/head"),
        ("head_sha", SHA + "\nsha=" + OTHER_SHA),
        ("head_sha", None),
        ("head_branch", "feature/unmerged"),
        ("head_branch", "main\nbranch=release/3.0"),
        ("head_branch", None),
        ("event", "pull_request"),
        ("event", "pull_request_target"),
        ("event", "workflow_run"),
        ("event", None),
        ("event", {}),
        ("conclusion", "failure"),
        ("conclusion", "cancelled"),
        ("status", "in_progress"),
        ("run_attempt", 2),
        ("run_attempt", True),
        ("run_attempt", "1"),
        ("workflow_id", 999),
        ("path", ".github/workflows/attacker.yml"),
        ("head_repository", {"id": IDENTITY["id"], "full_name": "attacker/hol-guard"}),
        ("head_repository", {"id": 999, "full_name": REPOSITORY}),
        ("head_repository", None),
        ("head_commit", {"id": SHA, "message": "Release [skip release publish]"}),
        ("head_commit", {"id": OTHER_SHA, "message": "Release"}),
        ("head_commit", {"id": SHA}),
    ],
)
def test_untrusted_event_or_live_run_fails_closed(location: str, field: str, value: object) -> None:
    """Enforce provenance against both the event and independently fetched run evidence."""
    fixture = GitHubFixture()
    target = fixture.run if location == "live" else fixture.event["workflow_run"]
    target[field] = value
    with pytest.raises(ValueError):
        fixture.verify()
    assert not any("/compare/" in path for path in fixture.calls)


@pytest.mark.parametrize("run_id", [True, 0, -1, "12345", "../../pulls/1", None])
def test_run_id_cannot_control_the_api_path(run_id: object) -> None:
    """Require positive integer IDs before constructing an API request."""
    fixture = GitHubFixture()
    fixture.event["workflow_run"]["id"] = run_id
    with pytest.raises(ValueError):
        fixture.verify()
    assert fixture.calls == []


@pytest.mark.parametrize("field,value", [("id", 888), ("path", "attacker.yml"), ("state", "disabled_manually")])
def test_matching_workflow_display_name_is_not_sufficient(field: str, value: object) -> None:
    """A workflow name alone cannot impersonate the canonical publishing workflow."""
    fixture = GitHubFixture()
    fixture.workflow[field] = value
    with pytest.raises(ValueError):
        fixture.verify()


@pytest.mark.parametrize(
    "field,value",
    [
        ("status", "behind"),
        ("status", "diverged"),
        ("status", None),
        ("base_commit", {"sha": OTHER_SHA}),
        ("merge_base_commit", {"sha": OTHER_SHA}),
    ],
)
def test_unmerged_or_rewritten_source_is_not_authorized(field: str, value: object) -> None:
    """Successful CI on an arbitrary commit does not prove membership in a release branch."""
    fixture = GitHubFixture()
    fixture.comparison[field] = value
    with pytest.raises(ValueError, match="trusted release branch"):
        fixture.verify()


@pytest.mark.parametrize("field,value", [("head_branch", "release/3.0"), ("event", "workflow_dispatch")])
def test_event_and_live_run_must_agree(field: str, value: str) -> None:
    """Do not silently replace the event's release identity with different valid-looking evidence."""
    fixture = GitHubFixture()
    fixture.run[field] = value
    with pytest.raises(ValueError, match="disagree"):
        fixture.verify()


def test_api_failure_never_emits_checkout_outputs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Unavailable provenance is a failed gate, not permission to use the raw event SHA."""
    event_path = tmp_path / "event.json"
    output_path = tmp_path / "output"
    event_path.write_text(json.dumps(GitHubFixture().event))
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event_path))
    monkeypatch.setenv("GITHUB_EVENT_NAME", "workflow_run")
    monkeypatch.setenv("GITHUB_REPOSITORY", REPOSITORY)
    monkeypatch.setenv("GITHUB_OUTPUT", str(output_path))

    def unavailable(_path: str) -> object:
        """Simulate an unavailable or unauthorized GitHub API without making a request."""
        raise OSError("API unavailable")

    monkeypatch.setattr(verifier, "github_json", unavailable)
    assert verifier.main() == 1
    assert not output_path.exists()


def test_verified_outputs_are_safe_for_actions(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Only validated fixed-format SHA and allowlisted branch values reach GITHUB_OUTPUT."""
    fixture = GitHubFixture()
    event_path = tmp_path / "event.json"
    output_path = tmp_path / "output"
    event_path.write_text(json.dumps(fixture.event))
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event_path))
    monkeypatch.setenv("GITHUB_EVENT_NAME", "workflow_run")
    monkeypatch.setenv("GITHUB_REPOSITORY", REPOSITORY)
    monkeypatch.setenv("GITHUB_OUTPUT", str(output_path))
    monkeypatch.setattr(verifier, "github_json", fixture.fetch)
    assert verifier.main() == 0
    assert output_path.read_text() == f"sha={SHA}\nbranch=main\n"


def test_gate_executes_only_trusted_default_branch_verification_code() -> None:
    """Keep the verifier read-only and prohibit checking out the candidate before verification."""
    workflow = yaml.safe_load((ROOT / ".github/workflows/verify-mcp-release-source.yml").read_text())
    job = workflow["jobs"]["verify"]
    assert workflow["permissions"] == {}
    assert job["permissions"] == {"actions": "read", "contents": "read"}
    assert job["if"] == "github.event_name == 'workflow_run'"
    checkout = job["steps"][0]
    assert checkout["with"] == {"ref": "${{ github.sha }}", "persist-credentials": False}
    assert job["steps"][1]["run"] == "python3 -I -S scripts/ci/verify_release_workflow_run.py"
    assert job["outputs"] == {"sha": "${{ steps.source.outputs.sha }}", "branch": "${{ steps.source.outputs.branch }}"}


def test_pull_request_validation_is_separate_from_privileged_triggers() -> None:
    """Unmerged bundles are validated only under the ordinary read-only pull_request event."""
    workflow = yaml.safe_load((ROOT / ".github/workflows/mcpb-validation.yml").read_text())
    assert workflow[True] == {"pull_request": {"branches": ["main", "release/3.0"]}}
    assert workflow["permissions"] == {"contents": "read"}
    job = workflow["jobs"]["validate"]
    assert "permissions" not in job
    assert "ref" not in job["steps"][0]["with"]
    assert job["steps"][0]["with"]["persist-credentials"] is False
    commands = "\n".join(step.get("run", "") for step in job["steps"])
    assert "compileall" in commands and "npm ci --ignore-scripts" in commands
    assert '"$MCPB_CLI" validate' in commands and '"$MCPB_CLI" pack' in commands
