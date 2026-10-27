"""Stable releases dispatched on their tag reach the MCP Registry and MCPB consumers."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from scripts.ci import verify_release_workflow_run as verifier
from tests.test_mcp_release_source_verification import IDENTITY, OTHER_SHA, REPOSITORY, SHA, GitHubFixture

TAG = "v3.57.0"
PREFIX = f"/repos/{REPOSITORY}"
WORKFLOWS = Path(__file__).resolve().parents[1] / ".github/workflows"


class TagRunFixture(GitHubFixture):
    """A first-attempt stable publication that Release Please dispatched on its tag."""

    def __init__(self) -> None:
        """Report the tag as head_branch, exactly as GitHub does for a tag-ref dispatch."""
        super().__init__()
        for run in (self.run, self.event["workflow_run"]):
            run.update(head_branch=TAG, event="workflow_dispatch")
        self.tag_ref: dict = {"object": {"type": "commit", "sha": SHA}}
        self.annotated: dict = {"object": {"type": "commit", "sha": SHA}}
        self.latest: dict = {"tag_name": TAG, "draft": False, "prerelease": False}

    def fetch(self, path: str) -> object:
        """Serve the tag, repository and latest-release lookups the tag path adds."""
        if path == f"{PREFIX}/git/ref/tags/{TAG}":
            self.calls.append(path)
            return self.tag_ref
        if path == f"{PREFIX}/git/tags/{OTHER_SHA}":
            self.calls.append(path)
            return self.annotated
        if path == PREFIX:
            self.calls.append(path)
            return IDENTITY
        if path == f"{PREFIX}/releases/latest":
            self.calls.append(path)
            return self.latest
        return super().fetch(path)


def test_stable_tag_dispatch_publishes_from_main() -> None:
    """The 3.57.0 run (head_branch v3.57.0) authorizes the consumers instead of being dropped."""
    fixture = TagRunFixture()
    assert fixture.verify() == (SHA, "main")
    assert fixture.calls[-1].endswith("refs%2Fheads%2Fmain?per_page=1")
    assert verifier.publication_completed(
        fixture.event, repository=REPOSITORY, sha=SHA, branch="main", fetch_json=fixture.fetch
    )


def test_annotated_stable_tag_is_followed_to_its_commit() -> None:
    fixture = TagRunFixture()
    fixture.tag_ref = {"object": {"type": "tag", "sha": OTHER_SHA}}
    assert fixture.verify() == (SHA, "main")


@pytest.mark.parametrize(
    "tag_ref",
    [
        {"object": {"type": "commit", "sha": OTHER_SHA}},
        {"object": {"type": "tree", "sha": SHA}},
        {"object": None},
        {},
    ],
)
def test_tag_that_moved_off_the_built_commit_is_refused(tag_ref: dict) -> None:
    fixture = TagRunFixture()
    fixture.tag_ref = tag_ref
    with pytest.raises(ValueError):
        fixture.verify()
    assert not any("/compare/" in path for path in fixture.calls)


def test_tagged_commit_must_still_be_on_main() -> None:
    fixture = TagRunFixture()
    fixture.comparison["status"] = "diverged"
    with pytest.raises(ValueError, match="trusted release branch"):
        fixture.verify()


@pytest.mark.parametrize(
    "branch,event",
    [
        (TAG, "push"),
        ("v3.57.0a1", "workflow_dispatch"),
        ("v3.57", "workflow_dispatch"),
        ("v03.57.0", "workflow_dispatch"),
        ("extension-data-1", "workflow_dispatch"),
        ("v3.57.0\nbranch=release/3.0", "workflow_dispatch"),
    ],
)
def test_only_canonical_stable_tags_dispatched_by_release_please_qualify(branch: str, event: str) -> None:
    fixture = TagRunFixture()
    for run in (fixture.run, fixture.event["workflow_run"]):
        run.update(head_branch=branch, event=event)
    with pytest.raises(ValueError):
        fixture.verify()
    assert fixture.calls[-1].endswith("/actions/workflows/publish.yml")


def test_event_tag_must_match_the_live_run() -> None:
    fixture = TagRunFixture()
    fixture.run["head_branch"] = "v3.56.0"
    with pytest.raises(ValueError, match="disagree"):
        fixture.verify()


def test_repair_dispatch_rebuilds_the_event_from_github() -> None:
    fixture = TagRunFixture()
    event = verifier.dispatched_release_event("12345", repository=REPOSITORY, fetch_json=fixture.fetch)
    assert event == {"repository": IDENTITY, "workflow_run": fixture.run}
    assert verifier.verify_release_source(
        event, event_name="workflow_run", repository=REPOSITORY, fetch_json=fixture.fetch
    ) == (SHA, "main")


@pytest.mark.parametrize(
    "latest",
    [
        {"tag_name": "v3.58.0", "draft": False, "prerelease": False},
        {"tag_name": TAG, "draft": True, "prerelease": False},
        {"tag_name": TAG, "draft": False, "prerelease": True},
        {},
    ],
)
def test_repair_dispatch_cannot_roll_back_to_an_older_release(latest: dict) -> None:
    fixture = TagRunFixture()
    fixture.latest = latest
    with pytest.raises(ValueError, match="latest stable"):
        verifier.dispatched_release_event("12345", repository=REPOSITORY, fetch_json=fixture.fetch)


@pytest.mark.parametrize("run_id", ["", "0", "-1", "12345/../1", "12345\n", "1" * 21])
def test_repair_dispatch_run_id_cannot_shape_the_api_path(run_id: str) -> None:
    fixture = TagRunFixture()
    with pytest.raises(ValueError, match="numeric"):
        verifier.dispatched_release_event(run_id, repository=REPOSITORY, fetch_json=fixture.fetch)
    assert fixture.calls == []


def test_repair_dispatch_emits_checkout_outputs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """main() ignores the dispatch payload and verifies the named run end to end."""
    fixture = TagRunFixture()
    event_path = tmp_path / "event.json"
    event_path.write_text(json.dumps({"inputs": {"publication_run_id": "999"}}))
    output_path = tmp_path / "output"
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event_path))
    monkeypatch.setenv("GITHUB_EVENT_NAME", "workflow_dispatch")
    monkeypatch.setenv("GITHUB_REPOSITORY", REPOSITORY)
    monkeypatch.setenv("GITHUB_OUTPUT", str(output_path))
    monkeypatch.setenv("PUBLICATION_RUN_ID", "12345")
    monkeypatch.setattr(verifier, "github_json", fixture.fetch)
    assert verifier.main() == 0
    assert output_path.read_text(encoding="utf-8") == f"sha={SHA}\nbranch=main\ntag={TAG}\n"


def test_repair_dispatch_without_a_run_id_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    output_path = tmp_path / "output"
    monkeypatch.setenv("GITHUB_EVENT_NAME", "workflow_dispatch")
    monkeypatch.setenv("GITHUB_REPOSITORY", REPOSITORY)
    monkeypatch.setenv("GITHUB_OUTPUT", str(output_path))
    monkeypatch.delenv("PUBLICATION_RUN_ID", raising=False)
    monkeypatch.setattr(verifier, "github_json", TagRunFixture().fetch)
    assert verifier.main() == 1
    assert not output_path.exists()


def test_consumers_publish_the_verified_tag_not_the_highest_tag_at_the_sha() -> None:
    fixture = TagRunFixture()
    assert verifier.released_tag(fixture.event) == TAG
    branch_run = TagRunFixture()
    for run in (branch_run.run, branch_run.event["workflow_run"]):
        run.update(head_branch="main", event="push")
    assert verifier.released_tag(branch_run.event) == ""
    for name in ("publish-mcp-registry.yml", "publish-mcpb.yml"):
        jobs = yaml.safe_load((WORKFLOWS / name).read_text())["jobs"]
        publish = jobs["publish"]
        resolve = next(step for step in publish["steps"] if step.get("id") == "release")
        assert resolve["env"]["VERIFIED_TAG"] == "${{ needs.verify.outputs.tag }}"
        assert 'tag="$VERIFIED_TAG"' in resolve["run"]


def test_no_other_run_can_displace_a_pending_tag_publication() -> None:
    """GitHub drops the older pending run in a group, so a tag run shares its group with no other release."""
    workflow = yaml.safe_load((WORKFLOWS / "publish-mcp-registry.yml").read_text())
    group = workflow["concurrency"]["group"]
    assert workflow["concurrency"]["cancel-in-progress"] is False
    assert "inputs.publication_run_id" not in group
    assert "github.event_name == 'workflow_dispatch' && 'repair'" in group
    assert "format('tag-{0}', github.event.workflow_run.head_branch)" in group
    assert "format('push-{0}', github.event.workflow_run.id)" in group
    steps = [step["name"] for step in workflow["jobs"]["publish"]["steps"]]
    assert steps.index("Refuse to replace a newer stable release") < steps.index("Publish to MCP registry")
