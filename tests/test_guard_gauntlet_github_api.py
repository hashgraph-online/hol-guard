"""Tests for repository API source binding and trusted Gauntlet workflow refs."""

import io

import pytest


@pytest.mark.parametrize("path", ["", "/", "/compare/" + "a" * 40 + "..." + "b" * 40])
def test_repository_api_accepts_root_and_immutable_comparison_routes(monkeypatch, path):
    """Allow repository metadata and immutable comparison routes within the configured API origin."""
    import urllib.request

    from ci.gauntlet.github_ci import GitHubAPI

    monkeypatch.setenv("GITHUB_REPOSITORY", "hashgraph-online/hol-guard")
    monkeypatch.setenv("GITHUB_TOKEN", "synthetic-test-only")
    requests = []

    def opened(request, timeout):
        """Capture an outgoing request and return synthetic repository comparison metadata."""
        requests.append(request)
        return io.BytesIO(b'{"status":"ahead","default_branch":"main"}')

    monkeypatch.setattr(urllib.request, "urlopen", opened)
    assert GitHubAPI().request(path)["status"] == "ahead"
    assert requests[0].full_url == "https://api.github.com/repos/hashgraph-online/hol-guard" + path


@pytest.mark.parametrize(
    "path",
    [
        "https://attacker.invalid/path",
        "//attacker.invalid/path",
        "/../other/repo",
        "/%2e%2e/other/repo",
        "/contents/./secret",
        "/%2f%2fattacker.invalid",
        "/contents/\\secret",
        "/contents/file#fragment",
        "/contents/file\n",
    ],
)
def test_repository_api_rejects_authority_and_traversal_inputs(monkeypatch, path):
    """Reject unsafe API paths before any authenticated network request is sent."""
    import urllib.request

    from ci.gauntlet.github_ci import GitHubAPI

    monkeypatch.setenv("GITHUB_REPOSITORY", "hashgraph-online/hol-guard")
    monkeypatch.setenv("GITHUB_TOKEN", "synthetic-test-only")

    def forbidden(*args, **kwargs):
        """Fail if an invalid API route reaches the network transport."""
        raise AssertionError("invalid route must not send a token")

    monkeypatch.setattr(urllib.request, "urlopen", forbidden)
    with pytest.raises(ValueError, match="invalid repository API path"):
        GitHubAPI().request(path)


def test_pull_resolves_current_base_ref_instead_of_stale_pr_metadata(monkeypatch):
    """Resolve the current destination ref separately from the stale base recorded on the PR."""
    from ci.gauntlet.github_ci import GitHubAPI

    monkeypatch.setenv("GITHUB_REPOSITORY", "hashgraph-online/hol-guard")
    monkeypatch.setenv("GITHUB_TOKEN", "synthetic-test-only")
    api = GitHubAPI()

    def request(path):
        """Return stale PR metadata and a newer tip for its encoded destination branch ref."""
        if path == "/pulls/1":
            return {"state": "open", "head": {"sha": "a" * 40}, "base": {"ref": "release/test", "sha": "b" * 40}}
        assert path == "/git/ref/heads/release%2Ftest"
        return {"ref": "refs/heads/release/test", "object": {"sha": "c" * 40, "type": "commit"}}

    monkeypatch.setattr(api, "request", request)
    pull = api.pull(1, "a" * 40)
    assert pull["base"]["sha"] == "b" * 40
    assert pull["gauntlet_base_sha"] == "c" * 40


def test_current_test_merge_must_match_the_independently_resolved_base(monkeypatch):
    """Accept only test-merge parents matching the candidate and the current destination tip."""
    from ci.gauntlet.github_ci import GitHubAPI

    monkeypatch.setenv("GITHUB_REPOSITORY", "hashgraph-online/hol-guard")
    monkeypatch.setenv("GITHUB_TOKEN", "synthetic-test-only")
    api = GitHubAPI()
    monkeypatch.setattr(
        api, "request", lambda path: {"sha": "d" * 40, "parents": [{"sha": "a" * 40}, {"sha": "c" * 40}]}
    )
    api.prove_source("d" * 40, "a" * 40, "c" * 40)
    with pytest.raises(ValueError, match="current test merge"):
        api.prove_source("d" * 40, "a" * 40, "b" * 40)


def test_privileged_gate_uses_only_default_trusted_checkout_and_reviewed_dispatch_refs():
    """Verify trusted gate checkout, dispatch restrictions and the expected job permissions."""
    from pathlib import Path

    import yaml

    workflow = yaml.safe_load(Path(".github/workflows/guard-gauntlet-gate.yml").read_text())
    initialize = workflow["jobs"]["initialize"]
    condition = initialize["if"]
    assert "github.event_name == 'pull_request_target'" in condition
    assert "github.event_name == 'workflow_dispatch'" in condition
    assert "github.event.repository.default_branch" in condition
    assert "refs/tags/guard-gauntlet-bootstrap-v3" in condition
    assert "github.event_name != 'pull_request'" not in condition
    checkouts = [step["with"] for step in initialize["steps"] if step.get("uses", "").startswith("actions/checkout@")]
    assert checkouts == [{"persist-credentials": False}]
    assert initialize["permissions"] == {
        "contents": "read",
        "pull-requests": "read",
        "statuses": "write",
        "actions": "read",
    }
