"""Recovery survives transient reads and runs independently of pack publication."""

from __future__ import annotations

import io
import json
import sys
import urllib.error
from dataclasses import dataclass
from pathlib import Path

import pytest

from tests.extension_claim_notice_harness import MERGE_SHA, MODULE, FakeGitHub, listing

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
try:
    import plan_extension_claim_recovery as recovery
finally:
    sys.path.pop(0)


@dataclass(frozen=True)
class Claimant:
    github_id: str = "100"
    pull_request: int = 7
    merge_sha: str = MERGE_SHA


@pytest.mark.parametrize("failure", [500, 502, 503, 504, 429, "connection"])
@pytest.mark.parametrize("graphql", [False, True])
def test_transient_read_is_retried(monkeypatch, failure, graphql):
    calls, waits = [], []

    def request(*args, **kwargs):
        calls.append(args[0].method)
        if len(calls) == 1:
            if failure == "connection":
                raise OSError("connection reset")
            raise urllib.error.HTTPError(args[0].full_url, failure, "unavailable", {}, io.BytesIO(b"retry"))
        return io.BytesIO(b'{"default_branch":"main"}')

    monkeypatch.setattr(MODULE.urllib.request, "urlopen", request)
    monkeypatch.setattr(MODULE.time, "sleep", waits.append)
    client = MODULE.GitHubApi("test-token", "example/repo")
    if graphql:
        result = client._request(
            "https://api.github.com/graphql",
            method="POST",
            payload={"query": "query { viewer { login } }"},
            read_only=True,
        )
    else:
        result = client.repo_metadata()
    assert result == {"default_branch": "main"}
    assert calls == (["POST", "POST"] if graphql else ["GET", "GET"])
    assert waits == [1]


@pytest.mark.parametrize(
    "method,status,expected_calls",
    [("GET", 503, 3), ("GET", 403, 1), ("POST", 503, 1), ("PATCH", 503, 1)],
)
def test_retries_are_bounded_and_never_repeat_writes(monkeypatch, method, status, expected_calls):
    calls = []

    def request(*args, **kwargs):
        calls.append(1)
        raise urllib.error.HTTPError(args[0].full_url, status, "unavailable", {}, io.BytesIO(b"failure"))

    monkeypatch.setattr(MODULE.urllib.request, "urlopen", request)
    monkeypatch.setattr(MODULE.time, "sleep", lambda _: None)
    client = MODULE.GitHubApi("test-token", "example/repo")
    with pytest.raises(MODULE.ClaimNoticeError, match=f"GitHub API {status}"):
        client._request(client.base_url, method=method)
    assert len(calls) == expected_calls


def test_inventory_groups_authored_and_descriptor_paths_and_excludes_first_party(tmp_path):
    for folder, identity in [
        ("command-sources", "command.example"),
        ("extensions", "command.example"),
        ("mcp-servers", "mcp.example"),
        ("extensions", "command.core"),
    ]:
        path = tmp_path / "contributions" / folder / f"{identity}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{}")
    for identity, trust in [
        ("command.example", "external"),
        ("command.mcp-example", "external"),
        ("command.core", "first-party"),
    ]:
        path = tmp_path / "contracts/extensions/trust" / f"{identity}.v1.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(
                {
                    "schemaVersion": "guard.extension-trust-binding.v1",
                    "extension": identity,
                    "trustClass": trust,
                }
            )
        )
    assert recovery.external_sources(tmp_path) == {
        "command.example": [
            "contributions/extensions/command.example.json",
            "contributions/command-sources/command.example.json",
        ],
        "mcp.example": ["contributions/mcp-servers/mcp.example.json"],
    }


def test_plan_uses_original_owner_and_respects_explicit_revocation(tmp_path, monkeypatch):
    sources = {"command.original": ["source"], "command.revoked": ["source"], "command.reassigned": ["source"]}
    for identity, ids in [("command.revoked", []), ("command.reassigned", ["200"])]:
        path = tmp_path / "contributions/extension-listings" / f"{identity}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(listing(identity, ids)))
    monkeypatch.setattr(
        recovery,
        "resolve_initial_contribution",
        lambda *args: Claimant(),
    )
    revoked = []
    assert recovery.invitation_entries(object(), tmp_path, sources, "a" * 40, revoked=revoked) == [
        {"extensionId": "command.original", "githubId": "100", "pullRequest": 7}
    ]
    assert {row["extensionId"] for row in revoked} == {"command.revoked", "command.reassigned"}


def test_ambiguous_history_does_not_block_unrelated_recovery(tmp_path, monkeypatch, capsys):
    def resolve(history, paths, sha):
        if paths == ["ambiguous"]:
            raise recovery.ClaimProvenanceError("reused path")
        return Claimant()

    monkeypatch.setattr(recovery, "resolve_initial_contribution", resolve)
    rows = recovery.invitation_entries(
        object(),
        tmp_path,
        {"command.bad": ["ambiguous"], "command.good": ["source"]},
        "a" * 40,
    )
    assert [row["extensionId"] for row in rows] == ["command.good"]
    assert "recovery needs provenance review" in capsys.readouterr().err


def test_later_listing_reassignment_uses_listing_pr_not_old_introduction(tmp_path, monkeypatch):
    identity = "command.example"
    path = tmp_path / "contributions/extension-listings" / f"{identity}.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(listing(identity, ["100"])))
    history = FakeGitHub()
    history.file_payloads[(MERGE_SHA, str(path.relative_to(tmp_path)))] = listing(identity, ["200"])
    monkeypatch.setattr(recovery, "resolve_initial_contribution", lambda *args: Claimant())
    assert recovery.invitation_entries(history, tmp_path, {identity: ["source"]}, MERGE_SHA) == []
    monkeypatch.setattr(history, "_request", lambda url: [{"number": 9}])
    monkeypatch.setattr(
        history,
        "pull_request",
        lambda number: {
            "merged": True,
            "base": {"ref": "main"},
            "merge_commit_sha": MERGE_SHA,
        },
    )
    monkeypatch.setattr(history, "compare", lambda *args: {"status": "ahead"})
    active, revoked = recovery.transition_entries(
        history,
        tmp_path,
        [
            {"extensionId": identity, "githubId": "100", "commit": MERGE_SHA},
        ],
    )
    assert active == [{"extensionId": identity, "githubId": "100", "pullRequest": 9}]
    assert revoked == []


def test_revoked_notice_is_scheduled_once_for_withdrawal(monkeypatch):
    client = FakeGitHub()
    client.logins = {"100": "old-owner"}
    client.comment_rows = [
        {
            "body": MODULE.build_comment(
                [MODULE.NoticeItem("command.example", (("100", "old-owner"),))], MODULE.DEFAULT_STUDIO_URL
            ),
            "user": {"id": MODULE.TRUSTED_NOTICE_ACTOR_ID, "type": "Bot"},
        }
    ]
    rows = [{"extensionId": "command.example", "githubId": "100", "pullRequest": 7}]
    monkeypatch.setattr(recovery, "batched_pull_comments", lambda *args: {})
    assert recovery.pending_revocations(client, rows) == [7]
    client.comment_rows[0]["body"] = MODULE.build_withdrawn_comment()
    assert recovery.pending_revocations(client, rows) == []


def test_read_only_retry_flag_cannot_enable_a_comment_write():
    client = MODULE.GitHubApi("test-token", "example/repo")
    with pytest.raises(MODULE.ClaimNoticeError, match="GraphQL query"):
        client._request(
            client.base_url + "/issues/7/comments", method="POST", payload={"body": "notice"}, read_only=True
        )


def test_listing_history_tracks_explicit_additions_not_unchanged_ids(tmp_path, monkeypatch):
    import subprocess

    old, new = "a" * 40, "b" * 40
    monkeypatch.setattr(recovery.subprocess, "check_output", lambda *args, **kwargs: f"{new}\n{old}\n")

    def run(command, **kwargs):
        ids = ["200"] if command[-1].startswith(old) else ["100", "200"]
        return subprocess.CompletedProcess(command, 0, json.dumps(listing("command.example", ids)), "")

    monkeypatch.setattr(recovery.subprocess, "run", run)
    transitions = recovery.listing_transitions(tmp_path, {"command.example": ["source"]}, new)
    assert transitions == [
        {"extensionId": "command.example", "githubId": "200", "commit": old, "implicit_before": True},
        {"extensionId": "command.example", "githubId": "100", "commit": new, "implicit_before": False},
    ]


def test_shallow_checkout_cannot_report_an_empty_recovery_plan(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["planner", "--source-root", str(tmp_path)])
    monkeypatch.setattr(recovery.subprocess, "check_output", lambda *args, **kwargs: "true\n")
    with pytest.raises(recovery.ClaimProvenanceError, match="complete source history"):
        recovery.main()


def test_bad_historical_listing_does_not_block_other_identities(tmp_path, monkeypatch, capsys):
    def transitions(root, sources, sha):
        if "command.bad" in sources:
            raise recovery.ClaimNoticeError("historical listing schema differs")
        return [{"extensionId": "command.good", "githubId": "100", "commit": "a" * 40}]

    monkeypatch.setattr(recovery, "_listing_transitions", transitions)
    rows = recovery.listing_transitions(tmp_path, {"command.bad": [], "command.good": []}, "a" * 40)
    assert [row["extensionId"] for row in rows] == ["command.good"]
    assert "command.bad: listing recovery needs review" in capsys.readouterr().err


def test_bad_introduction_listing_does_not_block_other_invitations(tmp_path, monkeypatch, capsys):
    identity = "command.bad"
    path = tmp_path / "contributions/extension-listings" / f"{identity}.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(listing(identity, ["100"])))
    history = FakeGitHub()
    history.file_payloads[(MERGE_SHA, str(path.relative_to(tmp_path)))] = {
        "schemaVersion": "obsolete",
        "maintainerGithubIds": ["100"],
    }
    monkeypatch.setattr(recovery, "resolve_initial_contribution", lambda *args: Claimant())
    rows = recovery.invitation_entries(history, tmp_path, {identity: ["source"], "command.good": ["source"]}, MERGE_SHA)
    assert [row["extensionId"] for row in rows] == ["command.good"]
    assert "command.bad: invitation recovery needs review" in capsys.readouterr().err


def test_provider_failure_cannot_become_a_successful_empty_plan(tmp_path, monkeypatch):
    def resolve(*args):
        raise recovery.GitHubApiError("GitHub API 503")

    monkeypatch.setattr(recovery, "resolve_initial_contribution", resolve)
    with pytest.raises(recovery.GitHubApiError, match="503"):
        recovery.invitation_entries(object(), tmp_path, {"command.example": ["source"]}, MERGE_SHA)


def test_provider_failure_on_initial_listing_is_not_a_schema_skip(tmp_path, monkeypatch):
    identity = "command.example"
    path = tmp_path / "contributions/extension-listings" / f"{identity}.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(listing(identity, ["100"])))
    history = FakeGitHub()
    monkeypatch.setattr(recovery, "resolve_initial_contribution", lambda *args: Claimant())

    def file_json(*args, **kwargs):
        raise recovery.GitHubApiError("GitHub API 403")

    monkeypatch.setattr(history, "file_json", file_json)
    with pytest.raises(recovery.GitHubApiError, match="403"):
        recovery.invitation_entries(history, tmp_path, {identity: ["source"]}, MERGE_SHA)


def test_recovery_workflow_is_independent_and_shares_delivery_lock():
    workflow = (Path(__file__).resolve().parents[1] / ".github/workflows/extension-claim-recovery.yml").read_text()
    assert "schedule:" in workflow
    assert "workflow_dispatch:" in workflow
    assert "needs: regen" not in workflow
    assert "plan_extension_claim_recovery.py" in workflow
    assert "fetch-depth: 0" in workflow
    assert "group: extension-claim-notice-${{ matrix.pr_number }}" in workflow
    assert "--refresh-existing" in workflow
