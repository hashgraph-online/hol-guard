from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

from scripts import extension_claim_github_history as history
from scripts.extension_claim_provenance import ClaimProvenanceError, resolve_introducing_claimant

SHA = "a" * 40
OLD = "b" * 40
PATH = "contributions/extensions/command.example.json"


class Client:
    repo = "hashgraph-online/hol-guard"
    base_url = "https://api.github.com/repos/" + repo
    source_root = None

    def __init__(self) -> None:
        self.requests = 0
        self.file_fallbacks = 0
        self.author_type = "User"
        self.large_files = False
        self.errors = False

    def _request(self, url, *, method, payload):
        assert url == "https://api.github.com/graphql" and method == "POST"
        self.requests += 1
        if self.errors:
            return {"errors": [{"message": "Synthetic API outage"}]}
        repository = {}
        for alias, sha in re.findall(r'(c\d+): object\(oid:"([a-f0-9]{40})"\)', payload["query"]):
            repository[alias] = {"oid": sha, "associatedPullRequests": {
                "pageInfo": {"hasNextPage": False}, "nodes": [{
                    "number": 7, "merged": True, "mergedAt": "2026-10-10T00:00:00Z", "baseRefName": "main",
                    "repository": {"nameWithOwner": self.repo}, "mergeCommit": {"oid": sha},
                    "author": {"__typename": self.author_type, "databaseId": 100, "login": "original-author"},
                    "files": {"pageInfo": {"hasNextPage": self.large_files},
                              "nodes": [{"path": PATH, "changeType": "ADDED"}]},
                }],
            }}
        return {"data": {"repository": repository}}

    def compare(self, base, head):
        return {"status": "identical" if base == head else "ahead"}

    def pull_request_files(self, number):
        self.file_fallbacks += 1
        return [{"filename": PATH, "status": "added"}]


def prepare(monkeypatch, client):
    monkeypatch.setattr(history, "_history_changes", lambda *args: [(SHA, "modified"), (OLD, "added")])
    return history.SnapshotClaimHistory(client, [PATH], SHA)


def test_batched_pr_evidence_resolves_owner_without_per_entry_rest(monkeypatch: pytest.MonkeyPatch) -> None:
    client = Client()
    wrapper = prepare(monkeypatch, client)
    assert resolve_introducing_claimant(wrapper, PATH, SHA).github_id == "100"
    assert client.requests == 1 and client.file_fallbacks == 0


def test_unique_introductions_use_bounded_query_batches(monkeypatch: pytest.MonkeyPatch) -> None:
    client = Client()
    paths = [f"contributions/extensions/command.example-{number}.json" for number in range(61)]
    oldest = {path: f"{number + 1:040x}" for number, path in enumerate(paths)}
    monkeypatch.setattr(history, "_history_changes", lambda client, path, *args: [(oldest[path], "added")])
    wrapper = history.SnapshotClaimHistory(client, paths, SHA)
    assert len(wrapper.prepared_history) == 61
    assert client.requests == 3


def test_incomplete_graphql_file_list_uses_paginated_reader(monkeypatch: pytest.MonkeyPatch) -> None:
    client = Client()
    client.large_files = True
    assert resolve_introducing_claimant(prepare(monkeypatch, client), PATH, SHA).github_id == "100"
    assert client.file_fallbacks == 1


def test_batched_bot_authorship_cannot_grant_authority(monkeypatch: pytest.MonkeyPatch) -> None:
    client = Client()
    client.author_type = "Bot"
    with pytest.raises(ClaimProvenanceError):
        resolve_introducing_claimant(prepare(monkeypatch, client), PATH, SHA)


def test_partial_api_errors_stop_publication(monkeypatch: pytest.MonkeyPatch) -> None:
    client = Client()
    client.errors = True
    with pytest.raises(RuntimeError, match="query failed"):
        prepare(monkeypatch, client)


def test_local_canonical_ancestry_needs_no_remote_comparisons(tmp_path: Path) -> None:
    def git(*args):
        return subprocess.check_output(["git", "-C", str(tmp_path), *args], text=True).strip()
    git("init", "-q")
    (tmp_path / "source.txt").write_text("original")
    git("add", "source.txt")
    oldest = git("-c", "user.name=Example", "-c", "user.email=example@example.com",
                 "commit-tree", git("write-tree"), "-m", "original")
    (tmp_path / "source.txt").write_text("updated")
    git("add", "source.txt")
    latest = git("-c", "user.name=Example", "-c", "user.email=example@example.com",
                 "commit-tree", git("write-tree"), "-p", oldest, "-m", "updated")
    git("update-ref", "refs/remotes/origin/main", latest)
    client = Client()
    client.source_root = tmp_path
    wrapper = object.__new__(history.SnapshotClaimHistory)
    wrapper.client = client
    assert wrapper.compare(oldest, latest)["status"] == "ahead"
    assert wrapper.compare(latest, oldest)["status"] == "behind"
    assert wrapper.compare(oldest, "main")["status"] == "ahead"
    assert wrapper.compare(latest, latest)["status"] == "identical"
