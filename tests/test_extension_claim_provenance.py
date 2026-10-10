from __future__ import annotations

import hashlib
import json
from typing import Any

import pytest

from scripts.extension_claim_provenance import (
    ClaimProvenanceError,
    populate_snapshot_claimants,
    resolve_initial_contribution,
    resolve_introducing_claimant,
)

SHA = "a" * 40
OLD = "b" * 40
PATH = "contributions/extensions/command.example.json"


class GitHub:
    repo = "hashgraph-online/hol-guard"
    base_url = "https://api.github.com/repos/" + repo

    def __init__(self) -> None:
        self.history = [{"sha": SHA}, {"sha": OLD}]
        self.statuses = {SHA: "modified", OLD: "added"}
        self.associated = [{"number": 7}]
        self.user = {"id": 100, "login": "original-author", "type": "User"}
        self.merged = True
        self.target_repo = self.repo
        self.relation = "ahead"

    def _request(self, url: str) -> Any:
        path = url.removeprefix(self.base_url + "/")
        if path.startswith("commits?"):
            return self.history
        if path == f"commits/{OLD}/pulls?per_page=100":
            return self.associated
        for sha, status in self.statuses.items():
            if path == f"commits/{sha}?per_page=100":
                return {"files": [{"filename": PATH, "status": status}]}
        raise AssertionError(path)

    def pull_request(self, number: int) -> dict:
        return {
            "merged": self.merged, "merged_at": "2026-10-10T00:00:00Z", "merge_commit_sha": OLD,
            "user": self.user, "base": {"ref": "main", "repo": {"full_name": self.target_repo}},
        }

    def pull_request_files(self, number: int) -> list[dict]:
        return [{"filename": PATH, "status": "added"}]

    def compare(self, base: str, head: str) -> dict:
        return {"status": "identical" if base == head else self.relation}


def test_later_source_edits_keep_the_introducing_contributor() -> None:
    owner = resolve_introducing_claimant(GitHub(), PATH, SHA)
    assert (owner.github_id, owner.login, owner.pull_request) == ("100", "original-author", 7)


@pytest.mark.parametrize("change", ["reused", "renamed", "bot", "unmerged", "wrong_repo", "unreachable", "ambiguous"])
def test_unproven_history_never_grants_automatic_authority(change: str) -> None:
    client = GitHub()
    if change == "reused":
        client.statuses[SHA] = "added"
    elif change == "renamed":
        client.statuses[SHA] = "renamed"
    elif change == "bot":
        client.user["type"] = "Bot"
    elif change == "unmerged":
        client.merged = False
    elif change == "wrong_repo":
        client.target_repo = "example/other"
    elif change == "unreachable":
        client.relation = "diverged"
    else:
        client.associated.append({"number": 8})
    with pytest.raises(ClaimProvenanceError):
        resolve_introducing_claimant(client, PATH, SHA)


def test_api_failure_propagates_instead_of_publishing_guessed_authority(monkeypatch: pytest.MonkeyPatch) -> None:
    client = GitHub()
    def unavailable(url: str) -> None:
        raise OSError("Synthetic API outage")
    monkeypatch.setattr(client, "_request", unavailable)
    with pytest.raises(OSError):
        resolve_introducing_claimant(client, PATH, SHA)


def test_source_change_on_a_later_commit_file_page_is_verified(monkeypatch: pytest.MonkeyPatch) -> None:
    client = GitHub()
    original = client._request
    def paginated(url: str) -> Any:
        if url.endswith(f"commits/{SHA}?per_page=100"):
            return {"files": [{"filename": f"docs/{number}.md", "status": "modified"} for number in range(100)]}
        if url.endswith(f"commits/{SHA}?per_page=100&page=2"):
            return {"files": [{"filename": PATH, "status": "modified"}]}
        return original(url)
    monkeypatch.setattr(client, "_request", paginated)
    assert resolve_introducing_claimant(client, PATH, SHA).github_id == "100"


@pytest.mark.parametrize("explicit_ids", [None, [], ["200"], ["100"]])
def test_snapshot_derives_owner_without_changing_committed_json(explicit_ids: list[str] | None) -> None:
    content = b'{"id":"command.example"}'
    entry = {
        "id": "command.example", "claimPolicy": "provenance", "trustClass": "external",
        "sourcePath": PATH, "contributionDigest": "sha256:" + hashlib.sha256(content).hexdigest(),
        "maintainerGithubIds": explicit_ids or [],
    }
    files = {
        PATH: content,
        "docs/guard/extensions/catalog.v1.json": json.dumps({"entries": [entry]}).encode(),
        "docs/guard/extensions/catalog.v2.json": json.dumps({"entries": [
            {**entry, "contributors": [], "originalContributions": []}
        ]}).encode(),
    }
    listing_path = "contributions/extension-listings/command.example.json"
    if explicit_ids is not None:
        files[listing_path] = json.dumps({"maintainerGithubIds": explicit_ids}).encode()
    committed = {key: value for key, value in files.items() if key.startswith("contributions/")}
    owners = populate_snapshot_claimants(files, GitHub(), SHA)
    expected = ["100"] if explicit_ids is None else explicit_ids
    for name in ("catalog.v1.json", "catalog.v2.json"):
        assert json.loads(files["docs/guard/extensions/" + name])["entries"][0]["maintainerGithubIds"] == expected
    assert {key: value for key, value in files.items() if key.startswith("contributions/")} == committed
    assert ("command.example" in owners) == (explicit_ids is None or explicit_ids == ["100"])


@pytest.mark.parametrize("earlier", ["descriptor", "authored"])
def test_format_migrations_and_later_descriptors_preserve_original_author(
    monkeypatch: pytest.MonkeyPatch, earlier: str
) -> None:
    from scripts import extension_claim_provenance as module
    authored = "contributions/command-sources/command.example.json"
    client = GitHub()
    monkeypatch.setattr(module, "_history_changes", lambda client, path, sha, get: [
        (OLD if (path == PATH) == (earlier == "descriptor") else SHA, "added")
    ])
    monkeypatch.setattr(client, "compare", lambda base, head: {
        "status": "ahead" if base == OLD else "behind"
    })
    chosen = []
    def verify(client, path, sha):
        chosen.append(path)
        return module.IntroducingClaimant("100", "original-author", 7, OLD)
    monkeypatch.setattr(module, "resolve_introducing_claimant", verify)
    assert resolve_initial_contribution(client, [PATH, authored], SHA).github_id == "100"
    assert chosen == [PATH if earlier == "descriptor" else authored]


def test_snapshot_api_failure_preserves_existing_catalog_authority(monkeypatch: pytest.MonkeyPatch) -> None:
    content = b'{"id":"command.example"}'
    entry = {"id": "command.example", "claimPolicy": "provenance", "trustClass": "external",
             "sourcePath": PATH, "contributionDigest": "sha256:" + hashlib.sha256(content).hexdigest(),
             "maintainerGithubIds": []}
    files = {PATH: content, **{f"docs/guard/extensions/catalog.{version}.json":
                             json.dumps({"entries": [entry]}).encode() for version in ["v1", "v2"]}}
    before = dict(files)
    client = GitHub()
    def unavailable(url: str) -> None:
        raise OSError("Synthetic API outage")
    monkeypatch.setattr(client, "_request", unavailable)
    with pytest.raises(OSError):
        populate_snapshot_claimants(files, client, SHA)
    assert files == before
