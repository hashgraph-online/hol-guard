"""Batch snapshot PR evidence while retaining local canonical Git ancestry checks."""

from __future__ import annotations

import json
import re
import subprocess
from typing import Any

if __package__:
    from .extension_claim_provenance import ClaimProvenanceError, _history_changes
else:
    from extension_claim_provenance import ClaimProvenanceError, _history_changes


class SnapshotClaimHistory:
    """One bounded metadata query per 30 introducing commits, with no durable cache.

    Historical path changes and ancestry remain verified from the full checkout.
    Every publication fetches fresh merged PR metadata; incomplete large PR file
    lists use the existing paginated REST reader rather than guessing.
    """

    def __init__(self, client: Any, paths: list[str], source_sha: str) -> None:
        self.client = client
        self.prepared_history: dict[str, list[tuple[str, str]]] = {}
        self._associated: dict[str, list[dict[str, int]]] = {}
        self._pulls: dict[int, dict[str, Any]] = {}
        self._files: dict[int, list[dict[str, str]]] = {}
        def get(path: str) -> Any:
            return client._request(f"{client.base_url}/{path}")
        for path in sorted(set(paths)):
            try:
                self.prepared_history[path] = _history_changes(client, path, source_sha, get)
            except ClaimProvenanceError:
                continue
        commits = sorted({history[-1][0] for history in self.prepared_history.values() if history})
        owner, repo = client.repo.split("/")
        fields = """... on Commit {
          oid associatedPullRequests(first:9) {
            pageInfo { hasNextPage }
            nodes { number merged mergedAt baseRefName repository { nameWithOwner }
              mergeCommit { oid }
              author { __typename login ... on User { databaseId } }
              files(first:100) { pageInfo { hasNextPage } nodes { path changeType } }
            }
          }
        }"""
        for offset in range(0, len(commits), 30):
            batch = commits[offset:offset + 30]
            objects = " ".join(f"c{i}: object(oid:{json.dumps(sha)}) {{ {fields} }}" for i, sha in enumerate(batch))
            query = f"query {{ repository(owner:{json.dumps(owner)},name:{json.dumps(repo)}) {{ {objects} }} }}"
            result = client._request("https://api.github.com/graphql", method="POST", payload={"query": query})
            if not isinstance(result, dict) or result.get("errors"):
                raise RuntimeError("Snapshot claim history query failed")
            repository = result.get("data", {}).get("repository")
            if not isinstance(repository, dict):
                raise RuntimeError("Snapshot claim history repository is unavailable")
            for i, sha in enumerate(batch):
                commit = repository.get(f"c{i}")
                if not isinstance(commit, dict) or commit.get("oid") != sha:
                    raise RuntimeError("Snapshot claim history commit identity differs")
                connection = commit.get("associatedPullRequests", {})
                nodes = connection.get("nodes")
                if not isinstance(nodes, list) or len(nodes) > 9:
                    raise RuntimeError("Snapshot associated PR evidence is invalid")
                if connection.get("pageInfo", {}).get("hasNextPage") and len(nodes) < 9:
                    raise RuntimeError("Snapshot associated PR evidence is incomplete")
                self._associated[sha] = []
                for row in nodes:
                    number = row.get("number") if isinstance(row, dict) else None
                    if type(number) is not int or number <= 0:
                        raise RuntimeError("Snapshot PR identity is invalid")
                    self._associated[sha].append({"number": number})
                    author = row.get("author") or {}
                    merge = row.get("mergeCommit") or {}
                    self._pulls[number] = {
                        "merged": row.get("merged"), "merged_at": row.get("mergedAt"),
                        "merge_commit_sha": merge.get("oid"),
                        "base": {"ref": row.get("baseRefName"), "repo": {
                            "full_name": (row.get("repository") or {}).get("nameWithOwner"),
                        }},
                        "user": {"type": author.get("__typename"), "id": author.get("databaseId"),
                                 "login": author.get("login")},
                    }
                    files = row.get("files")
                    if (isinstance(files, dict) and files.get("pageInfo", {}).get("hasNextPage") is False
                            and isinstance(files.get("nodes"), list) and len(files["nodes"]) <= 100):
                        self._files[number] = [
                            {"filename": item.get("path"), "status": str(item.get("changeType", "")).lower()}
                            for item in files["nodes"] if isinstance(item, dict)
                        ]

    def __getattr__(self, name: str) -> Any:
        return getattr(self.client, name)

    def _request(self, url: str) -> Any:
        prefix = self.client.base_url + "/commits/"
        if url.startswith(prefix) and url.endswith("/pulls?per_page=100"):
            sha = url.removeprefix(prefix).removesuffix("/pulls?per_page=100")
            if sha in self._associated:
                return self._associated[sha]
        return self.client._request(url)

    def pull_request(self, number: int) -> dict[str, Any]:
        if number in self._pulls:
            return self._pulls[number]
        return self.client.pull_request(number)

    def pull_request_files(self, number: int) -> list[dict[str, str]]:
        if number in self._files:
            return self._files[number]
        return self.client.pull_request_files(number)

    def compare(self, base: str, head: str) -> dict[str, str]:
        root = getattr(self.client, "source_root", None)
        if root is not None and re.fullmatch(r"[a-f0-9]{40}", base) and (
            head == "main" or re.fullmatch(r"[a-f0-9]{40}", head)
        ):
            target = "refs/remotes/origin/main" if head == "main" else head
            forward = subprocess.run(
                ["git", "-C", str(root), "merge-base", "--is-ancestor", base, target],
                capture_output=True, timeout=30,
            )
            if forward.returncode == 0:
                return {"status": "identical" if base == head else "ahead"}
            reverse = subprocess.run(
                ["git", "-C", str(root), "merge-base", "--is-ancestor", target, base],
                capture_output=True, timeout=30,
            )
            if reverse.returncode == 0:
                return {"status": "behind"}
            if forward.returncode == reverse.returncode == 1:
                return {"status": "diverged"}
        return self.client.compare(base, head)
