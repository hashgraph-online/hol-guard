"""Derive initial claim authority from canonical, merged contribution history."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any


class ClaimProvenanceError(ValueError):
    """History cannot establish one unambiguous introducing contributor."""


@dataclass(frozen=True)
class IntroducingClaimant:
    github_id: str
    login: str
    pull_request: int
    merge_sha: str


def _sha(value: object) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{40}", value):
        raise ClaimProvenanceError("Invalid canonical commit identity")
    return value


def _history_changes(client: Any, source_path: str, source_sha: str, get: Any) -> list[tuple[str, str]]:
    root = getattr(client, "source_root", None)
    if root is not None:
        available = subprocess.run(
            ["git", "-C", str(root), "merge-base", "--is-ancestor", source_sha, "refs/remotes/origin/main"],
            capture_output=True, timeout=30,
        )
        # Main can advance after checkout. Use the bounded live API proof for
        # that newer immutable head instead of silently dropping its invitation.
        if available.returncode:
            root = None
    if root is not None:
        def git(*args: str) -> str:
            result = subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True, timeout=30)
            if result.returncode or len(result.stdout.encode()) > 1024 * 1024:
                raise ClaimProvenanceError("Trusted source history is unavailable")
            return result.stdout.strip()
        if git("rev-parse", "--is-shallow-repository") != "false":
            raise ClaimProvenanceError("Automatic claim verification requires complete source history")
        commits = git("log", "--format=%H", "-n", "41", source_sha, "--", source_path).splitlines()
        changes = []
        for sha in commits:
            rows = git("diff-tree", "--root", "--no-commit-id", "--name-status", "--no-renames",
                       "-r", _sha(sha), "--", source_path).splitlines()
            if len(rows) != 1 or rows[0].split("\t")[-1] != source_path:
                raise ClaimProvenanceError("Incomplete contribution history")
            changes.append((sha, {"A": "added", "M": "modified"}.get(rows[0].split("\t")[0], "other")))
        return changes
    history = get(f"commits?sha={source_sha}&path={urllib.parse.quote(source_path, safe='')}&per_page=100")
    if not isinstance(history, list) or not 1 <= len(history) <= 40:
        raise ClaimProvenanceError("Contribution history needs review")
    changes = []
    for row in history:
        sha = _sha(row.get("sha") if isinstance(row, dict) else None)
        files = []
        for page in range(1, 5):
            suffix = "" if page == 1 else f"&page={page}"
            detail = get(f"commits/{sha}?per_page=100{suffix}")
            batch = detail.get("files") if isinstance(detail, dict) else None
            if not isinstance(batch, list) or len(batch) > 100 or len(files) + len(batch) > 300:
                raise ClaimProvenanceError("Incomplete commit file evidence")
            files.extend(batch)
            if len(batch) < 100:
                break
        matching = [file for file in files if isinstance(file, dict) and file.get("filename") == source_path]
        if len(matching) != 1:
            raise ClaimProvenanceError("Incomplete contribution history")
        changes.append((sha, matching[0].get("status")))
    return changes


def resolve_introducing_claimant(client: Any, source_path: str, source_sha: str) -> IntroducingClaimant:
    """Require a complete, never-renamed/reused path and one introducing PR.

    GitHub handles and commit emails never grant authority. The account's
    immutable numeric ID comes from the introducing, merged PR's User record.
    API failures propagate; ambiguous history needs review rather than guessing.
    """
    source_sha = _sha(source_sha)
    path_pattern = r"contributions/(?:extensions|command-sources|mcp-servers)/(?:command|mcp)\.[a-z0-9.-]+\.json"
    if not re.fullmatch(path_pattern, source_path):
        raise ClaimProvenanceError("Unsupported contribution path")

    def get(path: str) -> Any:
        return client._request(f"{client.base_url}/{path}")

    if client.compare(source_sha, "main").get("status") not in {"ahead", "identical"}:
        raise ClaimProvenanceError("Contribution snapshot is outside canonical main history")
    changes = _history_changes(client, source_path, source_sha, get)
    if not 1 <= len(changes) <= 40:
        raise ClaimProvenanceError("Contribution history needs review")
    commits = [sha for sha, _ in changes]
    if len(set(commits)) != len(commits):
        raise ClaimProvenanceError("Incomplete contribution history")
    oldest = commits[-1]
    for sha, status in changes:
        expected = "added" if sha == oldest else "modified"
        if status != expected:
            raise ClaimProvenanceError("Renamed or reused contribution path needs review")
    associated = get(f"commits/{oldest}/pulls?per_page=100")
    if not isinstance(associated, list) or not 1 <= len(associated) <= 8:
        raise ClaimProvenanceError("Introducing PR is ambiguous")
    candidates: list[IntroducingClaimant] = []
    seen: set[int] = set()
    for row in associated:
        number = row.get("number") if isinstance(row, dict) else None
        if type(number) is not int or number <= 0 or number in seen:
            raise ClaimProvenanceError("Invalid associated PR identity")
        seen.add(number)
        pull = client.pull_request(number)
        base = pull.get("base", {})
        repo = base.get("repo", {}) if isinstance(base, dict) else {}
        user = pull.get("user", {})
        if (
            not isinstance(base, dict) or not isinstance(repo, dict)
            or pull.get("merged") is not True or not pull.get("merged_at")
            or base.get("ref") != "main" or repo.get("full_name") != client.repo
            or not isinstance(user, dict) or user.get("type") != "User"
            or type(user.get("id")) is not int or not 0 < user["id"] <= 2**53 - 1
            or not isinstance(user.get("login"), str)
            or not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,98}[A-Za-z0-9])?", user["login"])
        ):
            continue
        merge_sha = _sha(pull.get("merge_commit_sha"))
        changes = [file for file in client.pull_request_files(number) if file.get("filename") == source_path]
        if len(changes) != 1 or changes[0].get("status") != "added":
            continue
        if client.compare(oldest, merge_sha).get("status") not in {"ahead", "identical"}:
            continue
        if client.compare(merge_sha, source_sha).get("status") not in {"ahead", "identical"}:
            continue
        candidates.append(IntroducingClaimant(str(user["id"]), user["login"], number, merge_sha))
    if len(candidates) != 1:
        raise ClaimProvenanceError("Introducing PR needs maintainer review")
    return candidates[0]


def populate_snapshot_claimants(
    files: dict[str, bytes], client: Any, source_sha: str
) -> dict[str, IntroducingClaimant]:
    """Enrich generated catalogs only; never change committed contribution JSON."""
    names = ["docs/guard/extensions/catalog.v1.json", "docs/guard/extensions/catalog.v2.json"]
    catalogs = [json.loads(files[name]) for name in names]
    candidates = []
    for entry in catalogs[0]["entries"]:
        if entry.get("claimPolicy") != "provenance" or entry.get("trustClass") != "external":
            continue
        listing_bytes = files.get(f"contributions/extension-listings/{entry['id']}.json")
        if listing_bytes is not None and "maintainerGithubIds" in json.loads(listing_bytes):
            continue
        content = files.get(entry["sourcePath"])
        if content is None or f"sha256:{hashlib.sha256(content).hexdigest()}" != entry["contributionDigest"]:
            raise ClaimProvenanceError("Catalog contribution digest does not match bundled source")
        candidates.append(entry)

    def resolve(entry: dict[str, Any]) -> tuple[str, IntroducingClaimant | None]:
        try:
            return entry["id"], resolve_introducing_claimant(client, entry["sourcePath"], source_sha)
        except ClaimProvenanceError as error:
            print(f"{entry['id']}: automatic claim authority needs review: {error}")
            return entry["id"], None

    with ThreadPoolExecutor(max_workers=4) as workers:
        resolved = dict(workers.map(resolve, candidates))
    for catalog in catalogs:
        for entry in catalog["entries"]:
            owner = resolved.get(entry["id"])
            if owner is None:
                continue
            entry["maintainerGithubIds"] = [owner.github_id]
            if "contributors" in entry:
                if len(entry["contributors"]) < 8 and not any(
                    row.get("githubId") == owner.github_id for row in entry["contributors"]
                ):
                    entry["contributors"].append({
                        "githubId": owner.github_id, "githubLogin": owner.login, "roles": ["author"],
                    })
                reference = {"kind": "pull-request", "url": f"https://github.com/{client.repo}/pull/{owner.pull_request}"}
                if len(entry["originalContributions"]) < 8 and reference not in entry["originalContributions"]:
                    entry["originalContributions"].append(reference)
    for name, catalog in zip(names, catalogs, strict=True):
        encoded = (json.dumps(catalog, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n").encode()
        if len(encoded) > 8 * 1024 * 1024:
            raise ClaimProvenanceError("Enriched catalog exceeds byte limit")
        files[name] = encoded
    return {extension_id: owner for extension_id, owner in resolved.items() if owner is not None}
