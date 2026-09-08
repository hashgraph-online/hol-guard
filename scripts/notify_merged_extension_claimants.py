#!/usr/bin/env python3
"""Notify newly authorized HOL Guard extension publishers after a merged PR."""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

MARKER = "<!-- hol-extension-claim-notice:v1 -->"
DEFAULT_STUDIO_URL = "https://hol.org/guard/extension-studio"
LISTING_PREFIX = "contributions/extension-listings/"
CONTRIBUTION_PREFIXES = (
    "contributions/extensions/",
    "contributions/mcp-servers/",
)
EXTENSION_ID_RE = re.compile(r"^(?:command|mcp)\.[a-z0-9]+(?:[.-][a-z0-9]+)*$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


class ClaimNoticeError(RuntimeError):
    """Raised when claim-notice provenance cannot be established safely."""


@dataclass(frozen=True)
class NoticeItem:
    extension_id: str
    identities: tuple[tuple[str, str | None], ...]


class GitHubApi:
    """Small GitHub REST client used by the post-merge workflow."""

    def __init__(self, token: str, repo: str) -> None:
        if not token:
            raise ClaimNoticeError("GitHub token is required")
        if not REPO_RE.fullmatch(repo):
            raise ClaimNoticeError("repository must use owner/name form")
        self.token = token
        self.repo = repo
        self.base_url = f"https://api.github.com/repos/{repo}"

    def _request(self, url: str, *, method: str = "GET", payload: Any | None = None) -> Any:
        body = None
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self.token}",
            "User-Agent": "hol-guard-extension-claim-notice/1.0",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(url, headers=headers, method=method, data=body)
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                raw = response.read()
        except urllib.error.HTTPError as error:
            detail = error.read().decode("utf-8", errors="replace")
            raise ClaimNoticeError(f"GitHub API {error.code} for {url}: {detail[:300]}") from error
        except OSError as error:
            raise ClaimNoticeError(f"GitHub API request failed for {url}: {error}") from error
        if not raw:
            return None
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ClaimNoticeError(f"GitHub API returned invalid JSON for {url}") from error

    def repo_metadata(self) -> dict[str, Any]:
        data = self._request(self.base_url)
        if not isinstance(data, dict):
            raise ClaimNoticeError("repository metadata response is invalid")
        return data

    def pull_request(self, number: int) -> dict[str, Any]:
        data = self._request(f"{self.base_url}/pulls/{number}")
        if not isinstance(data, dict):
            raise ClaimNoticeError("pull request response is invalid")
        return data

    def pull_request_files(self, number: int) -> list[dict[str, Any]]:
        files: list[dict[str, Any]] = []
        for page in range(1, 31):
            data = self._request(f"{self.base_url}/pulls/{number}/files?per_page=100&page={page}")
            if not isinstance(data, list):
                raise ClaimNoticeError("pull request files response is invalid")
            files.extend(item for item in data if isinstance(item, dict))
            if len(data) < 100:
                return files
        raise ClaimNoticeError("pull request changes exceed the supported 3000-file bound")

    def commit(self, sha: str) -> dict[str, Any]:
        data = self._request(f"{self.base_url}/commits/{sha}")
        if not isinstance(data, dict):
            raise ClaimNoticeError("commit response is invalid")
        return data

    def compare(self, base: str, head: str) -> dict[str, Any]:
        data = self._request(f"{self.base_url}/compare/{base}...{head}")
        if not isinstance(data, dict):
            raise ClaimNoticeError("compare response is invalid")
        return data

    def file_json(self, path: str, ref: str, *, missing_ok: bool = False) -> dict[str, Any] | None:
        encoded_path = urllib.parse.quote(path, safe="/")
        url = f"{self.base_url}/contents/{encoded_path}?ref={urllib.parse.quote(ref, safe='')}"
        try:
            data = self._request(url)
        except ClaimNoticeError as error:
            if missing_ok and "GitHub API 404" in str(error):
                return None
            raise
        if not isinstance(data, dict) or data.get("encoding") != "base64" or not isinstance(data.get("content"), str):
            raise ClaimNoticeError(f"repository file response is invalid for {path}@{ref}")
        try:
            decoded = base64.b64decode(data["content"], validate=False).decode("utf-8")
            parsed = json.loads(decoded)
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ClaimNoticeError(f"repository file is not valid UTF-8 JSON: {path}@{ref}") from error
        if not isinstance(parsed, dict):
            raise ClaimNoticeError(f"repository file must contain a JSON object: {path}@{ref}")
        return parsed

    def file_exists(self, path: str, ref: str) -> bool:
        return self.file_json(path, ref, missing_ok=True) is not None

    def comments(self, number: int) -> list[dict[str, Any]]:
        comments: list[dict[str, Any]] = []
        for page in range(1, 11):
            data = self._request(f"{self.base_url}/issues/{number}/comments?per_page=100&page={page}")
            if not isinstance(data, list):
                raise ClaimNoticeError("pull request comments response is invalid")
            comments.extend(item for item in data if isinstance(item, dict))
            if len(data) < 100:
                return comments
        raise ClaimNoticeError("pull request comments exceed the supported 1000-comment bound")

    def user_login(self, account_id: str) -> str | None:
        url = f"https://api.github.com/user/{urllib.parse.quote(account_id, safe='')}"
        try:
            data = self._request(url)
        except ClaimNoticeError as error:
            if "GitHub API 404" in str(error):
                return None
            raise
        login = data.get("login") if isinstance(data, dict) else None
        return login if isinstance(login, str) and login else None

    def post_comment(self, number: int, body: str) -> None:
        self._request(f"{self.base_url}/issues/{number}/comments", method="POST", payload={"body": body})


def _extension_id_from_path(path: str, prefix: str) -> str | None:
    if not path.startswith(prefix) or not path.endswith(".json"):
        return None
    name = path[len(prefix) : -5]
    if "/" in name or not EXTENSION_ID_RE.fullmatch(name):
        return None
    return name


def changed_extension_ids(files: list[dict[str, Any]]) -> tuple[set[str], set[str]]:
    """Return contribution-changed and listing-changed extension IDs."""
    contributions: set[str] = set()
    listings: set[str] = set()
    for item in files:
        if item.get("status") == "removed":
            continue
        path = item.get("filename")
        if not isinstance(path, str):
            continue
        listing_id = _extension_id_from_path(path, LISTING_PREFIX)
        if listing_id:
            listings.add(listing_id)
            continue
        for prefix in CONTRIBUTION_PREFIXES:
            contribution_id = _extension_id_from_path(path, prefix)
            if contribution_id:
                contributions.add(contribution_id)
                break
    return contributions, listings


def accepted_github_ids(listing: dict[str, Any], extension_id: str) -> tuple[str, ...]:
    """Read the authority-bearing numeric IDs from a canonical listing sidecar."""
    if listing.get("schemaVersion") != "guard.extension-listing.v1":
        raise ClaimNoticeError(f"{extension_id}: unsupported extension listing schema")
    if listing.get("extensionId") != extension_id:
        raise ClaimNoticeError(f"{extension_id}: listing identity does not match its path")
    values = listing.get("maintainerGithubIds", [])
    if not isinstance(values, list) or len(values) > 8:
        raise ClaimNoticeError(f"{extension_id}: maintainerGithubIds must be an array of at most eight IDs")
    result: list[str] = []
    for value in values:
        if not isinstance(value, str) or not value.isdecimal() or int(value) <= 0:
            raise ClaimNoticeError(f"{extension_id}: maintainerGithubIds contains an invalid numeric GitHub ID")
        if value not in result:
            result.append(value)
    return tuple(result)


def contribution_path(extension_id: str) -> str:
    if extension_id.startswith("command."):
        return f"contributions/extensions/{extension_id}.json"
    if extension_id.startswith("mcp."):
        return f"contributions/mcp-servers/{extension_id}.json"
    raise ClaimNoticeError(f"unsupported extension ID: {extension_id}")


def build_comment(items: list[NoticeItem], studio_url: str) -> str:
    lines = [
        MARKER,
        (
            "The merged extension metadata now authorizes the GitHub account(s) below "
            "to manage publisher profiles in HOL Guard Extension Studio."
        ),
        "",
    ]
    for item in items:
        link = f"{studio_url}?{urllib.parse.urlencode({'extension': item.extension_id})}"
        identities = [f"@{login}" if login else f"GitHub ID `{account_id}`" for account_id, login in item.identities]
        identity_text = ", ".join(identities) if identities else "accepted maintainer identity"
        lines.append(f"- `{item.extension_id}`: {identity_text} · [Open Extension Studio]({link})")
    lines.extend(
        [
            "",
            (
                "Claim verification re-reads canonical `main` and checks the accepted numeric GitHub ID "
                "before granting publisher access. The publisher profile is separate from runtime trust, "
                "activation, or upstream ownership."
            ),
        ]
    )
    return "\n".join(lines)


def _resolve_identities(client: GitHubApi, github_ids: tuple[str, ...]) -> tuple[tuple[str, str | None], ...]:
    return tuple((account_id, client.user_login(account_id)) for account_id in github_ids)


def collect_notice_items(client: GitHubApi, pr_number: int) -> list[NoticeItem]:
    repo = client.repo_metadata()
    default_branch = repo.get("default_branch")
    if not isinstance(default_branch, str) or not default_branch:
        raise ClaimNoticeError("repository default branch is unavailable")

    pr = client.pull_request(pr_number)
    if not pr.get("merged_at"):
        print(f"PR #{pr_number}: not merged; skipping")
        return []
    base = pr.get("base")
    base_ref = base.get("ref") if isinstance(base, dict) else None
    if base_ref != default_branch:
        print(f"PR #{pr_number}: merged into {base_ref!r}, not canonical {default_branch!r}; skipping")
        return []
    merge_sha = pr.get("merge_commit_sha")
    if not isinstance(merge_sha, str) or not SHA_RE.fullmatch(merge_sha):
        raise ClaimNoticeError("merged pull request is missing a canonical merge commit SHA")

    ancestry = client.compare(merge_sha, default_branch).get("status")
    if ancestry not in {"ahead", "identical"}:
        print(f"PR #{pr_number}: merge commit is no longer on canonical {default_branch}; skipping")
        return []

    commit = client.commit(merge_sha)
    parents = commit.get("parents")
    if not isinstance(parents, list) or not parents or not isinstance(parents[0], dict):
        raise ClaimNoticeError("merged commit has no first parent for authority comparison")
    before_sha = parents[0].get("sha")
    if not isinstance(before_sha, str) or not SHA_RE.fullmatch(before_sha):
        raise ClaimNoticeError("merged commit first parent is invalid")

    contribution_changes, listing_changes = changed_extension_ids(client.pull_request_files(pr_number))
    candidates = sorted(contribution_changes | listing_changes)
    if not candidates:
        print(f"PR #{pr_number}: no extension contribution or listing changes; skipping")
        return []

    items: list[NoticeItem] = []
    for extension_id in candidates:
        listing_path = f"{LISTING_PREFIX}{extension_id}.json"
        current_listing = client.file_json(listing_path, merge_sha, missing_ok=True)
        if current_listing is None:
            continue
        current_ids = accepted_github_ids(current_listing, extension_id)
        if not current_ids:
            continue

        native_path = contribution_path(extension_id)
        if not client.file_exists(native_path, merge_sha):
            raise ClaimNoticeError(f"{extension_id}: authority sidecar exists without a canonical native contribution")
        contribution_existed = client.file_exists(native_path, before_sha)

        if not contribution_existed:
            notify_ids = current_ids
        elif extension_id in listing_changes:
            previous_listing = client.file_json(listing_path, before_sha, missing_ok=True)
            previous_ids = accepted_github_ids(previous_listing, extension_id) if previous_listing else ()
            notify_ids = tuple(account_id for account_id in current_ids if account_id not in previous_ids)
        else:
            notify_ids = ()
        if not notify_ids:
            continue

        items.append(
            NoticeItem(
                extension_id=extension_id,
                identities=_resolve_identities(client, notify_ids),
            )
        )
    return items


def process(client: GitHubApi, pr_number: int, studio_url: str, *, dry_run: bool = False) -> int:
    if any(MARKER in str(comment.get("body") or "") for comment in client.comments(pr_number)):
        print(f"PR #{pr_number}: extension claim notice already exists; skipping")
        return 0
    items = collect_notice_items(client, pr_number)
    if not items:
        return 0
    body = build_comment(items, studio_url.rstrip("/"))
    if dry_run:
        print(body)
        return 0
    client.post_comment(pr_number, body)
    print(f"PR #{pr_number}: posted Extension Studio claim notice for {len(items)} extension(s)")
    return 0


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", ""))
    parser.add_argument("--pr-number", type=int, required=True)
    parser.add_argument("--studio-url", default=os.environ.get("GUARD_EXTENSION_STUDIO_URL", DEFAULT_STUDIO_URL))
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN") or ""
    try:
        return process(GitHubApi(token, args.repo), args.pr_number, args.studio_url, dry_run=args.dry_run)
    except ClaimNoticeError as error:
        print(f"extension claim notice failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
