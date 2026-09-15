#!/usr/bin/env python3
"""Notify newly authorized HOL Guard extension publishers after a merged PR."""

from __future__ import annotations

import argparse
import base64
import ipaddress
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
NOTICE_SOURCE_SURFACE = "github_claim_notice"
PORTAL_READINESS_URL_ENV = "GUARD_EXTENSION_PORTAL_READINESS_URL"
LISTING_PREFIX = "contributions/extension-listings/"
# Typed readiness reasons for the read-only/dry-run readiness artifact. A
# successful or skipped Actions run is not a delivered invitation; every
# non-eligible outcome must carry exactly one of these reasons.
READYNESS_REASONS = frozenset(
    {
        "no_mapping",
        "not_merged",
        "source_not_current",
        "portal_not_ready",
        "already_notified",
        "eligible_for_notice",
        "provider_unavailable",
    }
)
CONTRIBUTION_PREFIXES = (
    "contributions/extensions/",
    "contributions/mcp-servers/",
)
EXTENSION_ID_RE = re.compile(r"^(?:command|mcp)\.[a-z0-9]+(?:[.-][a-z0-9]+)*$")
TAG_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
GITHUB_ID_RE = re.compile(r"^[1-9][0-9]{0,19}$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
TRUSTED_NOTICE_ACTOR_ID = 41898282
MAX_LISTING_BYTES = 16_384
LISTING_REQUIRED_KEYS = frozenset({"schemaVersion", "extensionId", "tagline", "category", "limitations"})
LISTING_ALLOWED_KEYS = LISTING_REQUIRED_KEYS | frozenset({"documentationUrl", "tags", "maintainerGithubIds"})
LISTING_CATEGORIES = frozenset(
    {
        "core-safety",
        "cloud-infrastructure",
        "data-resilience",
        "delivery-remote",
        "managed-services",
        "package-supply-chain",
        "specialized-tools",
        "other",
    }
)


class ClaimNoticeError(RuntimeError):
    """Raised when claim-notice provenance cannot be established safely."""


@dataclass(frozen=True)
class NoticeItem:
    extension_id: str
    identities: tuple[tuple[str, str | None], ...]


@dataclass(frozen=True)
class ExtensionReadiness:
    """Typed per-extension notice readiness for the read-only artifact."""

    extension_id: str
    status: str
    notified_ids: tuple[str, ...] = ()


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


def _extension_change(path: object) -> tuple[str, str] | None:
    if not isinstance(path, str):
        return None
    listing_id = _extension_id_from_path(path, LISTING_PREFIX)
    if listing_id:
        return "listing", listing_id
    for prefix in CONTRIBUTION_PREFIXES:
        contribution_id = _extension_id_from_path(path, prefix)
        if contribution_id:
            return "contribution", contribution_id
    return None


def changed_extension_ids(files: list[dict[str, Any]]) -> tuple[set[str], set[str], set[str]]:
    """Return contribution, listing, and rename-affected extension IDs."""
    contributions: set[str] = set()
    listings: set[str] = set()
    renamed: set[str] = set()
    for item in files:
        status = item.get("status")
        if status == "removed":
            continue
        current = _extension_change(item.get("filename"))
        if current:
            kind, extension_id = current
            (listings if kind == "listing" else contributions).add(extension_id)
        if status != "renamed":
            continue
        for path in (item.get("filename"), item.get("previous_filename")):
            renamed_change = _extension_change(path)
            if renamed_change:
                renamed.add(renamed_change[1])
    return contributions, listings, renamed


def _plain_text(value: object, *, minimum: int, maximum: int, field: str) -> str:
    if (
        not isinstance(value, str)
        or not minimum <= len(value) <= maximum
        or value != value.strip()
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        raise ClaimNoticeError(f"listing {field} does not match the canonical plain-text contract")
    return value


def _public_https(value: object) -> None:
    value = _plain_text(value, minimum=10, maximum=1024, field="documentationUrl")
    try:
        parsed = urllib.parse.urlsplit(value)
        host = parsed.hostname
        if (
            parsed.scheme != "https"
            or not host
            or parsed.username is not None
            or parsed.password is not None
            or parsed.port not in (None, 443)
            or host.lower() in {"localhost", "localhost.localdomain"}
            or host.lower().endswith((".localhost", ".local", ".internal"))
            or "\\" in value
        ):
            raise ValueError("non-public reference")
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if "." not in host or host.endswith("."):
                raise ValueError("non-public host") from None
        else:
            raise ValueError("literal IP")
    except ValueError as error:
        raise ClaimNoticeError("listing documentationUrl must use public HTTPS without credentials") from error


def accepted_github_ids(listing: dict[str, Any], extension_id: str) -> tuple[str, ...]:
    """Validate the complete listing contract, then return its reviewed claimant IDs."""
    keys = frozenset(listing)
    if not keys.issuperset(LISTING_REQUIRED_KEYS) or not keys.issubset(LISTING_ALLOWED_KEYS):
        raise ClaimNoticeError(f"{extension_id}: listing fields do not match the canonical schema")
    if listing.get("schemaVersion") != "guard.extension-listing.v1":
        raise ClaimNoticeError(f"{extension_id}: unsupported extension listing schema")
    listed_id = listing.get("extensionId")
    if (
        listed_id != extension_id
        or not isinstance(listed_id, str)
        or len(listed_id) > 256
        or not EXTENSION_ID_RE.fullmatch(listed_id)
    ):
        raise ClaimNoticeError(f"{extension_id}: listing identity does not match its path")
    _plain_text(listing.get("tagline"), minimum=10, maximum=140, field="tagline")
    if listing.get("category") not in LISTING_CATEGORIES:
        raise ClaimNoticeError(f"{extension_id}: listing category is invalid")

    limitations = listing.get("limitations")
    if not isinstance(limitations, list) or not 1 <= len(limitations) <= 8:
        raise ClaimNoticeError(f"{extension_id}: listing limitations are invalid")
    checked_limitations = [_plain_text(value, minimum=10, maximum=400, field="limitations") for value in limitations]
    if len(set(checked_limitations)) != len(checked_limitations):
        raise ClaimNoticeError(f"{extension_id}: listing limitations must be unique")

    if "documentationUrl" in listing:
        _public_https(listing["documentationUrl"])
    if "tags" in listing:
        tags = listing["tags"]
        if not isinstance(tags, list) or len(tags) > 8:
            raise ClaimNoticeError(f"{extension_id}: listing tags are invalid")
        if any(not isinstance(tag, str) or not 2 <= len(tag) <= 30 or not TAG_RE.fullmatch(tag) for tag in tags):
            raise ClaimNoticeError(f"{extension_id}: listing tags are invalid")
        if len(set(tags)) != len(tags):
            raise ClaimNoticeError(f"{extension_id}: listing tags must be unique")

    values = listing.get("maintainerGithubIds", [])
    if not isinstance(values, list) or len(values) > 8:
        raise ClaimNoticeError(f"{extension_id}: maintainerGithubIds must be an array of at most eight IDs")
    if any(not isinstance(value, str) or not GITHUB_ID_RE.fullmatch(value) for value in values):
        raise ClaimNoticeError(f"{extension_id}: maintainerGithubIds contains an invalid numeric GitHub ID")
    if len(set(values)) != len(values):
        raise ClaimNoticeError(f"{extension_id}: maintainerGithubIds must be unique")

    try:
        encoded = json.dumps(
            listing,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode()
    except (TypeError, ValueError) as error:
        raise ClaimNoticeError(f"{extension_id}: listing cannot be canonically serialized") from error
    if len(encoded) > MAX_LISTING_BYTES:
        raise ClaimNoticeError(f"{extension_id}: listing exceeds the canonical byte budget")
    return tuple(values)


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
        # Canonical claim intent plus allowlisted attribution. The portal parser
        # supports `claim=<id>` and `source_surface=github_claim_notice`; legacy
        # `?extension=<id>` links continue to resolve as manage intents.
        intent = {"claim": item.extension_id, "source_surface": NOTICE_SOURCE_SURFACE}
        link = f"{studio_url}?{urllib.parse.urlencode(intent)}"
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


def has_trusted_notice(comments: list[dict[str, Any]]) -> bool:
    """Return whether the trusted GitHub Actions identity already posted this notice."""
    for comment in comments:
        if MARKER not in str(comment.get("body") or ""):
            continue
        user = comment.get("user")
        if isinstance(user, dict) and user.get("id") == TRUSTED_NOTICE_ACTOR_ID and user.get("type") == "Bot":
            return True
    return False


def _plan_notice_items(
    client: GitHubApi,
    pr_number: int,
    *,
    allow_renames: bool = False,
    records: list[ExtensionReadiness] | None = None,
) -> tuple[list[NoticeItem], str]:
    """Compute candidate notice items and the PR-level readiness status.

    Returns the eligible notice items plus one PR-level typed reason. When
    ``records`` is provided, one typed :class:`ExtensionReadiness` entry is
    appended per considered extension so delayed/backfilled runs can report
    ``no_mapping`` and ``source_not_current`` instead of skipping silently.
    """

    def record(extension_id: str, status: str, ids: tuple[str, ...] = ()) -> None:
        if records is not None:
            records.append(ExtensionReadiness(extension_id=extension_id, status=status, notified_ids=ids))

    repo = client.repo_metadata()
    default_branch = repo.get("default_branch")
    if not isinstance(default_branch, str) or not default_branch:
        raise ClaimNoticeError("repository default branch is unavailable")

    pr = client.pull_request(pr_number)
    if not pr.get("merged_at"):
        print(f"PR #{pr_number}: not merged; skipping")
        return [], "not_merged"
    base = pr.get("base")
    base_ref = base.get("ref") if isinstance(base, dict) else None
    if base_ref != default_branch:
        print(f"PR #{pr_number}: merged into {base_ref!r}, not canonical {default_branch!r}; skipping")
        return [], "not_merged"
    before_sha = base.get("sha") if isinstance(base, dict) else None
    if not isinstance(before_sha, str) or not SHA_RE.fullmatch(before_sha):
        raise ClaimNoticeError("merged pull request is missing its pre-merge base SHA")
    merge_sha = pr.get("merge_commit_sha")
    if not isinstance(merge_sha, str) or not SHA_RE.fullmatch(merge_sha):
        raise ClaimNoticeError("merged pull request is missing a canonical merge commit SHA")

    baseline_relation = client.compare(before_sha, merge_sha).get("status")
    if baseline_relation not in {"ahead", "identical"}:
        raise ClaimNoticeError("pull request base SHA is not an ancestor of the merged source")
    ancestry = client.compare(merge_sha, default_branch).get("status")
    if ancestry not in {"ahead", "identical"}:
        print(f"PR #{pr_number}: merge commit is no longer on canonical {default_branch}; skipping")
        return [], "source_not_current"

    contribution_changes, listing_changes, rename_changes = changed_extension_ids(client.pull_request_files(pr_number))
    candidates = contribution_changes | listing_changes
    if rename_changes and not allow_renames:
        print(f"PR #{pr_number}: rename-affected extensions require explicit maintainer backfill")
        candidates -= rename_changes
    candidates = sorted(candidates)
    if not candidates:
        print(f"PR #{pr_number}: no automatically claimable extension changes; skipping")
        return [], "no_mapping"

    items: list[NoticeItem] = []
    for extension_id in candidates:
        listing_path = f"{LISTING_PREFIX}{extension_id}.json"
        current_listing = client.file_json(listing_path, merge_sha, missing_ok=True)
        if current_listing is None:
            record(extension_id, "no_mapping")
            continue
        merge_ids = accepted_github_ids(current_listing, extension_id)
        if not merge_ids:
            record(extension_id, "no_mapping")
            continue

        native_path = contribution_path(extension_id)
        if not client.file_exists(native_path, merge_sha):
            raise ClaimNoticeError(f"{extension_id}: authority sidecar exists without a canonical native contribution")
        contribution_existed = client.file_exists(native_path, before_sha)

        if not contribution_existed:
            notify_ids = merge_ids
        elif extension_id in listing_changes:
            previous_listing = client.file_json(listing_path, before_sha, missing_ok=True)
            previous_ids = accepted_github_ids(previous_listing, extension_id) if previous_listing else ()
            notify_ids = tuple(account_id for account_id in merge_ids if account_id not in previous_ids)
        else:
            notify_ids = ()
        if not notify_ids:
            record(extension_id, "no_mapping")
            continue

        # Current-authority revalidation for delayed/backfilled notices: an old
        # merged sidecar must not re-invite a since-removed identity. Re-read
        # the canonical listing at the default branch tip and intersect.
        tip_listing = client.file_json(listing_path, default_branch, missing_ok=True)
        if tip_listing is None:
            print(f"PR #{pr_number}: {extension_id}: listing is absent from canonical {default_branch}; skipping")
            record(extension_id, "source_not_current")
            continue
        try:
            tip_ids = accepted_github_ids(tip_listing, extension_id)
        except ClaimNoticeError as error:
            print(f"PR #{pr_number}: {extension_id}: canonical listing is invalid on {default_branch}: {error}")
            record(extension_id, "source_not_current")
            continue
        revalidated = tuple(account_id for account_id in notify_ids if account_id in tip_ids)
        if not revalidated:
            print(
                f"PR #{pr_number}: {extension_id}: no requested identity remains in the current "
                f"accepted set on canonical {default_branch}; skipping"
            )
            record(extension_id, "source_not_current")
            continue
        if revalidated != notify_ids:
            dropped = [account_id for account_id in notify_ids if account_id not in tip_ids]
            print(f"PR #{pr_number}: {extension_id}: identities withdrawn since merge; not invited: {dropped}")
        record(extension_id, "eligible_for_notice", revalidated)
        items.append(
            NoticeItem(
                extension_id=extension_id,
                identities=_resolve_identities(client, revalidated),
            )
        )
    return items, "eligible_for_notice"


def collect_notice_items(client: GitHubApi, pr_number: int, *, allow_renames: bool = False) -> list[NoticeItem]:
    items, _ = _plan_notice_items(client, pr_number, allow_renames=allow_renames)
    return items


def portal_readiness(url: str) -> tuple[str, str]:
    """Check a configurable portal projection endpoint without ever faking ready.

    Returns ``(status, detail)`` where status is ``ok``, ``portal_not_ready``
    (reachable but not affirming readiness) or ``provider_unavailable``
    (unreachable). Never raises for expected portal states.
    """

    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "hol-guard-extension-claim-notice/1.0",
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            raw = response.read(65_536)
            status_code = getattr(response, "status", 200)
    except urllib.error.HTTPError as error:
        if 500 <= error.code <= 599:
            return "provider_unavailable", f"portal returned HTTP {error.code}"
        return "portal_not_ready", f"portal returned HTTP {error.code}"
    except OSError as error:
        return "provider_unavailable", f"portal unreachable: {error}"
    if status_code != 200:
        return "portal_not_ready", f"portal returned HTTP {status_code}"
    try:
        payload = json.loads(raw.decode("utf-8")) if raw else None
    except (UnicodeDecodeError, json.JSONDecodeError):
        return "portal_not_ready", "portal response is not valid JSON"
    if isinstance(payload, dict) and payload.get("ok") is True:
        return "ok", "portal reports ready"
    return "portal_not_ready", "portal did not affirm readiness"


def readiness_report(
    client: GitHubApi,
    pr_number: int,
    *,
    allow_renames: bool = False,
    portal_readiness_url: str | None = None,
) -> dict[str, object]:
    """Build the read-only notice readiness artifact with typed reasons.

    Reports ``no_mapping``, ``not_merged``, ``source_not_current``,
    ``portal_not_ready``, ``already_notified``, ``eligible_for_notice`` and
    ``provider_unavailable`` distinctly. This report never posts and never
    grants authority; a configured portal endpoint that is unreachable keeps
    every entry ``portal_not_ready``/``provider_unavailable`` — never ready.
    """

    entries: list[dict[str, object]] = []
    portal_status = "not_configured"
    portal_detail = "portal readiness endpoint is not configured"
    if portal_readiness_url:
        portal_status, portal_detail = portal_readiness(portal_readiness_url)
    try:
        already = has_trusted_notice(client.comments(pr_number))
        records: list[ExtensionReadiness] = []
        items, pr_reason = _plan_notice_items(client, pr_number, allow_renames=allow_renames, records=records)
    except ClaimNoticeError as error:
        if "GitHub API" in str(error):
            return {
                "schemaVersion": "guard.extension-claim-notice-readiness.v1",
                "pr": pr_number,
                "prStatus": "provider_unavailable",
                "detail": str(error)[:300],
                "entries": [],
            }
        raise
    _ = items
    for item in records:
        status = item.status
        if already:
            status = "already_notified"
        elif portal_status == "provider_unavailable":
            status = "provider_unavailable"
        elif status == "eligible_for_notice" and portal_status != "ok":
            status = "portal_not_ready"
        entries.append(
            {
                "extensionId": item.extension_id,
                "status": status,
                "notifiedIds": list(item.notified_ids),
            }
        )
    # The PR-level status must agree with the per-extension entries: it may
    # only report ``eligible_for_notice`` when at least one entry is eligible
    # and the portal check affirmed readiness (or was never configured for a
    # PR that produced no entries at all).
    if already:
        pr_status = "already_notified"
    elif portal_status == "provider_unavailable":
        pr_status = "provider_unavailable"
    elif entries:
        eligible = any(entry["status"] == "eligible_for_notice" for entry in entries)
        if not eligible:
            statuses = [str(entry["status"]) for entry in entries]
            distinct = sorted(set(statuses))
            pr_status = distinct[0] if len(distinct) == 1 else statuses[0]
        elif portal_status != "ok":
            pr_status = "portal_not_ready"
        else:
            pr_status = "eligible_for_notice"
    else:
        # No extension entries: the PR-level reason from the planner
        # (not_merged / source_not_current / no_mapping) stands on its own.
        pr_status = pr_reason
    return {
        "schemaVersion": "guard.extension-claim-notice-readiness.v1",
        "pr": pr_number,
        "prStatus": pr_status,
        "portalStatus": portal_status,
        "portalDetail": portal_detail,
        "entries": entries,
    }


def process(
    client: GitHubApi,
    pr_number: int,
    studio_url: str,
    *,
    dry_run: bool = False,
    allow_renames: bool = False,
    portal_readiness_url: str | None = None,
    report_only: bool = False,
) -> int:
    if report_only:
        print(
            json.dumps(
                readiness_report(
                    client,
                    pr_number,
                    allow_renames=allow_renames,
                    portal_readiness_url=portal_readiness_url,
                ),
                ensure_ascii=True,
                sort_keys=True,
            )
        )
        return 0
    if has_trusted_notice(client.comments(pr_number)):
        print(f"PR #{pr_number}: trusted extension claim notice already exists; skipping")
        return 0
    if portal_readiness_url:
        portal_status, portal_detail = portal_readiness(portal_readiness_url)
        if portal_status != "ok":
            # Fail closed: an unreachable or lagging portal projection must not
            # produce an invitation that promises an immediately available claim.
            print(f"PR #{pr_number}: portal readiness check failed ({portal_status}: {portal_detail}); skipping")
            return 0
    items = collect_notice_items(client, pr_number, allow_renames=allow_renames)
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
    parser.add_argument("--allow-renames", action="store_true")
    parser.add_argument(
        "--report",
        action="store_true",
        help="Print the read-only typed readiness report as JSON and post nothing.",
    )
    parser.add_argument(
        "--portal-readiness-url",
        default=os.environ.get(PORTAL_READINESS_URL_ENV, ""),
        help=(
            'Optional portal projection endpoint returning JSON {"ok": true}. '
            "Unreachable portals keep the run report portal_not_ready/provider_unavailable."
        ),
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN") or ""
    try:
        return process(
            GitHubApi(token, args.repo),
            args.pr_number,
            args.studio_url,
            dry_run=args.dry_run,
            allow_renames=args.allow_renames,
            portal_readiness_url=args.portal_readiness_url or None,
            report_only=args.report,
        )
    except ClaimNoticeError as error:
        print(f"extension claim notice failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
