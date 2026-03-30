"""Helpers for awesome-list and registry submission workflows."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

from .checks.manifest import load_manifest
from .models import GRADE_LABELS, ScanResult

REQUEST_TIMEOUT_SECONDS = 30
SUBMISSION_URL_MARKER_PREFIX = "<!-- codex-plugin-scanner-plugin-url: "
SUBMISSION_URL_MARKER_SUFFIX = " -->"


def _repo_api_path(repo: str) -> str:
    owner, name = repo.split("/", 1)
    return f"{quote(owner, safe='')}/{quote(name, safe='')}"


@dataclass(frozen=True, slots=True)
class SubmissionMetadata:
    """Resolved metadata for a plugin submission issue."""

    plugin_name: str
    plugin_url: str
    description: str
    author: str
    category: str


@dataclass(frozen=True, slots=True)
class SubmissionIssue:
    """A created or reused submission issue."""

    repo: str
    number: int
    url: str
    created: bool


def _submission_url_marker(plugin_url: str) -> str:
    return f"{SUBMISSION_URL_MARKER_PREFIX}{plugin_url}{SUBMISSION_URL_MARKER_SUFFIX}"


def _parse_submission_issue(
    issue: dict[str, object],
    *,
    repo: str,
    created: bool,
) -> SubmissionIssue:
    number = issue.get("number")
    url = issue.get("html_url")
    if not isinstance(number, int) or not isinstance(url, str) or not url:
        raise RuntimeError("GitHub issue response is missing required fields.")
    return SubmissionIssue(
        repo=repo,
        number=number,
        url=url,
        created=created,
    )


def _request_json(
    method: str,
    url: str,
    token: str,
    payload: dict[str, object] | None = None,
) -> dict[str, object] | list[dict[str, object]]:
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    request = Request(url, data=data, method=method)
    request.add_header("Accept", "application/vnd.github+json")
    request.add_header("Authorization", f"Bearer {token}")
    request.add_header("User-Agent", "codex-plugin-scanner")
    if data is not None:
        request.add_header("Content-Type", "application/json")
    with urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
        return json.loads(response.read().decode("utf-8"))


def resolve_submission_metadata(
    plugin_dir: Path,
    result: ScanResult,
    *,
    plugin_name: str | None = None,
    plugin_url: str | None = None,
    description: str | None = None,
    author: str | None = None,
    category: str = "Community Plugins",
    github_repository: str | None = None,
    github_server_url: str = "https://github.com",
) -> SubmissionMetadata:
    """Resolve submission fields from overrides, manifest metadata, and GitHub context."""

    manifest = load_manifest(plugin_dir) or {}
    interface = manifest.get("interface") if isinstance(manifest.get("interface"), dict) else {}
    manifest_author = manifest.get("author") if isinstance(manifest.get("author"), dict) else {}

    resolved_name = (
        (plugin_name or "").strip()
        or str(interface.get("displayName") or "").strip()
        or str(manifest.get("name") or "").strip()
        or (github_repository.split("/")[-1] if github_repository else plugin_dir.name)
    )
    resolved_url = (
        (plugin_url or "").strip()
        or str(manifest.get("repository") or "").strip()
        or str(manifest.get("homepage") or "").strip()
        or (f"{github_server_url.rstrip('/')}/{github_repository}" if github_repository else "")
    )
    resolved_description = (
        (description or "").strip()
        or str(interface.get("shortDescription") or "").strip()
        or str(manifest.get("description") or "").strip()
        or f"{resolved_name} scored {result.score}/100 with codex-plugin-scanner."
    )
    resolved_author = (
        (author or "").strip()
        or str(interface.get("developerName") or "").strip()
        or str(manifest_author.get("name") or "").strip()
        or (github_repository.split("/")[0] if github_repository else "")
    )

    return SubmissionMetadata(
        plugin_name=resolved_name,
        plugin_url=resolved_url,
        description=resolved_description,
        author=resolved_author,
        category=category.strip() or "Community Plugins",
    )


def build_submission_payload(
    metadata: SubmissionMetadata,
    result: ScanResult,
    *,
    source_repository: str,
    source_sha: str = "",
    workflow_url: str = "",
    scanner_version: str = "",
) -> dict[str, object]:
    """Build machine-readable submission metadata for downstream registry automation."""

    return {
        "pluginName": metadata.plugin_name,
        "pluginUrl": metadata.plugin_url,
        "description": metadata.description,
        "author": metadata.author,
        "category": metadata.category,
        "score": result.score,
        "grade": result.grade,
        "gradeLabel": GRADE_LABELS.get(result.grade, "Unknown"),
        "findings": result.severity_counts,
        "sourceRepository": source_repository,
        "sourceSha": source_sha,
        "workflowUrl": workflow_url,
        "scannerVersion": scanner_version,
        "timestamp": result.timestamp,
    }


def build_submission_issue_title(metadata: SubmissionMetadata, prefix: str = "[Plugin]") -> str:
    """Build the awesome-list submission issue title."""

    normalized_prefix = prefix.strip() or "[Plugin]"
    return f"{normalized_prefix} {metadata.plugin_name}".strip()


def build_submission_issue_body(
    metadata: SubmissionMetadata,
    result: ScanResult,
    *,
    payload: dict[str, object],
    workflow_url: str = "",
) -> str:
    """Render a human-readable and machine-readable submission issue body."""

    lines = [
        "## Plugin Submission",
        "",
        _submission_url_marker(metadata.plugin_url),
        "",
        f"- Plugin Name: {metadata.plugin_name}",
        f"- GitHub Repository URL: {metadata.plugin_url}",
        f"- Description: {metadata.description}",
        f"- Author: {metadata.author}",
        f"- Category: {metadata.category}",
        "",
        "## Scanner Verification",
        "",
        f"- Score: {result.score}/100",
        f"- Grade: {result.grade} - {GRADE_LABELS.get(result.grade, 'Unknown')}",
    ]
    if workflow_url:
        lines.append(f"- Workflow Run: {workflow_url}")

    lines += [
        "",
        "## Checklist",
        "",
        "- [x] Plugin has a valid `.codex-plugin/plugin.json` manifest",
        "- [x] Plugin is functional and well-documented",
        "- [x] Repository is public",
        "",
        "## Registry Payload",
        "",
        "```json",
        json.dumps(payload, indent=2),
        "```",
    ]
    return "\n".join(lines)


def find_existing_submission_issue(
    repo: str,
    plugin_url: str,
    token: str,
    *,
    api_base_url: str = "https://api.github.com",
) -> SubmissionIssue | None:
    """Find an existing open submission issue for the same plugin URL."""

    marker = _submission_url_marker(plugin_url)
    query = urlencode(
        {
            "q": f'repo:{repo} is:issue is:open "{marker}" in:body',
            "per_page": "10",
        }
    )
    issues = _request_json(
        "GET",
        f"{api_base_url.rstrip('/')}/search/issues?{query}",
        token,
    )
    if not isinstance(issues, dict):
        return None

    items = issues.get("items")
    if not isinstance(items, list):
        return None

    for issue in items:
        if not isinstance(issue, dict):
            continue
        body = str(issue.get("body") or "")
        if issue.get("pull_request") or marker not in body:
            continue
        return _parse_submission_issue(issue, repo=repo, created=False)
    return None


def create_submission_issue(
    repo: str,
    title: str,
    body: str,
    token: str,
    *,
    labels: tuple[str, ...] = (),
    api_base_url: str = "https://api.github.com",
) -> SubmissionIssue:
    """Create a submission issue, retrying without labels when the label set is invalid."""

    encoded_repo = _repo_api_path(repo)
    issue_url = f"{api_base_url.rstrip('/')}/repos/{encoded_repo}/issues"
    payload: dict[str, object] = {"title": title, "body": body}
    cleaned_labels = [label for label in labels if label.strip()]
    if cleaned_labels:
        payload["labels"] = cleaned_labels

    try:
        issue = _request_json("POST", issue_url, token, payload)
    except HTTPError as error:
        if error.code != 422 or "labels" not in payload:
            raise
        issue = _request_json("POST", issue_url, token, {"title": title, "body": body})

    if not isinstance(issue, dict):
        raise RuntimeError("GitHub issue creation returned an unexpected response.")

    return _parse_submission_issue(issue, repo=repo, created=True)
