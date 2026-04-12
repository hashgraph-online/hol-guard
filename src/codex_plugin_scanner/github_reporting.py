"""GitHub pull request reporting helpers for repo-side Guard workflows."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit
from urllib.request import Request, urlopen

from .models import GRADE_LABELS, Finding, ScanResult, max_severity

REQUEST_TIMEOUT_SECONDS = 30
PR_COMMENT_MARKER = "<!-- hol-guard-pr-comment -->"
VALID_PR_COMMENT_MODES = frozenset({"auto", "always", "off"})
VALID_PR_COMMENT_STYLES = frozenset({"concise", "detailed"})


@dataclass(frozen=True, slots=True)
class GitHubPrCommentConfig:
    mode: str
    style: str
    max_findings: int


@dataclass(frozen=True, slots=True)
class GitHubPrCommentResult:
    status: str
    comment_id: str = ""
    comment_url: str = ""


def resolve_pr_comment_config(
    *,
    default_mode: str,
    default_style: str,
    default_max_findings: int,
    configured_mode: str | None,
    configured_style: str | None,
    configured_max_findings: int | None,
) -> GitHubPrCommentConfig:
    mode = default_mode if default_mode in VALID_PR_COMMENT_MODES else "auto"
    if default_mode == "auto" and configured_mode in VALID_PR_COMMENT_MODES:
        mode = configured_mode
    style = default_style if default_style in VALID_PR_COMMENT_STYLES else "concise"
    if default_style == "concise" and configured_style in VALID_PR_COMMENT_STYLES:
        style = configured_style
    max_findings = default_max_findings if default_max_findings > 0 else 5
    if default_max_findings == 5 and configured_max_findings is not None and configured_max_findings > 0:
        max_findings = configured_max_findings
    return GitHubPrCommentConfig(mode=mode, style=style, max_findings=max_findings)


def load_pull_request_number(event_path: str) -> int | None:
    try:
        payload = json.loads(Path(event_path).read_text(encoding="utf-8"))
    except OSError:
        return None
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    pull_request = payload.get("pull_request")
    if isinstance(pull_request, dict):
        number = pull_request.get("number")
        if isinstance(number, int):
            return number
    issue = payload.get("issue")
    if isinstance(issue, dict) and isinstance(issue.get("pull_request"), dict):
        number = issue.get("number")
        if isinstance(number, int):
            return number
    return None


def should_manage_pr_comment(
    *,
    mode: str,
    event_name: str,
    pull_request_number: int | None,
) -> bool:
    if mode == "off":
        return False
    if pull_request_number is None:
        return False
    if mode == "always":
        return True
    return event_name in {"pull_request", "pull_request_target"}


def build_scan_pr_comment_body(
    *,
    result: ScanResult,
    profile: str,
    policy_pass: bool,
    style: str,
    max_findings_to_render: int,
) -> str:
    guard_status = "pass" if policy_pass else "blocked"
    severity = max_severity(result.findings)
    severity_label = severity.value if severity is not None else "none"
    grade_label = GRADE_LABELS.get(result.grade, "Unknown")
    lines = [
        PR_COMMENT_MARKER,
        "## Guard repo scan",
        "",
        f"- Verdict: `{guard_status}`",
        f"- Score: `{result.score}/100` ({result.grade} - {grade_label})",
        f"- Policy profile: `{profile}`",
        f"- Max severity: `{severity_label}`",
        f"- Findings: `{sum(result.severity_counts.values())}`",
    ]
    if result.scope == "repository":
        lines.append(f"- Local plugin targets: `{len(result.plugin_results)}`")
        lines.append(f"- Skipped marketplace entries: `{len(result.skipped_targets)}`")
    if style == "detailed":
        findings_to_render = tuple(result.findings[:max_findings_to_render])
        lines.extend(_render_findings_section(findings_to_render, max_findings_to_render, len(result.findings)))
    return "\n".join(lines)


def build_verify_pr_comment_body(
    *,
    verification_payload: dict[str, object],
    style: str,
    max_findings_to_render: int,
) -> str:
    verify_pass = bool(verification_payload.get("verify_pass"))
    status = "pass" if verify_pass else "blocked"
    cases = verification_payload.get("cases", [])
    case_items = cases if isinstance(cases, list) else []
    lines = [
        PR_COMMENT_MARKER,
        "## Guard verification",
        "",
        f"- Verdict: `{status}`",
        f"- Checks: `{len(case_items)}`",
    ]
    if style == "detailed":
        for case in case_items[:max_findings_to_render]:
            if not isinstance(case, dict):
                continue
            component = str(case.get("component") or "unknown")
            name = str(case.get("name") or "unnamed")
            message = str(case.get("message") or "")
            icon = "✅" if bool(case.get("passed")) else "⚠️"
            lines.append(f"- {icon} `{component}` {name}: {message}")
    return "\n".join(lines)


def upsert_pr_comment(
    *,
    repository: str,
    pull_request_number: int,
    token: str,
    api_base_url: str,
    body: str,
) -> GitHubPrCommentResult:
    comments_url = _repo_comments_url(
        api_base_url=api_base_url,
        repository=repository,
        pull_request_number=pull_request_number,
    )
    comments = _list_pr_comments(comments_url, token)
    existing_comment = _find_existing_pr_comment(comments)
    if existing_comment is None:
        created_comment = _request_json("POST", comments_url, token, {"body": body})
        return _parse_comment_result(created_comment, status="created")
    comment_id = existing_comment.get("id")
    existing_body = existing_comment.get("body")
    if isinstance(existing_body, str) and existing_body == body and isinstance(comment_id, int):
        return _parse_comment_result(existing_comment, status="unchanged")
    if not isinstance(comment_id, int):
        raise RuntimeError("GitHub comment response is missing an id.")
    updated_comment = _request_json(
        "PATCH",
        _repo_comment_url(api_base_url=api_base_url, repository=repository, comment_id=comment_id),
        token,
        {"body": body},
    )
    return _parse_comment_result(updated_comment, status="updated")


def _list_pr_comments(
    comments_url: str,
    token: str,
) -> list[dict[str, object]]:
    comments: list[dict[str, object]] = []
    next_url: str | None = _url_with_query_value(comments_url, "per_page", "100")
    while next_url is not None:
        payload, link_header = _request_json_with_headers("GET", next_url, token)
        if not isinstance(payload, list):
            raise RuntimeError("GitHub comment lookup returned an unexpected response.")
        comments.extend(payload)
        next_url = _next_link_url(link_header)
    return comments


def _render_findings_section(
    findings: tuple[Finding, ...],
    max_findings_to_render: int,
    total_findings: int,
) -> list[str]:
    lines = ["", "### Top findings"]
    if not findings:
        lines.append("- No findings.")
        return lines
    for finding in findings:
        location = ""
        if finding.file_path is not None:
            line_suffix = f":{finding.line_number}" if finding.line_number is not None else ""
            location = f" in `{finding.file_path}{line_suffix}`"
        lines.append(f"- `{finding.severity.value}` {finding.title}{location}")
    if total_findings > max_findings_to_render:
        lines.append(f"- …and {total_findings - max_findings_to_render} more.")
    return lines


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
    request.add_header("User-Agent", "hol-guard")
    if data is not None:
        request.add_header("Content-Type", "application/json")
    with urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
        return json.loads(response.read().decode("utf-8"))


def _request_json_with_headers(
    method: str,
    url: str,
    token: str,
    payload: dict[str, object] | None = None,
) -> tuple[dict[str, object] | list[dict[str, object]], str | None]:
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    request = Request(url, data=data, method=method)
    request.add_header("Accept", "application/vnd.github+json")
    request.add_header("Authorization", f"Bearer {token}")
    request.add_header("User-Agent", "hol-guard")
    if data is not None:
        request.add_header("Content-Type", "application/json")
    with urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
        return json.loads(response.read().decode("utf-8")), response.headers.get("Link")


def _find_existing_pr_comment(
    comments: list[dict[str, object]],
) -> dict[str, object] | None:
    for item in comments:
        body = item.get("body")
        if isinstance(body, str) and PR_COMMENT_MARKER in body:
            return item
    return None


def _url_with_query_value(url: str, key: str, value: str) -> str:
    parsed = urlsplit(url)
    query_items = dict(parse_qsl(parsed.query, keep_blank_values=True))
    query_items[key] = value
    return urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            urlencode(query_items),
            parsed.fragment,
        )
    )


def _next_link_url(link_header: str | None) -> str | None:
    if link_header is None or not link_header.strip():
        return None
    for item in link_header.split(","):
        section = item.strip()
        if 'rel="next"' not in section:
            continue
        if not section.startswith("<") or ">" not in section:
            continue
        return section[1 : section.index(">")]
    return None


def _repo_comments_url(
    *,
    api_base_url: str,
    repository: str,
    pull_request_number: int,
) -> str:
    owner, name = repository.split("/", 1)
    encoded_repo = f"{quote(owner, safe='')}/{quote(name, safe='')}"
    return f"{api_base_url.rstrip('/')}/repos/{encoded_repo}/issues/{pull_request_number}/comments"


def _repo_comment_url(
    *,
    api_base_url: str,
    repository: str,
    comment_id: int,
) -> str:
    owner, name = repository.split("/", 1)
    encoded_repo = f"{quote(owner, safe='')}/{quote(name, safe='')}"
    return f"{api_base_url.rstrip('/')}/repos/{encoded_repo}/issues/comments/{comment_id}"


def _parse_comment_result(
    payload: dict[str, object] | list[dict[str, object]],
    *,
    status: str,
) -> GitHubPrCommentResult:
    if not isinstance(payload, dict):
        raise RuntimeError("GitHub comment mutation returned an unexpected response.")
    comment_id = payload.get("id")
    comment_url = payload.get("html_url")
    return GitHubPrCommentResult(
        status=status,
        comment_id=str(comment_id) if isinstance(comment_id, int) else "",
        comment_url=comment_url if isinstance(comment_url, str) else "",
    )
