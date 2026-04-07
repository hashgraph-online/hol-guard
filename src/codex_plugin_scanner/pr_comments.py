"""Native sticky pull request comments for the scanner GitHub Action."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import Request, urlopen

REQUEST_TIMEOUT_SECONDS = 30
COMMENT_MARKER_PREFIX = "<!-- hol-codex-plugin-scanner:"
COMMENT_MARKER_SUFFIX = " -->"
COMMENT_DATA_PREFIX = "<!-- hol-codex-plugin-scanner-data:"
COMMENT_DATA_SUFFIX = " -->"
SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


@dataclass(frozen=True, slots=True)
class PullRequestContext:
    owner: str
    repo: str
    number: int
    event_name: str
    head_sha: str
    workflow_url: str


@dataclass(frozen=True, slots=True)
class PRCommentConfig:
    mode: str
    style: str
    header: str
    max_findings: int
    token: str
    skip_if_unchanged: bool
    compare_to_previous: bool
    api_base_url: str = "https://api.github.com"


@dataclass(frozen=True, slots=True)
class PRCommentFinding:
    severity: str
    title: str
    file_path: str = ""
    line_number: int | None = None
    remediation: str = ""


@dataclass(frozen=True, slots=True)
class PRCommentCategory:
    name: str
    score: int
    max_score: int


@dataclass(frozen=True, slots=True)
class PRCommentIntegration:
    name: str
    status: str
    message: str


@dataclass(frozen=True, slots=True)
class PRCommentSnapshot:
    mode: str
    profile: str
    plugin_dir: str
    scope: str
    score: int | None
    grade: str
    grade_label: str
    max_severity: str
    findings_total: int | None
    severity_counts: dict[str, int]
    min_score: int | None
    fail_on_severity: str
    score_gate_pass: bool | None
    severity_gate_pass: bool | None
    policy_pass: bool | None
    verify_pass: bool | None
    gate_pass: bool
    gate_reasons: tuple[str, ...]
    top_findings: tuple[PRCommentFinding, ...]
    categories: tuple[PRCommentCategory, ...]
    integrations: tuple[PRCommentIntegration, ...]
    submission_eligible: bool | None
    submission_issues: tuple[str, ...]
    workflow_url: str
    full_report_markdown: str = ""


@dataclass(frozen=True, slots=True)
class PRCommentOutcome:
    status: str
    reason: str = ""
    url: str = ""
    comment_id: int | None = None


@dataclass(frozen=True, slots=True)
class _ExistingComment:
    comment_id: int
    body: str
    url: str
    updated_at: str


def _repo_api_path(owner: str, repo: str) -> str:
    return f"{quote(owner, safe='')}/{quote(repo, safe='')}"


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


def _list_issue_comments(
    *,
    context: PullRequestContext,
    token: str,
    api_base_url: str,
) -> list[_ExistingComment]:
    encoded_repo = _repo_api_path(context.owner, context.repo)
    base_url = api_base_url.rstrip("/")
    comments: list[_ExistingComment] = []
    page = 1
    while True:
        response = _request_json(
            "GET",
            f"{base_url}/repos/{encoded_repo}/issues/{context.number}/comments?per_page=100&page={page}",
            token,
        )
        if not isinstance(response, list) or not response:
            return comments
        for item in response:
            comment_id = item.get("id")
            body = item.get("body")
            url = item.get("html_url")
            updated_at = item.get("updated_at")
            if not isinstance(comment_id, int):
                continue
            if not isinstance(body, str):
                continue
            if not isinstance(url, str) or not url:
                continue
            if not isinstance(updated_at, str):
                updated_at = ""
            comments.append(
                _ExistingComment(
                    comment_id=comment_id,
                    body=body,
                    url=url,
                    updated_at=updated_at,
                )
            )
        if len(response) < 100:
            return comments
        page += 1


def _create_issue_comment(
    *,
    context: PullRequestContext,
    token: str,
    body: str,
    api_base_url: str,
) -> _ExistingComment:
    encoded_repo = _repo_api_path(context.owner, context.repo)
    response = _request_json(
        "POST",
        f"{api_base_url.rstrip('/')}/repos/{encoded_repo}/issues/{context.number}/comments",
        token,
        {"body": body},
    )
    if not isinstance(response, dict):
        raise RuntimeError("GitHub comment response had unexpected shape.")
    comment_id = response.get("id")
    url = response.get("html_url")
    updated_at = response.get("updated_at")
    if not isinstance(comment_id, int) or not isinstance(url, str) or not isinstance(updated_at, str):
        raise RuntimeError("GitHub comment response is missing required fields.")
    return _ExistingComment(comment_id=comment_id, body=body, url=url, updated_at=updated_at)


def _update_issue_comment(
    *,
    context: PullRequestContext,
    token: str,
    comment_id: int,
    body: str,
    api_base_url: str,
) -> _ExistingComment:
    encoded_repo = _repo_api_path(context.owner, context.repo)
    response = _request_json(
        "PATCH",
        f"{api_base_url.rstrip('/')}/repos/{encoded_repo}/issues/comments/{comment_id}",
        token,
        {"body": body},
    )
    if not isinstance(response, dict):
        raise RuntimeError("GitHub comment response had unexpected shape.")
    url = response.get("html_url")
    updated_at = response.get("updated_at")
    if not isinstance(url, str) or not isinstance(updated_at, str):
        raise RuntimeError("GitHub comment response is missing required fields.")
    return _ExistingComment(comment_id=comment_id, body=body, url=url, updated_at=updated_at)


def _extract_pr_number_from_ref(ref: str) -> int | None:
    match = re.match(r"^refs/pull/(\d+)/(?:merge|head)$", ref)
    if match is None:
        return None
    try:
        return int(match.group(1))
    except ValueError:
        return None


def resolve_pr_context(
    *,
    event_name: str,
    event_path: str,
    ref: str,
    repository: str,
    head_sha: str,
    workflow_url: str,
) -> PullRequestContext | None:
    repository = repository.strip()
    if "/" not in repository:
        return None
    owner, repo = repository.split("/", 1)
    pr_number: int | None = None
    if event_path:
        event_file = Path(event_path)
        if event_file.exists():
            try:
                payload = json.loads(event_file.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                payload = None
            if isinstance(payload, dict):
                pull_request = payload.get("pull_request")
                if isinstance(pull_request, dict):
                    number = pull_request.get("number")
                    if isinstance(number, int):
                        pr_number = number
                    head = pull_request.get("head")
                    if isinstance(head, dict):
                        sha = head.get("sha")
                        if isinstance(sha, str) and sha:
                            head_sha = sha
    if pr_number is None:
        pr_number = _extract_pr_number_from_ref(ref)
    if pr_number is None:
        return None
    return PullRequestContext(
        owner=owner,
        repo=repo,
        number=pr_number,
        event_name=event_name,
        head_sha=head_sha,
        workflow_url=workflow_url,
    )


def compute_comment_header(*, mode: str, profile: str, plugin_dir: str, configured_header: str) -> str:
    header = configured_header.strip()
    if header:
        return header
    digest = hashlib.sha256(f"{mode}|{profile}|{plugin_dir}".encode()).hexdigest()[:12]
    return f"mode={mode};profile={profile};target={digest}"


def _comment_marker(header: str) -> str:
    return f"{COMMENT_MARKER_PREFIX}{header}{COMMENT_MARKER_SUFFIX}"


def _encode_metadata(snapshot: PRCommentSnapshot) -> str:
    metadata = {
        "score": snapshot.score,
        "findings_total": snapshot.findings_total,
        "severity_counts": snapshot.severity_counts,
        "policy_pass": snapshot.policy_pass,
        "verify_pass": snapshot.verify_pass,
        "max_severity": snapshot.max_severity,
    }
    encoded = base64.urlsafe_b64encode(json.dumps(metadata, separators=(",", ":")).encode("utf-8"))
    return encoded.decode("utf-8").rstrip("=")


def _decode_metadata(body: str) -> dict[str, object] | None:
    match = re.search(
        re.escape(COMMENT_DATA_PREFIX) + r"([A-Za-z0-9_-]+)" + re.escape(COMMENT_DATA_SUFFIX),
        body,
    )
    if match is None:
        return None
    encoded = match.group(1)
    padded = encoded + "=" * ((4 - (len(encoded) % 4)) % 4)
    try:
        decoded = base64.urlsafe_b64decode(padded.encode("utf-8"))
        payload = json.loads(decoded.decode("utf-8"))
    except (ValueError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _normalize_body(body: str) -> str:
    return "\n".join(line.rstrip() for line in body.strip().splitlines())


def _bool_label(value: bool | None) -> str:
    if value is None:
        return "n/a"
    return "yes" if value else "no"


def _gate_label(*, passed: bool | None, descriptor: str) -> str:
    if passed is None:
        return "n/a"
    return f"{descriptor} {'✅' if passed else '❌'}"


def _severity_breakdown(severity_counts: dict[str, int]) -> str:
    parts = [f"{severity}: {severity_counts.get(severity, 0)}" for severity in SEVERITY_ORDER]
    return ", ".join(parts)


def _truncate(text: str, limit: int = 240) -> str:
    normalized = " ".join(text.split())
    if len(normalized) <= limit:
        return normalized
    return f"{normalized[: limit - 1]}…"


def _format_path(file_path: str, line_number: int | None) -> str:
    if not file_path:
        return ""
    if line_number is None:
        return file_path
    return f"{file_path}:{line_number}"


def _format_top_findings(snapshot: PRCommentSnapshot, *, max_findings: int) -> list[str]:
    findings = list(snapshot.top_findings)[: max(max_findings, 0)]
    if not findings:
        return ["- No actionable findings."]
    lines: list[str] = []
    for finding in findings:
        location = _format_path(finding.file_path, finding.line_number)
        location_suffix = f" ({location})" if location else ""
        remediation = _truncate(finding.remediation) if finding.remediation else "Review scanner output details."
        lines.append(f"- **{finding.severity.upper()}** {finding.title}{location_suffix}")
        lines.append(f"  - {_truncate(remediation)}")
    return lines


def _format_categories(snapshot: PRCommentSnapshot, *, style: str) -> list[str]:
    if not snapshot.categories:
        return ["- No category details captured for this mode."]
    order = {
        "Manifest Validation": 0,
        "Security": 1,
        "Operational Security": 2,
        "Best Practices": 3,
        "Marketplace": 4,
        "Skill Security": 5,
        "Code Quality": 6,
    }
    categories = sorted(snapshot.categories, key=lambda category: order.get(category.name, 99))
    lines: list[str] = []
    for category in categories:
        if category.max_score == 0 and style == "concise":
            continue
        if category.max_score == 0:
            lines.append(f"- {category.name}: n/a")
            continue
        lines.append(f"- {category.name}: {category.score}/{category.max_score}")
    return lines or ["- No scored categories for this run."]


def _format_integrations(snapshot: PRCommentSnapshot) -> list[str]:
    if not snapshot.integrations:
        return ["- No optional integrations were active."]
    return [f"- {item.name}: `{item.status}` - {item.message}" for item in snapshot.integrations]


def _parse_previous_bool(value: object) -> bool | None:
    if isinstance(value, bool):
        return value
    return None


def _parse_previous_int(value: object) -> int | None:
    if isinstance(value, int):
        return value
    return None


def _parse_previous_severity_counts(value: object) -> dict[str, int]:
    if not isinstance(value, dict):
        return {}
    parsed: dict[str, int] = {}
    for key, raw in value.items():
        if not isinstance(key, str):
            continue
        if isinstance(raw, int):
            parsed[key] = raw
    return parsed


def _build_delta_line(previous: dict[str, object] | None, snapshot: PRCommentSnapshot) -> str:
    if previous is None:
        return "Compared with the previous scan on this PR: no prior scanner comment metadata was found."
    delta_parts: list[str] = []
    previous_score = _parse_previous_int(previous.get("score"))
    if snapshot.score is not None and previous_score is not None:
        score_delta = snapshot.score - previous_score
        delta_parts.append(f"score {'+' if score_delta >= 0 else ''}{score_delta}")
    previous_findings_total = _parse_previous_int(previous.get("findings_total"))
    if snapshot.findings_total is not None and previous_findings_total is not None:
        findings_delta = snapshot.findings_total - previous_findings_total
        delta_parts.append(f"findings {'+' if findings_delta >= 0 else ''}{findings_delta}")
    previous_counts = _parse_previous_severity_counts(previous.get("severity_counts"))
    for severity in SEVERITY_ORDER:
        if severity not in snapshot.severity_counts and severity not in previous_counts:
            continue
        delta = snapshot.severity_counts.get(severity, 0) - previous_counts.get(severity, 0)
        if delta != 0:
            delta_parts.append(f"{severity} {'+' if delta >= 0 else ''}{delta}")
    previous_policy = _parse_previous_bool(previous.get("policy_pass"))
    if snapshot.policy_pass is not None and previous_policy is not None:
        policy_state = "changed" if snapshot.policy_pass != previous_policy else "unchanged"
        delta_parts.append(f"policy {policy_state}")
    previous_verify = _parse_previous_bool(previous.get("verify_pass"))
    if snapshot.verify_pass is not None and previous_verify is not None:
        verify_state = "changed" if snapshot.verify_pass != previous_verify else "unchanged"
        delta_parts.append(f"verify {verify_state}")
    if not delta_parts:
        return "Compared with the previous scan on this PR: no measurable metric changes."
    return f"Compared with the previous scan on this PR: {', '.join(delta_parts)}."


def _render_pr_comment(
    *,
    marker: str,
    snapshot: PRCommentSnapshot,
    style: str,
    max_findings: int,
    compare_to_previous: bool,
    previous_metadata: dict[str, object] | None,
) -> str:
    verdict = "✅ Passed" if snapshot.gate_pass else "❌ Gate failed"
    min_score_value = "n/a" if snapshot.min_score is None else str(snapshot.min_score)
    score_gate_descriptor = f"min_score={min_score_value}"
    severity_gate_value = snapshot.fail_on_severity or "none"
    severity_gate_descriptor = f"fail_on_severity={severity_gate_value}"
    lines = [
        f"## HOL Codex Plugin Scanner · {verdict}",
        "",
        "_Checks run: manifest, security posture, operational security, marketplace integrity, "
        "skill safety, and code quality._",
        "",
        "| Metric | Value |",
        "| --- | --- |",
        f"| Mode | `{snapshot.mode}` |",
        f"| Profile | `{snapshot.profile}` |",
        f"| Scope | `{snapshot.scope}` |",
    ]
    if snapshot.score is not None:
        lines.append(f"| Score | `{snapshot.score}/100` |")
    if snapshot.grade:
        lines.append(f"| Grade | `{snapshot.grade}` ({snapshot.grade_label}) |")
    lines += [
        f"| Highest severity | `{snapshot.max_severity}` |",
        f"| Findings | `{snapshot.findings_total if snapshot.findings_total is not None else 'n/a'}` |",
        f"| Severity breakdown | `{_severity_breakdown(snapshot.severity_counts)}` |",
        f"| Score gate | `{_gate_label(passed=snapshot.score_gate_pass, descriptor=score_gate_descriptor)}` |",
        f"| Severity gate | `{_gate_label(passed=snapshot.severity_gate_pass, descriptor=severity_gate_descriptor)}` |",
        f"| Policy pass | `{_bool_label(snapshot.policy_pass)}` |",
        f"| Verify pass | `{_bool_label(snapshot.verify_pass)}` |",
    ]
    if snapshot.submission_eligible is not None:
        lines.append(f"| Submission eligible | `{_bool_label(snapshot.submission_eligible)}` |")

    if snapshot.gate_reasons:
        lines += ["", "**Blocking reasons**", ""]
        lines.extend(f"- {reason}" for reason in snapshot.gate_reasons)

    if compare_to_previous:
        lines += ["", _build_delta_line(previous_metadata, snapshot), ""]

    lines += ["**Top findings**", ""]
    lines.extend(_format_top_findings(snapshot, max_findings=max_findings))

    lines += ["", "<details>", "<summary>Category breakdown</summary>", ""]
    lines.extend(_format_categories(snapshot, style=style))
    lines += ["", "</details>", "", "<details>", "<summary>Integration and submission status</summary>", ""]
    lines.extend(_format_integrations(snapshot))
    if snapshot.submission_issues:
        lines += ["", f"- Submission issues: {', '.join(snapshot.submission_issues)}"]
    if snapshot.workflow_url:
        lines += ["", f"- Workflow run: {snapshot.workflow_url}"]
    lines += ["", "</details>"]

    if style == "full":
        lines += ["", f"- Plugin target: `{snapshot.plugin_dir}`"]
        if snapshot.verify_pass is False:
            lines += ["- Runtime verification reported at least one failing case."]
        if snapshot.full_report_markdown:
            lines += [
                "",
                "<details>",
                "<summary>Full scanner report</summary>",
                "",
                snapshot.full_report_markdown,
                "",
                "</details>",
            ]

    lines += [
        "",
        marker,
        f"{COMMENT_DATA_PREFIX}{_encode_metadata(snapshot)}{COMMENT_DATA_SUFFIX}",
    ]
    return "\n".join(lines)


def _find_existing_marker_comment(comments: list[_ExistingComment], marker: str) -> _ExistingComment | None:
    matching = [comment for comment in comments if marker in comment.body]
    if not matching:
        return None
    matching.sort(key=lambda item: (item.updated_at, item.comment_id))
    return matching[-1]


def publish_pr_comment(
    *,
    config: PRCommentConfig,
    snapshot: PRCommentSnapshot,
    event_name: str,
    event_path: str,
    ref: str,
    repository: str,
    head_sha: str,
) -> PRCommentOutcome:
    if config.mode == "off":
        return PRCommentOutcome(status="disabled")

    context = resolve_pr_context(
        event_name=event_name,
        event_path=event_path,
        ref=ref,
        repository=repository,
        head_sha=head_sha,
        workflow_url=snapshot.workflow_url,
    )
    if context is None:
        if config.mode == "always":
            return PRCommentOutcome(
                status="failed",
                reason="pr-comment is required, but this run is not associated with a pull request",
            )
        return PRCommentOutcome(status="skipped", reason="not a pull request event")

    if not config.token:
        if config.mode == "always":
            return PRCommentOutcome(status="failed", reason="pr-comment is required, but no comment token was provided")
        return PRCommentOutcome(status="skipped", reason="no comment token provided")

    try:
        header = compute_comment_header(
            mode=snapshot.mode,
            profile=snapshot.profile,
            plugin_dir=snapshot.plugin_dir,
            configured_header=config.header,
        )
        marker = _comment_marker(header)
        comments = _list_issue_comments(context=context, token=config.token, api_base_url=config.api_base_url)
        existing = _find_existing_marker_comment(comments, marker)
        previous_metadata = _decode_metadata(existing.body) if existing is not None else None
        body = _render_pr_comment(
            marker=marker,
            snapshot=snapshot,
            style=config.style,
            max_findings=config.max_findings,
            compare_to_previous=config.compare_to_previous,
            previous_metadata=previous_metadata,
        )
        should_skip = (
            existing is not None
            and config.skip_if_unchanged
            and _normalize_body(existing.body) == _normalize_body(body)
        )
        if should_skip:
            return PRCommentOutcome(
                status="unchanged",
                reason="comment body unchanged",
                url=existing.url,
                comment_id=existing.comment_id,
            )
        if existing is None:
            created = _create_issue_comment(
                context=context,
                token=config.token,
                body=body,
                api_base_url=config.api_base_url,
            )
            return PRCommentOutcome(status="created", url=created.url, comment_id=created.comment_id)
        updated = _update_issue_comment(
            context=context,
            token=config.token,
            comment_id=existing.comment_id,
            body=body,
            api_base_url=config.api_base_url,
        )
        return PRCommentOutcome(status="updated", url=updated.url, comment_id=updated.comment_id)
    except HTTPError as error:
        reason = f"GitHub API {error.code} while writing PR comment"
    except OSError as error:
        reason = f"network error while writing PR comment: {error}"
    except RuntimeError as error:
        reason = str(error)
    if config.mode == "always":
        return PRCommentOutcome(status="failed", reason=reason)
    return PRCommentOutcome(status="skipped", reason=reason)
