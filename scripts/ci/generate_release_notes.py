#!/usr/bin/env python3
"""Generate Guard GitHub release notes from git history and pull request metadata."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

CONVENTIONAL_PATTERN = re.compile(
    r"^(?P<type>[a-z]+)(?:\((?P<scope>[^)]+)\))?(?P<breaking>!)?:[ ]+"
    r"(?P<description>.+?)(?:[ ]+\(#(?P<pr>\d+)\))?$"
)
PR_SUFFIX_PATTERN = re.compile(r"^(?P<description>.+?)\s+\(#(?P<pr>\d+)\)$")
MERGE_COMMIT_PATTERN = re.compile(r"^Merge pull request #(?P<pr>\d+) from ")
STABLE_TAG_PATTERN = re.compile(r"^v(\d+\.\d+\.\d+)$")
ALPHA_TAG_PATTERN = re.compile(r"^alpha/v(\d+\.\d+\.\d+(?:a|b|rc)\d+)$")
VERSION_PATTERN = re.compile(r"^(\d+)\.(\d+)\.(\d+)(?:(a|b|rc)(\d+))?$")

SECTION_TITLES: dict[str, str] = {
    "feat": "Features",
    "fix": "Fixes",
    "perf": "Performance",
    "refactor": "Refactoring",
    "docs": "Documentation",
    "test": "Tests",
    "ci": "CI & automation",
    "build": "CI & automation",
}
SECTION_ORDER = [
    "feat",
    "fix",
    "perf",
    "refactor",
    "docs",
    "test",
    "ci",
    "internal",
]
BULLETED_SECTIONS = {"feat", "fix"}

MAX_SUMMARY_BULLETS = 3
MAX_BULLET_CHARS = 220
MAX_RENDERED_CHANGES = 80


@dataclass
class Change:
    """One commit landing in the release, enriched with PR metadata when available."""

    sha: str
    subject: str
    author: str
    type: str
    scope: str | None = None
    breaking: bool = False
    description: str = ""
    pr_number: int | None = None
    pr_title: str | None = None
    pr_author: str | None = None
    pr_author_id: int | None = None
    summary_bullets: list[str] = field(default_factory=list)

    @property
    def section(self) -> str:
        if self.type == "build":
            return "ci"
        return self.type if self.type in SECTION_TITLES else "internal"

    @property
    def display_description(self) -> str:
        source = self.pr_title or self.subject
        parsed = parse_subject(source)
        if parsed:
            return parsed["description"]
        title, _ = split_pr_suffix(source)
        return title

    @property
    def contributor(self) -> str:
        return self.pr_author or self.author

    @property
    def is_login_contributor(self) -> bool:
        """Whether the contributor name is a verified GitHub login from PR metadata."""
        return self.pr_author is not None


@dataclass
class PreviousRelease:
    """Resolution of the preceding same-channel release used for links.

    ``published`` means the GitHub releases API confirmed an actual release
    object for ``tag``; ``unpublished`` means the preceding tag has no release
    object (a tag alone is not a release); ``unavailable`` means the lookup
    itself failed. Only ``published`` may render a release URL; the other two
    degrade to an explicitly labelled source comparison.
    """

    status: str
    tag: str | None = None
    url: str | None = None


def parse_subject(subject: str) -> dict | None:
    """Parse a conventional-commit subject like ``feat(extensions): ... (#2761)``."""
    match = CONVENTIONAL_PATTERN.match(subject.strip())
    if not match:
        return None
    parsed = match.groupdict()
    return {
        "type": parsed["type"],
        "scope": parsed["scope"],
        "breaking": bool(parsed["breaking"]),
        "description": parsed["description"],
        "pr": int(parsed["pr"]) if parsed["pr"] else None,
    }


def split_pr_suffix(subject: str) -> tuple[str, int | None]:
    """Split a trailing squash suffix off a nonconventional subject.

    GitHub squash subjects need not follow the conventional-commit format:
    ``Add LDAP authentication (#123)`` still names pull request 123 as its
    evidence. Returns ``(title, pr_number)`` where ``title`` is the subject
    without the suffix, or ``(subject, None)`` when no suffix is present.
    """
    match = PR_SUFFIX_PATTERN.match(subject.strip())
    if not match:
        return subject.strip(), None
    return match.group("description"), int(match.group("pr"))


def version_sort_key(version: str) -> tuple | None:
    """Return a sortable key for ``3.0.70`` / ``3.0.0a290`` style versions.

    Pre-release markers (``a``/``b``/``rc``) sort below the stable release,
    matching PEP 440 ordering for the forms Guard publishes.
    """
    match = VERSION_PATTERN.match(version)
    if not match:
        return None
    major, minor, patch, marker, marker_number = match.groups()
    if marker:
        return (int(major), int(minor), int(patch), marker, int(marker_number))
    return (int(major), int(minor), int(patch), "zz", 0)


def parse_version_tag(tag: str) -> tuple | None:
    """Return a sortable key for ``v3.0.70`` / ``alpha/v3.0.0a290`` style tags."""
    match = STABLE_TAG_PATTERN.match(tag)
    if match:
        return version_sort_key(match.group(1))
    match = ALPHA_TAG_PATTERN.match(tag)
    if match:
        return version_sort_key(match.group(1))
    return None


def channel_tags(tags: Iterable[str], channel: str) -> list[str]:
    pattern = STABLE_TAG_PATTERN if channel == "stable" else ALPHA_TAG_PATTERN
    return [tag for tag in tags if pattern.match(tag)]


def select_previous_tag(tags: Iterable[str], current_version: str, channel: str) -> str | None:
    """Pick the closest same-channel tag strictly below ``current_version``."""
    current = version_sort_key(current_version)
    if current is None:
        return None
    candidates = []
    for tag in channel_tags(tags, channel):
        key = parse_version_tag(tag)
        if key is not None and key < current:
            candidates.append((key, tag))
    return max(candidates)[1] if candidates else None


def resolve_previous_release(repo: str, tag: str) -> "PreviousRelease":
    """Authoritative per-tag lookup via the GitHub CLI.

    One API call, no pagination window: asking about the specific candidate
    tag cannot miss a published predecessor the way a capped listing scan
    can. A tag alone is not a release, so a 404 means the tag has no
    published release object. Any other lookup failure is ``unavailable`` so
    publishing degrades to the labelled source comparison instead of
    aborting.
    """
    try:
        result = subprocess.run(
            ["gh", "api", f"repos/{repo}/releases/tags/{tag}"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return PreviousRelease(status="unavailable")
    if result.returncode != 0:
        stderr = result.stderr or ""
        if "404" in stderr:
            return PreviousRelease(status="unpublished")
        return PreviousRelease(status="unavailable")
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        return PreviousRelease(status="unavailable")
    if (
        isinstance(payload, dict)
        and payload.get("tag_name") == tag
        and payload.get("draft") is not True
    ):
        return PreviousRelease(
            status="published",
            tag=tag,
            url=f"https://github.com/{repo}/releases/tag/{tag}",
        )
    return PreviousRelease(status="unpublished")


def extract_summary_bullets(body: str | None, limit: int = MAX_SUMMARY_BULLETS) -> list[str]:
    """Pull the leading bullets out of a PR body's ``## Summary`` section."""
    if not body:
        return []
    lines = body.splitlines()
    bullets: list[str] = []
    in_summary = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("#"):
            heading = stripped.lstrip("#").strip().lower().rstrip(":")
            in_summary = heading == "summary"
            continue
        if not in_summary:
            continue
        if not stripped:
            if bullets:
                break
            continue
        if stripped.startswith(("-", "*")):
            bullet = stripped.lstrip("-*").strip()
            if len(bullet) > MAX_BULLET_CHARS:
                cut = bullet[: MAX_BULLET_CHARS - 1].rsplit(" ", 1)[0].rstrip(" ,;:-")
                bullet = f"{cut}…"
            bullets.append(bullet)
            if len(bullets) >= limit:
                break
        elif bullets:
            break
    return bullets


def run_git(args: Sequence[str], cwd: str | None = None) -> str:
    result = subprocess.run(
        ["git", *args],
        capture_output=True,
        text=True,
        check=True,
        cwd=cwd,
    )
    return result.stdout


def load_changes(end_ref: str, start_ref: str | None, cwd: str | None = None) -> list[Change]:
    """Read first-parent commits in ``start_ref..end_ref``.

    Following the first-parent chain yields one entry per landed pull request
    (squash commits carry their own subject; true merge commits carry
    ``Merge pull request #N`` and are retitled from the PR metadata later).
    Pure merge machinery such as branch-to-branch merges carries no change and
    is skipped.
    """
    revision = f"{start_ref}..{end_ref}" if start_ref else end_ref
    log = run_git(
        ["log", "--first-parent", "--format=%H%x1f%s%x1f%an", revision],
        cwd=cwd,
    )
    changes: list[Change] = []
    for line in log.splitlines():
        if not line.strip():
            continue
        sha, subject, author = line.split("\x1f", maxsplit=2)
        if subject.startswith("Merge ") and not MERGE_COMMIT_PATTERN.match(subject):
            continue
        changes.append(
            Change(sha=sha, subject=subject, author=author, type="internal", description=subject)
        )
    for change in changes:
        parsed = parse_subject(change.pr_title or change.subject)
        if parsed:
            change.type = parsed["type"]
            change.scope = parsed["scope"]
            change.breaking = parsed["breaking"]
            change.description = parsed["description"]
            if parsed["pr"]:
                change.pr_number = parsed["pr"]
        else:
            merge_match = MERGE_COMMIT_PATTERN.match(change.subject)
            if merge_match:
                change.pr_number = int(merge_match.group("pr"))
            else:
                # Nonconventional squash subject: "Add LDAP authentication (#123)"
                # still carries pull request 123 as its landing evidence.
                title, pr_number = split_pr_suffix(change.subject)
                if pr_number is not None:
                    change.pr_number = pr_number
                    change.description = title
    return changes


def fetch_pull_request(repo: str, number: int) -> dict | None:
    """Best-effort PR lookup via the GitHub CLI; returns None when unavailable."""
    try:
        result = subprocess.run(
            ["gh", "api", f"repos/{repo}/pulls/{number}"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        return None
    user = payload.get("user") or {}
    author_id = user.get("id")
    return {
        "title": payload.get("title"),
        "author": user.get("login"),
        "author_id": int(author_id) if isinstance(author_id, int) else None,
        "body": payload.get("body"),
    }


def enrich_with_pull_requests(changes: list[Change], repo: str) -> None:
    """Replace merge-commit subjects with PR titles and attach PR summaries."""
    seen: dict[int, dict | None] = {}
    for number in sorted({change.pr_number for change in changes if change.pr_number}):
        seen[number] = fetch_pull_request(repo, number)
    for change in changes:
        if change.pr_number is None:
            continue
        payload = seen.get(change.pr_number)
        if not payload:
            continue
        change.pr_title = payload["title"]
        change.pr_author = payload["author"]
        change.pr_author_id = payload.get("author_id")
        change.summary_bullets = extract_summary_bullets(payload["body"])
        parsed = parse_subject(change.pr_title or "")
        if parsed:
            change.type = parsed["type"]
            change.scope = parsed["scope"]
            change.breaking = change.breaking or parsed["breaking"]
            change.description = parsed["description"]
        elif change.pr_title:
            # Nonconventional PR title: keep it as the description, still
            # credited like a conventional entry via the verified PR author.
            title, _ = split_pr_suffix(change.pr_title)
            change.description = title


def human_contributors(changes: Sequence[Change]) -> list[tuple[str, bool]]:
    """Distinct human contributors as ``(name, is_github_login)`` pairs.

    Entries backed by PR metadata are verified logins resolved to numeric
    GitHub account ids, so two logins from the same account (a rename between
    PRs) collapse to one credit. Git display names are a fallback: they are
    deduplicated by exact name only and are never matched to a login, because
    a display name alone is not an identity - guessing one would miscredit a
    different person. Fallback names also never render as @mentions.
    """
    contributors: list[tuple[str, bool]] = []
    seen_login_ids: set[int] = set()
    seen_fallback_names: set[str] = set()
    for change in changes:
        if change.is_login_contributor:
            name = change.pr_author or ""
            if not name or name.endswith("[bot]") or name == "anonymous":
                continue
            if change.pr_author_id is not None:
                if change.pr_author_id in seen_login_ids:
                    continue
                seen_login_ids.add(change.pr_author_id)
            entry = (name, True)
            if entry not in contributors:
                contributors.append(entry)
            continue
        name = change.author
        if not name or name.endswith("[bot]") or name == "anonymous":
            continue
        if name in seen_fallback_names:
            continue
        seen_fallback_names.add(name)
        entry = (name, False)
        if entry not in contributors:
            contributors.append(entry)
    return contributors


def entry_line(change: Change, repo: str) -> str:
    description = change.display_description
    if description and description[0].islower():
        description = description[0].upper() + description[1:]
    breaking = " **(breaking)**" if change.breaking else ""
    if change.pr_number:
        link = f"[#{change.pr_number}](https://github.com/{repo}/pull/{change.pr_number})"
    else:
        link = f"[`{change.sha[:7]}`](https://github.com/{repo}/commit/{change.sha})"
    if change.scope:
        return f"- **{change.scope}**: {description} ({link}){breaking}"
    return f"- {description} ({link}){breaking}"


def render_sections(changes: Sequence[Change], repo: str) -> str:
    blocks: list[str] = []
    for section in SECTION_ORDER:
        entries = [change for change in changes if change.section == section]
        if not entries:
            continue
        lines = [f"## {SECTION_TITLES.get(section, 'Internal')}", ""]
        for change in entries:
            lines.append(entry_line(change, repo))
            if section in BULLETED_SECTIONS:
                for bullet in change.summary_bullets:
                    lines.append(f"  - {bullet}")
        blocks.append("\n".join(lines))
    return "\n\n".join(blocks)


def render_condensed_sections(changes: Sequence[Change], repo: str) -> str:
    """Summarize very large histories (no previous tag) instead of listing every entry.

    GitHub caps release bodies at 125,000 characters; a first-of-channel release
    covering the full project history would exceed that, so render per-section
    counts plus a link into the commit history.
    """
    counts: list[tuple[str, int]] = []
    for section in SECTION_ORDER:
        entries = [change for change in changes if change.section == section]
        if entries:
            counts.append((SECTION_TITLES.get(section, "Internal"), len(entries)))
    lines = ["## Changes by category", ""]
    lines.extend(f"- **{title}**: {count}" for title, count in counts)
    lines.append("")
    lines.append(f"This release spans too many changes to list; browse the [full commit history](https://github.com/{repo}/commits/{changes[0].sha}).")
    return "\n".join(lines)


def render_notes(
    changes: Sequence[Change],
    *,
    version: str,
    channel: str,
    repo: str,
    tag: str,
    previous_tag: str | None,
    source_sha: str,
    previous_release: PreviousRelease | None = None,
) -> str:
    """Render the full release-notes body for one Guard release.

    ``previous_release`` carries the resolved predecessor from the GitHub
    releases API. Only a ``published`` resolution may link a release page; a
    tag without a release object (``unpublished``) or a failed lookup
    (``unavailable``) renders a plain-text tag plus an explicitly labelled
    source comparison instead - never a fabricated release URL. ``None``
    keeps the legacy rendering that treats ``previous_tag`` as published.
    """
    contributors = human_contributors(changes)
    pr_count = len({change.pr_number for change in changes if change.pr_number})
    heading_stats = []
    if changes:
        heading_stats.append(f"{len(changes)} commit{'s' if len(changes) != 1 else ''}")
    if pr_count:
        heading_stats.append(f"{pr_count} merged pull request{'s' if pr_count != 1 else ''}")
    if contributors:
        heading_stats.append(f"{len(contributors)} contributor{'s' if len(contributors) != 1 else ''}")

    short_sha = source_sha[:7]
    lines: list[str] = []
    if channel == "alpha":
        lines.append(
            f"Guard {version} is an opt-in prerelease cut from "
            f"[`{short_sha}`](https://github.com/{repo}/commit/{source_sha}). "
            "Stable installations remain on the stable channel."
        )
    else:
        lines.append(
            f"Guard {version} is a stable release cut from "
            f"[`{short_sha}`](https://github.com/{repo}/commit/{source_sha})."
        )
    published_release = previous_release is None or previous_release.status == "published"
    if previous_tag:
        previous_version = previous_tag.removeprefix("alpha/").lstrip("v")
        if published_release:
            since = f" since [Guard {previous_version}](https://github.com/{repo}/releases/tag/{previous_tag})"
        elif previous_release is not None and previous_release.status == "unavailable":
            since = f" since tag `{previous_tag}` (published release lookup unavailable)"
        else:
            since = f" since tag `{previous_tag}` (previous tag has no published release)"
        lines.append(f"**{' • '.join(heading_stats)}**{since}." if heading_stats else f"Released{since}.")
    elif heading_stats:
        scope_note = (
            " — the first release on this channel, covering the full history to this point"
            if changes
            else ""
        )
        lines.append(f"**{' • '.join(heading_stats)}**{scope_note}.")
    lines.append("")

    if len(changes) > MAX_RENDERED_CHANGES:
        lines.append(render_condensed_sections(changes, repo))
        lines.append("")
    else:
        sections = render_sections(changes, repo)
        if sections:
            lines.append(sections)
            lines.append("")
        else:
            lines.append("This release ships no user-facing changes; it refreshes release artifacts only.")
            lines.append("")

    lines.append("## Install")
    lines.append("")
    lines.append("Install this release:")
    lines.append("")
    lines.append("```bash")
    lines.append(f'uv tool install "hol-guard[cisco]=={version}"')
    lines.append("```")
    lines.append("")
    if previous_tag:
        comparison = (
            f"[{previous_tag}...{tag}]"
            f"(https://github.com/{repo}/compare/{previous_tag}...{tag})"
        )
        if published_release:
            lines.append(f"**Full changelog**: {comparison}")
        elif previous_release is not None and previous_release.status == "unavailable":
            lines.append(
                f"**Source comparison**: {comparison} — the published-release lookup"
                " was unavailable, so this is a source-level comparison, not a"
                " release-to-release changelog."
            )
        else:
            lines.append(
                f"**Source comparison**: {comparison} — the previous tag has no"
                " published release, so this is a source-level comparison, not a"
                " release-to-release changelog."
            )
        lines.append("")
    if contributors:
        credited = [f"@{name}" if is_login else name for name, is_login in contributors]
        lines.append(f"Thanks {', '.join(credited)}!")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True, help="Release version, e.g. 3.0.70")
    parser.add_argument("--channel", required=True, choices=["stable", "alpha"])
    parser.add_argument("--repo", default=None, help="OWNER/REPO, defaults to the origin remote")
    parser.add_argument("--tag", default=None, help="Release tag; defaults from version and channel")
    parser.add_argument("--previous-tag", default=None, help="Previous same-channel tag; auto-detected when omitted")
    parser.add_argument("--source-sha", default=None, help="Release commit; defaults to resolving --tag")
    parser.add_argument("--end-ref", default=None, help="Git ref covering the release commits (default: tag/sha)")
    parser.add_argument("--output", default=None, help="Write notes here instead of stdout")
    parser.add_argument(
        "--skip-pr-metadata",
        action="store_true",
        help="Do not call the GitHub API for PR titles and summaries",
    )
    args = parser.parse_args()

    if args.repo is None:
        origin = run_git(["remote", "get-url", "origin"]).strip()
        match = re.search(r"[:/]([^/:]+)/([^/]+?)(?:\.git)?$", origin)
        if not match:
            print("Unable to derive OWNER/REPO from the origin remote", file=sys.stderr)
            return 1
        repo = f"{match.group(1)}/{match.group(2)}"
    else:
        repo = args.repo

    tag = args.tag or (f"alpha/v{args.version}" if args.channel == "alpha" else f"v{args.version}")
    source_sha = args.source_sha
    if source_sha is None:
        try:
            source_sha = run_git(["rev-parse", "--verify", f"{args.end_ref or tag}^{{commit}}"]).strip()
        except subprocess.CalledProcessError:
            source_sha = ""
    if not source_sha:
        print(f"Unable to resolve release commit for {args.end_ref or tag}", file=sys.stderr)
        return 1

    previous_tag = args.previous_tag
    if previous_tag is None:
        tags = run_git(["tag", "--list"]).split()
        previous_tag = select_previous_tag(tags, args.version, args.channel)

    # A git tag alone is not a release: only link a predecessor that the
    # releases API confirms as an actual published release object on the same
    # channel. Lookup failures fail open to the labelled degraded rendering so
    # website availability never becomes a dependency of software publishing.
    previous_release: PreviousRelease | None = None
    if previous_tag is not None:
        previous_release = resolve_previous_release(repo, previous_tag)

    changes = load_changes(args.end_ref or source_sha, previous_tag)
    if not args.skip_pr_metadata:
        enrich_with_pull_requests(changes, repo)
    notes = render_notes(
        changes,
        version=args.version,
        channel=args.channel,
        repo=repo,
        tag=tag,
        previous_tag=previous_tag,
        source_sha=source_sha,
        previous_release=previous_release,
    )
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(notes)
    else:
        sys.stdout.write(notes)
    return 0


if __name__ == "__main__":
    try:
        exit_code = main()
    except BrokenPipeError:
        exit_code = 0
    raise SystemExit(exit_code)
