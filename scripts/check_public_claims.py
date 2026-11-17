#!/usr/bin/env python3
"""Keep broad protection wording in public HOL Guard copy next to its limits.

Guard protects only the harness events its protection contract names, and the
contract lists the events that fail open, only observe, or have no boundary.
Public copy that calls Guard "antivirus" or claims universal or complete
protection must say so close by, or a reader takes the headline as a promise.

A claim passes when its own paragraph, or one of the next two prose paragraphs
in the same section, links to the protection claims or the support matrix, or
states a limit in plain words ("does not cover", "blind spot", and similar).
Badge rows, HTML comments, and fenced code do not count as prose. The package
description in pyproject.toml has no neighbours, so it must carry the limit in
its own text.

    python scripts/check_public_claims.py          check the repository
    python scripts/check_public_claims.py FILE...  check only these Markdown files
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

CLAIM = re.compile(
    r"\banti-?virus\b"
    r"|\buniversal\s+(?:protection|coverage|prevention|interception|mediation|security)\b"
    r"|\b(?:complete|total|full)\s+(?:protection|coverage)\b"
    r"|\b100\s?%\s+(?:protection|coverage|protected)\b"
    r"|\bprotects?\s+(?:all|every|any)\s+(?:agents?|harness(?:es)?|actions?|tools?)\b",
    re.IGNORECASE,
)
LIMIT = re.compile(
    r"harness-claims(?:\.md|\.v1\.json)?\b"
    r"|harness-support\.md"
    r"|/guard/security/(?:coverage|non-coverage)\b"
    r"|\b(?:do|does)(?:\s+not|n't)\s+(?:cover|claim|protect|stop|see|count|prove)\b"
    r"|\bnot\s+(?:covered|universal)\b"
    r"|\bblind\s+spots?\b"
    r"|\blimitations?\b"
    r"|\bfails?\s+open\b"
    r"|\bobserve(?:-|\s+)only\b",
    re.IGNORECASE,
)
# A negation counts only when it governs the claim: it sits right before the
# claim ("no complete protection"), or negates a verb that takes the claim as
# its object ("does not claim universal protection", "never disable
# antivirus"). "needs no setup for complete protection" and "needs no account
# and provides complete protection" are still claims.
NEGATED_CLAIM = re.compile(
    r"\b(?:(?:not|never|nor)\s+(?:(?:claim|provide|offer|promise|give|guarantee|disable|replace|a|an)s?\s+)?|no\s+)$",
    re.IGNORECASE,
)
# "no blind spots" and "without limitations" deny a limit; they do not state one.
# A sentence ends at terminal punctuation or where a list item, table row,
# or heading starts on a new line. A plain line wrap inside a sentence
# does not end it, so a negation wrapped onto the previous line still counts.
SENTENCE_BOUNDARY = re.compile(r"[.!?]|\n\s*(?:[-*+|#]|\d+[.)])\s")
QUOTE_CONTINUATION = re.compile(r"\n\s*>\s?")
NEGATED_LIMIT = re.compile(r"\b(?:no|without|zero|free\s+of)\s+(?:\w+\s+)?$", re.IGNORECASE)
FOLLOWING_PROSE_BLOCKS = 2

# Public pages that describe what Guard protects. Planning notes, research,
# execution logs, ADRs and audits are working documents, not product claims.
# Agent skill and droid text is copy that agents repeat to users, so it is
# held to the same rule as the README.
PUBLIC_PAGES = (
    "README.md",
    "HOL_GUARD_ANSWERS.md",
    ".factory/skills/hol-guard/SKILL.md",
    ".factory/droids/hol-guard-runner.md",
)
PUBLIC_DOC_DIRECTORY = Path("docs/guard")
WORKING_DOCUMENT = re.compile(r"(?:^|[-_.])(?:prd|todo|research|plan|log|handoff|ledger)(?:[-_.]|$)", re.IGNORECASE)
WORKING_DIRECTORIES = frozenset({"adr", "audits"})


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    claim: str

    def __str__(self) -> str:
        return (
            f"{self.path}:{self.line}: '{self.claim}' needs an adjacent limitation "
            "(link the protection claims or say what Guard does not cover)"
        )


@dataclass(frozen=True)
class Block:
    line: int
    text: str
    heading: int
    prose: bool


_FENCE = re.compile(r"^\s{0,3}(`{3,}|~{3,})(.*)$")
_HTML_COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)
_BADGE_OR_IMAGE = re.compile(r"^\s*(?:\[!\[[^\]]*\]\([^)]*\)\]\([^)]*\)|!\[[^\]]*\]\([^)]*\))\s*$")


def _is_prose(lines: list[str]) -> bool:
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("<!--") or _BADGE_OR_IMAGE.match(stripped):
            continue
        return True
    return False


def _without_comments(text: str) -> str:
    """Blank HTML comments, keeping their newlines so line numbers hold. Readers never see them."""
    return _HTML_COMMENT.sub(lambda match: "\n" * match.group(0).count("\n"), text)


def _heading_level(line: str) -> int:
    stripped = line.lstrip()
    return len(stripped) - len(stripped.lstrip("#"))


def _blocks(text: str) -> list[Block]:
    text = _without_comments(text)
    blocks: list[Block] = []
    current: list[str] = []
    start = 0
    fence = ""

    def flush() -> None:
        if current:
            joined = "\n".join(current)
            heading = _heading_level(current[0])
            blocks.append(Block(start, joined, heading, bool(heading) or _is_prose(current)))
            current.clear()

    for number, line in enumerate(text.splitlines(), start=1):
        opener = _FENCE.match(line)
        if fence:
            # Only a run of the opening character at least as long as the
            # opening fence, with nothing after it, closes the block.
            if (
                opener
                and opener.group(1)[0] == fence[0]
                and len(opener.group(1)) >= len(fence)
                and not opener.group(2).strip()
            ):
                fence = ""
            continue
        if opener and not (opener.group(1)[0] == "`" and "`" in opener.group(2)):
            flush()
            fence = opener.group(1)
            continue
        if not line.strip():
            flush()
            continue
        if line.lstrip().startswith("#"):
            flush()
            start = number
            current.append(line)
            flush()
            continue
        if not current:
            start = number
        current.append(line)
    flush()
    return blocks


def _claims(text: str) -> list[tuple[int, str]]:
    found: list[tuple[int, str]] = []
    for match in CLAIM.finditer(text):
        boundaries = list(SENTENCE_BOUNDARY.finditer(text, 0, match.start()))
        sentence_start = boundaries[-1].end() if boundaries else 0
        # A blockquote repeats its marker on every wrapped line; it continues
        # the sentence, so drop it before looking for a governing negation.
        prefix = QUOTE_CONTINUATION.sub("\n", text[sentence_start : match.start()])
        if NEGATED_CLAIM.search(prefix):
            continue
        found.append((text.count("\n", 0, match.start()), match.group(0)))
    return found


def _states_limit(text: str) -> bool:
    return any(not NEGATED_LIMIT.search(text[: match.start()]) for match in LIMIT.finditer(text))


def check_markdown(path: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    blocks = _blocks(text)
    for index, block in enumerate(blocks):
        claims = _claims(block.text)
        if not claims:
            continue
        # A paragraph's section ends at the next heading. A heading's section
        # runs through its subheadings and ends at a heading of its own level
        # or higher.
        window = [block]
        for following in blocks[index + 1 :]:
            if following.heading and (not block.heading or following.heading <= block.heading):
                break
            if following.heading:
                continue
            if following.prose:
                window.append(following)
            if len(window) > FOLLOWING_PROSE_BLOCKS:
                break
        if any(_states_limit(candidate.text) for candidate in window):
            continue
        findings.extend(Finding(path, block.line + offset, claim) for offset, claim in claims)
    return findings


def _toml_loads(text: str) -> dict[str, object]:
    try:
        import tomllib
    except ModuleNotFoundError:  # Python 3.10
        import tomli as tomllib
    return tomllib.loads(text)


def _description_line(text: str) -> int:
    for number, row in enumerate(text.splitlines(), start=1):
        if re.match(r"\s*description\s*=", row):
            return number
    return 1


def check_package_description(path: str, text: str) -> list[Finding]:
    project = _toml_loads(text).get("project")
    description = project.get("description") if isinstance(project, dict) else None
    if not isinstance(description, str) or _states_limit(description):
        return []
    line = _description_line(text)
    return [Finding(path, line, claim) for _, claim in _claims(description)]


def public_markdown(root: Path) -> list[Path]:
    pages = [root / page for page in PUBLIC_PAGES if (root / page).is_file()]
    base = root / PUBLIC_DOC_DIRECTORY
    pages.extend(
        page
        for page in sorted(base.rglob("*.md"))
        if not WORKING_DOCUMENT.search(page.stem)
        and not WORKING_DIRECTORIES.intersection(page.relative_to(base).parts[:-1])
    )
    return pages


def check_repository(root: Path = REPO_ROOT) -> list[Finding]:
    findings: list[Finding] = []
    for page in public_markdown(root):
        findings.extend(check_markdown(page.relative_to(root).as_posix(), page.read_text(encoding="utf-8")))
    pyproject = root / "pyproject.toml"
    if pyproject.is_file():
        findings.extend(check_package_description("pyproject.toml", pyproject.read_text(encoding="utf-8")))
    return findings


def main(argv: list[str]) -> int:
    if argv:
        findings = [
            finding for name in argv for finding in check_markdown(name, Path(name).read_text(encoding="utf-8"))
        ]
    else:
        findings = check_repository()
    for finding in findings:
        print(finding, file=sys.stderr)
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
