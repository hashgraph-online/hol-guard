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
    r"|\buniversal (?:protection|coverage|prevention|interception|mediation|security)\b"
    r"|\b(?:complete|total|full) (?:protection|coverage)\b"
    r"|\b100\s?% (?:protection|coverage|protected)\b"
    r"|\bprotects? (?:all|every|any) (?:agents?|harness(?:es)?|actions?|tools?)\b",
    re.IGNORECASE,
)
LIMIT = re.compile(
    r"harness-claims(?:\.md|\.v1\.json)?\b"
    r"|harness-support\.md"
    r"|/guard/security/(?:coverage|non-coverage)\b"
    r"|\b(?:do|does)(?: not|n't) (?:cover|claim|protect|stop|see|count|prove)\b"
    r"|\bnot (?:covered|universal)\b"
    r"|\bblind spots?\b"
    r"|\blimitations?\b"
    r"|\bfails? open\b"
    r"|\bobserve[- ]only\b",
    re.IGNORECASE,
)
NEGATED_CLAIM = re.compile(
    r"\b(?:not|no|never|without|nor)\b[^.]{0,60}$",
    re.IGNORECASE,
)
FOLLOWING_PROSE_BLOCKS = 2

# Public pages that describe what Guard protects. Planning notes, research,
# execution logs and ADRs are working documents, not product claims.
PUBLIC_PAGES = ("README.md",)
PUBLIC_DOC_DIRECTORY = Path("docs/guard")
WORKING_DOCUMENT = re.compile(r"(?:prd|todo|research|plan|log|handoff|ledger)(?:[-_.]|$)", re.IGNORECASE)


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
    heading: bool
    prose: bool


_BADGE_OR_IMAGE = re.compile(r"^\s*(?:\[!\[[^\]]*\]\([^)]*\)\]\([^)]*\)|!\[[^\]]*\]\([^)]*\))\s*$")


def _is_prose(lines: list[str]) -> bool:
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("<!--") or _BADGE_OR_IMAGE.match(stripped):
            continue
        return True
    return False


def _blocks(text: str) -> list[Block]:
    blocks: list[Block] = []
    current: list[str] = []
    start = 0
    fenced = False

    def flush() -> None:
        if current:
            joined = "\n".join(current)
            heading = current[0].lstrip().startswith("#")
            blocks.append(Block(start, joined, heading, heading or _is_prose(current)))
            current.clear()

    for number, line in enumerate(text.splitlines(), start=1):
        if line.lstrip().startswith(("```", "~~~")):
            flush()
            fenced = not fenced
            continue
        if fenced:
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
        sentence_start = max(text.rfind(".", 0, match.start()), text.rfind("\n", 0, match.start()))
        if NEGATED_CLAIM.search(text[sentence_start + 1 : match.start()]):
            continue
        found.append((text.count("\n", 0, match.start()), match.group(0)))
    return found


def check_markdown(path: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    blocks = _blocks(text)
    for index, block in enumerate(blocks):
        claims = _claims(block.text)
        if not claims:
            continue
        window = [block]
        for following in blocks[index + 1 :]:
            if following.heading and not block.heading:
                break
            if following.heading:
                continue
            if following.prose:
                window.append(following)
            if len(window) > FOLLOWING_PROSE_BLOCKS:
                break
        if any(LIMIT.search(candidate.text) for candidate in window):
            continue
        findings.extend(Finding(path, block.line + offset, claim) for offset, claim in claims)
    return findings


_DESCRIPTION = re.compile(r'^description\s*=\s*"((?:[^"\\]|\\.)*)"\s*$')


def check_package_description(path: str, text: str) -> list[Finding]:
    for number, row in enumerate(text.splitlines(), start=1):
        match = _DESCRIPTION.match(row)
        if not match:
            continue
        description = match.group(1)
        if LIMIT.search(description):
            return []
        return [Finding(path, number, claim) for _, claim in _claims(description)]
    return []


def public_markdown(root: Path) -> list[Path]:
    pages = [root / page for page in PUBLIC_PAGES if (root / page).is_file()]
    pages.extend(
        page for page in sorted((root / PUBLIC_DOC_DIRECTORY).glob("*.md")) if not WORKING_DOCUMENT.search(page.stem)
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
