"""Reject broad protection claims that carry no stated limit.

HOL Guard sees only the events a supported agent sends through its hooks, so
"antivirus" and "universal" wording overstates it unless the same passage says
where that coverage ends. This check reads the public claim surfaces (README,
answers page, install and coverage docs, agent skill text) and fails when such
a word appears in a paragraph, table row or list item with no explicit limit
beside it. A heading is bounded by the opening text of its own section.

Technical uses such as a "universal wheel" are not protection claims and are
skipped.

    python3 scripts/ci/public_claims_lint.py --root .
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path

# Files where Guard describes its own protection to users. A listed file that
# disappears fails the check, so a rename cannot silently drop it from scope.
PUBLIC_CLAIM_FILES = (
    "README.md",
    "HOL_GUARD_ANSWERS.md",
    "docs/guard/get-started.md",
    "docs/guard/harness-support.md",
    "docs/guard/harness-version-coverage.md",
    "docs/guard/windows-platform-coverage.md",
    "docs/guard/local-vs-cloud.md",
    ".factory/skills/hol-guard/SKILL.md",
    ".factory/droids/hol-guard-runner.md",
)
PUBLIC_CLAIM_GLOBS = ("docs/guard/*-coverage.md",)

CLAIM = re.compile(r"\b(anti-?virus|universal(?:ly)?)\b", re.IGNORECASE)
# Packaging terms that share a claim word but describe a file, not protection.
TECHNICAL = re.compile(r"\buniversal(?:2| wheel)\b|py3-none-any", re.IGNORECASE)
LIMIT = re.compile(
    r"\b(?:does not|do not|doesn't|don't|cannot|not|only|limit(?:s|ed|ation|ations)?|unsupported"
    r"|fail(?:s)? open|observe(?:d|s)?|support matrix)\b|harness-support\.md",
    re.IGNORECASE,
)
# A heading's own section is read this far for its limit.
HEADING_WINDOW_LINES = 40


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    text: str

    def render(self) -> str:
        return (
            f"{self.path}:{self.line}: protection claim without an adjacent limit: {self.text.strip()[:120]!r}. "
            "Say where coverage ends in the same passage, or link the support matrix."
        )


def _claims(line: str) -> bool:
    return CLAIM.search(TECHNICAL.sub("", line)) is not None


def _block(lines: list[str], index: int) -> str:
    """The passage a line belongs to: its table row or list item, else its paragraph."""

    line = lines[index]
    stripped = line.lstrip()
    if stripped.startswith("|") or stripped.startswith(("- ", "* ")) or re.match(r"\d+\. ", stripped):
        return line
    start = index
    while start > 0 and lines[start - 1].strip() and not lines[start - 1].lstrip().startswith("#"):
        start -= 1
    end = index
    while end + 1 < len(lines) and lines[end + 1].strip() and not lines[end + 1].lstrip().startswith("#"):
        end += 1
    return "\n".join(lines[start : end + 1])


def _section(lines: list[str], index: int) -> str:
    """A heading's own section, up to the next heading or the window's end."""

    body: list[str] = []
    for line in lines[index + 1 : index + 1 + HEADING_WINDOW_LINES]:
        if line.lstrip().startswith("#"):
            break
        body.append(line)
    return "\n".join(body)


def check_text(path: str, text: str) -> list[Finding]:
    lines = text.splitlines()
    findings: list[Finding] = []
    fenced = False
    for index, line in enumerate(lines):
        if line.lstrip().startswith("```"):
            fenced = not fenced
            continue
        if fenced or not _claims(line):
            continue
        heading = line.lstrip().startswith("#")
        passage = _section(lines, index) if heading else _block(lines, index)
        if LIMIT.search(TECHNICAL.sub("", passage)) is None:
            findings.append(Finding(path, index + 1, line))
    return findings


def claim_files(root: Path) -> tuple[list[Path], list[str]]:
    missing = [name for name in PUBLIC_CLAIM_FILES if not (root / name).is_file()]
    files = {root / name for name in PUBLIC_CLAIM_FILES if (root / name).is_file()}
    for pattern in PUBLIC_CLAIM_GLOBS:
        files.update(path for path in root.glob(pattern) if path.is_file())
    return sorted(files), missing


def run(root: Path) -> list[str]:
    files, missing = claim_files(root)
    problems = [f"{name}: listed public claim file is missing; update PUBLIC_CLAIM_FILES" for name in missing]
    for path in files:
        relative = path.relative_to(root).as_posix()
        problems.extend(finding.render() for finding in check_text(relative, path.read_text(encoding="utf-8")))
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=Path("."))
    args = parser.parse_args(argv)
    problems = run(args.root.resolve())
    for problem in problems:
        print(problem, file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
