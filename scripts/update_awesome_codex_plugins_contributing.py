#!/usr/bin/env python3
"""Refresh scanner release metadata inside awesome-codex-plugins CONTRIBUTING.md."""

from __future__ import annotations

import argparse
import re
from pathlib import Path


STEP2_PATTERN = re.compile(
    r"(### Step 2: Run the scanner locally and check your score\n\n)"
    r".*?"
    r"(\n\n### Step 3: Verify your plugin repo has the required files)",
    re.DOTALL,
)

RUN_LOCAL_PATTERN = re.compile(
    r"(### Run the Scanner Locally\n\n)"
    r".*?"
    r"(\n\n### Required in Your Plugin Repo)",
    re.DOTALL,
)
VERSION_PATTERN = re.compile(r"[0-9A-Za-z][0-9A-Za-z._-]*")


def _build_step2_body(scanner_version: str, scanner_sha256: str) -> str:
    return (
        "The release metadata below is synced automatically from the latest published HOL scanner release.\n\n"
        "```bash\n"
        f'pipx install --force "plugin-scanner=={scanner_version}"\n'
        "plugin-scanner scan . --format text\n"
        "```\n\n"
        f"Expected reviewed wheel SHA256: `{scanner_sha256}`\n\n"
        "If you want to verify the exact wheel before install:\n\n"
        "```bash\n"
        "rm -rf .hol-plugin-scanner-dist\n"
        f'python3 -m pip download --only-binary=:all: --no-deps --dest .hol-plugin-scanner-dist "plugin-scanner=={scanner_version}"\n'
        "python3 -m pip hash .hol-plugin-scanner-dist/*.whl\n"
        "```\n\n"
        "You need a score of **80/130** or higher with **no critical or high severity findings**. Save the output to include in your PR description."
    )


def _build_run_local_body(scanner_version: str, scanner_sha256: str) -> str:
    return (
        "The commands below stay pinned to the same reviewed scanner release used in the submission guide.\n\n"
        "```bash\n"
        "# Install the current reviewed release\n"
        f'pipx install --force "plugin-scanner=={scanner_version}"\n\n'
        "# Scan your plugin\n"
        "plugin-scanner scan . --format text\n\n"
        "# Or lint for quick fixes\n"
        "plugin-scanner lint . --format text\n\n"
        "# Verify install readiness\n"
        "plugin-scanner verify . --format text\n"
        "```\n\n"
        f"Expected reviewed wheel SHA256: `{scanner_sha256}`"
    )


def _replace_once(
    content: str,
    pattern: re.Pattern[str],
    replacement_body: str,
    section_name: str,
) -> str:
    def _replacement(match: re.Match[str]) -> str:
        return f"{match.group(1)}{replacement_body}{match.group(2)}"

    updated, count = pattern.subn(_replacement, content)
    if count != 1:
        raise ValueError(f"Expected exactly 1 occurrence of {section_name} in CONTRIBUTING.md, found {count}")
    return updated


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--path", required=True, type=Path)
    parser.add_argument("--scanner-version", required=True)
    parser.add_argument("--scanner-sha256", required=True)
    return parser


def main() -> int:
    args = _build_parser().parse_args()
    source_path = args.path
    scanner_version = args.scanner_version.strip()
    scanner_sha256 = args.scanner_sha256.strip().lower()

    if not re.fullmatch(VERSION_PATTERN, scanner_version):
        raise ValueError("scanner version must contain only letters, numbers, dots, underscores, or dashes")
    if not re.fullmatch(r"[0-9a-f]{64}", scanner_sha256):
        raise ValueError("scanner sha256 must be a 64-character lowercase hex digest")

    original = source_path.read_text(encoding="utf-8")
    updated = _replace_once(
        original,
        STEP2_PATTERN,
        _build_step2_body(scanner_version, scanner_sha256),
        "Step 2 scanner section",
    )
    updated = _replace_once(
        updated,
        RUN_LOCAL_PATTERN,
        _build_run_local_body(scanner_version, scanner_sha256),
        "Run the Scanner Locally section",
    )

    source_path.write_text(updated, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
