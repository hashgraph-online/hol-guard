from __future__ import annotations

import argparse
from dataclasses import dataclass
from typing import cast

from packaging.version import Version

ALPHA_BRANCH = "refs/heads/feat/guard-policy-v3"


@dataclass(frozen=True)
class AlphaRelease:
    version: str
    git_ref: str


def validate_alpha_release(version_text: str, git_ref: str) -> AlphaRelease:
    if git_ref != ALPHA_BRANCH:
        raise ValueError(f"Alpha releases must run from {ALPHA_BRANCH}")

    version = Version(version_text)
    if (
        version.major != 3
        or version.pre is None
        or version.pre[0] != "a"
        or version.dev is not None
        or version.post is not None
        or version.local is not None
    ):
        raise ValueError("Alpha releases require a public PEP 440 3.x alpha version such as 3.0.0a1")

    return AlphaRelease(version=str(version), git_ref=git_ref)


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate a Guard 3.x alpha release request")
    _ = parser.add_argument("--version", required=True)
    _ = parser.add_argument("--git-ref", required=True)
    args = parser.parse_args()
    version_text = cast(str, args.version)
    git_ref = cast(str, args.git_ref)
    release = validate_alpha_release(version_text, git_ref)
    print(release.version)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
