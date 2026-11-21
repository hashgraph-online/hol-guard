"""Bind live qualification to a Git source tree and the exact installed build."""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from typing import Any

SHA = re.compile(r"[0-9a-f]{40}")


def source_identity(repo: Path, candidate_sha: str | None = None) -> dict[str, Any]:
    """Accept a candidate itself or its two-parent GitHub test merge, never a loose ancestor."""

    # The requested checkout owns identity, not a wrapper's Git location or
    # injected configuration. Keep loader/platform variables for the real CLI.
    environment = {key: value for key, value in os.environ.items() if not key.upper().startswith("GIT_")}
    environment.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)

    def git(*args: str) -> str:
        """Run Git in the selected checkout with inherited Git overrides removed."""
        return subprocess.check_output(["git", *args], cwd=repo, env=environment, text=True, timeout=15).strip()

    source = git("rev-parse", "HEAD")
    candidate = candidate_sha or source
    if SHA.fullmatch(source) is None or SHA.fullmatch(candidate) is None:
        raise ValueError("source and candidate identities must be full Git commits")
    # cat-file reads actual commit headers even in a shallow checkout; rev-list
    # may hide parents at the shallow boundary.
    headers = git("cat-file", "-p", source).split("\n\n", 1)[0].splitlines()
    parents = [line.removeprefix("parent ") for line in headers if line.startswith("parent ")]
    if candidate != source and (len(parents) != 2 or candidate not in parents):
        raise ValueError("installed-source checkout is not the requested candidate or its exact test merge")
    status = git("status", "--porcelain", "--untracked-files=all")
    return {
        "candidate_sha": candidate,
        "tested_source_sha": source,
        "source_parents": parents,
        "tested_base_sha": next((p for p in parents if p != candidate), None) if candidate != source else None,
        "source_dirty": bool(status),
    }


def validate_identity(report: dict[str, Any], *, expected_sha: str, expected_base_sha: str | None = None) -> None:
    """Reject forged ancestry claims and stale integration bases supplied by the producer."""
    if report.get("source_dirty") is not False:
        raise ValueError("tested source tree is dirty or dirtiness is unrecorded")
    source = report.get("tested_source_sha")
    candidate = report.get("candidate_sha")
    parents = report.get("source_parents")
    if (
        candidate != expected_sha
        or not isinstance(source, str)
        or SHA.fullmatch(source) is None
        or report.get("installed_source_sha") != source
        or not isinstance(parents, list)
        or any(not isinstance(p, str) or SHA.fullmatch(p) is None for p in parents)
    ):
        raise ValueError("source, installed build and candidate binding disagree")
    if source != candidate:
        if len(parents) != 2 or candidate not in parents:
            raise ValueError("tested source is not an exact candidate test merge")
        base = next(p for p in parents if p != candidate)
        if report.get("tested_base_sha") != base or (expected_base_sha is not None and base != expected_base_sha):
            raise ValueError("test-merge base is stale or inconsistent")
    elif report.get("tested_base_sha") is not None:
        raise ValueError("a direct candidate build cannot claim a different tested base")
