"""Trust the target-branch verifier, with one pinned initial-installation path."""

from __future__ import annotations

import os
import urllib.parse
from typing import Any

from .source_identity import SHA

BOOTSTRAP_REPOSITORY = "hashgraph-online/hol-guard"
BOOTSTRAP_PULL_REQUEST = 3463


def validate_producer_revision(api: Any, number: int, pull: dict, run: dict) -> None:
    """A writer-dispatched candidate judge is not automatically trusted code."""
    revision = run.get("head_sha")
    # GitHub PR metadata may retain an old base after its destination advances.
    # Only the independently resolved current branch tip can anchor verifier trust.
    base = pull.get("gauntlet_base_sha")
    if not isinstance(base, str) or SHA.fullmatch(base) is None:
        raise RuntimeError("Gauntlet producer has no current trusted base revision")
    if not isinstance(revision, str) or SHA.fullmatch(revision) is None:
        raise RuntimeError("Gauntlet producer has no immutable verifier revision")
    if revision == base:
        return
    comparison = api.request(f"/compare/{base}...{revision}")
    branch = urllib.parse.quote(api.request("")["default_branch"], safe="")
    on_default = api.request(f"/compare/{revision}...{branch}")
    if comparison.get("status") == "ahead" and on_default.get("status") in {"identical", "ahead"}:
        return
    bootstrap = os.environ.get("GUARD_GAUNTLET_BOOTSTRAP_VERIFIER_SHA", "")
    if (
        api.repo == BOOTSTRAP_REPOSITORY
        and number == BOOTSTRAP_PULL_REQUEST
        and SHA.fullmatch(bootstrap) is not None
        and revision == bootstrap
        and isinstance(pull.get("gauntlet_base_sha"), str)
        and SHA.fullmatch(pull["gauntlet_base_sha"]) is not None
        and not api.gauntlet_installed_at(pull["gauntlet_base_sha"])
    ):
        return
    raise RuntimeError("Gauntlet evidence must be verified by the current trusted base revision")
