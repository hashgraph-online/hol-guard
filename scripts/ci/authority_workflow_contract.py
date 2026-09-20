"""Structural trigger requirements for always-selected authority checks."""

from __future__ import annotations

import yaml

_REQUIRED_BRANCHES = frozenset({"main", "release/3.2"})
_REQUIRED_PR_EVENTS = frozenset({"opened", "synchronize", "reopened"})


def require_unfiltered_release_pull_requests(source: str, *, label: str) -> None:
    # BaseLoader leaves the YAML 1.1 word `on` as a string, as Actions expects.
    document = yaml.load(source, Loader=yaml.BaseLoader)
    events = document.get("on") if isinstance(document, dict) else None
    if not isinstance(events, dict) or "pull_request" not in events:
        raise RuntimeError(f"{label} must run on pull requests to main and release/3.2")
    trigger = events["pull_request"]
    if trigger in (None, ""):
        return
    if not isinstance(trigger, dict):
        raise RuntimeError(f"{label} has an invalid pull_request trigger")
    if any(key in trigger for key in ("paths", "paths-ignore", "branches-ignore")):
        raise RuntimeError(f"{label} must not filter authority pull requests by changed paths or ignored branches")
    branches = trigger.get("branches")
    if branches is not None and (
        not isinstance(branches, list)
        or not _REQUIRED_BRANCHES.issubset(branches)
        or any(not isinstance(branch, str) or branch.startswith("!") for branch in branches)
    ):
        raise RuntimeError(f"{label} must include main and release/3.2 pull requests")
    event_types = trigger.get("types")
    if event_types is not None and (not isinstance(event_types, list) or not _REQUIRED_PR_EVENTS.issubset(event_types)):
        raise RuntimeError(f"{label} must include opened, synchronize and reopened pull requests")
