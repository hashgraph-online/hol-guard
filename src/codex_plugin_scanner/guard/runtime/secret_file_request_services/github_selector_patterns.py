"""Static GitHub selector and endpoint shape checks for shell argument review."""

from __future__ import annotations

import re

_REPOSITORY_COMPONENT = re.compile(r"[A-Za-z0-9_.-]+")
_PR_HEAD_OID_ENDPOINT = re.compile(
    "".join(
        (
            r"\Arepos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/commits/",
            r"\$\(gh pr view [1-9][0-9]* --json headRefOid --jq \.headRefOid\)",
            r"/check-runs(?:\?[A-Za-z0-9_.=&-]+)?\Z",
        )
    )
)


def github_repository_selector_is_safe(selector: str) -> bool:
    if any(marker in selector for marker in ("$", "`", "$(", "${")):
        return False
    parts = selector.split("/")
    if len(parts) == 3:
        if parts[0].casefold() != "github.com":
            return False
        parts = parts[1:]
    return len(parts) == 2 and all(_REPOSITORY_COMPONENT.fullmatch(part) for part in parts)


def github_pr_head_oid_endpoint_matches(value: str) -> bool:
    return _PR_HEAD_OID_ENDPOINT.fullmatch(value) is not None
