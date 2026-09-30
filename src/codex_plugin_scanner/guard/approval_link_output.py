"""Focused output helpers for authenticated approval links."""

from __future__ import annotations

from collections.abc import Callable
from contextlib import suppress
from pathlib import Path
from typing import TextIO

from .approval_hook_copy import (
    _SIGNED_APPROVAL_LINK_UNAVAILABLE,
    _without_raw_approval_url,
    authenticated_approval_review_url,
    is_loopback_approval_url,
    with_approval_review_url,
)


def open_authenticated_approval_link(
    review_url: str | None,
    *,
    guard_home: Path | None,
    authenticate: Callable[..., str | None],
    unavailable_message: str,
    open_browser: Callable[[str], object],
    output_stream: TextIO,
) -> None:
    """Print and open an approval link only after local authentication."""

    if not review_url:
        return
    browser_url = authenticate(review_url, guard_home=guard_home)
    if browser_url is None:
        print(unavailable_message, file=output_stream, flush=True)
        return
    print(
        f"HOL Guard is waiting for approval in your browser: {browser_url}",
        file=output_stream,
        flush=True,
    )
    with suppress(Exception):
        open_browser(browser_url)


def native_review_reason(
    canonical_harness: str,
    reason: str,
    approval_url: str,
    *,
    guard_home: Path | None,
) -> str:
    """Add a safe approval link to a native review reason."""

    if canonical_harness != "codex" or not is_loopback_approval_url(approval_url):
        return with_approval_review_url(reason, {"approval_url": approval_url}, guard_home=guard_home)
    signed_url = authenticated_approval_review_url(approval_url, guard_home=guard_home)
    stripped_reason = reason.strip()
    if signed_url is None:
        without_raw_url = _without_raw_approval_url(stripped_reason, approval_url)
        return f"{without_raw_url} {_SIGNED_APPROVAL_LINK_UNAVAILABLE}".strip()
    if signed_url in stripped_reason:
        return stripped_reason
    if approval_url in stripped_reason:
        return stripped_reason.replace(approval_url, signed_url)
    return f"{stripped_reason} Open HOL Guard to approve or keep this blocked: {signed_url}."


__all__ = ["native_review_reason", "open_authenticated_approval_link"]
