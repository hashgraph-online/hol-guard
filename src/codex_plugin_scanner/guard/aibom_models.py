"""AIBOM CLI options and cloud wire-size defaults."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

AibomExportFormat = Literal["json", "markdown"]


@dataclass(frozen=True, slots=True)
class AibomCliOptions:
    """Options controlling local inventory traversal and optional Cisco scans."""

    include_symlinks: bool = True
    follow_unsafe_symlinks: bool = False
    cisco_skill_scan: str = "off"
    cisco_mcp_scan: str = "off"
    cisco_timeout_seconds: float | None = None


_AIBOM_CLOUD_SYNC_OPTIONS = AibomCliOptions(
    cisco_skill_scan="auto",
    cisco_mcp_scan="auto",
    cisco_timeout_seconds=30.0,
)


_AIBOM_AUTO_SYNC_INTERVAL_SECONDS = 15 * 60  # 15 min — stale AIBOM data undermines trust surfaces


_AIBOM_EMPTY_SYNC_RETRY_SECONDS = 2 * 60


_AIBOM_GUARD_EVENTS_BACKOFF_KEY = "aibom_guard_events_backoff"


_AIBOM_GUARD_EVENTS_BACKOFF_MINUTES = 5  # matches _GUARD_EVENTS_ENDPOINT_UNAVAILABLE_RETRY_MINUTES


_AIBOM_SYNC_BATCH_SIZE = 3  # keep each POST under Cloudflare's 100s origin timeout


_AIBOM_MAX_REQUEST_BODY_BYTES = 7_500_000  # stay below the portal's 8 MB request limit
