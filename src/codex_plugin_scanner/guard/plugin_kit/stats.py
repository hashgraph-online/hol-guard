"""``hol-guard plugin stats``: a listing owner's own numbers from HOL.

The command reads a stats key from ``HOL_API_KEY`` (create one in the HOL
plugin workspace; it can only read listings its account owns) and prints
the listing's views for the last 28 days and the last complete week of
attested installs. HOL withholds any install count under its minimum, so
the command never prints one.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from typing import Any

from ...version import __version__
from ..mdm.network import ManagedNetworkError, managed_urlopen

STATS_URL = "https://hol.org/api/v1/guard/plugins/{slug}/stats"
KEY_ENV = "HOL_API_KEY"
_STATS_LIMIT_BYTES = 64 * 1024
_STATS_TIMEOUT_SECONDS = 20.0


class PluginStatsError(RuntimeError):
    """The stats could not be read."""


def read_key(environ: Mapping[str, str] | None = None) -> str:
    key = (environ if environ is not None else os.environ).get(KEY_ENV, "").strip()
    if not key:
        raise PluginStatsError(
            f"Set {KEY_ENV} to a stats key. Create one under Stats in your terminal in the HOL plugin workspace."
        )
    return key


def fetch_stats(slug: str, key: str) -> dict[str, Any]:
    url = STATS_URL.format(slug=urllib.parse.quote(slug, safe=""))
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": f"hol-guard/{__version__}",
            "Accept": "application/json",
            "Authorization": f"Bearer {key}",
        },
    )
    try:
        with managed_urlopen(request, timeout=_STATS_TIMEOUT_SECONDS) as response:
            raw = response.read(_STATS_LIMIT_BYTES + 1)
    except urllib.error.HTTPError as error:
        if error.code == 401:
            raise PluginStatsError(f"HOL did not accept the key in {KEY_ENV}. It may have been revoked.") from error
        if error.code == 403:
            raise PluginStatsError(f"The key's account does not own {slug} on HOL.") from error
        if error.code == 400:
            raise PluginStatsError("Use a HOL listing slug such as owner/plugin.") from error
        raise PluginStatsError(f"HOL could not answer right now (HTTP {error.code}). Try again shortly.") from error
    except (ManagedNetworkError, urllib.error.URLError, OSError) as error:
        raise PluginStatsError("The stats could not be downloaded from HOL.") from error
    if len(raw) > _STATS_LIMIT_BYTES:
        raise PluginStatsError("The stats from HOL were larger than expected.")
    try:
        stats = json.loads(raw)
    except ValueError as error:
        raise PluginStatsError("The stats from HOL were not valid JSON.") from error
    if not isinstance(stats, dict) or stats.get("apiVersion") != "v1":
        raise PluginStatsError("The stats from HOL were not in the expected shape. Run: pip install -U hol-guard")
    return stats


def _is_count(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _count(value: object) -> str:
    return f"{value:,}" if _is_count(value) else "not measured"


def _install_count(value: object, minimum: object) -> str:
    # HOL sends null for an install count it withholds under its minimum.
    return f"{value:,}" if _is_count(value) else f"under {minimum}"


def render_stats(stats: Mapping[str, Any]) -> list[str]:
    raw_listing = stats.get("listing")
    listing: Mapping[str, Any] = raw_listing if isinstance(raw_listing, Mapping) else {}
    raw_window = listing.get("window")
    window: Mapping[str, Any] = raw_window if isinstance(raw_window, Mapping) else {}
    start = str(window.get("from") or "")[:10]
    end = str(window.get("to") or "")[:10]
    lines = [f"{stats.get('plugin')}", "", f"Listing, last {window.get('days', 28)} days ({start} to {end} UTC)"]
    if listing.get("measured"):
        lines += [
            f"  views            {_count(listing.get('views'))}",
            f"  unique visitors  {_count(listing.get('uniqueVisitors'))}",
            f"  install clicks   {_count(listing.get('installClicks'))}",
        ]
    else:
        lines.append("  not measured yet")
    installs = stats.get("attestedInstalls")
    lines.append("")
    if not isinstance(installs, Mapping):
        lines.append("Attested installs: none reported yet")
        return lines
    minimum = installs.get("minMachines")
    lines.append(f"Attested installs, week {installs.get('week')} (counts under {minimum} machines are withheld)")
    lines.append(f"  machines         {_install_count(installs.get('machines'), minimum)}")
    if "viaGuard" in installs:
        lines.append(f"  via hol-guard    {_install_count(installs.get('viaGuard'), minimum)}")
    by_runtime = installs.get("byRuntime")
    for cell in by_runtime if isinstance(by_runtime, list) else []:
        if isinstance(cell, Mapping):
            lines.append(f"  {cell.get('runtime')!s:<16} {_install_count(cell.get('machines'), minimum)}")
    return lines
