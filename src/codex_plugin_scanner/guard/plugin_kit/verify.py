"""``hol-guard plugin verify``: compare what Claude Code installed with HOL's integrity ledger.

HOL records, for each listing version, the commit every channel served. This
command reads the commit and version Claude Code recorded for the listing's
plugin and checks it against that record. A difference is reported as a
warning only: Guard never changes or removes the plugin because of it, and
the command exits 0 whether or not the commits match.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from ...version import __version__
from ..mdm.network import ManagedNetworkError, managed_urlopen
from . import install

LEDGER_SCHEMA = "hol.plugin-integrity-ledger.v1"
_LEDGER_LIMIT_BYTES = 512 * 1024
_LEDGER_TIMEOUT_SECONDS = 10.0
# Events that say something about one version's contents; the rest describe
# packaging and stay on the listing page.
_VERSION_EVENTS = {"differs", "republished", "version_withdrawn", "pinned_commit_unreachable"}


def ledger_endpoint(spec_endpoint: str) -> str:
    """The ledger lookup next to the install-spec endpoint, so an override
    (a local portal) serves both."""

    base, _, _ = spec_endpoint.rstrip("/").rpartition("/")
    return f"{base}/integrity-ledger"


def fetch_ledger(slug: str, endpoint: str) -> dict[str, Any]:
    url = f"{endpoint}?{urllib.parse.urlencode({'slug': slug})}"
    request = urllib.request.Request(
        url, headers={"User-Agent": f"hol-guard/{__version__}", "Accept": "application/json"}
    )
    try:
        with managed_urlopen(request, timeout=_LEDGER_TIMEOUT_SECONDS, allow_redirects=False) as response:
            raw = response.read(_LEDGER_LIMIT_BYTES + 1)
    except urllib.error.HTTPError as error:
        if error.code == 404:
            raise install.PluginInstallError(
                f"HOL has no integrity record for {slug}.", exit_code=install.EXIT_NOTHING, code="not_found"
            ) from error
        if error.code == 400:
            raise install.PluginInstallError("Use a HOL listing slug such as owner/plugin.") from error
        raise install.PluginInstallError(
            f"HOL could not answer the integrity lookup (HTTP {error.code}). Try again shortly.",
            exit_code=install.EXIT_UNREACHABLE,
            code="unreachable",
        ) from error
    except (ManagedNetworkError, urllib.error.URLError, OSError) as error:
        raise install.PluginInstallError(
            "The integrity record could not be downloaded from HOL.",
            exit_code=install.EXIT_UNREACHABLE,
            code="unreachable",
        ) from error
    if len(raw) > _LEDGER_LIMIT_BYTES:
        raise install.PluginInstallError("The integrity record from HOL was larger than expected.")
    try:
        ledger = json.loads(raw)
    except ValueError as error:
        raise install.PluginInstallError("The integrity record from HOL was not valid JSON.") from error
    if not isinstance(ledger, dict) or ledger.get("schema") != LEDGER_SCHEMA:
        raise install.PluginInstallError("The integrity record from HOL was not in the expected shape.")
    return ledger


def claude_plugin_id(spec: Mapping[str, Any]) -> str | None:
    """``plugin@marketplace`` for the listing's Claude Code target, as Claude Code records it."""

    targets = spec.get("targets")
    for target in targets if isinstance(targets, list) else []:
        if not isinstance(target, Mapping) or target.get("runtime") != "claude-code":
            continue
        marketplace = target.get("marketplace")
        name = marketplace.get("name") if isinstance(marketplace, Mapping) else None
        plugin = target.get("plugin")
        if isinstance(plugin, str) and plugin and isinstance(name, str) and name:
            return f"{plugin}@{name}"
    return None


def claude_installed(home: Path, plugin_id: str) -> dict[str, str | None] | None:
    """The version and commit Claude Code recorded for the user's install, or
    None when it has none. Raises when its record cannot be read."""

    plugins = install._claude_record(home)
    if plugins is None:
        raise install.PluginInstallError(f"{install._claude_unreadable(home)}.")
    entries = plugins.get(plugin_id)
    for entry in entries if isinstance(entries, list) else []:
        if isinstance(entry, Mapping) and entry.get("scope") == "user":
            version, commit = entry.get("version"), entry.get("gitCommitSha")
            return {
                "version": version if isinstance(version, str) and version else None,
                "commit": commit if isinstance(commit, str) and commit else None,
            }
    return None


def compare(installed: Mapping[str, str | None], ledger: Mapping[str, Any]) -> dict[str, Any]:
    """Hold the installed commit against what HOL recorded for its version.

    ``status`` is ``matches``, ``differs`` (HOL recorded other commits for this
    version), ``not_recorded`` (HOL has no commit for this version yet) or
    ``no_commit`` (Claude Code kept no commit, as for a plugin installed by
    running a declared command).
    """

    version, commit = installed.get("version"), installed.get("commit")
    records = ledger.get("records")
    commits: dict[str, list[str]] = {}
    for item in records if isinstance(records, list) else []:
        if not isinstance(item, Mapping) or item.get("kind") != "git_commit":
            continue
        if version is not None and item.get("version") != version:
            continue
        sha, channel = item.get("commitSha"), item.get("channel")
        if isinstance(sha, str) and sha:
            channels = commits.setdefault(sha, [])
            if isinstance(channel, str) and channel not in channels:
                channels.append(channel)
    if commit is None:
        status = "no_commit"
    elif not commits:
        status = "not_recorded"
    elif commit in commits:
        status = "matches"
    else:
        status = "differs"
    raw_events = ledger.get("events")
    events = [
        {"kind": event.get("kind"), "version": event.get("version"), "sentence": event.get("sentence")}
        for event in (raw_events if isinstance(raw_events, list) else [])
        if isinstance(event, Mapping)
        and event.get("kind") in _VERSION_EVENTS
        and (event.get("version") in (None, version) or version is None)
    ]
    return {
        "status": status,
        "recorded": [{"commit": sha, "channels": ch} for sha, ch in commits.items()],
        "events": events,
    }


def listing_releases_url(spec: Mapping[str, Any]) -> str | None:
    listing = spec.get("listingUrl")
    return f"{listing.rstrip('/')}/releases" if isinstance(listing, str) and listing.startswith("https://") else None


def render(
    slug: str, installed: Mapping[str, str | None], result: Mapping[str, Any], releases: str | None
) -> list[str]:
    version = installed.get("version") or "an unknown version"
    commit = installed.get("commit")
    lines = [f"{slug} in Claude Code: {version}" + (f" at commit {install._short(commit)}" if commit else "")]
    recorded: Sequence[Mapping[str, Any]] = result.get("recorded") or []
    shown = ", ".join(
        f"{install._short(item.get('commit'))} ({', '.join(item.get('channels') or [])})" for item in recorded
    )
    status = result.get("status")
    if status == "matches":
        lines.append(f"  Matches what HOL recorded for {version}.")
    elif status == "differs":
        lines.append(
            f"Warning: HOL recorded {shown} for {version}, not the commit Claude Code installed. "
            "Guard changed nothing; check the listing's releases before you keep using it."
        )
    elif status == "not_recorded":
        lines.append(f"  HOL has no commit recorded for {version} yet, so there is nothing to compare.")
    else:
        lines.append("  Claude Code kept no commit for this install, so there is nothing to compare.")
    for event in result.get("events") or []:
        lines.append(f"  HOL noted: {event.get('sentence')}")
    if releases and (status == "differs" or result.get("events")):
        lines.append(f"  Releases: {releases}")
    return lines
