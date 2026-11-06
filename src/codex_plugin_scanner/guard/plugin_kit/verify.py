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
LEDGER_PATH = "/api/guard/plugins/integrity-ledger"
_LEDGER_LIMIT_BYTES = 512 * 1024
_LEDGER_TIMEOUT_SECONDS = 10.0


def ledger_endpoint(spec_endpoint: str) -> str:
    """The ledger lookup next to the install-spec endpoint, so an override
    (a local portal) serves both. An override that names only an origin gets
    HOL's own ledger path on that origin."""

    parts = urllib.parse.urlsplit(spec_endpoint)
    head, _, _ = parts.path.rstrip("/").rpartition("/")
    path = f"{head}/integrity-ledger" if head else LEDGER_PATH
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, path, "", ""))


def fetch_listing_spec(slug: str, endpoint: str, *, overridden: bool, progress: Any = None) -> dict[str, Any]:
    """The listing's install spec, fetched without following redirects so the
    ledger request that follows stays on the origin the spec came from."""

    try:
        return install.fetch_spec(slug, endpoint, progress=progress, allow_redirects=False)
    except install.PluginInstallError as error:
        cause = error.__cause__
        if not overridden and isinstance(cause, urllib.error.HTTPError) and 300 <= cause.code < 400:
            raise install.PluginInstallError(
                "HOL answered the install lookup with a redirect, which verify does not follow. Try again shortly.",
                exit_code=install.EXIT_UNREACHABLE,
                code="unreachable",
            ) from error
        if error.code == "not_found":
            raise install.PluginInstallError(str(error), exit_code=install.EXIT_NOTHING, code="not_found") from error
        raise


def fetch_ledger(slug: str, endpoint: str) -> object:
    """HOL's integrity record for ``slug``, parsed but not yet checked; ``compare`` checks it."""

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

    try:
        state = install.claude_state(home, plugin_id)
    except install._StoppedError as error:
        raise install.PluginInstallError(str(error)) from None
    if state.get("record") != "read":
        raise install.PluginInstallError(f"{install._claude_unreadable(home)}.")
    entry = state.get("entry")
    if not isinstance(entry, dict):
        return None
    version, commit = entry.get("version"), entry.get("commit")
    return {
        "version": version if isinstance(version, str) and version else None,
        "commit": commit if isinstance(commit, str) and commit else None,
    }


def compare(
    installed: Mapping[str, str | None], ledger: object, *, slug: str, spec_slug: object = None
) -> dict[str, Any]:
    """Check the ledger names ``slug`` (or the canonical slug the install spec
    gave) and is well formed, then hold the installed commit against what HOL
    recorded for its version.

    ``status`` is ``matches``, ``differs`` (HOL recorded other commits for this
    version), ``not_recorded`` (HOL has no commit for this version yet),
    ``no_commit`` (Claude Code kept no commit, as for a plugin installed by
    running a declared command) or ``no_version`` (Claude Code kept no
    version, so no recorded commit can be tied to the install).
    """

    from .cli import PluginKitNativeError, kit_request

    request = {"command": "integrity", "slug": slug, "spec_slug": spec_slug, "installed": dict(installed)}
    try:
        result = kit_request({**request, "ledger": ledger})
    except PluginKitNativeError as error:
        raise install.PluginInstallError(str(error)) from None
    if result.get("refused") == "listing":
        raise install.PluginInstallError(f"HOL answered the integrity lookup for {slug} with another listing's record.")
    if not isinstance(result.get("status"), str):
        raise install.PluginInstallError("The integrity record from HOL was not in the expected shape.")
    return {"status": result["status"], "recorded": result.get("recorded") or [], "events": result.get("events") or []}


def listing_releases_url(spec: Mapping[str, Any]) -> str | None:
    listing = spec.get("listingUrl")
    return f"{listing.rstrip('/')}/releases" if isinstance(listing, str) and listing.startswith("https://") else None


def render(
    slug: str, installed: Mapping[str, str | None], result: Mapping[str, Any], releases: str | None
) -> list[str]:
    # Everything below but the slug came from a file or a network answer, so
    # control characters are escaped before they reach the terminal.
    version = install._printable(installed.get("version") or "an unknown version")
    commit = installed.get("commit")
    lines = [
        f"{slug} in Claude Code: {version}"
        + (f" at commit {install._printable(install._short(commit))}" if commit else "")
    ]
    recorded: Sequence[Mapping[str, Any]] = result.get("recorded") or []
    shown = ", ".join(
        f"{install._printable(install._short(item.get('commit')))} "
        f"({install._printable(', '.join(item.get('channels') or []))})"
        for item in recorded
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
    elif status == "no_version":
        lines.append("  Claude Code kept no version for this install, so there is nothing to compare.")
    else:
        lines.append("  Claude Code kept no commit for this install, so there is nothing to compare.")
    for event in result.get("events") or []:
        lines.append(f"  HOL noted: {install._printable(str(event.get('sentence')))}")
    if releases and (status == "differs" or result.get("events")):
        lines.append(f"  Releases: {install._printable(releases)}")
    return lines
