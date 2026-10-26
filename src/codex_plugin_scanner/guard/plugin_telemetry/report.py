"""Build and send the weekly plugin install report.

Guard downloads the public HOL listing index, and the native
``plugin-telemetry`` command matches the plugins installed under each agent
runtime's home against it on the device. Only listed plugins are reported:
slug, runtime, plugin version and a weekly counting key, plus a ``via`` marker
when ``hol-guard plugin install --apply`` installed the listing.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ...version import __version__
from ..mdm.network import ManagedNetworkError, managed_urlopen
from ..plugin_kit.install import mark_guard_installs
from .state import TelemetryState, TelemetryStateBusyError, claim_week, read_secret, read_state, release_week

PLUGIN_TELEMETRY_COMMAND = "plugin-telemetry"
PLUGIN_TELEMETRY_FEATURE = "plugin-telemetry-v1"
INDEX_URL = "https://hol.org/api/guard/plugins/install-telemetry/index"
REPORT_URL = "https://hol.org/api/guard/plugins/install-telemetry"
PRIVACY_URL = "https://hol.org/privacy#guard-plugin-install-telemetry"
_TIMEOUT_SECONDS = 20.0
# HOL builds the listing index from the whole plugin catalog, which can take
# about 30 seconds on a server that has not built it yet.
_INDEX_TIMEOUT_SECONDS = 60.0
_NATIVE_TIMEOUT_SECONDS = 60.0
# The full index is downloaded, then cut down to the installed repositories
# before it reaches the native runtime, which reads at most 6 MiB of stdin.
_INDEX_LIMIT_BYTES = 32 * 1024 * 1024
_NATIVE_REQUEST_LIMIT_BYTES = 6 * 1024 * 1024
_OUTPUT_LIMIT_BYTES = 1024 * 1024
_INDEX_FIELDS = ("slug", "repository", "manifestName", "pluginRoot")


_OFF_MESSAGE = "Plugin install counts are off. Run: hol-guard telemetry plugins on"


class PluginTelemetryError(RuntimeError):
    """The report could not be built or sent; the message is safe to print."""


def current_week(now: datetime | None = None) -> str:
    year, week, _weekday = (now or datetime.now(timezone.utc)).isocalendar()
    return f"{year}-W{week:02d}"


def runtime_homes(user_home: Path | None = None) -> dict[str, str]:
    """The agent runtime homes that exist on this machine."""

    home = user_home or Path.home()
    candidates = {
        "claude": os.environ.get("CLAUDE_CONFIG_DIR") or str(home / ".claude"),
        "codex": os.environ.get("CODEX_HOME") or str(home / ".codex"),
        "gemini": str(home / ".gemini"),
        "cursor": str(home / ".cursor"),
    }
    return {name: path for name, path in candidates.items() if Path(path).is_dir()}


def _request(url: str, *, body: bytes | None = None) -> urllib.request.Request:
    headers = {"User-Agent": f"hol-guard/{__version__}", "Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    return urllib.request.Request(url, data=body, headers=headers, method="POST" if body is not None else "GET")


def fetch_index() -> list[dict[str, object]]:
    try:
        with managed_urlopen(_request(INDEX_URL), timeout=_INDEX_TIMEOUT_SECONDS) as response:
            raw = response.read(_INDEX_LIMIT_BYTES + 1)
    except (ManagedNetworkError, urllib.error.URLError, OSError) as error:
        raise PluginTelemetryError("The HOL plugin index could not be downloaded.") from error
    if len(raw) > _INDEX_LIMIT_BYTES:
        raise PluginTelemetryError("The HOL plugin index is larger than expected.")
    try:
        payload = json.loads(raw)
    except ValueError as error:
        raise PluginTelemetryError("The HOL plugin index was not valid JSON.") from error
    entries = payload.get("entries") if isinstance(payload, dict) else None
    if not isinstance(entries, list):
        raise PluginTelemetryError("The HOL plugin index was not in the expected shape.")
    return [
        {field: entry[field] for field in _INDEX_FIELDS if isinstance(entry.get(field), str)}
        for entry in entries
        if isinstance(entry, dict) and isinstance(entry.get("slug"), str)
    ]


def _native_request(request: Mapping[str, object], *, feature: str = PLUGIN_TELEMETRY_FEATURE) -> dict[str, Any]:
    from ..codex_hook_launch_runtime import run_isolated_hook_process
    from ..native_runtime import native_runtime_status

    status = native_runtime_status()
    if (
        not status.available
        or not status.compatible
        or status.identity is None
        or status.capabilities is None
        or feature not in status.capabilities.features
    ):
        raise PluginTelemetryError("This command needs a newer Guard native runtime. Run: pip install -U hol-guard")
    runtime = status.identity.path
    input_text = json.dumps(dict(request), sort_keys=True, separators=(",", ":"))
    if len(input_text.encode("utf-8")) > _NATIVE_REQUEST_LIMIT_BYTES:
        raise PluginTelemetryError(
            "The HOL plugin index is too large for this Guard version. Run: pip install -U hol-guard"
        )
    completed = run_isolated_hook_process(
        (str(runtime), PLUGIN_TELEMETRY_COMMAND, "--stdin"),
        input_text=input_text,
        cwd=runtime.parent,
        environment=dict(os.environ),
        timeout_seconds=_NATIVE_TIMEOUT_SECONDS,
        output_limit=_OUTPUT_LIMIT_BYTES,
    )
    if (
        completed.returncode != 0
        or completed.timed_out
        or completed.output_limit_exceeded
        or completed.containment_failed
    ):
        raise PluginTelemetryError("The Guard native runtime could not build the report.")
    try:
        response = json.loads(completed.stdout)
    except ValueError as error:
        raise PluginTelemetryError("The Guard native runtime could not build the report.") from error
    if not isinstance(response, dict) or response.get("ok") is not True or not isinstance(response.get("result"), dict):
        code = response.get("error") if isinstance(response, dict) else None
        raise PluginTelemetryError(f"The Guard native runtime refused the report ({code or 'no result'}).")
    return response["result"]


def installed_index(index: list[dict[str, object]]) -> list[dict[str, object]]:
    """The index entries whose repository a plugin installed here declares.

    Matching needs a repository, so the rest of the index is never needed on
    the device. The repository list is used here and is not sent anywhere.

    The native runtime returns normalized URLs (``https://host/owner/repo``).
    Normalizing only lower-cases and strips a prefix or suffix, so any index
    URL that normalizes to one of them contains its ``host/owner/repo`` part.
    The filter keeps those entries and may keep a few extra ones; the native
    matcher still decides exactly which listing a plugin belongs to.
    """

    result = _native_request({"command": "repositories", "homes": runtime_homes()})
    repositories = result.get("repositories")
    keys = (
        {item.removeprefix("https://") for item in repositories if isinstance(item, str)}
        if isinstance(repositories, list)
        else set()
    )
    if not keys:
        return []
    return [
        entry
        for entry in index
        if isinstance(entry.get("repository"), str) and any(key in str(entry["repository"]).lower() for key in keys)
    ]


def build_report(secret: str, *, week: str, index: list[dict[str, object]] | None = None) -> dict[str, Any]:
    """``{"installed": n, "report": {...}}`` for this machine and week."""

    return _native_request(
        {
            "command": "report",
            "homes": runtime_homes(),
            "index": installed_index(fetch_index() if index is None else index),
            "secret": secret,
            "week": week,
            "guardVersion": __version__,
        }
    )


def post_report(report: Mapping[str, object]) -> int:
    body = json.dumps(dict(report), sort_keys=True, separators=(",", ":")).encode("utf-8")
    try:
        with managed_urlopen(_request(REPORT_URL, body=body), timeout=_TIMEOUT_SECONDS) as response:
            payload = json.loads(response.read(64 * 1024) or b"{}")
    except urllib.error.HTTPError as error:
        raise PluginTelemetryError(f"HOL did not accept the report (HTTP {error.code}).") from error
    except (ManagedNetworkError, urllib.error.URLError, OSError, ValueError) as error:
        raise PluginTelemetryError("The report could not be sent.") from error
    accepted = payload.get("accepted") if isinstance(payload, dict) else None
    return accepted if isinstance(accepted, int) else 0


def dry_run(guard_home: Path) -> dict[str, Any]:
    """The report Guard would send this week, built without sending it.

    Before opt-in there is no device secret, so the keys use a throwaway one.
    """

    secret = read_secret(guard_home) or os.urandom(32).hex()
    built = build_report(secret, week=current_week())
    if isinstance(built.get("report"), dict):
        built["report"] = mark_guard_installs(built["report"], guard_home)
    return built


def _send(guard_home: Path, week: str, previous: TelemetryState) -> dict[str, Any]:
    try:
        secret = read_secret(guard_home)
        if secret is None:
            raise PluginTelemetryError(_OFF_MESSAGE)
        built = build_report(secret, week=week)
        report = mark_guard_installs(built["report"], guard_home)
        entries = report.get("entries") if isinstance(report, dict) else None
        # Counts can be turned off while the index downloads and the report builds.
        if not read_state(guard_home).enabled:
            raise PluginTelemetryError(_OFF_MESSAGE)
        accepted = post_report(report) if entries else 0
    except BaseException:
        release_week(guard_home, week, previous)
        raise
    return {"week": week, "installed": built.get("installed", 0), "listed": len(entries or []), "accepted": accepted}


def send_now(guard_home: Path, *, now: datetime | None = None) -> dict[str, Any]:
    """Send this week's report. Requires opt-in; records the week on success."""

    week = current_week(now)
    try:
        previous = claim_week(guard_home, week, only_if_due=False)
    except TelemetryStateBusyError as error:
        raise PluginTelemetryError("Another Guard process is sending the report. Try again shortly.") from error
    if previous is None:
        raise PluginTelemetryError(_OFF_MESSAGE)
    return _send(guard_home, week, previous)


def send_if_due(guard_home: Path, *, now: datetime | None = None) -> dict[str, Any] | None:
    """Send at most one report per ISO week, and only after opt-in."""

    week = current_week(now)
    state = read_state(guard_home)
    if not state.enabled or state.last_week == week:
        return None
    try:
        previous = claim_week(guard_home, week, only_if_due=True)
    except TelemetryStateBusyError:
        return None
    if previous is None:
        return None
    return _send(guard_home, week, previous)
