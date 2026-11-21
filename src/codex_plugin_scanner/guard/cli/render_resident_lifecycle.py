"""How ``doctor`` reports the resident runtime's day from its lifecycle journal."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

_LIFECYCLE_TITLE = {
    "critical": "Native runtime not restarting",
    "degraded": "Native runtime unhealthy today",
}
_LIFECYCLE_BORDER = {"critical": "red", "degraded": "yellow"}
# What the day's journal establishes, which is not what is running now: the
# runtime derives these states from the events it recorded over the window,
# so the panel speaks about the day and sends the reader to `runtime status`
# for the live answer.
_LIFECYCLE_LEAD = {
    "critical": (
        "Guard's runtime stopped being restarted today: the last thing its journal recorded was "
        "the restart budget refusing a start, so nothing of this runtime came back up after it."
    ),
    "degraded": (
        "Guard's runtime has not been healthy today: runs have been ending badly and starting "
        "again, which a report taken at any one moment does not show."
    ),
}
_COLD_START_BANDS = ("cold_starts_within_1s", "cold_starts_within_5s", "cold_starts_slower")


def _lifecycle_age(seconds: object) -> str:
    """How long ago, in the coarsest unit that still says something."""

    if not isinstance(seconds, int) or isinstance(seconds, bool) or seconds < 0:
        return "at an unknown time"
    if seconds < 60:
        return f"{seconds}s ago"
    if seconds < 3600:
        return f"{seconds // 60}m ago"
    return f"{seconds // 3600}h ago"


def _cold_start_line(lifecycle: dict[object, object]) -> str | None:
    """The day's cold-start bands, or ``None`` when none was counted.

    A runtime older than the bands omits them, and a reply missing any one of
    them prints nothing rather than a partial line.
    """

    bands = [
        band
        for field in _COLD_START_BANDS
        if isinstance(band := lifecycle.get(field), int) and not isinstance(band, bool) and band >= 0
    ]
    if len(bands) != len(_COLD_START_BANDS) or sum(bands) == 0:
        return None
    return f"Cold starts: {bands[0]} ready within 1 second, {bands[1]} within 5 seconds, {bands[2]} slower."


def print_resident_lifecycle_note(console: Console, payload: dict[str, object]) -> None:
    """Say when this install's day has been worse than this moment looks.

    The counters beside this one describe the process that is running now, so
    an install that crashes every few minutes and recovers in between reports
    a clean bill of health between crashes. The panel prints only when the
    runtime's own answer is that the day was degraded or that nothing is being
    restarted at all. On a healthy day only the cold-start bands print, since
    a slow start is worth seeing even when every run ended well.
    """

    native_runtime = payload.get("native_runtime")
    lifecycle = native_runtime.get("lifecycle") if isinstance(native_runtime, dict) else None
    if not isinstance(lifecycle, dict):
        return
    cold_starts = _cold_start_line(lifecycle)
    state = lifecycle.get("state")
    if state not in _LIFECYCLE_LEAD:
        if state == "healthy" and cold_starts is not None:
            console.print(Text(f"Native runtime, last 24 hours. {cold_starts}"))
        return
    lines = [
        _LIFECYCLE_LEAD[state],
        (
            f"Last 24 hours: {lifecycle.get('starts', 0)} starts, "
            f"{lifecycle.get('orderly_exits', 0)} ended cleanly, "
            f"{lifecycle.get('failed_exits', 0)} failed, "
            f"{lifecycle.get('premature_exits', 0)} stopped early, "
            f"{lifecycle.get('refused_starts', 0)} starts refused."
        ),
    ]
    if cold_starts is not None:
        lines.append(cold_starts)
    last_event = lifecycle.get("last_event")
    if isinstance(last_event, str) and last_event:
        lines.append(f"Last event: {last_event}, {_lifecycle_age(lifecycle.get('last_event_age_seconds'))}.")
    lines.append(
        "This is the day behind the install, not what is up now: run `hol-guard runtime status` "
        "for that, or `hol-guard doctor --repair`."
    )
    console.print(Panel(Text("\n".join(lines)), title=_LIFECYCLE_TITLE[state], border_style=_LIFECYCLE_BORDER[state]))
