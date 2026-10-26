"""Record the approval links `native_review_reason` writes into review answers.

Each vector fixes the clock and the daemon auth token, so the signed
`#guard-token=` session in the link is reproducible byte for byte.

Run from the repository root:

    .venv/bin/python rust/crates/guard-runtime/testdata/native_review_link/record_native_review_link_vectors.py
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from codex_plugin_scanner.guard import approval_hook_copy, local_dashboard_session
from codex_plugin_scanner.guard.approval_link_output import native_review_reason

OUT = Path(__file__).with_name("native_review_link_vectors.json")
GUARD_HOME = Path("/home/agent/.hol-guard")
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
TOKENS = ["3f" * 32, "token with spaces", None]
NOWS = [
    datetime(2026, 10, 13, 15, 0, 0, tzinfo=timezone.utc),
    datetime(2026, 12, 31, 23, 59, 59, 123456, tzinfo=timezone.utc),
]
URLS = [
    "http://127.0.0.1:4781/requests/0123456789abcdef",
    "http://localhost:4781/requests/r-1",
    "http://[::1]:4781/requests/r_1",
    "http://LOCALHOST/requests/r.1",
    "http://127.0.0.1:4781",
    "https://guard.example.test/requests/r1",
]
HARNESSES = ["codex", "cursor"]


def _reasons(url: str) -> list[str]:
    return [
        "Network installer piped to a shell.",
        "",
        "   ",
        f"  Review it at {url} .  ",
        f"Paused: {url}: .",
        f"Review {url} then {url}",
        "Paused for review:",
        "Revisi\u00f3n requerida \u2014 \u00f1 :\u00a0.",
        "Blocked \u2026 see:\t.\nnext",
    ]


def _micros(moment: datetime) -> int:
    delta = moment - EPOCH
    return (delta.days * 86_400 + delta.seconds) * 1_000_000 + delta.microseconds


class _Clock(datetime):
    fixed: datetime = NOWS[0]

    @classmethod
    def now(cls, tz=None):  # type: ignore[override]
        return cls.fixed


def _record(harness: str, reason: str, url: str, token: str | None, now: datetime) -> dict[str, object]:
    _Clock.fixed = now
    with (
        mock.patch.object(local_dashboard_session, "datetime", _Clock),
        mock.patch.object(approval_hook_copy, "load_guard_daemon_auth_token", lambda _home: token),
    ):
        expected = native_review_reason(harness, reason, url, guard_home=GUARD_HOME)
    return {
        "harness": harness,
        "reason": reason,
        "approval_url": url,
        "auth_token": token,
        "now_micros": _micros(now),
        "expected": expected,
    }


def _session(token: str, surface: str, now: datetime) -> dict[str, object]:
    _Clock.fixed = now
    with mock.patch.object(local_dashboard_session, "datetime", _Clock):
        expected = local_dashboard_session.build_local_dashboard_session_token(auth_token=token, surface=surface)
    return {"auth_token": token, "surface": surface, "now_micros": _micros(now), "expected": expected}


def main() -> None:
    reasons = [
        _record(harness, reason, url, token, now)
        for harness in HARNESSES
        for url in URLS
        for reason in _reasons(url)
        for token in TOKENS
        for now in NOWS
    ]
    sessions = [
        _session(token, surface, now)
        for token in [t for t in TOKENS if t is not None]
        for surface in ["approval-center", "protection-repair"]
        for now in [*NOWS, NOWS[0] + timedelta(microseconds=1)]
    ]
    document = {"reasons": reasons, "sessions": sessions}
    OUT.write_text(json.dumps(document, indent=1, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
