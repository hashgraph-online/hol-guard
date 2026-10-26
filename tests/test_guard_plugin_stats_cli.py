"""``hol-guard plugin stats``: key handling, HOL's answers and the printed numbers."""

from __future__ import annotations

import contextlib
import io
import json
import urllib.error
from email.message import Message
from typing import Any

import pytest

from codex_plugin_scanner import cli as guard_cli
from codex_plugin_scanner.guard.plugin_kit import stats

STATS: dict[str, Any] = {
    "apiVersion": "v1",
    "plugin": "acme/toolgate",
    "generatedAt": "2026-10-26T12:00:00.000Z",
    "listing": {
        "window": {"from": "2026-09-29T00:00:00.000Z", "to": "2026-10-26T12:00:00.000Z", "days": 28},
        "measured": True,
        "views": 1380,
        "uniqueVisitors": 210,
        "installClicks": 33,
    },
    "attestedInstalls": {
        "week": "2026-W43",
        "minMachines": 5,
        "machines": 41,
        "viaGuard": 12,
        "byRuntime": [{"runtime": "claude-code", "machines": 30}],
    },
}


class Reply:
    def __init__(self, body: bytes) -> None:
        self.body = body

    def __enter__(self) -> Reply:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read(self, limit: int) -> bytes:
        return self.body[:limit]


def run(argv: list[str], monkeypatch: pytest.MonkeyPatch) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    monkeypatch.setattr(guard_cli.sys, "argv", ["hol-guard"])
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = guard_cli.main(argv)
    return code, out.getvalue(), err.getvalue()


@pytest.fixture
def requests(monkeypatch: pytest.MonkeyPatch) -> list[Any]:
    sent: list[Any] = []

    def answer(request: Any, timeout: float) -> Reply:
        sent.append(request)
        return Reply(json.dumps(STATS).encode())

    monkeypatch.setattr(stats, "managed_urlopen", answer)
    monkeypatch.setenv("HOL_API_KEY", "holp_abc.secret")
    return sent


def test_stats_prints_each_number_with_its_window(requests: list[Any], monkeypatch: pytest.MonkeyPatch) -> None:
    code, out, _ = run(["plugin", "stats", "acme/toolgate"], monkeypatch)
    assert code == 0
    assert out.splitlines() == [
        "acme/toolgate",
        "",
        "Listing, last 28 days (2026-09-29 to 2026-10-26 UTC)",
        "  views            1,380",
        "  unique visitors  210",
        "  install clicks   33",
        "",
        "Attested installs, week 2026-W43 (counts under 5 machines are withheld)",
        "  machines         41",
        "  via hol-guard    12",
        "  claude-code      30",
    ]
    request = requests[0]
    assert request.full_url == "https://hol.org/api/v1/guard/plugins/acme%2Ftoolgate/stats"
    assert request.get_header("Authorization") == "Bearer holp_abc.secret"


def test_stats_json_prints_hols_answer(requests: list[Any], monkeypatch: pytest.MonkeyPatch) -> None:
    code, out, _ = run(["plugin", "stats", "acme/toolgate", "--json"], monkeypatch)
    assert code == 0
    assert json.loads(out) == STATS


def test_stats_says_unknown_rather_than_zero() -> None:
    lines = stats.render_stats(
        {
            **STATS,
            "listing": {**STATS["listing"], "measured": False, "views": None},
            "attestedInstalls": {
                **STATS["attestedInstalls"],
                "machines": None,
                "viaGuard": None,
                "byRuntime": [{"runtime": "codex", "machines": None}],
            },
        }
    )
    assert "  not measured yet" in lines
    assert "  machines         under 5" in lines
    assert "  via hol-guard    under 5" in lines
    assert "  codex            under 5" in lines
    assert stats.render_stats({**STATS, "attestedInstalls": None})[-1] == "Attested installs: none reported yet"


def test_stats_needs_a_key_and_sends_nothing_without_one(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("HOL_API_KEY", raising=False)
    monkeypatch.setattr(stats, "managed_urlopen", lambda *args, **kwargs: pytest.fail("sent a request"))
    code, out, err = run(["plugin", "stats", "acme/toolgate"], monkeypatch)
    assert code == 2
    assert out == ""
    assert "Set HOL_API_KEY" in err


@pytest.mark.parametrize(
    ("status", "message"),
    [
        (401, "did not accept the key"),
        (403, "does not own acme/toolgate"),
        (503, "HTTP 503"),
    ],
)
def test_stats_explains_refusals_without_echoing_the_key(
    monkeypatch: pytest.MonkeyPatch, status: int, message: str
) -> None:
    def refuse(request: Any, timeout: float) -> Reply:
        raise urllib.error.HTTPError(request.full_url, status, "refused", Message(), None)

    monkeypatch.setattr(stats, "managed_urlopen", refuse)
    monkeypatch.setenv("HOL_API_KEY", "holp_abc.secret")
    code, _, err = run(["plugin", "stats", "acme/toolgate"], monkeypatch)
    assert code == 2
    assert message in err
    assert "holp_abc" not in err


def test_stats_rejects_an_unexpected_answer(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(stats, "managed_urlopen", lambda *args, **kwargs: Reply(b'{"apiVersion":"v2"}'))
    monkeypatch.setenv("HOL_API_KEY", "holp_abc.secret")
    code, _, err = run(["plugin", "stats", "acme/toolgate"], monkeypatch)
    assert code == 2
    assert "expected shape" in err


def test_stats_tolerates_a_malformed_runtime_breakdown(monkeypatch: pytest.MonkeyPatch) -> None:
    body = json.dumps({**STATS, "attestedInstalls": {**STATS["attestedInstalls"], "byRuntime": 1}}).encode()
    monkeypatch.setattr(stats, "managed_urlopen", lambda *args, **kwargs: Reply(body))
    monkeypatch.setenv("HOL_API_KEY", "holp_abc.secret")
    code, out, err = run(["plugin", "stats", "acme/toolgate"], monkeypatch)
    assert code == 0
    assert "machines" in out
    assert "Traceback" not in err
