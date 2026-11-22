"""A just-published alpha must be offered while PyPI's cached project index still omits it."""

from __future__ import annotations

import http.client
import io
import json
from contextlib import contextmanager

import pytest

from codex_plugin_scanner.guard.cli import update_commands, update_fresh_alpha

_PROJECT = {
    "info": {"version": "3.61.0a19"},
    "releases": {
        "3.60.0": [{"yanked": False, "requires_python": ">=3.10"}],
        "3.61.0a19": [{"yanked": False, "requires_python": ">=3.10"}],
    },
}


def _version_payload(version: str, *, yanked: bool = False) -> dict[str, object]:
    return {
        "info": {"version": version},
        "urls": [{"filename": f"hol_guard-{version}-py3-none-any.whl", "yanked": yanked, "requires_python": ">=3.10"}],
    }


def _stub_pypi(monkeypatch: pytest.MonkeyPatch, version_answers: dict[str, object]) -> list[str]:
    requested: list[str] = []

    def fake_latest() -> str:
        monkeypatch.setattr(update_commands, "_last_pypi_payload", json.loads(json.dumps(_PROJECT)))
        return "3.60.0"

    @contextmanager
    def fake_urlopen(request, *, timeout, policy):
        url = request.full_url
        requested.append(url)
        answer = version_answers.get(url)
        if answer is None:
            raise OSError("not found")
        if isinstance(answer, BaseException):
            raise answer
        yield io.BytesIO(json.dumps(answer).encode("utf-8"))

    monkeypatch.setattr(update_commands, "_latest_version_from_pypi", fake_latest)
    monkeypatch.setattr(update_commands, "_alpha_liveness_checker", lambda *_args: lambda _version: True)
    monkeypatch.setattr(update_commands, "managed_urlopen", fake_urlopen)
    monkeypatch.setattr(update_commands, "_runtime_python_version", lambda: "3.12.0")
    return requested


def _url(version: str) -> str:
    return f"https://pypi.org/pypi/hol-guard/{version}/json"


def test_reserved_alpha_published_on_pypi_is_offered(monkeypatch: pytest.MonkeyPatch) -> None:
    requested = _stub_pypi(monkeypatch, {_url("3.61.0a20"): _version_payload("3.61.0a20")})
    monkeypatch.setattr(update_commands, "_newest_reserved_alpha_version", lambda *, latest_pypi: "3.61.0a20")

    payload = update_commands._version_check_payload("3.61.0a19", include_alpha=True)

    assert payload["status"] == "stale"
    assert payload["latest_version"] == "3.61.0a20"
    assert payload["update_available"] is True
    assert "reserved_alpha_version" not in payload
    assert requested == [_url("3.61.0a20")]
    releases = update_commands._last_pypi_payload["releases"]
    assert releases["3.61.0a20"][0]["filename"] == "hol_guard-3.61.0a20-py3-none-any.whl"


@pytest.mark.parametrize(
    "answer",
    [
        None,
        _version_payload("3.61.0a20", yanked=True),
        _version_payload("3.61.0a21"),
        {"info": {"version": "3.61.0a20"}, "urls": []},
        http.client.BadStatusLine("garbled"),
    ],
    ids=["unpublished", "yanked", "wrong-version", "no-files", "bad-status-line"],
)
def test_reserved_alpha_without_pypi_files_stays_reserved(
    monkeypatch: pytest.MonkeyPatch,
    answer: object,
) -> None:
    _stub_pypi(monkeypatch, {} if answer is None else {_url("3.61.0a20"): answer})
    monkeypatch.setattr(update_commands, "_newest_reserved_alpha_version", lambda *, latest_pypi: "3.61.0a20")

    payload = update_commands._version_check_payload("3.61.0a19", include_alpha=True)

    assert payload["status"] == "current"
    assert payload["latest_version"] == "3.61.0a19"
    assert payload["reserved_alpha_version"] == "3.61.0a20"
    assert "3.61.0a20" not in update_commands._last_pypi_payload["releases"]


def test_reserved_alpha_lookup_runs_once_per_check(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_pypi(monkeypatch, {})
    calls: list[str | None] = []
    monkeypatch.setattr(
        update_commands,
        "_newest_reserved_alpha_version",
        lambda *, latest_pypi: calls.append(latest_pypi) or None,
    )

    payload = update_commands._version_check_payload("3.61.0a19", include_alpha=True)

    assert payload["status"] == "current"
    assert calls == ["3.61.0a19"]


def test_stable_channel_never_asks_for_reserved_alpha(monkeypatch: pytest.MonkeyPatch) -> None:
    requested = _stub_pypi(monkeypatch, {})
    monkeypatch.setattr(
        update_commands,
        "_newest_reserved_alpha_version",
        lambda *, latest_pypi: pytest.fail("stable channel looked up an alpha"),
    )

    payload = update_commands._version_check_payload("3.60.0")

    assert payload["status"] == "current"
    assert requested == []


def test_version_is_quoted_into_the_url() -> None:
    seen: list[str] = []

    def opener(request):
        seen.append(request.full_url)
        raise OSError("refused")

    files = update_fresh_alpha.fetch_published_release_files(
        "1.0/../x",
        opener=opener,
        read_bounded=lambda response, *, deadline: b"",
        timeout=1.0,
    )

    assert files is None
    assert seen == ["https://pypi.org/pypi/hol-guard/1.0%2F..%2Fx/json"]
