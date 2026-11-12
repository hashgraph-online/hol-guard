"""The Codex install shim applies the native install plan and refuses an unreadable one."""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard import native_runner_authority as authority
from codex_plugin_scanner.guard.adapters import codex
from codex_plugin_scanner.guard.native_runner_authority import NativeRunnerAuthorityError

_BLOCK = (codex._SHELL_GUARD_BEGIN + "\nlegacy\n" + codex._SHELL_GUARD_END + "\n").encode("ascii")


def _answer(monkeypatch: pytest.MonkeyPatch, answer: dict[str, object]) -> list[dict[str, object]]:
    requests: list[dict[str, object]] = []

    def fake(kind: str, args: dict[str, object]) -> dict[str, object]:
        assert kind == "codex_install_plan"
        requests.append(args)
        return answer

    monkeypatch.setattr(authority, "native_runner_authority", fake)
    return requests


def test_a_file_without_the_begin_marker_is_not_sent(monkeypatch: pytest.MonkeyPatch) -> None:
    requests = _answer(monkeypatch, {"ranges": []})

    assert codex._remove_managed_shell_guard_blocks(b"\xffexport A=1\n") == b"\xffexport A=1\n"
    assert requests == []


def test_answered_ranges_remove_only_their_bytes(monkeypatch: pytest.MonkeyPatch) -> None:
    content = b"\xffKEEP\n" + _BLOCK + b"AFTER\xfe\n"
    requests = _answer(monkeypatch, {"ranges": [[6, 6 + len(_BLOCK)]]})

    assert codex._remove_managed_shell_guard_blocks(content) == b"\xffKEEP\nAFTER\xfe\n"
    assert requests == [{"op": "shell_blocks", "content": content.decode("latin-1")}]


@pytest.mark.parametrize(
    "ranges",
    [
        None,
        [[0]],
        [[1, 1]],
        [[2, 1]],
        [[0, 999]],
        [[-1, 2]],
        [[True, 2]],
        [[4, 6], [0, 2]],
        [[0, 4], [2, 6]],
        [["0", "2"]],
    ],
)
def test_unreadable_ranges_are_refused(monkeypatch: pytest.MonkeyPatch, ranges: object) -> None:
    _answer(monkeypatch, {"ranges": ranges})

    with pytest.raises(NativeRunnerAuthorityError):
        codex._remove_managed_shell_guard_blocks(_BLOCK)


def test_only_launches_with_argument_lists_are_sent(monkeypatch: pytest.MonkeyPatch) -> None:
    requests = _answer(monkeypatch, {"names": ["proxy"]})
    servers: dict[object, object] = {
        "proxy": {"command": "hol-guard", "args": ["codex-mcp-proxy", 1]},
        "plain": {"command": 7, "args": []},
        "no-args": {"command": "npx"},
        "bad-args": {"command": "npx", "args": "x"},
        "not-a-table": "x",
        3: {"command": "npx", "args": []},
    }

    assert codex._guard_proxy_server_names(servers) == frozenset({"proxy"})
    assert requests == [
        {
            "op": "guard_proxies",
            "servers": {
                "proxy": {"command": "hol-guard", "args": ["codex-mcp-proxy"]},
                "plain": {"command": None, "args": []},
            },
        }
    ]


def test_no_launch_sends_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    requests = _answer(monkeypatch, {"names": []})

    assert codex._guard_proxy_server_names({"x": {"command": "npx"}}) == frozenset()
    assert requests == []


@pytest.mark.parametrize("names", [None, "proxy", [1], ["unknown"]])
def test_unreadable_proxy_names_are_refused(monkeypatch: pytest.MonkeyPatch, names: object) -> None:
    _answer(monkeypatch, {"names": names})

    with pytest.raises(NativeRunnerAuthorityError):
        codex._guard_proxy_server_names({"proxy": {"command": "hol-guard", "args": []}})
