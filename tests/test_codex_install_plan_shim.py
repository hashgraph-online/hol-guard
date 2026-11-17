"""The Codex install shim applies the native install plan and refuses an unreadable one."""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard import codex_harness_client as plan
from codex_plugin_scanner.guard import native_runner_authority as authority
from codex_plugin_scanner.guard.native_runner_authority import NativeRunnerAuthorityError


def _answer(monkeypatch: pytest.MonkeyPatch, answer: dict[str, object]) -> list[dict[str, object]]:
    requests: list[dict[str, object]] = []

    def fake(kind: str, args: dict[str, object]) -> dict[str, object]:
        assert kind == "codex_install_plan"
        requests.append(args)
        return answer

    monkeypatch.setattr(authority, "native_runner_authority", fake)
    return requests


def test_named_servers_are_sent_for_the_runtime_to_read(monkeypatch: pytest.MonkeyPatch) -> None:
    requests = _answer(monkeypatch, {"names": ["proxy"]})
    servers: dict[object, object] = {
        "proxy": {"command": "hol-guard", "args": ["codex-mcp-proxy", 1]},
        "plain": {"command": 7, "args": []},
        "no-args": {"command": "npx"},
        3: {"command": "npx", "args": []},
    }

    assert plan.guard_proxy_server_names(servers) == frozenset({"proxy"})
    assert requests == [
        {
            "op": "guard_proxies",
            "servers": {
                "proxy": {"command": "hol-guard", "args": ["codex-mcp-proxy", 1]},
                "plain": {"command": 7, "args": []},
                "no-args": {"command": "npx"},
            },
        }
    ]


def test_no_named_server_sends_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    requests = _answer(monkeypatch, {"names": []})

    assert plan.guard_proxy_server_names({}) == frozenset()
    assert requests == []


@pytest.mark.parametrize("names", [None, "proxy", [1], ["unknown"]])
def test_unreadable_proxy_names_are_refused(monkeypatch: pytest.MonkeyPatch, names: object) -> None:
    _answer(monkeypatch, {"names": names})

    with pytest.raises(NativeRunnerAuthorityError):
        plan.guard_proxy_server_names({"proxy": {"command": "hol-guard", "args": []}})
