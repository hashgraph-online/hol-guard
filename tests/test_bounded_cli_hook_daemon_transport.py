from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlparse

import pytest

from codex_plugin_scanner.guard.adapters import bounded_cli_hook_daemon as daemon
from codex_plugin_scanner.guard.daemon import auth_token as auth_token_module


@pytest.mark.parametrize("url", ["https://127.0.0.1:4781/hook", "http://example.com/hook"])
def test_loopback_url_rejects_wrong_scheme_and_remote_host(url: str) -> None:
    with pytest.raises(ValueError):
        daemon._assert_loopback_http_url(url)


def test_loopback_opener_disables_proxies_and_installs_redirect_guard(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    handlers: list[object] = []
    sentinel = cast(Any, object())

    def build(*items: object) -> urllib.request.OpenerDirector:
        handlers.extend(items)
        return sentinel

    monkeypatch.setattr(daemon.urllib.request, "build_opener", build)

    assert daemon._build_loopback_opener() is sentinel
    proxy = next(item for item in handlers if isinstance(item, urllib.request.ProxyHandler))
    assert cast(Any, proxy).proxies == {}
    assert any(isinstance(item, daemon._LoopbackOnlyRedirectHandler) for item in handlers)


def test_redirect_guard_rejects_remote_target_before_following() -> None:
    handler: Any = daemon._LoopbackOnlyRedirectHandler()
    request = urllib.request.Request("http://127.0.0.1:4781/start")

    with pytest.raises(ValueError, match="loopback"):
        handler.redirect_request(request, None, 302, "Found", {}, "http://example.com/escape")

    redirected = handler.redirect_request(request, None, 302, "Found", {}, "http://localhost:4781/next")
    assert redirected is not None
    assert redirected.full_url == "http://localhost:4781/next"


@pytest.mark.parametrize("stored, expected", [("secret", "secret"), ("", None), (None, None)])
def test_daemon_auth_token_preserves_only_nonempty_private_text(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    stored: str | None,
    expected: str | None,
) -> None:
    seen: dict[str, object] = {}

    def read(path: Path, **kwargs: object) -> str | None:
        seen.update(path=path, **kwargs)
        return stored

    monkeypatch.setattr(auth_token_module, "read_private_regular_text", read)
    guard_home = tmp_path / "guard-home"

    assert daemon._read_daemon_auth_token(guard_home) == expected
    assert seen == {
        "path": guard_home / "daemon-auth-token",
        "max_bytes": 4096,
        "require_private_parent": True,
    }


@pytest.mark.parametrize(
    ("state", "expected"),
    [
        (None, None),
        ("not-json", None),
        ("[]", None),
        ('{"host":1,"port":4781}', None),
        ('{"host":"example.com","port":4781}', None),
        ('{"host":"::2","port":4781}', None),
        ('{"host":"[::1]","port":4781}', None),
        ('{"host":"127.0.0.1","port":"4781"}', None),
        ('{"host":"127.0.0.1","port":true}', None),
        ('{"host":"127.0.0.1","port":0}', None),
        ('{"host":"localhost","port":4781}', "http://localhost:4781/v1/hooks/grok"),
        ('{"host":"::1","port":4781}', "http://[::1]:4781/v1/hooks/grok"),
    ],
)
def test_daemon_endpoint_accepts_only_valid_loopback_state(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    state: str | None,
    expected: str | None,
) -> None:
    monkeypatch.setattr(daemon, "read_private_regular_text", lambda *_args, **_kwargs: state)
    assert daemon._daemon_hook_endpoint(tmp_path, "grok") == expected


def test_ipv6_daemon_endpoint_is_parseable_and_accepted_by_transport() -> None:
    endpoint = "http://[::1]:4781/v1/hooks/grok"
    parsed = urlparse(endpoint)
    assert (parsed.hostname, parsed.port) == ("::1", 4781)
    daemon._assert_loopback_http_url(endpoint)

    response = _Response(body=b'{"policy_action":"allow"}', final_url=endpoint)
    result = daemon.try_daemon_hook(
        guard_home=Path("/private/unused"),
        harness="grok",
        input_text='{"hook_event_name":"PreToolUse"}',
        timeout_seconds=2,
        _endpoint_loader=lambda *_args: endpoint,
        _token_loader=lambda _path: "token",
        _opener_builder=lambda: cast(Any, _Opener(response)),
    )

    assert result is not None
    stdout, stderr, code = result
    assert json.loads(stdout)["decision"] == "allow"
    assert (stderr, code) == ("", 0)


class _Response:
    def __init__(self, *, body: bytes, status: int = 200, final_url: str = "") -> None:
        self.body = body
        self.status = status
        self.final_url = final_url

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def geturl(self) -> str:
        return self.final_url

    def read(self, _limit: int) -> bytes:
        return self.body


class _Opener:
    def __init__(self, outcome: _Response | Exception) -> None:
        self.outcome = outcome

    def open(self, _request: object, *, timeout: float) -> _Response:
        assert 0 < timeout <= daemon._DAEMON_TIMEOUT_BUDGET_SECONDS
        if isinstance(self.outcome, Exception):
            raise self.outcome
        return self.outcome


def _try_with(outcome: _Response | Exception) -> tuple[str, str, int] | None:
    return daemon.try_daemon_hook(
        guard_home=Path("/private/unused"),
        harness="grok",
        input_text='{"hook_event_name":"PreToolUse"}',
        timeout_seconds=20,
        _endpoint_loader=lambda *_args: "http://127.0.0.1:4781/v1/hooks/grok",
        _token_loader=lambda _path: "token",
        _opener_builder=lambda: cast(Any, _Opener(outcome)),
    )


@pytest.mark.parametrize(
    "outcome",
    [
        _Response(body=b"{}", status=503),
        _Response(body=b"{}", final_url="http://example.com/redirect"),
        _Response(body=b"x" * (daemon._MAX_HOOK_RESPONSE_BYTES + 1)),
        _Response(body=b"\xff"),
        _Response(body=b"   "),
        _Response(body=b"not-json"),
        _Response(body=b"[]"),
        urllib.error.URLError("offline"),
        TimeoutError("slow"),
    ],
)
def test_daemon_transport_rejects_invalid_or_untrusted_responses(outcome: _Response | Exception) -> None:
    assert _try_with(outcome) is None


def test_daemon_transport_requires_endpoint_and_token() -> None:
    common: dict[str, Any] = {
        "guard_home": Path("/private/unused"),
        "harness": "grok",
        "input_text": "{}",
        "timeout_seconds": 2,
    }
    assert daemon.try_daemon_hook(**common, _endpoint_loader=lambda *_args: None) is None
    assert (
        daemon.try_daemon_hook(
            **common,
            _endpoint_loader=lambda *_args: "http://example.com/hook",
            _token_loader=lambda _path: "token",
        )
        is None
    )
    assert (
        daemon.try_daemon_hook(
            **common,
            _endpoint_loader=lambda *_args: "http://127.0.0.1:4781/hook",
            _token_loader=lambda _path: None,
        )
        is None
    )


def test_hermes_daemon_response_uses_harness_native_translation(monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard.adapters import hermes_runtime_hooks

    expected = ('{"decision":"allow"}', "", 0)
    deadlines: list[object] = []

    def bridge(*_args: object, **kwargs: object) -> tuple[str, str, int]:
        deadlines.append(kwargs.get("deadline"))
        return expected

    monkeypatch.setattr(hermes_runtime_hooks, "hermes_bridge_response", bridge)
    started = time.monotonic()
    result = daemon.try_daemon_hook(
        guard_home=Path("/private/unused"),
        harness="hermes",
        input_text='{"hook_event_name":"PreToolUse"}',
        timeout_seconds=2,
        _endpoint_loader=lambda *_args: "http://127.0.0.1:4781/v1/hooks/hermes",
        _token_loader=lambda _path: "token",
        _opener_builder=lambda: cast(Any, _Opener(_Response(body=b'{"x":1}'))),
    )
    assert result == expected
    # The render inherits the hook's absolute deadline rather than a fresh timeout.
    assert len(deadlines) == 1
    assert isinstance(deadlines[0], float)
    assert started < deadlines[0] <= time.monotonic() + 2


def test_native_response_edge_contracts() -> None:
    assert daemon._native_hook_permission_decision("unknown") is None
    assert daemon._should_exit_block("copilot", "PreToolUse", "block") is False

    stdout, stderr, code = daemon._daemon_response_to_native(
        {
            "hookSpecificOutput": {
                "permissionDecision": "deny",
                "permissionDecisionReason": "blocked",
            }
        },
        harness="kimi",
        event_name="PreToolUse",
    )
    assert json.loads(stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert (stderr, code) == ("blocked", 2)

    stdout, _stderr, code = daemon._daemon_response_to_native(
        {"policy_action": "allow"},
        harness="codex",
        event_name="UserPromptSubmit",
    )
    assert json.loads(stdout) == {"hookSpecificOutput": {"hookEventName": "UserPromptSubmit"}}
    assert code == 0

    stdout, _stderr, code = daemon._daemon_response_to_native(
        {"policy_action": "block", "reason": "blocked"},
        harness="codex",
        event_name="UserPromptSubmit",
    )
    assert json.loads(stdout)["continue"] is False
    assert code == 0


def test_grok_wait_ignores_malformed_native_output(tmp_path: Path) -> None:
    original = ("not-json", "stderr", 2)
    assert (
        daemon._apply_grok_bridge_approval_wait(
            guard_home=tmp_path,
            harness="grok",
            input_text='{"hook_event_name":"PreToolUse"}',
            stdout=original[0],
            stderr=original[1],
            exit_code=original[2],
        )
        == original
    )


@pytest.mark.parametrize(
    ("harness", "event_name", "minimum", "maximum"),
    [
        ("zcode", "UserPromptSubmit", 9.0, 10.0),
        ("hermes", "UserPromptSubmit", 9.0, 10.0),
        ("zcode", "PreToolUse", 0.0, daemon._DAEMON_TIMEOUT_BUDGET_SECONDS),
    ],
)
def test_prompt_transport_waits_for_cold_workspace_publication(
    harness: str, event_name: str, minimum: float, maximum: float
) -> None:
    timeouts: list[float] = []

    class _RecordingOpener:
        def open(self, _request: object, *, timeout: float) -> _Response:
            timeouts.append(timeout)
            return _Response(body=b'{"policy_action":"allow"}')

    daemon.try_daemon_hook(
        guard_home=Path("/private/unused"),
        harness=harness,
        input_text=json.dumps({"hook_event_name": event_name, "cwd": "/private/unused"}),
        timeout_seconds=25,
        _endpoint_loader=lambda *_args: f"http://127.0.0.1:4781/v1/hooks/{harness}",
        _token_loader=lambda _path: "token",
        _opener_builder=lambda: cast(Any, _RecordingOpener()),
    )
    assert len(timeouts) == 1
    assert minimum < timeouts[0] <= maximum
