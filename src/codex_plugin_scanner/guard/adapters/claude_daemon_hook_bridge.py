"""Claude Code daemon hook bridge executed by the same Python as Guard."""

from __future__ import annotations

import json
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

from ..daemon.manager import load_guard_daemon_auth_token
from .claude_code import CLAUDE_GUARD_DAEMON_HOOK_MARKER

_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
_DEGRADED_DAEMON_MESSAGE = (
    "HOL Guard could not reach the local daemon ({reason}), so it is using Claude's native "
    "approval prompt as a temporary safety fallback."
)
_PRETOOLUSE_DEGRADED_SUFFIX = (
    " Keep this action blocked unless you intentionally trust it. Restart Guard to restore the "
    "branded Allow once / Allow during this session / Keep blocked flow."
)
_RISKY_PROMPT_SYSTEM_MESSAGE = (
    "HOL Guard intercepted this prompt because it asks Claude to access local secrets. If Claude "
    "asks to continue, HOL Guard will route the decision through a branded approval prompt."
)
_RISKY_PROMPT_ADDITIONAL_CONTEXT = (
    "HOL Guard will intercept Claude's next attempt to access local secrets and open a branded "
    "approval question to protect you."
)


def main(
    *,
    state_path: str | Path,
    fallback_daemon_url: str,
    fallback_command: tuple[str, ...],
    query: str,
) -> int:
    """Proxy Claude hook stdin to the Guard daemon, falling back to the Python hook."""

    _ = CLAUDE_GUARD_DAEMON_HOOK_MARKER
    body = sys.stdin.read()
    data = body.strip() or "{}"
    try:
        endpoint = urljoin(_daemon_url(state_path, fallback_daemon_url), f"/v1/hooks/claude-code?{query}")
        _assert_loopback_http_url(endpoint)
        response_body = _post_to_loopback_daemon(endpoint, data, state_path=state_path)
    except ValueError as error:
        sys.stdout.write(_run_local_fallback(str(error), data, fallback_command))
        return 0
    except urllib.error.HTTPError as error:
        detail = error.read().decode("utf-8", errors="replace")
        reason = f"daemon returned HTTP {error.code}"
        if detail.strip():
            reason = f"{reason}: {detail.strip()}"
        sys.stdout.write(_run_local_fallback(reason, data, fallback_command))
        return 0
    except urllib.error.URLError as error:
        reason = str(error.reason or error)
        sys.stdout.write(_run_local_fallback(reason, data, fallback_command))
        return 0
    except Exception as error:
        sys.stdout.write(_run_local_fallback(str(error), data, fallback_command))
        return 0
    if _should_suppress_output(data, response_body):
        return 0
    sys.stdout.write(response_body if response_body.strip() else "{}")
    return 0


def _build_loopback_opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        _LoopbackOnlyRedirectHandler(),
    )


class _LoopbackOnlyRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _assert_loopback_http_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _assert_loopback_http_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme != "http":
        raise ValueError(f"daemon URL must use http, not {parsed.scheme!r}")
    host = (parsed.hostname or "").lower()
    if host not in _LOOPBACK_HOSTS:
        raise ValueError(f"daemon URL must target loopback, not {host!r}")
    if parsed.port is None:
        raise ValueError("daemon URL must include an explicit port")


def _post_to_loopback_daemon(endpoint: str, data: str, *, state_path: str | Path) -> str:
    auth_token = load_guard_daemon_auth_token(Path(state_path).parent)
    headers = {"Content-Type": "application/json"}
    if isinstance(auth_token, str) and auth_token.strip():
        headers["X-Guard-Token"] = auth_token
    request = urllib.request.Request(
        endpoint,
        data=data.encode("utf-8"),
        headers=headers,
        method="POST",
    )
    opener = _build_loopback_opener()
    with opener.open(request, timeout=30) as response:
        final_url = response.geturl()
        if final_url:
            _assert_loopback_http_url(final_url)
        return response.read().decode("utf-8", errors="replace")


def _daemon_url(state_path: str | Path, fallback_daemon_url: str) -> str:
    path = Path(state_path)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(payload, dict):
            port = payload.get("port")
            if isinstance(port, int):
                return f"http://127.0.0.1:{port}/"
    except (OSError, ValueError):
        pass
    normalized = fallback_daemon_url.rstrip("/") + "/"
    _assert_loopback_http_url(normalized)
    return normalized


def _event_name(data: str) -> str:
    try:
        payload = json.loads(data or "{}")
    except json.JSONDecodeError:
        return "PreToolUse"
    if not isinstance(payload, dict):
        return "PreToolUse"
    event = payload.get("hook_event_name", payload.get("event", "PreToolUse"))
    return str(event or "PreToolUse")


def _prompt_text(data: str) -> str:
    try:
        payload = json.loads(data or "{}")
    except json.JSONDecodeError:
        return ""
    if not isinstance(payload, dict):
        return ""
    prompt = payload.get("prompt", payload.get("user_prompt", ""))
    return str(prompt or "")


def _degraded_prompt(data: str) -> str:
    prompt = _prompt_text(data).lower()
    risky = any(token in prompt for token in (".env", "secret", "api key", "token"))
    if risky:
        return json.dumps(
            {
                "systemMessage": _RISKY_PROMPT_SYSTEM_MESSAGE,
                "hookSpecificOutput": {
                    "hookEventName": "UserPromptSubmit",
                    "additionalContext": _RISKY_PROMPT_ADDITIONAL_CONTEXT,
                },
            },
            separators=(",", ":"),
        )
    return json.dumps({"hookSpecificOutput": {"hookEventName": "UserPromptSubmit"}}, separators=(",", ":"))


def _degraded(reason: str, data: str) -> str:
    event = _event_name(data)
    message = _DEGRADED_DAEMON_MESSAGE.format(reason=reason)
    if event == "UserPromptSubmit":
        return _degraded_prompt(data)
    if event == "PreToolUse":
        return json.dumps(
            {
                "systemMessage": (
                    "HOL Guard could not reach the local daemon, so it cannot render the full HOL Guard approval flow."
                ),
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "ask",
                    "permissionDecisionReason": message + _PRETOOLUSE_DEGRADED_SUFFIX,
                },
            },
            separators=(",", ":"),
        )
    return "{}"


def _should_suppress_output(data: str, response_body: str) -> bool:
    if _event_name(data) != "UserPromptSubmit":
        return False
    trimmed = (response_body or "").strip()
    return trimmed in {"", "{}"}


def _run_local_fallback(reason: str, data: str, fallback_command: tuple[str, ...]) -> str:
    try:
        result = subprocess.run(
            list(fallback_command),
            input=data,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return _degraded(f"{reason}; fallback failed: {error}", data)
    if result.returncode == 0:
        stdout = (result.stdout or "").strip()
        if _should_suppress_output(data, stdout):
            return ""
        return stdout if stdout else "{}"
    detail = (result.stderr or result.stdout or "").strip()
    suffix = f"; fallback exited {result.returncode}"
    if detail:
        suffix = f"{suffix}: {detail}"
    return _degraded(f"{reason}{suffix}", data)


def _bridge_config_from_argv(argv: list[str]) -> dict[str, Any]:
    if len(argv) != 2:
        raise SystemExit("claude_daemon_hook_bridge expects one JSON config argument")
    payload = json.loads(argv[1])
    if not isinstance(payload, dict):
        raise SystemExit("claude_daemon_hook_bridge config must be a JSON object")
    fallback_command = payload.get("fallback_command")
    if not isinstance(fallback_command, list) or not fallback_command:
        raise SystemExit("claude_daemon_hook_bridge config missing fallback_command")
    config: dict[str, Any] = {}
    for required_key in ("state_path", "fallback_daemon_url", "query"):
        if required_key not in payload:
            raise SystemExit(f"claude_daemon_hook_bridge config missing {required_key!r}")
        config[required_key] = str(payload[required_key])
    config["fallback_command"] = tuple(str(item) for item in fallback_command)
    return config


if __name__ == "__main__":
    config = _bridge_config_from_argv(sys.argv)
    raise SystemExit(
        main(
            state_path=config["state_path"],
            fallback_daemon_url=config["fallback_daemon_url"],
            fallback_command=config["fallback_command"],
            query=config["query"],
        )
    )
