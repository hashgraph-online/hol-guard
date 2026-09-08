"""Installed-wheel hook client used by native runtime probes."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from codex_plugin_scanner.guard.adapters.claude_daemon_hook_transport import authenticated_claude_hook_response
from codex_plugin_scanner.guard.adapters.codex_daemon_hook_transport import _daemon_response_once
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer


def installed_hook_request(
    daemon: GuardDaemonServer,
    guard_home: Path,
    workspace: Path,
    harness: str,
    event: str,
    payload: dict[str, object],
) -> dict[str, object] | None:
    """Send a probe request through the harness's production authentication path."""

    query = urllib.parse.urlencode({"home": str(guard_home), "workspace": str(workspace)})
    encoded = json.dumps(payload, separators=(",", ":"))
    if harness == "codex":
        return _daemon_response_once(
            state_path=guard_home / "daemon-state.json",
            query=query,
            data=encoded,
            timeout_seconds=5,
        )
    if harness == "claude-code":
        decoded = json.loads(
            authenticated_claude_hook_response(
                state_path=guard_home / "daemon-state.json",
                query=query,
                data=encoded,
                timeout_seconds=5,
            )
        )
        return decoded if isinstance(decoded, dict) else None
    request = urllib.request.Request(
        f"http://127.0.0.1:{daemon.port}/v1/hooks/{harness}?{query}",
        data=encoded.encode("utf-8"),
        headers={"Content-Type": "application/json", "X-Guard-Token": daemon._server.auth_token},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            decoded = json.loads(response.read().decode("utf-8"))
            return decoded if isinstance(decoded, dict) else None
    except urllib.error.HTTPError as error:
        detail = error.read().decode("utf-8", errors="replace")[:512]
        raise RuntimeError(
            f"installed hook corpus request failed: harness={harness} event={event} status={error.code} body={detail}"
        ) from error
