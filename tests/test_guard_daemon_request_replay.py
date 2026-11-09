"""The daemon handler answers a raw request replayed through the Guard CLI."""

from __future__ import annotations

import json
import stat
from pathlib import Path

from codex_plugin_scanner.guard.daemon import request_replay
from codex_plugin_scanner.guard.daemon.request_replay import (
    _PersistedMapping,
    _ReplayState,
    replay_request,
)


def _status(response: bytes) -> int:
    return int(response.split(b"\r\n", 1)[0].split(b" ")[1])


def _body(response: bytes) -> dict[str, object]:
    return json.loads(response.split(b"\r\n\r\n", 1)[1])


def test_replay_answers_health(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard"
    guard_home.mkdir()
    response = replay_request(
        guard_home, b"GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", port=5474, home_dir=tmp_path
    )
    assert _status(response) == 200
    assert _body(response).get("ok") is True


def test_replay_state_survives_between_processes(tmp_path: Path) -> None:
    mapping = _PersistedMapping(_ReplayState(tmp_path), "daemon_discovery_challenges")
    mapping["challenge"] = {"expires_at": 1}
    reread = _PersistedMapping(_ReplayState(tmp_path), "daemon_discovery_challenges")
    assert reread == {"challenge": {"expires_at": 1}}
    state_file = tmp_path / request_replay._STATE_FILENAME
    assert stat.S_IMODE(state_file.stat().st_mode) == 0o600
    reread.pop("challenge")
    assert _PersistedMapping(_ReplayState(tmp_path), "daemon_discovery_challenges") == {}


def test_replay_state_ignores_a_symlinked_file(tmp_path: Path) -> None:
    target = tmp_path / "elsewhere.json"
    target.write_text(json.dumps({"daemon_discovery_challenges": {"x": 1}}))
    (tmp_path / request_replay._STATE_FILENAME).symlink_to(target)
    assert _ReplayState(tmp_path).get("daemon_discovery_challenges") is None
