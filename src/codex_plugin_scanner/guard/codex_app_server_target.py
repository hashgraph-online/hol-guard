"""Reachability proof for a recorded Codex app-server target."""

from __future__ import annotations

import socket
from collections.abc import Mapping
from pathlib import Path

from .codex_app_server import (
    _CODEX_HOME_KEYS,
    _SOCKET_KEYS,
    _THREAD_ID_KEYS,
    _first_string,
    _is_safe_codex_thread_id,
    _is_safe_local_socket_path,
    _is_trusted_local_socket,
    default_codex_app_server_socket_path,
)


def codex_app_server_target_reachable(metadata: Mapping[str, object]) -> bool:
    """Prove a recorded Codex target is safe and accepting local connections."""

    thread_id = _first_string(metadata, _THREAD_ID_KEYS)
    if thread_id is None or not _is_safe_codex_thread_id(thread_id):
        return False
    codex_home = _first_string(metadata, _CODEX_HOME_KEYS)
    socket_path = _first_string(metadata, _SOCKET_KEYS) or str(
        default_codex_app_server_socket_path(environ={"CODEX_HOME": codex_home or ""})
    )
    if not _is_safe_local_socket_path(socket_path) or not _is_trusted_local_socket(Path(socket_path).expanduser()):
        return False
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(0.2)
            client.connect(str(Path(socket_path).expanduser()))
    except OSError:
        return False
    return True
