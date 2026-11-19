"""Reachability proof for a recorded Codex app-server target.

Guard's native runtime decides (`codex-app-server-target`): the recorded thread
id must be safe, and the control socket, the recorded one or the default for the
recorded Codex home, must be a trusted local socket that accepts a connection.
This module sends it the recorded target and this process's own home, temporary
and working directories, which bound where the socket may live.
"""

from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Mapping
from pathlib import Path

_FEATURE = "native-codex-app-server-target-v1"
_COMMAND = "codex-app-server-target"
_OUTPUT_LIMIT = 4096
_TIMEOUT_SECONDS = 5.0
_TARGET_KEYS = (
    "codex_thread_id",
    "thread_id",
    "threadId",
    "conversation_id",
    "conversationId",
    "session_id",
    "sessionId",
    "codex_app_server_socket",
    "app_server_socket",
    "appServerSocket",
    "codex_home",
    "codexHome",
)


def codex_app_server_target_reachable(metadata: Mapping[str, object]) -> bool:
    """Prove a recorded Codex target is safe and accepting local connections.

    False when the native runtime cannot be asked: nothing is proven then.
    """

    from .mdm.runtime_request import runtime_answer

    request = {
        "metadata": {key: metadata[key] for key in _TARGET_KEYS if key in metadata},
        "home_dir": str(Path.home()),
        "temp_dir": tempfile.gettempdir(),
        "cwd": os.getcwd(),
    }
    try:
        encoded = json.dumps(request, sort_keys=True, allow_nan=False)
    except (TypeError, ValueError):
        return False
    answer = runtime_answer(_FEATURE, _COMMAND, encoded, output_limit=_OUTPUT_LIMIT, timeout_seconds=_TIMEOUT_SECONDS)
    return answer is not None and answer.get("reachable") is True
