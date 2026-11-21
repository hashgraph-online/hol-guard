"""HTTP framing for the dashboard's Codex short-replies switch.

A read reports whether Guard's short-reply instruction is in the Codex config.
A write turns it on or off, behind the approval gate the dashboard already
uses for settings changes. The native runtime owns the change.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from ..approval_gate import ApprovalGateError, input_from_mapping, require_high_risk, require_settings_write
from ..codex_lean_sessions import LeanSessionsError
from ..codex_short_replies import disable, enable, status

PATH = "/v1/context-assistance/codex-short-replies"
KIND = "codex_short_replies"
_NO_STORE = {"Cache-Control": "no-store"}


def respond(handler: Any, payload: dict[str, object] | None) -> None:
    home = handler.server.store.guard_home
    try:
        if payload is None:
            state = status(Path.home(), home, os.environ)
        else:
            enabled = payload.get("enabled")
            if not isinstance(enabled, bool):
                handler._write_json({"error": "invalid_codex_short_replies_input"}, status=400, extra_headers=_NO_STORE)
                return
            grant = require_high_risk(home, purpose="settings_write", approval_gate_input=input_from_mapping(payload))
            require_settings_write(home, approval_gate_grant=grant)
            state = (enable if enabled else disable)(Path.home(), home, os.environ)
    except ApprovalGateError as error:
        handler._write_approval_gate_error(error)
        return
    except LeanSessionsError as error:
        _unavailable(handler, error.code)
        return
    except TimeoutError:
        _unavailable(handler, "codex_config_busy")
        return
    except (OSError, RuntimeError, ValueError):
        _unavailable(handler, "codex_config_unavailable")
        return
    handler._write_json(state, extra_headers=_NO_STORE)


def _unavailable(handler: Any, code: str) -> None:
    handler._write_json({"error": "codex_short_replies_unavailable", "code": code}, status=409, extra_headers=_NO_STORE)
