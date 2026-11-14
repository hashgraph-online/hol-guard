"""HTTP framing for the dashboard's usage meter.

The first read of a large history runs in the background; until it finishes
the route answers `counting` and the page asks again.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from ..context_usage_meter import METER
from ..native_context_assistance import ContextAssistanceError, savings

PATH = "/v1/context-assistance/usage"
KIND = "usage"


def respond(handler: Any) -> None:
    guard_home = handler.server.store.guard_home
    state = METER.read(Path.home(), guard_home, os.environ)
    # An older or stopped resident has no estimate; the meter still shows.
    try:
        state = {**state, "savings": savings(guard_home=guard_home)}
    except ContextAssistanceError:
        state = {**state, "savings": None}
    handler._write_json(state, extra_headers={"Cache-Control": "no-store"})
