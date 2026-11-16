"""HTTP framing for the dashboard's usage meter.

The first read of a large history runs in the background; until it finishes
the route answers `counting` and the page asks again.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from ..context_usage_meter import METER

PATH = "/v1/context-assistance/usage"
KIND = "usage"


def respond(handler: Any) -> None:
    state = METER.read(Path.home(), handler.server.store.guard_home, os.environ)
    handler._write_json(state, extra_headers={"Cache-Control": "no-store"})
