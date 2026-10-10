"""One JSON-safe deep copy shared by the native DTO projections."""

from __future__ import annotations

import json
from typing import Any


def json_safe_copy(value: object) -> Any:
    """JSON-safe deep copy; non-JSON leaves stringify (``default=str``) like every other DTO."""

    return json.loads(json.dumps(value, default=str))
