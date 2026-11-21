"""How a failed ``hol-guard install`` reports itself."""

from __future__ import annotations

import json
import sys
from typing import TextIO


def report_install_failure(error: Exception, as_json: bool, output_stream: TextIO | None = None) -> None:
    """Name a failed install on stderr, and on stdout as JSON when asked for it."""
    message = str(error)
    print(message, file=sys.stderr)
    if as_json:
        reason = getattr(error, "reason", None)
        failure: dict[str, object] = {"status": "failed", "message": message}
        if isinstance(reason, str) and reason:
            failure["error"] = reason
        print(json.dumps(failure, indent=2), file=output_stream or sys.stdout)
