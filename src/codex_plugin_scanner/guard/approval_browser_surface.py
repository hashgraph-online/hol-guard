"""R-SURFACE glue: ask the native runtime whether a live browser session holds the approval page.

The native ``approval_browser_surface`` authority kind owns the decision. While an agent drives a
shared browser profile or a browser reached through a debugging port, Guard opens no approval page
automatically; the request stays on every other surface and its link is shown to the person.
"""

from __future__ import annotations

import os
from pathlib import Path

_TIMEOUT_SECONDS = 2.0


def approval_page_held(guard_home: Path) -> bool:
    """Whether a live browser session holds the automatic approval page.

    A runtime that cannot answer holds nothing, so the page opens as the surface policy says.
    """

    from .native_runner_authority import native_runner_authority

    try:
        answer = native_runner_authority(
            "approval_browser_surface",
            {"guard_home": os.fspath(guard_home)},
            guard_home,
            timeout_seconds=_TIMEOUT_SECONDS,
        )
    except Exception:
        return False
    return isinstance(answer, dict) and answer.get("approval_page_held") is True
