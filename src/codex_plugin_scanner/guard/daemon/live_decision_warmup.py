"""Load the live-decision hook facade before the first approval lands."""

from __future__ import annotations

import threading
from typing import Protocol

WARMUP_THREAD_NAME = "codex-live-decision-warm"


class _Diagnostics(Protocol):
    def record_exception(self, event: str) -> object: ...


def start_codex_live_decision_warmup(diagnostics: _Diagnostics) -> threading.Thread:
    """Import the facade on a background thread once the daemon listens.

    Revalidation imports this facade on first use so daemon imports stay
    order-safe. Paid inside a request, that first import holds the import
    lock for about a tenth of a second while the harness waits on the
    completion. A failure is recorded and leaves the import to the request
    path.
    """

    def warm() -> None:
        try:
            from ..cli import commands_support_hook_payload  # noqa: F401
        except Exception:
            diagnostics.record_exception("codex_live_decision_warmup_failed")

    thread = threading.Thread(target=warm, name=WARMUP_THREAD_NAME, daemon=True)
    thread.start()
    return thread
