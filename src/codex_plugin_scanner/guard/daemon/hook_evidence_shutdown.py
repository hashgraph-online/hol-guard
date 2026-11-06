"""One ordered owner for Python evidence producers and their native writer.

HTTP close and service finalization may race. Neither may stop the native
writer while a producer still owns a thread or a dispatch still has work.
Unconfirmed stages retain ownership for a later bounded cleanup attempt.
"""

from __future__ import annotations

import threading
from typing import Any

_OWNERS_LOCK = threading.Lock()


class _EvidenceShutdown:
    def __init__(self, host: object) -> None:
        self.host = host
        self.lock = threading.Lock()
        self.producer_closed = False
        self.dispatch_closed = False
        self.writer_closed = False

    def stop(self, timeout_seconds: float) -> bool:
        if not self.lock.acquire(timeout=max(0.0, timeout_seconds)):
            return False
        try:
            if not self.producer_closed:
                worker = getattr(self.host, "hook_worker", None)
                if worker is not None:
                    close = getattr(worker, "close_contained", None)
                    if not callable(close):
                        close = worker.close
                    if close() is not True:
                        return False
                self.producer_closed = True
            if not self.dispatch_closed:
                dispatch = getattr(self.host, "runtime_hook_evidence_dispatch", None)
                if dispatch is not None and dispatch.stop(timeout_seconds) is not True:
                    return False
                self.dispatch_closed = True
            if not self.writer_closed:
                writer = getattr(self.host, "runtime_hook_evidence_writer", None)
                if writer is not None and writer.stop(timeout_seconds=timeout_seconds) is not True:
                    return False
                self.writer_closed = True
            return True
        except Exception:
            # A native refusal or incomplete producer is not confirmed
            # shutdown. Keep the remaining stages and native journal owned.
            return False
        finally:
            self.lock.release()


def shutdown_hook_evidence(host: Any, *, timeout_seconds: float = 1.0) -> bool:
    """Share stage acknowledgements across every cleanup path for this host."""
    owner = getattr(host, "_hook_evidence_shutdown_owner", None)
    if owner is None:
        with _OWNERS_LOCK:
            owner = getattr(host, "_hook_evidence_shutdown_owner", None)
            if owner is None:
                owner = _EvidenceShutdown(host)
                host._hook_evidence_shutdown_owner = owner
    return owner.stop(timeout_seconds)
