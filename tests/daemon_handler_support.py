"""A stand-in for the request handler the native daemon replaced.

The native daemon owns the socket and every hook route; unit tests that call
library handler methods directly build them on this bare object.
"""

from __future__ import annotations


class GuardDaemonHandler:
    """A bare handler object tests attach state to."""


__all__ = ["GuardDaemonHandler"]
