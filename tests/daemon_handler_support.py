"""The Guard library route handlers the native daemon hands requests to.

The native daemon owns the socket and answers through library calls; these
are the handler methods those calls run, composed for unit tests that call
them directly.
"""

from __future__ import annotations

from codex_plugin_scanner.guard.routes.control_host import _host_class as _control_host_class
from codex_plugin_scanner.guard.routes.hook_host import _host_class as _hook_host_class


class GuardDaemonHandler(_control_host_class(), _hook_host_class()):  # type: ignore[misc]
    """Control and hook handler methods on one object."""


__all__ = ["GuardDaemonHandler"]
