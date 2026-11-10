"""The Guard library route handlers the native daemon hands requests to.

The native daemon owns the socket and answers through library calls; these
are the hook handler methods those calls run, composed for unit tests that
call them directly.
"""

from __future__ import annotations

from codex_plugin_scanner.guard.routes.hook_host import _host_class as _hook_host_class


class GuardDaemonHandler(_hook_host_class()):  # type: ignore[misc]
    """Hook handler methods on one object."""


__all__ = ["GuardDaemonHandler"]
