"""Deliver connector setup notices for native queued reviews.

The resident performs connector classification and launch lookup inside the
queue operation. Python only forwards the stored connector identity to the
desktop notice path.
"""

from __future__ import annotations


def raise_connector_setup_notice(store: object, queued: object) -> None:
    """Raise the desktop notice for a queued native connector row."""

    if not isinstance(queued, dict):
        return
    setup = queued.get("connector_setup")
    name = setup.get("name") if isinstance(setup, dict) else None
    if not isinstance(name, str) or not name:
        return
    from ..approvals import notify_connector_setup

    notify_connector_setup(store, queued, connector_name=name)


__all__ = ["raise_connector_setup_notice"]
