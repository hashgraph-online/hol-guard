"""Guard schema helpers.

The two contract builders load on first use. Importing any schema module,
such as the event schema every Guard store loads, otherwise pulled in the
plugin scanner and its checks, and the daemon's worker host paid for that on
every cold start.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .consumer_mode import build_consumer_mode_contract
    from .surface_server import build_surface_server_contract

__all__ = ["build_consumer_mode_contract", "build_surface_server_contract"]


def __getattr__(name: str) -> Any:
    if name == "build_consumer_mode_contract":
        from .consumer_mode import build_consumer_mode_contract

        return build_consumer_mode_contract
    if name == "build_surface_server_contract":
        from .surface_server import build_surface_server_contract

        return build_surface_server_contract
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
