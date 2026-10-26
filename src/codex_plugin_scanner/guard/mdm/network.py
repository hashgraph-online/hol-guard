"""Enterprise networking facade for Guard managed HTTP clients."""

from __future__ import annotations

from .network_transport import (
    ManagedNetworkError,
    active_network_policy,
    managed_opener,
    managed_requests_session,
    managed_ssl_context,
    managed_urlopen,
    platform_system_proxies,
)

__all__ = [
    "ManagedNetworkError",
    "active_network_policy",
    "managed_opener",
    "managed_requests_session",
    "managed_ssl_context",
    "managed_urlopen",
    "platform_system_proxies",
]
