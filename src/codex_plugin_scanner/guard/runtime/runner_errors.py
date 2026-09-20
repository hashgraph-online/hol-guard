"""Shared Guard Cloud synchronization exception types."""

from __future__ import annotations


class GuardSyncNotConfiguredError(RuntimeError):
    """Raised when Guard Cloud sync is requested before the machine is paired."""


class GuardSyncEndpointUntrustedError(GuardSyncNotConfiguredError):
    """Raised when a configured Guard Cloud endpoint fails trust validation."""


class GuardSyncNotAvailableError(RuntimeError):
    """Raised when Guard Cloud sync is blocked by plan limits or temporary outages."""

    retryable: bool

    def __init__(self, message: str, *, retryable: bool = False) -> None:
        super().__init__(message)
        self.retryable = retryable


class GuardSyncAuthorizationExpiredError(GuardSyncNotConfiguredError):
    """Raised when local OAuth material can no longer mint a runtime access token."""
