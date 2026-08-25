"""Named remaining-step errors for supply-chain restore."""

from __future__ import annotations


class SupplyChainRepairDeferredError(Exception):
    """A recovery step still needs a named user action instead of another silent retry."""

    def __init__(self, *, code: str, message: str, action: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.action = action


__all__ = ["SupplyChainRepairDeferredError"]
