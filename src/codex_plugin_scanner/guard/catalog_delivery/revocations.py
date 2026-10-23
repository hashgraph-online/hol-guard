"""Revocation outcome raised when native preparation reports a revoked pack."""

from __future__ import annotations


class RevokedPackError(ValueError):
    def __init__(self, identity, epoch):
        self.identity = identity
        self.epoch = epoch
        super().__init__(f"Policy pack {identity} is revoked at epoch {epoch}.")
