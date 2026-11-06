"""Canonical Cline harness protection contract."""

from __future__ import annotations

from .contracts import HarnessProtectionContract, contract_for

_contract = contract_for("cline")
if _contract is None:  # pragma: no cover - import-time invariant
    raise RuntimeError("Cline must be registered in the canonical harness contracts")
CLINE_CONTRACT: HarnessProtectionContract = _contract


def register_cline_contract() -> None:
    """Compatibility no-op: Cline is registered statically with shared contracts."""


register_cline_contract()

__all__ = ["CLINE_CONTRACT", "register_cline_contract"]
