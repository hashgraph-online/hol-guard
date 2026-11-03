"""The supply chain detector of a workspace assessment run.

Each package the local audit asks about, blocks or warns on becomes one
finding named by its coordinate: ecosystem, scoped name and resolved version.
New rule data, a second lockfile listing the same package or another advisory
adds evidence to that finding instead of making a new one. A package whose
lookup could not be answered offline is a coverage gap, not a finding. The
resident owns that projection; see ``native_workspace_package_findings``.
"""

from __future__ import annotations

from typing import Final

SUPPLY_CHAIN_DETECTOR: Final = "supply_chain_local_v1"

__all__ = ["SUPPLY_CHAIN_DETECTOR"]
