"""Inventory evidence enrichment and safe source-of-truth inspection.

The item grammar this module used to carry — the kind an artifact type maps
onto, the content hash it settles on, its capability set and its risk level —
now lives in the native runtime behind the `inventory_item_classification`
operation. What stays here reaches other Python modules for detection and
trust evidence, which the caller still gathers before it asks.
"""

from __future__ import annotations

import importlib
from pathlib import Path

from .inventory_contract_models import InventoryItemKind


def _aibom_detection_module():
    """Load source-of-truth detection lazily to avoid inventory initialization cycles."""
    return importlib.import_module(".aibom_detection", __package__)


def _aibom_trust_metadata_module():
    """Load trust metadata enrichment without eagerly initializing its dependencies."""
    return importlib.import_module(".aibom_trust_metadata", __package__)


def _inventory_item_description_module():
    """Load native item description helpers through their existing module interface."""
    return importlib.import_module(".inventory_item_description", __package__)


def _apply_aibom_metadata_enrichment(
    artifact: object,
    *,
    captured_at: str,
    item_kind: InventoryItemKind,
    metadata: dict[str, object],
    home_dir: Path,
    workspace_dir: Path | None,
    instruction_role: str | None = None,
    cisco_runs: tuple[object, ...] = (),
) -> dict[str, object]:
    """Add inventory detection, symlink, and trust evidence through established helpers.

    ``instruction_role`` is the resident's reading of what an overlay's
    configured path names. It is not derived here: the discovery walk reads
    the same grammar in the native runtime, and a second copy of it is how the
    role a snapshot records and the role discovery assigned come apart.
    """
    enriched = dict(metadata)
    artifact_type = str(getattr(artifact, "artifact_type", "unknown"))
    if artifact_type == "skill":
        from .skill_document_evidence import enrich_skill_document_metadata

        enriched = enrich_skill_document_metadata(
            getattr(artifact, "config_path", None),
            enriched,
            home_dir=home_dir,
            workspace_dir=workspace_dir,
        )
    if instruction_role and "instructionRole" not in enriched:
        enriched["instructionRole"] = instruction_role
    return _aibom_trust_metadata_module().apply_local_trust_metadata(
        artifact,
        captured_at=captured_at,
        item_kind=item_kind,
        metadata=enriched,
        workspace_dir=workspace_dir,
        cisco_runs=cisco_runs,
    )
