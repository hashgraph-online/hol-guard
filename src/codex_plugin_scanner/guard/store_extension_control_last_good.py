"""Durable last-good export of the local extension-control authority.

The authenticated snapshot normally lives only in ``guard.db``. When that file
is quarantined and re-created, the key and anchor survive in the credential
vault but the controls would be lost. The resident keeps an owner-only copy of
the latest committed snapshot beside the database; this module restores it. The copy is the same
authenticated record the database holds, so it is trusted only after it
verifies under the authority key and matches the vault anchor exactly.
"""

# pyright: reportAttributeAccessIssue=false, reportPrivateUsage=false, reportUnknownArgumentType=false, reportUnknownMemberType=false, reportUnknownVariableType=false

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import cast

from .runtime.extension_control_authority import (
    ExtensionControlAuthorityError,
    layers_from_json,
)
from .store_extension_control_authority_support import _now, _plan_int, _plan_map

_LOGGER = logging.getLogger(__name__)
LAST_GOOD_FILE_NAME = "extension-control-last-good.json"


def _count_controls(layers_json: str) -> int:
    try:
        return sum(len(layer.controls) for layer in layers_from_json(layers_json))
    except ExtensionControlAuthorityError:
        return 0


class ExtensionControlLastGoodMixin:
    """GuardStore mixin that restores the committed authority snapshot."""

    # Human-readable notes for the most recent explicit recovery. CLI callers
    # surface these so a lossy reset is never silent.
    extension_control_recovery_warnings: tuple[str, ...] = ()

    def _last_good_path(self) -> Path:
        return cast(Path, self.guard_home) / LAST_GOOD_FILE_NAME

    def _quarantine_unusable_last_good_export(self) -> bool:
        """Move an export that cannot be applied aside; report whether it moved."""

        path = self._last_good_path()
        if not path.is_file() or path.is_symlink():
            return False
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        try:
            os.replace(path, path.with_name(f"extension-control-last-good.unapplied-{stamp}.json"))
        except OSError:
            return False
        return True

    def _restore_last_good_authority(self, *, key: bytes) -> bool:
        """Re-create the snapshot row from the export when it matches the vault anchor.

        The resident reads and verifies the export, seals any baseline
        transition and writes the rows in one transaction.
        """

        anchor_json = self._read_anchor_json()
        if anchor_json is None:
            return False
        reply = self._extension_control_authority_op("restore", key=key, anchor_json=anchor_json, now=_now())
        if reply.get("restored") is None:
            return False
        restored = _plan_map(reply, "restored")
        revision = _plan_int(restored, "revision")
        control_count = _plan_int(restored, "control_count")
        _LOGGER.warning(
            "Guard restored %d extension control(s) at revision %d from its last-good export.",
            control_count,
            revision,
        )
        return True
