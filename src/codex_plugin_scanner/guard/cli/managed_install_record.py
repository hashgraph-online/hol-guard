"""The native record step of a managed install or uninstall.

The runtime binds each install proof, writes and reads back the
managed-install row, and installs or removes the agent safety guidance.
"""

from __future__ import annotations

import json
from typing import Any

from ..codex_install_transaction import codex_install_transaction
from ..harness.base import HarnessContext
from ..managed_install_revision import bump_managed_install_revision
from ..runtime_transition import TransitionError
from ..store import GuardStore


def _native_install_ask(op: str, context: HarnessContext, **fields: Any) -> dict[str, Any]:
    """One managed-install op; a pending runtime transition refuses as before."""
    from ..harness.native_harness import ask

    try:
        return ask(op, context, **fields)
    except ValueError as error:
        if str(error) == "pending_transition":
            raise TransitionError("pending_transition") from None
        raise


def _record_managed_install(
    command: str,
    harness: str,
    manifest: dict[str, object],
    context: HarnessContext,
    store: GuardStore,
    workspace: str | None,
    now: str,
) -> dict[str, object] | None:
    """Bind the proof, write the row and read it back, natively, under the store's owner."""
    try:
        with codex_install_transaction(store.guard_home, store.path, actor="managed-install-record"):
            answer = _native_install_ask(
                "managed_install_record",
                context,
                command=command,
                target=harness,
                manifest=json.dumps(manifest, default=lambda _: None),
                workspace=workspace,
                now=now,
                source=store.guard_source,
            )
    finally:
        bump_managed_install_revision()
    row = answer.get("row")
    if not isinstance(row, dict):
        return None
    return {
        "harness": str(row["harness"]),
        "active": bool(row["active"]),
        "workspace": row["workspace"],
        "manifest": json.loads(str(row["manifest_json"])),
        "updated_at": str(row["updated_at"]),
    }
