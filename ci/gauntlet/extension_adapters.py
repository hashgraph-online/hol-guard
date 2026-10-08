"""Reviewed extension-permission contracts for blocked-extension Gauntlet cases."""

from __future__ import annotations

import shlex
from dataclasses import dataclass


@dataclass(frozen=True)
class ExtensionAdapter:
    """One executable whose disabled permission the runner signs and the oracle verifies."""

    executable: str
    extension_id: str
    rule_id: str
    permission_id: str
    label: str


# The oracle checks native evidence against this table, not against the
# installed catalog, so a catalog that remaps a rule cannot pass silently.
EXTENSION_ADAPTERS = {
    adapter.executable: adapter
    for adapter in (
        ExtensionAdapter(
            "ollama",
            "command.ollama",
            "command.ollama.rm",
            "command.ollama.permission.rm",
            "ollama remove",
        ),
        ExtensionAdapter(
            "gws",
            "command.google-workspace.gws",
            "command.google-workspace.gws.send",
            "command.google-workspace.gws.permission.send",
            "Google Workspace send",
        ),
        ExtensionAdapter(
            "sf",
            "command.salesforce.sf",
            "command.salesforce.sf.delete",
            "command.salesforce.sf.permission.delete",
            "Salesforce delete",
        ),
    )
}


def extension_adapter(command: str) -> ExtensionAdapter:
    """Return the reviewed adapter for a single-command blocked-extension case."""
    try:
        words = shlex.split(command)
    except ValueError as error:
        raise ValueError("blocked-extension command is not valid shell syntax") from error
    adapter = EXTENSION_ADAPTERS.get(words[0]) if words else None
    if adapter is None:
        raise ValueError("blocked-extension command has no reviewed extension adapter")
    return adapter
