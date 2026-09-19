"""Observe stable controls without excluding concurrent native decisions."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..native_command_control_authority_io import NativeCommandControlMutationRequiredError
from ..runtime.command_extensions import CommandSafetyExtensionRegistry
from ..runtime.extension_control_authority import ExtensionControlAuthorityView

if TYPE_CHECKING:
    from ..store import GuardStore


def read_observed_extension_control_authority(
    store: GuardStore, registry: CommandSafetyExtensionRegistry
) -> ExtensionControlAuthorityView:
    """Use a shared lease until the authenticated reader requires a real transition."""
    try:
        return store.read_extension_control_authority_for_registry(registry, read_only=True)
    except NativeCommandControlMutationRequiredError:
        # The shared lease has unwound. The ordinary mutation-capable reader
        # rechecks current state under EX before applying an actual migration.
        return store.read_extension_control_authority_for_registry(registry)
