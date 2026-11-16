"""Hermes through the native ``harness_adapter`` kind.

The kind owns Hermes's paths, detection (the skill directory identities
included), the MCP overlay, the pre-tool hook payload, the Guard entries in
``config.yaml`` and its shell-hooks allowlist, the authenticated manifest,
uninstall, the launch environment, the runtime probe, the doctor warning and
the proxy launch of each local stdio server. It asks this process for
nothing.
"""

from __future__ import annotations

from .base import HarnessContext, PreparedHarnessInstall
from .native_harness import NativeHarnessAdapter

_HARNESS = "hermes"


class HermesHarnessAdapter(NativeHarnessAdapter):
    """Hermes skills, MCP servers and its ``hooks.pre_tool_call`` entry."""

    def __init__(self) -> None:
        super().__init__(_HARNESS, (), "")

    def install(self, context: HarnessContext) -> dict[str, object]:
        return super().install(context)

    def prepare_install(self, context: HarnessContext) -> PreparedHarnessInstall:
        """Unavailable: the plan signs its manifest, which may create the state key."""
        from ..runtime_transition import TransitionError

        raise TransitionError("adapter_preparation_unavailable")
