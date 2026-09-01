"""OptiQra harness adapter.

OptiQra is a website auditing/optimization tool whose ``/api/auto-fix-project``
endpoint lets a model propose and apply code fixes to an uploaded project.
Unlike the CLI/IDE harnesses this package otherwise adapts (Kimi, ZCode, Pi,
Hermes, ...), OptiQra has no local, on-disk configuration for Guard to
discover or write a managed hook block into: it is a service that resolves
its own fix actions and is expected to call ``guard hook --harness optiqra``
directly from its own backend, once per resolved file-write action, before
that action is applied.

This adapter therefore only registers OptiQra's harness identity (so runtime
hook payloads, decisions, and receipts attribute correctly) and reports an
honest "not locally installed" detection instead of inventing a config-file
discovery step that does not exist for this integration shape.
"""

from __future__ import annotations

from ..models import HarnessDetection
from .base import HarnessAdapter, HarnessContext


class OptiQraHarnessAdapter(HarnessAdapter):
    """Attribute OptiQra's ``auto-fix-project`` actions to Guard decisions."""

    harness = "optiqra"
    aliases = ("optiqra",)
    executable = ""
    approval_tier = "approval-center"
    approval_summary = (
        "Guard evaluates the resolved fix action and final diff OptiQra proposes before "
        "/api/auto-fix-project writes it, and routes anything that isn't a clean allow "
        "through the local approval center."
    )
    fallback_hint = (
        "OptiQra has no local Guard shim to repair; confirm its backend calls "
        "`guard hook --harness optiqra` before applying auto-fix writes."
    )

    def detect(self, context: HarnessContext) -> HarnessDetection:
        """Report OptiQra's install state honestly.

        OptiQra has no local config file or launchable executable for Guard to
        discover: it calls into Guard directly from its own request handler.
        There is nothing on this machine to scan, so detection is always
        "not installed" rather than a guess.
        """

        del context
        return HarnessDetection(
            harness=self.harness,
            installed=False,
            command_available=False,
            config_paths=(),
            artifacts=(),
            warnings=(
                "OptiQra integrates by calling `guard hook --harness optiqra` directly "
                "from its own backend rather than through a locally installed config hook, "
                "so Guard cannot detect whether the integration is wired up.",
            ),
        )

    def install(self, context: HarnessContext) -> dict[str, object]:
        del context
        raise NotImplementedError(
            "OptiQra has no local launcher or config file for Guard to manage. Wire "
            "OptiQra's own /api/auto-fix-project handler to call `guard hook "
            "--harness optiqra` with the resolved action, target files, and diff "
            "before writing, instead of running `hol-guard install optiqra`."
        )

    def uninstall(self, context: HarnessContext) -> dict[str, object]:
        del context
        raise NotImplementedError(
            "OptiQra has no local Guard shim to remove; remove the `guard hook "
            "--harness optiqra` call from OptiQra's own backend instead."
        )
