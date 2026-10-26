"""Run one resident-owned runtime detector through the native detector run.

Tests that pin a single detector's behavior call ``NativeDetector(id).detect``
under the ``native_runtime_detectors_runtime`` fixture; the answer comes from
the Rust resident, never from a Python evaluator.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.native_runtime_detectors import native_runtime_detector_entries
from codex_plugin_scanner.guard.runtime.actions import GuardActionEnvelope
from codex_plugin_scanner.guard.runtime.detectors import DetectorContext, DetectorRunResult, DetectorTelemetry
from codex_plugin_scanner.guard.runtime.signals import RiskSignalCategory, RiskSignalV2


class NativeDetector:
    def __init__(self, detector_id: str) -> None:
        self.detector_id = detector_id

    def detect(self, action: GuardActionEnvelope, context: DetectorContext) -> tuple[RiskSignalV2, ...]:
        return self.run(action, context).signals

    def run(
        self,
        action: GuardActionEnvelope,
        context: DetectorContext,
        *,
        enabled_categories: Sequence[RiskSignalCategory] | None = None,
    ) -> DetectorRunResult:
        """This detector's telemetry and signals from one native detector run."""
        entries = native_runtime_detector_entries(
            action,
            workspace=context.workspace,
            guard_home=context.guard_home,
            timeout_ms=60_000,
            disabled_detector_ids=(),
            enabled_categories=enabled_categories,
        )
        detector_id, categories, status, elapsed_ms, error_type, signals = next(
            entry for entry in entries if entry[0] == self.detector_id
        )
        telemetry = DetectorTelemetry(detector_id, categories, status, elapsed_ms, error_type)
        return DetectorRunResult(signals=signals, telemetry=(telemetry,))


def shell_command_signals(detector_id: str, command: str) -> tuple[RiskSignalV2, ...]:
    """Signals one native detector emits for a shell command in a fixed workspace."""
    action = GuardActionEnvelope(
        schema_version=1,
        action_id="",
        harness="codex",
        event_name="BashCommand",
        action_type="shell_command",
        workspace=None,
        workspace_hash=None,
        tool_name="bash",
        command=command,
        prompt_excerpt=None,
        prompt_text=None,
        target_paths=(),
        network_hosts=(),
        mcp_server=None,
        mcp_tool=None,
        package_manager=None,
        package_name=None,
        script_name=None,
        raw_payload_redacted={},
    )
    workspace = Path("/workspace/project")
    context = DetectorContext(
        config=GuardConfig(guard_home=Path("/tmp/guard-home"), workspace=workspace),
        workspace=workspace,
        prior_decisions={},
        threat_intel={},
        redaction_settings={},
    )
    return NativeDetector(detector_id).detect(action, context)
