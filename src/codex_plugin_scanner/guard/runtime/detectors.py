"""Runtime detector registry primitives for Guard actions.

The default runtime detectors run in the native resident (one
``runtime_detector_run`` call per action); only the scanner-backed Cisco
preflight detectors run here. The registry merges both into one result in
detector-id order.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol

from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.native_cisco_preflight import (
    CiscoMcpPreflightDetector,
    CiscoSkillPreflightDetector,
    NativeCiscoPreflightError,
)
from codex_plugin_scanner.guard.native_runtime_detectors import native_runtime_detector_entries
from codex_plugin_scanner.guard.runtime.actions import GuardActionEnvelope
from codex_plugin_scanner.guard.runtime.signals import RiskSignalCategory, RiskSignalV2

DETECTOR_CATEGORY_TAGS: tuple[RiskSignalCategory, ...] = (
    "secret",
    "network",
    "prompt",
    "mcp",
    "skill",
    "supply_chain",
    "encoded",
    "persistence",
    "bypass",
    "false_positive",
    "filesystem",
    "execution",
)
DetectorRunStatus = Literal["ok", "disabled", "filtered", "timeout", "error"]
_SLOW_DETECTOR_THRESHOLD_MS: int = 100


@dataclass(frozen=True, slots=True)
class DetectorContext:
    """Context shared with runtime detectors."""

    config: GuardConfig
    workspace: Path | None
    prior_decisions: Mapping[str, object]
    threat_intel: Mapping[str, object]
    redaction_settings: Mapping[str, object]
    approved_scan_roots: tuple[Path, ...] = ()
    guard_home: Path | None = None


class GuardDetector(Protocol):
    """Detector interface for runtime Guard actions."""

    detector_id: str

    @property
    def categories(self) -> tuple[RiskSignalCategory, ...]:
        """Return the detector's risk categories."""
        ...

    def detect(self, action: GuardActionEnvelope, context: DetectorContext) -> tuple[RiskSignalV2, ...]:
        """Return typed risk signals for the runtime action."""
        ...


@dataclass(frozen=True, slots=True)
class DetectorTelemetry:
    """Debug-safe detector execution telemetry."""

    detector_id: str
    categories: tuple[RiskSignalCategory, ...]
    status: DetectorRunStatus
    elapsed_ms: int
    error_type: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "detector_id": self.detector_id,
            "categories": list(self.categories),
            "status": self.status,
            "elapsed_ms": self.elapsed_ms,
            "error_type": self.error_type,
        }


@dataclass(frozen=True, slots=True)
class DetectorRunResult:
    """Signals and telemetry produced by a registry run."""

    signals: tuple[RiskSignalV2, ...]
    telemetry: tuple[DetectorTelemetry, ...]

    def slow_detectors(self, threshold_ms: int = _SLOW_DETECTOR_THRESHOLD_MS) -> tuple[DetectorTelemetry, ...]:
        """Return telemetry entries that exceeded *threshold_ms*."""
        return tuple(t for t in self.telemetry if t.elapsed_ms >= threshold_ms)


class NativeRuntimeDetectors:
    """Marker for the resident-owned default detectors, run as one native call.

    Any failure raises ``NativeRuntimeDetectorError`` out of the registry run,
    so callers fail closed instead of evaluating without these detectors.
    """


class DetectorRegistry:
    """Runs detectors in deterministic order with failure isolation."""

    def __init__(
        self,
        detectors: Iterable[GuardDetector | NativeRuntimeDetectors],
        *,
        clock: Callable[[], float] | None = None,
    ) -> None:
        items = tuple(detectors)
        self._native = any(isinstance(detector, NativeRuntimeDetectors) for detector in items)
        self._detectors = tuple(
            sorted(
                (detector for detector in items if not isinstance(detector, NativeRuntimeDetectors)),
                key=lambda detector: detector.detector_id,
            )
        )
        self._clock = clock or time.monotonic

    def run(
        self,
        action: GuardActionEnvelope,
        context: DetectorContext,
        *,
        timeout_ms: int = 50,
        disabled_detector_ids: Sequence[str] = (),
        enabled_categories: Sequence[RiskSignalCategory] | None = None,
    ) -> DetectorRunResult:
        disabled_ids = frozenset(disabled_detector_ids)
        category_filter = frozenset(enabled_categories) if enabled_categories is not None else None
        entries: list[tuple[DetectorTelemetry, tuple[RiskSignalV2, ...]]] = []
        for detector in self._detectors:
            entries.append(self._run_one(detector, action, context, timeout_ms, disabled_ids, category_filter))
        if self._native:
            native = native_runtime_detector_entries(
                action,
                workspace=context.workspace,
                guard_home=context.guard_home or context.config.guard_home,
                timeout_ms=timeout_ms,
                disabled_detector_ids=tuple(disabled_detector_ids),
                enabled_categories=tuple(enabled_categories) if enabled_categories is not None else None,
            )
            entries.extend(
                (DetectorTelemetry(detector_id, categories, status, elapsed_ms, error_type), signals)
                for detector_id, categories, status, elapsed_ms, error_type, signals in native
            )
        entries.sort(key=lambda entry: entry[0].detector_id)
        return DetectorRunResult(
            signals=tuple(signal for _, signals in entries for signal in signals),
            telemetry=tuple(telemetry for telemetry, _ in entries),
        )

    def _run_one(
        self,
        detector: GuardDetector,
        action: GuardActionEnvelope,
        context: DetectorContext,
        timeout_ms: int,
        disabled_ids: frozenset[str],
        category_filter: frozenset[RiskSignalCategory] | None,
    ) -> tuple[DetectorTelemetry, tuple[RiskSignalV2, ...]]:
        if detector.detector_id in disabled_ids:
            return _telemetry(detector, "disabled", elapsed_ms=0), ()
        if category_filter is not None and not category_filter.intersection(detector.categories):
            return _telemetry(detector, "filtered", elapsed_ms=0), ()
        started_at = self._clock()
        try:
            detector_signals = detector.detect(action, context)
            elapsed_ms = _elapsed_ms(started_at, self._clock())
        except NativeCiscoPreflightError:
            raise
        except Exception as error:
            elapsed_ms = _elapsed_ms(started_at, self._clock())
            return _telemetry(detector, "error", elapsed_ms=elapsed_ms, error_type=type(error).__name__), ()
        signals = _filter_signals(detector_signals, category_filter)
        status: DetectorRunStatus = "timeout" if elapsed_ms > timeout_ms else "ok"
        return _telemetry(detector, status, elapsed_ms=elapsed_ms), signals


def register_default_detectors() -> tuple[GuardDetector | NativeRuntimeDetectors, ...]:
    """Return the default detectors: the Cisco preflight pair and the native set."""
    return (
        CiscoMcpPreflightDetector(),
        CiscoSkillPreflightDetector(),
        NativeRuntimeDetectors(),
    )


def _elapsed_ms(started_at: float, finished_at: float) -> int:
    return max(0, round((finished_at - started_at) * 1000))


def _filter_signals(
    signals: Sequence[RiskSignalV2],
    category_filter: frozenset[RiskSignalCategory] | None,
) -> tuple[RiskSignalV2, ...]:
    if category_filter is None:
        return tuple(signals)
    return tuple(signal for signal in signals if signal.category in category_filter)


def _telemetry(
    detector: GuardDetector,
    status: DetectorRunStatus,
    *,
    elapsed_ms: int,
    error_type: str | None = None,
) -> DetectorTelemetry:
    return DetectorTelemetry(
        detector_id=detector.detector_id,
        categories=detector.categories,
        status=status,
        elapsed_ms=elapsed_ms,
        error_type=error_type,
    )
