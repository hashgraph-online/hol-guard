"""Runtime detector registry primitives for Guard actions."""

from __future__ import annotations

import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol

from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.runtime.actions import GuardActionEnvelope
from codex_plugin_scanner.guard.runtime.data_flow_rules import detect_data_flow_exfiltration
from codex_plugin_scanner.guard.runtime.secret_sensitivity import SecretPathMatch, classify_secret_path
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
)
DetectorRunStatus = Literal["ok", "disabled", "filtered", "timeout", "error"]


@dataclass(frozen=True, slots=True)
class DetectorContext:
    """Context shared with runtime detectors."""

    config: GuardConfig
    workspace: Path | None
    prior_decisions: Mapping[str, object]
    threat_intel: Mapping[str, object]
    redaction_settings: Mapping[str, object]


class GuardDetector(Protocol):
    """Detector interface for runtime Guard actions."""

    detector_id: str
    categories: tuple[RiskSignalCategory, ...]

    def detect(self, action: GuardActionEnvelope, context: DetectorContext) -> tuple[RiskSignalV2, ...]:
        """Return typed risk signals for the runtime action."""


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


class DetectorRegistry:
    """Runs detectors in deterministic order with failure isolation."""

    def __init__(
        self,
        detectors: Iterable[GuardDetector],
        *,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self._detectors = tuple(sorted(detectors, key=lambda detector: detector.detector_id))
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
        signals: list[RiskSignalV2] = []
        telemetry: list[DetectorTelemetry] = []
        for detector in self._detectors:
            if detector.detector_id in disabled_ids:
                telemetry.append(_telemetry(detector, "disabled", elapsed_ms=0))
                continue
            if category_filter is not None and not category_filter.intersection(detector.categories):
                telemetry.append(_telemetry(detector, "filtered", elapsed_ms=0))
                continue
            started_at = self._clock()
            try:
                detector_signals = detector.detect(action, context)
                elapsed_ms = _elapsed_ms(started_at, self._clock())
            except Exception as error:
                elapsed_ms = _elapsed_ms(started_at, self._clock())
                telemetry.append(_telemetry(detector, "error", elapsed_ms=elapsed_ms, error_type=type(error).__name__))
                continue
            if elapsed_ms > timeout_ms:
                telemetry.append(_telemetry(detector, "timeout", elapsed_ms=elapsed_ms))
                continue
            signals.extend(_filter_signals(detector_signals, category_filter))
            telemetry.append(_telemetry(detector, "ok", elapsed_ms=elapsed_ms))
        return DetectorRunResult(signals=tuple(signals), telemetry=tuple(telemetry))


class SecretPathDetector:
    detector_id = "secret.path"
    categories: tuple[RiskSignalCategory, ...] = ("secret",)

    def detect(self, action: GuardActionEnvelope, context: DetectorContext) -> tuple[RiskSignalV2, ...]:
        if action.action_type != "file_read":
            return ()
        matches = tuple(_secret_path_matches(action.target_paths, workspace=context.workspace))
        return tuple(_secret_path_signal(match, index=index) for index, match in enumerate(matches))


class DataFlowExfiltrationDetector:
    detector_id = "data_flow.exfiltration"
    categories: tuple[RiskSignalCategory, ...] = ("secret", "network")

    def detect(self, action: GuardActionEnvelope, context: DetectorContext) -> tuple[RiskSignalV2, ...]:
        return detect_data_flow_exfiltration(action, workspace=context.workspace)


def register_default_detectors() -> tuple[GuardDetector, ...]:
    return (DataFlowExfiltrationDetector(), SecretPathDetector())


def _secret_path_signal(match: SecretPathMatch, *, index: int) -> RiskSignalV2:
    return RiskSignalV2(
        signal_id=f"secret:path:{_slug(match.family)}:{index}",
        category="secret",
        severity="high",
        confidence="strong",
        detector="secret.path",
        title=f"Direct access to {match.family}",
        plain_reason=f"Requested direct access to {match.family}.",
        technical_detail=f"matched secret path family: {match.family}",
        evidence_ref="target_paths",
        redaction_level="summary",
        false_positive_hint="Allow only if this tool needs the exact local secret file for the current task.",
        advisory_id=None,
    )


def _secret_path_matches(paths: Sequence[str], *, workspace: Path | None) -> tuple[SecretPathMatch, ...]:
    matches: list[SecretPathMatch] = []
    for path in paths:
        match = classify_secret_path(path, cwd=workspace)
        if match is not None:
            matches.append(match)
    return tuple(matches)


def _elapsed_ms(started_at: float, finished_at: float) -> int:
    return max(0, round((finished_at - started_at) * 1000))


def _filter_signals(
    signals: Sequence[RiskSignalV2],
    category_filter: frozenset[RiskSignalCategory] | None,
) -> tuple[RiskSignalV2, ...]:
    if category_filter is None:
        return tuple(signals)
    return tuple(signal for signal in signals if signal.category in category_filter)


def _slug(value: str) -> str:
    return "-".join(part for part in value.lower().replace(".", " ").replace("/", " ").split() if part)


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
