"""Parse and deduplicate typed detector evidence from a runtime context."""

from __future__ import annotations

from collections.abc import Mapping

from .signals import RiskSignalV2


def _runtime_detector_risk_signals(
    runtime_detector_context: Mapping[str, object] | None,
) -> tuple[RiskSignalV2, ...]:
    if runtime_detector_context is None:
        return ()
    raw_signals = runtime_detector_context.get("signals_v2")
    if not isinstance(raw_signals, list):
        return ()
    signals: list[RiskSignalV2] = []
    seen: set[str] = set()
    for raw_signal in raw_signals:
        if not isinstance(raw_signal, Mapping):
            continue
        try:
            signal = RiskSignalV2.from_dict(raw_signal)
        except (TypeError, ValueError):
            continue
        if signal.signal_id in seen:
            continue
        seen.add(signal.signal_id)
        signals.append(signal)
    return tuple(signals)
