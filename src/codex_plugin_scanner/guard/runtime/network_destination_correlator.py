"""Time-bounded DNS-to-connect correlation without reverse-DNS inference."""

from __future__ import annotations

from dataclasses import dataclass

from codex_plugin_scanner.guard.runtime.network_local_core import ResolutionBinding, resolution_allows
from codex_plugin_scanner.guard.runtime.network_policy_contract import Destination, DestinationKind


@dataclass(frozen=True, slots=True)
class DestinationCorrelation:
    address: Destination
    hosts: tuple[Destination, ...]
    binding_digests: tuple[str, ...]


class DestinationCorrelator:
    def __init__(self) -> None:
        self._bindings: dict[str, ResolutionBinding] = {}

    def observe(self, binding: ResolutionBinding) -> None:
        self._bindings[binding.digest] = binding

    def correlate(self, *, address: str, now_epoch_ms: int) -> DestinationCorrelation:
        ip = Destination(DestinationKind.IP, address)
        matches = tuple(
            sorted(
                (
                    binding
                    for binding in self._bindings.values()
                    if resolution_allows(binding, address=ip.value, now_epoch_ms=now_epoch_ms)
                ),
                key=lambda binding: (binding.host.value, binding.digest),
            )
        )
        return DestinationCorrelation(
            address=ip,
            hosts=tuple(sorted({binding.host for binding in matches}, key=lambda host: host.value)),
            binding_digests=tuple(binding.digest for binding in matches),
        )

    def expire(self, *, now_epoch_ms: int) -> int:
        expired = [digest for digest, binding in self._bindings.items() if now_epoch_ms >= binding.expires_at_epoch_ms]
        for digest in expired:
            del self._bindings[digest]
        return len(expired)
