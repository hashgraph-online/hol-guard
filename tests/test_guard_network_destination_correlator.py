from __future__ import annotations

from codex_plugin_scanner.guard.runtime.network_destination_correlator import DestinationCorrelator
from codex_plugin_scanner.guard.runtime.network_local_core import bind_resolution


def test_correlator_reports_only_observed_unexpired_dns_bindings() -> None:
    correlator = DestinationCorrelator()
    correlator.observe(
        bind_resolution(
            host="api.example.com",
            addresses=("192.0.2.1",),
            observed_at_epoch_ms=1_000,
            ttl_seconds=2,
        )
    )
    correlator.observe(
        bind_resolution(
            host="cdn.example.com",
            addresses=("192.0.2.1",),
            observed_at_epoch_ms=1_500,
            ttl_seconds=4,
        )
    )

    correlation = correlator.correlate(address="192.0.2.1", now_epoch_ms=2_000)
    assert tuple(host.value for host in correlation.hosts) == (
        "api.example.com",
        "cdn.example.com",
    )
    assert len(correlation.binding_digests) == 2

    assert correlator.expire(now_epoch_ms=3_000) == 1
    later = correlator.correlate(address="192.0.2.1", now_epoch_ms=3_000)
    assert tuple(host.value for host in later.hosts) == ("cdn.example.com",)


def test_correlator_does_not_infer_hosts_for_unobserved_addresses() -> None:
    correlator = DestinationCorrelator()
    correlation = correlator.correlate(address="192.0.2.99", now_epoch_ms=2_000)

    assert correlation.hosts == ()
    assert correlation.binding_digests == ()
