"""Opt-in matched bridge measurement using the native test's exported fixtures.

Synthetic factory assertions are test-only, as in the ordinary backend tests;
the real resident transport, traversal, CAS and public Python read are used.
"""

from __future__ import annotations

import hashlib
import json
import os
import resource
import subprocess
import threading
import time
from collections import Counter
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_catalog_read as native
from codex_plugin_scanner.guard.catalog_delivery import discovery
from codex_plugin_scanner.guard.catalog_delivery.authority import VerifiedDistribution
from codex_plugin_scanner.guard.native_resident_client import close_native_residents
from tests.test_catalog_discovery_backend import provision


@pytest.mark.skipif(
    not os.environ.get("HOL_GUARD_CATALOG_EXPORT"), reason="requires native exported measurement fixtures"
)
@pytest.mark.parametrize("count", [166, 1660, 16600])
def test_matched_real_bridge(tmp_path, monkeypatch, native_hook_force, count):
    fixture = Path(os.environ["HOL_GUARD_CATALOG_EXPORT"]) / str(count)
    data = (fixture / "root.json").read_bytes()
    root = json.loads(data)
    authority = object.__new__(VerifiedDistribution)
    for key, value in {
        "data": data,
        "digest": hashlib.sha256(data).hexdigest(),
        "source_sha": root["source_sha"],
        "expires_at": root["expires_at"],
    }.items():
        object.__setattr__(authority, key, value)
    home = tmp_path / "home"
    provision(home)
    discovery._cached = None
    counters = Counter()
    real_status, real_request = discovery.native_runtime_status, discovery.native_resident_client_request

    def status():
        counters["runtime_status"] += 1
        return real_status()

    def request(**kwargs):
        action = json.loads(kwargs["payload"])["request"]["action"]
        counters["rpc"] += 1
        counters[action["kind"]] += 1
        counters["wire_bytes"] += len(kwargs["payload"])
        return real_request(**kwargs)

    def fetch(location, maximum):
        counters["fetch"] += 1
        assert location["asset"].startswith("object-")
        value = (fixture / "origin" / location["asset"][7:]).read_bytes()
        assert len(value) == maximum
        counters["fetched_bytes"] += len(value)
        return value

    monkeypatch.setattr(discovery, "native_runtime_status", status)
    monkeypatch.setattr(discovery, "native_resident_client_request", request)
    real_read_request = native.native_resident_client_request
    frames = []

    def read_request(**kwargs):
        response = real_read_request(**kwargs)
        frames.append(response[:512] if response is not None else None)
        return response

    monkeypatch.setattr(native, "native_resident_client_request", read_request)
    started = time.monotonic()
    stop = threading.Event()
    memory = Counter()

    def sample():
        while not stop.is_set():
            rows = subprocess.check_output(["ps", "-axo", "rss=,command="], text=True).splitlines()
            total = 0
            for row in rows:
                if str(home / "native-runtime") in row and "hol-guard-runtime " in row:
                    rss = int(row.split(None, 1)[0]) * 1024
                    total += rss
                    if " serve-managed --state-dir " in row:
                        memory["resident_sampled_peak_rss_bytes"] = max(memory["resident_sampled_peak_rss_bytes"], rss)
            memory["transport_sampled_peak_rss_bytes"] = max(memory["transport_sampled_peak_rss_bytes"], total)
            stop.wait(0.25)

    sampler = threading.Thread(target=sample, daemon=True)
    sampler.start()
    measurements = {"count": count}
    try:
        handle = discovery.prepare_discovery(home, authority, fetch=fetch)
        prep_seconds = time.monotonic() - started
        measurements["prepare_seconds"] = prep_seconds
        print(
            f"native-discovery-fast-prepared count={count} seconds={prep_seconds} counts={dict(counters)}", flush=True
        )
        arguments = dict(
            guard_home=home,
            discovery_handle=handle,
            route="index",
            query="limit=1",
            if_none_match=None,
            expected_catalog_digest="b" * 64,
            timeout_seconds=60,
        )
        started_read = time.monotonic()
        result = native.native_catalog_read(**arguments)
        read_seconds = time.monotonic() - started_read
        measurements.update(index_read_seconds=read_seconds, index_read_status=result.status if result else 501)
        assert result is not None and result.status == 200, (result, frames)
        assert json.loads(result.body)["total_count"] == count
        arguments.update(route="permissions", query="q=permissionneedle&limit=1")
        result = native.native_catalog_read(**arguments)
        assert result.status == 200 and json.loads(result.body)["total_count"] == 1
        arguments.update(route=f"extensions/synthetic-{count - 1:06}", query="")
        result = native.native_catalog_read(**arguments)
        assert result.status == 200
        arguments["if_none_match"] = result.etag
        assert native.native_catalog_read(**arguments).status == 304
        assert counters["runtime_status"] == 2
        # A ready catalog must return its complete page within the advertised
        # deadline; a prompt temporary failure does not satisfy readiness.
        arguments.update(route="index", query="limit=1", if_none_match=None, timeout_seconds=2)
        deadline_start = time.monotonic()
        deadline_result = native.native_catalog_read(**arguments)
        deadline_seconds = time.monotonic() - deadline_start
        assert deadline_seconds < 2.5
        assert deadline_result is not None and deadline_result.status == 200
        measurements.update(
            {
                "deadline_seconds": deadline_seconds,
                "deadline_status": deadline_result.status if deadline_result is not None else 501,
                "read_checks_passed": True,
            }
        )
    finally:
        stop.set()
        sampler.join(2)
        for label, name in (("transport_cas_files", "transport"), ("discovery_cas_files", "objects")):
            directory = home / "native-runtime/catalog-discovery" / name
            if directory.exists():
                measurements[label] = sum(path.suffix == ".json" for path in directory.iterdir())
        measurements.update(
            python_peak_rss_bytes=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss, **counters, **memory
        )
        destination = os.environ.get("HOL_GUARD_CATALOG_MEASUREMENTS")
        if destination:
            with Path(destination).open("a") as output:
                output.write(json.dumps(measurements, sort_keys=True) + "\n")
        print("native-discovery-fast-bridge " + json.dumps(measurements, sort_keys=True))
        close_native_residents(guard_home=home)
