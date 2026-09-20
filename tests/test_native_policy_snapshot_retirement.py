"""Actual private generation state, signed cache and authenticated control input."""

from __future__ import annotations

import hashlib
import hmac
import json
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_policy_snapshot_control as control
from codex_plugin_scanner.guard import native_policy_snapshot_retirement as retirement
from codex_plugin_scanner.guard import native_policy_snapshot_storage as storage
from codex_plugin_scanner.guard.native_policy_publication_lock import hold_policy_publication_mutation
from codex_plugin_scanner.guard.native_policy_snapshot_codec import (
    _canonical_json_bytes_v3,
    derive_native_policy_verifier_key,
)
from codex_plugin_scanner.guard.native_policy_snapshot_constants import (
    _MAX_GENERATION,
    _NATIVE_POLICY_SNAPSHOT_PENDING_NAME,
    _V3_GENERATION_STATE_NAME,
    NATIVE_POLICY_SNAPSHOT_CACHE_NAME,
    NativePolicySnapshotError,
)
from codex_plugin_scanner.guard.native_policy_snapshot_contract import build_policy_snapshot_v3
from codex_plugin_scanner.guard.native_policy_snapshot_control import observe_native_authority
from codex_plugin_scanner.guard.native_policy_snapshot_generation import native_policy_snapshot_v3
from tests.native_policy_snapshot_test_fixtures import _config

_MASTER = b"s" * 32
_RUNTIME = "a" * 64
_RETIREMENT = "f" * 64


def _snapshot(home: Path, *, generation: int | None = None) -> dict[str, object]:
    if generation is not None:
        return build_policy_snapshot_v3(
            config=_config(),
            guard_home=home,
            runtime_identity=_RUNTIME,
            rule_digest="b" * 64,
            verifier_key=derive_native_policy_verifier_key(_MASTER),
            generation=generation,
        )
    return native_policy_snapshot_v3(
        config=_config(),
        guard_home=home,
        runtime_identity=_RUNTIME,
        rule_digest="b" * 64,
        policy_integrity_key=_MASTER,
    )


def _observation(home: Path, floor: int | None = 7) -> control.NativeAuthorityObservation:
    reference = (
        None
        if floor is None
        else {"fingerprint": "c" * 64, "generation_floor": floor, "policy_digest": "d" * 64, "usable_snapshot": True}
    )
    key = derive_native_policy_verifier_key(_MASTER)

    def client(**kwargs: object) -> bytes:
        payload = kwargs["payload"]
        assert isinstance(payload, bytes)
        outer = json.loads(payload)
        assert outer["operation"] == "policy_snapshot_observe"
        request = outer["request"]
        intent = request["intent"]
        assert (
            request["mac"]
            == hmac.new(key, control._OBSERVATION_DOMAIN + _canonical_json_bytes_v3(intent), hashlib.sha256).hexdigest()
        )
        response = {
            "schema": "guard-policy-snapshot-observation-response.v1",
            "runtime_identity": intent["runtime_identity"],
            "scope_digest": intent["scope_digest"],
            "resident_generation": 13,
            "request_sha256": hashlib.sha256(_canonical_json_bytes_v3(request)).hexdigest(),
            "nonce": intent["nonce"],
            "authority": reference,
        }
        mac = hmac.new(
            key, control._OBSERVATION_RESPONSE_DOMAIN + _canonical_json_bytes_v3(response), hashlib.sha256
        ).hexdigest()
        return _canonical_json_bytes_v3({"response": response, "mac": mac})

    return observe_native_authority(
        executable=home / "synthetic-runtime",
        guard_home=home,
        runtime_identity=_RUNTIME,
        verifier_key=key,
        deadline_monotonic=time.monotonic() + 5,
        client=client,
    )


def _reserve(
    home: Path,
    observation: control.NativeAuthorityObservation | None = None,
    *,
    runtime_identity: str = _RUNTIME,
    policy_integrity_key: bytes = _MASTER,
    deadline_monotonic: float | None = None,
) -> int:
    return retirement.reserve_native_policy_retirement(
        guard_home=home,
        runtime_identity=runtime_identity,
        policy_integrity_key=policy_integrity_key,
        observation=observation if observation is not None else _observation(home),
        retirement_policy_digest=_RETIREMENT,
        deadline_monotonic=time.monotonic() + 5 if deadline_monotonic is None else deadline_monotonic,
    )


@pytest.mark.parametrize("floor", [None, 7, 30])
def test_retirement_reserves_above_observed_and_all_pending_work(tmp_path: Path, floor: int | None) -> None:
    home = tmp_path / "guard"
    home.mkdir(mode=0o700)
    _snapshot(home)
    pending = _snapshot(home, generation=20)
    storage._write_v3_snapshot_file(home, _NATIVE_POLICY_SNAPSHOT_PENDING_NAME, pending)

    generation = _reserve(home, _observation(home, floor))

    assert generation == max(floor or 0, 20) + 1
    assert storage._read_v3_generation_state(home) == (generation, _RETIREMENT)
    assert not (home / "native-runtime" / _NATIVE_POLICY_SNAPSHOT_PENDING_NAME).exists()
    cached = storage._read_v3_snapshot_cache(home, verifier_key=derive_native_policy_verifier_key(_MASTER))
    assert cached is not None and cached[0] == pending
    # A second acquisition proves the returned reservation holds neither lock.
    assert _reserve(home, _observation(home, floor)) == generation + 1


@pytest.mark.parametrize(
    "corruption", ["cache", "cache-mac", "counter-missing", "counter-behind", "counter-conflict", "pending"]
)
def test_retirement_preserves_corrupt_or_inconsistent_evidence(tmp_path: Path, corruption: str) -> None:
    home = tmp_path / "guard"
    home.mkdir(mode=0o700)
    snapshot = _snapshot(home)
    cache = home / "native-runtime" / NATIVE_POLICY_SNAPSHOT_CACHE_NAME
    pending = home / "native-runtime" / _NATIVE_POLICY_SNAPSHOT_PENDING_NAME
    if corruption == "cache":
        cache.write_bytes(b"{}")
    elif corruption == "cache-mac":
        integrity = snapshot["integrity"]
        assert isinstance(integrity, dict)
        integrity["mac"] = "0" * 64
        cache.write_bytes(_canonical_json_bytes_v3(snapshot))
    elif corruption == "counter-missing":
        (home / _V3_GENERATION_STATE_NAME).unlink()
    elif corruption == "counter-behind":
        storage._write_v3_snapshot_cache(home, _snapshot(home, generation=2))
    elif corruption == "counter-conflict":
        generation = snapshot["generation"]
        assert isinstance(generation, int)
        storage._write_v3_generation_state(home, generation=generation, policy_digest="e" * 64)
    else:
        pending.write_bytes(b"{}")
        pending.chmod(0o600)
    counter = home / _V3_GENERATION_STATE_NAME
    before_counter = counter.read_bytes() if counter.exists() else None
    before_cache = cache.read_bytes()

    with pytest.raises(NativePolicySnapshotError):
        _reserve(home)

    assert (counter.read_bytes() if counter.exists() else None) == before_counter
    assert cache.read_bytes() == before_cache
    if corruption == "pending":
        assert pending.read_bytes() == b"{}"


def test_retirement_failed_atomic_counter_replacement_preserves_cache_and_floor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "guard"
    home.mkdir(mode=0o700)
    _snapshot(home)
    counter = home / _V3_GENERATION_STATE_NAME
    cache = home / "native-runtime" / NATIVE_POLICY_SNAPSHOT_CACHE_NAME
    before = (counter.read_bytes(), cache.read_bytes())
    original = storage.os.replace

    def refuse(source: str | Path, target: str | Path) -> None:
        if Path(target) == counter:
            raise OSError("synthetic counter replacement failure")
        return original(source, target)

    monkeypatch.setattr(storage.os, "replace", refuse)
    with pytest.raises(NativePolicySnapshotError, match="generation_state_write_failed"):
        _reserve(home)
    assert (counter.read_bytes(), cache.read_bytes()) == before


@pytest.mark.parametrize("mutation", ["scope", "runtime", "floor-type", "deadline", "exhausted", "key"])
def test_retirement_requires_exact_authenticated_subject_and_valid_bounded_state(tmp_path: Path, mutation: str) -> None:
    home = tmp_path / "guard"
    home.mkdir(mode=0o700)
    _snapshot(home)
    observation = _observation(home, _MAX_GENERATION if mutation == "exhausted" else 7)
    runtime_identity = _RUNTIME
    policy_integrity_key = _MASTER
    deadline_monotonic = time.monotonic() + 5
    if mutation == "scope":
        observation = replace(observation, scope_digest="e" * 64)
    elif mutation == "runtime":
        runtime_identity = "e" * 64
    elif mutation == "floor-type":
        assert observation.authority is not None
        observation = replace(observation, authority=replace(observation.authority, generation_floor=True))
    elif mutation == "deadline":
        deadline_monotonic = time.monotonic() - 1
    elif mutation == "key":
        policy_integrity_key = b"x" * 32
    before = storage._read_v3_generation_state(home)
    with pytest.raises(NativePolicySnapshotError):
        _reserve(
            home,
            observation,
            runtime_identity=runtime_identity,
            policy_integrity_key=policy_integrity_key,
            deadline_monotonic=deadline_monotonic,
        )
    assert storage._read_v3_generation_state(home) == before


@pytest.mark.parametrize("lock_kind", ["publication", "generation"])
def test_retirement_waits_only_within_original_deadline_without_mutating_state(
    tmp_path: Path,
    lock_kind: str,
) -> None:
    home = tmp_path / "guard"
    home.mkdir(mode=0o700)
    _snapshot(home)
    observation = _observation(home)
    before = storage._read_v3_generation_state(home)
    held = threading.Event()
    release = threading.Event()
    errors: list[BaseException] = []
    release_results: list[bool] = []

    def holder() -> None:
        try:
            lock = (
                hold_policy_publication_mutation(home, timeout_seconds=1)
                if lock_kind == "publication"
                else storage._v3_generation_lock(home, deadline_monotonic=time.monotonic() + 1)
            )
            with lock:
                held.set()
                release_results.append(release.wait(2))
        except BaseException as error:
            errors.append(error)
            held.set()

    thread = threading.Thread(target=holder)
    thread.start()
    try:
        assert held.wait(1) and not errors
        start = time.monotonic()
        with pytest.raises((NativePolicySnapshotError, TimeoutError)):
            _reserve(home, observation, deadline_monotonic=start + 0.05)
        assert time.monotonic() - start < 0.5
        assert storage._read_v3_generation_state(home) == before
    finally:
        release.set()
        thread.join(timeout=2)
    assert not thread.is_alive() and not errors
    assert release_results == [True]
    assert _reserve(home, observation) > (before[0] if before else 0)


def test_deadline_after_atomic_reservation_retains_floor_and_next_attempt_advances(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "guard"
    home.mkdir(mode=0o700)
    _snapshot(home)
    observation = _observation(home)
    cache = home / "native-runtime" / NATIVE_POLICY_SNAPSHOT_CACHE_NAME
    before_cache = cache.read_bytes()
    before = storage._read_v3_generation_state(home)
    original = retirement._write_v3_generation_state
    deadline = time.monotonic() + 0.2
    completed: list[int] = []

    def expire_after_write(guard_home: Path, *, generation: int, policy_digest: str) -> None:
        original(guard_home, generation=generation, policy_digest=policy_digest)
        completed.append(generation)
        time.sleep(max(0, deadline - time.monotonic()) + 0.005)

    with monkeypatch.context() as patch:
        patch.setattr(retirement, "_write_v3_generation_state", expire_after_write)
        with pytest.raises(NativePolicySnapshotError, match="control_deadline_exceeded"):
            _reserve(home, observation, deadline_monotonic=deadline)
    assert len(completed) == 1
    assert before is not None and completed[0] > before[0]
    assert storage._read_v3_generation_state(home) == (completed[0], _RETIREMENT)
    assert cache.read_bytes() == before_cache
    assert _reserve(home, _observation(home)) == completed[0] + 1


def test_retirement_preserves_existing_publication_lock_wait_ceiling(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "guard"
    home.mkdir(mode=0o700)
    _snapshot(home)
    observation = _observation(home)
    actual_lock = retirement.hold_policy_publication_mutation
    timeouts: list[float] = []

    @contextmanager
    def observed_lock(guard_home: Path, *, timeout_seconds: float) -> Iterator[None]:
        timeouts.append(timeout_seconds)
        with actual_lock(guard_home, timeout_seconds=timeout_seconds):
            yield

    monkeypatch.setattr(retirement, "hold_policy_publication_mutation", observed_lock)
    assert _reserve(home, observation, deadline_monotonic=time.monotonic() + 30) > 0
    assert timeouts == [5.0]
