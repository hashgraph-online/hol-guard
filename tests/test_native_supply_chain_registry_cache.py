"""Public registry metadata is downloaded once and reused briefly between reviews."""

from __future__ import annotations

import io
import threading
import time
import urllib.error
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_supply_chain_archive as archive_module
from codex_plugin_scanner.guard import native_supply_chain_egress as egress
from codex_plugin_scanner.guard import native_supply_chain_registry_cache as registry_cache
from codex_plugin_scanner.guard.daemon import hook_native_package_review as package_review
from codex_plugin_scanner.guard.mdm.contracts import ManagedNetworkPolicy
from codex_plugin_scanner.guard.native_supply_chain_registry_cache import (
    SETTLE_SECONDS,
    TTL_SECONDS,
    RegistryCache,
    RegistryDeadlineError,
    registry_wait_deadline,
)

URL = "https://registry.npmjs.org/zod"
KEY = (URL, (("accept", "application/json"),), 1024, 0, None)
OK = (200, (("content-type", "application/json"),), b"{}")


class _Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def _counting(result: object) -> tuple[list[int], object]:
    calls: list[int] = []

    def read() -> object:
        calls.append(1)
        return result

    return calls, read


def test_a_fresh_response_is_reused_until_it_expires() -> None:
    clock = _Clock()
    cache = RegistryCache(clock=clock)
    calls, read = _counting(OK)

    assert cache.fetch(KEY, read) == OK
    clock.now += TTL_SECONDS - 1
    assert cache.fetch(KEY, read) == OK
    assert len(calls) == 1
    clock.now += 1
    assert cache.fetch(KEY, read) == OK
    assert len(calls) == 2


@pytest.mark.parametrize(
    "result",
    [
        (404, (), b"{}"),
        (304, (), b""),
        (200, (), b"x" * 1025),
        {"kind": "error", "message": "timed out"},
        {"kind": "blocked", "code": "managed_public_registry_disabled"},
    ],
)
def test_only_a_complete_success_is_kept(result: object) -> None:
    cache = RegistryCache()
    calls, read = _counting(result)

    cache.fetch(KEY, read)
    cache.fetch(KEY, read)

    assert len(calls) == 2


def test_the_oldest_response_makes_room_for_a_new_one(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(registry_cache, "MAX_ENTRIES", 2)
    cache = RegistryCache()
    keys = [(f"{URL}/{index}", (), 1024, 0, None) for index in range(3)]
    for key in keys:
        cache.fetch(key, lambda: OK)
    calls, read = _counting(OK)

    cache.fetch(keys[2], read)
    assert calls == []
    cache.fetch(keys[0], read)
    assert calls == [1]


def test_concurrent_reviews_share_one_download() -> None:
    cache = RegistryCache()
    release = threading.Event()
    calls: list[int] = []

    def read() -> object:
        calls.append(1)
        release.wait(5)
        return OK

    results: list[object] = []
    workers = [threading.Thread(target=lambda: results.append(cache.fetch(KEY, read))) for _ in range(3)]
    for worker in workers:
        worker.start()
    time.sleep(0.05)
    release.set()
    for worker in workers:
        worker.join(5)

    assert results == [OK, OK, OK]
    assert calls == [1]


def test_a_read_past_the_deadline_finishes_for_the_next_attempt() -> None:
    cache = RegistryCache()
    release = threading.Event()
    calls: list[int] = []

    def read() -> object:
        calls.append(1)
        release.wait(5)
        return OK

    with registry_wait_deadline(time.monotonic() + SETTLE_SECONDS + 0.05), pytest.raises(RegistryDeadlineError):
        cache.fetch(KEY, read)
    release.set()
    for _ in range(100):
        if cache.fetch(KEY, lambda: pytest.fail("the finished download must be reused")) == OK:
            break
        time.sleep(0.01)
    assert calls == [1]


def test_without_a_deadline_the_caller_waits_for_the_read() -> None:
    cache = RegistryCache()

    def slow() -> object:
        time.sleep(0.05)
        return OK

    assert cache.fetch(KEY, slow) == OK


def _need(**overrides: object) -> dict[str, object]:
    need: dict[str, object] = {
        "class": "registry",
        "method": "GET",
        "url": URL,
        "headers": {"Accept": "application/json"},
        "body_sha256": "",
        "occurrence": 1,
        "timeout_seconds": 2.0,
        "max_redirects": 0,
        "max_response_bytes": 1024,
        "delay_seconds": 0.0,
    }
    need.update(overrides)
    return need


@pytest.mark.parametrize(
    "overrides",
    [
        {"class": "advisory"},
        {"method": "POST"},
        {"body": "e30="},
        {"delay_seconds": 1.0},
        {"headers": {"Accept": "application/json", "Authorization": "Bearer x"}},
        {"headers": {"Cookie": "session=x"}},
    ],
)
def test_reads_that_carry_state_are_never_reused(overrides: dict[str, object]) -> None:
    assert egress._registry_cache_key(_need(**overrides)) is None


def test_the_redirect_limit_is_part_of_the_key() -> None:
    assert egress._registry_cache_key(_need()) != egress._registry_cache_key(_need(max_redirects=2))


def test_a_network_policy_change_is_never_served_from_the_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    policies = iter([ManagedNetworkPolicy(), ManagedNetworkPolicy(allow_public_registries=False)])
    monkeypatch.setattr(egress, "resolved_network_policy", lambda _policy: (next(policies), True))

    before_change = egress._registry_cache_key(_need())
    after_change = egress._registry_cache_key(_need())

    assert before_change != after_change


def test_an_unreadable_network_policy_is_never_cached(monkeypatch: pytest.MonkeyPatch) -> None:
    def unreadable(_policy: object) -> object:
        raise OSError("policy unreadable")

    monkeypatch.setattr(egress, "resolved_network_policy", unreadable)

    assert egress._registry_cache_key(_need()) is None


def test_separate_reviews_download_a_registry_document_once(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    performed: list[str] = []

    def fake_urlopen(request: object, **_kwargs: object) -> object:
        performed.append(request.full_url)  # type: ignore[attr-defined]
        raise urllib.error.HTTPError(URL, 200, "OK", {}, io.BytesIO(b"{}"))  # type: ignore[arg-type]

    monkeypatch.setattr(egress, "managed_urlopen", fake_urlopen)
    cache = RegistryCache()
    outcomes = []
    for _ in range(2):
        archives = archive_module.ArchiveFulfilment(guard_home=tmp_path, scratch_dir=tmp_path, retain=False)
        outcomes.append(egress.EgressExchanger(tmp_path, archives, registry_cache=cache)._http(_need()))

    assert performed == [URL]
    assert outcomes[0] == outcomes[1]


def test_a_review_still_downloading_stops_quietly_for_a_retry(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    deadlines: list[float | None] = []

    def evaluate(*_args: object, **_kwargs: object) -> object:
        deadlines.append(registry_cache._WAIT_DEADLINE.get())
        raise RegistryDeadlineError

    monkeypatch.setattr(package_review, "package_review_plan", lambda *_args, **_kwargs: (object(), True))
    monkeypatch.setattr(package_review, "_evaluate", evaluate)
    monkeypatch.setattr(
        package_review,
        "render_pre_tool",
        lambda _harness, verdict, **_kwargs: dict(verdict),
    )

    response = package_review.native_package_review_response(
        object(),
        harness="omp",
        payload={"tool_input": {"command": "npm install zod --ignore-scripts"}},
        native_result={"reason_code": "native_package_review", "minimum_action": "review"},
        workspace=tmp_path,
        guard_home=tmp_path / "guard",
        deadline=123.0,
    )

    assert deadlines == [123.0]
    assert response is not None
    assert response["decision"] == "deny"
    assert response["reason"] == package_review.REGISTRY_STILL_LOADING_REASON
    assert response["prompted"] is False
    assert registry_cache._WAIT_DEADLINE.get() is None
