"""Failed V3 renewal retains only an unchanged accepted source-free lease."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard.models import PolicyDecision
from codex_plugin_scanner.guard.native_policy_snapshot import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.native_policy_snapshot_constants import NATIVE_POLICY_VERIFIER_KEY_NAME
from codex_plugin_scanner.guard.store import GuardStore
from tests.native_policy_snapshot_test_fixtures import _ack, _DeterministicClock, _status


def _accepted(tmp_path: Path) -> tuple[Any, ...]:
    store = GuardStore(tmp_path / "guard")
    runtime = store.guard_home / "native-runtime"
    runtime.mkdir(mode=0o700)
    directory = runtime / "resident-v3-synthetic"
    directory.mkdir(mode=0o700)
    generation = directory / "generation-00000000000000000001.json"
    generation.write_text("{}")
    generation.chmod(0o600)
    status = _status()
    clock = _DeterministicClock()
    mutations: list[Any] = [lambda: None]
    responses: list[Any] = [None]
    calls = 0

    def client(**kwargs: Any) -> bytes | None:
        nonlocal calls
        calls += 1
        if calls == 1:
            return _ack(kwargs["payload"])
        mutations[0]()
        if isinstance(responses[0], Exception):
            raise responses[0]
        return responses[0]

    publisher = NativePolicySnapshotPublisher(
        store=store,
        status_provider=lambda: status,
        client_request=client,
        wall_clock=clock.wall_time,
        monotonic_clock=clock.monotonic_time,
    )
    publisher._publish_once()
    assert publisher.is_ready() and publisher.current_snapshot() is not None, publisher.last_error
    assert publisher.requires_policy_authority is False
    return store, publisher, status, clock, generation, mutations, responses


@pytest.mark.parametrize("response", [None, b"", b"{}", TimeoutError("synthetic timeout")])
def test_failed_renewal_keeps_exact_prior_generation_only_until_expiry(tmp_path: Path, response: object) -> None:
    _, publisher, _, clock, _, _, responses = _accepted(tmp_path)
    responses[0] = response
    first = publisher.current_snapshot()
    try:
        publisher._publish_once(renew_after_generation=first["generation"])
        assert publisher.is_ready()
        assert publisher.current_snapshot() == first
        assert publisher.current_snapshot_binding()["generation"] == first["generation"]
        assert publisher.last_error is not None
        clock.wall = first["expires_at_ms"] / 1_000
        assert not publisher.is_ready()
        assert publisher.current_snapshot() is None
    finally:
        publisher.close()


@pytest.mark.parametrize("stage", ["transport", "confirmation"])
@pytest.mark.parametrize(
    "mutation",
    [
        "config",
        "config-equivalent",
        "verifier-withdraw",
        "local-row",
        "untrusted-row",
        "required-source",
        "resident-new",
        "resident-withdraw",
        "epoch",
        "closed",
        "expiry",
        "identity",
        "rules",
        "capability",
        "disabled",
    ],
)
def test_failed_renewal_cannot_retain_changed_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stage: str, mutation: str
) -> None:
    store, publisher, status, clock, generation, mutations, _ = _accepted(tmp_path)
    first = publisher.current_snapshot()

    def change() -> None:
        if mutation == "config":
            (store.guard_home / "config.toml").write_text('default_action = "block"\n')
        elif mutation == "config-equivalent":
            (store.guard_home / "config.toml").write_text("")
        elif mutation == "verifier-withdraw":
            (store.guard_home / "native-runtime" / NATIVE_POLICY_VERIFIER_KEY_NAME).unlink()
        elif mutation == "local-row":
            store.upsert_policy(
                PolicyDecision(harness="codex", scope="global", action="block", source="local"), "2026-09-18T00:00:00Z"
            )
        elif mutation == "untrusted-row":
            with store._connect() as connection:
                connection.execute(
                    "insert into policy_decisions(harness,scope,action,source,updated_at) values(?,?,?,?,?)",
                    ("codex", "global", "block", "local", "2026-09-18T00:00:00Z"),
                )
        elif mutation == "required-source":
            store.set_sync_payload("policy_bundle", {"invalid": True}, "2026-09-18T00:00:00Z")
        elif mutation == "resident-new":
            generation.with_name("generation-00000000000000000002.json").write_text("{}")
        elif mutation == "resident-withdraw":
            generation.unlink()
        elif mutation == "epoch":
            publisher.request_publish()
        elif mutation == "closed":
            publisher.close()
        elif mutation == "expiry":
            clock.wall = first["expires_at_ms"] / 1_000
        elif mutation == "identity":
            status.identity.sha256 = "c" * 64
        elif mutation == "rules":
            status.capabilities.rule_digest = "c" * 64
        elif mutation == "capability":
            status.capabilities.features = ()
        elif mutation == "disabled":
            status.mode = "off"
        else:
            raise AssertionError(mutation)

    if stage == "transport":
        mutations[0] = change
    else:
        confirm = publisher._confirm_resident_fingerprint

        def changed_confirmation(*args: Any) -> object:
            result = confirm(*args)
            change()
            return result

        monkeypatch.setattr(publisher, "_confirm_resident_fingerprint", changed_confirmation)
    try:
        publisher._publish_once(renew_after_generation=first["generation"])
        assert not publisher.is_ready()
        assert publisher.current_snapshot() is None
        assert store.get_sync_payload("policy_bundle_ack") is None
    finally:
        publisher.close()
