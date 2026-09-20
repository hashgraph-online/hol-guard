"""Initial command preparation never replaces reservation or ACK recapture."""

from __future__ import annotations

import threading
from collections.abc import Mapping
from contextlib import closing
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.native_policy_authority_contract import NATIVE_MANAGED_AUTHORITY_FEATURE
from codex_plugin_scanner.guard.native_policy_snapshot_constants import _PUBLISH_TIMEOUT_SECONDS
from codex_plugin_scanner.guard.native_policy_snapshot_publisher import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.native_policy_snapshot_publisher_context import PublicationContext
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.store import GuardStore
from tests.native_policy_snapshot_test_fixtures import _ack, _status
from tests.test_canonical_policy_row_authority import _activated_store
from tests.test_guard_extension_control_authority import MemorySecretStore, _commit, _store
from tests.test_native_policy_snapshot_reservation_capture import _make_publisher


@pytest.mark.parametrize("scoped", [False, True], ids=["v3", "v4"])
def test_initial_binding_is_reused_only_before_fresh_reservation_and_ack(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, scoped: bool
) -> None:
    store = _activated_store(tmp_path) if scoped else GuardStore(tmp_path / "guard")
    calls: list[dict[str, object]] = []
    with closing(_make_publisher(store, calls, scoped=scoped)) as publisher:
        compile_binding = publisher._compiled_command_extensions
        capture_context = publisher._publication_context
        reads: list[dict[str, object]] = []
        supplied: list[Mapping[str, object] | None] = []
        transport_read_counts: list[int] = []
        client = publisher._client_request
        assert client is not None

        def read_binding() -> dict[str, object]:
            binding = compile_binding()
            reads.append(binding)
            return binding

        def context(
            *,
            publish_epoch: int | None = None,
            prepared_command_extensions: Mapping[str, object] | None = None,
        ) -> PublicationContext | None:
            supplied.append(prepared_command_extensions)
            return capture_context(publish_epoch=publish_epoch, prepared_command_extensions=prepared_command_extensions)

        def transport(**kwargs):
            transport_read_counts.append(len(reads))
            return client(**kwargs)

        monkeypatch.setattr(publisher, "_compiled_command_extensions", read_binding)
        monkeypatch.setattr(publisher, "_publication_context", context)
        monkeypatch.setattr(publisher, "_client_request", transport)
        assert publisher._command_control_runtime is None
        publisher._publish_once()
        assert publisher.is_ready(), publisher.last_error
        assert len(reads) == 3
        assert len(supplied) == 2 and supplied[0] is reads[0] and supplied[1] is None
        assert transport_read_counts == [2]
        assert len(calls) == 1
        assert ("source_input_digest" in calls[0]) is scoped
        assert reads[1] is not reads[0] and reads[2] is not reads[1]
        assert reads[1] == reads[2] == calls[0]["command_extensions"]
        assert publisher._command_control_runtime is not None

        reads.clear()
        supplied.clear()
        transport_read_counts.clear()
        publisher.request_publish()
        publisher._publish_once()
        assert publisher.is_ready(), publisher.last_error
        assert len(reads) == 3 and supplied == [None, None]
        assert transport_read_counts == [2]
        assert len(calls) == 2
        assert reads[1] is not reads[0] and reads[2] is not reads[1]
        assert reads[1] == reads[2] == calls[1]["command_extensions"]


@pytest.mark.parametrize("scoped", [False, True], ids=["v3", "v4"])
def test_control_mutation_after_bootstrap_refuses_stale_binding_until_fresh_attempt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, scoped: bool
) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.extension_control_proof._require_local_terminal_confirmation",
        lambda _enrollment: None,
    )
    store = _store(tmp_path / "guard", MemorySecretStore())
    calls: list[dict[str, object]] = []
    with closing(_make_publisher(store, calls, scoped=scoped)) as publisher:
        if scoped:
            assert publisher._status_provider is not None
            capabilities = publisher._status_provider().capabilities
            capabilities.features += (NATIVE_MANAGED_AUTHORITY_FEATURE,)
            capabilities.extension_catalog_digest = BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest
        compile_binding = publisher._compiled_command_extensions
        capture_context = publisher._publication_context
        reads: list[dict[str, object]] = []
        supplied: list[Mapping[str, object] | None] = []
        mutation_epochs: list[tuple[int, int]] = []
        context_epochs: list[int | None] = []

        def read_binding() -> dict[str, object]:
            binding = compile_binding()
            reads.append(binding)
            if len(reads) == 1:
                before = publisher._epoch
                _commit(store)
                mutation_epochs.append((before, publisher._epoch))
            return binding

        def context(
            *,
            publish_epoch: int | None = None,
            prepared_command_extensions: Mapping[str, object] | None = None,
        ) -> PublicationContext | None:
            supplied.append(prepared_command_extensions)
            context_epochs.append(publish_epoch)
            return capture_context(publish_epoch=publish_epoch, prepared_command_extensions=prepared_command_extensions)

        monkeypatch.setattr(publisher, "_compiled_command_extensions", read_binding)
        monkeypatch.setattr(publisher, "_publication_context", context)
        publisher._publish_once()
        assert len(mutation_epochs) == 1
        before, after = mutation_epochs[0]
        assert after > before
        assert context_epochs == [after] and publisher._epoch == after
        assert len(reads) == 1 and supplied[0] is reads[0]
        assert reads[0]["revision"] == 0
        assert not publisher.is_ready() and publisher.current_snapshot_binding() is None
        assert publisher.last_error == "native_command_control_binding_changed"
        assert calls == []

        publisher.request_publish()
        publisher._publish_once()
        assert publisher.is_ready(), publisher.last_error
        assert len(reads) == 4 and supplied[1:] == [None, None]
        assert len(calls) == 1 and ("source_input_digest" in calls[0]) is scoped
        assert reads[-1]["revision"] == 1
        assert reads[-2] == reads[-1] == calls[0]["command_extensions"]
        assert reads[-1]["effective_digest"] != reads[0]["effective_digest"]


@pytest.mark.parametrize("external_mutation", [False, True], ids=["steady", "concurrent-mutation"])
def test_start_commits_its_invalidation_before_the_first_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, external_mutation: bool
) -> None:
    """Exercise the real first attempt; the transport ACK is synthetic, not an SLO proof."""
    store = GuardStore(tmp_path / "guard")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    transport_entered = threading.Event()
    release_ack = threading.Event()
    first_completed = threading.Event()
    release_worker = threading.Event()
    calls: list[bytes] = []
    first_ready: list[bool] = []
    failures: list[BaseException] = []
    start_epochs: list[int] = []
    transport_epochs: list[int] = []
    starter_thread = threading.get_ident()

    def client_request(**kwargs: object) -> bytes:
        payload = kwargs["payload"]
        assert isinstance(payload, bytes)
        assert (store.guard_home / "native-runtime" / "policy-verifier.key").is_file()
        calls.append(payload)
        transport_epochs.append(publisher._epoch)
        transport_entered.set()
        assert release_ack.wait(_PUBLISH_TIMEOUT_SECONDS)
        if external_mutation:
            # A genuine newer request must still invalidate this ACK.
            publisher.request_publish()
        return _ack(payload)

    publisher = NativePolicySnapshotPublisher(store=store, status_provider=_status, client_request=client_request)
    assert publisher.register_workspace(workspace)
    original_request = publisher.request_publish
    original_publish = publisher._publish_once

    def request(*, require_source_authority: bool = False) -> None:
        starting = threading.get_ident() == starter_thread
        if starting and publisher._thread is not None:
            # Model a valid scheduling gap if start launches the worker before
            # committing its own final invalidation. No source read is replaced.
            assert transport_entered.wait(_PUBLISH_TIMEOUT_SECONDS)
        original_request(require_source_authority=require_source_authority)
        if starting:
            start_epochs.append(publisher._epoch)
            release_ack.set()

    def publish(*, renew_after_generation: int | None = None) -> None:
        try:
            original_publish(renew_after_generation=renew_after_generation)
            first_ready.append(publisher.is_ready())
        except BaseException as error:
            failures.append(error)
        finally:
            first_completed.set()
            # Inspect the completed first attempt before a later retry can
            # conceal an invalidation caused by start itself.
            if not release_worker.wait(_PUBLISH_TIMEOUT_SECONDS):
                failures.append(AssertionError("first publication inspection did not complete"))

    monkeypatch.setattr(publisher, "request_publish", request)
    monkeypatch.setattr(publisher, "_publish_once", publish)
    try:
        publisher.start()
        assert first_completed.wait(_PUBLISH_TIMEOUT_SECONDS)
        assert not failures
        assert len(calls) == 1
        assert first_ready == [not external_mutation], publisher.last_error
        assert transport_epochs == start_epochs
        if external_mutation:
            assert publisher._epoch == start_epochs[0] + 1
            assert publisher.current_snapshot() is None
        else:
            snapshot = publisher.current_snapshot()
            assert snapshot is not None
            assert publisher._epoch == start_epochs[0]
    finally:
        release_ack.set()
        publisher.close(timeout_seconds=0)
        release_worker.set()
        thread = publisher._thread
        if thread is not None:
            thread.join(timeout=_PUBLISH_TIMEOUT_SECONDS)
            assert not thread.is_alive()
