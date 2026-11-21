"""Source publication through the actual native resident, isolated local state."""

import time
from pathlib import Path
from threading import Event, Thread

from codex_plugin_scanner.guard import native_policy_snapshot_publisher as publisher_api
from codex_plugin_scanner.guard.native_policy_snapshot_publisher import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_native_business_document_compile import document
from tests.test_native_business_source_store import _grant, _install


def test_source_verification_does_not_block_readiness(tmp_path, native_mcp_probe, monkeypatch):
    store = GuardStore(tmp_path / "readiness-home")
    native_mcp_probe(store.guard_home)
    (store.guard_home / "config.toml").write_text('mode = "prompt"\nprotection_posture = "protected"\n')
    _install(store, document(), _grant(store, document()))
    publisher = NativePolicySnapshotPublisher(store=store)
    read = publisher._compiled_business_source
    reads = []
    readers = []

    def verify():
        reads.append(1)
        if len(reads) == 3:
            completed = Event()

            def readiness():
                publisher.is_ready()
                completed.set()

            reader = Thread(target=readiness)
            readers.append(reader)
            reader.start()
            assert completed.wait(1), "source verification held the readiness condition"
        return read()

    monkeypatch.setattr(publisher, "_compiled_business_source", verify)
    try:
        publisher._publish_once()
        assert len(reads) == 3
        assert publisher.is_ready(), publisher.last_error
    finally:
        publisher.close()
        for reader in readers:
            reader.join(timeout=2)


def test_actual_publisher_admits_exact_source_and_withdraws_on_source_loss(tmp_path: Path, native_mcp_probe):
    store = GuardStore(tmp_path / "publisher-home")
    native_mcp_probe(store.guard_home)
    (store.guard_home / "config.toml").write_text(
        'mode = "prompt"\nprotection_posture = "protected"\n', encoding="utf-8"
    )
    candidate = document()
    installed = _install(store, candidate, _grant(store, candidate))
    publisher = NativePolicySnapshotPublisher(store=store, poll_interval_seconds=0.05)
    publisher.start()
    try:
        assert publisher.wait_until_ready(time.monotonic() + 15), publisher.last_error
        snapshot = publisher.current_snapshot()
        assert snapshot is not None
        assert snapshot["business_policy"]["sourceDocumentDigest"] == installed.source.source_digest
        assert snapshot["mode"] == "enforce"
        (store.guard_home / "native-runtime" / "business-source-authority.v1.json").unlink()
        deadline = time.monotonic() + 6
        while publisher.is_ready() and time.monotonic() < deadline:
            time.sleep(0.02)
        assert not publisher.is_ready()
        assert publisher.current_snapshot() is None
    finally:
        publisher.close()


def test_actual_ack_is_refused_when_source_changes_before_barrier_commit(tmp_path: Path, native_mcp_probe, monkeypatch):
    store = GuardStore(tmp_path / "late-ack-home")
    native_mcp_probe(store.guard_home)
    (store.guard_home / "config.toml").write_text(
        'mode = "prompt"\nprotection_posture = "protected"\n', encoding="utf-8"
    )
    _install(store, document(1), _grant(store, document(1)))
    newer_grant = _grant(store, document(2), initialize=False)
    publish = publisher_api._publish_snapshot_v3
    acknowledged = []

    def replace_after_ack(**kwargs):
        result = publish(**kwargs)
        acknowledged.append(result[0]["generation"])
        _install(store, document(2), newer_grant)
        return result

    monkeypatch.setattr(publisher_api, "_publish_snapshot_v3", replace_after_ack)
    publisher = NativePolicySnapshotPublisher(store=store)
    try:
        publisher._publish_once()
        assert acknowledged
        assert not publisher.is_ready()
        assert publisher.current_snapshot() is None
        assert publisher.last_error == "native_business_source_binding_changed"
    finally:
        publisher.close()


def test_business_source_cannot_be_acknowledged_in_observe_mode(tmp_path: Path, native_mcp_probe):
    store = GuardStore(tmp_path / "observe-home")
    native_mcp_probe(store.guard_home)
    (store.guard_home / "config.toml").write_text('mode = "observe"\n', encoding="utf-8")
    _install(store, document(), _grant(store, document()))
    publisher = NativePolicySnapshotPublisher(store=store)
    try:
        publisher._publish_once()
        assert not publisher.is_ready()
        assert publisher.current_snapshot() is None
        assert publisher.last_error == "native_business_source_enforce_required"
    finally:
        publisher.close()


def test_source_replacement_between_post_ack_read_and_barrier_is_refused(tmp_path, native_mcp_probe, monkeypatch):
    store = GuardStore(tmp_path / "barrier-gap-home")
    native_mcp_probe(store.guard_home)
    (store.guard_home / "config.toml").write_text('mode = "prompt"\nprotection_posture = "protected"\n')
    _install(store, document(1), _grant(store, document(1)))
    newer_grant = _grant(store, document(2), initialize=False)
    publisher = NativePolicySnapshotPublisher(store=store)
    read = publisher._compiled_business_source
    reads = []

    def replace_after_read():
        result = read()
        reads.append(1)
        if len(reads) == 2:
            _install(store, document(2), newer_grant)
        return result

    monkeypatch.setattr(publisher, "_compiled_business_source", replace_after_read)
    try:
        publisher._publish_once()
        assert len(reads) == 3
        assert not publisher.is_ready() and publisher.current_snapshot() is None
        assert publisher.last_error == "native_business_source_binding_changed"
    finally:
        publisher.close()
