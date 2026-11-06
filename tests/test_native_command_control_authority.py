"""Bounded signed marker, durable private writes, and cross-process locking."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import subprocess
import sys
import threading
import time
from copy import deepcopy
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.native_command_control_authority import (
    AUTHORITY_DOMAIN,
    AUTHORITY_FILE_NAME,
    AUTHORITY_KEY_DOMAIN,
    AUTHORITY_MAX_BYTES,
    AUTHORITY_SCHEMA,
    FLOOR_LINK_DOMAIN,
    RECOVERY_SCHEMA,
    ZERO_DIGEST,
    authority_binding,
    authority_key_id,
    decode_authority,
    encode_authority,
    floor_link_digest,
    validate_authority_binding,
    validate_control_floor,
)
from codex_plugin_scanner.guard.native_command_control_authority_io import (
    NativeCommandControlAuthorityUnavailableError,
    NativeCommandControlMutationRequiredError,
    hold_command_control_authority_lock,
    read_private_state,
    require_command_control_mutation_lease,
    write_private_state,
)
from codex_plugin_scanner.guard.native_policy_snapshot_constants import NativePolicySnapshotError

READER_COUNT = 6

KEY = b"k" * 32
# The resident only digests a snapshot named by a real catalog digest.
_CATALOG_DIGEST = "0" * 64


def test_shared_python_rust_authority_vectors() -> None:
    path = Path(__file__).parents[1] / "contracts/extensions/native-command-control-authority.v1.fixtures.json"
    fixture = json.loads(path.read_text())
    verifier_key = bytes.fromhex(fixture["verifier_key_hex"])
    for vector in fixture["vectors"]:
        expected = vector["canonical_signed_json"].encode()
        assert encode_authority(vector["record"], verifier_key) == expected
        assert decode_authority(expected, verifier_key)["schema"] == AUTHORITY_SCHEMA
    assert floor_link_digest(fixture["current_floor"]) == fixture["current_floor_link_digest"]
    assert floor_link_digest(None) == fixture["null_floor_link_digest"]


def _record() -> dict:
    return {
        "schema": AUTHORITY_SCHEMA,
        "epoch": 2,
        "mutation_revision": 9,
        "authority_key_id": "1" * 64,
        "phase": "committed",
        "effective_digest": "2" * 64,
        "recovery": {
            "schema": RECOVERY_SCHEMA,
            "previous_epoch": 1,
            "previous_mutation_revision": 6,
            "previous_authority_key_id": "3" * 64,
            "previous_floor_digest": "4" * 64,
            "nonce": "5" * 64,
        },
    }


def test_authority_domains_and_exact_body_authentication() -> None:
    body = _record()
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    encoded = encode_authority(body, KEY)
    decoded = decode_authority(encoded, KEY)
    assert decoded["mac"] == hmac.new(KEY, AUTHORITY_DOMAIN + canonical, hashlib.sha256).hexdigest()
    assert authority_binding(decoded) == {
        key: body[key] for key in ("epoch", "mutation_revision", "authority_key_id", "recovery")
    }
    assert authority_key_id(KEY) == hashlib.sha256(AUTHORITY_KEY_DOMAIN + KEY).hexdigest()
    assert authority_key_id(None) == ZERO_DIGEST
    assert floor_link_digest(None) == hashlib.sha256(FLOOR_LINK_DOMAIN + b"null").hexdigest()
    with pytest.raises(NativePolicySnapshotError, match="integrity"):
        decode_authority(encoded, b"x" * 32)
    with pytest.raises(NativePolicySnapshotError, match="integrity"):
        decode_authority(encoded.replace(b'"mutation_revision":9', b'"mutation_revision":8'), KEY)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("schema", "unknown"),
        ("epoch", True),
        ("epoch", 0),
        ("mutation_revision", 0),
        ("mutation_revision", 1 << 64),
        ("authority_key_id", "A" * 64),
        ("phase", "open"),
        ("phase", []),
        ("effective_digest", None),
        ("recovery", {}),
        ("unknown", 1),
    ],
)
def test_invalid_marker_shapes_are_not_signed(field: str, value: object) -> None:
    candidate = _record()
    candidate[field] = value
    with pytest.raises(NativePolicySnapshotError):
        encode_authority(candidate, KEY)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("schema", "unknown"),
        ("previous_epoch", 2),
        ("previous_epoch", -1),
        ("previous_mutation_revision", 9),
        ("previous_mutation_revision", False),
        ("previous_authority_key_id", None),
        ("previous_floor_digest", "g" * 64),
        ("nonce", "x"),
        ("unknown", 1),
    ],
)
def test_recovery_requires_valid_prior_context(field: str, value: object) -> None:
    candidate = _record()
    candidate["recovery"][field] = value
    with pytest.raises(NativePolicySnapshotError):
        encode_authority(candidate, KEY)


def test_closed_marker_has_no_effective_digest_and_decoding_is_bounded() -> None:
    candidate = {**_record(), "phase": "closed", "effective_digest": None}
    encoded = encode_authority(candidate, KEY)
    assert decode_authority(encoded, KEY)["phase"] == "closed"
    with pytest.raises(NativePolicySnapshotError):
        encode_authority({**candidate, "effective_digest": "a" * 64}, KEY)
    for invalid in (b"", b"x" * (AUTHORITY_MAX_BYTES + 1), b'{"epoch":1,"epoch":2}'):
        with pytest.raises(NativePolicySnapshotError):
            decode_authority(invalid, KEY)


def test_extended_floor_authenticates_the_retained_recovery_link() -> None:
    authority = authority_binding(_record())
    floor = {
        "revision": 0,
        "managed_revision": 2,
        "effective_digest": "a" * 64,
        "authority": authority,
        "previous_floor_digest": "4" * 64,
    }
    assert validate_control_floor(floor) == floor
    changed = deepcopy(floor)
    changed["previous_floor_digest"] = "b" * 64
    with pytest.raises(NativePolicySnapshotError):
        validate_control_floor(changed)
    with pytest.raises(NativePolicySnapshotError):
        validate_authority_binding({**authority, "unknown": 1})


def test_private_marker_handles_short_writes_and_rejects_links(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import codex_plugin_scanner.guard.native_command_control_authority_io as io_module

    encoded = encode_authority(_record(), KEY)
    original_write = os.write
    monkeypatch.setattr(io_module.os, "write", lambda fd, data: original_write(fd, data[:7]))
    write_private_state(tmp_path, AUTHORITY_FILE_NAME, encoded, AUTHORITY_MAX_BYTES)
    assert read_private_state(tmp_path, AUTHORITY_FILE_NAME, AUTHORITY_MAX_BYTES) == encoded
    path = tmp_path / "native-runtime" / AUTHORITY_FILE_NAME
    if os.name != "nt":
        linked = tmp_path / "linked.json"
        os.link(path, linked)
        with pytest.raises(NativePolicySnapshotError):
            read_private_state(tmp_path, AUTHORITY_FILE_NAME, AUTHORITY_MAX_BYTES)
        linked.unlink()
        path.unlink()
        path.symlink_to(tmp_path / "absent.json")
        with pytest.raises(OSError):
            read_private_state(tmp_path, AUTHORITY_FILE_NAME, AUTHORITY_MAX_BYTES)


def test_mutation_requirement_accepts_exclusive_lease_and_rejects_shared_lease(tmp_path: Path) -> None:
    with hold_command_control_authority_lock(tmp_path):
        require_command_control_mutation_lease(tmp_path)
    with (
        hold_command_control_authority_lock(tmp_path, shared=True),
        pytest.raises(NativeCommandControlMutationRequiredError),
    ):
        require_command_control_mutation_lease(tmp_path)


@pytest.mark.skipif(os.name == "nt", reason="POSIX retained-inode identity replacement fault")
def test_mutation_lock_rejects_inode_replacement_and_allows_same_thread_reads(tmp_path: Path) -> None:
    with (
        pytest.raises(NativePolicySnapshotError, match="path_invalid"),
        hold_command_control_authority_lock(tmp_path),
    ):
        with hold_command_control_authority_lock(tmp_path, timeout_seconds=0):
            pass
        with hold_command_control_authority_lock(tmp_path / ".." / tmp_path.name, timeout_seconds=0):
            pass
        lock = tmp_path / "extension-control-authority.lock"
        lock.rename(tmp_path / "old.lock")
        lock.write_bytes(b"0")
    with hold_command_control_authority_lock(tmp_path):
        assert (tmp_path / "extension-control-authority.lock").stat().st_mode & 0o777 == 0o600


@pytest.mark.skipif(not hasattr(os, "fork"), reason="fork inheritance is a POSIX process boundary")
def test_fork_does_not_inherit_reentrant_mutation_ownership(tmp_path: Path) -> None:
    with hold_command_control_authority_lock(tmp_path):
        child = os.fork()
        if child == 0:
            try:
                with hold_command_control_authority_lock(tmp_path, timeout_seconds=0):
                    os._exit(2)
            except TimeoutError:
                os._exit(0)
            except BaseException:
                os._exit(3)
        _, status = os.waitpid(child, 0)
        assert os.waitstatus_to_exitcode(status) == 0


@pytest.mark.skipif(not hasattr(os, "fork"), reason="fork inheritance is a POSIX process boundary")
@pytest.mark.parametrize("shared", [False, True])
def test_child_unwinding_inherited_context_does_not_unlock_parent(tmp_path: Path, shared: bool) -> None:
    parent = os.getpid()
    try:
        with hold_command_control_authority_lock(tmp_path, shared=shared):
            child = os.fork()
            if child == 0:
                return  # Unwind the inherited context before exiting this process.
            _, status = os.waitpid(child, 0)
            assert os.waitstatus_to_exitcode(status) == 0
            script = """
import fcntl, pathlib, sys
with (pathlib.Path(sys.argv[1]) / 'extension-control-authority.lock').open('r+b') as handle:
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        sys.exit(0)
    sys.exit(2)
"""
            result = subprocess.run([sys.executable, "-c", script, str(tmp_path)], timeout=5, check=False)
            assert result.returncode == 0
    finally:
        if os.getpid() != parent:
            os._exit(0)


@pytest.mark.skipif(os.name == "nt", reason="Windows fs2/msvcrt overlap is qualified by the native integration suite")
def test_foreign_shared_evaluation_lease_excludes_python_mutation(tmp_path: Path) -> None:
    with hold_command_control_authority_lock(tmp_path):
        pass
    script = """
import fcntl, pathlib, sys
with (pathlib.Path(sys.argv[1]) / 'extension-control-authority.lock').open('r+b') as handle:
    fcntl.flock(handle.fileno(), fcntl.LOCK_SH)
    print('leased', flush=True)
    sys.stdin.readline()
"""
    process = subprocess.Popen(
        [sys.executable, "-c", script, str(tmp_path)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True
    )
    try:
        assert process.stdout is not None and process.stdout.readline() == "leased\n"
        with pytest.raises(TimeoutError), hold_command_control_authority_lock(tmp_path, timeout_seconds=0):
            pytest.fail("mutation acquired a shared evaluation lease")
        process.communicate("release\n", timeout=5)
        assert process.returncode == 0
        with hold_command_control_authority_lock(tmp_path, timeout_seconds=0):
            pass
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)


@pytest.mark.skipif(os.name == "nt", reason="Windows fs2/msvcrt overlap is qualified by the native integration suite")
def test_waiting_mutation_is_not_starved_by_overlapping_shared_leases(tmp_path: Path) -> None:
    """A publisher that keeps re-reading must not hold a mutation out forever."""

    with hold_command_control_authority_lock(tmp_path, shared=True):
        pass
    stop = threading.Event()
    entered = threading.Barrier(READER_COUNT + 1)

    def reader() -> None:
        entered.wait()
        while not stop.is_set():
            with hold_command_control_authority_lock(tmp_path, shared=True):
                time.sleep(0.05)

    readers = [threading.Thread(target=reader, daemon=True) for _ in range(READER_COUNT)]
    for thread in readers:
        thread.start()
    try:
        entered.wait()
        time.sleep(0.2)
        started = time.monotonic()
        with hold_command_control_authority_lock(tmp_path, timeout_seconds=20.0):
            waited = time.monotonic() - started
    finally:
        stop.set()
        for thread in readers:
            thread.join(timeout=5)
    # The readers hold overlapping leases for the whole interval, so a
    # nonblocking exclusive request would still be polling here.
    assert waited < 5.0


def test_reader_and_writer_leases_still_exclude_each_other(tmp_path: Path) -> None:
    with hold_command_control_authority_lock(tmp_path, shared=True):
        pass
    held = threading.Event()
    release = threading.Event()

    def holder() -> None:
        with hold_command_control_authority_lock(tmp_path, shared=True):
            held.set()
            release.wait(timeout=10)

    thread = threading.Thread(target=holder, daemon=True)
    thread.start()
    try:
        assert held.wait(timeout=10)
        with (
            pytest.raises(TimeoutError),
            hold_command_control_authority_lock(tmp_path, timeout_seconds=0.2),
        ):
            pytest.fail("a mutation overlapped a live shared lease")
    finally:
        release.set()
        thread.join(timeout=10)
    with hold_command_control_authority_lock(tmp_path, timeout_seconds=1.0):
        pass


def test_lease_timeout_reports_unavailability_rather_than_a_verdict(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.store_extension_control_authority_reads import (
        ExtensionControlAuthorityReadsMixin,
    )

    class _Registry:
        catalog_digest = "0" * 64

    class _Store(ExtensionControlAuthorityReadsMixin):
        def __init__(self, error: Exception) -> None:
            self.error = error
            self.verdicts = 0

        def _extension_control_authority_lock(self, *, shared: bool = False, timeout_seconds: float | None = None):
            raise self.error

        def _catalog_target_manifest(self, registry: object) -> dict[str, str]:
            return {}

        def _degraded_view(self, catalog_digest: str) -> str:
            self.verdicts += 1
            return "degraded"

        def _tampered_view(self, catalog_digest: str) -> str:
            self.verdicts += 1
            return "tampered"

    outage = NativeCommandControlAuthorityUnavailableError(shared=False)
    for store in (_Store(outage), _Store(outage)):
        with pytest.raises(NativeCommandControlAuthorityUnavailableError):
            store.read_extension_control_authority(catalog_digest="0" * 64)
        with pytest.raises(NativeCommandControlAuthorityUnavailableError):
            store.read_extension_control_authority_for_registry(_Registry())
        assert store.verdicts == 0

    # Every other failure keeps its existing verdict.
    failing = _Store(RuntimeError("database is locked"))
    assert failing.read_extension_control_authority(catalog_digest="0" * 64) == "degraded"
    assert failing.verdicts == 1


def _startup_view_with_store(store: object) -> object:
    from codex_plugin_scanner.guard.daemon.server import _GuardDaemonHTTPServer
    from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY

    server = object.__new__(_GuardDaemonHTTPServer)
    server.store = store  # type: ignore[attr-defined]
    return _GuardDaemonHTTPServer._startup_extension_control_view(server, BUILT_IN_COMMAND_EXTENSION_REGISTRY)


def test_daemon_startup_falls_back_to_a_shared_read_when_the_lease_is_busy() -> None:
    """A busy lease must not stop the daemon: it would take the hook worker with it."""

    from codex_plugin_scanner.guard.native_command_control_authority_io import (
        AUTHORITY_LOCK_TIMEOUT_SECONDS,
        NativeCommandControlAuthorityUnavailableError,
    )
    from codex_plugin_scanner.guard.runtime.extension_control_authority import (
        AuthorityHealth,
        ExtensionControlAuthorityView,
    )

    protected = ExtensionControlAuthorityView(AuthorityHealth.PROTECTED, 7, _CATALOG_DIGEST, ())

    class _Store:
        def __init__(self) -> None:
            self.reads: list[tuple[bool, float | None]] = []

        def read_extension_control_authority_for_registry(
            self, registry: object, *, read_only: bool = False, lock_timeout_seconds: float | None = None
        ) -> ExtensionControlAuthorityView:
            self.reads.append((read_only, lock_timeout_seconds))
            if not read_only:
                raise NativeCommandControlAuthorityUnavailableError(shared=False)
            return protected

        def extension_control_authority_unreadable_view(self, catalog_digest: str) -> ExtensionControlAuthorityView:
            raise AssertionError("the shared read answered, so no fallback view is warranted")

    store = _Store()
    assert _startup_view_with_store(store) is protected
    assert [read_only for read_only, _ in store.reads] == [False, True]
    # Both attempts queue behind the same exclusive entry gate, so the fallback
    # waits out what the first attempt left rather than a second full budget.
    first, second = (budget for _, budget in store.reads)
    assert first == AUTHORITY_LOCK_TIMEOUT_SECONDS / 2
    assert second is not None and 0.0 < second <= AUTHORITY_LOCK_TIMEOUT_SECONDS


def test_daemon_startup_leaves_the_shared_fallback_a_span_to_run_in(monkeypatch: object) -> None:
    """An exclusive attempt that waits out its whole budget must not starve the fallback."""

    import time as time_module

    from codex_plugin_scanner.guard.native_command_control_authority_io import (
        AUTHORITY_LOCK_TIMEOUT_SECONDS,
        NativeCommandControlAuthorityUnavailableError,
    )
    from codex_plugin_scanner.guard.runtime.extension_control_authority import (
        AuthorityHealth,
        ExtensionControlAuthorityView,
    )

    protected = ExtensionControlAuthorityView(AuthorityHealth.PROTECTED, 7, _CATALOG_DIGEST, ())
    clock = [1000.0]
    monkeypatch.setattr(time_module, "monotonic", lambda: clock[0])  # type: ignore[attr-defined]

    class _Store:
        def __init__(self) -> None:
            self.reads: list[tuple[bool, float | None]] = []

        def read_extension_control_authority_for_registry(
            self, registry: object, *, read_only: bool = False, lock_timeout_seconds: float | None = None
        ) -> ExtensionControlAuthorityView:
            self.reads.append((read_only, lock_timeout_seconds))
            if not read_only:
                # A busy lease spends the whole budget it was handed before it
                # reports that it read nothing.
                clock[0] += lock_timeout_seconds or 0.0
                raise NativeCommandControlAuthorityUnavailableError(shared=False)
            return protected

        def extension_control_authority_unreadable_view(self, catalog_digest: str) -> ExtensionControlAuthorityView:
            raise AssertionError("the fallback had budget left, so it must have been tried")

    store = _Store()
    assert _startup_view_with_store(store) is protected
    assert [read_only for read_only, _ in store.reads] == [False, True]
    assert store.reads[1][1] == AUTHORITY_LOCK_TIMEOUT_SECONDS / 2


def test_daemon_startup_reports_no_layers_when_no_lease_is_obtainable() -> None:
    """An unread authority grants nothing; the next refresh replaces this view."""

    from codex_plugin_scanner.guard.native_command_control_authority_io import (
        NativeCommandControlAuthorityUnavailableError,
    )
    from codex_plugin_scanner.guard.runtime.extension_control_authority import (
        AuthorityHealth,
        ExtensionControlAuthorityView,
    )

    unreadable = ExtensionControlAuthorityView(AuthorityHealth.DEGRADED_UNACKNOWLEDGED, 0, _CATALOG_DIGEST, ())

    class _Store:
        def read_extension_control_authority_for_registry(
            self, registry: object, *, read_only: bool = False, lock_timeout_seconds: float | None = None
        ) -> ExtensionControlAuthorityView:
            raise NativeCommandControlAuthorityUnavailableError(shared=read_only)

        def extension_control_authority_unreadable_view(self, catalog_digest: str) -> ExtensionControlAuthorityView:
            return unreadable

    view = _startup_view_with_store(_Store())
    assert view is unreadable
    assert not view.layers


def test_unreadable_authority_view_is_marked_unread() -> None:
    """The fallback view reports that nothing was read, not that protection was lost."""

    from codex_plugin_scanner.guard.runtime.extension_control_runtime import ExtensionControlRuntimeSnapshot
    from codex_plugin_scanner.guard.store_extension_control_authority_support import (
        _ExtensionControlAuthoritySupportMixin,
    )

    class _Support(_ExtensionControlAuthoritySupportMixin):
        def __init__(self) -> None:
            self._extension_control_degraded_acknowledged = False

    view = _Support().extension_control_authority_unreadable_view(_CATALOG_DIGEST)
    assert view.unread is True
    assert not view.layers
    assert ExtensionControlRuntimeSnapshot.from_authority_view(view).unread is True


def test_acknowledging_degraded_mode_refuses_an_unread_authority() -> None:
    """Acknowledging an unread authority would persist an outage nobody observed."""

    import pytest

    from codex_plugin_scanner.guard.daemon.extension_control_api import ExtensionControlApiService
    from codex_plugin_scanner.guard.daemon.extension_control_errors import ExtensionControlApiError
    from codex_plugin_scanner.guard.runtime.extension_control_authority import (
        AuthorityHealth,
        ExtensionControlAuthorityView,
    )
    from codex_plugin_scanner.guard.runtime.extension_control_runtime import ExtensionControlRuntimeSnapshot

    class _Runtime:
        def __init__(self, snapshot: ExtensionControlRuntimeSnapshot) -> None:
            self._snapshot = snapshot

        def current(self) -> ExtensionControlRuntimeSnapshot:
            return self._snapshot

    def _service(view: ExtensionControlAuthorityView) -> ExtensionControlApiService:
        service = object.__new__(ExtensionControlApiService)
        service._runtime = _Runtime(ExtensionControlRuntimeSnapshot.from_authority_view(view))
        return service

    unread = ExtensionControlAuthorityView(AuthorityHealth.DEGRADED_UNACKNOWLEDGED, 0, _CATALOG_DIGEST, (), unread=True)
    with pytest.raises(ExtensionControlApiError) as unread_error:
        _ = _service(unread).acknowledge_degraded({})
    assert unread_error.value.status == 503
    assert unread_error.value.code == "authority_unread"

    # A read authority that really is degraded still reaches the grant check.
    observed = ExtensionControlAuthorityView(AuthorityHealth.PROTECTED, 3, _CATALOG_DIGEST, ())
    with pytest.raises(ExtensionControlApiError) as protected_error:
        _ = _service(observed).acknowledge_degraded({})
    assert protected_error.value.code == "authority_not_degraded"


def test_refresh_serves_the_held_snapshot_when_the_lease_is_busy(monkeypatch: pytest.MonkeyPatch) -> None:
    """A busy lease leaves the refresh without a reading; the route still answers."""

    from codex_plugin_scanner.guard.daemon import extension_control_api as api_module
    from codex_plugin_scanner.guard.runtime.extension_control_authority import (
        AuthorityHealth,
        ExtensionControlAuthorityView,
    )
    from codex_plugin_scanner.guard.runtime.extension_control_runtime import ExtensionControlRuntimeSnapshot

    held = ExtensionControlRuntimeSnapshot.from_authority_view(
        ExtensionControlAuthorityView(AuthorityHealth.PROTECTED, 4, _CATALOG_DIGEST, ())
    )

    class _Runtime:
        def current(self) -> ExtensionControlRuntimeSnapshot:
            return held

        def refresh(self, view: object) -> ExtensionControlRuntimeSnapshot:
            raise AssertionError("a busy lease must not reach the runtime refresh")

    class _Store:
        def read_extension_control_authority_for_registry(self, registry: object) -> ExtensionControlAuthorityView:
            raise NativeCommandControlAuthorityUnavailableError(shared=False)

    served: list[ExtensionControlRuntimeSnapshot] = []

    def _payload(registry: object, snapshot: ExtensionControlRuntimeSnapshot, store: object) -> dict[str, object]:
        served.append(snapshot)
        return {"health": snapshot.health.value}

    monkeypatch.setattr(api_module, "effective_controls_payload", _payload)
    service = object.__new__(api_module.ExtensionControlApiService)
    service._runtime = _Runtime()
    service._store = _Store()
    service._registry = object()

    assert service.refresh() == {"health": "protected"}
    assert served == [held]
