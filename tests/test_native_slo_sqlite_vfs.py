"""Executed callback controls and actual Python SQLite transactions, separately."""

from __future__ import annotations

import contextlib
import ctypes
import hashlib
import json
import shlex
import shutil
import sqlite3
import subprocess
import sys
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from codex_plugin_scanner.guard.daemon.runtime_hook_evidence_queue_observation import EvidenceQueueObservation
from codex_plugin_scanner.guard.daemon.runtime_hook_evidence_writer import RuntimeHookEvidenceWriter
from codex_plugin_scanner.guard.store import GuardStore
from scripts.native_slo_mixed_request import fixture_request
from scripts.native_slo_mixed_witness import ReceiptWitness
from scripts.native_slo_sqlite_vfs import SQLiteVFSObservation
from tests.test_native_decision_receipt import _receipt

pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or sys.version_info < (3, 12),
    reason="Linux and Python 3.12 SQLite extension entrypoint admission required",
)
SOURCE = Path(__file__).resolve().parents[1] / "scripts" / "ci" / "rsp131_sqlite_vfs"
CALLBACK_CASES = (
    "v1",
    "v2",
    "v3",
    "optional",
    "vfs",
    "failed_open_without_methods",
    "failed_open_with_methods",
    "unknown_version",
    "thread",
    "saturation",
)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture(scope="session")
def sqlite_vfs_build(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    compiler = shutil.which("cc")
    assert compiler is not None, "a C compiler and SQLite development headers are required"
    root = tmp_path_factory.mktemp("rsp131-sqlite-vfs-build")
    extension = root / "guard_vfs.so"
    fixture = root / "forward_fixture"
    common = [compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", "-fvisibility=hidden", "-pthread", "-I", str(SOURCE)]
    commands = [
        [
            *common,
            "-MD",
            "-MF",
            str(root / "extension.d"),
            "-fPIC",
            "-shared",
            str(SOURCE / "io.c"),
            str(SOURCE / "vfs.c"),
            str(SOURCE / "control.c"),
            "-ldl",
            "-o",
            str(extension),
        ],
        [
            *common,
            "-MD",
            "-MF",
            str(root / "fixture.d"),
            "-DSQLITE_CORE=1",
            str(SOURCE / "io.c"),
            str(SOURCE / "vfs.c"),
            str(SOURCE / "forward_fixture.c"),
            "-o",
            str(fixture),
        ],
    ]
    receipts = []
    for index, argv in enumerate(commands):
        result = subprocess.run(argv, capture_output=True, text=True, timeout=30, check=False)
        receipt = {"argv": argv, "returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr}
        receipts.append(receipt)
        (root / f"compile-{index}.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
        assert result.returncode == 0, receipt
    dependencies = set()
    dependency_text = {}
    for name in ("extension.d", "fixture.d"):
        raw = (root / name).read_text(encoding="utf-8")
        dependency_text[name] = raw
        flattened = raw.replace("\\\n", "")
        assert flattened.count(":") == 1 and "$" not in flattened and "#" not in flattened
        dependencies.update(Path(item).resolve(strict=True) for item in shlex.split(flattened.split(":", 1)[1]))
    assert any(path.name == "sqlite3.h" for path in dependencies)
    assert any(path.name == "sqlite3ext.h" for path in dependencies)
    result = {
        "extension": extension,
        "fixture": fixture,
        "extension_sha256": _sha(extension),
        "fixture_sha256": _sha(fixture),
        "source_sha256": {path.name: _sha(path) for path in sorted(SOURCE.glob("*.[ch]"))},
        "compilation": receipts,
        "compiler_sha256": _sha(Path(compiler).resolve(strict=True)),
        "dependency_files": dependency_text,
        "included_file_sha256": {str(path): _sha(path) for path in sorted(dependencies)},
    }
    (root / "build-receipt.json").write_text(json.dumps(result, default=str, indent=2) + "\n", encoding="utf-8")
    return result


@pytest.mark.parametrize("case", CALLBACK_CASES)
def test_actual_compiled_callback_forwarding(sqlite_vfs_build: dict[str, Any], case: str) -> None:
    result = subprocess.run(
        [str(sqlite_vfs_build["fixture"]), case], capture_output=True, text=True, timeout=5, check=False
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {"control": case, "passed": True, "scope": "portable_callback_fixture"}


def _database(path: Path, mode: str = "wal") -> Path:
    connection = sqlite3.connect(path)
    try:
        assert connection.execute(f"pragma journal_mode={mode}").fetchone()[0] == mode
        connection.execute("create table facts (key text primary key, value text not null)")
        connection.commit()
    finally:
        connection.close()
    path.chmod(0o600)
    return path


def _observer(database: Path, build: dict[str, Any]) -> SQLiteVFSObservation:
    return SQLiteVFSObservation(
        database=database, extension=build["extension"], extension_sha256=build["extension_sha256"]
    )


def _cell(report: dict[str, Any], scope: str, role: str) -> dict[str, int]:
    return next(cell for cell in report["vfs"]["cells"] if cell["scope"] == scope and cell["file_role"] == role)


@pytest.mark.parametrize("mode", ["wal", "delete"])
def test_actual_python_engine_commit_rollback_and_busy_equal_without_observer(
    tmp_path: Path, sqlite_vfs_build: dict[str, Any], mode: str
) -> None:
    outcomes = []
    for observed in (False, True):
        database = _database(tmp_path / f"{observed}.db", mode)
        observer = _observer(database, sqlite_vfs_build) if observed else None

        def connect(observer: SQLiteVFSObservation | None = observer, database: Path = database) -> sqlite3.Connection:
            return (
                observer.connect(scope="writer", timeout=0.02) if observer else sqlite3.connect(database, timeout=0.02)
            )

        first = connect()
        try:
            first.execute("insert into facts values ('kept', 'original')")
            first.commit()
            first.execute("update facts set value='rolled-back'")
            first.rollback()
            first.execute("insert into facts values ('pending', 'not-committed')")
            second = connect()
            try:
                with pytest.raises(sqlite3.OperationalError) as error:
                    second.execute("insert into facts values ('blocked', 'never')")
                assert error.value.sqlite_errorcode == sqlite3.SQLITE_BUSY
            finally:
                second.close()
            first.rollback()
            outcomes.append(first.execute("select key, value from facts order by key").fetchall())
        finally:
            first.close()
            if observer is not None:
                assert observer.close()
        if observer is not None:
            report = observer.report()
            assert report["identity"]["extension_loaded_by_actual_python_connection"]
            assert report["identity"]["actual_sqlite_api_image"]["sha256"]
            assert report["identity"]["sqlite_source_id"] == report["vfs"]["sqlite_source_id"]
            assert report["vfs"]["default_vfs_unchanged"] is True
            assert report["vfs"]["registered"] is False
            assert report["all_vfs_files_closed"] is True
            assert report["connection_scope_at_open_complete"] is True
            role = "wal" if mode == "wal" else "rollback_journal"
            assert _cell(report, "writer", role)["vfs_x_write_success_bytes"] > 0
            assert sum(cell["vfs_x_sync_calls"] for cell in report["vfs"]["cells"]) > 0
            assert report["scope"] == "explicit_named_vfs_local_control_connections"
            assert report["qualified"] is False
            assert report["unavailable"]["kernel_fsync_calls"] == "VFS_xSync_is_not_a_kernel_syscall_count"
    assert outcomes == [[("kept", "original")], [("kept", "original")]]


def test_writer_and_readback_connections_have_distinct_actual_opening_threads(
    tmp_path: Path, sqlite_vfs_build: dict[str, Any]
) -> None:
    observer = _observer(_database(tmp_path / "threads.db"), sqlite_vfs_build)
    written, read_done = threading.Event(), threading.Event()
    errors: list[BaseException] = []
    rows: list[Any] = []

    def write() -> None:
        connection = None
        try:
            connection = observer.connect(scope="writer")
            connection.execute("insert into facts values ('thread', 'value')")
            connection.commit()
            written.set()
            if not read_done.wait(5):
                raise TimeoutError("readback thread did not complete")
        except BaseException as error:
            errors.append(error)
            written.set()
        finally:
            if connection is not None:
                connection.close()

    def read() -> None:
        connection = None
        try:
            if not written.wait(5):
                raise TimeoutError("writer thread did not signal completion")
            connection = observer.connect(scope="readback")
            rows.extend(connection.execute("select key, value from facts").fetchall())
        except BaseException as error:
            errors.append(error)
        finally:
            if connection is not None:
                connection.close()
            read_done.set()

    threads = [threading.Thread(target=write), threading.Thread(target=read)]
    try:
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(10)
        assert not any(thread.is_alive() for thread in threads)
        assert not errors and rows == [("thread", "value")]
    finally:
        assert observer.close()
    report = observer.report()
    assert report["attested_connections"] == {"other": 0, "writer": 1, "readback": 1}
    assert _cell(report, "writer", "main_database")["vfs_x_open_calls"] == 1
    assert _cell(report, "readback", "main_database")["vfs_x_open_calls"] == 1
    assert report["connection_scope_at_open_complete"] is True


def test_cross_thread_connection_is_forwarded_but_scope_coverage_is_refused(
    tmp_path: Path, sqlite_vfs_build: dict[str, Any]
) -> None:
    observer = _observer(_database(tmp_path / "moved.db"), sqlite_vfs_build)
    connection = observer.connect(scope="writer", check_same_thread=False)
    errors: list[BaseException] = []

    def work() -> None:
        try:
            connection.execute("insert into facts values ('moved', 'thread')")
            connection.commit()
        except BaseException as error:
            errors.append(error)

    thread = threading.Thread(target=work)
    try:
        thread.start()
        thread.join(5)
        assert not thread.is_alive() and not errors
        assert connection.execute("select value from facts").fetchall() == [("thread",)]
    finally:
        connection.close()
        assert observer.close()
    report = observer.report()
    assert sum(cell["calls_on_different_thread"] for cell in report["vfs"]["cells"]) > 0
    assert report["connection_scope_at_open_complete"] is False


def test_live_file_retains_callbacks_until_actual_close_and_default_connections_continue(
    tmp_path: Path, sqlite_vfs_build: dict[str, Any]
) -> None:
    database = _database(tmp_path / "live.db")
    observer = _observer(database, sqlite_vfs_build)
    connection = observer.connect(scope="writer")
    assert observer.close() is False
    assert observer.report()["all_vfs_files_closed"] is False
    connection.execute("insert into facts values ('still', 'live')")
    connection.commit()
    connection.close()
    assert observer.close() is True
    exported = observer.report()
    exported["vfs"]["cells"].clear()
    exported["identity"]["extension"]["sha256"] = "mutated-copy"
    assert len(observer.report()["vfs"]["cells"]) == 12
    assert observer.report()["identity"]["extension"]["sha256"] == sqlite_vfs_build["extension_sha256"]
    regular = sqlite3.connect(database)
    try:
        assert regular.execute("select value from facts").fetchall() == [("live",)]
    finally:
        regular.close()
    with pytest.raises(sqlite3.OperationalError, match="no such vfs"):
        sqlite3.connect(f"{database.as_uri()}?vfs={observer.name}", uri=True)


def test_vfs_name_collision_refuses_without_changing_active_registry(
    tmp_path: Path, sqlite_vfs_build: dict[str, Any]
) -> None:
    database = _database(tmp_path / "collision.db")
    with _observer(database, sqlite_vfs_build) as observer:
        duplicate = sqlite3.connect(":memory:")
        try:
            duplicate.enable_load_extension(True)
            duplicate.load_extension(str(sqlite_vfs_build["extension"]), entrypoint="sqlite3_guardvfsext_init")
            duplicate.enable_load_extension(False)
            with pytest.raises(sqlite3.InterfaceError) as error:
                duplicate.execute("select guard_sqlite_vfs(?, ?, ?)", ("register", observer.name, str(database)))
            assert type(error.value) is sqlite3.InterfaceError
            assert str(error.value) == "SQLite VFS observer admission or lifecycle refused"
            assert error.value.sqlite_errorcode == sqlite3.SQLITE_MISUSE
            assert error.value.sqlite_errorname == "SQLITE_MISUSE"
            assert observer.report()["vfs"]["default_vfs_unchanged"] is True
            connection = observer.connect()
            connection.close()
        finally:
            duplicate.close()


@pytest.mark.parametrize("failure", ["wrong_hash", "symlink", "other_writable"])
def test_extension_descriptor_admission_refuses_before_observation(
    tmp_path: Path, sqlite_vfs_build: dict[str, Any], failure: str
) -> None:
    extension = tmp_path / "extension.so"
    expected = sqlite_vfs_build["extension_sha256"]
    if failure == "symlink":
        extension.symlink_to(sqlite_vfs_build["extension"])
    else:
        shutil.copyfile(sqlite_vfs_build["extension"], extension)
        extension.chmod(0o666 if failure == "other_writable" else 0o600)
    if failure == "wrong_hash":
        expected = "0" * 64
    with pytest.raises((ValueError, OSError)):
        SQLiteVFSObservation(
            database=_database(tmp_path / "refused.db"), extension=extension, extension_sha256=expected
        )
    with _observer(_database(tmp_path / "after.db"), sqlite_vfs_build) as admitted:
        assert admitted.report()["vfs"]["default_vfs_unchanged"] is True


def test_actual_guard_writer_receipts_keep_journal_vfs_queue_and_readback_distinct(
    tmp_path: Path, sqlite_vfs_build: dict[str, Any]
) -> None:
    from codex_plugin_scanner.guard import store_connection_schema

    store = GuardStore(tmp_path / "guard")
    writer = RuntimeHookEvidenceWriter(store=store, batch_wait_seconds=0.025)
    observer = _observer(store.path, sqlite_vfs_build)
    queue = EvidenceQueueObservation()
    receipts = [_receipt(request_id=f"vfs-{index}") for index in range(3)]
    edges = {f"mixed-load-{index}": {"receipt": receipt} for index, receipt in enumerate(receipts)}
    worker = SimpleNamespace(_review_raw_hook_native=lambda **kwargs: edges[kwargs["payload"]["native_slo_attempt"]])
    session = SimpleNamespace(
        store=store,
        guard_home=store.guard_home,
        daemon=SimpleNamespace(_server=SimpleNamespace(hook_worker=worker, runtime_hook_evidence_writer=writer)),
    )
    original_connect = sqlite3.connect
    witness = ReceiptWitness(session, maximum=3, queue_observation=queue, sqlite_observer=observer).__enter__()
    try:
        with writer._condition:
            for index, receipt in enumerate(receipts):
                request = fixture_request("claude-code", "PostToolUse", attempt=f"mixed-load-{index}")
                assert worker._review_raw_hook_native(payload=request) is edges[f"mixed-load-{index}"]
                assert writer.submit_native_decision_receipt(receipt) is True
            assert writer.submit_native_decision_receipt(receipts[0]) is True
        assert writer.stop(timeout_seconds=3)
        assert writer.stats()["receipt_processed"] == 3
        assert writer.stats()["receipt_deduped"] == 1
        witness.reconcile(verify_all=True)
        assert store.get_native_decision_receipt(receipts[0]["decision_id"]) is not None
        assert sqlite3.connect is original_connect
    finally:
        writer.stop(timeout_seconds=3)
        witness.close()
    report = witness.report()
    assert store_connection_schema.sqlite3 is sqlite3
    assert report["committed"] == report["writer_admitted"] == report["native_receipts"] == 3
    assert report["binding_mismatches"] == report["missing"] == 0
    assert report["journal_io"]["journal_written_bytes"] > 0
    assert report["journal_io"]["journal_file_fsync_calls"] > 0
    assert report["sqlite_fsync_calls"] is report["sqlite_written_bytes"] is None
    assert report["full_persistence_metric_coverage"] is False
    assert report["writer_queue_observation"] is not None
    vfs = report["sqlite_vfs_observation"]
    assert vfs["closed"] and vfs["all_vfs_files_closed"]
    assert vfs["scope"] == "named_vfs_connections_from_selected_store_factory"
    assert vfs["attested_connections"]["writer"] >= 1
    assert vfs["attested_connections"]["readback"] >= 2
    assert vfs["attested_connections"]["other"] >= 1
    assert _cell(vfs, "writer", "wal")["vfs_x_write_success_bytes"] > 0
    assert vfs["connection_scope_at_open_complete"] is True


def test_store_factory_scope_does_not_intercept_unrelated_connections_and_restores_nested_readback(
    tmp_path: Path, sqlite_vfs_build: dict[str, Any]
) -> None:
    from codex_plugin_scanner.guard import store_connection_schema

    store = GuardStore(tmp_path / "guard")
    writer = RuntimeHookEvidenceWriter(store=store)
    observer = _observer(store.path, sqlite_vfs_build)
    original_module = store_connection_schema.sqlite3
    observer.install(store, writer)
    try:
        baseline = observer.report()["vfs"]["cells"]
        with pytest.raises(RuntimeError, match=r"local control.*after factory"):
            observer.connect(scope="writer")
        assert observer.report()["vfs"]["cells"] == baseline
        assert observer.report()["attested_connections"] == {"other": 0, "writer": 0, "readback": 0}
        unrelated = _database(tmp_path / "unrelated.db")
        connection = store_connection_schema.sqlite3.connect(unrelated, timeout=0.01)
        connection.close()
        assert observer.report()["vfs"]["cells"] == baseline
        with observer.readback():
            with pytest.raises(ValueError, match="sentinel"), observer.readback():
                with store._connect() as connection:
                    assert connection.row_factory is sqlite3.Row
                    assert connection.execute("pragma busy_timeout").fetchone()[0] >= 0
                raise ValueError("sentinel")
            with store._connect() as connection:
                assert connection.row_factory is sqlite3.Row
        with store._connect():
            pass
        assert observer.report()["attested_connections"] == {"other": 1, "writer": 0, "readback": 2}
    finally:
        assert writer.stop(timeout_seconds=3)
        assert observer.close()
    assert store_connection_schema.sqlite3 is original_module
    assert sqlite3.connect is original_module.connect


def test_unadmitted_preloaded_library_is_refused_before_sqlite_extension_loading(
    tmp_path: Path, sqlite_vfs_build: dict[str, Any]
) -> None:
    extension = tmp_path / "preloaded.so"
    shutil.copyfile(sqlite_vfs_build["extension"], extension)
    extension.chmod(0o600)
    resident = ctypes.CDLL(str(extension))
    assert resident is not None
    with pytest.raises(ValueError, match="already mapped without admission"):
        SQLiteVFSObservation(
            database=_database(tmp_path / "preloaded.db"),
            extension=extension,
            extension_sha256=sqlite_vfs_build["extension_sha256"],
        )


def test_pinned_descriptor_detects_a_real_file_change_at_scope_exit(tmp_path: Path) -> None:
    from scripts.native_slo_sqlite_vfs_identity import pinned_extension

    image = tmp_path / "unloaded-image"
    image.write_bytes(b"local-unloaded-image")
    image.chmod(0o600)
    original = _sha(image)
    with pytest.raises(ValueError, match="identity changed"), pinned_extension(image, expected_sha256=original):
        image.write_bytes(b"changed-unloaded-image")


def test_failed_admission_cleanup_releases_observer_lock_before_real_retry(
    tmp_path: Path, sqlite_vfs_build: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    from scripts import native_slo_sqlite_vfs as module

    database = _database(tmp_path / "cleanup.db")

    @contextlib.contextmanager
    def failing_pinned_extension(*_args: object, **_kwargs: object):
        yield -1, {"device": -1, "inode": -1}
        raise ValueError("cleanup sentinel")

    def failing_mapping_check(_identity: object) -> bool:
        raise RuntimeError("admission sentinel")

    # A failing old constructor must not strand the lock used by later tests.
    with monkeypatch.context() as lifetime:
        lifetime.setattr(module, "_ACTIVE", threading.Lock())
        with monkeypatch.context() as admission:
            admission.setattr(module, "pinned_extension", failing_pinned_extension)
            admission.setattr(module, "already_mapped", failing_mapping_check)
            with pytest.raises(ValueError, match="cleanup sentinel"):
                _observer(database, sqlite_vfs_build)
        with _observer(database, sqlite_vfs_build) as admitted:
            assert admitted.report()["vfs"]["default_vfs_unchanged"] is True
