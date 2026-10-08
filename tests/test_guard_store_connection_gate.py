"""Storage-gate coverage for live GuardStore connections.

Two layers:

- A static scan proving every ``sqlite3.connect(self.path, ...)`` in the guard
  package runs lexically inside a storage gate (``_hold_storage_gate`` /
  ``_try_hold_storage_gate``) or sits in a small, justified allowlist.
- Deterministic unit coverage for the rename hazard: an exclusive quarantine
  must wait behind a held shared gate instead of renaming the store out from
  under a live connection, and the heartbeat must fail fast (never block)
  while the exclusive gate is held.
"""

from __future__ import annotations

import ast
import sqlite3
import threading
import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.sqlite_tuning import sqlite_connect_timeout_override, sqlite_operation_deadline
from codex_plugin_scanner.guard.store import GuardStore

GUARD_PACKAGE = Path(__file__).resolve().parents[1] / "src" / "codex_plugin_scanner" / "guard"

_GATE_CONTEXT_MANAGERS = frozenset({"_hold_storage_gate", "_try_hold_storage_gate"})

# (module filename, enclosing function) -> justification.
# `_connect_once` opens the real connection but is only ever reached through
# `_connect`, which holds the shared gate for the connection lifetime, or
# while this thread owns storage recovery — which itself runs under the
# exclusive gate in `_recover_fatal_sqlite_store`.
_UNGATED_CONNECT_ALLOWLIST: dict[tuple[str, str], str] = {
    ("store_connection_schema.py", "_connect_once"): (
        "only called from _connect under the shared gate, or under the "
        "exclusive gate while this thread owns storage recovery"
    ),
}


def _is_self_path(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "path"
        and isinstance(node.value, ast.Name)
        and node.value.id == "self"
    )


def _is_sqlite3_connect(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "connect"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "sqlite3"
    )


def _is_gate_context(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in _GATE_CONTEXT_MANAGERS
    )


class _GateScanner(ast.NodeVisitor):
    def __init__(self, module: str) -> None:
        self.module = module
        self.function_stack: list[str] = ["<module>"]
        self.gated_depth = 0
        self.violations: list[str] = []
        self.connect_once_calls: list[tuple[str, int, bool]] = []

    def _visit_function(self, node: ast.AST) -> None:
        self.function_stack.append(node.name)  # type: ignore[attr-defined]
        self.generic_visit(node)
        self.function_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node)

    def _visit_with(self, node: ast.With | ast.AsyncWith) -> None:
        if any(_is_gate_context(item.context_expr) for item in node.items):
            self.gated_depth += 1
            self.generic_visit(node)
            self.gated_depth -= 1
            return
        self.generic_visit(node)

    def visit_With(self, node: ast.With) -> None:
        self._visit_with(node)

    def visit_AsyncWith(self, node: ast.AsyncWith) -> None:
        self._visit_with(node)

    def visit_Call(self, node: ast.Call) -> None:
        if (
            _is_sqlite3_connect(node)
            and node.args
            and any(_is_self_path(descendant) for descendant in ast.walk(node.args[0]))
        ):
            function = self.function_stack[-1]
            if self.gated_depth == 0 and (self.module, function) not in _UNGATED_CONNECT_ALLOWLIST:
                self.violations.append(f"{self.module}:{node.lineno} in {function}()")
        if isinstance(node.func, ast.Attribute) and node.func.attr == "_connect_once":
            self.connect_once_calls.append((self.function_stack[-1], node.lineno, self.gated_depth > 0))
        self.generic_visit(node)


def test_every_self_path_connection_holds_the_storage_gate() -> None:
    """New sqlite3.connect(self.path) sites must be inside the storage gate."""

    violations: list[str] = []
    for source in sorted(GUARD_PACKAGE.rglob("*.py")):
        scanner = _GateScanner(source.name)
        scanner.visit(ast.parse(source.read_text(encoding="utf-8"), filename=str(source)))
        violations.extend(scanner.violations)
        # The allowlist claim: `_connect_once` is only reachable under a gate
        # — every call site must be inside `_connect` or a gated with block.
        for function, line, gated in scanner.connect_once_calls:
            if not gated and function != "_connect":
                violations.append(
                    f"{source.name}:{line} calls _connect_once from {function}() without the storage gate"
                )
    assert not violations, (
        "sqlite3.connect(self.path, ...) outside the Guard storage gate; "
        "wrap the connection lifetime in _hold_storage_gate / "
        "_try_hold_storage_gate or extend the reviewed allowlist:\n" + "\n".join(violations)
    )


def test_exclusive_recovery_waits_for_a_held_shared_gate(tmp_path: Path) -> None:
    """The quarantine rename must not run while a heartbeat-style shared gate is held."""

    store = GuardStore(tmp_path / "guard", prime_policy_integrity=False)
    (tmp_path / "guard" / "guard.db").write_bytes(b"not-a-sqlite-database\x00gate-test")

    gate_held = threading.Event()
    release = threading.Event()
    acquired: list[bool] = []

    def hold_shared_gate() -> None:
        with store._try_hold_storage_gate(exclusive=False) as held:  # pyright: ignore[reportPrivateUsage]
            acquired.append(held)
            if held:
                gate_held.set()
                assert release.wait(timeout=10)

    holder = threading.Thread(target=hold_shared_gate)
    holder.start()
    assert gate_held.wait(timeout=5)
    assert acquired == [True]

    recovered: list[bool] = []
    recovery = threading.Thread(
        target=lambda: recovered.append(
            store._recover_fatal_sqlite_store(  # pyright: ignore[reportPrivateUsage]
                sqlite3.DatabaseError("database disk image is malformed")
            )
        )
    )
    recovery.start()
    # Give recovery a window to prove it is blocked on the shared gate rather
    # than renaming the store out from under the holder.
    assert not recovery.join(timeout=0.5)
    assert list((tmp_path / "guard").glob("guard.db.corrupt-*")) == []

    release.set()
    holder.join(timeout=5)
    recovery.join(timeout=30)

    assert recovered == [True]
    assert len(list((tmp_path / "guard").glob("guard.db.corrupt-*"))) >= 1
    with sqlite3.connect(store.path) as connection:
        assert connection.execute("pragma integrity_check").fetchone() == ("ok",)


def test_try_touch_runtime_state_fails_fast_under_exclusive_gate(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """The heartbeat must return False without touching SQLite while recovery holds the store."""

    store = GuardStore(tmp_path / "guard", prime_policy_integrity=False)
    gate_held = threading.Event()
    release = threading.Event()

    def hold_exclusive_gate() -> None:
        with store._hold_storage_gate(exclusive=True):  # pyright: ignore[reportPrivateUsage]
            gate_held.set()
            assert release.wait(timeout=10)

    holder = threading.Thread(target=hold_exclusive_gate)
    holder.start()
    assert gate_held.wait(timeout=5)

    connect_calls: list[object] = []
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.store_receipts.sqlite3.connect",
        lambda *args, **kwargs: (
            connect_calls.append(args)
            or (_ for _ in ()).throw(AssertionError("sqlite3.connect reached while the exclusive storage gate is held"))
        ),
    )
    try:
        result = store.try_touch_runtime_state(
            session_id="session",
            last_heartbeat_at="2026-01-01T00:00:00+00:00",
            timeout_seconds=0.1,
        )
    finally:
        release.set()
        holder.join(timeout=5)

    assert result is False
    assert connect_calls == []


def test_storage_gate_allows_nested_reads_on_one_thread(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard", prime_policy_integrity=False)

    with store._connect() as outer:  # pyright: ignore[reportPrivateUsage]
        assert outer.execute("pragma schema_version").fetchone() is not None
        with store._connect() as inner:  # pyright: ignore[reportPrivateUsage]
            assert inner.execute("pragma schema_version").fetchone() is not None


def test_replacement_remains_exclusive_until_schema_is_ready(
    tmp_path: Path,
    monkeypatch,
) -> None:
    store = GuardStore(tmp_path / "guard", prime_policy_integrity=False)
    store.path.write_bytes(b"not-a-sqlite-database\x00gate-test")
    initializing = threading.Event()
    release = threading.Event()
    original_initialize = store._initialize_schema  # pyright: ignore[reportPrivateUsage]

    def delayed_initialize() -> None:
        initializing.set()
        assert release.wait(timeout=2)
        original_initialize()

    monkeypatch.setattr(store, "_initialize_schema", delayed_initialize)
    recovery = threading.Thread(
        target=lambda: store._recover_fatal_sqlite_store(  # pyright: ignore[reportPrivateUsage]
            sqlite3.DatabaseError("database disk image is malformed")
        )
    )
    recovery.start()
    assert initializing.wait(timeout=1)
    reader_finished = threading.Event()

    def read_store() -> None:
        with store._connect() as connection:  # pyright: ignore[reportPrivateUsage]
            _ = connection.execute("select count(*) from schema_migrations").fetchone()
            reader_finished.set()

    reader = threading.Thread(target=read_store)
    reader.start()
    time.sleep(0.05)
    assert reader_finished.is_set() is False

    release.set()
    recovery.join(timeout=2)
    reader.join(timeout=2)

    assert reader_finished.is_set() is True


def test_storage_gate_and_sqlite_lock_consume_one_operation_budget(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard", prime_policy_integrity=False)
    gate_held = threading.Event()
    caller_started = threading.Event()
    holder_errors: list[BaseException] = []

    def hold_gate() -> None:
        try:
            with store._hold_storage_gate(exclusive=True):
                gate_held.set()
                if not caller_started.wait(timeout=2):
                    raise TimeoutError("storage gate holder was not released")
                time.sleep(0.25)
        except BaseException as error:
            holder_errors.append(error)

    writer = sqlite3.connect(store.path)
    writer.execute("begin immediate")
    holder = threading.Thread(target=hold_gate)
    holder.start()
    try:
        assert gate_held.wait(timeout=1)
        started = time.monotonic()
        caller_started.set()
        with (
            pytest.raises(sqlite3.OperationalError, match="locked"),
            sqlite_connect_timeout_override(0.4),
            store._connect() as connection,
        ):
            connection.execute(
                "insert into guard_events (event_name, payload_json, occurred_at) values ('deadline', '{}', 'now')"
            )
        elapsed = time.monotonic() - started
        assert elapsed < 0.52, f"gate and SQLite each restarted the wait budget: {elapsed:.3f}s"
    finally:
        caller_started.set()
        writer.rollback()
        writer.close()
        holder.join(timeout=2)
    assert not holder.is_alive() and not holder_errors
    assert not list(store.guard_home.glob("guard.db.corrupt-*"))
    with store._connect() as connection:
        assert connection.execute("select count(*) from guard_events where event_name='deadline'").fetchone()[0] == 0


@pytest.mark.parametrize("budget_kind", ["relative", "absolute", "inverse"])
def test_expired_caller_budget_cannot_be_restarted_by_nested_override(tmp_path: Path, budget_kind: str) -> None:
    from codex_plugin_scanner.guard.runtime_transition import inverse_recovery_budget

    store = GuardStore(tmp_path / "guard", prime_policy_integrity=False)
    deadline = time.monotonic() + 0.03
    if budget_kind == "relative":
        budget = sqlite_connect_timeout_override(0.03)
    elif budget_kind == "absolute":
        budget = sqlite_operation_deadline(deadline)
    else:
        budget = inverse_recovery_budget(deadline)
    with budget:
        time.sleep(0.04)
        with (
            pytest.raises(TimeoutError, match="deadline expired"),
            sqlite_connect_timeout_override(1),
            store._connect() as connection,
        ):
            connection.execute(
                "insert into guard_events (event_name, payload_json, occurred_at) values ('expired', '{}', 'now')"
            )
    assert not list(store.guard_home.glob("guard.db.corrupt-*"))
    with store._connect() as connection:
        assert connection.execute("select count(*) from guard_events where event_name='expired'").fetchone()[0] == 0


@pytest.mark.parametrize("use_cursor", [False, True])
def test_later_statement_uses_remaining_busy_budget(tmp_path: Path, use_cursor: bool) -> None:
    store = GuardStore(tmp_path / "guard", prime_policy_integrity=False)
    writer = sqlite3.connect(store.path)
    writer.execute("begin immediate")
    started = time.monotonic()
    try:
        with (
            pytest.raises(sqlite3.OperationalError, match="locked"),
            sqlite_connect_timeout_override(0.4),
            store._connect() as connection,
        ):
            target = connection.cursor() if use_cursor else connection
            time.sleep(0.25)
            target.execute(
                "insert into guard_events (event_name, payload_json, occurred_at) values ('late', '{}', 'now')"
            )
        assert time.monotonic() - started < 0.52, "an open connection renewed the statement wait"
    finally:
        writer.rollback()
        writer.close()


def test_long_query_obeys_deadline_after_caller_clears_progress_handler(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard", prime_policy_integrity=False)
    started = time.monotonic()
    with (
        pytest.raises(sqlite3.OperationalError, match="interrupted"),
        sqlite_connect_timeout_override(0.04),
        store._connect() as connection,
    ):
        connection.set_progress_handler(None, 0)
        connection.execute(
            "with recursive numbers(n) as (select 1 union all select n+1 from numbers where n<2000000) "
            "select sum(n) from numbers"
        ).fetchone()
    assert time.monotonic() - started < 0.3
    assert not list(store.guard_home.glob("guard.db.corrupt-*"))


@pytest.mark.parametrize("finalizer", ["commit", "context", "script", "many"])
def test_expired_transaction_cannot_commit_through_alternate_apis(tmp_path: Path, finalizer: str) -> None:
    store = GuardStore(tmp_path / "guard", prime_policy_integrity=False)
    sql = "insert into guard_events (event_name, payload_json, occurred_at) values ('late-commit', '{}', 'now')"
    with (
        pytest.raises(TimeoutError, match="deadline expired"),
        sqlite_connect_timeout_override(0.04),
        store._connect() as connection,
    ):
        if finalizer == "context":
            with connection:
                connection.execute(sql)
                time.sleep(0.05)
        else:
            connection.execute(sql)
            time.sleep(0.05)
            if finalizer == "commit":
                connection.commit()
            elif finalizer == "script":
                connection.executescript("select 1;")
            else:
                connection.cursor().executemany(sql, [()])
    with store._connect() as connection:
        assert connection.execute("select count(*) from guard_events where event_name='late-commit'").fetchone()[0] == 0


@pytest.mark.parametrize("use_cursor", [False, True])
def test_bulk_parameter_producer_cannot_execute_rows_after_deadline(tmp_path: Path, use_cursor: bool) -> None:
    store = GuardStore(tmp_path / "guard", prime_policy_integrity=False)
    executed: list[str] = []

    def observed(value: str) -> str:
        executed.append(value)
        return value

    def parameters():
        yield ("before",)
        time.sleep(0.05)
        yield ("after",)

    with (
        pytest.raises(TimeoutError, match="deadline expired"),
        sqlite_connect_timeout_override(0.04),
        store._connect() as connection,
    ):
        connection.create_function("observed", 1, observed)
        target = connection.cursor() if use_cursor else connection
        target.executemany(
            "insert into guard_events (event_name, payload_json, occurred_at) values (observed(?), '{}', 'now')",
            parameters(),
        )
    assert executed == ["before"], "bulk execution stepped a row after its original deadline"
    with store._connect() as connection:
        assert (
            connection.execute("select count(*) from guard_events where event_name in ('before','after')").fetchone()[0]
            == 0
        )


def test_budgeted_bulk_write_preserves_sqlite_result_accounting(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard", prime_policy_integrity=False)
    with sqlite_connect_timeout_override(0.4), store._connect() as connection:
        cursor = connection.executemany(
            "insert into guard_events (event_name, payload_json, occurred_at) values (?, '{}', 'now')",
            ((f"bulk-{index}",) for index in range(3)),
        )
        assert cursor.rowcount == 3 and cursor.lastrowid is None
    with store._connect() as connection:
        assert connection.execute("select count(*) from guard_events where event_name like 'bulk-%'").fetchone()[0] == 3


@pytest.mark.parametrize("path_kind", ["probe", "write-probe", "local-salvage", "cloud-salvage"])
@pytest.mark.parametrize("expired", [False, True])
def test_recovery_connections_obey_deadline_and_close_handles(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    path_kind: str,
    expired: bool,
) -> None:
    from codex_plugin_scanner.guard import sqlite_cloud_review_recovery, sqlite_recovery
    from codex_plugin_scanner.guard.sqlite_deadline_connection import DeadlineConnection

    source = GuardStore(tmp_path / "source", prime_policy_integrity=False)
    destination = GuardStore(tmp_path / "destination", prime_policy_integrity=False)
    opened: list[sqlite3.Connection] = []
    real_connect = sqlite3.connect

    def observed_connect(*args, **kwargs):
        assert not expired, "expired recovery opened a new SQLite connection"
        connection = real_connect(*args, **kwargs)
        opened.append(connection)
        return connection

    def recover() -> None:
        if path_kind == "probe":
            assert sqlite_recovery._probe_sqlite_store(source.path) == "healthy"
        elif path_kind == "write-probe":
            assert sqlite_recovery._guard_home_accepts_sqlite_write(source.guard_home)
        elif path_kind == "local-salvage":
            assert sqlite_recovery.salvage_local_cli_state(source=source.path, destination=destination.path)
        else:
            assert not sqlite_cloud_review_recovery.salvage_cloud_review_state(
                source=source.path,
                destination=destination.path,
            )  # Generated empty source has no cloud consent to recover.

    monkeypatch.setattr(sqlite3, "connect", observed_connect)
    with sqlite_operation_deadline(time.monotonic() + (-1 if expired else 2)):
        if expired:
            with pytest.raises(TimeoutError, match="deadline expired"):
                recover()
        else:
            recover()
    assert len(opened) == (0 if expired else 2 if "salvage" in path_kind else 1)
    for connection in opened:
        assert isinstance(connection, DeadlineConnection)
        with pytest.raises(sqlite3.ProgrammingError, match="closed"):
            connection.execute("select 1")
    assert not list(source.guard_home.glob("storage-probe-*"))


def test_recovery_connection_keeps_its_shorter_local_wait_cap(tmp_path: Path) -> None:
    from contextlib import closing

    from codex_plugin_scanner.guard.sqlite_deadline_connection import connect_sqlite_with_deadline

    with (
        sqlite_operation_deadline(time.monotonic() + 2),
        closing(connect_sqlite_with_deadline(tmp_path / "generated.db", timeout_seconds=0.05)) as connection,
    ):
        assert 0 <= connection.execute("pragma busy_timeout").fetchone()[0] <= 50


@pytest.mark.parametrize("factory_kind", ["base", "class", "callable", "slot-class", "slot-callable"])
def test_custom_cursor_preserves_behavior_and_refuses_late_statement(tmp_path: Path, factory_kind: str) -> None:
    store = GuardStore(tmp_path / "guard", prime_policy_integrity=False)
    calls: list[str] = []
    late_rows: list[str] = []
    created: list[sqlite3.Cursor] = []

    class TrackingCursor(sqlite3.Cursor):
        def execute(self, sql, *args, **kwargs):
            calls.append(sql)
            return super().execute(sql, *args, **kwargs)

    class SlottedTrackingCursor(sqlite3.Cursor):
        __slots__ = ("marker",)

        def __init__(self, connection):
            super().__init__(connection)
            self.marker = "custom-state"

        def execute(self, sql, *args, **kwargs):
            calls.append(sql)
            return super().execute(sql, *args, **kwargs)

    def factory(connection):
        cursor = SlottedTrackingCursor(connection) if factory_kind.startswith("slot-") else TrackingCursor(connection)
        created.append(cursor)
        return cursor

    def observe(value: str) -> str:
        late_rows.append(value)
        return value

    selected = {
        "base": sqlite3.Cursor,
        "class": TrackingCursor,
        "callable": factory,
        "slot-class": SlottedTrackingCursor,
        "slot-callable": factory,
    }[factory_kind]
    with (
        pytest.raises(TimeoutError, match="deadline expired"),
        sqlite_connect_timeout_override(0.04),
        store._connect() as connection,
    ):
        connection.create_function("observe_late", 1, observe)
        cursor = connection.cursor(factory=selected)
        if factory_kind != "base":
            assert isinstance(cursor, (TrackingCursor, SlottedTrackingCursor))
        if factory_kind.startswith("slot-"):
            assert cursor.marker == "custom-state"
        if factory_kind.endswith("callable"):
            assert created == [cursor]
        assert cursor.execute("select 41").fetchone()[0] == 41
        time.sleep(0.05)
        cursor.execute(
            "insert into guard_events (event_name, payload_json, occurred_at) "
            "values (observe_late('custom-expired'), '{}', 'now')"
        )
    assert not late_rows, "explicit cursor factory bypassed the connection's deadline"
    assert calls == ([] if factory_kind == "base" else ["select 41"])


def test_custom_cursor_callback_cannot_step_sql_after_consuming_deadline(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard", prime_policy_integrity=False)
    executed: list[str] = []

    class SlowCursor(sqlite3.Cursor):
        def execute(self, sql, *args, **kwargs):
            time.sleep(0.05)
            return super().execute(sql, *args, **kwargs)

    def observed(value: str) -> str:
        executed.append(value)
        return value

    with (
        pytest.raises(TimeoutError, match="deadline expired"),
        sqlite_connect_timeout_override(0.04),
        store._connect() as connection,
    ):
        connection.create_function("observed", 1, observed)
        connection.cursor(factory=SlowCursor).execute(
            "insert into guard_events (event_name, payload_json, occurred_at) values (observed('slow'), '{}', 'now')"
        )
    assert not executed


def test_script_lock_wait_consumes_the_original_operation_deadline(tmp_path: Path) -> None:
    import time

    from codex_plugin_scanner.guard.sqlite_deadline_connection import connect_sqlite_with_deadline
    from codex_plugin_scanner.guard.sqlite_tuning import sqlite_operation_deadline

    database = tmp_path / "script-budget.db"
    writer = sqlite3.connect(database)
    writer.execute("create table items (value integer)")
    writer.commit()
    writer.execute("begin immediate")
    started = time.monotonic()
    try:
        with sqlite_operation_deadline(started + 0.3):
            connection = connect_sqlite_with_deadline(database, timeout_seconds=1)
            try:
                connection.create_function("consume_budget", 0, lambda: time.sleep(0.2))
                with pytest.raises(sqlite3.OperationalError) as failure:
                    connection.executescript("select consume_budget(); insert into items values (1);")
                assert failure.value.sqlite_errorcode in (sqlite3.SQLITE_BUSY, sqlite3.SQLITE_INTERRUPT)
            finally:
                connection.close()
        assert time.monotonic() - started < 0.42, "the lock wait must not restart the script's full budget"
    finally:
        writer.rollback()
        writer.close()
    with sqlite3.connect(database) as inspection:
        assert inspection.execute("select count(*) from items").fetchone() == (0,)


def test_script_cannot_execute_a_short_statement_after_callback_expiry(tmp_path: Path) -> None:
    import time

    from codex_plugin_scanner.guard.sqlite_deadline_connection import connect_sqlite_with_deadline
    from codex_plugin_scanner.guard.sqlite_tuning import sqlite_operation_deadline

    executed = []
    with sqlite_operation_deadline(time.monotonic() + 0.05):
        connection = connect_sqlite_with_deadline(tmp_path / "script-expiry.db", timeout_seconds=1)
        try:
            connection.create_function("consume_budget", 0, lambda: time.sleep(0.07))
            connection.create_function("observe_write", 0, lambda: executed.append("stepped") or 1)
            with pytest.raises(sqlite3.OperationalError) as failure:
                connection.executescript("select consume_budget(); select observe_write();")
            assert failure.value.sqlite_errorcode == sqlite3.SQLITE_INTERRUPT
        finally:
            connection.close()
    assert not executed, "expiry must fence even statements shorter than the normal progress interval"


@pytest.mark.parametrize("factory_kind", ["class", "callable"])
def test_custom_script_cursor_cannot_bypass_statement_deadlines(tmp_path: Path, factory_kind: str) -> None:
    import time

    from codex_plugin_scanner.guard.sqlite_deadline_connection import connect_sqlite_with_deadline
    from codex_plugin_scanner.guard.sqlite_tuning import sqlite_operation_deadline

    class DirectCursor(sqlite3.Cursor):
        def executescript(self, script):
            return sqlite3.Cursor.executescript(self, script)

    executed = []
    factory = DirectCursor if factory_kind == "class" else lambda connection: DirectCursor(connection)
    with sqlite_operation_deadline(time.monotonic() + 0.05):
        connection = connect_sqlite_with_deadline(tmp_path / "custom-script.db", timeout_seconds=1)
        try:
            connection.create_function("consume_budget", 0, lambda: time.sleep(0.07))
            connection.create_function("observe_write", 0, lambda: executed.append("stepped") or 1)
            with pytest.raises(sqlite3.OperationalError) as failure:
                connection.cursor(factory=factory).executescript("select consume_budget(); select observe_write();")
            assert failure.value.sqlite_errorcode == sqlite3.SQLITE_INTERRUPT
        finally:
            connection.close()
    assert not executed


def test_script_trace_callback_cannot_resume_a_write_after_expiry(tmp_path: Path) -> None:
    import time

    from codex_plugin_scanner.guard.sqlite_deadline_connection import connect_sqlite_with_deadline
    from codex_plugin_scanner.guard.sqlite_tuning import sqlite_operation_deadline

    database = tmp_path / "script-trace.db"
    with sqlite3.connect(database) as seed:
        seed.execute("create table items (value integer)")

    def traced(sql):
        if sql.lower().startswith("insert"):
            time.sleep(0.07)

    with sqlite_operation_deadline(time.monotonic() + 0.05):
        connection = connect_sqlite_with_deadline(database, timeout_seconds=1)
        try:
            connection.set_trace_callback(traced)
            with pytest.raises(sqlite3.OperationalError) as failure:
                connection.executescript("insert into items values (1);")
            assert failure.value.sqlite_errorcode == sqlite3.SQLITE_INTERRUPT
        finally:
            connection.close()
    with sqlite3.connect(database) as inspection:
        assert inspection.execute("select count(*) from items").fetchone() == (0,)


def test_script_preserves_sqlite_parsing_transactions_and_caller_trace(tmp_path: Path) -> None:
    import time

    from codex_plugin_scanner.guard.sqlite_deadline_connection import connect_sqlite_with_deadline
    from codex_plugin_scanner.guard.sqlite_tuning import sqlite_operation_deadline

    traced = []
    with sqlite_operation_deadline(time.monotonic() + 2):
        connection = connect_sqlite_with_deadline(tmp_path / "script-semantics.db", timeout_seconds=1)
        try:
            connection.set_trace_callback(traced.append)
            connection.executescript("""
                BEGIN;
                CREATE TABLE items (value TEXT);
                CREATE TRIGGER duplicate AFTER INSERT ON items WHEN new.value = 'a;b'
                BEGIN INSERT INTO items VALUES ('trigger;value'); END;
                INSERT INTO items VALUES ('a;b');
                COMMIT;
            """)
            assert not connection.in_transaction
            assert connection.execute("select value from items order by rowid").fetchall() == [
                ("a;b",),
                ("trigger;value",),
            ]
            assert any("CREATE TRIGGER" in sql for sql in traced)
            assert any("select value from items" in sql for sql in traced)
            connection.set_trace_callback(None)
            before = len(traced)
            assert connection.execute("select count(*) from items").fetchone() == (2,)
            assert len(traced) == before
        finally:
            connection.close()
