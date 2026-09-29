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
