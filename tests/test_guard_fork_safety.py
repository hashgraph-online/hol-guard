"""Unit tests for the forked-child synchronization rebuild registry."""

from __future__ import annotations

import threading
from types import ModuleType

from codex_plugin_scanner.guard import fork_safety

_LOCK_TYPE = type(threading.Lock())
_RLOCK_TYPE = type(threading.RLock())


def test_fresh_primitive_rebuilds_each_supported_type() -> None:
    cases = (
        (threading.Lock(), _LOCK_TYPE),
        (threading.RLock(), _RLOCK_TYPE),
        (threading.Condition(), threading.Condition),
        (threading.Event(), threading.Event),
    )
    for original, expected_type in cases:
        fresh = fork_safety._fresh_primitive(original)
        assert fresh is not None
        assert type(fresh) is expected_type
        assert fresh is not original


def test_fresh_primitive_preserves_set_event_state() -> None:
    event = threading.Event()
    event.set()
    fresh = fork_safety._fresh_primitive(event)
    assert isinstance(fresh, threading.Event)
    assert fresh.is_set()


def test_fresh_primitive_rebuilds_tuple_members_only() -> None:
    lock = threading.Lock()
    fresh = fork_safety._fresh_primitive((lock, "keep", 7))
    assert isinstance(fresh, tuple)
    assert type(fresh[0]) is _LOCK_TYPE
    assert fresh[0] is not lock
    assert fresh[1] == "keep"
    assert fresh[2] == 7
    assert fork_safety._fresh_primitive(("no", "primitives")) is None


def test_fresh_primitive_ignores_plain_values() -> None:
    for value in (None, 42, "text", {"k": 1}, threading.local()):
        assert fork_safety._fresh_primitive(value) is None


def test_rebuild_namespace_replaces_module_level_locks() -> None:
    module = ModuleType("fork_safety_fake_module")
    original = threading.Lock()
    module.__dict__["_sample_lock"] = original
    module.__dict__["_sample_data"] = {"keep": "me"}

    fork_safety._rebuild_namespace_primitives(
        module,
        rebind=lambda name, fresh: setattr(module, name, fresh),
    )

    rebuilt = module.__dict__["_sample_lock"]
    assert type(rebuilt) is _LOCK_TYPE
    assert rebuilt is not original
    assert rebuilt.acquire(blocking=False)
    rebuilt.release()
    assert module.__dict__["_sample_data"] == {"keep": "me"}


def test_rebuild_namespace_reaches_class_level_locks() -> None:
    class _Holder:
        _inner_lock = threading.Lock()

    original = _Holder._inner_lock
    module = ModuleType("fork_safety_fake_module")
    module.__dict__["Holder"] = _Holder

    fork_safety._rebuild_namespace_primitives(
        module,
        rebind=lambda name, fresh: setattr(module, name, fresh),
    )

    assert type(_Holder._inner_lock) is _LOCK_TYPE
    assert _Holder._inner_lock is not original


def test_forget_in_child_registers_and_scan_clears_container() -> None:
    container: dict[str, object] = {"inherited": object()}
    fork_safety.forget_in_child(container)
    assert container in fork_safety._CONTAINERS
    container.clear()
