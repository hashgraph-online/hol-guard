"""Fork-safety for module-level synchronization state.

A process forked with ``multiprocessing`` (the default start method on
Linux) inherits every Lock/RLock/Condition/Event/Semaphore/Barrier in
whatever state the parent's threads left it.  A primitive held by a
thread that does not exist in the child can never be released, so the
first child-side caller deadlocks — and a container of parent-owned
handles (resident client pools, per-path lock maps, publisher or signal
registries) hands the child objects that can never work.  Both failure
modes surface as hung child processes, not errors.

After a fork, the child-side hook below rebuilds every module- and
class-level synchronization primitive across ``codex_plugin_scanner.*``
modules already loaded, so freshly looked-up attributes are live locks.
Containers that hold parent-owned primitives or handles must be dropped
instead — modules register them with :func:`forget_in_child` at import
time and the child clears them, constructing fresh entries on demand.

Rebinding an inherited primitive in the child is always safe: a lock
cannot coordinate across a fork boundary either way.  The scan runs once
per fork and covers modules added later without further registration.
"""

from __future__ import annotations

import logging
import os
import sys
import threading
from collections.abc import Callable, MutableMapping, MutableSet
from types import ModuleType
from typing import Any

_logger = logging.getLogger(__name__)

_PACKAGE_PREFIX = "codex_plugin_scanner."

# ``threading.Lock``/``threading.RLock`` are factory functions, not types,
# on Python < 3.13 — capture the real lock types from instances instead.
_LOCK_TYPE = type(threading.Lock())
_RLOCK_TYPE = type(threading.RLock())

_CONTAINERS_LOCK = threading.Lock()
_CONTAINERS: list[MutableMapping[Any, Any] | MutableSet[Any]] = []


def forget_in_child(container: MutableMapping[Any, Any] | MutableSet[Any]) -> None:
    """Clear ``container`` in forked children.

    Use for module-level dicts/sets that hold parent-owned primitives or
    handles — per-path lock maps, client pools, publisher or signal
    registries — whose entries cannot work in the child.  Entries are
    dropped without signalling or cleanup: inherited handles belong to
    the parent, and the child rebuilds what it needs on demand.

    Registration is import-time only; the child-side hook clears every
    container registered before the fork.
    """

    with _CONTAINERS_LOCK:
        _CONTAINERS.append(container)


def _fresh_primitive(value: object, _seen: set[int] | None = None) -> object | None:
    """Return a fresh primitive matching ``value``, or None if not one.

    Mutable containers (dict/list/set) are rebuilt in place so shared
    references keep working; the same object is left in the namespace and
    None is returned because no rebinding is needed.
    """

    seen = _seen if _seen is not None else set()

    if isinstance(value, threading.Condition):
        return threading.Condition()
    if isinstance(value, threading.Event):
        fresh_event = threading.Event()
        if value.is_set():
            fresh_event.set()
        return fresh_event
    if type(value) is threading.BoundedSemaphore:
        return threading.BoundedSemaphore(getattr(value, "_initial_value", 1))
    if type(value) is threading.Semaphore:
        # Plain Semaphore does not record its initial value; the remaining
        # count is the closest recoverable capacity, with 1 as the floor so
        # the child never inherits a permanently exhausted semaphore.
        capacity = getattr(value, "_initial_value", None)
        if capacity is None:
            capacity = max(getattr(value, "_value", 1), 1)
        return threading.Semaphore(capacity)
    if type(value) is threading.Barrier:
        return threading.Barrier(
            value.parties,
            action=getattr(value, "_action", None),
            timeout=getattr(value, "_timeout", None),
        )
    if type(value) is _RLOCK_TYPE:
        return threading.RLock()
    if type(value) is _LOCK_TYPE:
        return threading.Lock()
    if isinstance(value, tuple):
        changed = False
        items: list[object] = []
        for item in value:
            fresh_item = _fresh_primitive(item, seen)
            if fresh_item is None:
                items.append(item)
            else:
                items.append(fresh_item)
                changed = True
        return tuple(items) if changed else None
    if isinstance(value, (dict, set, list)):
        _rebuild_mutable_container(value, seen)
        return None
    return None


def _rebuild_mutable_container(
    container: MutableMapping[Any, Any] | set[Any] | list[Any], _seen: set[int] | None = None
) -> None:
    """Rebuild synchronization primitives inside ``container`` in place."""

    seen = _seen if _seen is not None else set()
    if id(container) in seen:
        return
    seen.add(id(container))

    if isinstance(container, dict):
        for key, item in list(container.items()):
            fresh = _fresh_primitive(item, seen)
            if fresh is not None:
                container[key] = fresh
    elif isinstance(container, set):
        for item in tuple(container):
            fresh = _fresh_primitive(item, seen)
            if fresh is not None:
                container.discard(item)
                container.add(fresh)
    elif isinstance(container, list):
        for index, item in enumerate(container):
            fresh = _fresh_primitive(item, seen)
            if fresh is not None:
                container[index] = fresh


def _rebuild_namespace_primitives(namespace: object, *, rebind: Callable[[str, object], None]) -> None:
    for name, value in tuple(vars(namespace).items()):
        if name.startswith("__"):
            continue
        fresh = _fresh_primitive(value)
        if fresh is not None:
            rebind(name, fresh)
        elif isinstance(namespace, ModuleType) and isinstance(value, type):
            # ClassVar primitives live on the class object, whose vars()
            # is a read-only mappingproxy — rebind through setattr instead.
            # Guard per-class: a metaclass that forbids setattr must not
            # stop the rest of the module's primitives from rebuilding.
            try:
                _rebuild_namespace_primitives(value, rebind=lambda n, f, cls=value: setattr(cls, n, f))
            except (TypeError, AttributeError) as error:
                _logger.debug("fork-safety: skipping class %r: %s", value, error)
                continue


def _reset_after_fork() -> None:
    for module in tuple(sys.modules.values()):
        module_name = getattr(module, "__name__", None)
        if not isinstance(module_name, str) or not module_name.startswith(_PACKAGE_PREFIX):
            continue
        if not isinstance(module, ModuleType):
            continue
        try:
            _rebuild_namespace_primitives(module, rebind=lambda n, f, m=module: setattr(m, n, f))
        except (TypeError, AttributeError) as error:
            _logger.debug("fork-safety: skipping module %r: %s", module_name, error)
            continue
    for container in tuple(_CONTAINERS):
        container.clear()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_reset_after_fork)
