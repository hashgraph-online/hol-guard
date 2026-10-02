"""Fork-safety for module-level synchronization state.

A process forked with ``multiprocessing`` (the default start method on
Linux) inherits every Lock/RLock/Condition/Event in whatever state the
parent's threads left it.  A primitive held by a thread that does not
exist in the child can never be released, so the first child-side caller
deadlocks — and a container of parent-owned handles (resident client
pools, per-path lock maps, publisher or signal registries) hands the
child objects that can never work.  Both failure modes surface as hung
child processes, not errors.

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

import os
import sys
import threading
from collections.abc import Callable, MutableMapping, MutableSet
from types import ModuleType
from typing import Any

_PACKAGE_PREFIX = __name__.split(".", 2)[0] + "."

_LOCK_TYPE = type(threading.Lock())
_RLOCK_TYPE = type(threading.RLock())

_CONTAINERS: list[MutableMapping[Any, Any] | MutableSet[Any]] = []


def forget_in_child(container: MutableMapping[Any, Any] | MutableSet[Any]) -> None:
    """Clear ``container`` in forked children.

    Use for module-level dicts/sets that hold parent-owned primitives or
    handles — per-path lock maps, client pools, publisher or signal
    registries — whose entries cannot work in the child.  Entries are
    dropped without signalling or cleanup: inherited handles belong to
    the parent, and the child rebuilds what it needs on demand.
    """

    _CONTAINERS.append(container)


def _fresh_primitive(value: object) -> object | None:
    """Return a fresh primitive matching ``value``, or None if not one."""

    if isinstance(value, threading.Condition):
        return threading.Condition()
    if isinstance(value, threading.Event):
        return threading.Event()
    if type(value) is _RLOCK_TYPE:
        return threading.RLock()
    if type(value) is _LOCK_TYPE:
        return threading.Lock()
    if isinstance(value, tuple):
        changed = False
        items: list[object] = []
        for item in value:
            fresh_item = _fresh_primitive(item)
            if fresh_item is None:
                items.append(item)
            else:
                items.append(fresh_item)
                changed = True
        return tuple(items) if changed else None
    return None


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
            _rebuild_namespace_primitives(value, rebind=lambda n, f, cls=value: setattr(cls, n, f))


def _reset_after_fork() -> None:
    for module in tuple(sys.modules.values()):
        module_name = getattr(module, "__name__", None)
        if not isinstance(module_name, str) or not module_name.startswith(_PACKAGE_PREFIX):
            continue
        if not isinstance(module, ModuleType):
            continue
        try:
            _rebuild_namespace_primitives(module, rebind=lambda n, f, m=module: setattr(m, n, f))
        except (TypeError, AttributeError):
            continue
    for container in _CONTAINERS:
        container.clear()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_reset_after_fork)
