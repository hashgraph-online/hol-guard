"""Scoped, aggregate-only probes for actual Python JSON/hash callable work."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Protocol


class Recorder(Protocol):
    def call(self, function: Callable[..., Any], name: str, *args: Any, **kwargs: Any) -> Any: ...

    def work(self, name: str, unit: str, count: int) -> None: ...


def byte_size(value: object) -> int | None:
    if isinstance(value, (bytes, bytearray)):
        return len(value)
    if isinstance(value, memoryview):
        return value.nbytes
    return None


class ModuleProbe:
    """Replace one importing module's binding, never the shared library module."""

    def __init__(self, target: Any, overrides: dict[str, Any]) -> None:
        self._target = target
        self._overrides = overrides

    def __getattr__(self, name: str) -> Any:
        return self._overrides[name] if name in self._overrides else getattr(self._target, name)


def json_probe(target: Any, recorder: Recorder, prefix: str) -> ModuleProbe:
    def dumps(*args: Any, **kwargs: Any) -> Any:
        name = f"{prefix}_json_dumps"
        result = recorder.call(target.dumps, name, *args, **kwargs)
        if isinstance(result, str):
            # A JSON string is not UTF-8 bytes. Never re-encode just to count it.
            recorder.work(name, "returned_characters", len(result))
        return result

    def loads(*args: Any, **kwargs: Any) -> Any:
        name = f"{prefix}_json_loads"
        value = args[0] if args else kwargs.get("s")
        size = byte_size(value)
        if size is not None:
            recorder.work(name, "attempted_input_bytes", size)
        elif isinstance(value, str):
            recorder.work(name, "attempted_input_characters", len(value))
        return recorder.call(target.loads, name, *args, **kwargs)

    return ModuleProbe(target, {"dumps": dumps, "loads": loads})


def hashlib_probe(target: Any, recorder: Recorder, prefix: str) -> ModuleProbe:
    def sha256(*args: Any, **kwargs: Any) -> Any:
        name = f"{prefix}_sha256_init"
        value = args[0] if args else kwargs.get("string", b"")
        size = byte_size(value)
        if size is not None:
            recorder.work(name, "attempted_input_bytes", size)
        digest = recorder.call(target.sha256, name, *args, **kwargs)
        if size is not None:
            recorder.work(name, "hashed_bytes", size)
        return HashProbe(digest, recorder, prefix)

    return ModuleProbe(target, {"sha256": sha256})


class HashProbe:
    def __init__(self, target: Any, recorder: Recorder, prefix: str) -> None:
        self._target, self._recorder, self._prefix = target, recorder, prefix

    def __getattr__(self, name: str) -> Any:
        return getattr(self._target, name)

    def update(self, data: Any) -> Any:
        name = f"{self._prefix}_sha256_update"
        size = byte_size(data)
        if size is not None:
            self._recorder.work(name, "attempted_input_bytes", size)
        result = self._recorder.call(self._target.update, name, data)
        if size is not None:
            self._recorder.work(name, "hashed_bytes", size)
        return result

    def digest(self) -> Any:
        return self._recorder.call(self._target.digest, f"{self._prefix}_sha256_finalize")

    def hexdigest(self) -> Any:
        return self._recorder.call(self._target.hexdigest, f"{self._prefix}_sha256_finalize")

    def copy(self) -> HashProbe:
        return HashProbe(self._target.copy(), self._recorder, self._prefix)
