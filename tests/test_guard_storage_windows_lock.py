from __future__ import annotations

import ctypes
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import store_storage_lock as locks


class NativeFunction:
    def __init__(self) -> None:
        self.calls: list[tuple[object, ...]] = []
        self.result = 1
        self.argtypes: object = None
        self.restype: object = None

    def __call__(self, *args: object) -> int:
        self.calls.append(args)
        return self.result


@pytest.fixture
def api(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    value = SimpleNamespace(LockFileEx=NativeFunction(), UnlockFileEx=NativeFunction(), last_error=33)
    monkeypatch.setattr(ctypes, "WinDLL", lambda *args, **kwargs: value, raising=False)
    monkeypatch.setattr(ctypes, "get_last_error", lambda: value.last_error, raising=False)
    monkeypatch.setattr(ctypes, "WinError", lambda code: OSError(code, "bounded fixture error"), raising=False)
    return value


def test_win32_binding_uses_shared_or_exclusive_nonblocking_exact_range(api: SimpleNamespace) -> None:
    lock = locks._WindowsStorageLock(0x123456789)
    lock.acquire(exclusive=False)
    lock.release()
    lock.acquire(exclusive=True)
    lock.release()
    shared, exclusive = api.LockFileEx.calls
    assert shared[0].value == exclusive[0].value == 0x123456789
    assert shared[1:5] == (1, 0, 1, 0)
    assert exclusive[1:5] == (3, 0, 1, 0)
    assert api.LockFileEx.argtypes[0] is ctypes.c_void_p
    assert api.LockFileEx.restype is ctypes.c_int
    for call in api.UnlockFileEx.calls:
        assert call[1:4] == (0, 1, 0)
        assert ctypes.addressof(call[4]._obj) == ctypes.addressof(shared[5]._obj)
    assert bytes(shared[5]._obj) == bytes(ctypes.sizeof(locks._Overlapped))


def test_win32_contention_is_retryable_but_other_errors_fail_closed(api: SimpleNamespace) -> None:
    lock = locks._WindowsStorageLock(42)
    api.LockFileEx.result = 0
    with pytest.raises(BlockingIOError):
        lock.acquire(exclusive=False)
    api.last_error = 6  # Invalid handle must not be retried as ordinary contention.
    with pytest.raises(OSError) as error:
        lock.acquire(exclusive=False)
    assert not isinstance(error.value, BlockingIOError)
    assert api.UnlockFileEx.calls == []


def test_win32_unlock_failure_is_not_reported_as_success(api: SimpleNamespace) -> None:
    lock = locks._WindowsStorageLock(42)
    lock.acquire(exclusive=False)
    api.UnlockFileEx.result = 0
    api.last_error = 158
    with pytest.raises(OSError):
        lock.release()
