"""One stdlib input contract for imported and generated hook clients."""

from __future__ import annotations

from collections.abc import Callable
from typing import cast

# Static source is embedded in standalone clients, including frozen installs
# where inspect.getsource cannot recover the bundled Python implementation.
HOOK_INPUT_READER_TEMPLATE = """
class _HookInputError(ValueError):
    def __init__(self, prefix):
        super().__init__("hook_input_too_large")
        self.prefix = prefix


def _read_hook_input(deadline_monotonic: float) -> str:
    import io
    import os
    import sys
    import time
    limit = 1_000_000
    if time.monotonic() >= deadline_monotonic:
        raise TimeoutError("hook_input_timeout")
    stream = getattr(sys.stdin, "buffer", sys.stdin)
    if isinstance(stream, (io.BytesIO, io.StringIO)):
        raw = stream.read(limit + 1)
        if isinstance(raw, str):
            raw = raw.encode("utf-8")
        chunks = [raw]
        size = len(raw)
    else:
        fd = stream.fileno()
        chunks = []
        size = 0
        if os.name == "nt":
            import ctypes
            import msvcrt
            from ctypes import wintypes
            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            peek = kernel.PeekNamedPipe
            peek.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD,
                             ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD),
                             ctypes.POINTER(wintypes.DWORD)]
            peek.restype = wintypes.BOOL
            file_type = kernel.GetFileType
            file_type.argtypes = [wintypes.HANDLE]
            file_type.restype = wintypes.DWORD
            handle = msvcrt.get_osfhandle(fd)
            kind = file_type(handle)
            if kind not in {1, 3}:
                raise ValueError("unsupported_hook_input")
        else:
            import select
        while size <= limit:
            remaining = deadline_monotonic - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("hook_input_timeout")
            read_size = min(65536, limit + 1 - size)
            if os.name == "nt":
                if kind == 3:
                    available = wintypes.DWORD()
                    if not peek(handle, None, 0, None, ctypes.byref(available), None):
                        error = ctypes.get_last_error()
                        if error in {109, 233}:
                            break
                        raise OSError(error, "hook_input_pipe_failed")
                    if not available.value:
                        time.sleep(min(0.01, remaining))
                        continue
                    read_size = min(read_size, available.value)
            else:
                try:
                    ready, _, _ = select.select([fd], [], [], remaining)
                except InterruptedError:
                    continue
                if not ready:
                    raise TimeoutError("hook_input_timeout")
            if time.monotonic() >= deadline_monotonic:
                raise TimeoutError("hook_input_timeout")
            try:
                chunk = os.read(fd, read_size)
            except InterruptedError:
                continue
            if not chunk:
                break
            size += len(chunk)
            chunks.append(chunk)
    if time.monotonic() >= deadline_monotonic:
        raise TimeoutError("hook_input_timeout")
    raw = b"".join(chunks)
    if size > limit:
        raise _HookInputError(raw[:limit].decode("utf-8", errors="replace"))
    return raw.decode("utf-8")
"""

_reader_namespace: dict[str, object] = {}
exec(compile(HOOK_INPUT_READER_TEMPLATE, __file__, "exec"), _reader_namespace)
read_hook_input = cast(Callable[[float], str], _reader_namespace["_read_hook_input"])
