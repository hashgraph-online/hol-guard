"""Absolute socket-read budgets shared with standalone stdlib hook clients."""

from __future__ import annotations

import urllib.request
from collections.abc import Callable
from typing import cast

HOOK_HTTP_DEADLINE_TEMPLATE = """
def _deadline_http_handler(deadline_monotonic):
    import http.client
    import io
    import time
    import urllib.request

    def remaining():
        budget = deadline_monotonic - time.monotonic()
        if budget <= 0:
            raise TimeoutError("hook_http_timeout")
        return budget

    class DeadlineReader(io.RawIOBase):
        def __init__(self, raw, sock):
            super().__init__()
            self.raw = raw
            self.sock = sock

        def readable(self):
            return True

        def readinto(self, buffer):
            self.sock.settimeout(remaining())
            result = self.raw.readinto(buffer)
            remaining()
            return result

        def close(self):
            try:
                if not self.closed:
                    self.raw.close()
            finally:
                super().close()

    class DeadlineSocket:
        def __init__(self, sock):
            self.sock = sock

        def __getattr__(self, name):
            return getattr(self.sock, name)

        def sendall(self, data, *args):
            self.sock.settimeout(remaining())
            self.sock.sendall(data, *args)
            remaining()

        def makefile(self, mode="rb", buffering=None):
            if mode != "rb":
                raise ValueError("unsupported_hook_http_stream")
            remaining()
            raw = self.sock.makefile("rb", buffering=0)
            try:
                return io.BufferedReader(DeadlineReader(raw, self.sock))
            except BaseException:
                raw.close()
                raise

    class DeadlineConnection(http.client.HTTPConnection):
        def connect(self):
            self.timeout = min(self.timeout, remaining())
            super().connect()
            self.sock = DeadlineSocket(self.sock)
            remaining()

    class DeadlineHandler(urllib.request.HTTPHandler):
        handler_order = 400

        def http_open(self, request):
            remaining()
            return self.do_open(DeadlineConnection, request)

    return DeadlineHandler()
"""

_handler_namespace: dict[str, object] = {"__name__": __name__}
exec(compile(HOOK_HTTP_DEADLINE_TEMPLATE, __file__, "exec"), _handler_namespace)
deadline_http_handler = cast(
    Callable[[float], urllib.request.HTTPHandler], _handler_namespace["_deadline_http_handler"]
)
