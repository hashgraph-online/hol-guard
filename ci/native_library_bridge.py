"""The Guard CLI a test's native daemon runs, with library calls sent back to the test.

``ci.guard_daemon_harness`` names this script as the daemon's CLI command when
a test runs the in-process daemon harness against the native daemon. The
daemon then owns every route, the caller check and the reply, while the
``desktop library-call`` and ``desktop library-serve`` work it hands to the
Guard library runs inside the test process, where the test's patches apply.

Usage: ``native_library_bridge.py PORT NONCE CLI_JSON [daemon arguments...]``.
Any other CLI command runs the real Guard CLI that ``CLI_JSON`` names.

The script imports nothing from Guard so it starts fast.
"""

from __future__ import annotations

import contextlib
import json
import os
import socket
import sys
import threading

_LIBRARY_MODES = frozenset({"library-call", "library-serve"})


def _guard_home(arguments: list[str]) -> str:
    for index, argument in enumerate(arguments):
        if argument == "--guard-home" and index + 1 < len(arguments):
            return arguments[index + 1]
        if argument.startswith("--guard-home="):
            return argument.split("=", 1)[1]
    return ""


def _pump_input(connection: socket.socket) -> None:
    source = sys.stdin.buffer
    try:
        while True:
            chunk = source.read1(65536)
            if not chunk:
                break
            connection.sendall(chunk)
    except OSError:
        pass
    with contextlib.suppress(OSError):
        connection.shutdown(socket.SHUT_WR)


def _relay(port: int, nonce: str, mode: str, guard_home: str) -> int:
    connection = socket.create_connection(("127.0.0.1", port))
    header = {"nonce": nonce, "mode": mode, "guard_home": guard_home}
    connection.sendall(json.dumps(header).encode("utf-8") + b"\n")
    threading.Thread(target=_pump_input, args=(connection,), daemon=True).start()
    out = sys.stdout.buffer
    while True:
        chunk = connection.recv(65536)
        if not chunk:
            break
        out.write(chunk)
        out.flush()
    connection.close()
    return 0


def main(argv: list[str]) -> int:
    port, nonce, cli = int(argv[1]), argv[2], json.loads(argv[3])
    arguments = argv[4:]
    if len(arguments) >= 2 and arguments[0] == "desktop" and arguments[1] in _LIBRARY_MODES:
        return _relay(port, nonce, arguments[1], _guard_home(arguments))
    command = [*cli, *arguments]
    os.execv(command[0], command)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
