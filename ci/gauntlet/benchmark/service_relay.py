"""Key-free stdio relay to one supervisor-owned Unix MCP service socket.

This standalone stdlib script can be launched by absolute path through the
native managed proxy's scrubbed child environment. It never opens a database,
loads policy/oracles, discovers accounts, or receives a signing key.
"""
from __future__ import annotations

import argparse
import json
import select
import socket
import sys
from pathlib import Path

MAX_FRAME_BYTES = 2 * 1024 * 1024


def validate_frame(line: bytes, maximum: int = MAX_FRAME_BYTES) -> dict:
    if len(line) > maximum:
        raise ValueError("MCP frame exceeds transport budget")

    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError("duplicate JSON object field")
            value[key] = item
        return value

    def reject_constant(_value):
        raise ValueError("nonfinite JSON value")

    value = json.loads(line, object_pairs_hook=pairs, parse_constant=reject_constant)
    if not isinstance(value, dict) or value.get("jsonrpc") != "2.0":
        raise ValueError("invalid MCP JSON-RPC frame")
    return value


def relay(path: Path, *, max_frame_bytes: int = MAX_FRAME_BYTES) -> int:
    if not path.is_absolute():
        raise ValueError("relay socket path must be absolute")
    streams = {}
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(5)
        connection.connect(str(path))
        connection.settimeout(5)
        streams[sys.stdin.buffer] = bytearray()
        streams[connection] = bytearray()
        while streams:
            ready, _, _ = select.select(list(streams), [], [], 1)
            for source in ready:
                chunk = (connection.recv(64 * 1024) if source is connection
                         else sys.stdin.buffer.read1(64 * 1024))
                buffer = streams[source]
                if not chunk:
                    if buffer:
                        raise ValueError("incomplete MCP frame at disconnect")
                    streams.pop(source)
                    if source is connection:
                        return 0
                    connection.shutdown(socket.SHUT_WR)
                    continue
                buffer.extend(chunk)
                while b"\n" in buffer:
                    line, _, remaining = buffer.partition(b"\n")
                    validate_frame(line, max_frame_bytes)
                    if source is connection:
                        sys.stdout.buffer.write(line + b"\n")
                        sys.stdout.buffer.flush()
                    else:
                        connection.sendall(line + b"\n")
                    buffer[:] = remaining
                if len(buffer) > max_frame_bytes:
                    raise ValueError("MCP frame exceeds transport budget")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket", type=Path, required=True)
    args = parser.parse_args(argv)
    return relay(args.socket)


if __name__ == "__main__":
    raise SystemExit(main())
