"""Collector-side FD relay. Never contains a signing key or candidate code."""
from __future__ import annotations

import base64
import fcntl
import json
import os
import subprocess
import sys


def main() -> int:
    readers, writers = [], []
    for _ in range(3):
        read, write = os.pipe()
        readers.append(fcntl.fcntl(read, fcntl.F_DUPFD_CLOEXEC, 20))
        writers.append(fcntl.fcntl(write, fcntl.F_DUPFD_CLOEXEC, 30))
        os.close(read)
        os.close(write)
    for index, descriptor in enumerate(readers, 3):
        os.dup2(descriptor, index, inheritable=True)
        os.close(descriptor)
    child = subprocess.Popen(sys.argv[1:], pass_fds=(3, 4, 5), close_fds=True)
    for descriptor in (3, 4, 5):
        os.close(descriptor)
    try:
        data = sys.stdin.buffer.readline(1024 * 1024 + 1)
        if len(data) > 1024 * 1024:
            raise ValueError("bootstrap packet exceeds bound")
        packet = json.loads(data)
        values = [json.dumps(packet["plan"], sort_keys=True).encode(),
                  json.dumps(packet["isolation"], sort_keys=True).encode(),
                  base64.b64decode(packet["public_key"], validate=True)]
        for descriptor, value in zip(writers, values, strict=True):
            with os.fdopen(descriptor, "wb") as pipe:
                pipe.write(value)
        return child.wait(timeout=150)
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=5)


if __name__ == "__main__":
    raise SystemExit(main())
