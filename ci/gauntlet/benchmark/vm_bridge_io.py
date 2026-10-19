"""Deadline-bound nonblocking management stdio; never parse actor output here."""
from __future__ import annotations

import math
import os
import select
import socket
import stat
import struct
import time

from .vm_bridge_frames import BridgeProtocolError, FrameCodec


def validate_management_fd(descriptor):
    if type(descriptor) is not int:
        raise BridgeProtocolError('dedicated management descriptor required')
    mode = os.fstat(descriptor).st_mode
    if not (stat.S_ISFIFO(mode) or stat.S_ISSOCK(mode)):
        raise BridgeProtocolError('management channel requires pipes or stream sockets')
    if stat.S_ISSOCK(mode):
        with socket.socket(fileno=os.dup(descriptor)) as channel:
            if (channel.family != socket.AF_UNIX
                    or channel.getsockopt(socket.SOL_SOCKET,socket.SO_TYPE) != socket.SOCK_STREAM):
                raise BridgeProtocolError('only private Unix stream sockets are supported')


class BridgeIO:
    def __init__(self, reader_fd: int, writer_fd: int, codec: FrameCodec):
        if type(reader_fd) is not int or type(writer_fd) is not int or reader_fd == writer_fd:
            raise BridgeProtocolError('distinct dedicated management descriptors required')
        for descriptor in (reader_fd, writer_fd):
            validate_management_fd(descriptor)
        self.reader_fd, self.writer_fd, self.codec = reader_fd, writer_fd, codec
        # These descriptors belong exclusively to this transport. Never wrap an
        # actor's stdio or a descriptor shared with another reader/writer.
        os.set_blocking(reader_fd, False)
        os.set_blocking(writer_fd, False)

    def _remaining(self, deadline):
        if type(deadline) not in (int,float) or not math.isfinite(deadline):
            raise BridgeProtocolError('finite monotonic I/O deadline required')
        remaining = deadline-time.monotonic()
        if remaining <= 0:
            raise TimeoutError('bridge management I/O deadline exceeded')
        return remaining

    def _read(self, length, deadline):
        output = bytearray()
        while len(output) < length:
            ready, _, _ = select.select([self.reader_fd], [], [], self._remaining(deadline))
            if not ready:
                raise TimeoutError('bridge frame read deadline exceeded')
            try:
                chunk = os.read(self.reader_fd, min(65536, length-len(output)))
            except BlockingIOError:
                continue
            if not chunk:
                raise EOFError('bridge management stream ended before terminal acknowledgement')
            output.extend(chunk)
        return bytes(output)

    def receive(self, kind, *, deadline):
        try:
            length = struct.unpack('!I', self._read(4, deadline))[0]
            # Reject the announced size before allocating/reading its body.
            self.codec.validate_length(length)
            return self.codec.decode(self._read(length, deadline), expected_kind=kind)
        except BaseException:
            self.codec.invalidate()
            raise

    def send(self, kind, body, *, deadline):
        try:
            self._remaining(deadline)
            raw = self.codec.encode(kind, body)
            offset = 0
            while offset < len(raw):
                _, ready, _ = select.select([], [self.writer_fd], [], self._remaining(deadline))
                if not ready:
                    raise TimeoutError('bridge frame write deadline exceeded')
                try:
                    count = os.write(self.writer_fd, raw[offset:offset+65536])
                except BlockingIOError:
                    continue
                if count <= 0:
                    raise BrokenPipeError('bridge frame write made no progress')
                offset += count
        except BaseException:
            self.codec.invalidate()
            raise
