"""Private pipes to an unprivileged cell actor; never collector authority."""
from __future__ import annotations

import os
import select
import struct
import time

from .vm_bridge_frames import FrameCodec


class CellCodec(FrameCodec):
    role_pair = frozenset({'cell-supervisor','cell-actor'})
    schema = 'gauntlet-product-cell-frame.v1'
    domain = b'gauntlet-product-cell-frame.v1\x00'


def read_bootstrap(fd: int, *, timeout=5, limit=4096):
    """Private dedicated pipe only; never a network/authentication bootstrap."""
    deadline=time.monotonic()+timeout
    os.set_blocking(fd,False)
    def read(length):
        data=bytearray()
        while len(data)<length:
            left=deadline-time.monotonic()
            if left<=0 or not select.select([fd],[],[],left)[0]:
                raise TimeoutError('cell private bootstrap deadline')
            try:
                chunk=os.read(fd,min(65536,length-len(data)))
            except BlockingIOError:
                continue
            if not chunk:
                raise EOFError('cell bootstrap ended')
            data.extend(chunk)
        return bytes(data)
    length=struct.unpack('!I',read(4))[0]
    if not 1<=length<=limit:
        raise ValueError('cell private bootstrap byte budget')
    return read(length)
