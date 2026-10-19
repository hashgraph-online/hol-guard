"""Authenticated, bounded records between trusted collectors outside actors.

Keys must be fresh 32-byte random values conveyed only over an already
authenticated private management channel. Never expose keys or this API to the
agent/product. Authentication is transport custody, not verifier eligibility.
"""
from __future__ import annotations

import hashlib
import hmac
import re
import struct
import uuid

from .json_data import canonical_json, strict_json_loads

SCHEMA = 'gauntlet-vm-bridge-frame.v1'
DOMAIN = b'gauntlet-vm-bridge-frame.v1\x00'
MAX_FRAME_BYTES = 12 * 1024**2
ROLES = {'controller', 'product-collector'}


class BridgeProtocolError(ValueError):
    """The connection is no longer usable; never retry an uncertain operation."""


def _uuid(value):
    try:
        valid = type(value) is str and str(uuid.UUID(value)) == value
    except ValueError:
        valid = False
    if not valid:
        raise BridgeProtocolError('canonical session/boot UUID required')
    return value


class FrameCodec:
    """One session, two ordered directions, fail-closed after any bad record."""

    role_pair = frozenset(ROLES)
    schema = SCHEMA
    domain = DOMAIN

    def __init__(self, key: bytes, *, session: str, local_role: str, local_boot: str,
                 peer_boot: str, maximum_frames=10000, maximum_bytes=256*1024**2):
        if type(key) is not bytes or len(key) != 32 or local_role not in self.role_pair:
            raise BridgeProtocolError('fresh private key and declared collector role required')
        if (type(maximum_frames) is not int or not 1 <= maximum_frames <= 10000
                or type(maximum_bytes) is not int or not 1024 <= maximum_bytes <= 256*1024**2):
            raise BridgeProtocolError('finite bridge aggregate limits required')
        self.session, self.local_boot, self.peer_boot = map(_uuid, (session, local_boot, peer_boot))
        self.local_role = local_role
        self.peer_role = next(role for role in self.role_pair if role != local_role)
        self.maximum_frames, self.maximum_bytes = maximum_frames, maximum_bytes
        self.sent, self.received, self.bytes_sent, self.bytes_received = 0, 0, 0, 0
        self._key, self.poisoned = key, False

    def __repr__(self):
        return f'FrameCodec(session={self.session!r}, role={self.local_role!r}, poisoned={self.poisoned!r})'

    def invalidate(self):
        self.poisoned = True

    def _active(self):
        if self.poisoned:
            raise BridgeProtocolError('bridge connection is invalid')

    def validate_length(self, length):
        self._active()
        if (type(length) is not int or not 1 <= length <= MAX_FRAME_BYTES
                or self.received >= self.maximum_frames
                or self.bytes_received + length + 4 > self.maximum_bytes):
            self.invalidate()
            raise BridgeProtocolError('bridge frame/aggregate budget exceeded')

    def encode(self, kind: str, body: dict) -> bytes:
        self._active()
        try:
            if kind not in {'request', 'response'} or type(body) is not dict or self.sent >= self.maximum_frames:
                raise BridgeProtocolError('invalid bridge message kind/body or exhausted frame budget')
            message = {'schema':self.schema,'session':self.session,'source_role':self.local_role,
                       'destination_role':self.peer_role,'source_boot':self.local_boot,
                       'destination_boot':self.peer_boot,'sequence':self.sent,'kind':kind,'body':body}
            signature = hmac.new(self._key, self.domain+canonical_json(message).encode(), hashlib.sha256).hexdigest()
            raw = canonical_json({'message':message,'mac':signature}).encode()
            if len(raw) > MAX_FRAME_BYTES or self.bytes_sent + len(raw) + 4 > self.maximum_bytes:
                raise BridgeProtocolError('outgoing bridge byte budget exceeded')
            # Reserve before writing: failed writes must invalidate, never replay.
            self.sent += 1
            self.bytes_sent += len(raw)+4
            return struct.pack('!I', len(raw))+raw
        except Exception:
            self.invalidate()
            raise

    def decode(self, raw: bytes, *, expected_kind: str) -> dict:
        self._active()
        try:
            if type(raw) is not bytes:
                raise BridgeProtocolError('bridge frame bytes required')
            self.validate_length(len(raw))
            envelope = strict_json_loads(raw)
            if (type(envelope) is not dict or set(envelope) != {'message','mac'}
                    or type(envelope['mac']) is not str or not re.fullmatch('[0-9a-f]{64}',envelope['mac'])):
                raise BridgeProtocolError('invalid authenticated bridge envelope')
            message = envelope['message']
            if (type(message) is not dict or set(message) != {'schema','session','source_role',
                    'destination_role','source_boot','destination_boot','sequence','kind','body'}):
                raise BridgeProtocolError('invalid bridge message fields')
            signature = hmac.new(self._key, self.domain+canonical_json(message).encode(), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(signature, envelope['mac']):
                raise BridgeProtocolError('bridge authentication failed')
            if (message['schema'] != self.schema or message['session'] != self.session
                    or message['source_role'] != self.peer_role or message['destination_role'] != self.local_role
                    or message['source_boot'] != self.peer_boot or message['destination_boot'] != self.local_boot
                    or type(message['sequence']) is not int or message['sequence'] != self.received
                    or expected_kind not in {'request','response'} or message['kind'] != expected_kind
                    or type(message['body']) is not dict):
                raise BridgeProtocolError('bridge session/realm/direction/order mismatch')
            self.received += 1
            self.bytes_received += len(raw)+4
            return message['body']
        except Exception:
            self.invalidate()
            raise
