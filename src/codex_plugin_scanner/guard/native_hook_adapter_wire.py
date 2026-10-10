"""Order-preserving wire tagging for the native hook adapter (see ``native_hook_adapter``)."""

from __future__ import annotations

import hashlib
import math
from collections.abc import Mapping

# Must equal ``REF_STRING_BYTES`` in the Rust ``hook_adapter_value`` module.
_REF_STRING_BYTES = 64 * 1024
# The resident's strict frame parser limits one string to 1 MiB, one array to
# 4096 items, and nesting depth; 131072 chars is at most 512 KiB of UTF-8.
_CHUNK_CHARS = 131072
_MAX_COLLECTION_ITEMS = 4096
_MAX_TAG_DEPTH = 24


class _UnrepresentableError(ValueError):
    pass


class _TooLargeError(ValueError):
    """The payload has a shape the resident's strict frame parser cannot take."""


class _Tagger:
    """Tags a payload for the wire and resolves digest references in the answer."""

    def __init__(self) -> None:
        # sha256 (hex, of the UTF-8 bytes) -> the oversize string the request carried.
        self.refs: dict[str, str] = {}

    def tag(self, value: object, *, depth: int = 0) -> object:
        if depth > _MAX_TAG_DEPTH:
            raise _TooLargeError("depth")
        if value is None or isinstance(value, (bool, int)):
            return value
        if isinstance(value, float):
            if not math.isfinite(value):
                raise _UnrepresentableError("float")
            return value
        if isinstance(value, str):
            return self._tag_string(value)
        if isinstance(value, Mapping):
            if len(value) * 2 + 1 > _MAX_COLLECTION_ITEMS:
                raise _TooLargeError("items")
            tagged: list[object] = ["d"]
            for child_key, child in value.items():
                if not isinstance(child_key, str):
                    raise _UnrepresentableError("key")
                tagged.extend((self._tag_key(child_key), self.tag(child, depth=depth + 1)))
            return tagged
        if isinstance(value, (list, tuple)):
            if len(value) + 1 > _MAX_COLLECTION_ITEMS:
                raise _TooLargeError("items")
            return ["l", *(self.tag(item, depth=depth + 1) for item in value)]
        raise _UnrepresentableError(type(value).__name__)

    def _tag_key(self, key: str) -> str:
        if len(key) > _CHUNK_CHARS:
            raise _TooLargeError("key")
        result = self._tag_string(key)
        assert isinstance(result, str)
        return result

    def _tag_string(self, value: str) -> object:
        try:
            encoded = value.encode("utf-8")
        except UnicodeEncodeError:
            raise _UnrepresentableError("surrogate") from None
        if len(encoded) >= _REF_STRING_BYTES:
            self.refs[hashlib.sha256(encoded).hexdigest()] = value
        if len(value) > _CHUNK_CHARS:
            # One resident string slot is 1 MiB; the parts rejoin losslessly.
            return ["c", *(value[start : start + _CHUNK_CHARS] for start in range(0, len(value), _CHUNK_CHARS))]
        return value

    def untag(self, value: object) -> object:
        if not isinstance(value, list):
            return value
        if not value:
            raise _UnrepresentableError("tag")
        tag, body = value[0], value[1:]
        if tag == "l":
            return [self.untag(item) for item in body]
        if tag == "d":
            if len(body) % 2 or any(not isinstance(body[i], str) for i in range(0, len(body), 2)):
                raise _UnrepresentableError("dict")
            return {body[i]: self.untag(body[i + 1]) for i in range(0, len(body), 2)}
        if tag == "r" and len(body) == 1 and isinstance(body[0], str) and body[0] in self.refs:
            return self.refs[body[0]]
        raise _UnrepresentableError("tag")
