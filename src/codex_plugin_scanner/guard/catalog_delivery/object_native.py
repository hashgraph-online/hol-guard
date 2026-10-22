"""Native checks of delivery objects and containers.

The runtime decides whether fetched bytes are the objects they claim to be.
This adapter moves bytes and file paths to it and turns a rejection back into
the ``ValueError`` its callers expect.
"""

from __future__ import annotations

import base64
import functools
import hashlib
import json
import os
import threading
from collections import OrderedDict
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any, TypeVar

from . import lifecycle

Result = TypeVar("Result")

REQUEST_INVALID = "delivery object request invalid"
# The container checks that the standard ZIP reader used to make.
CONTAINER_STRUCTURE = "delivery container archive invalid"

# Verified answers to reads whose request names the digest of every byte they
# return. Enabling one extension re-reads the same catalogs and installed
# members hundreds of times across preview, preparation and publication, and
# each read starts the runtime. Publication then misses its deadline on slower
# hosts. Answers stay in memory up to a byte budget. An answer is reused only
# while the runtime and every file it read are unchanged.
_ANSWERS: OrderedDict[bytes, tuple[str, tuple[tuple[str, tuple[int, ...]], ...]]] = OrderedDict()
_ANSWERS_LOCK = threading.Lock()
_ANSWERS_LIMIT = 8 * 1024 * 1024
_ANSWER_LIMIT = 1024 * 1024


def _native(**fields: Any) -> dict[str, Any]:
    return lifecycle.invoke("object", **fields)


def sessioned(function: Callable[..., Result]) -> Callable[..., Result]:
    """Verify and copy the runtime once for every native check one operation makes."""

    @functools.wraps(function)
    def run(*args: Any, **kwargs: Any) -> Result:
        with lifecycle.session():
            return function(*args, **kwargs)

    return run


def call(operation: str, *, invalid: str = REQUEST_INVALID, **fields: Any) -> dict[str, Any]:
    """Run one operation; ``invalid`` names a request that cannot be serialised."""
    try:
        reply = _native(operation=operation, **fields)
    except (TypeError, OverflowError) as error:
        raise ValueError(invalid) from error
    rejected = reply.get("rejected")
    if rejected is not None:
        raise ValueError(rejected)
    return reply


def _identity(path: str) -> tuple[int, ...]:
    st = os.stat(path, follow_symlinks=False)
    return (st.st_mode, st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def addressed(
    operation: str,
    *,
    sources: Callable[[dict[str, Any]], Iterable[Path]],
    invalid: str = REQUEST_INVALID,
    **fields: Any,
) -> dict[str, Any]:
    """Run a read whose request fixes its answer, reusing an earlier verified answer.

    ``sources`` names the files an answer read. Only an answer carrying data is
    kept, and only while each of those files keeps its identity, so a removed,
    replaced or modified file goes back to the runtime. A rejection, a partial
    expansion that names missing objects, and a resolved whole asset also go
    back every time.
    """
    try:
        runtime = lifecycle.runtime_fingerprint()
        material = json.dumps({"operation": operation, "request": fields, "runtime": runtime}, sort_keys=True)
    except (OSError, TypeError, ValueError):
        # A missing runtime must fail in native verification, not answer from memory.
        return call(operation, invalid=invalid, **fields)
    digest = hashlib.sha256(material.encode()).digest()
    with _ANSWERS_LOCK:
        held = _ANSWERS.get(digest)
    if held is not None:
        try:
            current = all(_identity(path) == identity for path, identity in held[1])
        except OSError:
            current = False
        with _ANSWERS_LOCK:
            if current and _ANSWERS.get(digest) is held:
                _ANSWERS.move_to_end(digest)
                return json.loads(held[0])
            if _ANSWERS.get(digest) is held:
                del _ANSWERS[digest]
    reply = call(operation, invalid=invalid, **fields)
    if "data" not in reply or "need" in reply:
        return reply
    answer = json.dumps(reply)
    if len(answer) > _ANSWER_LIMIT:
        return reply
    try:
        read = tuple((str(path), _identity(str(path))) for path in sources(reply))
    except (OSError, KeyError, TypeError, ValueError):
        return reply
    with _ANSWERS_LOCK:
        _ANSWERS[digest] = (answer, read)
        _ANSWERS.move_to_end(digest)
        size = sum(len(entry[0]) for entry in _ANSWERS.values())
        while size > _ANSWERS_LIMIT:
            size -= len(_ANSWERS.popitem(last=False)[1][0])
    return reply


def objects_read(directory: Path) -> Callable[[dict[str, Any]], list[Path]]:
    """The cache objects an expansion answer names in its ``reads``."""
    return lambda reply: [directory / f"{sha256}.json" for sha256 in reply["reads"]]


def member_at(path, asset: str, name: str, length: int) -> bytes:
    """One verified member of the container file at ``path``."""
    reply = call("member", path=str(path), asset=asset, name=name, length=length)
    return base64.b64decode(reply["data"], validate=True)


def verify(data: bytes, sha256: str, length: int) -> None:
    """Fetched bytes must have the length and digest that were asked for."""
    call("verify", data=base64.b64encode(data).decode("ascii"), sha256=sha256, length=length)
