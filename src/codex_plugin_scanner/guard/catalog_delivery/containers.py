"""Bounded transfer containers; each selected member retains its own digest.

The container checks are native (see ``object_native``). ``location`` stays here
for validators that check every entry of an index and cannot start the runtime
for each one.
"""

from __future__ import annotations

import os
import re
import tempfile
from pathlib import Path

from .object_native import member_at
from .selection import DIGEST

TAG = re.compile(r"extension-data-[0-9a-f]{40}-[0-9]{1,20}\.[0-9]{1,10}-[0-9]{6}")
CONTAINER = re.compile(r"(objects|packs)-[0-9]{6}\.zip")


def location(value, digest, kind):
    suffix = ".json" if kind == "object" else ".zip"
    if (
        kind not in {"object", "pack"}
        or not isinstance(digest, str)
        or DIGEST.fullmatch(digest) is None
        or not isinstance(value, dict)
        or set(value) not in ({"tag", "asset"}, {"tag", "asset", "member"})
        or not isinstance(value["tag"], str)
        or TAG.fullmatch(value["tag"]) is None
    ):
        raise ValueError("delivery asset location invalid")
    member = kind + "-" + digest + suffix
    if "member" not in value:
        if value["asset"] != member:
            raise ValueError("delivery asset identity invalid")
    elif (
        value["member"] != member
        or not isinstance(value["asset"], str)
        or CONTAINER.fullmatch(value["asset"]) is None
        or not value["asset"].startswith("objects-" if kind == "object" else "packs-")
    ):
        raise ValueError("delivery container location invalid")
    return value


def member(data, asset, name, length):
    """One verified member of container bytes held in memory."""
    descriptor, name_on_disk = tempfile.mkstemp(prefix="hol-guard-container-")
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
        return member_at(Path(name_on_disk), asset, name, length)
    finally:
        os.unlink(name_on_disk)
