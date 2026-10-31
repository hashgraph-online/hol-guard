"""Running runtime instances carried from one probe to the next.

Once the file at a runtime's path is replaced, nothing on disk says what an
older process started from. The native probe binds each process to its build
while the file still provably matches; this file keeps the running ones so the
next probe can pass them back as ``known_instances``. Losing or damaging it
only makes those processes unknown, which never clears an advisory; the native
probe rejects any stored artifact that claims more than it could observe.

Scans of different scopes share the file. Each write re-reads it and replaces
only the locations its own probe covered, so a scan never restores what
another one removed. Two scans racing on the same location keep the later
one's view; a process the earlier scan bound is then unknown again, never fixed.
"""

from __future__ import annotations

import json
import os
import tempfile
import unicodedata
from collections.abc import Mapping
from pathlib import Path

from .runtime_identity_probe import RuntimeProbe

INSTANCE_STORE_NAME = "runtime-instances.json"
INSTANCE_STORE_SCHEMA = "guard.runtime-instances.v1"
MAX_KNOWN_INSTANCES = 1_024
_KEYS = frozenset({"boot_identity", "pid", "start_identity", "location_id", "artifact"})
_ARTIFACT_TEXT = ("artifact_id", "family", "os", "arch")
_ARTIFACT_OPTIONAL_TEXT = ("vendor", "version", "build_id")
_ARTIFACT_DIGESTS = ("executable_sha256", "component_identity_sha256")
_ARTIFACT_KEYS = frozenset({*_ARTIFACT_TEXT, *_ARTIFACT_OPTIONAL_TEXT, *_ARTIFACT_DIGESTS, "identity_assurance"})
_CARRIED_ASSURANCE = frozenset({"unknown", "self_reported"})
_HEX = frozenset("0123456789abcdef")


def load_known_instances(guard_home: Path) -> list[dict[str, object]]:
    """The instances an earlier probe saw running, or none when the record is missing or unreadable.

    A record the native probe would refuse is dropped on its own, so it costs
    only the process it named rather than every carried binding.
    """

    try:
        data = json.loads((guard_home / INSTANCE_STORE_NAME).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    if not isinstance(data, dict) or data.get("schema") != INSTANCE_STORE_SCHEMA:
        return []
    items = data.get("instances")
    if not isinstance(items, list):
        return []
    return [dict(item) for item in items if _carried(item)][:MAX_KNOWN_INSTANCES]


def remember_instances(guard_home: Path, probe: RuntimeProbe) -> None:
    """Keep what ``probe`` saw running, and the stored instances at locations it did not cover."""

    if probe.instances is None:
        return
    probed = {location.get("location_id") for location in probe.locations}
    artifacts = {artifact.get("artifact_id"): artifact for artifact in probe.artifacts}
    kept: list[dict[str, object]] = [
        {
            "boot_identity": row["boot_identity"],
            "pid": row["pid"],
            "start_identity": row["start_identity"],
            "location_id": row["location_id"],
            "artifact": artifacts[row["artifact_id"]],
        }
        for row in probe.instances
        if row.get("state") == "running" and row.get("location_id") is not None
    ]
    seen = {(item["boot_identity"], item["pid"], item["start_identity"]) for item in kept}
    for item in load_known_instances(guard_home):
        process = (item.get("boot_identity"), item.get("pid"), item.get("start_identity"))
        if item.get("location_id") not in probed and process not in seen:
            seen.add(process)
            kept.append(item)
    payload = {"schema": INSTANCE_STORE_SCHEMA, "instances": kept[:MAX_KNOWN_INSTANCES]}
    try:
        _write(guard_home / INSTANCE_STORE_NAME, json.dumps(payload, separators=(",", ":"), sort_keys=True))
    except OSError:
        # The next probe then reports these processes as unknown, never as fixed.
        return


def _carried(item: object) -> bool:
    if not isinstance(item, Mapping) or set(item) != _KEYS:
        return False
    pid = item["pid"]
    location = item["location_id"]
    return (
        isinstance(pid, int)
        and not isinstance(pid, bool)
        and 0 < pid < 2**32
        and _identity_text(item["boot_identity"])
        and _identity_text(item["start_identity"])
        and (location is None or _identity_text(location))
        and _carried_artifact(item["artifact"])
    )


def _identity_text(value: object) -> bool:
    return isinstance(value, str) and 0 < len(value) <= 512 and "\0" not in value


def _carried_artifact(artifact: object) -> bool:
    """The checks the native assessment applies, so a stored artifact never costs the whole probe."""

    if not isinstance(artifact, Mapping) or not set(artifact) <= _ARTIFACT_KEYS:
        return False
    artifact_id = artifact.get("artifact_id")
    return (
        isinstance(artifact_id, str)
        and artifact_id.startswith("artifact:")
        and all(_artifact_text(artifact.get(key)) for key in _ARTIFACT_TEXT)
        and all(artifact.get(key) is None or _artifact_text(artifact.get(key)) for key in _ARTIFACT_OPTIONAL_TEXT)
        and all(_digest(artifact.get(key)) for key in _ARTIFACT_DIGESTS)
        and artifact.get("identity_assurance") in _CARRIED_ASSURANCE
    )


def _artifact_text(value: object) -> bool:
    return (
        isinstance(value, str)
        and bool(value.strip())
        and len(value.encode("utf-8")) <= 256
        and not any(unicodedata.category(char) == "Cc" for char in value)
    )


def _digest(value: object) -> bool:
    return value is None or (isinstance(value, str) and len(value) == 64 and set(value) <= _HEX)


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


__all__ = [
    "INSTANCE_STORE_NAME",
    "MAX_KNOWN_INSTANCES",
    "load_known_instances",
    "remember_instances",
]
