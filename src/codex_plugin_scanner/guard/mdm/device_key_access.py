"""Narrow verified access to machine key generations for fixed signing protocols."""

from __future__ import annotations

from .contracts import MachinePaths
from .device_key import KeyGeneration, _read_metadata, verified_machine_device_key_ids


def verified_machine_device_key_by_id(
    paths: MachinePaths,
    key_id: str | None = None,
    *,
    system_name: str | None = None,
) -> KeyGeneration:
    active_key_id, verified_ids = verified_machine_device_key_ids(paths, system_name=system_name)
    requested = key_id or active_key_id
    if requested not in verified_ids:
        raise OSError("device_key_public_mismatch")
    metadata = _read_metadata(paths)
    if metadata is None or metadata.state != "active":
        raise OSError("device_key_rotation_incomplete")
    for generation in (metadata.active, metadata.previous):
        if generation is not None and generation.key_id == requested:
            return generation
    raise OSError("device_key_rotation_incomplete")


__all__ = ["verified_machine_device_key_by_id"]
