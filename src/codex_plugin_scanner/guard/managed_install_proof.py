"""Authenticated-by-origin file proofs for Guard-managed harness installs."""

from __future__ import annotations

import hashlib
import os
from collections.abc import Mapping
from pathlib import Path

from .adapters.base import HarnessContext

MANAGED_INSTALL_PROOF_SCHEMA = "guard.managed-install-proof.v1"
_MANAGED_PATH_KEYS = (
    "config_path",
    "hooks_path",
    "managed_config_path",
    "managed_hooks_path",
    "plugin_path",
    "shim_path",
)
_MANAGED_PATH_LIST_KEYS = ("shim_paths",)
_MAX_PROOF_FILE_BYTES = 4 * 1024 * 1024


def _allowed_file(value: object, context: HarnessContext) -> Path | None:
    if not isinstance(value, str) or not value.strip():
        return None
    candidate = Path(value).expanduser()
    if not candidate.is_absolute() or candidate.is_symlink() or not candidate.is_file():
        return None
    try:
        resolved = candidate.resolve(strict=True)
        size = resolved.stat().st_size
    except OSError:
        return None
    if size > _MAX_PROOF_FILE_BYTES:
        return None
    roots = (context.home_dir.resolve(), context.guard_home.resolve())
    if not any(os.path.commonpath((str(resolved), str(root))) == str(root) for root in roots):
        return None
    return resolved


def _manifest_paths(manifest: Mapping[str, object], context: HarnessContext) -> tuple[Path, ...]:
    candidates: list[object] = [manifest.get(key) for key in _MANAGED_PATH_KEYS]
    for key in _MANAGED_PATH_LIST_KEYS:
        value = manifest.get(key)
        if isinstance(value, list | tuple):
            candidates.extend(value)
    paths = {_allowed_file(candidate, context) for candidate in candidates}
    return tuple(sorted((path for path in paths if path is not None), key=str))


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(64 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def bind_managed_install_proof(
    manifest: Mapping[str, object],
    context: HarnessContext,
) -> dict[str, object]:
    result = dict(manifest)
    artifacts = [{"path": str(path), "sha256": _sha256(path)} for path in _manifest_paths(manifest, context)]
    result["protection_artifact_proof"] = {
        "schema_version": MANAGED_INSTALL_PROOF_SCHEMA,
        "artifacts": artifacts,
    }
    return result


def verify_managed_install_proof(
    manifest: object,
    context: HarnessContext,
) -> bool | None:
    if not isinstance(manifest, Mapping):
        return None
    proof = manifest.get("protection_artifact_proof")
    if not isinstance(proof, Mapping) or proof.get("schema_version") != MANAGED_INSTALL_PROOF_SCHEMA:
        return None
    artifacts = proof.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        return None
    for artifact in artifacts:
        if not isinstance(artifact, Mapping):
            return False
        path = _allowed_file(artifact.get("path"), context)
        expected = artifact.get("sha256")
        if path is None or not isinstance(expected, str) or _sha256(path) != expected:
            return False
    return True


__all__ = (
    "MANAGED_INSTALL_PROOF_SCHEMA",
    "bind_managed_install_proof",
    "verify_managed_install_proof",
)
