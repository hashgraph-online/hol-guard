"""Codex hook key and manifest writers with no runtime caller, for tests.

The native runtime creates and removes the hook key, signs the manifest and
publishes both; these helpers plant one exact state at a time so tests can
check what the runtime does with it.
"""

from __future__ import annotations

import base64
import os
from pathlib import Path

from codex_plugin_scanner.guard.codex_hook_integrity import (
    HOOK_MANIFEST_MAC_ALGORITHM,
    HookSecretMaterial,
    _hook_key,
    _hook_key_answer,
    _ordinary_hook_writer,
    atomic_write_bytes,
)
from codex_plugin_scanner.guard.local_authority_integrity import sign_local_authority_payload
from codex_plugin_scanner.guard.native_owned import record_codex_mutation
from codex_plugin_scanner.guard.native_transition_files import publication
from tests.codex_hook_paths_support import canonical_manifest_bytes, hook_manifest_path, hook_secret_path

_HOOK_MANIFEST_INTEGRITY_PURPOSE = "codex-managed-hook-manifest"
_PRIVATE_FILE_MODE = 0o600


def load_or_create_hook_secret(guard_home: Path) -> HookSecretMaterial:
    with _ordinary_hook_writer(guard_home, hook_secret_path(guard_home), actor="codex.authority-key"):
        return _hook_key("key_ensure", guard_home)


def sign_hook_manifest(unsigned_manifest: dict[str, object], secret: HookSecretMaterial) -> dict[str, object]:
    if "authentication" in unsigned_manifest:
        raise ValueError("Unsigned Codex hook manifests must not contain authentication metadata.")
    generated_at = unsigned_manifest.get("generated_at")
    if not isinstance(generated_at, str) or not generated_at:
        raise ValueError("Unsigned Codex hook manifests require a generation time.")
    payload = dict(unsigned_manifest)
    payload["authentication"] = {
        "algorithm": HOOK_MANIFEST_MAC_ALGORITHM,
        **sign_local_authority_payload(
            payload,
            key_home=os.path.abspath(secret.guard_home),
            key_id=secret.key_id,
            purpose=_HOOK_MANIFEST_INTEGRITY_PURPOSE,
            signed_at=generated_at,
        ),
    }
    return payload


def write_hook_manifest(guard_home: Path, config_path: Path, manifest: dict[str, object]) -> Path:
    with _ordinary_hook_writer(guard_home, config_path, actor="codex.authority-manifest"):
        path = hook_manifest_path(guard_home, config_path)
        atomic_write_bytes(path, canonical_manifest_bytes(manifest) + b"\n", mode=_PRIVATE_FILE_MODE, private=True)
        return path


def remove_hook_manifest(guard_home: Path, config_path: Path) -> None:
    with _ordinary_hook_writer(guard_home, config_path, actor="codex.remove-manifest"):
        publication("remove_manifest", guard_home, config=os.path.abspath(config_path.expanduser()))


def remove_hook_secret_if_unused(guard_home: Path) -> None:
    """Remove the private key after an explicit uninstall removes its last manifest."""

    with _ordinary_hook_writer(guard_home, hook_secret_path(guard_home), actor="codex.remove-unused-key"):
        if _hook_key_answer("key_remove_if_unused", guard_home).get("removed") is True:
            record_codex_mutation("remove_unused_key", hook_secret_path(guard_home), b"", None)


def restore_private_file(path: Path, payload: bytes | None) -> None:
    publication(
        "restore",
        path.parent,
        path=os.path.abspath(path.expanduser()),
        payload=None if payload is None else base64.b64encode(payload).decode("ascii"),
    )
