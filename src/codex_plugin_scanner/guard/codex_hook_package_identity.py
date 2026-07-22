"""Same-version package identity checks for authenticated Codex hook updates."""

from __future__ import annotations

from collections.abc import Mapping

from .codex_hook_file_integrity import CodexHookIntegrityError
from .codex_hook_integrity import HOOK_MANIFEST_SCHEMA_VERSION


def assert_package_reauthentication_is_safe(
    previous_manifest: Mapping[str, object] | None,
    replacement_manifest: Mapping[str, object],
) -> None:
    """Allow interpreter relocation only when the managed package bytes match."""

    if previous_manifest is None or previous_manifest.get("schema_version") != HOOK_MANIFEST_SCHEMA_VERSION:
        return
    if previous_manifest.get("package_version") != replacement_manifest.get("package_version"):
        return
    previous_identity = _package_content_identity(previous_manifest)
    replacement_identity = _package_content_identity(replacement_manifest)
    if previous_identity is not None and previous_identity == replacement_identity:
        return
    raise CodexHookIntegrityError(
        "codex_hook_package_reauthentication_refused",
        "Guard refused to authenticate changed same-version hook code or interpreter bytes. "
        "Reinstall hol-guard from a trusted package, then run `hol-guard install codex` again.",
    )


def _package_content_identity(manifest: Mapping[str, object]) -> tuple[tuple[str, str, int, int, bool], ...] | None:
    packaged_files = manifest.get("packaged_files")
    if not isinstance(packaged_files, list) or not packaged_files:
        return None
    identities: list[tuple[str, str, int, int, bool]] = []
    for file_identity in packaged_files:
        if not isinstance(file_identity, Mapping):
            return None
        role = file_identity.get("role")
        digest = file_identity.get("sha256")
        size = file_identity.get("size")
        mode = file_identity.get("mode")
        executable_required = file_identity.get("executable_required")
        if (
            not isinstance(role, str)
            or not isinstance(digest, str)
            or not isinstance(size, int)
            or isinstance(size, bool)
            or not isinstance(mode, int)
            or isinstance(mode, bool)
            or not isinstance(executable_required, bool)
        ):
            return None
        identities.append((role, digest, size, mode, executable_required))
    if len({identity[0] for identity in identities}) != len(identities):
        return None
    return tuple(sorted(identities))


__all__ = ["assert_package_reauthentication_is_safe"]
