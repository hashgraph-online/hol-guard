"""Shared validation helpers for native DeepSeek Harness packages."""

from __future__ import annotations

import re
from dataclasses import dataclass

from .ecosystems.types import NormalizedPackage
from .path_support import is_safe_relative_path

DSH_SEMVER_RE = re.compile(
    "".join(
        (
            r"^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)",
            r"(?:-(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*))*)?",
            r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$",
        )
    )
)


@dataclass(frozen=True, slots=True)
class DshValidation:
    metadata_ok: bool
    bundle_ok: bool
    patch_ok: bool
    runtime_ok: bool
    runtime_path: str | None


def _export_target(value: object) -> str | None:
    """Resolve a package export target, preferring import/default conditions."""

    if isinstance(value, str) and value.strip():
        return value
    if not isinstance(value, dict):
        return None
    for condition in ("import", "default", "require", "node"):
        if condition in value and (resolved := _export_target(value[condition])) is not None:
            return resolved
    for nested in value.values():
        if (resolved := _export_target(nested)) is not None:
            return resolved
    return None


def _runtime_path(manifest: dict[str, object]) -> str | None:
    """Resolve the root runtime export, falling back to main only without exports."""

    if "exports" in manifest:
        exports = manifest["exports"]
        if isinstance(exports, dict) and "." in exports:
            return _export_target(exports["."])
        return _export_target(exports)
    main = manifest.get("main")
    return main if isinstance(main, str) and main.strip() else None


def _javascript_tokens(source: str) -> tuple[str, ...]:
    """Tokenize identifiers and punctuation while ignoring JS comments and literals."""

    tokens: list[str] = []
    index = 0
    length = len(source)
    while index < length:
        char = source[index]
        following = source[index + 1] if index + 1 < length else ""
        if char == "/" and following == "/":
            index += 2
            while index < length and source[index] not in "\r\n":
                index += 1
            continue
        if char == "/" and following == "*":
            end = source.find("*/", index + 2)
            index = length if end < 0 else end + 2
            continue
        if char in {"'", '"', "`"}:
            quote = char
            index += 1
            while index < length:
                if source[index] == "\\":
                    index += 2
                    continue
                if source[index] == quote:
                    index += 1
                    break
                index += 1
            continue
        if char.isalpha() or char in {"_", "$"}:
            end = index + 1
            while end < length and (source[end].isalnum() or source[end] in {"_", "$"}):
                end += 1
            tokens.append(source[index:end])
            index = end
            continue
        if not char.isspace():
            tokens.append(char)
        index += 1
    return tuple(tokens)


def _exports_apply(source: str) -> bool:
    """Return true only when tokenized ESM/CommonJS syntax exports ``apply``."""

    tokens = _javascript_tokens(source)
    for index, token in enumerate(tokens):
        tail = tokens[index:]
        if token == "export":
            declaration_index = 1
            if len(tail) > 1 and tail[1] == "async":
                declaration_index = 2
            if (
                len(tail) > declaration_index + 1
                and tail[declaration_index] in {"function", "const", "let", "var", "class"}
                and tail[declaration_index + 1] == "apply"
            ):
                return True
            if len(tail) > 1 and tail[1] == "{":
                close = tail.index("}") if "}" in tail else len(tail)
                entries = tail[2:close]
                if "apply" in entries:
                    return True
                if any(entries[pos : pos + 3] == (name, "as", "apply") for pos, name in enumerate(entries[:-2])):
                    return True
        if tail[:4] in (("exports", ".", "apply", "="), ("module", ".", "exports", ".")):
            if tail[:4] == ("exports", ".", "apply", "="):
                return True
            if len(tail) >= 6 and tail[4:6] == ("apply", "="):
                return True
    return False


def validate_dsh_package(package: NormalizedPackage) -> DshValidation:
    """Validate shared DSH metadata, bundle assets, and Cordis runtime surface."""

    manifest = package.raw_manifest
    name = manifest.get("name")
    version = manifest.get("version")
    metadata_ok = (
        isinstance(name, str)
        and bool(name.strip())
        and isinstance(version, str)
        and bool(DSH_SEMVER_RE.fullmatch(version))
    )
    dsh = manifest.get("dsh")
    bundle = dsh.get("bundle") if isinstance(dsh, dict) else None
    bundle_ok = isinstance(bundle, dict) and bool(bundle)
    patch = bundle.get("patch") if isinstance(bundle, dict) else None
    patch_target = package.root_path / patch if isinstance(patch, str) else None
    patch_ok = (
        isinstance(patch, str)
        and bool(patch.strip())
        and is_safe_relative_path(package.root_path, patch, require_exists=True)
        and patch_target is not None
        and patch_target.is_file()
        and not patch_target.is_symlink()
    )
    runtime_path = _runtime_path(manifest)
    runtime_target = package.root_path / runtime_path if runtime_path is not None else None
    runtime_ok = False
    if (
        runtime_path is not None
        and runtime_target is not None
        and is_safe_relative_path(package.root_path, runtime_path, require_exists=True)
        and runtime_target.is_file()
        and not runtime_target.is_symlink()
    ):
        try:
            runtime_ok = _exports_apply(runtime_target.read_text(encoding="utf-8"))
        except (OSError, UnicodeError):
            runtime_ok = False
    return DshValidation(metadata_ok, bundle_ok, patch_ok, runtime_ok, runtime_path)
