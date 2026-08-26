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

_REGEX_PREFIX_TOKENS = frozenset(
    {
        "(",
        "[",
        "{",
        "=",
        ":",
        ",",
        ";",
        "!",
        "?",
        "&&",
        "||",
        "=>",
        "case",
        "delete",
        "do",
        "else",
        "in",
        "instanceof",
        "new",
        "of",
        "return",
        "throw",
        "typeof",
        "void",
        "yield",
        "await",
    }
)


@dataclass(frozen=True, slots=True)
class DshValidation:
    metadata_ok: bool
    bundle_ok: bool
    patch_ok: bool
    runtime_ok: bool
    runtime_path: str | None


def _export_target(value: object) -> str | None:
    """Resolve one Node package export target without selecting subpath exports."""

    if isinstance(value, str):
        stripped = value.strip()
        return stripped or None
    if isinstance(value, list):
        for candidate in value:
            if (resolved := _export_target(candidate)) is not None:
                return resolved
        return None
    if not isinstance(value, dict):
        return None

    for condition in ("import", "require", "node", "default"):
        if condition in value and (resolved := _export_target(value[condition])) is not None:
            return resolved
    for condition, candidate in value.items():
        if not isinstance(condition, str) or condition == "types" or condition.startswith("."):
            continue
        if (resolved := _export_target(candidate)) is not None:
            return resolved
    return None


def _runtime_path(manifest: dict[str, object]) -> str | None:
    """Resolve the package root export, falling back to ``main`` only without ``exports``."""

    if "exports" in manifest:
        exports = manifest["exports"]
        if isinstance(exports, dict):
            if "." in exports:
                return _export_target(exports["."])
            if any(isinstance(key, str) and key.startswith(".") for key in exports):
                return None
        return _export_target(exports)
    main = manifest.get("main")
    if not isinstance(main, str):
        return None
    stripped = main.strip()
    return stripped or None


def _skip_quoted(source: str, index: int, quote: str) -> int:
    """Skip one JavaScript string or template literal."""

    index += 1
    while index < len(source):
        char = source[index]
        if char == "\\":
            index += 2
            continue
        index += 1
        if char == quote:
            break
    return index


def _skip_regex(source: str, index: int) -> int:
    """Skip a JavaScript regex literal using a conservative lexical heuristic."""

    index += 1
    in_character_class = False
    while index < len(source):
        char = source[index]
        if char == "\\":
            index += 2
            continue
        if char == "[":
            in_character_class = True
        elif char == "]":
            in_character_class = False
        elif char == "/" and not in_character_class:
            index += 1
            while index < len(source) and source[index].isalpha():
                index += 1
            break
        elif char in "\r\n":
            break
        index += 1
    return index


def _regex_can_start(tokens: list[str]) -> bool:
    return not tokens or tokens[-1] in _REGEX_PREFIX_TOKENS


def _javascript_tokens(source: str) -> tuple[str, ...]:
    """Tokenize identifiers and punctuation while ignoring comments and literals."""

    tokens: list[str] = []
    index = 0
    while index < len(source):
        char = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if char == "/" and following == "/":
            index += 2
            while index < len(source) and source[index] not in "\r\n":
                index += 1
            continue
        if char == "/" and following == "*":
            end = source.find("*/", index + 2)
            index = len(source) if end < 0 else end + 2
            continue
        if char == "/" and _regex_can_start(tokens):
            index = _skip_regex(source, index)
            continue
        if char in {"'", '"', "`"}:
            index = _skip_quoted(source, index, char)
            continue
        if char.isalpha() or char in {"_", "$"}:
            end = index + 1
            while end < len(source) and (source[end].isalnum() or source[end] in {"_", "$"}):
                end += 1
            tokens.append(source[index:end])
            index = end
            continue
        if source.startswith(("=>", "&&", "||"), index):
            tokens.append(source[index : index + 2])
            index += 2
            continue
        if not char.isspace():
            tokens.append(char)
        index += 1
    return tuple(tokens)


def _matching_brace(tokens: tuple[str, ...], start: int) -> int | None:
    """Return the matching closing brace index for a tokenized object or list."""

    opening = tokens[start]
    closing = {"{": "}", "(": ")", "[": "]"}.get(opening)
    if closing is None:
        return None
    depth = 0
    for index in range(start, len(tokens)):
        if tokens[index] == opening:
            depth += 1
        elif tokens[index] == closing:
            depth -= 1
            if depth == 0:
                return index
    return None


def _export_list_has_apply(entries: tuple[str, ...]) -> bool:
    """Return whether an ESM export list exposes the name ``apply``."""

    start = 0
    while start < len(entries):
        end = start
        while end < len(entries) and entries[end] != ",":
            end += 1
        clause = entries[start:end]
        if clause and clause[0] != "type":
            if len(clause) == 1 and clause[0] == "apply":
                return True
            if len(clause) >= 3 and clause[-2:] == ("as", "apply"):
                return True
        start = end + 1
    return False


def _commonjs_object_has_apply(tokens: tuple[str, ...], start: int, end: int) -> bool:
    """Return whether a top-level CommonJS export object declares an ``apply`` key."""

    depth = 0
    clause_start = start + 1
    index = clause_start
    while index <= end:
        token = tokens[index] if index < end else ","
        if token in {"{", "[", "("}:
            depth += 1
        elif token in {"}", "]", ")"}:
            depth -= 1
        elif depth == 0 and token == ",":
            clause = tokens[clause_start:index]
            if clause and clause[0] == "apply" and (len(clause) == 1 or clause[1] == ":"):
                return True
            clause_start = index + 1
        index += 1
    return False


def _exports_apply(source: str) -> bool:
    """Return true only when tokenized ESM or CommonJS syntax exports ``apply``."""

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
                close = _matching_brace(tail, 1)
                if close is not None and _export_list_has_apply(tail[2:close]):
                    return True
        if tail[:4] == ("exports", ".", "apply", "="):
            return True
        if tail[:6] == ("module", ".", "exports", ".", "apply", "="):
            return True
        if tail[:4] == ("module", ".", "exports", "=") and len(tail) > 4 and tail[4] == "{":
            close = _matching_brace(tail, 4)
            if close is not None and _commonjs_object_has_apply(tail, 4, close):
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
    raw_patch = bundle.get("patch") if isinstance(bundle, dict) else None
    patch = raw_patch.strip() if isinstance(raw_patch, str) else None
    patch_target = package.root_path / patch if patch else None
    patch_ok = False
    if patch is not None and patch_target is not None:
        patch_ok = (
            is_safe_relative_path(package.root_path, patch, require_exists=True)
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
