"""Bounded execution context captured by the outer host hook bridge."""

from __future__ import annotations

import hashlib
import json
import os
import re

HOOK_EXECUTION_ENVIRONMENT_KEY = "guard_execution_environment"
MAX_STAMPED_HOOK_INPUT_BYTES = 1_000_000
# Present-but-empty pager variables still select Git's pager (empty disables it).
_PAGER_NAMES = ("GIT_PAGER", "PAGER")
_GIT_TRUE_VALUES = frozenset({"1", "true", "yes", "on"})
# Loader search paths are stamped by value so the native check can prove each
# directory. Injection variables (LD_PRELOAD, DYLD_INSERT_LIBRARIES) are not.
LIBRARY_SEARCH_PATH_NAMES = (
    "LD_LIBRARY_PATH",
    "DYLD_LIBRARY_PATH",
    "DYLD_FALLBACK_LIBRARY_PATH",
    "DYLD_FRAMEWORK_PATH",
    "DYLD_FALLBACK_FRAMEWORK_PATH",
)
_MAX_STAMPED_PATH_BYTES = 32 * 1024
# Git pages through `less` when no pager is configured, so an explicit `less`
# adds no execution surface beyond the default. Only flags that take no
# argument are accepted; -o/-O/-k/-T and similar name files.
_DEFAULT_EQUIVALENT_PAGER = re.compile(r"(?:cat|less(?: -[ABCEFGIJKLMNQRSUVWXacdefgimnqrsuw~]+)*)?")


def git_config_no_system_enabled(value: str | None) -> bool:
    """Match Git's accepted truthy spellings for GIT_CONFIG_NOSYSTEM."""
    return value is not None and value.casefold() in _GIT_TRUE_VALUES


def pager_default_equivalent(value: str | None) -> bool:
    """Report a pager variable that cannot run more than Git's default pager."""
    return value is not None and _DEFAULT_EQUIVALENT_PAGER.fullmatch(value) is not None


def _loader_value_fits(value: str | None) -> bool:
    """Keep a loader value only when its UTF-8 size is within the native bound.

    POSIX surfaces non-UTF-8 environment bytes as surrogate escapes. Measuring
    those with a strict encode raises, so the stamp omits the value and leaves
    the name in the environment-name set.
    """
    if not value:
        return False
    try:
        return len(value.encode()) <= _MAX_STAMPED_PATH_BYTES
    except UnicodeEncodeError:
        return False


def library_search_paths() -> dict[str, str]:
    """Return the exported loader search paths that fit the native path bound."""
    return {
        name: value
        for name in LIBRARY_SEARCH_PATH_NAMES
        if (value := os.environ.get(name)) and _loader_value_fits(value)
    }


def collect_hook_execution_environment() -> dict[str, object]:
    """Declare lookup inputs with an opaque sender commitment, not a signature.

    Native contracts own bounds validation. Withheld environment values cannot
    be recomputed by the receiver, and Unicode names are not silently dropped.
    """
    active = {key: value for key, value in os.environ.items() if value}
    return {
        "path": os.environ.get("PATH", ""),
        "home": os.environ.get("HOME"),
        "git_pager_disabled": pager_default_equivalent(os.environ.get("GIT_PAGER")),
        "pager_disabled": pager_default_equivalent(os.environ.get("PAGER")),
        "environment_names": sorted(set(active) | {n for n in _PAGER_NAMES if n in os.environ}),
        "xdg_config_home": os.environ.get("XDG_CONFIG_HOME") or None,
        "git_config_no_system": git_config_no_system_enabled(os.environ.get("GIT_CONFIG_NOSYSTEM")),
        "library_search_paths": library_search_paths(),
        "environment_digest": hashlib.sha256(
            json.dumps(active, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
    }


def stamp_hook_input_text(text: str) -> str:
    try:
        payload = json.loads(text)
    except (ValueError, TypeError):
        return text
    if not isinstance(payload, dict):
        return text
    payload[HOOK_EXECUTION_ENVIRONMENT_KEY] = collect_hook_execution_environment()
    stamped = json.dumps(payload, ensure_ascii=True, separators=(",", ":"))
    # A near-limit input stays forwardable; the edge then treats context as unavailable.
    return text if len(stamped) > MAX_STAMPED_HOOK_INPUT_BYTES else stamped
