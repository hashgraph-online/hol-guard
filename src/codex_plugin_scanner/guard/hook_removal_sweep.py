"""Find and strip Guard-owned hook handlers from harness config files.

The per-harness adapters remove what Guard recorded at install time. This
sweep is the backstop for hooks the store no longer knows about (a lost state
directory, a half-finished update, an older Guard version): it scans each known
harness config file for hook handlers whose command carries a Guard signature
and removes only those handlers. Handlers that are not Guard's are preserved.

Only JSON and TOML files are rewritten. A TOML rewrite is accepted only when
the re-parsed result equals the pruned payload, so a lossy serializer can never
silently drop unrelated settings.
"""

from __future__ import annotations

import json
import os
import shlex
import stat
import tempfile
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path

from .adapters.base import HarnessContext
from .adapters.contracts import contract_for
from .codex_config import dump_toml, tomllib

_MAX_CONFIG_BYTES = 8 * 1024 * 1024
_COMMAND_KEYS = ("command", "bash", "powershell", "script", "cmd")
_GUARD_EXECUTABLES = frozenset({"hol-guard", "hol-guard.exe", "hol guard", "plugin-guard", "plugin-guard.exe"})
_GUARD_MARKERS = (
    "hol_guard_managed",
    "hol guard managed",
    "hol_guard_claude_daemon_hook",
    "hol_guard_claude_session_start_hook",
    "hol-guard-codex-hook",
    "hol-guard-cursor-hook",
    "hol_guard_hook_argv",
    "__guard-bounded-hook",
    "codex_daemon_hook_bridge",
    "claude_daemon_hook_bridge",
    "bounded_cli_hook_bridge",
    "managed/bounded-hooks/",
)
# Supplementary hook files that are not listed in the protection contracts.
_EXTRA_HOOK_FILES = {
    "codex": ("~/.codex/hooks.json",),
    "claude-code": ("~/.claude/settings.json", "~/.claude/settings.local.json"),
    "copilot": ("~/.copilot/hooks.json", "~/.copilot/config.json"),
}
_WORKSPACE_EXTRA_FILES = {
    "codex": (".codex/config.toml", ".codex/hooks.json"),
    "claude-code": (".claude/settings.json", ".claude/settings.local.json"),
    "cursor": (".cursor/hooks.json",),
    "devin": (".devin/hooks.v1.json",),
}
_SWEEPABLE_SUFFIXES = (".json", ".toml")


@dataclass(frozen=True)
class SweepFileResult:
    path: Path
    removed: int = 0
    wrote: bool = False
    error: str | None = None
    event_names: tuple[str, ...] = ()


@dataclass
class SweepTotals:
    files: list[SweepFileResult] = field(default_factory=list)

    @property
    def removed(self) -> int:
        return sum(item.removed for item in self.files)


def is_guard_hook_command(command: object) -> bool:
    """Return True when a hook command string carries a Guard signature."""

    if not isinstance(command, str) or not command.strip():
        return False
    lowered = command.lower().replace('\\"', '"')
    if any(marker in lowered for marker in _GUARD_MARKERS):
        return True
    try:
        tokens = shlex.split(command)
    except ValueError:
        tokens = command.split()
    if not tokens:
        return False
    first = Path(tokens[0].replace("\\", "/")).name.lower()
    rest = [token.lower() for token in tokens[1:]]
    if first in _GUARD_EXECUTABLES and "hook" in rest:
        return True
    joined = " ".join(rest)
    if "codex_plugin_scanner.cli" not in joined:
        return False
    return ("guard" in rest and "hook" in rest) or "'guard', 'hook'" in joined


def _handler_is_guard(handler: Mapping[str, object]) -> bool:
    return any(is_guard_hook_command(handler.get(key)) for key in _COMMAND_KEYS)


def _is_handler_dict(node: object) -> bool:
    return isinstance(node, dict) and any(isinstance(node.get(key), str) for key in _COMMAND_KEYS)


def _prune_entries(entries: list[object], removed: list[str], event: str) -> list[object]:
    """Drop Guard handlers (and matcher groups they leave empty) from one event list."""

    kept: list[object] = []
    for item in entries:
        if not isinstance(item, dict):
            kept.append(item)
            continue
        if _is_handler_dict(item):
            if _handler_is_guard(item):
                removed.append(event)
                continue
            kept.append(item)
            continue
        inner = item.get("hooks")
        if not isinstance(inner, list):
            kept.append(item)
            continue
        before = len(removed)
        pruned_inner = _prune_entries(inner, removed, event)
        if len(removed) == before:
            kept.append(item)
        elif pruned_inner:
            kept.append({**item, "hooks": pruned_inner})
        # A group left with no handlers has nothing to run; drop it.
    return kept


def prune_guard_hooks(payload: dict[str, object]) -> tuple[dict[str, object], list[str]]:
    """Strip Guard handlers under the payload's ``hooks`` key."""

    removed: list[str] = []
    hooks = payload.get("hooks")
    pruned: object
    if isinstance(hooks, list):
        pruned = _prune_entries(hooks, removed, "")
    elif isinstance(hooks, dict):
        events: dict[str, object] = {}
        for name, entries in hooks.items():
            if not isinstance(entries, list):
                events[name] = entries
                continue
            before = len(removed)
            pruned_entries = _prune_entries(entries, removed, str(name))
            if len(removed) > before and not pruned_entries:
                continue
            events[name] = pruned_entries
        pruned = events
    else:
        return payload, removed
    if not removed:
        return payload, removed
    result = dict(payload)
    if pruned:
        result["hooks"] = pruned
    else:
        result.pop("hooks", None)
    return result, removed


def _load(path: Path) -> tuple[dict[str, object] | None, str | None]:
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode):
            return None, "not_regular_file"
        if metadata.st_size > _MAX_CONFIG_BYTES:
            return None, "too_large"
        raw = path.read_bytes()
    except OSError:
        return None, "unreadable"
    try:
        text = raw.decode("utf-8")
        payload = tomllib.loads(text) if path.suffix == ".toml" else json.loads(text)
    except (UnicodeDecodeError, ValueError, tomllib.TOMLDecodeError):
        return None, "unparseable"
    if not isinstance(payload, dict):
        return None, "unexpected_shape"
    return payload, None


def _serialize(path: Path, payload: dict[str, object]) -> str | None:
    if path.suffix == ".toml":
        text = dump_toml(payload)
        try:
            if tomllib.loads(text) != payload:
                return None
        except tomllib.TOMLDecodeError:
            return None
        return text
    return json.dumps(payload, indent=2) + "\n"


def _atomic_replace(path: Path, text: str, mode: int) -> None:
    descriptor, temporary = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(text)
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        with suppress(OSError):
            os.unlink(temporary)


def sweep_config_file(path: Path, *, dry_run: bool) -> SweepFileResult:
    """Remove Guard hook handlers from one file; never raises."""

    payload, problem = _load(path)
    if payload is None:
        return SweepFileResult(path=path, error=problem)
    pruned, removed = prune_guard_hooks(payload)
    if not removed:
        return SweepFileResult(path=path)
    events = tuple(sorted({name for name in removed if name}))
    if dry_run:
        return SweepFileResult(path=path, removed=len(removed), event_names=events)
    text = _serialize(path, pruned)
    if text is None:
        return SweepFileResult(path=path, removed=0, error="rewrite_not_lossless", event_names=events)
    try:
        mode = stat.S_IMODE(path.lstat().st_mode)
        _atomic_replace(path, text, mode)
    except OSError:
        return SweepFileResult(path=path, error="write_failed", event_names=events)
    return SweepFileResult(path=path, removed=len(removed), wrote=True, event_names=events)


def _inside(path: Path, roots: tuple[Path, ...]) -> bool:
    try:
        resolved = path.resolve()
    except (OSError, RuntimeError):
        return False
    return any(resolved == root or root in resolved.parents for root in roots)


def harness_hook_files(harness: str, context: HarnessContext) -> tuple[Path, ...]:
    """Existing JSON/TOML config files that may hold hooks for ``harness``."""

    contract = contract_for(harness)
    raw: list[Path] = []
    relative_specs = list(contract.config_paths) if contract is not None else []
    for spec in (*relative_specs, *_EXTRA_HOOK_FILES.get(harness, ())):
        base = Path(spec)
        if base.parts and base.parts[0] == "~":
            raw.append(context.home_dir.joinpath(*base.parts[1:]))
        elif base.is_absolute():
            raw.append(base)
        else:
            raw.append(context.home_dir / base)
            if context.workspace_dir is not None:
                raw.append(context.workspace_dir / base)
    if context.workspace_dir is not None:
        raw.extend(context.workspace_dir / spec for spec in _WORKSPACE_EXTRA_FILES.get(harness, ()))
    roots = tuple(
        root.resolve() for root in (context.home_dir, context.workspace_dir) if root is not None and root.exists()
    )
    files: list[Path] = []
    for candidate in raw:
        if candidate.suffix not in _SWEEPABLE_SUFFIXES or candidate in files:
            continue
        # lstat so a symlinked config is reported, not followed outside the
        # user's own roots.
        if not candidate.is_symlink() and candidate.is_file() and _inside(candidate, roots):
            files.append(candidate)
    return tuple(files)


def sweep_harness(harness: str, context: HarnessContext, *, dry_run: bool) -> SweepTotals:
    totals = SweepTotals()
    for path in harness_hook_files(harness, context):
        totals.files.append(sweep_config_file(path, dry_run=dry_run))
    return totals


__all__ = [
    "SweepFileResult",
    "SweepTotals",
    "harness_hook_files",
    "is_guard_hook_command",
    "prune_guard_hooks",
    "sweep_config_file",
    "sweep_harness",
]
