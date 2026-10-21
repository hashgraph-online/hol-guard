"""Pytest plugin that records request-classification calls as parity vectors.

Load with ``-p scripts.ci.sfrs_vector_recorder`` while running existing tests
against the Python implementation. Every outermost call into the recorded entry
points is appended to ``$SFRS_VECTOR_OUT`` as one JSON line holding the inputs,
the result, a bounded snapshot of the test directory the call could read and the
SHA-256 pre-images that were hashed during the call. ``sfrs_vector_finalize``
turns the raw lines into the committed vector files.

Run with ``--basetemp=<root>`` and ``SFRS_VECTOR_ROOT=<resolved root>`` so every
recorded path lives below one prefix that replay can substitute.
"""

from __future__ import annotations

import base64
import dataclasses
import enum
import functools
import hashlib
import importlib
import inspect
import json
import os
import sys
from collections import OrderedDict
from collections.abc import Callable
from pathlib import Path
from typing import Any

_OUT = Path(os.environ.get("SFRS_VECTOR_OUT", "/tmp/sfrs-vectors-raw.jsonl"))
_ROOT = os.environ.get("SFRS_VECTOR_ROOT", "")
# The recording shell's own ripgrep config is not a case input; only a value a
# test sets is recorded.
_AMBIENT_RIPGREP_CONFIG = os.environ.get("RIPGREP_CONFIG_PATH")
_MAX_ENTRIES = 400
_MAX_FILE_BYTES = 65536
_MAX_DEPTH = 5
_MAX_PREIMAGE_BYTES = 262144
_PREIMAGE_CACHE_SIZE = 4096

_SRC = "codex_plugin_scanner.guard"
_SERVICES = f"{_SRC}.runtime.secret_file_request_services"
_ENTRY_POINTS: tuple[tuple[str, str, int], ...] = (
    (f"{_SERVICES}.request_models", "classify_sensitive_path", 0),
    (f"{_SERVICES}.request_models", "extract_sensitive_file_read_request", 0),
    (f"{_SERVICES}.request_models", "extract_sensitive_file_read_request_from_action", 0),
    (f"{_SERVICES}.request_artifacts", "extract_sensitive_file_write_request", 0),
    (f"{_SERVICES}.request_artifacts", "command_list_candidate_texts", 0),
    (f"{_SERVICES}.benign_requests", "build_tool_action_request_artifact", 0),
    (f"{_SERVICES}.github_shell_capabilities", "classify_github_shell_capabilities", 0),
    (f"{_SERVICES}.source_edit_context", "low_risk_compound_developer_execution_context", 0),
    (f"{_SERVICES}.shell_quote_parsing", "literal_cd_execution_context", 0),
    (f"{_SERVICES}.docker_requests", "shell_execution_context_starts_with_literal_cd", 0),
    (f"{_SERVICES}.read_only_filters", "_read_only_lookup_target_is_safe", 0),
    (f"{_SRC}.cli.commands_support_runtime_artifacts", "_hook_runtime_artifact", 1),
)
_OVERRIDE_GUARDS: tuple[tuple[str, str, str, str], ...] = (
    (
        f"{_SRC}.runtime.secret_file_requests",
        "evaluate_command",
        f"{_SRC}.runtime.command_evaluation",
        "evaluate_command",
    ),
    (
        f"{_SRC}.runtime.secret_file_requests",
        "model_shell_execution_context",
        f"{_SRC}.runtime.shell_execution_context",
        "model_shell_execution_context",
    ),
)

_state = {"depth": [0, 0], "sha": OrderedDict(), "order": 0, "last_evaluation": None}
_originals: dict[str, Callable[..., Any]] = {}
_real_sha256 = hashlib.sha256


class _RecordingHash:
    def __init__(self, data: bytes = b"", **kwargs: Any) -> None:
        self._hash = _real_sha256(data, **kwargs)
        self._buffer = bytearray(data[:_MAX_PREIMAGE_BYTES])
        self._truncated = len(data) > _MAX_PREIMAGE_BYTES

    def update(self, data: bytes) -> None:
        self._hash.update(data)
        if self._truncated:
            return
        remaining = _MAX_PREIMAGE_BYTES - len(self._buffer)
        self._buffer += data[:remaining]
        self._truncated = len(data) > remaining

    def copy(self) -> _RecordingHash:
        clone = _RecordingHash()
        clone._hash = self._hash.copy()
        clone._buffer = bytearray(self._buffer)
        clone._truncated = self._truncated
        return clone

    def _remember(self, digest: str) -> None:
        """Store the pre-image, or a ``None`` marker when it is truncated or not UTF-8.

        The marker keeps the digest in the table so any record that references it
        is dropped by the finalizer instead of shipping an unrebound digest.
        """

        preimage: bytes | None = None if self._truncated else bytes(self._buffer)
        if preimage is not None:
            try:
                preimage.decode("utf-8")
            except UnicodeDecodeError:
                preimage = None
        _remember(digest, preimage)

    def hexdigest(self) -> str:
        digest = self._hash.hexdigest()
        self._remember(digest)
        return digest

    def digest(self) -> bytes:
        raw = self._hash.digest()
        self._remember(raw.hex())
        return raw

    def __getattr__(self, name: str) -> Any:
        return getattr(self._hash, name)


def _remember(digest: str, preimage: bytes | None) -> None:
    table: OrderedDict[str, tuple[int, bytes | None]] = _state["sha"]  # type: ignore[assignment]
    if digest in table:
        return
    _state["order"] += 1  # type: ignore[operator]
    table[digest] = (_state["order"], preimage)  # type: ignore[assignment]
    while len(table) > _PREIMAGE_CACHE_SIZE:
        table.popitem(last=False)


def _serialize(value: Any, *, depth: int = 0) -> Any:
    if depth > 24:
        return {"$truncated": True}
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, enum.Enum):
        return _serialize(value.value, depth=depth + 1)
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, bytes):
        return {"$bytes": base64.b64encode(value).decode("ascii")}
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        fields = {
            field.name: _serialize(getattr(value, field.name, None), depth=depth + 1)
            for field in dataclasses.fields(value)
        }
        return {"$type": type(value).__name__, **fields}
    if isinstance(value, dict):
        return {str(key): _serialize(item, depth=depth + 1) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_serialize(item, depth=depth + 1) for item in value]
    if isinstance(value, (set, frozenset)):
        return sorted(
            (_serialize(item, depth=depth + 1) for item in value), key=lambda item: json.dumps(item, sort_keys=True)
        )
    to_dict = getattr(value, "to_dict", None)
    if callable(to_dict):
        try:
            return {"$type": type(value).__name__, **_serialize(to_dict(), depth=depth + 1)}
        except Exception:
            pass
    return {"$repr": repr(value)[:400], "$type": type(value).__name__}


def _under_root(text: str) -> bool:
    return bool(_ROOT) and (text == _ROOT or text.startswith(_ROOT + os.sep))


def _test_directory(arguments: dict[str, Any]) -> Path | None:
    for key in ("cwd", "home_dir", "workspace", "workspace_root", "guard_home"):
        value = arguments.get(key)
        if isinstance(value, (Path, str)) and _under_root(str(value)):
            relative = Path(str(value)).relative_to(_ROOT)
            if relative.parts:
                return Path(_ROOT) / relative.parts[0]
    return None


def _snapshot(directory: Path) -> dict[str, Any] | None:
    entries: list[dict[str, Any]] = []
    for current, dirnames, filenames in os.walk(directory, followlinks=False):
        relative = Path(current).relative_to(directory)
        if len(relative.parts) >= _MAX_DEPTH:
            dirnames[:] = []
        dirnames.sort()
        for name in sorted(dirnames):
            full = Path(current) / name
            rel = str(relative / name) if relative.parts else name
            if full.is_symlink():
                entries.append({"path": rel, "kind": "symlink", "target": os.readlink(full)})
            else:
                entries.append({"path": rel, "kind": "dir"})
        for name in sorted(filenames):
            full = Path(current) / name
            rel = str(relative / name) if relative.parts else name
            if full.is_symlink():
                entries.append({"path": rel, "kind": "symlink", "target": os.readlink(full)})
                continue
            try:
                data = full.read_bytes()
            except OSError:
                return None
            if len(data) > _MAX_FILE_BYTES:
                return None
            entry: dict[str, Any] = {"path": rel, "kind": "file", "mode": full.stat().st_mode & 0o777}
            try:
                entry["text"] = data.decode("utf-8")
            except UnicodeDecodeError:
                entry["base64"] = base64.b64encode(data).decode("ascii")
            entries.append(entry)
        if len(entries) > _MAX_ENTRIES:
            return None
    return {"dir": str(directory.relative_to(_ROOT)), "entries": entries}


def _env_snapshot() -> dict[str, str | None]:
    home = os.environ.get("HOME")
    snapshot: dict[str, str | None] = {"HOME": home if home is not None and _under_root(home) else None}
    ripgrep_config = os.environ.get("RIPGREP_CONFIG_PATH")
    if ripgrep_config and ripgrep_config != _AMBIENT_RIPGREP_CONFIG:
        snapshot["RIPGREP_CONFIG_PATH"] = ripgrep_config
    path_entries = os.environ.get("PATH", "").split(os.pathsep)
    if any(entry and _under_root(entry) for entry in path_entries):
        snapshot["PATH"] = os.pathsep.join(entry for entry in path_entries if entry and _under_root(entry))
        snapshot["PATH"] += os.pathsep + "/usr/bin" + os.pathsep + "/bin"
    return snapshot


def _overridden() -> bool:
    for facade_name, facade_attr, owner_name, owner_attr in _OVERRIDE_GUARDS:
        facade = sys.modules.get(facade_name)
        owner = sys.modules.get(owner_name)
        if facade is None or owner is None:
            continue
        if getattr(facade, facade_attr, None) is not getattr(owner, owner_attr, None):
            return True
    return False


def _relevant_sha(text: str) -> dict[str, list[Any]]:
    table: OrderedDict[str, tuple[int, bytes | None]] = _state["sha"]  # type: ignore[assignment]
    by_prefix: dict[str, list[str]] = {}
    for digest in table:
        by_prefix.setdefault(digest[:8], []).append(digest)
    selected: dict[str, list[Any]] = {}
    pending = [text]
    while pending:
        current = pending.pop()
        for prefix, digests in by_prefix.items():
            if prefix not in current:
                continue
            for digest in digests:
                if digest[:8] in current and digest not in selected:
                    order, preimage = table[digest]
                    if preimage is None:
                        selected[digest] = [order, None]
                        continue
                    decoded = preimage.decode("utf-8")
                    selected[digest] = [order, decoded]
                    pending.append(decoded)
    return selected


def _record(
    entry: str, signature: inspect.Signature, args: tuple[Any, ...], kwargs: dict[str, Any], result: Any
) -> None:
    try:
        bound = signature.bind(*args, **kwargs)
    except TypeError:
        return
    arguments = dict(bound.arguments)
    for key, value in arguments.items():
        if (
            isinstance(value, (Path, str))
            and not _under_root(str(value))
            and key in {"cwd", "home_dir", "workspace", "guard_home", "workspace_root"}
        ):
            return
    directory = _test_directory(arguments)
    evaluation_payload = _serialize(_state["last_evaluation"]) if _state["last_evaluation"] is not None else None
    snapshot = _snapshot(directory) if directory is not None else None
    if directory is not None and snapshot is None:
        return
    serialized_args = _serialize(arguments)
    serialized_result = _serialize(result)
    line = {
        "entry": entry,
        "test": os.environ.get("PYTEST_CURRENT_TEST", "").split(" ")[0],
        "args": serialized_args,
        "result": serialized_result,
        "env": _env_snapshot(),
        "snapshot": snapshot,
        "evaluation": evaluation_payload,
        "sha": _relevant_sha(json.dumps([serialized_args, serialized_result, evaluation_payload], sort_keys=True)),
    }
    with _OUT.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(line, sort_keys=True) + "\n")


def _wrap(entry: str, function: Callable[..., Any], layer: int) -> Callable[..., Any]:
    signature = inspect.signature(function)

    @functools.wraps(function)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        depth = _state["depth"]
        if depth[layer] > 0:  # type: ignore[index]
            return function(*args, **kwargs)
        depth[layer] += 1  # type: ignore[index]
        _state["last_evaluation"] = None
        try:
            result = function(*args, **kwargs)
        finally:
            depth[layer] -= 1  # type: ignore[index]
        if not _overridden():
            try:
                _record(entry, signature, args, kwargs, result)
            except Exception as error:
                sys.stderr.write(f"sfrs-recorder: {entry}: {error!r}\n")
        return result

    wrapper.__sfrs_original__ = function  # type: ignore[attr-defined]
    return wrapper


def _wrap_evaluation(function: Callable[..., Any]) -> Callable[..., Any]:
    @functools.wraps(function)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        result = function(*args, **kwargs)
        _state["last_evaluation"] = result
        return result

    wrapper.__sfrs_original__ = function  # type: ignore[attr-defined]
    return wrapper


def _rebind(replacements: dict[int, Any]) -> None:
    for module in list(sys.modules.values()):
        namespace = getattr(module, "__dict__", None)
        if not isinstance(namespace, dict):
            continue
        for name, value in list(namespace.items()):
            replacement = replacements.get(id(value))
            if replacement is not None and value is not replacement:
                namespace[name] = replacement


def install() -> None:
    replacements: dict[int, Any] = {}
    for module_name, function_name, layer in _ENTRY_POINTS:
        module = importlib.import_module(module_name)
        original = getattr(module, function_name)
        if getattr(original, "__sfrs_original__", None) is not None:
            continue
        _originals[f"{module_name}.{function_name}"] = original
        replacements[id(original)] = _wrap(function_name, original, layer)
    benign = importlib.import_module(f"{_SERVICES}.benign_requests")
    evaluate = benign.evaluate_command
    if getattr(evaluate, "__sfrs_original__", None) is None:
        replacements[id(evaluate)] = _wrap_evaluation(evaluate)
    hashlib.sha256 = _RecordingHash  # type: ignore[assignment]
    _rebind(replacements)
    _state["replacements"] = replacements  # type: ignore[assignment]


def pytest_configure(config: Any) -> None:
    install()


def pytest_collection_finish(session: Any) -> None:
    replacements = _state.get("replacements")
    if isinstance(replacements, dict):
        _rebind(replacements)


def pytest_runtest_setup(item: Any) -> None:
    replacements = _state.get("replacements")
    if isinstance(replacements, dict):
        _rebind(replacements)


def pytest_runtest_logreport(report: Any) -> None:
    if not report.failed:
        return
    target = Path(os.environ.get("SFRS_VECTOR_FAILED", "/tmp/sfrs-vectors-failed.txt"))
    with target.open("a", encoding="utf-8") as handle:
        handle.write(f"FAILED {report.nodeid.split(' ')[0]}\n")
