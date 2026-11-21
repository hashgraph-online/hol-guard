"""Shared pieces of the package-shim admin parity vectors.

The recorder (``shim_admin_vector_recorder.py``) replays scenarios against the
Python implementation that preceded the resident ``shim_admin`` op, and the Rust
replay test (``rust/crates/guard-command/tests/shim_admin_vectors.rs``) replays the
same scenarios against ``guard_command::shims``. Both sides agree on:

* the step format (``write``/``mkdir``/``symlink``/``remove``/``call``),
* ``{root}`` standing in for the per-run scratch directory, and
* the normalisation below, which makes recorded output independent of the
  scratch directory. Shim bytes embed the directory, so every content hash the
  implementation records would otherwise change from run to run; a hash of a file
  (or of a wrapper plus its sidecar, the attestation bytes) is replaced by the hash
  of the same bytes with the directory replaced by ``{root}``.
"""

from __future__ import annotations

import base64
import hashlib
import importlib
import os
import re
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT_TOKEN = "{root}"
SIDECAR_MARK = b"\n# hol-guard-sidecar\n"
HEX64 = re.compile(r"(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])")
TRANSIENT_FRAGMENTS = ("/var/folders/", "/private/var/folders/", "/tmp/", "/private/tmp/", "/temp/", "pytest-of-")
FIXED_NOW = "2026-03-04T05:06:07.123456+00:00"


def is_transient_root(root: str) -> bool:
    return any(fragment in root for fragment in TRANSIENT_FRAGMENTS)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def root_forms(root: str) -> list[str]:
    """Spellings of a scratch directory that implementations emit.

    On POSIX there is one. On Windows the same directory also appears with doubled
    backslashes (inside ``repr`` and JSON strings) and with forward slashes.
    """

    forms = [root]
    if "\\" in root:
        forms = [root.replace("\\", "\\\\"), root, root.replace("\\", "/")]
    return forms


def replace_root(text: str, root: str, token: str = ROOT_TOKEN) -> str:
    for form in root_forms(root):
        text = text.replace(form, token)
    return text


def substitute(value: object, root: str, token: str = ROOT_TOKEN) -> object:
    """Replace every occurrence of ``root`` in strings (and keys) of a JSON value."""

    if isinstance(value, str):
        return replace_root(value, root, token)
    if isinstance(value, list):
        return [substitute(item, root, token) for item in value]
    if isinstance(value, dict):
        return {str(substitute(key, root, token)): substitute(item, root, token) for key, item in value.items()}
    return value


def expand(value: object, root: str) -> object:
    return substitute(value, ROOT_TOKEN, root) if root != ROOT_TOKEN else value


def remap_hashes(value: object, hash_map: dict[str, str]) -> object:
    """Replace known 64-hex digests inside strings with their root-independent form."""

    if isinstance(value, str):
        return HEX64.sub(lambda match: hash_map.get(match.group(0), match.group(0)), value)
    if isinstance(value, list):
        return [remap_hashes(item, hash_map) for item in value]
    if isinstance(value, dict):
        return {str(remap_hashes(key, hash_map)): remap_hashes(item, hash_map) for key, item in value.items()}
    return value


def snapshot(root: str) -> dict[str, dict[str, object]]:
    """Whole-tree snapshot: relative path -> kind, exec bits and raw content."""

    tree: dict[str, dict[str, object]] = {}
    base = Path(root)
    for current, directories, files in os.walk(root, followlinks=False):
        directories.sort()
        for name in sorted([*directories, *files]):
            path = Path(current) / name
            relative = path.relative_to(base).as_posix()
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                tree[relative] = {"kind": "symlink", "target": os.readlink(path)}
            elif stat.S_ISDIR(info.st_mode):
                tree[relative] = {"kind": "dir"}
            else:
                tree[relative] = {"kind": "file", "exec": info.st_mode & 0o111, "data": path.read_bytes()}
    return tree


def hash_candidates(tree: dict[str, dict[str, object]]) -> dict[str, bytes]:
    """Preimages of the digests an implementation can record for this tree."""

    candidates: dict[str, bytes] = {}
    for relative, entry in tree.items():
        if entry["kind"] != "file":
            continue
        data = entry["data"]
        assert isinstance(data, bytes)
        candidates[relative] = data
        parent, _, name = relative.rpartition("/")
        sidecar = tree.get(f"{parent}/.{name}.py") if parent else None
        if sidecar is not None and sidecar["kind"] == "file":
            sidecar_data = sidecar["data"]
            assert isinstance(sidecar_data, bytes)
            candidates[f"{relative}#attested"] = data + SIDECAR_MARK + sidecar_data
        else:
            candidates[f"{relative}#attested-bare"] = data + SIDECAR_MARK
    return candidates


def collect_hashes(tree: dict[str, dict[str, object]], root: str, hash_map: dict[str, str]) -> None:
    for data in hash_candidates(tree).values():
        normalised = replace_root_bytes(data, root)
        if normalised != data:
            hash_map[sha256_hex(data)] = sha256_hex(normalised)


def replace_root_bytes(data: bytes, root: str) -> bytes:
    for form in root_forms(root):
        data = data.replace(form.encode("utf-8"), ROOT_TOKEN.encode("utf-8"))
    return data


def normalised_bytes(data: bytes, root: str, hash_map: dict[str, str]) -> bytes:
    """File bytes with the scratch directory and known digests made run-independent."""

    data = replace_root_bytes(data, root)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return data
    return str(remap_hashes(text, hash_map)).encode("utf-8")


def tree_digest(tree: dict[str, dict[str, object]], root: str, hash_map: dict[str, str]) -> dict[str, list[object]]:
    digest: dict[str, list[object]] = {}
    for relative, entry in tree.items():
        if entry["kind"] == "dir":
            digest[relative] = ["d"]
        elif entry["kind"] == "symlink":
            digest[relative] = ["l", replace_root(str(entry["target"]), root)]
        else:
            data = entry["data"]
            assert isinstance(data, bytes)
            digest[relative] = ["f", entry["exec"], sha256_hex(normalised_bytes(data, root, hash_map))]
    return digest


def tree_files(tree: dict[str, dict[str, object]], root: str, hash_map: dict[str, str]) -> dict[str, object]:
    """Final tree with content: text when UTF-8 (normalised), else base64."""

    files: dict[str, object] = {}
    for relative, entry in tree.items():
        if entry["kind"] == "dir":
            files[relative] = {"kind": "dir"}
        elif entry["kind"] == "symlink":
            files[relative] = {"kind": "symlink", "target": replace_root(str(entry["target"]), root)}
        else:
            data = entry["data"]
            assert isinstance(data, bytes)
            record: dict[str, object] = {"kind": "file", "exec": entry["exec"]}
            data = normalised_bytes(data, root, hash_map)
            try:
                record["text"] = data.decode("utf-8")
            except UnicodeDecodeError:
                record["b64"] = base64.b64encode(data).decode("ascii")
            files[relative] = record
    return files


class _Proxy:
    """Delegates to a real module while overriding chosen attributes."""

    def __init__(self, real: object, overrides: dict[str, object], hidden: tuple[str, ...] = ()) -> None:
        object.__setattr__(self, "_real", real)
        object.__setattr__(self, "_overrides", overrides)
        object.__setattr__(self, "_hidden", hidden)

    def __getattr__(self, name: str) -> object:
        if name in self._overrides:
            return self._overrides[name]
        if name in self._hidden:
            raise AttributeError(name)
        return getattr(self._real, name)


class _FixedDatetime(datetime):
    fixed = datetime.fromisoformat(FIXED_NOW)

    @classmethod
    def now(cls, tz: object = None) -> datetime:  # type: ignore[override]
        return cls.fixed.astimezone(tz) if tz is not None else cls.fixed.replace(tzinfo=None)  # type: ignore[arg-type]


def install_facts(facts: dict[str, object]) -> list[tuple[object, str, object]]:
    """Patch the process facts the pre-cutover Python implementation reads; returns undo records.

    Only meaningful against the recorded base commit (see the recorder), where
    ``shell_profile_cleanup`` and the Python admin bodies still exist.
    """

    # Resolved at run time: these modules exist only at the recorded base commit.
    package_shim_frozen, shell_profile_cleanup, shims = (
        importlib.import_module(f"codex_plugin_scanner.guard.{name}")
        for name in ("package_shim_frozen", "shell_profile_cleanup", "shims")
    )

    argv0 = facts["argv0"]
    sys_overrides: dict[str, object] = {
        "executable": facts["executable"],
        "version_info": (*facts["python_version"], 0, "final", 0),  # type: ignore[misc]
        "argv": [] if argv0 is None else [argv0],
    }
    if facts["frozen"]:
        sys_overrides["frozen"] = True
    sys_proxy = _Proxy(sys, sys_overrides, hidden=() if facts["frozen"] else ("frozen",))
    os_overrides: dict[str, object] = {}
    # A real Windows run needs no patching; a POSIX host cannot model ``ntpath``.
    if facts["windows"] and os.name != "nt":
        os_overrides = {"name": "nt", "pathsep": ";"}
    os_proxy = _Proxy(os, os_overrides)
    frozen_cli = str(facts["frozen_cli"])
    trusted = [str(item) for item in facts["trusted_frozen_cli_paths"]]  # type: ignore[attr-defined]
    import_root = Path(str(facts["import_root"]))
    _FixedDatetime.fixed = datetime.fromisoformat(str(facts["now"])).astimezone(timezone.utc)
    patches: list[tuple[object, str, object]] = []

    def patch(module: object, name: str, value: object) -> None:
        patches.append((module, name, getattr(module, name)))
        setattr(module, name, value)

    patch(shims, "sys", sys_proxy)
    patch(package_shim_frozen, "sys", sys_proxy)
    patch(shims, "os", os_proxy)
    patch(package_shim_frozen, "os", os_proxy)
    patch(shell_profile_cleanup, "os", os_proxy)
    patch(package_shim_frozen, "resolve_frozen_guard_cli", lambda: frozen_cli)
    patch(package_shim_frozen, "trusted_frozen_guard_cli_paths", lambda: list(trusted))
    patch(shims, "_trusted_import_root", lambda: import_root)
    patch(shims, "SQLITE_CONNECT_TIMEOUT_SECONDS", float(facts["sqlite_connect_timeout_seconds"]))  # type: ignore[arg-type]
    patch(shims, "datetime", _FixedDatetime)
    return patches


def undo_facts(patches: list[tuple[object, str, object]]) -> None:
    for module, name, original in reversed(patches):
        setattr(module, name, original)
