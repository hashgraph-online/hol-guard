"""Long-lived Guard processes must not mint a new ctypes type per native call.

``ctypes.POINTER`` (and ``pointer`` and ``Type * n``) caches every derived
type for the life of the interpreter. A ``ctypes.Structure`` class built inside
a function body is a brand-new type on every call, so deriving a pointer from it
grows that cache by one entry per call and the daemon's memory never comes back.
"""

from __future__ import annotations

import ast
import ctypes
import types
from pathlib import Path

import pytest

import codex_plugin_scanner.guard.native_policy_snapshot as snapshot_module

SOURCE_ROOT = Path(__file__).resolve().parents[1] / "src" / "codex_plugin_scanner"
DERIVING_CALLS = frozenset({"POINTER", "pointer"})
CACHING_DECORATORS = frozenset({"cache", "lru_cache"})


def _fake_snapshot_kernel(created: list[tuple[object, ...]]) -> types.SimpleNamespace:
    def get_information(_handle: object, reference: object) -> int:
        information = reference._obj  # type: ignore[attr-defined]
        information.dwFileAttributes = snapshot_module._WINDOWS_FILE_ATTRIBUTE_NORMAL
        return 1

    def create_file(*arguments: object) -> object:
        created.append(arguments)
        return ctypes.c_void_p(71)

    return types.SimpleNamespace(
        CreateFileW=create_file,
        CloseHandle=lambda _handle: 1,
        GetFileInformationByHandle=get_information,
        GetFileType=lambda _handle: snapshot_module._WINDOWS_FILE_TYPE_DISK,
    )


def _open_snapshot_handles(
    kernel32: types.SimpleNamespace,
    created: list[tuple[object, ...]],
    count: int,
    *,
    create_new: bool,
) -> tuple[set[type], set[type]]:
    structure_types: set[type] = set()
    pointer_types: set[type] = set()
    descriptor = ctypes.c_void_p(17) if create_new else None
    for _ in range(count):
        opened = snapshot_module._windows_open_handle(
            Path("C:/Guard/snapshot.json"),
            directory=False,
            create_new=create_new,
            descriptor=descriptor,
        )
        structure_types.add(type(opened[2]))
        pointer_types.add(kernel32.GetFileInformationByHandle.argtypes[1])
        if create_new:
            structure_types.add(type(created[-1][3]._obj))
    return structure_types, pointer_types


@pytest.mark.parametrize("create_new", [False, True], ids=["open", "create"])
def test_repeated_snapshot_opens_reuse_one_ctypes_type(
    monkeypatch: pytest.MonkeyPatch,
    create_new: bool,
) -> None:
    created: list[tuple[object, ...]] = []
    kernel32 = _fake_snapshot_kernel(created)
    monkeypatch.setattr(snapshot_module, "_windows_dll", lambda _name: kernel32)
    pointer_cache = getattr(ctypes, "_pointer_type_cache", None)

    _open_snapshot_handles(kernel32, created, 2, create_new=create_new)
    cached_before = len(pointer_cache) if pointer_cache is not None else 0
    structure_types, pointer_types = _open_snapshot_handles(kernel32, created, 200, create_new=create_new)

    assert len(structure_types) == (2 if create_new else 1)
    assert len(pointer_types) == 1
    if pointer_cache is not None:
        assert len(pointer_cache) == cached_before


def _decorator_names(function: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    names: set[str] = set()
    for decorator in function.decorator_list:
        target = decorator.func if isinstance(decorator, ast.Call) else decorator
        if isinstance(target, ast.Attribute):
            names.add(target.attr)
        elif isinstance(target, ast.Name):
            names.add(target.id)
    return names


def _local_ctypes_types(function: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    local: set[str] = set()
    for node in ast.walk(function):
        if isinstance(node, ast.ClassDef) and any(
            ast.unparse(base).split(".")[-1] in {"Structure", "Union", "BigEndianStructure", "LittleEndianStructure"}
            for base in node.bases
        ):
            local.add(node.name)
    return local


def _cached_derivations(function: ast.FunctionDef | ast.AsyncFunctionDef, local: set[str]) -> list[str]:
    findings: list[str] = []
    cached = bool(_decorator_names(function) & CACHING_DECORATORS)
    for node in ast.walk(function):
        if isinstance(node, ast.Call):
            callee = ast.unparse(node.func).split(".")[-1]
            if callee in DERIVING_CALLS and any(
                isinstance(name, ast.Name) and name.id in local for arg in node.args for name in ast.walk(arg)
            ):
                findings.append(ast.unparse(node))
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mult):
            if isinstance(node.left, ast.Name) and node.left.id in local:
                findings.append(ast.unparse(node))
        elif isinstance(node, ast.Return) and not cached:
            if isinstance(node.value, ast.Name) and node.value.id in local:
                findings.append(f"return {node.value.id} (uncached)")
    return findings


def test_runtime_sources_never_derive_cached_types_from_per_call_structures() -> None:
    offenders: list[str] = []
    for path in sorted(SOURCE_ROOT.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for function in ast.walk(tree):
            if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            local = _local_ctypes_types(function)
            if not local:
                continue
            for finding in _cached_derivations(function, local):
                offenders.append(f"{path.relative_to(SOURCE_ROOT)}:{function.lineno} {function.name}: {finding}")
    assert offenders == []
