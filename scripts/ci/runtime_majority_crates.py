"""Cargo crate-graph helpers for the runtime-majority report.

A crate is linked into ``hol-guard-runtime`` when it is a normal or
target-specific path dependency of the binary crate (transitively); dev- and
build-dependencies and separate binary targets are not linked.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 compatibility
    import tomli as tomllib  # type: ignore[no-redef]


def _dependency_tables(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    tables = [manifest.get("dependencies", {})]
    for target in manifest.get("target", {}).values():
        tables.append(target.get("dependencies", {}))
    return [table for table in tables if isinstance(table, dict)]


def load_crate_graph(rust_root: Path) -> dict[str, tuple[Path, list[str], dict[str, Any]]]:
    """Map crate name -> (directory, linked path-dependency names, manifest)."""
    crates: dict[str, tuple[Path, dict[str, Any]]] = {}
    for manifest_path in sorted((rust_root / "crates").glob("*/Cargo.toml")):
        manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
        crates[str(manifest["package"]["name"])] = (manifest_path.parent, manifest)
    graph: dict[str, tuple[Path, list[str], dict[str, Any]]] = {}
    for name, (directory, manifest) in crates.items():
        deps: list[str] = []
        for table in _dependency_tables(manifest):
            for dep_name, spec in table.items():
                if isinstance(spec, dict) and "path" in spec:
                    target = (directory / str(spec["path"])).resolve()
                    for other, (other_dir, _) in crates.items():
                        if other_dir.resolve() == target:
                            deps.append(other)
                elif dep_name in crates:
                    deps.append(dep_name)
        graph[name] = (directory, sorted(set(deps)), manifest)
    return graph


def linked_crates(graph: dict[str, tuple[Path, list[str], dict[str, Any]]], binary_crate: str) -> list[str]:
    seen: list[str] = []
    stack = [binary_crate]
    while stack:
        current = stack.pop()
        if current in seen:
            continue
        seen.append(current)
        stack.extend(graph[current][1])
    return sorted(seen)


def crate_roots(directory: Path, manifest: dict[str, Any], *, binary: bool) -> list[Path]:
    if binary:
        roots = [directory / str(item.get("path", "src/main.rs")) for item in manifest.get("bin", [])]
        return roots or [directory / "src/main.rs"]
    lib = manifest.get("lib", {})
    return [directory / str(lib.get("path", "src/lib.rs"))]
