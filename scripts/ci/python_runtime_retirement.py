"""Verify physical retirement of superseded Python runtime implementations.

This augments the import/capability gate; it does not replace native behavioral
qualification. It rejects retired paths, imports, named implementation copies,
and wheel/sdist remnants without extracting an archive or importing old code.
"""

from __future__ import annotations

import ast
import hashlib
import tarfile
from collections.abc import Iterator, Mapping, Sequence
from pathlib import Path, PurePosixPath
from zipfile import ZipFile

from scripts.ci.python_capability_cleanup_analysis import ImportGraphAnalysis, production_importers

_SOURCE_ROOTS = ("src", "tests", "ci", "scripts")


def _sha256(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(char in "0123456789abcdef" for char in value)


def _relative_path(value: object, *, source: bool) -> str:
    if not isinstance(value, str) or "\\" in value:
        raise RuntimeError("retirement path must be a repository-relative POSIX path")
    path = PurePosixPath(value)
    roots = ("src",) if source else ("tests", "ci")
    if path.is_absolute() or ".." in path.parts or not path.parts or path.parts[0] not in roots:
        raise RuntimeError(f"invalid retirement path: {value}")
    if path.as_posix() != value or path.suffix != ".py":
        raise RuntimeError(f"invalid retirement Python path: {value}")
    return value


def _records(contract: Mapping[str, object]) -> list[dict[str, object]]:
    records = contract.get("retired_modules", [])
    if not isinstance(records, list):
        raise RuntimeError("retired_modules must be a list")
    checked: list[dict[str, object]] = []
    paths: set[str] = set()
    modules: set[str] = set()
    for record in records:
        if not isinstance(record, dict):
            raise RuntimeError("retired module records must be objects")
        path = _relative_path(record.get("path"), source=True)
        module = ".".join(PurePosixPath(path).with_suffix("").parts[1:])
        if record.get("module") != module or path in paths or module in modules:
            raise RuntimeError(f"duplicate or inconsistent retired module identity: {path}")
        if not _sha256(record.get("source_sha256")):
            raise RuntimeError(f"retired source digest is required: {path}")
        symbols = record.get("forbidden_symbols")
        if (
            not isinstance(symbols, list)
            or not symbols
            or not all(isinstance(symbol, str) and symbol.isidentifier() for symbol in symbols)
        ):
            raise RuntimeError(f"retired implementation symbols are required: {path}")
        replacements = record.get("native_replacements")
        if (
            not isinstance(replacements, list)
            or not replacements
            or not all(
                isinstance(item, str) and item.startswith("rust/") and ".." not in PurePosixPath(item).parts
                for item in replacements
            )
        ):
            raise RuntimeError(f"native replacement paths are required: {path}")
        paths.add(path)
        modules.add(module)
        checked.append(record)
    return checked


def _matches_module(value: str, modules: set[str]) -> bool:
    return any(value == module or value.startswith(module + ".") for module in modules)


def _literal_string(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _literal_string(node.left), _literal_string(node.right)
        if left is not None and right is not None and len(left) + len(right) <= 256:
            return left + right
    return None


def _source_violations(text: str, name: str, modules: set[str], symbols: set[str]) -> list[str]:
    tree = ast.parse(text, filename=name)
    parts = list(PurePosixPath(name).with_suffix("").parts)
    if parts and parts[0] == "src":
        parts.pop(0)
    if parts and parts[-1] == "__init__":
        parts.pop()
    else:
        parts = parts[:-1]
    failures: list[str] = []
    dynamic_aliases = {"import_module", "__import__"}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module in {"importlib", "builtins"}:
            expected = "import_module" if node.module == "importlib" else "__import__"
            dynamic_aliases.update(alias.asname or alias.name for alias in node.names if alias.name == expected)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.name in symbols:
            failures.append(f"{name}:{node.lineno}: retired implementation symbol {node.name}")
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if _matches_module(alias.name, modules):
                    failures.append(f"{name}:{node.lineno}: imports retired module {alias.name}")
        elif isinstance(node, ast.ImportFrom):
            prefix = parts[: len(parts) - node.level + 1] if node.level else []
            if node.module:
                prefix += node.module.split(".")
            target = ".".join(prefix)
            for alias in node.names:
                imported = target + "." + alias.name if target else alias.name
                if _matches_module(target, modules) or _matches_module(imported, modules):
                    failures.append(f"{name}:{node.lineno}: imports retired module {imported}")
        elif isinstance(node, ast.Call) and node.args:
            function = node.func
            dynamic = (isinstance(function, ast.Name) and function.id in dynamic_aliases) or (
                isinstance(function, ast.Attribute) and function.attr in {"import_module", "__import__"}
            )
            target = _literal_string(node.args[0]) if dynamic else None
            if target is not None and _matches_module(target, modules):
                failures.append(f"{name}:{node.lineno}: dynamically imports retired module {target}")
    return failures


def _artifact_members(artifact: Path) -> Iterator[tuple[str, bytes | None]]:
    if artifact.name.endswith(".whl"):
        with ZipFile(artifact) as archive:
            for member in archive.infolist():
                if member.is_dir():
                    continue
                yield member.filename, archive.read(member) if member.filename.endswith(".py") else None
        return
    if artifact.name.endswith(".tar.gz"):
        with tarfile.open(artifact, "r:gz") as archive:
            for member in archive:
                # Never follow archive links, including links to a deleted module.
                if member.issym() or member.islnk():
                    yield member.name, None
                    yield member.linkname, None
                if not member.isfile():
                    continue
                data = None
                if member.name.endswith(".py"):
                    stream = archive.extractfile(member)
                    if stream is None:
                        raise RuntimeError(f"cannot read package member: {member.name}")
                    with stream:
                        data = stream.read()
                yield member.name, data
        return
    raise RuntimeError(f"unsupported package artifact: {artifact}")


def validate_retired_modules(
    root: Path,
    contract: Mapping[str, object],
    *,
    analysis: ImportGraphAnalysis,
    artifacts: Sequence[Path] = (),
) -> list[dict[str, object]]:
    records = _records(contract)
    retired_tests = contract.get("retired_test_paths", [])
    if not isinstance(retired_tests, list):
        raise RuntimeError("retired_test_paths must be a list")
    for value in retired_tests:
        path = _relative_path(value, source=False)
        if (root / path).exists() or (root / path).is_symlink():
            raise RuntimeError(f"retired implementation test still exists: {path}")
    modules = {str(record["module"]) for record in records}
    symbols = {symbol for record in records for symbol in record["forbidden_symbols"]}
    digests = {str(record["source_sha256"]) for record in records}
    basenames = {PurePosixPath(str(record["path"])).stem for record in records}
    evidence: list[dict[str, object]] = []
    for record in records:
        relative = str(record["path"])
        path = root / relative
        if path.exists() or path.is_symlink():
            raise RuntimeError(f"retired Python source still exists: {relative}")
        for replacement in record["native_replacements"]:
            if not (root / replacement).is_file():
                raise RuntimeError(f"native replacement is missing: {replacement}")
        importers = production_importers(root, str(record["module"]), analysis=analysis)
        if importers:
            raise RuntimeError(f"retired module still has source import reachability: {relative}: {importers}")
        evidence.append({"path": relative, "module": record["module"], "source_present": False, "source_importers": []})
    if not records:
        return evidence

    def check_content(name: str, data: bytes) -> None:
        if hashlib.sha256(data).hexdigest() in digests:
            raise RuntimeError(f"copied retired Python implementation: {name}")
        text = data.decode("utf-8-sig")
        if not any(token in text for token in symbols | basenames | {"import"}):
            return
        failures = _source_violations(text, name, modules, symbols)
        if failures:
            raise RuntimeError("; ".join(failures))

    for directory in _SOURCE_ROOTS:
        for path in sorted((root / directory).rglob("*.py")):
            check_content(path.relative_to(root).as_posix(), path.read_bytes())
    for artifact in artifacts:
        for name, data in _artifact_members(artifact):
            basename = PurePosixPath(name.replace("\\", "/")).name
            if any(
                basename == stem + ".py"
                or basename == stem + ".pyc"
                or (basename.startswith(stem + ".") and basename.endswith(".pyc"))
                for stem in basenames
            ):
                raise RuntimeError(f"package artifact contains retired module: {name}")
            if data is not None:
                check_content(name, data)
    return evidence
