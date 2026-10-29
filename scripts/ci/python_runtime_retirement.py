"""Verify physical retirement of superseded Python runtime implementations.

This augments the import/capability gate; it does not replace native behavioral
qualification. It rejects retired paths, imports, named implementation copies,
and wheel/sdist remnants without extracting an archive or importing old code.
"""

from __future__ import annotations

import ast
import hashlib
import json
import tarfile
from collections.abc import Callable, Iterator, Mapping, Sequence
from pathlib import Path, PurePosixPath
from zipfile import ZipFile

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 compatibility
    import tomli as tomllib

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


def _dead_code_removal(record: Mapping[str, object]) -> bool:
    """Allow a retirement that deleted dead Python rather than superseding it.

    Most retired modules name the Rust that took their behaviour over. A few
    reached nobody at all, so there is no replacement to name; those still have
    to be recorded here, or their path and digest keep no protection against
    quietly coming back. Such a record declares why it was dead instead.
    """
    if record.get("retirement") != "dead_code":
        return False
    reason = record.get("removal_reason")
    if not isinstance(reason, str) or not reason.strip():
        raise RuntimeError(f"dead code retirement needs a removal reason: {record.get('path')}")
    return True


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
        if not isinstance(replacements, list) or not all(
            isinstance(item, str) and item.startswith("rust/") and ".." not in PurePosixPath(item).parts
            for item in replacements
        ):
            raise RuntimeError(f"native replacement paths are required: {path}")
        if not replacements and not _dead_code_removal(record):
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


def _retired_flag_reads(tree: ast.AST, name: str, flags: set[str]) -> list[str]:
    """Reject environment reads of removed runtime flags (writes stay legal)."""

    def env_base(value: ast.AST) -> bool:
        return (isinstance(value, ast.Name) and value.id == "environ") or (
            isinstance(value, ast.Attribute) and value.attr == "environ"
        )

    failures: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Subscript):
            if env_base(node.value):
                key = node.slice
                if isinstance(key, ast.Constant) and isinstance(key.value, str) and key.value in flags:
                    failures.append(f"{name}:{node.lineno}: reads retired runtime flag {key.value}")
        elif isinstance(node, ast.Call) and node.args:
            function = node.func
            arg = node.args[0]
            if not isinstance(arg, ast.Constant) or not isinstance(arg.value, str) or arg.value not in flags:
                continue
            if (isinstance(function, ast.Name) and function.id == "getenv") or (
                isinstance(function, ast.Attribute) and function.attr in {"getenv", "get"} and env_base(function.value)
            ):
                failures.append(f"{name}:{node.lineno}: reads retired runtime flag {arg.value}")
    return failures


def _source_violations(text: str, name: str, modules: set[str], symbols: set[str], *, shipped: bool) -> list[str]:
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
        elif shipped and isinstance(node, ast.Constant) and isinstance(node.value, str):
            # A shim, a relaunch and a manifest all name their module in a
            # string, which no import graph reaches. A test may name a retired
            # module to prove it is gone, so only shipped source counts.
            for module in sorted(modules):
                if module in node.value:
                    failures.append(f"{name}:{node.lineno}: names retired module {module} in a string")
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


def _removed_runtime_flags(contract: Mapping[str, object]) -> set[str]:
    delta = contract.get("dependency_delta")
    if not isinstance(delta, Mapping):
        return set()
    flags = delta.get("removed_runtime_flags")
    if not isinstance(flags, list) or not all(isinstance(flag, str) and flag for flag in flags):
        raise RuntimeError("dependency_delta.removed_runtime_flags must be a list of strings")
    return set(flags)


def _retired_content_validator(records: list[dict[str, object]], flags: set[str]) -> Callable[[str, bytes], None]:
    modules = {str(record["module"]) for record in records}
    symbols = {symbol for record in records for symbol in record["forbidden_symbols"]}
    digests = {str(record["source_sha256"]) for record in records}
    basenames = {PurePosixPath(str(record["path"])).stem for record in records}

    def check_content(name: str, data: bytes, *, shipped: bool = True) -> None:
        if hashlib.sha256(data).hexdigest() in digests:
            raise RuntimeError(f"copied retired Python implementation: {name}")
        text = data.decode("utf-8-sig")
        if not any(token in text for token in symbols | basenames | flags | {"import"}):
            return
        failures = _source_violations(text, name, modules, symbols, shipped=shipped)
        if flags:
            failures.extend(_retired_flag_reads(ast.parse(text, filename=name), name, flags))
        if failures:
            raise RuntimeError("; ".join(failures))

    return check_content


def _artifact_member_is_shipped(name: str) -> bool:
    """Whether an archive member lands on the import path of an install.

    An sdist also carries `tests`, `ci` and `scripts`, which a wheel never
    installs. Those files may name a retired module on purpose to prove it is
    gone, so they are held to the same rules as the repository copies.
    """
    parts = PurePosixPath(name.replace("\\", "/")).parts
    return not any(part in _SOURCE_ROOTS[1:] for part in parts[:2])


def validate_retired_artifacts(contract: Mapping[str, object], artifacts: Sequence[Path]) -> None:
    """Check package paths and contents once, before expensive source analysis."""
    records = _records(contract)
    basenames = {PurePosixPath(str(record["path"])).stem for record in records}
    bodies = contract.get("retired_bodies", [])
    if not basenames and not bodies:
        return
    check_content = _retired_content_validator(records, _removed_runtime_flags(contract))
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
                check_content(name, data, shipped=_artifact_member_is_shipped(name))
                _check_retired_body_content(name, data, bodies)


def _entry_point_targets(root: Path) -> list[tuple[str, str, str]]:
    """Every declared console script and entry point, as (name, module, attribute)."""
    manifest = root / "pyproject.toml"
    if not manifest.is_file():
        return []
    project = tomllib.loads(manifest.read_text(encoding="utf-8")).get("project")
    if not isinstance(project, Mapping):
        return []
    declared: list[tuple[str, object]] = []
    scripts = project.get("scripts")
    if isinstance(scripts, Mapping):
        declared.extend(scripts.items())
    groups = project.get("entry-points")
    if isinstance(groups, Mapping):
        for group, members in groups.items():
            if isinstance(members, Mapping):
                declared.extend((f"{group}:{member}", target) for member, target in members.items())
    targets: list[tuple[str, str, str]] = []
    for name, target in declared:
        module, separator, attribute = target.partition(":") if isinstance(target, str) else ("", "", "")
        if not separator or not module.strip() or not attribute.strip():
            raise RuntimeError(f"entry point has no module:attribute target: {name}: {target!r}")
        targets.append((str(name), module.strip(), attribute.strip()))
    return targets


def _table(data: object, *keys: str) -> Mapping[str, object] | None:
    for key in keys:
        if not isinstance(data, Mapping):
            return None
        data = data.get(key)
    return data if isinstance(data, Mapping) else None


def _wheel_import_roots(root: Path) -> list[tuple[str, str | None]]:
    """Where an installed import starts, as (directory, packaged top-level name).

    The wheel ships only the packages `pyproject.toml` names, so a module that
    lives under `tests`, `ci` or `scripts` is absent from the install however
    plainly the repository holds it.
    """
    manifest = root / "pyproject.toml"
    packages: object = None
    if manifest.is_file():
        table = tomllib.loads(manifest.read_text(encoding="utf-8"))
        wheel = _table(table, "tool", "hatch", "build", "targets", "wheel")
        packages = wheel.get("packages") if wheel is not None else None
    roots: list[tuple[str, str | None]] = []
    for entry in packages if isinstance(packages, list) else []:
        if not isinstance(entry, str) or not entry:
            continue
        parts = PurePosixPath(entry).parts
        roots.append((PurePosixPath(*parts[:-1]).as_posix() if len(parts) > 1 else "", parts[-1]))
    return roots or [("src", None)]


def _module_source(root: Path, module: str) -> Path | None:
    parts = module.split(".")
    for directory, package in _wheel_import_roots(root):
        if package is not None and parts[0] != package:
            continue
        base = root.joinpath(directory, *parts) if directory else root.joinpath(*parts)
        for candidate in (base.with_suffix(".py"), base / "__init__.py"):
            if candidate.is_file():
                return candidate
    return None


def _declared_names(body: Sequence[ast.stmt]) -> dict[str, ast.stmt]:
    """Every name a block binds at runtime, mapped to the statement that binds it."""
    declared: dict[str, ast.stmt] = {}
    for node in body:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            declared[node.name] = node
        elif isinstance(node, ast.Import | ast.ImportFrom):
            for alias in node.names:
                if alias.name != "*":
                    declared[alias.asname or alias.name.partition(".")[0]] = node
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    declared[target.id] = node
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value is not None:
            declared[node.target.id] = node
    return declared


def _module_binds_beyond_this_read(body: Sequence[ast.stmt]) -> bool:
    """Whether a module answers for names no static read of it can list.

    A module exporting through `__getattr__` or a star import still resolves an
    attribute this gate never sees, so calling that attribute missing would
    reject an entry point the installed command loads. Only a module body
    counts: a class's own `__getattr__` serves its instances, not an attribute
    read off the class itself, so it cannot rescue a stranded target.
    """
    for node in body:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.name == "__getattr__":
            return True
        if isinstance(node, ast.ImportFrom) and any(alias.name == "*" for alias in node.names):
            return True
    return False


def _attribute_resolves(source: str, attribute: str) -> bool:
    """Whether every component of a dotted entry-point attribute still exists."""
    body: Sequence[ast.stmt] = ast.parse(source).body
    module_level = True
    for component in attribute.split("."):
        if module_level and _module_binds_beyond_this_read(body):
            return True
        node = _declared_names(body).get(component)
        if node is None:
            return False
        if not isinstance(node, ast.ClassDef):
            # An imported or assigned name holds a value no static read follows,
            # so whatever hangs below it is out of this gate's reach.
            return True
        if node.bases or node.keywords:
            # A base class or a metaclass supplies attributes from a definition
            # this read never visits, so the rest of the path is unknowable here.
            return True
        body = node.body
        module_level = False
    return True


def validate_entry_point_targets(root: Path, retired_modules: set[str]) -> None:
    """Reject an entry point a retirement left pointing at nothing.

    A console script names its module in a string, so no import graph reaches
    it and no retired-import check sees it. A deletion that takes the module,
    or only the function the script names, therefore ships a wheel whose
    command fails at launch instead of reddening a gate here.
    """
    for name, module, attribute in _entry_point_targets(root):
        if module in retired_modules:
            raise RuntimeError(f"entry point targets a retired module: {name}: {module}")
        source = _module_source(root, module)
        if source is None:
            raise RuntimeError(f"entry point targets a module that does not exist: {name}: {module}")
        if not _attribute_resolves(source.read_text(encoding="utf-8"), attribute):
            raise RuntimeError(f"entry point targets a missing attribute: {name}: {module}:{attribute}")


def _shipped_packages(root: Path) -> set[str]:
    """Top-level package names an installed wheel answers imports for."""
    names: set[str] = set()
    for directory, package in _wheel_import_roots(root):
        if package is not None:
            names.add(package)
            continue
        base = root / directory if directory else root
        if base.is_dir():
            names.update(child.name for child in base.iterdir() if (child / "__init__.py").is_file())
    return names


def _dotted_module_name(value: str) -> bool:
    parts = value.split(".")
    return len(parts) > 1 and all(part.isidentifier() for part in parts)


def _launch_targets(tree: ast.AST, packages: set[str]) -> Iterator[tuple[int, str]]:
    """Module names a `-m` or `-c` launch sequence carries as plain strings.

    A shim, a relaunch and a bootstrap all name their module in an argument
    list rather than in an import, so the import graph never reaches it. The
    module still has to be installed when the command runs.
    """
    for node in ast.walk(tree):
        if isinstance(node, (ast.List, ast.Tuple)):
            elements: Sequence[ast.expr] = node.elts
        elif isinstance(node, ast.Call):
            elements = node.args
        else:
            continue
        literals = [_literal_string(element) for element in elements]
        if not any(literal in {"-m", "-c"} for literal in literals):
            continue
        for element, literal in zip(elements, literals, strict=True):
            if literal is None or not _dotted_module_name(literal):
                continue
            if literal.split(".")[0] in packages:
                yield element.lineno, literal


def validate_launcher_module_targets(root: Path, retired_modules: set[str]) -> None:
    """Reject a `-m` or `-c` launch that names a module the install no longer has.

    Guard relaunches itself through the interpreter in several places. The
    module name travels as an argument string, so a retirement that takes it
    leaves a shim that only fails when a user runs the command.
    """
    directory = root / "src"
    if not directory.is_dir():
        return
    packages = _shipped_packages(root)
    if not packages:
        return
    for path in sorted(directory.rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        if "-m" not in text and "-c" not in text:
            continue
        name = path.relative_to(root).as_posix()
        for lineno, module in _launch_targets(ast.parse(text, filename=name), packages):
            if _matches_module(module, retired_modules):
                raise RuntimeError(f"{name}:{lineno}: launcher runs retired module {module}")
            if _module_source(root, module) is None:
                raise RuntimeError(f"{name}:{lineno}: launcher runs a module that does not exist: {module}")


def _plugin_module_references(data: object) -> Iterator[str]:
    if isinstance(data, Mapping):
        module = data.get("module")
        if data.get("kind") == "python-module" and isinstance(module, str):
            yield module
        for value in data.values():
            yield from _plugin_module_references(value)
    elif isinstance(data, list):
        for value in data:
            yield from _plugin_module_references(value)


def validate_plugin_module_references(root: Path, retired_modules: set[str]) -> None:
    """Reject a contribution whose detector names a module that is not there.

    An extension names its detector module in a manifest string. Nothing
    imports it, so a retirement that takes the module ships a manifest
    pointing at nothing and every gate stays quiet.
    """
    directory = root / "contributions"
    if not directory.is_dir():
        return
    for path in sorted(directory.rglob("*.json")):
        text = path.read_text(encoding="utf-8")
        if "python-module" not in text:
            continue
        name = path.relative_to(root).as_posix()
        for module in _plugin_module_references(json.loads(text)):
            if _matches_module(module, retired_modules):
                raise RuntimeError(f"{name}: contribution names retired module {module}")
            if _module_source(root, module) is None:
                raise RuntimeError(f"{name}: contribution names a module that does not exist: {module}")


def validate_retired_modules(
    root: Path,
    contract: Mapping[str, object],
    *,
    analysis: ImportGraphAnalysis,
    artifacts: Sequence[Path] = (),
) -> list[dict[str, object]]:
    records = _records(contract)
    validate_retired_bodies(root, contract)
    retired = {str(record["module"]) for record in records}
    validate_entry_point_targets(root, retired)
    validate_launcher_module_targets(root, retired)
    validate_plugin_module_references(root, retired)
    retired_tests = contract.get("retired_test_paths", [])
    if not isinstance(retired_tests, list):
        raise RuntimeError("retired_test_paths must be a list")
    for value in retired_tests:
        path = _relative_path(value, source=False)
        if (root / path).exists() or (root / path).is_symlink():
            raise RuntimeError(f"retired implementation test still exists: {path}")
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

    flags = _removed_runtime_flags(contract)
    basenames = {PurePosixPath(str(record["path"])).stem for record in records}
    check_content = _retired_content_validator(records, flags)

    for directory in _SOURCE_ROOTS:
        for path in sorted((root / directory).rglob("*.py")):
            if path.stem in basenames:
                raise RuntimeError(f"retired module name reappeared: {path.relative_to(root).as_posix()}")
            check_content(path.relative_to(root).as_posix(), path.read_bytes(), shipped=directory == "src")
    validate_retired_artifacts(contract, artifacts)
    return evidence


def validate_retired_bodies(root: Path, contract: Mapping[str, object]) -> None:
    """Allow a public DTO facade while rejecting its original implementation."""
    records = contract.get("retired_bodies", [])
    if not isinstance(records, list):
        raise RuntimeError("retired_bodies must be a list")
    seen: set[str] = set()
    for record in records:
        if not isinstance(record, dict):
            raise RuntimeError("retired body record must be an object")
        path = _relative_path(record.get("path"), source=True)
        symbols = record.get("forbidden_symbols")
        replacements = record.get("native_replacements")
        if path in seen or not _sha256(record.get("source_sha256")):
            raise RuntimeError(f"invalid retired body identity: {path}")
        if (
            not isinstance(symbols, list)
            or not symbols
            or not all(isinstance(s, str) and s.isidentifier() for s in symbols)
        ):
            raise RuntimeError(f"retired body symbols required: {path}")
        if (
            not isinstance(replacements, list)
            or not replacements
            or not all(
                isinstance(p, str)
                and p.startswith("rust/")
                and ".." not in PurePosixPath(p).parts
                and (root / p).is_file()
                for p in replacements
            )
        ):
            raise RuntimeError(f"retired body native replacement missing: {path}")
        seen.add(path)
        _check_retired_body_content(path, (root / path).read_bytes(), records)


def _check_retired_body_content(name: str, source: bytes, records: object) -> None:
    if not isinstance(records, list):
        raise RuntimeError("retired_bodies must be a list")
    digest = hashlib.sha256(source).hexdigest()
    for record in records:
        if not isinstance(record, dict) or not _sha256(record.get("source_sha256")):
            raise RuntimeError("invalid retired body record")
        if digest == record["source_sha256"]:
            raise RuntimeError(f"retired Python body still exists: {name}")
        if PurePosixPath(name).name != PurePosixPath(str(record.get("path"))).name:
            continue
        tree = ast.parse(source)
        identifiers = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
        identifiers.update(
            node.name
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
        )
        if identifiers.intersection(record.get("forbidden_symbols", [])):
            raise RuntimeError(f"retired Python implementation symbol still exists: {name}")
