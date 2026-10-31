"""Packaging metadata names only the tools, groups and inputs this tree still has.

A retirement deletes an implementation and the distribution it imported, but
the build requirement that installed it, the extra that selected it, the
resolver pin that held its transitive version and the packaging path that
shipped its data all survive in `pyproject.toml`. Each one keeps costing every
build and every install. `test_runtime_dependency_use.py` reads
`[project.dependencies]` against the shipped source; this gate reads the rest of
the packaging metadata and refuses an entry whose consumer is gone.
"""

from __future__ import annotations

import ast
import importlib
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = ROOT / "src"
SCRIPT_ROOT = ROOT / "scripts"
PACKAGE = "codex_plugin_scanner"
BUILD_HOOK = "build_command_projection_hook"

# Distributions whose import name is not the distribution name. A build
# requirement is matched against what the build actually imports, and PyYAML
# installs as `pyyaml` but imports as `yaml`.
IMPORT_NAMES = {
    "pyyaml": ("yaml",),
    "typing-extensions": ("typing_extensions",),
}

tomllib = importlib.import_module("tomllib" if sys.version_info >= (3, 11) else "tomli")

# uv installs `dependency-groups.dev` unless a caller opts out, so no command
# names it the way every other group is named.
DEFAULT_GROUP = "dev"

# Where a selection would be written: the workflows, actions and scripts that
# build an environment for a job.
SELECTION_ROOTS = (".github", "scripts", "ci")


def _metadata() -> dict[str, object]:
    return tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def _distribution(requirement: str) -> str:
    """The distribution name at the front of a PEP 508 requirement."""
    name = requirement.split(";", 1)[0]
    for separator in ("[", "=", "<", ">", "!", "~", " "):
        name = name.split(separator, 1)[0]
    return name.strip().lower().replace("_", "-")


def _runtime_imports(tree: ast.Module) -> list[ast.Import | ast.ImportFrom]:
    """Every import this file performs when it runs.

    An import inside `if TYPE_CHECKING:` is never executed, so the
    distribution behind it is not installed by running this file and the
    package module behind it is not reached. The `else` branch of such a test
    is the one that runs, so it is still read.
    """

    found: list[ast.Import | ast.ImportFrom] = []

    class Visitor(ast.NodeVisitor):
        def visit_If(self, node: ast.If) -> None:
            test = node.test
            type_checking = (isinstance(test, ast.Name) and test.id == "TYPE_CHECKING") or (
                isinstance(test, ast.Attribute)
                and isinstance(test.value, ast.Name)
                and test.value.id == "typing"
                and test.attr == "TYPE_CHECKING"
            )
            if type_checking:
                for child in node.orelse:
                    self.visit(child)
                return
            self.generic_visit(node)

        def visit_Import(self, node: ast.Import) -> None:
            found.append(node)

        def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
            found.append(node)

    Visitor().visit(tree)
    return found


def _top_level_imports(tree: ast.Module) -> set[str]:
    """Every top-level module name this file imports by name."""
    names: set[str] = set()
    for node in _runtime_imports(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names.add(node.module.split(".", 1)[0])
    return names


def _package_imports(tree: ast.Module, *, package: str = "") -> set[str]:
    """Every `codex_plugin_scanner` module this file names, submodules included.

    `package` is the importing module's own package, which a relative import
    inside the shipped source is resolved against; a script beside the hook has
    none and names its package imports in full.
    """
    names: set[str] = set()
    for node in _runtime_imports(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names if alias.name.startswith(PACKAGE))
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if node.level:
                parts = package.split(".") if package else []
                if node.level > len(parts):
                    continue
                prefix = parts[: len(parts) - node.level + 1]
                module = ".".join([*prefix, module] if module else prefix)
            if not module.startswith(PACKAGE):
                continue
            names.add(module)
            # `from package.module import name` may name a submodule, not an object.
            names.update(f"{module}.{alias.name}" for alias in node.names)
    return names


def _source_for(module: str) -> Path | None:
    """The file a `codex_plugin_scanner` module name resolves to, if any."""
    relative = module.replace(".", "/")
    for candidate in (SOURCE_ROOT / f"{relative}.py", SOURCE_ROOT / relative / "__init__.py"):
        if candidate.is_file():
            return candidate
    return None


def _build_hook_scripts() -> set[str]:
    """The scripts the wheel's build hook reaches, directly or by loading them."""
    reached: set[str] = set()
    pending = [BUILD_HOOK]
    while pending:
        name = pending.pop()
        if name in reached:
            continue
        path = SCRIPT_ROOT / f"{name}.py"
        if not path.is_file():
            continue
        reached.add(name)
        text = path.read_text(encoding="utf-8")
        tree = ast.parse(text, filename=str(path))
        pending.extend(module for module in _top_level_imports(tree) if (SCRIPT_ROOT / f"{module}.py").is_file())
        # The hook loads support modules by name and runs others as a subprocess.
        pending.extend(match.group(1) for match in re.finditer(r'_support\("([^"]+)"\)', text))
        pending.extend(match.group(1) for match in re.finditer(r'"scripts/([a-z_]+)\.py"', text))
    return reached


def _build_time_modules() -> set[str]:
    """Every distribution module imported while hatchling builds the wheel.

    The hook imports its backend, loads support scripts beside itself and, in
    turn, reads frozen projections through the package's own delivery modules.
    A requirement is paid for at build time only if something on that path
    imports it.
    """
    modules: set[str] = set()
    packages: list[str] = []
    for name in _build_hook_scripts():
        tree = ast.parse((SCRIPT_ROOT / f"{name}.py").read_text(encoding="utf-8"))
        modules.update(_top_level_imports(tree))
        packages.extend(_package_imports(tree))
    seen: set[str] = set()
    while packages:
        module = packages.pop()
        if module in seen:
            continue
        seen.add(module)
        source = _source_for(module)
        if source is None:
            continue
        tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
        modules.update(_top_level_imports(tree))
        # A relative import resolves against the importing module's package, so
        # `__init__.py` is its own package and every other file is its parent.
        own = module if source.name == "__init__.py" else module.rpartition(".")[0]
        packages.extend(_package_imports(tree, package=own))
    return modules


def _selection_text() -> str:
    """Everything that could name an extra or a group while installing one."""
    parts: list[str] = []
    for root in SELECTION_ROOTS:
        for path in (ROOT / root).rglob("*"):
            if path.is_file() and path.suffix in {".yml", ".yaml", ".sh", ".py", ".toml", ""}:
                parts.append(path.read_text(encoding="utf-8", errors="ignore"))
    return "\n".join(parts)


def _unused_requirements(requires: list[str], imported: set[str]) -> list[str]:
    """The distributions among `requires` that nothing in `imported` accounts for."""
    return sorted(
        name
        for name in requires
        if not any(module in imported for module in IMPORT_NAMES.get(name, (name.replace("-", "_"),)))
    )


def test_every_build_requirement_is_imported_while_the_wheel_is_built() -> None:
    """Verify every build requirement is imported while the wheel is built."""
    imported = _build_time_modules()
    metadata = _metadata()
    requires = [_distribution(entry) for entry in metadata["build-system"]["requires"]]
    unused = _unused_requirements(requires, imported)
    assert not unused, (
        "These build requirements are installed into every build environment but nothing the build hook "
        f"reaches imports them: {unused}. Retire the requirement with the code that needed it."
    )


def test_the_build_requirement_gate_reads_through_the_package_the_hook_imports() -> None:
    """`jsonschema` is reached only through the delivery modules, so the walk must see it."""
    assert {"hatchling", "jsonschema"} <= _build_time_modules()


def test_a_requirement_whose_import_name_differs_is_matched_by_its_import_name() -> None:
    """A distribution name is not an import name, so the gate maps the ones that differ."""
    assert _unused_requirements(["pyyaml"], {"yaml"}) == []
    assert _unused_requirements(["pyyaml"], {"pyyaml"}) == ["pyyaml"]
    assert _unused_requirements(["hatchling"], {"hatchling"}) == []


def test_an_import_that_only_type_checking_performs_is_not_a_build_time_import() -> None:
    """A requirement reached only under `if TYPE_CHECKING:` is never installed by the build.

    The same holds for the package closure: a module named only in a type-only
    import is not reached at build time, so whatever it imports is not paid for
    either. The `else` branch of such a test is what actually runs.
    """

    tree = ast.parse(
        "from typing import TYPE_CHECKING\n"
        "if TYPE_CHECKING:\n"
        "    import tomlkit\n"
        f"    from {PACKAGE}.guard import models\n"
        "else:\n"
        "    import json\n"
        "if typing.TYPE_CHECKING:\n"
        "    import keyring\n"
        "import ast\n"
    )
    assert _top_level_imports(tree) == {"typing", "json", "ast"}
    assert _package_imports(tree) == set()


def _selects(name: str, flag: str, text: str) -> bool:
    """Whether this text selects `name` the way an installer reads it.

    The name has to stand as the whole argument of its own selection flag, or
    inside the extras bracket of a requirement spelling. A bare quoted word is
    not a selection: `"dev"` and `"publish"` are also an argparse choice and a
    dictionary key under `scripts/`, so counting those would let the last job
    that installed an extra be deleted while the extra stayed declared.
    """

    escaped = re.escape(name)
    if re.search(rf"{flag}[= ]{escaped}(?![\w.-])", text):
        return True
    # `hol-guard[cisco]`, `.[dev,publish]`: the extras bracket of a spec.
    return flag == "--extra" and bool(re.search(rf"\[(?:[\w.-]+,\s*)*{escaped}(?:\s*,\s*[\w.-]+)*\]", text))


def test_every_extra_and_group_is_selected_by_something_that_installs_it() -> None:
    """Verify every extra and dependency group is selected by something that installs it."""
    metadata = _metadata()
    text = _selection_text()
    unselected = sorted(
        name for name in metadata["project"]["optional-dependencies"] if not _selects(name, "--extra", text)
    )
    assert not unselected, (
        f"These extras are declared but no workflow, action or script selects them: {unselected}. "
        "Remove the extra, or restore the job that installed it."
    )
    groups = sorted(
        name for name in metadata["dependency-groups"] if name != DEFAULT_GROUP and not _selects(name, "--group", text)
    )
    assert not groups, (
        f"These dependency groups are declared but no workflow, action or script selects them: {groups}. "
        "Remove the group, or restore the job that installed it."
    )


def test_a_name_that_merely_appears_somewhere_is_not_a_selection() -> None:
    """The gate reads selection syntax, not any occurrence of the name.

    Every declared extra is an ordinary English word that `scripts/` and `ci/`
    also use as a dictionary key, an argparse choice or a path segment. If one
    of those counted, retiring the last job that installed an extra would leave
    the gate green and the extra declared.
    """

    quoted = "\n".join(('choices=["publish", "dev"]', '{"cisco": 1}', 'path = "dev/publish"'))
    for name in ("publish", "dev", "cisco"):
        assert not _selects(name, "--extra", quoted), name
        assert not _selects(name, "--group", quoted), name
    assert _selects("publish", "--extra", "uv sync --frozen --extra publish --python 3.12")
    assert _selects("ci-test", "--group", "uv sync --no-dev --group ci-test")
    assert _selects("cisco", "--extra", "uv tool install 'hol-guard[cisco]'")
    # A longer name that merely starts with this one is a different selection.
    assert not _selects("dev", "--extra", "uv sync --extra dev-tools")
    assert not _selects("cisco", "--group", "uv sync --group cisco-mcp")


def test_every_resolver_override_still_has_a_package_to_override() -> None:
    """Verify every resolver override still names a package the lock resolves."""
    metadata = _metadata()
    locked = {
        name.lower().replace("_", "-")
        for name in re.findall(r'^name = "([^"]+)"', (ROOT / "uv.lock").read_text(encoding="utf-8"), re.M)
    }
    overrides = metadata["tool"]["uv"]["override-dependencies"]
    orphaned = sorted({_distribution(entry) for entry in overrides} - locked)
    assert not orphaned, (
        "These resolver overrides pin a version for a distribution the lock no longer resolves: "
        f"{orphaned}. The pin reaches nothing; remove it with the dependency that pulled it in."
    )


def test_every_packaged_input_still_exists() -> None:
    """Verify every path the wheel and the source archive name still exists.

    `exclude` is deliberately defensive and may name a directory a developer
    only sometimes has, so it is not read here. The paths that are read are the
    ones a build selects, copies or renames: a missing one means the archive
    silently stops carrying something.
    """
    build = _metadata()["tool"]["hatch"]["build"]
    missing: list[str] = []
    for entry in build["targets"]["sdist"]["only-include"]:
        if not (ROOT / entry).exists():
            missing.append(f"sdist only-include: {entry}")
    for entry in build["artifacts"]:
        if not (ROOT / entry.removesuffix("/**")).exists():
            missing.append(f"artifacts: {entry}")
    for target in ("wheel", "sdist"):
        for entry in build["targets"][target]["force-include"]:
            if not (ROOT / entry).exists():
                missing.append(f"{target} force-include: {entry}")
    assert not missing, (
        f"These packaging inputs no longer exist, so the build no longer carries them: {missing}. "
        "Remove the entry with the code that produced it, or restore the input."
    )


def test_every_mutation_target_path_still_exists() -> None:
    """Verify the mutation gate still names source and support paths that exist."""
    mutmut = _metadata()["tool"]["mutmut"]
    missing = sorted(
        f"{key}: {entry}"
        for key in ("source_paths", "also_copy", "pytest_add_cli_args_test_selection")
        for entry in mutmut[key]
        if not (ROOT / entry).exists()
    )
    assert not missing, (
        f"The mutation gate names paths this tree no longer has: {missing}. "
        "Point the gate at what replaced them, or drop the entry."
    )


def _module_level_names(tree: ast.Module) -> set[str]:
    """Every name this module binds at its top level.

    An entry point may be defined here, assigned here or re-exported from
    another module, and all three are importable as `module:attribute`.
    """
    names: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            names.add(node.name)
        elif isinstance(node, ast.Assign):
            names.update(target.id for target in node.targets if isinstance(target, ast.Name))
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            names.add(node.target.id)
        elif isinstance(node, ast.Import | ast.ImportFrom):
            names.update(alias.asname or alias.name.split(".", 1)[0] for alias in node.names)
    return names


def test_every_console_script_names_an_entry_point_the_package_still_has() -> None:
    """Verify each installed command resolves to a module and attribute that exist.

    A console script is written into every install's `bin/`. When the module it
    names is renamed or its entry function is retired, nothing fails until a
    user runs the command, so the break reaches the install rather than the
    build. Read the target here instead.
    """
    broken: list[str] = []
    for command, target in _metadata()["project"]["scripts"].items():
        module, _, attribute = target.partition(":")
        source = _source_for(module)
        if source is None:
            broken.append(f"{command} = {target}: no module")
            continue
        tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
        if attribute not in _module_level_names(tree):
            broken.append(f"{command} = {target}: {source.relative_to(ROOT)} defines no {attribute}")
    assert not broken, (
        f"These installed commands name an entry point the package no longer has: {broken}. "
        "Point the script at what replaced it, or remove the command with the code behind it."
    )
