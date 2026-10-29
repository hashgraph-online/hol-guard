"""Every shipped runtime dependency is one the shipped source actually imports.

A retirement that moves work into the native runtime deletes the Python that
imported a distribution, but the requirement survives in `[project.dependencies]`
and keeps reaching every install. This gate reads the declared requirements and
the imports under `src/` and refuses a runtime dependency nothing shipped uses.
"""

from __future__ import annotations

import ast
import importlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = ROOT / "src"

tomllib = importlib.import_module("tomllib" if sys.version_info >= (3, 11) else "tomli")

# Distributions whose import name is not the distribution name.
IMPORT_NAMES = {
    "pyyaml": ("yaml",),
    "typing-extensions": ("typing_extensions",),
}


def _distribution(requirement: str) -> str:
    """The distribution name at the front of a PEP 508 requirement."""
    name = requirement.split(";", 1)[0]
    for separator in ("[", "=", "<", ">", "!", "~", " "):
        name = name.split(separator, 1)[0]
    return name.strip().lower().replace("_", "-")


def _declared_runtime_distributions() -> set[str]:
    payload = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    return {_distribution(entry) for entry in payload["project"]["dependencies"]}


def _dynamic_import_names(call: ast.Call) -> set[str]:
    """Module names a dynamic import call names as plain strings."""
    function = call.func
    name = function.attr if isinstance(function, ast.Attribute) else getattr(function, "id", "")
    if name not in {"import_module", "__import__"}:
        return set()
    names: set[str] = set()
    for argument in call.args:
        # `import_module("tomllib" if ... else "tomli")` names both branches.
        for node in ast.walk(argument):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                names.add(node.value)
    return names


def _imported_top_level_modules() -> set[str]:
    modules: set[str] = set()
    for path in SOURCE_ROOT.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                modules.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                modules.add(node.module.split(".", 1)[0])
            elif isinstance(node, ast.Call):
                modules.update(name.split(".", 1)[0] for name in _dynamic_import_names(node))
    return modules


def test_every_runtime_dependency_is_imported_by_the_shipped_source() -> None:
    imported = _imported_top_level_modules()
    unused = sorted(
        distribution
        for distribution in _declared_runtime_distributions()
        if not any(name in imported for name in IMPORT_NAMES.get(distribution, (distribution.replace("-", "_"),)))
    )
    assert not unused, (
        "These runtime dependencies reach every install but nothing under src/ imports them: "
        f"{unused}. Retire the requirement with the code, or move it to the group that still needs it."
    )


def test_a_dependency_reached_only_through_a_dynamic_import_still_counts() -> None:
    """`tomli` is imported by name on Python 3.10, so the gate must see it."""
    assert "tomli" in _imported_top_level_modules()
