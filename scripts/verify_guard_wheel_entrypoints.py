"""Verify the Guard release wheel's console script contract."""

from __future__ import annotations

import ast
import sys
from configparser import ConfigParser
from pathlib import Path
from zipfile import ZipFile

EXPECTED_SCRIPTS = {
    "hol-guard": "codex_plugin_scanner.cli:main",
    "plugin-guard": "codex_plugin_scanner.cli:main",
    "hol-guard-eval": "codex_plugin_scanner.guard.evaluation_cli:main",
}


def verify(directory: Path) -> None:
    wheels = list(directory.glob("hol_guard-*.whl"))
    if len(wheels) != 1:
        raise ValueError(f"Expected one Guard wheel, found {len(wheels)}")

    with ZipFile(wheels[0]) as wheel:
        metadata = [name for name in wheel.namelist() if name.endswith(".dist-info/entry_points.txt")]
        if len(metadata) != 1:
            raise ValueError("Expected one Guard entry_points.txt")

        parser = ConfigParser(interpolation=None)
        parser.read_string(wheel.read(metadata[0]).decode("utf-8"))
        actual = dict(parser.items("console_scripts"))
        if actual != EXPECTED_SCRIPTS:
            raise ValueError(f"Guard wheel scripts differ: {actual!r}")

        for target in set(EXPECTED_SCRIPTS.values()):
            module, function = target.split(":", 1)
            module_path = module.replace(".", "/") + ".py"
            source = ast.parse(wheel.read(module_path), filename=module_path)
            if not any(
                isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == function
                for node in source.body
            ):
                raise ValueError(f"Guard wheel is missing {target}")


if __name__ == "__main__":
    verify(Path(sys.argv[1]))
