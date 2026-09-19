"""Run the retained source contract partitions with explicit checked-in roots."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
_ROOTS_PATH = _ROOT / "scripts/ci/policy_source_contract_roots.json"


@dataclass(frozen=True)
class SourceGroup:
    name: str
    partition: str
    selectors: list[str]


@dataclass(frozen=True)
class Configuration:
    original_roots: list[str]
    additional_roots: list[str]
    style_roots: list[str]
    groups: list[SourceGroup]
    policy_selectors: list[str]
    imports: list[str]


def _strings(value: object, label: str) -> list[str]:
    if not isinstance(value, list) or not value or any(not isinstance(item, str) for item in value):
        raise ValueError(f"Invalid source contract {label}")
    result = [str(item) for item in value]
    if len(result) != len(set(result)):
        raise ValueError(f"Duplicate source contract {label}")
    return result


def _source_file(value: str) -> None:
    path = Path(value)
    if (
        path.is_absolute()
        or ".." in path.parts
        or not path.parts
        or path.parts[0]
        not in {
            "src",
            "tests",
            "scripts",
            "ci",
        }
    ):
        raise ValueError(f"Invalid source contract path: {value}")
    selected = _ROOT / path
    if selected.suffix != ".py" or selected.is_symlink() or not selected.is_file():
        raise ValueError(f"Missing regular source contract file: {value}")
    if not selected.resolve(strict=True).is_relative_to(_ROOT):
        raise ValueError(f"Source contract path escaped the checkout: {value}")


def _selector(value: str) -> None:
    path, *names = value.split("::")
    _source_file(path)
    if any(not name.isidentifier() for name in names):
        raise ValueError(f"Invalid source contract selector: {value}")


def _configuration() -> Configuration:
    payload = json.loads(_ROOTS_PATH.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or payload.get("schema") != "hol-guard.policy-source-contract.v1":
        raise ValueError("Invalid source contract root inventory")
    original = _strings(payload.get("original_type_roots"), "original roots")
    additional = _strings(payload.get("additional_type_roots"), "additional roots")
    style = _strings(payload.get("additional_style_roots"), "style roots")
    policy = _strings(payload.get("policy_noconftest"), "policy selectors")
    imports = _strings(payload.get("import_modules"), "imports")
    raw_groups = payload.get("source_groups")
    if not isinstance(raw_groups, list) or not raw_groups:
        raise ValueError("Missing source contract groups")
    groups: list[SourceGroup] = []
    names: set[str] = set()
    for raw in raw_groups:
        if not isinstance(raw, dict):
            raise ValueError("Invalid source contract group")
        name = raw.get("id")
        partition = raw.get("partition")
        if not isinstance(name, str) or not name.startswith("source-") or name in names:
            raise ValueError("Invalid or duplicate source contract group name")
        if partition not in {"policy", "maintenance"}:
            raise ValueError("Invalid source contract partition")
        selectors = _strings(raw.get("selectors"), "group selectors")
        groups.append(SourceGroup(name, str(partition), selectors))
        names.add(name)
    for path in (*original, *additional, *style):
        _source_file(path)
    for selected in (*policy, *(item for group in groups for item in group.selectors)):
        _selector(selected)
    if any(
        not module.startswith("codex_plugin_scanner.guard.")
        or not module.removeprefix("codex_plugin_scanner.guard.").isidentifier()
        for module in imports
    ):
        raise ValueError("Invalid source contract import")
    return Configuration(original, additional, style, groups, policy, imports)


def _unique(values: Sequence[str]) -> list[str]:
    return list(dict.fromkeys(values))


def _run(name: str, argv: Sequence[str]) -> int:
    print(json.dumps({"sourceContractCheck": name, "started": True}), flush=True)
    result = subprocess.run(argv, cwd=_ROOT, check=False)
    print(json.dumps({"sourceContractCheck": name, "exit": result.returncode}), flush=True)
    return result.returncode


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("python_version", choices=("3.10", "3.12"))
    parser.add_argument("partition", choices=("policy", "maintenance"))
    arguments = parser.parse_args()
    actual_version = f"{sys.version_info.major}.{sys.version_info.minor}"
    if actual_version != arguments.python_version or Path(sys.prefix).resolve() != _ROOT / ".venv":
        raise RuntimeError("Source contract interpreter does not match its matrix entry")
    configuration = _configuration()
    commands: list[tuple[str, list[str]]] = []
    uv = ["uv", "run", "--no-sync"]
    if arguments.partition == "policy":
        non_source_roots = [path for path in configuration.original_roots if not path.startswith("src/")]
        # Existing src-wide CI owns the original Python 3.10 production check.
        # Retain the explicit production roots under the Python 3.12 language.
        type_roots = configuration.original_roots if arguments.python_version == "3.12" else non_source_roots
        type_roots = _unique([*type_roots, *configuration.additional_roots])
        style_roots = _unique([*non_source_roots, *configuration.additional_roots, *configuration.style_roots])
        source_import = "from codex_plugin_scanner.guard import " + ", ".join(
            module.rsplit(".", 1)[-1] for module in configuration.imports
        )
        commands.extend(
            [
                ("ruff", [*uv, "ruff", "check", *style_roots]),
                ("format", [*uv, "ruff", "format", "--check", *style_roots]),
                (
                    "types",
                    [
                        *uv,
                        "basedpyright",
                        "--pythonpath",
                        ".venv/bin/python",
                        "--pythonversion",
                        arguments.python_version,
                        *type_roots,
                    ],
                ),
                ("imports", [*uv, "python", "-c", source_import]),
            ]
        )
    for group in configuration.groups:
        if group.partition == arguments.partition:
            commands.append((group.name, [*uv, "pytest", "-q", *group.selectors]))
    if arguments.partition == "policy":
        commands.append(("policy-noconftest", [*uv, "pytest", "--noconftest", *configuration.policy_selectors, "-q"]))
    first_failure = 0
    for name, argv in commands:
        code = _run(name, argv)
        if code != 0 and first_failure == 0:
            first_failure = code
    return first_failure


if __name__ == "__main__":
    raise SystemExit(main())
