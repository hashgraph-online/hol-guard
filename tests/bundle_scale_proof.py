"""Executable real-source packaging fixture; runs no Cargo and edits no checkout.

Run with the repository Python, --core-tree pointing at a stable core worker
checkout, --compiler at its exact-source executable, and a fresh --output path.
Each requested --scale creates an independent external source snapshot, builds
an actual pure wheel and sdist, then rebuilds the wheel from the frozen sdist
with an unavailable compiler. Native wheel assembly remains a parent gate.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")


def snapshot(source, core, destination, scale):
    destination.mkdir(parents=True)
    ignore = shutil.ignore_patterns("__pycache__", "*.pyc", "target", "node_modules", ".DS_Store")
    for name in ("src", "scripts", "contracts", "contributions", "tests/fixtures"):
        shutil.copytree(source / name, destination / name, ignore=ignore)
    shutil.copytree(core / "rust", destination / "rust", ignore=ignore)
    for name in ("pyproject.toml", "README.md", "LICENSE", ".git"):
        shutil.copyfile(source / name, destination / name)
    for name in ("build_native_command_program.py", "core_command_build_inputs.py"):
        shutil.copyfile(core / "scripts" / name, destination / "scripts" / name)
    shutil.copyfile(
        core / "contracts/extensions/core-defaults.v1.json", destination / "contracts/extensions/core-defaults.v1.json"
    )
    docs = "docs/guard/contracts/guard-cloud-review.md"
    (destination / docs).parent.mkdir(parents=True)
    shutil.copyfile(source / docs, destination / docs)
    # A small genuine matcher source, with unique owned identities/executables,
    # plus genuine authored MCP records with unique package launch identities.
    for directory, kind, template, prefix, extension_prefix in (
        ("command-sources", "command", "noodle", "bundlescale", "command."),
        ("mcp-servers", "mcp", "x-reader", "bundlescalemcp", "command.mcp-"),
    ):
        inputs = source / "contributions" / directory
        text = (inputs / f"{kind}.{template}.json").read_text()
        count = len(list(inputs.glob(f"{kind}.*.json")))
        for number in range(count * (scale - 1)):
            name = f"{prefix}{number:06}"
            identity = extension_prefix + name
            write(destination / f"contributions/{directory}/{kind}.{name}.json", json.loads(text.replace(template, name)))
            write(
                destination / f"contracts/extensions/trust/{identity}.v1.json",
                {"schemaVersion": "guard.extension-trust-binding.v1", "extension": identity, "trustClass": "external"},
            )


def run(command, root, environment, log):
    with log.open("ab") as stream:
        subprocess.run(command, cwd=root, env=environment, stdout=stream, stderr=subprocess.STDOUT, check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core-tree", type=Path, required=True)
    parser.add_argument("--compiler", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--scale", type=int, action="append", required=True)
    args = parser.parse_args()
    source = Path(__file__).resolve().parents[1]
    output = args.output.resolve()
    output.mkdir(exist_ok=False)
    environment = {**os.environ, "HOL_GUARD_BUILD_SOURCE_COMPILER": str(args.compiler.resolve(strict=True))}
    reports = []
    for scale in args.scale:
        root = output / f"source-{scale}"
        snapshot(source, args.core_tree, root, scale)
        log = output / f"bundle-scale-{scale}.log"
        run([sys.executable, "-m", "hatchling", "build", "-t", "wheel", "-t", "sdist"], root, environment, log)
        wheel = next((root / "dist").glob("*.whl"))
        with zipfile.ZipFile(wheel) as archive:
            names = archive.namelist()
            assert len(names) < 16384
            assert not any("/contributions/" in name or "/command-sources/" in name for name in names)
            bundle = json.loads(
                archive.read(
                    "codex_plugin_scanner/guard/contracts/data/extensions/command-pack-bundle/command-pack-bundle.v1.json"
                )
            )
            program = archive.read(
                "codex_plugin_scanner/guard/contracts/data/extensions/native-command-program.v1.json"
            )
        sdist = next((root / "dist").glob("*.tar.gz"))
        extracted = output / f"rebuild-{scale}"
        extracted.mkdir()
        with tarfile.open(sdist) as archive:
            archive.extractall(extracted, filter="data")
        rebuilt = next(extracted.iterdir())
        run(
            [sys.executable, "-m", "hatchling", "build", "-t", "wheel"],
            rebuilt,
            {**environment, "HOL_GUARD_BUILD_SOURCE_COMPILER": "/compiler-must-not-be-used"},
            log,
        )
        with zipfile.ZipFile(next((rebuilt / "dist").glob("*.whl"))) as archive:
            assert set(names) == set(archive.namelist())
            for name in names:
                if "/command-pack-bundle/" in name:
                    with zipfile.ZipFile(wheel) as original:
                        assert original.read(name) == archive.read(name)
        reports.append(
            {
                "scale": scale,
                "extensions": bundle["policy"]["root"]["extensions"],
                "wheel_files": len(names),
                "compatibility": {key: row["count"] for key, row in bundle["compatibility"].items()},
                "core_program_sha256": hashlib.sha256(program).hexdigest(),
                "compiler_free_rebuild": True,
                "wheel": str(wheel),
                "sdist": str(sdist),
            }
        )
        write(output / "bundle-scale-proof.json", reports)
        print(json.dumps(reports[-1]), flush=True)


if __name__ == "__main__":
    main()
