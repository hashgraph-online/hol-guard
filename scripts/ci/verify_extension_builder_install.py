"""Verify the installed authoring CLI outside its source checkout, without live targets."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import tempfile
import time
from pathlib import Path


def _environment(home: Path) -> dict[str, str]:
    environment = os.environ.copy()
    for name in tuple(environment):
        if name in {"PYTHONPATH", "PYTHONHOME"} or name.startswith(("COV_CORE_", "COVERAGE_")):
            environment.pop(name)
    home.mkdir()
    environment.update({"HOME": str(home), "USERPROFILE": str(home), "PYTHONDONTWRITEBYTECODE": "1"})
    return environment


def _run(command: list[str], root: Path, environment: dict[str, str], expected: int = 0) -> dict[str, object]:
    completed = subprocess.run(
        command, cwd=root, env=environment, capture_output=True, text=True, timeout=120, check=False
    )
    if completed.returncode != expected:
        raise RuntimeError(
            f"Installed authoring check exited {completed.returncode}, expected {expected}.\n"
            f"{completed.stdout[-4000:]}\n{completed.stderr[-4000:]}"
        )
    result = json.loads(completed.stdout)
    if not isinstance(result, dict):
        raise ValueError("Installed authoring command did not return a JSON object")
    return result


def _source_copy(source: Path, target: Path) -> None:
    for name in ("contracts", "contributions"):
        shutil.copytree(source / name, target / name)
    for name in (
        "pyproject.toml",
        "scripts/release/stage_guard_cloud_review_artifacts.py",
        "src/codex_plugin_scanner/guard/runtime/command_builtin_extension_catalog.py",
        "src/codex_plugin_scanner/guard/runtime/command_reviewed_literal_matcher.py",
    ):
        destination = target / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source / name, destination)


def _example(binary: Path, source: Path, root: Path, environment: dict[str, str], kind: str) -> dict[str, object]:
    examples = source / "docs/guard/extension-builder/examples"
    filenames = {"cli": "cli-surface.json", "mcp": "mcp-tools.json"}
    inventory = root / filenames[kind]
    shutil.copyfile(examples / filenames[kind], inventory)
    kit = root / f"{kind}-kit"
    identity = ["--executable", "builder-install-demo"]
    if kind == "mcp":
        identity = ["--launcher", "npx", "--package", "@example/builder-install-demo"]
    base = [str(binary), "extensions"]
    started = time.perf_counter()
    generated = _run(
        [
            *base,
            "generate",
            "--from",
            kind,
            "--input",
            str(inventory),
            "--output",
            str(kit),
            "--slug",
            "builder-install-demo",
            "--publisher",
            "community.example",
            "--homepage",
            "https://example.test/builder-install-demo",
            *identity,
            "--json",
        ],
        root,
        environment,
    )
    validated = _run([*base, "validate", str(kit), "--json"], root, environment)
    if generated["revisionDigest"] != validated["revisionDigest"] or generated["reviewedOperations"] != 0:
        raise AssertionError("Installed generation and validation disagree")
    replay = root / f"{kind}-replay"
    _run(
        [
            *base,
            "generate",
            "--from",
            "snapshot",
            "--input",
            str(kit / "discovery.json"),
            "--output",
            str(replay),
            "--json",
        ],
        root,
        environment,
    )
    difference = _run([*base, "diff", str(kit), str(replay), "--json"], root, environment)
    if difference["changed"] is not False:
        raise AssertionError("Installed snapshot replay changed its artifacts")
    checkout = root / f"{kind}-checkout"
    _source_copy(source, checkout)
    plan = _run([*base, "apply", str(kit), "--repo", str(checkout), "--json"], root, environment)
    if (
        plan["written"] is not False
        or (checkout / "contributions/authoring" / str(generated["contributionId"])).exists()
    ):
        raise AssertionError("An integration plan unexpectedly wrote files")
    written = _run(
        [
            *base,
            "apply",
            str(kit),
            "--repo",
            str(checkout),
            "--write",
            "--expected-plan",
            str(plan["planDigest"]),
            "--json",
        ],
        root,
        environment,
    )
    repeated = _run([*base, "apply", str(kit), "--repo", str(checkout), "--write", "--json"], root, environment)
    if written["written"] is not True or any(item["action"] != "unchanged" for item in repeated["files"]):
        raise AssertionError("Installed integration is not idempotent")
    return {
        "kind": kind,
        "operations": generated["discoveredOperations"],
        "revisionDigest": generated["revisionDigest"],
        "elapsedSeconds": round(time.perf_counter() - started, 4),
        "generated": True,
        "validated": True,
        "identicalReplay": True,
        "idempotentApply": True,
    }


def _maximum_inventory(binary: Path, root: Path, environment: dict[str, str]) -> dict[str, object]:
    inventory = root / "maximum.json"
    inventory.write_text(
        json.dumps(
            {
                "schemaVersion": "guard.cli-surface.v1",
                "commands": [{"path": [f"operation{i}"]} for i in range(256)],
            }
        ),
        encoding="utf-8",
    )
    kit = root / "maximum-kit"
    base = [str(binary), "extensions"]
    started = time.perf_counter()
    generated = _run(
        [
            *base,
            "generate",
            "--from",
            "cli",
            "--input",
            str(inventory),
            "--output",
            str(kit),
            "--slug",
            "builder-maximum-demo",
            "--executable",
            "builder-maximum-demo",
            "--publisher",
            "community.example",
            "--homepage",
            "https://example.test/maximum",
            "--json",
        ],
        root,
        environment,
    )
    generation = time.perf_counter() - started
    started = time.perf_counter()
    _run([*base, "validate", str(kit), "--json"], root, environment)
    validation = time.perf_counter() - started
    if generated["discoveredOperations"] != 256:
        raise AssertionError("Maximum supported inventory was truncated")
    return {
        "operations": 256,
        "generationSeconds": round(generation, 4),
        "validationSeconds": round(validation, 4),
        "measurement": "One installed CLI wall-clock sample, including process startup; not a latency guarantee.",
    }


def verify(python: Path, wheel: Path, source: Path) -> dict[str, object]:
    binary = python.with_name("hol-guard.exe" if os.name == "nt" else "hol-guard")
    with tempfile.TemporaryDirectory(prefix="guard-builder-install-") as temporary:
        root = Path(temporary).resolve()
        environment = _environment(root / "home")
        identity = _run(
            [
                str(python),
                "-I",
                "-c",
                "import json; import codex_plugin_scanner.guard.extension_builder as builder; "
                "print(json.dumps({'path': builder.__file__, 'version': builder.BUILDER_VERSION}))",
            ],
            root,
            environment,
        )
        package = Path(str(identity["path"])).resolve()
        environment_root = python.parent.parent.resolve()
        if not package.is_relative_to(environment_root) or package.is_relative_to(source):
            raise AssertionError("Authoring was imported from source instead of the isolated installed wheel")
        results = [_example(binary, source, root, environment, kind) for kind in ("cli", "mcp")]
        maximum = _maximum_inventory(binary, root, environment)
        if list((root / "home").glob(".hol-guard*")):
            raise AssertionError("Offline authoring initialized Guard state")
    return {
        "schemaVersion": "guard.extension-builder-install-evidence.v1",
        "passed": True,
        "builderVersion": identity["version"],
        "platform": platform.platform(),
        "python": platform.python_version(),
        "wheelSha256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
        "examples": results,
        "maximumInventory": maximum,
        "sourceFallback": False,
        "guardStateCreated": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python", type=Path, required=True)
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = verify(args.python.absolute(), args.wheel.resolve(), args.source_root.resolve())
    content = json.dumps(result, indent=2, sort_keys=True) + "\n"
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(content, encoding="utf-8")
    print(content, end="")


if __name__ == "__main__":
    main()
