"""Build/check native program and catalog projections from canonical JSON sources.

Python only orchestrates file I/O. Rust owns source validation, lowering, and
identities. This development command is never called on the hook hot path.
"""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = ROOT / "contracts/extensions/native-command-program.v1.json"


def canonical_bytes(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False) + "\n"
    ).encode()


def read_object(path: Path) -> dict:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 4 * 1024 * 1024:
        raise ValueError(f"invalid source file: {path.relative_to(ROOT)}")

    def unique(pairs: list[tuple[str, object]]) -> dict:
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate source key: {path.name}/{key}")
            result[key] = value
        return result

    value = json.loads(path.read_bytes(), object_pairs_hook=unique)
    if not isinstance(value, dict):
        raise ValueError(f"source must be an object: {path.name}")
    return value


def build_request() -> dict:
    sources = []
    source_paths = [
        path
        for path in sorted((ROOT / "contributions/command-sources").glob("*.json"))
        if path.name != "migration-manifest.json"
    ]
    mcp_paths = sorted((ROOT / "contributions/mcp-servers").glob("*.json"))
    paths = source_paths + mcp_paths
    if len(paths) > 512 or sum(path.stat().st_size for path in paths) > 4 * 1024 * 1024:
        raise ValueError("canonical source catalog exceeds native input budget")
    for path in source_paths:
        source = read_object(path)
        if path.stem != source.get("extension", {}).get("extension_id"):
            raise ValueError(f"source filename/identity mismatch: {path.name}")
        sources.append(source)
    if not sources:
        raise ValueError("canonical command sources are missing")
    return {
        "schema": "guard.command-extension-build.v1",
        "sources": sources,
        "mcp_sources": [read_object(path) for path in mcp_paths],
        "trust": read_object(ROOT / "contracts/extensions/trust-class-map.v1.json"),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Reject a missing or stale checked-in artifact.")
    parser.add_argument("--compiler", type=Path, help="Explicit already-built native source compiler.")
    args = parser.parse_args()
    command = (
        [str(args.compiler.resolve(strict=True)), "compile"]
        if args.compiler
        else [
            "cargo",
            "+1.88.0",
            "run",
            "--locked",
            "--quiet",
            "--manifest-path",
            str(ROOT / "rust/Cargo.toml"),
            "-p",
            "guard-command",
            "--bin",
            "guard-command-source",
            "--",
            "compile",
        ]
    )
    request = canonical_bytes(build_request())
    if len(request) > 4 * 1024 * 1024:
        raise ValueError("source build envelope exceeds native input budget")
    completed = subprocess.run(command, input=request, stdout=subprocess.PIPE, cwd=ROOT, timeout=600, check=False)
    if completed.returncode:
        raise ValueError(f"native source compilation failed: {completed.stdout.decode(errors='replace')[:1024]}")
    compiled = json.loads(completed.stdout)
    if compiled["catalog_projection_kind"] != "complete":
        raise ValueError("release generation requires a complete catalog")
    program = compiled["program"]
    catalog = {
        "schema": "guard.command-catalog.v1",
        "catalog": compiled["catalog"],
        "catalog_digest": program["catalog_digest"],
        "program_digest": program["program_digest"],
        "source_digest": compiled["source_digest"],
        "implementation_digest": compiled["implementation_digest"],
    }
    outputs = {
        ARTIFACT: canonical_bytes(program),
        ROOT / "contracts/extensions/command-catalog.v1.json": canonical_bytes(catalog),
    }
    package_directory = ROOT / "src/codex_plugin_scanner/guard/contracts/data/extensions"
    if any(parent.is_symlink() for parent in (package_directory, *package_directory.parents) if parent != ROOT):
        raise ValueError("package resource directory cannot traverse a symlink")
    outputs.update({package_directory / path.name: content for path, content in tuple(outputs.items())})
    for descriptor in compiled["descriptors"]:
        identity = descriptor["id"]
        if "/" in identity or "\\" in identity or not identity.startswith("command."):
            raise ValueError("invalid generated descriptor identity")
        outputs[ROOT / "contributions/extensions" / f"{identity}.json"] = canonical_bytes(descriptor)
    descriptor_directory = ROOT / "contributions/extensions"
    expected_descriptors = {path for path in outputs if path.parent == descriptor_directory}
    unexpected_descriptors = sorted(
        path for path in descriptor_directory.glob("command.*.json") if path not in expected_descriptors
    )
    if any(not path.is_file() or path.is_symlink() for path in unexpected_descriptors):
        raise ValueError("unexpected generated descriptor destination is not a regular file")
    stale = [
        str(path.relative_to(ROOT))
        for path, content in outputs.items()
        if not path.is_file() or path.read_bytes() != content
    ]
    if any(path.is_symlink() for path in outputs):
        raise ValueError("generated artifact destination cannot be a symlink")
    if args.check:
        if stale or unexpected_descriptors:
            print(
                json.dumps(
                    {
                        "ok": False,
                        "stale": [*stale, *(str(path.relative_to(ROOT)) for path in unexpected_descriptors)],
                        "repair": "Run scripts/build_native_command_program.py.",
                    },
                    sort_keys=True,
                )
            )
            return 1
        embedded = subprocess.run(
            [*command[:-1], "evaluate-batch"],
            input=canonical_bytes(
                {
                    "schema": "guard.command-extension-evaluation-batch.v1",
                    "cases": [{"id": "embedded-identity", "command": "pwd"}],
                }
            ),
            stdout=subprocess.PIPE,
            cwd=ROOT,
            timeout=60,
            check=False,
        )
        if embedded.returncode:
            raise ValueError("native compiler embedded-program verification failed")
        identity = json.loads(embedded.stdout)
        if any(identity.get(key) != program[key] for key in ("program_digest", "catalog_digest")):
            raise ValueError("native compiler embeds a stale program; rebuild it after generating the artifacts")
    else:
        for path in unexpected_descriptors:
            path.unlink()
        for path, content in outputs.items():
            if path.parent == package_directory:
                package_directory.mkdir(parents=True, exist_ok=True)
            if not path.is_file() or path.read_bytes() != content:
                path.write_bytes(content)
    print(
        json.dumps(
            {
                "artifact": str(ARTIFACT.relative_to(ROOT)),
                "program_digest": program["program_digest"],
                "catalog_digest": program["catalog_digest"],
                "bytes": len(outputs[ARTIFACT]),
                "generated_files": len(outputs),
                "checked": bool(args.check),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, KeyError, OSError, subprocess.SubprocessError) as error:
        raise SystemExit(str(error)) from error
