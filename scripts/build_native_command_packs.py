"""Stage immutable native compiler outputs; never interprets matcher policy.

The root is a build artifact, not an independently authenticated update. Only
the normal release packaging may grant it authority. Existing contributor
commands and authored JSON remain unchanged.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path

import build_native_command_program as legacy
from command_pack_compiler_session import PackCompilerSession
from command_pack_store import PackReader, durable_directory, publish_object

MAX_OBJECT_BYTES = 64 * 1024
MAX_OUTPUT_LINE = 96 * 1024


def input_stream(root: Path, output, identities: set[str] | None = None) -> int:
    rows = []
    for directory, kind in (("command-sources", "command"), ("mcp-servers", "mcp")):
        for path in sorted((root / "contributions" / directory).glob("*.json")):
            if path.name != "migration-manifest.json":
                rows.append((path, kind))
    if not rows:
        raise ValueError("canonical source inventory is empty")

    def frame(data: bytes) -> None:
        if not data or len(data) > legacy.MAX_SOURCE_BYTES:
            raise ValueError("pack source record exceeds native input budget")
        output.write(len(data).to_bytes(4, "big"))
        output.write(data)

    output.write(b"HGPS\x01")
    frame(legacy.canonical_bytes({"schema": "guard.command-pack-source-stream.v1", "count": len(rows)}))
    for path, kind in rows:
        # Native strict decoding still sees the original bytes, including duplicate keys.
        data = legacy.read_source_bytes(path, root=root)
        value = legacy.source_object(data, path)
        extension_id = value.get("extension", {}).get("extension_id") if kind == "command" else value.get("id")
        if not isinstance(extension_id, str) or path.stem != extension_id:
            raise ValueError(f"source filename/identity mismatch: {path.name}")
        if kind == "mcp":
            if not extension_id.startswith("mcp."):
                raise ValueError(f"invalid MCP identity: {path.name}")
            extension_id = f"command.mcp-{extension_id[4:]}"
        if identities is not None:
            identities.add(extension_id)
        binding_path = root / "contracts/extensions/trust" / f"{extension_id}.v1.json"
        binding = legacy.read_object(binding_path, root=root)
        if (
            binding.get("schemaVersion") != "guard.extension-trust-binding.v1"
            or binding.get("extension") != extension_id
        ):
            raise ValueError(f"invalid trust binding: {path.name}")
        classes = {"first-party": [], "trusted-library": [], "external": []}
        trust_class = binding.get("trustClass")
        if trust_class not in classes:
            raise ValueError(f"invalid trust class: {path.name}")
        classes[trust_class] = [extension_id]
        frame(
            legacy.canonical_bytes(
                {
                    "kind": kind,
                    "trust": {
                        "schemaVersion": "guard.extension-trust-class-map.v1",
                        "classes": classes,
                        "publishers": {
                            "hol": {"id": "hol", "displayName": "HOL"},
                            "hol-curated": {"id": "hol-curated", "displayName": "HOL curated library"},
                        },
                    },
                }
            )
        )
        frame(data)
    output.seek(0)
    return len(rows)


def safe_directory(path: Path) -> None:
    for current in (path, *path.parents):
        if current.is_symlink():
            raise ValueError("pack output must not traverse symlinks")
    path.mkdir(parents=True, exist_ok=True)
    if not path.is_dir():
        raise ValueError("pack output must be a directory")


def stage(
    compiler: Path,
    destination: Path,
    *,
    session: PackCompilerSession | None = None,
    source_root: Path | None = None,
    reuse=None,
) -> dict:
    if reuse is not None:
        from extension_delivery_compiler_reuse import VerifiedCompilerReuse

        if not isinstance(reuse, VerifiedCompilerReuse) or session is not None:
            raise ValueError("compiler reuse requires a verified publication and a fresh process")
    if session:
        with session.request():
            return _stage(compiler, destination, session=session, source_root=source_root)
    return _stage(compiler, destination, source_root=source_root, reuse=reuse)


def _stage(
    compiler: Path,
    destination: Path,
    *,
    session: PackCompilerSession | None = None,
    source_root: Path | None = None,
    reuse=None,
) -> dict:
    safe_directory(destination)
    objects = destination / "objects"
    safe_directory(objects)
    root = None
    expected_engine = legacy.implementation_digest()
    identities: set[str] = set()
    reused = created = changed_bytes = 0
    compilation = None
    with tempfile.TemporaryFile() as source, tempfile.TemporaryFile() as errors:
        count = input_stream(source_root or legacy.ROOT, source, identities)
        process = (
            session.submit(compiler, source)
            if session
            else subprocess.Popen(
                [str(compiler), *(reuse.arguments() if reuse is not None else ["compile-packs"])],
                stdin=source,
                stdout=subprocess.PIPE,
                stderr=errors,
            )
        )
        try:
            assert process.stdout is not None
            while line := process.stdout.readline(MAX_OUTPUT_LINE + 1):
                if len(line) > MAX_OUTPUT_LINE or not line.endswith(b"\n"):
                    raise ValueError("native pack output exceeds record budget")
                row = json.loads(line)
                if (session or reuse is not None) and row.get("kind") == "compilation":
                    stats = row.get("stats")
                    if (
                        compilation is not None
                        or not isinstance(stats, dict)
                        or set(stats) != {"compiled", "reused", "retained_encoded_bytes"}
                        or any(type(value) is not int or value < 0 for value in stats.values())
                        or stats["compiled"] + stats["reused"] != count
                        or stats["retained_encoded_bytes"] > 64 * 1024 * 1024
                    ):
                        raise ValueError("native compilation report is invalid")
                    compilation = stats
                    continue
                if row.get("kind") == "root":
                    if (
                        root is not None
                        or row.get("schema") != "guard.command-pack-release.v1"
                        or row.get("extensions") != count
                    ):
                        raise ValueError("native pack root is incomplete")
                    root = row
                    if session:
                        break
                    continue
                if root is not None or row.get("kind") != "object":
                    raise ValueError(f"native pack compilation failed: {row.get('code', 'invalid output')}")
                data = base64.b64decode(row["data"], validate=True)
                digest = hashlib.sha256(data).hexdigest()
                if (
                    not data
                    or len(data) > MAX_OBJECT_BYTES
                    or row.get("length") != len(data)
                    or row.get("sha256") != digest
                ):
                    raise ValueError("native pack object integrity failure")
                if publish_object(objects, digest, data):
                    created += 1
                    changed_bytes += len(data)
                else:
                    reused += 1
            status = process.poll() if session else process.wait()
            if session and (compilation is None or root is None):
                raise ValueError(f"native compiler session failed: {session.error()}")
            if status or root is None:
                errors.seek(0)
                raise ValueError(
                    f"native pack compiler failed ({status}): {errors.read(2048).decode(errors='replace')}"
                )
            if reuse is not None and compilation is None:
                raise ValueError("native compiler reuse report is missing")
        finally:
            if not session and process.poll() is None:
                process.terminate()
                process.wait()
            if not session and process.stdout is not None:
                process.stdout.close()
    # A failed build can leave immutable unreferenced objects, but never a new
    # root. Reused objects are byte checked; the cache supplies no policy authority.
    try:
        PackReader(objects).verify_release(root, expected_engine, identities)
    except (OSError, KeyError, TypeError, RecursionError) as error:
        raise ValueError("pack release references are incomplete or invalid") from error
    durable_directory(objects)
    root_bytes = legacy.canonical_bytes(root)
    release = destination / "release.json"
    if release.is_symlink():
        raise ValueError("pack root must not be a symlink")
    with tempfile.NamedTemporaryFile(dir=destination, prefix=".release-", delete=False) as target:
        temporary = Path(target.name)
        try:
            target.write(root_bytes)
            target.flush()
            os.fsync(target.fileno())
            target.close()
            os.replace(temporary, release)
            durable_directory(destination)
        finally:
            temporary.unlink(missing_ok=True)
    return {
        "schema": "guard.pack-build-report.v1",
        "extensions": count,
        "release_sha256": hashlib.sha256(root_bytes).hexdigest(),
        "engine": root["engine"],
        "created_objects": created,
        "reused_objects": reused,
        "changed_object_bytes": changed_bytes,
        "compilation": compilation or {"compiled": count, "reused": 0, "retained_encoded_bytes": 0},
    }


def bootstrap_compiler() -> Path:
    """Build the maintainer tool without admitting the contribution catalog."""
    subprocess.run(
        [
            "cargo",
            "+1.88.0",
            "build",
            "--locked",
            "--release",
            "--manifest-path",
            str(legacy.ROOT / "rust/Cargo.toml"),
            "-p",
            "guard-pack-compiler",
        ],
        cwd=legacy.ROOT,
        check=True,
    )
    target = Path(os.environ.get("CARGO_TARGET_DIR", "rust/target"))
    if not target.is_absolute():
        target = legacy.ROOT / target
    executable = "guard-pack-compiler.exe" if os.name == "nt" else "guard-pack-compiler"
    return target / "release" / executable


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compiler", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    compiler = args.compiler or bootstrap_compiler()
    print(json.dumps(stage(compiler.resolve(), args.output), sort_keys=True))


if __name__ == "__main__":
    main()
