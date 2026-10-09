"""Collect actual Rust execution by pytest without exposing profiler env to native children."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

from scripts.ci import lcov
from scripts.ci import rust_coverage_report as coverage
from scripts.ci.successful_job_artifact import select

SCHEMA = "hol-guard.native-consumer-coverage.v1"
SHARD_SCHEMA = "hol-guard.native-consumer-shard-coverage.v1"
PREFIX = "native-consumer-coverage"
PRODUCER = "native-consumer-coverage"
SELECTION = "native-consumer-coverage-selection.json"
METADATA_SELECTION = "native-consumer-metadata-selection.json"
METADATA_DIRECTORY = "native-consumer-metadata"
PROFILE_PATTERN = "ci-native-%8m.profraw"
BINS = ("hol-guard-runtime", "guard-command-source")
TOOLS = ("llvm-cov", "llvm-profdata")


def regular(path: Path, *, limit: int = 512 * 1024 * 1024) -> Path:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > limit:
        raise ValueError("Native coverage input is linked, non-regular, or oversized")
    return path


def read_json(path: Path) -> dict:
    regular(path, limit=2 * 1024 * 1024)

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate native coverage metadata key")
            result[key] = value
        return result

    value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique)
    if not isinstance(value, dict):
        raise ValueError("Native coverage metadata must be an object")
    return value


def context(root: Path) -> dict:
    repository = os.environ["GITHUB_REPOSITORY"]
    if repository != "hashgraph-online/hol-guard":
        raise ValueError("Native coverage belongs to another repository")
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    if head != os.environ["GITHUB_SHA"]:
        raise ValueError("Native coverage checkout differs from the workflow source")
    run, attempt = int(os.environ["GITHUB_RUN_ID"]), int(os.environ["GITHUB_RUN_ATTEMPT"])
    if run <= 0 or attempt <= 0:
        raise ValueError("Native coverage run identity is invalid")
    version = subprocess.check_output(
        [sys.executable, "scripts/sync_repo_version.py", "--check"], cwd=root, text=True
    ).strip()
    return {
        "repository": repository,
        "run_id": run,
        "attempt": attempt,
        "checkout_sha": head,
        "source_tree_hash": coverage.source_tree_hash(root),
        "lockfile_hash": coverage.digest(root / "rust/Cargo.lock"),
        "package_version": version,
        "toolchain_channel": coverage.toolchain_channel(root),
    }


def profiles(root: Path) -> Path:
    directory = root / "rust/target/ci-native-profiles"
    if directory.is_symlink() or not directory.resolve().is_relative_to(root.resolve()):
        raise ValueError("Native profile directory escaped the checkout")
    return directory


def command(args: list[str], root: Path, *, env=None, capture=False) -> str:
    result = subprocess.run(args, cwd=root, env=env, check=True, text=True, stdout=subprocess.PIPE if capture else None)
    return result.stdout if capture else ""


def source_snapshot(root: Path) -> dict[str, str]:
    files = subprocess.check_output(["git", "ls-files", "-z", "--", "rust"], cwd=root).split(b"\0")
    return {os.fsdecode(name): coverage.digest(regular(root / os.fsdecode(name))) for name in files if name}


def build(root: Path, directory: Path) -> None:
    coverage.checked_directory(root, directory)
    identity = context(root)
    channel = identity["toolchain_channel"]
    details = command(["rustc", f"+{channel}", "-vV"], root, capture=True)
    host = next(line.removeprefix("host: ") for line in details.splitlines() if line.startswith("host: "))
    sysroot = Path(command(["rustc", f"+{channel}", "--print", "sysroot"], root, capture=True).strip())
    tool_directory = sysroot / "lib/rustlib" / host / "bin"
    if not all((tool_directory / name).is_file() for name in TOOLS):
        command(["rustup", "component", "add", "--toolchain", channel, "llvm-tools-preview"], root)
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "metadata.json").unlink(missing_ok=True)
    (directory / "bin").mkdir(exist_ok=True)
    (directory / "tools").mkdir(exist_ok=True)
    target = root / "rust/target/consumer-llvm-cov-target"
    target.mkdir(parents=True, exist_ok=True)
    profile_directory = profiles(root)
    profile_directory.mkdir(parents=True, exist_ok=True)
    profile_bytes = os.fsencode(str(profile_directory / PROFILE_PATTERN)) + b"\0"
    routing_source = target / "profile-routing.rs"
    routing_object = target / "profile-routing.o"
    routing_source.write_text(
        "#[no_mangle]\n#[used]\npub static __llvm_profile_filename: [u8; "
        + str(len(profile_bytes))
        + "] = ["
        + ",".join(map(str, profile_bytes))
        + "];\n",
        encoding="utf-8",
    )
    command(
        [
            "rustc",
            f"+{channel}",
            "--edition=2021",
            "--crate-type=lib",
            "--emit=obj",
            str(routing_source),
            "-o",
            str(routing_object),
        ],
        root,
    )
    env = dict(os.environ)
    env.pop("LLVM_PROFILE_FILE", None)
    env.pop("RUSTFLAGS", None)
    env["CARGO_TARGET_DIR"] = str(target)
    rustflags = ["-C", "instrument-coverage", "-C", f"link-arg={routing_object}"]
    env["CARGO_ENCODED_RUSTFLAGS"] = "\x1f".join(rustflags)
    env["CARGO_PROFILE_RELEASE_STRIP"] = "none"
    env["CARGO_PROFILE_RELEASE_DEBUG"] = "0"
    env["CARGO_PROFILE_RELEASE_OPT_LEVEL"] = "1"
    env["CARGO_PROFILE_RELEASE_LTO"] = "false"
    env["HOL_GUARD_BUILD_SHA"] = identity["checkout_sha"]
    env["HOL_GUARD_PACKAGE_VERSION"] = identity["package_version"]
    command(
        [
            "cargo",
            f"+{channel}",
            "build",
            "--manifest-path",
            "rust/Cargo.toml",
            "--locked",
            "--release",
            "-p",
            "guard-command",
            "-p",
            "hol-guard-runtime",
            "--bin",
            BINS[1],
            "--bin",
            BINS[0],
        ],
        root,
        env=env,
    )
    for name in BINS:
        shutil.copy2(regular(target / "release" / name), directory / "bin" / name)
    for name in TOOLS:
        source = (tool_directory / name).resolve(strict=True)
        if not source.is_relative_to(sysroot.resolve()):
            raise ValueError("LLVM tool escaped the pinned toolchain")
        shutil.copy2(source, directory / "tools" / name)
    files = [f"bin/{name}" for name in BINS] + [f"tools/{name}" for name in TOOLS]
    manifest = {
        **identity,
        "schema": SCHEMA,
        "host": host,
        "rustc": details,
        "source_root": str(root.resolve()),
        "profile_directory": str(profile_directory.resolve()),
        "profile_pattern": PROFILE_PATTERN,
        "rustflags": rustflags,
        "release_strip": "none",
        "release_debug": "0",
        "release_opt_level": "1",
        "release_lto": "false",
        "files": {name: coverage.digest(regular(directory / name)) for name in files},
    }
    capability = json.loads(command([str(directory / "bin" / BINS[0]), "capabilities"], root, env=env, capture=True))
    if (
        capability.get("build_sha") != identity["checkout_sha"]
        or capability.get("runtime_version") != identity["package_version"]
    ):
        raise ValueError("Instrumented native binary has a different build identity")
    manifest["runtime_capabilities"] = capability
    signatures = {}
    for name in BINS:
        for path in profile_directory.glob("ci-native-*.profraw"):
            regular(path).unlink()
        probe = ["capabilities"] if name == BINS[0] else ["export-trust"]
        command([str(directory / "bin" / name), *probe], root, env=env, capture=True)
        observed = {
            path.name.removeprefix("ci-native-").rsplit("_", 1)[0]
            for path in profile_directory.glob("ci-native-*.profraw")
        }
        if len(observed) != 1 or not next(iter(observed)).isdecimal():
            raise ValueError("Native consumer has no unique profile signature")
        signatures[name] = observed.pop()
    if len(set(signatures.values())) != len(BINS):
        raise ValueError("Native consumer profile signatures collide")
    manifest["profile_signatures"] = signatures

    for name in TOOLS:
        command([str(directory / "tools" / name), "--version"], root, capture=True)
    if context(root) != identity:
        raise ValueError("Native coverage source changed during compilation")
    (directory / "metadata.json").write_text(json.dumps(manifest, sort_keys=True) + "\n", encoding="utf-8")


def selection(root: Path, *, metadata: bool = False) -> dict:
    expected = context(root)
    artifact = select(
        expected["repository"],
        expected["run_id"],
        expected["attempt"],
        job_name=PRODUCER,
        artifact_prefix=PREFIX + ("-metadata" if metadata else ""),
    )
    return {**expected, "artifact": artifact}


def verify_bundle(root: Path, directory: Path, selected: dict) -> dict:
    coverage.checked_directory(root, directory)
    manifest = read_json(directory / "metadata.json")
    expected = context(root)
    if any(manifest.get(key) != value or selected.get(key) != value for key, value in expected.items()):
        raise ValueError("Native consumer artifact identity is stale or mismatched")
    if manifest.get("schema") != SCHEMA or manifest.get("profile_pattern") != PROFILE_PATTERN:
        raise ValueError("Native consumer instrumentation contract differs")
    if manifest.get("profile_directory") != str(profiles(root).resolve()):
        raise ValueError("Native consumer profile destination differs from this checkout")
    files = manifest.get("files")
    if not isinstance(files, dict) or set(files) != {f"bin/{name}" for name in BINS} | {
        f"tools/{name}" for name in TOOLS
    }:
        raise ValueError("Native consumer bundle is incomplete")
    signatures = manifest.get("profile_signatures")
    if (
        not isinstance(signatures, dict)
        or set(signatures) != set(BINS)
        or any(not isinstance(value, str) or not value.isdecimal() for value in signatures.values())
        or len(set(signatures.values())) != len(BINS)
    ):
        raise ValueError("Native consumer profile signatures are ambiguous or missing")
    for name, digest in files.items():
        relative = Path(name)
        if relative.is_absolute() or ".." in relative.parts or relative.parts[0] not in {"bin", "tools", "lib"}:
            raise ValueError("Native consumer bundle path is outside its manifest")
        path = directory / relative
        if not path.resolve().is_relative_to(directory.resolve()) or coverage.digest(regular(path)) != digest:
            raise ValueError("Native consumer binary/tool hash differs")
    for name in BINS:
        (directory / "bin" / name).chmod(0o755)
    for name in TOOLS:
        (directory / "tools" / name).chmod(0o755)
    return manifest


def configure(root: Path, directory: Path) -> None:
    selected = read_json(root / SELECTION)
    verify_bundle(root, directory, selected)
    profile_directory = profiles(root)
    profile_directory.mkdir(parents=True, exist_ok=True)
    for path in profile_directory.iterdir():
        if path.name.startswith("ci-native-") and path.suffix == ".profraw":
            regular(path).unlink()
    binary = directory.resolve() / "bin" / BINS[0]
    compiler = directory.resolve() / "bin" / BINS[1]
    with Path(os.environ["GITHUB_ENV"]).open("a", encoding="utf-8") as handle:
        for name, value in (
            ("HOL_GUARD_NATIVE_BINARY", binary),
            ("HOL_GUARD_NATIVE_SOURCE_COMPILER", compiler),
            ("HOL_GUARD_NATIVE_TEST_SOURCE_COMPILER", compiler),
            ("HOL_GUARD_BUILD_SOURCE_COMPILER", compiler),
        ):
            handle.write(f"{name}={value}\n")


def export_shard(root: Path, directory: Path, output: Path, shard: int) -> None:
    selected = read_json(root / SELECTION)
    manifest = verify_bundle(root, directory, selected)
    total = int(os.environ["CI_PYTEST_COVERAGE_SHARDS"])
    if not 0 <= shard < total:
        raise ValueError("Rust consumer coverage shard is outside the planned inventory")
    raw_profiles = sorted(profiles(root).glob("ci-native-*.profraw"))
    for path in raw_profiles:
        regular(path)
    coverage.checked_directory(root, output)
    output.mkdir(parents=True, exist_ok=True)
    (output / "metadata.json").unlink(missing_ok=True)
    signature_groups = manifest["profile_signatures"]
    selected_profiles = {
        name: [path for path in raw_profiles if path.name.startswith(f"ci-native-{signature}_")]
        for name, signature in signature_groups.items()
    }
    if set(raw_profiles) != {path for paths in selected_profiles.values() for path in paths}:
        raise ValueError("Native profiles include an unbound binary signature")
    pieces = []
    empty_input = output / "empty-profile.txt"
    for name in BINS:
        profdata = output / f"{name}.profdata"
        piece = output / f"{name}.lcov"
        inputs = selected_profiles[name]
        if not inputs:
            # Preserve all zero-hit mappings without inventing native execution.
            empty_input.write_bytes(b"")
            inputs = [empty_input]
        command(
            [
                str(directory / "tools/llvm-profdata"),
                "merge",
                "--sparse",
                "--failure-mode=all",
                *map(str, inputs),
                "-o",
                str(profdata),
            ],
            root,
        )
        with piece.open("w", encoding="utf-8") as handle:
            subprocess.run(
                [
                    str(directory / "tools/llvm-cov"),
                    "export",
                    str(directory / "bin" / name),
                    "--format=lcov",
                    "--instr-profile",
                    str(profdata),
                    "--ignore-filename-regex",
                    r"/(\.cargo|\.rustup)/",
                ],
                cwd=root,
                stdout=handle,
                check=True,
                text=True,
            )
        coverage.validate_report(piece, root, normalize=True)
        pieces.append(piece)
        profdata.unlink()
    report = output / "rust-lcov.info"
    report.write_text(lcov.merge(pieces), encoding="utf-8")
    for piece in pieces:
        piece.unlink()

    sources = coverage.validate_report(report, root, normalize=True)
    current = context(root)
    if any(manifest.get(key) != value for key, value in current.items()):
        raise ValueError("Native source changed during shard execution")
    metadata = {
        **current,
        "schema": SHARD_SCHEMA,
        "shard": shard,
        "shard_count": total,
        "native_producer": selected["artifact"],
        "native_manifest": manifest,
        "report_hash": coverage.digest(report),
        "sources": sources,
        "profiles": {path.name: coverage.digest(path) for path in raw_profiles},
        "raw_profile_count": len(raw_profiles),
    }
    (output / "metadata.json").write_text(json.dumps(metadata, sort_keys=True) + "\n", encoding="utf-8")
    empty_input.unlink(missing_ok=True)


def shard_lcov_verifier(root: Path):
    expected = context(root)
    producer = selection(root)
    recorded_selection = read_json(root / METADATA_SELECTION)
    if recorded_selection != selection(root, metadata=True):
        raise ValueError("Native producer metadata is not the current successful artifact")
    authoritative_manifest = read_json(root / METADATA_DIRECTORY / "metadata.json")
    if authoritative_manifest.get("schema") != SCHEMA or any(
        authoritative_manifest.get(key) != value for key, value in expected.items()
    ):
        raise ValueError("Native producer metadata differs from the current source")
    snapshot = source_snapshot(root)
    total = int(os.environ["CI_PYTEST_COVERAGE_SHARDS"])

    def verify(directory: Path, *, shard: int, job_id: int, artifact_id: int) -> Path:
        if job_id <= 0 or artifact_id <= 0 or not 0 <= shard < total:
            raise ValueError("Rust consumer shard entitlement is invalid")
        coverage.checked_directory(root, directory)
        metadata = read_json(directory / "metadata.json")
        if (
            metadata.get("schema") != SHARD_SCHEMA
            or metadata.get("shard") != shard
            or metadata.get("shard_count") != total
            or any(metadata.get(key) != value for key, value in expected.items())
        ):
            raise ValueError("Rust consumer shard/source identity differs")
        if metadata.get("native_producer") != producer["artifact"]:
            raise ValueError("Rust consumer shard used a different successful producer")
        native = metadata.get("native_manifest")
        if (
            native != authoritative_manifest
            or native.get("schema") != SCHEMA
            or native.get("profile_pattern") != PROFILE_PATTERN
            or any(native.get(key) != value for key, value in expected.items())
        ):
            raise ValueError("Rust consumer shard instrumented manifest differs")
        recorded = metadata.get("sources")
        if not isinstance(recorded, dict) or any(snapshot.get(name) != digest for name, digest in recorded.items()):
            raise ValueError("Rust consumer coverage source bytes differ")
        report = regular(directory / "rust-lcov.info")
        if coverage.digest(report) != metadata.get("report_hash"):
            raise ValueError("Rust consumer coverage report hash differs")
        if coverage.validate_report(report, root, source_hashes=snapshot.copy()) != recorded:
            raise ValueError("Rust consumer coverage source inventory differs")
        return report

    return verify


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("build", "select", "select-metadata", "configure", "export"))
    parser.add_argument("--directory", type=Path, default=Path(PREFIX))
    parser.add_argument("--output", type=Path, default=Path("rust-consumer-coverage"))
    parser.add_argument("--shard", type=int)
    args = parser.parse_args()
    root = Path.cwd().resolve()
    directory = root / args.directory
    if args.command == "build":
        build(root, directory)
    elif args.command in {"select", "select-metadata"}:
        metadata = args.command == "select-metadata"
        chosen = selection(root, metadata=metadata)
        selection_path = METADATA_SELECTION if metadata else SELECTION
        (root / selection_path).write_text(json.dumps(chosen, sort_keys=True) + "\n", encoding="utf-8")
        with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as handle:
            handle.write(f"artifact-id={chosen['artifact']['id']}\n")
    elif args.command == "configure":
        configure(root, directory)
    else:
        if args.shard is None:
            parser.error("export requires --shard")
        export_shard(root, directory, root / args.output, args.shard)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
