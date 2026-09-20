"""Package exact build bytes for source-only auto discovery; never an installed claim."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import zipfile
from pathlib import Path

from scripts.build_native_hol_guard_wheel import build_native_wheel


def stage_source_bundle(
    *,
    source_wheel: Path,
    runtime: Path,
    package_root: Path,
    output_dir: Path,
    version: str,
    source_sha: str,
    rule_digest: str,
    platform_tag: str,
    target: str,
) -> Path:
    """Reuse release packaging/provenance checks, then copy only its two native members."""
    native_dir = package_root / "_native"
    if native_dir.exists() or native_dir.is_symlink():
        raise ValueError("source native bundle already exists")
    wheel = build_native_wheel(
        source_wheel=source_wheel,
        runtime=runtime,
        output_dir=output_dir,
        version=version,
        source_sha=source_sha,
        rule_digest=rule_digest,
        platform_tag=platform_tag,
        target=target,
    )
    name = "hol-guard-runtime.exe" if platform_tag.startswith("win") else "hol-guard-runtime"
    with zipfile.ZipFile(wheel) as archive:
        prefix = "codex_plugin_scanner/_native/"
        members = [item.filename for item in archive.infolist() if item.filename.startswith(prefix)]
        if sorted(members) != sorted([prefix + name, prefix + "runtime-manifest.json"]):
            raise ValueError("native wheel members differ from source proof contract")
        binary = archive.read(prefix + name)
        manifest_bytes = archive.read(prefix + "runtime-manifest.json")
    manifest = json.loads(manifest_bytes)
    if binary != runtime.read_bytes():
        raise ValueError("native build changed after wheel verification")
    if (
        manifest["source_sha"] != source_sha
        or manifest["package_version"] != version
        or manifest["protocol_version"] != 1
        or manifest["rule_digest"] != rule_digest
        or manifest["runtime_size"] != len(binary)
        or manifest["runtime_sha256"] != hashlib.sha256(binary).hexdigest()
    ):
        raise ValueError("native wheel manifest differs from source proof contract")
    # The source tree is a disposable owned CI checkout. Refuse replacement of
    # any prior bundle and write only these exact two verified artifact members.
    native_dir.mkdir(mode=0o700)
    created: list[Path] = []
    try:
        for leaf, content, mode in (
            (name, binary, 0o755),
            ("runtime-manifest.json", manifest_bytes, 0o644),
        ):
            destination = native_dir / leaf
            with destination.open("xb") as stream:
                created.append(destination)
                stream.write(content)
            destination.chmod(mode)
    except BaseException:
        for destination in reversed(created):
            destination.unlink()
        native_dir.rmdir()
        raise
    return native_dir / name


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--rule-digest", required=True)
    parser.add_argument("--platform-tag", required=True)
    parser.add_argument("--target", required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    actual_source = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    if actual_source != args.source_sha:
        raise ValueError("source checkout differs from selected build")
    print(
        stage_source_bundle(
            source_wheel=args.wheel,
            runtime=args.runtime,
            package_root=root / "src" / "codex_plugin_scanner",
            output_dir=args.output_dir,
            version=args.version,
            source_sha=args.source_sha,
            rule_digest=args.rule_digest,
            platform_tag=args.platform_tag,
            target=args.target,
        )
    )


if __name__ == "__main__":
    main()
