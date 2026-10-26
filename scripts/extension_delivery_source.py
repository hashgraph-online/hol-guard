"""Bind generated data to exact reviewed code and canonical contribution bytes."""

from __future__ import annotations

import subprocess
from pathlib import Path

from build_native_command_program import MAX_SOURCE_BYTES
from extension_artifact_bundle import source_sha

from codex_plugin_scanner.guard.extension_builder.io import read_bytes

DIRECTORIES = (
    "contributions/command-sources",
    "contributions/mcp-servers",
    "contributions/extensions",
    "contributions/extension-listings",
    "contracts/extensions/trust",
    "contracts/extensions/revocations",
    "contracts/catalog-delivery",
)


def verify_sources(root: Path, expected_sha: str, *, generated=False) -> None:
    expected_sha = source_sha(expected_sha)
    actual = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True, timeout=15).strip()
    if actual != expected_sha:
        raise ValueError("delivery checkout differs from reviewed source")
    dirty = subprocess.check_output(
        [
            "git",
            "status",
            "--porcelain",
            "--untracked-files=normal",
            "--",
            "rust",
            "scripts",
            "src",
            ".github/workflows",
            "contracts",
            "contributions",
            "pyproject.toml",
            "uv.lock",
            *([] if generated else ["docs/guard/extensions"]),
        ],
        cwd=root,
        timeout=15,
    )
    if dirty:
        raise ValueError("delivery code or contribution inputs differ from reviewed source")
    readme = root / "docs/guard/extensions/README.md"
    if not generated and readme.exists():
        original = subprocess.run(
            ["git", "show", expected_sha + ":docs/guard/extensions/README.md"],
            cwd=root,
            capture_output=True,
            timeout=15,
            check=False,
        )
        if original.returncode or original.stdout != read_bytes(readme, limit=MAX_SOURCE_BYTES):
            raise ValueError("delivery directory template differs from reviewed source")
    inventory = subprocess.check_output(
        ["git", "ls-tree", "-r", "-z", "HEAD", "--", *DIRECTORIES], cwd=root, timeout=30
    )
    committed = {}
    for row in inventory.split(b"\0"):
        if not row:
            continue
        metadata, path = row.split(b"\t", 1)
        mode, kind, identity = metadata.split(b" ")
        if kind != b"blob" or mode not in {b"100644", b"100755"}:
            raise ValueError("delivery source is not a regular committed file")
        committed[path.decode()] = identity
    paths = sorted(path for directory in DIRECTORIES for path in (root / directory).glob("*.json"))
    expected = {name for name in committed if name.endswith(".json") and name.rsplit("/", 1)[0] in DIRECTORIES}
    if expected != {path.relative_to(root).as_posix() for path in paths}:
        raise ValueError("delivery source inventory differs from reviewed commit")
    with subprocess.Popen(
        ["git", "cat-file", "--batch"], cwd=root, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    ) as process:
        try:
            assert process.stdin is not None and process.stdout is not None
            for path in paths:
                name = path.relative_to(root).as_posix()
                if name not in committed or any(char in name for char in "\n\r\0"):
                    raise ValueError("delivery source is absent from reviewed commit")
                content = read_bytes(path, limit=MAX_SOURCE_BYTES)
                process.stdin.write(b"HEAD:" + name.encode() + b"\n")
                process.stdin.flush()
                header = process.stdout.readline(256).split()
                if (
                    len(header) != 3
                    or header[0] != committed[name]
                    or header[1] != b"blob"
                    or header[2] != str(len(content)).encode()
                ):
                    raise ValueError("delivery source object identity differs")
                remaining = len(content)
                offset = 0
                while remaining:
                    part = process.stdout.read(min(65536, remaining))
                    if not part or part != content[offset : offset + len(part)]:
                        raise ValueError("delivery source bytes differ from reviewed commit")
                    remaining -= len(part)
                    offset += len(part)
                if process.stdout.read(1) != b"\n":
                    raise ValueError("delivery source object framing invalid")
            process.stdin.close()
            if process.wait(timeout=15):
                raise ValueError("delivery source verification failed")
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
