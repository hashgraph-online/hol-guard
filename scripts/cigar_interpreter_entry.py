#!/usr/bin/env python3
"""Draft a pinned private CPython entry; never install, execute or qualify it.

The operator must establish the supplied GitHub release metadata's provenance
independently. Native preparation repeats all artifact and tree checks.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import tarfile
import zlib
from pathlib import Path, PurePosixPath

MAX_BYTES = 256 * 1024 * 1024
MAX_FILE = 128 * 1024 * 1024
MAX_FILES = 8192
TARGETS = {
    "darwin-arm64": "aarch64-apple-darwin",
    "darwin-x64": "x86_64-apple-darwin",
    "linux-x64-gnu": "x86_64-unknown-linux-gnu",
    "linux-arm64-gnu": "aarch64-unknown-linux-gnu",
    "linux-x64-musl": "x86_64-unknown-linux-musl",
    "linux-arm64-musl": "aarch64-unknown-linux-musl",
    "win32-x64": "x86_64-pc-windows-msvc",
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def admit(name: str, directory: bool, namespace: dict) -> str:
    name = name.rstrip("/") if directory else name
    if not name or not name.isascii() or len(name) > 1024 or len(name.split("/")) > 24:
        raise ValueError("unsafe interpreter path")
    prefix = []
    for index, part in enumerate(name.split("/")):
        lower = part.lower()
        stem = lower.split(".", 1)[0]
        if (
            not part
            or part in {".", ".."}
            or len(part) > 240
            or part.endswith((".", " "))
            or any(ord(c) < 32 or ord(c) == 127 or c in '\\:<>"|?*' for c in part)
            or stem in {"con", "prn", "aux", "nul", "clock$"}
            or re.fullmatch(r"(?:com|lpt)[0-9]", stem)
            or lower.endswith((".pth", ".egg-link", ".data"))
        ):
            raise ValueError("unsafe interpreter path")
        prefix.append(part)
        path = "/".join(prefix)
        is_dir = directory or index + 1 < len(name.split("/"))
        previous = namespace.get(path.lower())
        if previous is not None and (previous[0] != path or not previous[1] or not is_dir):
            raise ValueError("interpreter path collision")
        namespace[path.lower()] = (path, is_dir)
    return name


def resolve(name: str, target: str, hard: bool) -> str:
    if not target or not target.isascii() or len(target) > 1024 or target.startswith("/"):
        raise ValueError("unsafe interpreter alias")
    parts = [] if hard else list(PurePosixPath(name).parent.parts)
    if hard:
        if not target.startswith("python/"):
            raise ValueError("unsafe interpreter alias")
        target = target[7:]
    for part in target.split("/"):
        if part in {"", "."}:
            continue
        if part == "..":
            if not parts:
                raise ValueError("unsafe interpreter alias")
            parts.pop()
        else:
            parts.append(part)
    return admit("/".join(parts), False, {})


def inspect_archive(data: bytes) -> tuple[dict, int, str]:
    inflater = zlib.decompressobj(31)
    raw = inflater.decompress(data, MAX_BYTES + 1)
    if len(raw) > MAX_BYTES or not inflater.eof or inflater.unused_data or inflater.unconsumed_tail:
        raise ValueError("unsupported gzip framing or expansion")
    namespace = {}
    files = {}
    links = {}
    total = 0
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
        for index, member in enumerate(archive):
            if index >= MAX_FILES:
                raise ValueError("interpreter member limit")
            if (
                member.pax_headers
                or member.offset_data != member.offset + 512
                or not (member.isreg() or member.isdir() or member.issym() or member.islnk())
            ):
                raise ValueError("unsupported interpreter tar record")
            if member.mode & 0o7000 or member.size > MAX_FILE or (not member.isreg() and member.size):
                raise ValueError("unsupported interpreter member")
            if member.name.rstrip("/") == "python" and member.isdir():
                continue
            if not member.name.startswith("python/"):
                raise ValueError("unsafe interpreter root")
            name = admit(member.name[7:], member.isdir(), namespace)
            if member.isdir():
                continue
            if member.isreg():
                stream = archive.extractfile(member)
                if stream is None:
                    raise ValueError("missing interpreter content")
                content = stream.read(MAX_FILE + 1)
                if len(content) != member.size:
                    raise ValueError("truncated interpreter content")
                total += len(content)
                if total > MAX_BYTES:
                    raise ValueError("interpreter expansion limit")
                files[name] = (len(content), sha256(content), bool(member.mode & 0o111))
            else:
                links[name] = resolve(name, member.linkname, member.islnk())
        if len(raw) - archive.offset < 1024 or any(raw[archive.offset :]):
            raise ValueError("unsupported trailing tar data")
    for name, target in links.items():
        seen = {name}
        while target in links:
            if len(seen) >= 8 or target in seen:
                raise ValueError("interpreter alias cycle")
            seen.add(target)
            target = links[target]
        if target not in files:
            raise ValueError("interpreter alias target missing")
        total += files[target][0]
        if total > MAX_BYTES:
            raise ValueError("interpreter alias expansion limit")
        files[name] = files[target]
    digest = hashlib.sha256(b"guard-cigar-python-tree.v1\0")
    for name, (_, hash_value, _) in sorted(files.items()):
        digest.update(len(name.encode()).to_bytes(8, "big"))
        digest.update(name.encode())
        digest.update(hash_value.encode())
    return files, total, digest.hexdigest()


def draft(args: argparse.Namespace) -> dict:
    if args.archive.is_symlink() or not args.archive.is_file() or args.archive.stat().st_size > MAX_FILE:
        raise ValueError("expected a bounded regular interpreter archive")
    name = args.archive.name
    pattern = (
        rf"cpython-(3\.14\.([0-9]+))\+([0-9]{{8}})-{re.escape(TARGETS[args.platform])}-install_only_stripped\.tar\.gz"
    )
    match = re.fullmatch(pattern, name)
    if not match or int(match[2]) > 65535:
        raise ValueError("expected final standard-GIL CPython3.14 archive")
    release_bytes = args.release_metadata.read_bytes()
    if len(release_bytes) > 16 * 1024 * 1024:
        raise ValueError("release metadata limit")
    metadata = json.loads(release_bytes)
    revision = args.source_revision or metadata["target_commitish"]
    if (
        metadata.get("draft") is not False
        or metadata.get("prerelease") is not False
        or metadata["tag_name"] != match[3]
        or not re.fullmatch(r"[0-9a-f]{40}", revision)
    ):
        raise ValueError("invalid interpreter source identity")
    assets = [asset for asset in metadata["assets"] if asset["name"] == name]
    if len(assets) != 1:
        raise ValueError("missing or duplicate interpreter release asset")
    data = args.archive.read_bytes()
    asset = assets[0]
    url = (
        f"https://github.com/astral-sh/python-build-standalone/releases/download/{match[3]}/{name.replace('+', '%2B')}"
    )
    if (
        asset["browser_download_url"] != url
        or asset["size"] != len(data)
        or asset["digest"] != "sha256:" + sha256(data)
    ):
        raise ValueError("interpreter differs from supplied release metadata")
    files, total, tree = inspect_archive(data)
    executable = "python.exe" if args.platform == "win32-x64" else "bin/python3.14"
    if executable not in files or not files[executable][2]:
        raise ValueError("missing executable interpreter")
    build_id = args.build_id or f"cpython-{match[1].replace('.', '_')}-{match[3]}-{args.platform}"
    if not re.fullmatch(r"[A-Za-z0-9_:-]{1,128}", build_id):
        raise ValueError("invalid interpreter build ID")
    return {
        "schema": "guard-cigar-interpreter-entry-draft.v1",
        "interpreter_build": {
            "build_id": build_id,
            "python_version": [3, 14, int(match[2])],
            "platform": args.platform,
            "source_release": match[3],
            "source_revision": revision,
            "archive_sha256": sha256(data),
            "archive_bytes": len(data),
            "tree_sha256": tree,
            "files": len(files),
            "expanded_bytes": total,
            "executable_sha256": files[executable][1],
            "qualification": "upstream_only",
            "qualification_receipt_sha256": None,
            "withdrawn": False,
        },
        "release_metadata_sha256": sha256(release_bytes),
        "guard_qualified": False,
        "provenance_note": "Verify release metadata provenance independently; this draft is not catalog authority.",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--release-metadata", type=Path, required=True)
    parser.add_argument("--platform", choices=TARGETS, required=True)
    parser.add_argument("--source-revision", help="Verified full source commit if target_commitish is not a commit")
    parser.add_argument("--build-id")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = draft(args)
    with args.output.open("x") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")
    print(
        json.dumps(
            {
                "output": str(args.output),
                "tree_sha256": result["interpreter_build"]["tree_sha256"],
                "guard_qualified": False,
            }
        )
    )


if __name__ == "__main__":
    main()
