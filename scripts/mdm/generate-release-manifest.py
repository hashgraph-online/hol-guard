#!/usr/bin/env python3
"""Generate a deterministic release manifest before platform signing."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import platform
import stat
import subprocess
import time
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

SCHEMA = "hol-guard-release-manifest.v1"
POLICY_SCHEMA = "hol-guard-mdm-policy.v1"
MAX_RUNTIME_FILES = 100_000
MAX_RUNTIME_DIRECTORIES = 100_000
MAX_RUNTIME_ENTRIES = 200_000
MAX_RUNTIME_BYTES = 2 * 1024 * 1024 * 1024
MAX_RUNTIME_FILE_BYTES = 512 * 1024 * 1024
HASH_CHUNK_BYTES = 1024 * 1024
MAX_TRAVERSAL_SECONDS = 30.0


def _commit() -> str:
    try:
        result = subprocess.run(["git", "rev-parse", "HEAD"], check=True, capture_output=True, text=True)
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    return result.stdout.strip() or "unknown"


def _open_readonly_no_follow(path: Path) -> int:
    if os.name != "nt":
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        return os.open(path, flags)
    import ctypes
    import msvcrt

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = (
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
    )
    create_file.restype = ctypes.c_void_p
    handle = create_file(str(path), 0x80000000, 0x7, None, 3, 0x00200000 | 0x08000000, None)
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        binary_flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOINHERIT", 0)
        descriptor = msvcrt.open_osfhandle(int(handle), binary_flags)
    except OSError:
        kernel32.CloseHandle(ctypes.c_void_p(handle))
        raise
    metadata = os.fstat(descriptor)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    if getattr(metadata, "st_file_attributes", 0) & reparse_flag:
        os.close(descriptor)
        raise OSError("runtime entry is a reparse point")
    return descriptor


def _manifest_files(root: Path, output: Path) -> list[dict[str, str]]:
    files: list[dict[str, str]] = []
    total_bytes = 0
    directory_count = 1
    entry_count = 0
    deadline = time.monotonic() + MAX_TRAVERSAL_SECONDS
    pending = [root]
    while pending:
        current_path = pending.pop()
        with os.scandir(current_path) as entries:
            for entry in entries:
                entry_count += 1
                if entry_count > MAX_RUNTIME_ENTRIES or time.monotonic() > deadline:
                    raise ValueError("runtime entry count exceeds manifest limit")
                path = Path(entry.path)
                entry_metadata = entry.stat(follow_symlinks=False)
                reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
                if entry.is_symlink() or getattr(entry_metadata, "st_file_attributes", 0) & reparse_flag:
                    raise ValueError("runtime contains a symlink")
                if entry.is_dir(follow_symlinks=False):
                    directory_count += 1
                    if directory_count > MAX_RUNTIME_DIRECTORIES:
                        raise ValueError("runtime directory count exceeds manifest limit")
                    pending.append(path)
                    continue
                if not entry.is_file(follow_symlinks=False):
                    raise ValueError("runtime contains a non-regular file")
                if path == output:
                    continue
                descriptor = _open_readonly_no_follow(path)
                try:
                    before = os.fstat(descriptor)
                    if not stat.S_ISREG(before.st_mode):
                        raise ValueError("runtime contains a non-regular file")
                    if before.st_size > MAX_RUNTIME_FILE_BYTES or before.st_size > MAX_RUNTIME_BYTES - total_bytes:
                        raise ValueError("runtime size exceeds manifest limit")
                    digest = hashlib.sha256()
                    consumed = 0
                    while chunk := os.read(descriptor, min(HASH_CHUNK_BYTES, before.st_size - consumed + 1)):
                        consumed += len(chunk)
                        if consumed > before.st_size:
                            raise ValueError("runtime changed during manifest generation")
                        digest.update(chunk)
                    after = os.fstat(descriptor)
                finally:
                    os.close(descriptor)
                stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
                changed = any(getattr(before, field) != getattr(after, field) for field in stable_fields)
                if consumed != before.st_size or changed:
                    raise ValueError("runtime changed during manifest generation")
                total_bytes += consumed
                if total_bytes > MAX_RUNTIME_BYTES:
                    raise ValueError("runtime size exceeds manifest limit")
                files.append(
                    {
                        "path": path.relative_to(root).as_posix(),
                        "sha256": digest.hexdigest(),
                    }
                )
                if len(files) > MAX_RUNTIME_FILES:
                    raise ValueError("runtime file count exceeds manifest limit")
    files.sort(key=lambda item: item["path"])
    if not files:
        raise ValueError("runtime must contain at least one protected file")
    return files


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime-root", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--build-id", required=True)
    parser.add_argument("--platform", required=True, choices=("macos", "windows"))
    parser.add_argument("--architecture", default=platform.machine().lower())
    parser.add_argument("--installer-identity", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--signing-key", type=Path)
    parser.add_argument("--key-id")
    args = parser.parse_args()
    root = args.runtime_root.resolve(strict=True)
    output = args.output.resolve()
    if not output.is_relative_to(root):
        parser.error("--output must be inside --runtime-root")
    try:
        files = _manifest_files(root, output)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    payload = {
        "schemaVersion": SCHEMA,
        "version": args.version,
        "buildId": args.build_id,
        "sourceCommit": _commit(),
        "platform": args.platform,
        "architecture": args.architecture,
        "policySchemaVersion": POLICY_SCHEMA,
        "installerIdentity": args.installer_identity,
        "files": files,
    }
    if (args.signing_key is None) != (args.key_id is None):
        parser.error("--signing-key and --key-id must be supplied together")
    if args.signing_key is not None:
        private_key = serialization.load_pem_private_key(args.signing_key.read_bytes(), password=None)
        if not isinstance(private_key, Ed25519PrivateKey):
            parser.error("--signing-key must contain an Ed25519 private key")
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
        payload["signature"] = {
            "keyId": args.key_id,
            "value": base64.b64encode(private_key.sign(canonical)).decode(),
        }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
