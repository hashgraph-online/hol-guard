"""Explicit offline cache commands; these never change extension controls."""

from __future__ import annotations

import time
from pathlib import Path


def configure(subparsers):
    for action in ("prefetch", "export-offline", "import-offline", "cleanup-cache"):
        transfer = subparsers.add_parser(action, help="Manage verified offline protection data")
        if action in {"export-offline", "import-offline"}:
            transfer.add_argument("path", type=Path)
        if action != "cleanup-cache":
            transfer.add_argument("--remote", action="store_true", help="Use the current verified public publication")
        else:
            transfer.add_argument("--maximum-bytes", type=int, default=512 * 1024 * 1024)


def run(args, store):
    from ..catalog_delivery import activation_store, cache_io, offline, preparation_authority, transport

    if args.controls_command == "cleanup-cache":
        return cache_io.cleanup(store, maximum_bytes=args.maximum_bytes)
    authority = (
        transport.fetch_root(now=int(time.time())) if args.remote else preparation_authority.load_installed_bundle()
    )
    if authority is None:
        raise ValueError("this installed release has no authenticated offline bundle")
    directory = activation_store.prepare_directory_for_store(store)
    if args.controls_command == "export-offline":
        return offline.export_release(authority, directory, args.path)
    if args.controls_command == "import-offline":
        return offline.import_release(authority, args.path, directory)
    return offline.prefetch(authority, directory)
