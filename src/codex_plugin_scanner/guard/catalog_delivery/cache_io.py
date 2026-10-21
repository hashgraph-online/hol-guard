"""Cache lease and immutable transfer IO; selection/admissibility remain native."""

from __future__ import annotations

import base64
import os
import tempfile
from pathlib import Path

from ..extension_builder.io import checked_path, read_bytes
from . import lifecycle
from .pack_store import durable_directory, publish_object


class Lease:
    """Held through prepared-result lifetime; process death releases the OS lease."""

    def __init__(self, directory: Path):
        from ..native_command_control_authority_io import _same_file, _validate_file

        self.fd = None
        directory = checked_path(directory)
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        path = checked_path(directory / ".cache-lease")
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        fd = os.open(path, flags | getattr(os, "O_CLOEXEC", 0), 0o600)
        self.fd = fd
        try:
            metadata = _validate_file(fd, maximum_bytes=1, repair_mode=True)
            if metadata.st_size == 0:
                os.write(fd, b"0")
                os.fsync(fd)
            if os.name == "nt":
                from ..native_command_control_windows_lock import try_lock_authority_file

                try_lock_authority_file(fd, shared=True)
            else:
                import fcntl

                fcntl.flock(fd, fcntl.LOCK_SH)
            if not _same_file(metadata, os.stat(path, follow_symlinks=False)):
                raise ValueError("cache lease inode changed")
        except BaseException:
            self.close()
            raise

    def close(self):
        fd, self.fd = self.fd, None
        if fd is not None:
            os.close(fd)

    def __del__(self):
        self.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def write_once(path: Path, data: bytes):
    """Publish complete bytes without replacing an existing immutable inode."""
    path = checked_path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.exists():
        if read_bytes(path, limit=len(data)) != data:
            raise ValueError("immutable offline transfer differs")
        return
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".transfer-", delete=False) as stream:
        temporary = Path(stream.name)
        try:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
            stream.close()
            try:
                os.link(temporary, path)
            except FileExistsError:
                if read_bytes(path, limit=len(data)) != data:
                    raise ValueError("immutable offline transfer differs") from None
            durable_directory(path.parent)
        finally:
            temporary.unlink(missing_ok=True)


def stage_archive(directory, reference, fetch, *, invoke=None):
    """Native validates the whole ZIP before any member is published."""
    path = checked_path(directory / "archives" / (reference["sha256"] + ".zip"))
    if not path.exists():
        write_once(path, fetch(reference["location"], reference["length"]))
    admitted = (lifecycle.invoke if invoke is None else invoke)(
        "offline",
        operation="archive",
        path=str(path),
        sha256=reference["sha256"],
        length=reference["length"],
        include_data=True,
    )
    objects = checked_path(directory / "objects")
    objects.mkdir(mode=0o700, parents=True, exist_ok=True)
    for identity, data in admitted["objects"]:
        publish_object(objects, identity, base64.b64decode(data, validate=True))


def cleanup(store, *, maximum_bytes=512 * 1024 * 1024):
    from ..native_command_control_authority_io import hold_command_control_authority_lock
    from ..native_command_control_authority_store import (
        _key,
        read_command_control_authority,
        read_native_control_floor,
    )
    from . import activation_baseline
    from .activation_store import _row, directory_for_store

    directory = directory_for_store(store)
    if not directory.exists():
        return {"evicted": 0}
    # Establish the stable lease inode. Drop SH before taking the native EX.
    lease = Lease(directory)
    lease.close()
    with hold_command_control_authority_lock(store.guard_home):
        key = _key(store)
        marker = read_command_control_authority(store, key)
        floor = read_native_control_floor(store, key)
        with store._connect() as connection:
            if not connection.execute(
                "select 1 from sqlite_master where name='extension_control_schema_migration'"
            ).fetchone():
                rows = []
            else:
                active = _row(connection)
                rows = [] if active is None or activation_baseline.is_baseline(active["record_json"]) else [active]
                if connection.execute(
                    "select 1 from sqlite_master where name='extension_command_pack_pending'"
                ).fetchone():
                    rows.extend(connection.execute("select * from extension_command_pack_pending").fetchall())
        # No caller supplies identities or pin sets. Rust authenticates every row.
        return lifecycle.invoke(
            "offline",
            operation="cleanup",
            directory=str(directory),
            key=key.hex(),
            control_authority=marker,
            control_floor=floor,
            maximum_bytes=maximum_bytes,
            activations=[
                dict(
                    activation=row["record_json"],
                    activation_digest=row["record_digest"],
                    activation_mac=row["record_mac"],
                )
                for row in rows
            ],
        )
