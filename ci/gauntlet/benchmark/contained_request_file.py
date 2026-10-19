"""Bounded native request handoff with descriptor-anchored root cleanup."""
from __future__ import annotations

import os
import secrets
import sys
from contextlib import contextmanager, suppress
from pathlib import Path


@contextmanager
def contained_request_file(home: Path, raw: bytes, *, cleanup_errors: list[str], owner: int = 10004):
    if not isinstance(raw, bytes) or len(raw) > 1024 * 1024:
        raise ValueError("bounded immutable native request bytes required")
    home_fd = os.open(home, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    name = "hol-guard-contained-test-" + secrets.token_hex(16)
    directory_fd, identity, created = None, None, False
    try:
        os.mkdir(name, mode=0o700, dir_fd=home_fd)
        created = True
        directory_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=home_fd)
        identity = os.fstat(directory_fd)
        descriptor = os.open("request.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=directory_fd)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            os.fchmod(stream.fileno(), 0o600)
            os.fchown(stream.fileno(), owner, owner)
        os.fchmod(directory_fd, 0o700)
        os.fchown(directory_fd, owner, owner)
        yield name
    finally:
        try:
            if directory_fd is not None:
                with suppress(FileNotFoundError):
                    os.unlink("request.json", dir_fd=directory_fd)
                try:
                    current = os.stat(name, dir_fd=home_fd, follow_symlinks=False)
                except FileNotFoundError:
                    # Newer installed sinks retire their validated request.
                    # A missing name alone could also hide a renamed directory;
                    # accept only the original, descriptor-bound unlinked inode.
                    if sys.platform != 'linux' or os.fstat(directory_fd).st_nlink != 0:
                        raise ValueError("private contained request directory custody changed")
                    created = False
                else:
                    if (current.st_dev, current.st_ino) != (identity.st_dev, identity.st_ino):
                        raise ValueError("private contained request directory custody changed")
            if created:
                os.rmdir(name, dir_fd=home_fd)
        except (OSError, ValueError) as error:
            cleanup_errors.append(str(error))
        finally:
            if directory_fd is not None:
                os.close(directory_fd)
            os.close(home_fd)
