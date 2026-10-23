"""Recognize bounded stock pytest cache data without trusting ignore patterns.

This is source-inventory policy, not permission to execute cache contents. Unknown
files, executable metadata, links and special files remain ordinary source (or
fail ordinary source validation). Explicit full dependency inventories never use
this exception. Tracked bytes must still match their committed objects.
"""
from contextlib import ExitStack
import hashlib
import os
from pathlib import Path, PurePosixPath
import stat

from .json_data import strict_json_loads


POLICY = 'pytest-standard-cache-data.v1'
MAX_FILE_BYTES = 65536
METADATA = {
    '.gitignore': '3ed731b65d06150c138e2dadb0be0697550888a6b47eb8c45ecc9adba8b8e9bd',
    'CACHEDIR.TAG': '37dc88ef9a0abeddbe81053a6dd8fdfb13afb613045ea1eb4a5c815a74a3bde4',
    'README.md': '73fd6fccdd802c419a6b2d983d6c3173b7da97558ac4b589edec2dfe443db9ad',
}
JSON_FILES = {'v/cache/nodeids', 'v/cache/lastfailed'}
DIRECTORIES = {'v', 'v/cache'}


def _data_files(files):
    if not METADATA.keys() <= files.keys() or files.keys() - METADATA.keys() - JSON_FILES:
        return False
    if any(type(raw) is not bytes or len(raw) > MAX_FILE_BYTES for raw in files.values()):
        return False
    for name, pin in METADATA.items():
        if hashlib.sha256(files[name]).hexdigest() != pin:
            return False
    for name in JSON_FILES & files.keys():
        try:
            value = strict_json_loads(files[name])
        except ValueError:
            return False
        if name.endswith('/nodeids'):
            if type(value) is not list or len(value) > 4096:
                return False
            if any(type(item) is not str or len(item) > 4096 for item in value):
                return False
        elif (type(value) is not dict or len(value) > 4096
              or any(len(key) > 4096 or type(item) is not bool for key, item in value.items())):
            return False
    return True


def standard_cache_measurement(path: Path) -> tuple[int, int] | None:
    """Return entry/byte costs for recognized data, using no-follow directory FDs."""
    try:
        with ExitStack() as stack:
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
            root = os.open(path, flags)
            stack.callback(os.close, root)
            pending, files, entries = [(root, '')], {}, 0
            directories = [(root, os.fstat(root))]
            while pending:
                directory, prefix = pending.pop()
                children = stack.enter_context(os.scandir(directory))
                for child_entry in children:
                    leaf = child_entry.name
                    entries += 1
                    if entries > len(METADATA) + len(JSON_FILES) + len(DIRECTORIES):
                        return None
                    name = prefix + leaf
                    metadata = os.stat(leaf, dir_fd=directory, follow_symlinks=False)
                    if stat.S_ISDIR(metadata.st_mode):
                        if name not in DIRECTORIES:
                            return None
                        child = os.open(leaf, flags, dir_fd=directory)
                        stack.callback(os.close, child)
                        if (os.fstat(child).st_dev, os.fstat(child).st_ino) != (metadata.st_dev, metadata.st_ino):
                            return None
                        directories.append((child, os.fstat(child)))
                        pending.append((child, name + '/'))
                    elif (name in METADATA or name in JSON_FILES) and stat.S_ISREG(metadata.st_mode):
                        if metadata.st_mode & 0o111 or metadata.st_size > MAX_FILE_BYTES:
                            return None
                        descriptor = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                                             | os.O_CLOEXEC, dir_fd=directory)
                        with os.fdopen(descriptor, 'rb') as stream:
                            before = os.fstat(stream.fileno())
                            if not stat.S_ISREG(before.st_mode) or before.st_mode & 0o111:
                                return None
                            raw = stream.read(MAX_FILE_BYTES + 1)
                            after = os.fstat(stream.fileno())
                        identity = lambda item: (item.st_dev, item.st_ino, item.st_size,
                                                 item.st_mtime_ns, item.st_ctime_ns, item.st_mode)
                        if identity(before) != identity(metadata) or identity(before) != identity(after):
                            return None
                        files[name] = raw
                    else:
                        return None
            for descriptor, before in directories:
                after = os.fstat(descriptor)
                if (before.st_dev, before.st_ino, before.st_mtime_ns, before.st_ctime_ns) != (
                        after.st_dev, after.st_ino, after.st_mtime_ns, after.st_ctime_ns):
                    return None
            return (entries + 1, sum(map(len, files.values()))) if _data_files(files) else None
    except OSError:
        return None


def committed_cache_names(blobs: dict) -> frozenset[str]:
    """Apply the same data predicate to an inert, already-bounded Git graph."""
    groups = {}
    for name, (mode, raw) in blobs.items():
        parts = PurePosixPath(name).parts
        for index, part in enumerate(parts):
            if part == '.pytest_cache':
                prefix = '/'.join(parts[:index + 1])
                relative = '/'.join(parts[index + 1:])
                groups.setdefault(prefix, {})[relative] = raw if mode == '100644' else None
    return frozenset(prefix + '/' + name
                     for prefix, files in groups.items() if _data_files(files)
                     for name in files)
