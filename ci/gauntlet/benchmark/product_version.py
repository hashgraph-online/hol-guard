"""Caller-pinned package versions; installed metadata is inert consistency evidence."""
from __future__ import annotations

import os
import re
import stat
from pathlib import Path

from .json_data import strict_json_loads

LEGACY_VERSION = '3.43.1'
VERSION_PATTERN = r'[0-9]+\.[0-9]+\.[0-9]+(?:(?:a|b|rc)[0-9]+|\.post[0-9]+|\.dev[0-9]+)?'


def validate_version(version):
    if type(version) is not str or len(version) > 64 or re.fullmatch(VERSION_PATTERN, version) is None:
        raise ValueError('exact literal Guard package version required')
    return version


def version_options(version):
    """Absence retains the historical profile; explicit pins never use a fallback."""
    return {} if version is None else {'expected_package_version': validate_version(version)}


def verify_claim_version(claim, version):
    """Check consistency with an external pin, without authenticating product claims."""
    validate_version(version)
    try:
        if (claim['package_version'] != version or claim['manifest']['package_version'] != version
                or claim['capabilities']['runtime_version'] != version):
            raise ValueError('product package claim differs from frozen version')
    except (KeyError, TypeError) as error:
        raise ValueError('missing product package version claim') from error


def verify_installed_version(prefix: Path, *, version, source_sha, native_sha256):
    """Read metadata only, after the caller verifies the frozen prefix inventory."""
    validate_version(version)
    relative = Path('lib/python3.12/site-packages/codex_plugin_scanner/_native/runtime-manifest.json')
    path = prefix / relative
    if prefix.resolve() != prefix or any((prefix / Path(*relative.parts[:i])).is_symlink()
                                         for i in range(1, len(relative.parts) + 1)):
        raise ValueError('literal installed runtime manifest required')
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_size > 8192:
        raise ValueError('bounded ordinary installed runtime manifest required')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        opened = os.fstat(stream.fileno())
        raw = stream.read(8193)
        after = os.fstat(stream.fileno())
    identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
    if len(raw) > 8192 or identity(before) != identity(opened) or identity(opened) != identity(after):
        raise ValueError('installed runtime manifest changed while reading')
    manifest = strict_json_loads(raw)
    if (type(manifest) is not dict or manifest.get('package_version') != version
            or manifest.get('source_sha') != source_sha or manifest.get('runtime_sha256') != native_sha256):
        raise ValueError('installed runtime manifest differs from frozen package/native pins')
    return version
