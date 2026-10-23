"""Inert, bounded transfer of a pinned Root-owned installed runtime tree.

No installation hooks, Python imports from the tree, archive extraction helpers,
hardlinks, device nodes or privileged modes. Existing prefixes are never replaced.
These bytes are a runtime input, not trusted executable collector code.
"""
from __future__ import annotations

import hashlib
import io
import os
import re
import stat
import zipfile
from pathlib import Path, PurePosixPath

from .json_data import canonical_json, digest, strict_json_loads

MAX_BYTES, MAX_FILE, MAX_ENTRIES = 512 * 1024**2, 128 * 1024**2, 100000
PYTHON_LINKS = {'/usr/bin/python3', '/usr/bin/python3.12'}
HEX = re.compile(r'[0-9a-f]{64}')


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _pin(value):
    if type(value) is not str or not HEX.fullmatch(value):
        raise ValueError('exact external SHA256 required')
    return value


def _name(name):
    if (type(name) is not str or not name or len(name) > 4096 or '\\' in name
            or any(ord(char) < 32 for char in name) or name.startswith('/')
            or PurePosixPath(name).as_posix() != name
            or any(part in {'', '.', '..'} for part in name.split('/'))):
        raise ValueError('noncanonical runtime entry path')


def _link_target(name, target):
    if type(target) is not str or not target or len(target) > 4096:
        raise ValueError('invalid runtime symlink')
    if target.startswith('/'):
        if target not in PYTHON_LINKS:
            raise ValueError('undeclared external runtime link')
        return target
    parts = list(PurePosixPath(name).parent.parts)
    for part in target.split('/'):
        if part in {'', '.'}:
            continue
        if part == '..':
            if not parts:
                raise ValueError('runtime link escapes tree')
            parts.pop()
        else:
            if '\\' in part or any(ord(char) < 32 for char in part):
                raise ValueError('invalid runtime link component')
            parts.append(part)
    return '/'.join(parts) or '.'


def _manifest(entries):
    if type(entries) is not dict or not 1 <= len(entries) <= MAX_ENTRIES:
        raise ValueError('runtime entry count budget')
    legacy, total = {}, 0
    for name, row in entries.items():
        if name != '.':
            _name(name)
        if type(row) is not dict or row.get('kind') not in {'directory', 'file', 'link'}:
            raise ValueError('unsupported runtime object')
        kind = row['kind']
        extra = {'sha256', 'size'} if kind == 'file' else {'link'} if kind == 'link' else set()
        fields = {'kind', 'mode', 'uid'} | extra
        if (set(row) != fields or type(row['uid']) is not int or row['uid'] != 0
                or type(row['mode']) is not int or not 0 <= row['mode'] <= 0o777
                or (kind != 'link' and row['mode'] & 0o022)
                or (kind == 'link' and row['mode'] != 0o777)):
            raise ValueError('runtime ownership/mode/field mismatch')
        legacy[name] = {key:value for key, value in row.items() if key not in {'kind', 'size'}}
        if kind == 'file':
            _pin(row['sha256'])
            if type(row['size']) is not int or not 0 <= row['size'] <= MAX_FILE:
                raise ValueError('runtime file byte budget')
            total += row['size']
            if total > MAX_BYTES:
                raise ValueError('runtime tree byte budget')
        if name != '.':
            parent = str(PurePosixPath(name).parent)
            if entries.get(parent, {}).get('kind') != 'directory':
                raise ValueError('runtime entry ancestor is not a directory')
        if kind == 'link':
            target, visited = _link_target(name, row['link']), set()
            for _ in range(32):
                if target in PYTHON_LINKS:
                    break
                if target in visited or target not in entries:
                    raise ValueError('cyclic or dangling runtime link')
                visited.add(target)
                parts = PurePosixPath(target).parts
                linked = next((str(PurePosixPath(*parts[:index])) for index in range(1, len(parts)+1)
                               if entries.get(str(PurePosixPath(*parts[:index])), {}).get('kind') == 'link'), None)
                if linked is None:
                    break
                suffix = parts[len(PurePosixPath(linked).parts):]
                target = _link_target(linked, entries[linked]['link'])
                if suffix:
                    if target in PYTHON_LINKS:
                        raise ValueError('runtime link traverses external interpreter')
                    target = str(PurePosixPath(target, *suffix))
            else:
                raise ValueError('runtime link resolution budget')
    if entries.get('.', {}).get('kind') != 'directory':
        raise ValueError('runtime root must be a directory')
    return digest(legacy), total


def inventory(prefix: Path):
    """Hash input files without importing or executing any runtime code."""
    if not prefix.is_absolute() or prefix.resolve() != prefix:
        raise ValueError('canonical absolute runtime tree required')
    paths = [prefix]
    entries, objects, total = {}, {}, 0
    for directory, dirs, files in os.walk(prefix, followlinks=False):
        paths.extend(Path(directory)/name for name in sorted([*dirs, *files]))
        if len(paths) > MAX_ENTRIES:
            raise ValueError('runtime entry count budget')
    for path in paths:
        info = path.lstat()
        name = '.' if path == prefix else path.relative_to(prefix).as_posix()
        row = {'mode':stat.S_IMODE(info.st_mode), 'uid':info.st_uid}
        if stat.S_ISLNK(info.st_mode):
            row.update(kind='link', link=os.readlink(path))
        elif stat.S_ISDIR(info.st_mode):
            row['kind'] = 'directory'
        elif stat.S_ISREG(info.st_mode):
            if info.st_size > MAX_FILE or total + info.st_size > MAX_BYTES:
                raise ValueError('runtime input byte budget')
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(descriptor, 'rb') as stream:
                if os.fstat(stream.fileno()) != info:
                    raise ValueError('runtime input changed before capture')
                data = stream.read(MAX_FILE+1)
                after = os.fstat(stream.fileno())
                if (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) != (
                        info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns):
                    raise ValueError('runtime input changed during capture')
            if len(data) != info.st_size:
                raise ValueError('runtime input byte count changed')
            total += len(data)
            row.update(kind='file', sha256=_sha(data), size=len(data))
            objects[row['sha256']] = data
        else:
            raise ValueError('runtime contains a nonregular object')
        entries[name] = row
    tree, total = _manifest(entries)
    return entries, objects, tree, total


def create_bundle(prefix: Path, output: Path, *, expected_tree_digest: str):
    entries, objects, tree, total = inventory(prefix)
    if tree != _pin(expected_tree_digest):
        raise ValueError('runtime source tree differs from external pin')
    manifest = {'schema':'runtime-tree-bundle.v1', 'entries':entries}
    with output.open('xb') as stream, zipfile.ZipFile(stream, 'w', compression=zipfile.ZIP_STORED) as archive:
        def write(name, data):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system, info.external_attr = 3, 0o600 << 16
            archive.writestr(info, data)
        write('manifest.json', canonical_json(manifest).encode())
        for pin, data in sorted(objects.items()):
            write('objects/'+pin, data)
    if output.stat().st_size > MAX_BYTES:
        raise ValueError('runtime archive byte budget')
    return {'schema':'runtime-tree-bundle-record.v1','archive_sha256':_sha(output.read_bytes()),
            'tree_digest':tree,'entries':len(entries),'bytes':total,'archive_bytes':output.stat().st_size}


def validate_bundle(raw: bytes, *, expected_archive_digest: str, expected_tree_digest: str):
    if type(raw) is not bytes or len(raw) > MAX_BYTES or _sha(raw) != _pin(expected_archive_digest):
        raise ValueError('runtime archive byte budget or digest mismatch')
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        infos = archive.infolist()
        names = [info.filename for info in infos]
        if (len(infos) > MAX_ENTRIES+1 or len(set(names)) != len(names)
                or 'manifest.json' not in names
                or any(info.compress_type != zipfile.ZIP_STORED or info.flag_bits & 1
                       or info.file_size != info.compress_size or info.file_size > MAX_FILE for info in infos)):
            raise ValueError('unsupported runtime archive structure')
        if archive.getinfo('manifest.json').file_size > 16*1024**2:
            raise ValueError('runtime manifest byte budget')
        manifest = strict_json_loads(archive.read('manifest.json'))
        if set(manifest) != {'schema', 'entries'} or manifest['schema'] != 'runtime-tree-bundle.v1':
            raise ValueError('runtime bundle schema mismatch')
        entries = manifest['entries']
        tree, _ = _manifest(entries)
        if tree != _pin(expected_tree_digest):
            raise ValueError('runtime tree differs from external pin')
        objects = {row['sha256'] for row in entries.values() if row['kind'] == 'file'}
        if set(names) != {'manifest.json', *('objects/'+pin for pin in objects)}:
            raise ValueError('undeclared or missing runtime archive object')
        data = {}
        for pin in objects:
            item = archive.read('objects/'+pin)
            if _sha(item) != pin:
                raise ValueError('runtime object digest mismatch')
            data[pin] = item
        if any(len(data[row['sha256']]) != row['size'] for row in entries.values() if row['kind'] == 'file'):
            raise ValueError('runtime object size mismatch')
    return entries, data


def install_bundle(archive: Path, destination: Path, *, expected_archive_digest: str, expected_tree_digest: str):
    if os.getuid() != 0 or os.geteuid() != 0 or os.getgid() != 0 or os.getegid() != 0:
        raise ValueError('runtime installation requires trusted Root bootstrap')
    if not destination.is_absolute() or '..' in destination.parts or destination.exists() or destination.is_symlink():
        raise ValueError('new absolute exclusive runtime destination required')
    for path in destination.parents:
        info = path.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022
                or path.resolve() != path):
            raise ValueError('runtime destination ancestry must be exclusively Root-owned')
    descriptor = os.open(archive, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, 'rb') as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode) or os.fstat(stream.fileno()).st_size > MAX_BYTES:
            raise ValueError('bounded regular runtime archive required')
        raw = stream.read(MAX_BYTES+1)
    entries, objects = validate_bundle(raw, expected_archive_digest=expected_archive_digest,
                                       expected_tree_digest=expected_tree_digest)
    destination.mkdir(mode=0o700)
    # Keep the entire partially installed tree inaccessible to actors. Files and
    # directories precede links; validated manifests forbid link ancestors.
    for name, row in sorted(entries.items(), key=lambda item:(len(PurePosixPath(item[0]).parts), item[0])):
        if name == '.':
            continue
        path = destination/name
        if row['kind'] == 'directory':
            path.mkdir(mode=0o700)
        elif row['kind'] == 'file':
            with path.open('xb') as stream:
                stream.write(objects[row['sha256']])
    for name, row in entries.items():
        if row['kind'] == 'link':
            (destination/name).symlink_to(row['link'])
    for name, row in sorted(entries.items(), key=lambda item:len(PurePosixPath(item[0]).parts), reverse=True):
        if row['kind'] != 'link' and name != '.':
            (destination/name).chmod(row['mode'])
    # Re-inventory before exposing the root. A failure preserves a private tree.
    actual, _, _, total = inventory(destination)
    actual['.']['mode'] = entries['.']['mode']
    if actual != entries or _manifest(actual)[0] != expected_tree_digest:
        raise ValueError('installed runtime bytes or metadata differ from pinned input')
    destination.chmod(entries['.']['mode'])
    return {'schema':'runtime-tree-install.v1','tree_digest':expected_tree_digest,
            'archive_sha256':expected_archive_digest,'entries':len(entries),'bytes':total,
            'candidate_code_executed':False}
