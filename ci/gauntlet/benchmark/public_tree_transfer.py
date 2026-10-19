"""Bounded inert SDK/cache transfer; preserve the public-tree identity contract.

This is the existing 2 GiB public SDK profile, separate from the 512 MiB
installed-product runtime bundle. Never execute installation hooks or tree code.
Only externally pinned archives may be installed into new Root-owned custody.
"""
from __future__ import annotations

import hashlib
import os
import stat
import zipfile
from pathlib import Path

from .json_data import canonical_json, digest, strict_json_loads
from .runtime_bundle import _link_target, _name, _pin

MAX_BYTES, MAX_ENTRIES, MAX_MANIFEST = 2 * 1024**3, 100000, 16 * 1024**2
MAX_ARCHIVE = MAX_BYTES + 64 * 1024**2


def _validate(entries):
    if type(entries) is not dict or not 1 <= len(entries) <= MAX_ENTRIES:
        raise ValueError('bounded public tree inventory required')
    total, rows = 0, []
    for name, row in entries.items():
        _name(name)
        if type(row) is not dict or row.get('kind') not in {'directory', 'file', 'link'}:
            raise ValueError('unsupported public tree entry')
        kind = row['kind']
        extra = {'size', 'sha256'} if kind == 'file' else {'symlink'} if kind == 'link' else set()
        if (set(row) != {'kind','uid','gid','mode'} | extra
                or type(row['uid']) is not int or row['uid'] not in {0,501}
                or type(row['gid']) is not int or not 0 <= row['gid'] <= 65535
                or type(row['mode']) is not int or not 0 <= row['mode'] <= 0o777
                or (kind != 'link' and (row['mode'] & 0o002
                    or row['gid'] == 10001 and row['mode'] & 0o020))
                or kind == 'link' and row['mode'] != 0o777):
            raise ValueError('public ownership/mode/fields differ from SDK profile')
        parent = str(Path(name).parent)
        if parent != '.' and entries.get(parent, {}).get('kind') != 'directory':
            raise ValueError('public tree entry has an indirect or missing parent')
        if kind == 'file':
            _pin(row['sha256'])
            if type(row['size']) is not int or not 0 <= row['size'] <= MAX_BYTES:
                raise ValueError('public tree file size budget')
            total += row['size']
        if kind == 'link':
            target = row['symlink']
            if type(target) is not str or target.startswith('/'):
                raise ValueError('public tree links must be internal')
            _link_target(name, target)
        rows.append({'path':name, **{k:v for k,v in row.items() if k != 'kind'}})
    if total > MAX_BYTES:
        raise ValueError('public tree total size budget')
    for name, row in entries.items():
        if row['kind'] != 'link':
            continue
        target, seen = _link_target(name, row['symlink']), set()
        for _ in range(32):
            if target in seen or target not in entries:
                raise ValueError('cyclic or dangling public tree link')
            seen.add(target)
            parts = Path(target).parts
            linked = next((str(Path(*parts[:i])) for i in range(1,len(parts)+1)
                if entries.get(str(Path(*parts[:i])),{}).get('kind') == 'link'),None)
            if linked is None:
                break
            suffix = parts[len(Path(linked).parts):]
            target = str(Path(_link_target(linked,entries[linked]['symlink']),*suffix))
        else:
            raise ValueError('public tree link resolution budget')
    return digest(sorted(rows,key=lambda row:row['path'])), total


def inventory(root):
    root = Path(root)
    if not root.is_absolute() or root.resolve() != root or not root.is_dir():
        raise ValueError('canonical public source tree required')
    entries = {}
    for directory, dirs, files in os.walk(root,followlinks=False):
        for name in sorted([*dirs,*files]):
            path = Path(directory)/name
            metadata = path.lstat()
            row = {'uid':metadata.st_uid,'gid':metadata.st_gid,'mode':stat.S_IMODE(metadata.st_mode)}
            if stat.S_ISLNK(metadata.st_mode):
                row.update(kind='link',symlink=os.readlink(path))
            elif stat.S_ISDIR(metadata.st_mode):
                row['kind'] = 'directory'
            elif stat.S_ISREG(metadata.st_mode):
                if metadata.st_size > MAX_BYTES:
                    raise ValueError('public source file size budget')
                with path.open('rb') as stream:
                    row.update(kind='file',size=metadata.st_size,sha256=hashlib.file_digest(stream,'sha256').hexdigest())
            else:
                raise ValueError('public source contains special entry')
            entries[path.relative_to(root).as_posix()] = row
            if len(entries) > MAX_ENTRIES:
                raise ValueError('public source entry count budget')
    tree, total = _validate(entries)
    return entries, tree, total


def create_bundle(root, output, *, expected_tree_digest):
    root, output = Path(root), Path(output)
    entries, tree, total = inventory(root)
    if tree != _pin(expected_tree_digest):
        raise ValueError('public source tree differs from external pin')
    raw = canonical_json({'schema':'public-tree-transfer.v1','entries':entries}).encode()
    if len(raw) > MAX_MANIFEST:
        raise ValueError('public manifest byte budget')
    with output.open('xb') as stream, zipfile.ZipFile(stream,'w',compression=zipfile.ZIP_STORED) as archive:
        archive.writestr('manifest.json',raw)
        for name,row in sorted(entries.items()):
            if row['kind'] == 'file':
                archive.write(root/name,'files/'+name)
    if inventory(root)[0] != entries or output.stat().st_size > MAX_ARCHIVE:
        raise ValueError('public source changed during capture or archive exceeds budget')
    with output.open('rb') as stream:
        archive_sha = hashlib.file_digest(stream,'sha256').hexdigest()
    return {'schema':'public-tree-transfer-record.v1','archive_sha256':archive_sha,
            'tree_digest':tree,'entries':len(entries),'bytes':total,'archive_bytes':output.stat().st_size}


def install_bundle(archive_path, destination, *, expected_archive_digest, expected_tree_digest):
    destination = Path(destination)
    if (os.geteuid() != 0 or not destination.is_absolute() or destination.exists()
            or destination.is_symlink() or not destination.parent.is_dir()):
        raise ValueError('new absolute destination in Root custody required')
    for parent in (destination.parent,*destination.parent.parents):
        metadata = parent.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022:
            raise ValueError('public destination ancestry is not private Root custody')
    descriptor = os.open(archive_path,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(descriptor,'rb') as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_size > MAX_ARCHIVE
                or hashlib.file_digest(stream,'sha256').hexdigest() != _pin(expected_archive_digest)):
            raise ValueError('public archive differs from bounded external pin')
        stream.seek(0)
        with zipfile.ZipFile(stream) as archive:
            names = archive.namelist()
            if len(names) != len(set(names)) or len(names) > MAX_ENTRIES+1:
                raise ValueError('duplicate or excessive public archive members')
            info = archive.getinfo('manifest.json')
            if info.file_size > MAX_MANIFEST:
                raise ValueError('public manifest byte budget')
            manifest = strict_json_loads(archive.read(info))
            if (type(manifest) is not dict or set(manifest) != {'schema','entries'}
                    or manifest['schema'] != 'public-tree-transfer.v1'):
                raise ValueError('versioned public archive required')
            entries = manifest['entries'];tree,total = _validate(entries)
            if tree != _pin(expected_tree_digest):
                raise ValueError('public archive tree differs from external pin')
            files = {'files/'+name for name,row in entries.items() if row['kind'] == 'file'}
            if set(names) != files | {'manifest.json'}:
                raise ValueError('public archive members differ from manifest')
            for name,row in entries.items():
                if row['kind'] == 'file' and archive.getinfo('files/'+name).file_size != row['size']:
                    raise ValueError('public archive file length mismatch')
            destination.mkdir(mode=0o700)
            for name,row in sorted(entries.items(),key=lambda item:(len(Path(item[0]).parts),item[0])):
                target = destination/name
                if row['kind'] == 'directory':
                    target.mkdir(mode=0o700)
                elif row['kind'] == 'file':
                    with archive.open('files/'+name) as source,target.open('xb') as output:
                        hasher = hashlib.sha256();written = 0
                        while chunk := source.read(1024**2):
                            written += len(chunk)
                            if written > row['size']:
                                raise ValueError('public extracted file exceeds budget')
                            hasher.update(chunk);output.write(chunk)
                    if written != row['size'] or hasher.hexdigest() != row['sha256']:
                        raise ValueError('public extracted file hash mismatch')
            # All regular ancestry exists before any links; none is traversed to write.
            for name,row in entries.items():
                if row['kind'] == 'link':
                    (destination/name).symlink_to(row['symlink'])
            for name,row in sorted(entries.items(),key=lambda item:-len(Path(item[0]).parts)):
                target = destination/name
                os.chown(target,row['uid'],row['gid'],follow_symlinks=False)
                if row['kind'] != 'link':
                    target.chmod(row['mode'])
        after = os.fstat(stream.fileno())
        stable = lambda value: (value.st_dev,value.st_ino,value.st_size,value.st_mtime_ns,value.st_ctime_ns)
        if stable(before) != stable(after):
            raise ValueError('public archive changed during installation')
    if inventory(destination)[1] != tree:
        raise ValueError('installed public tree identity mismatch')
    destination.chmod(0o755)
    return {'schema':'installed-public-tree.v1','tree_digest':tree,'entries':len(entries),'bytes':total}
