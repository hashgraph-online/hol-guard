"""Owned image-build step: keep pinned Node/npm inside the readonly /usr closure.

Run only in the new dependency-image build, never on a host or existing prefix.
The old /opt distribution remains unchanged; no package hooks or Node code run.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import stat
from pathlib import Path

NODE_SHA256='3159f9115ab4be7d318b7c28e946837a4dceb7f2b3c43232aa2f2e3852550b90'


def install():
    if os.geteuid()!=0 or Path('/usr/lib/hol-benchmark-node-runtime.v1').exists():
        raise ValueError('fresh owned dependency-image build required')
    node=Path('/opt/node/bin/node');npm=Path('/opt/node/lib/node_modules/npm')
    if (node.is_symlink() or not node.is_file() or not npm.is_dir() or npm.is_symlink()
            or hashlib.sha256(node.read_bytes()).hexdigest()!=NODE_SHA256):
        raise ValueError('existing immutable Node distribution differs from exact pin')
    paths=[node,npm,*npm.rglob('*')]
    if len(paths)>100000:
        raise ValueError('bounded Node dependency inventory required')
    for path in paths:
        metadata=path.lstat()
        if metadata.st_uid!=0 or (not path.is_symlink() and metadata.st_mode & 0o022):
            raise ValueError('Node dependencies must retain readonly Root custody')
        if path.is_symlink():
            if not path.resolve().is_relative_to(npm):
                raise ValueError('npm dependency link escapes its installed package')
        elif not (stat.S_ISREG(metadata.st_mode) or stat.S_ISDIR(metadata.st_mode)):
            raise ValueError('special Node dependency entry unsupported')
    destination=Path('/usr/lib/node_modules/npm')
    if destination.exists() or destination.is_symlink():
        raise ValueError('new npm runtime destination required')
    destination.parent.mkdir(mode=0o755,exist_ok=True)
    shutil.copytree(npm,destination,symlinks=True)
    target=Path('/usr/bin/node')
    if not target.is_symlink() or os.readlink(target)!='/opt/node/bin/node':
        raise ValueError('only the known old image Node symlink may be replaced')
    target.unlink()
    with node.open('rb') as incoming,target.open('xb') as outgoing:
        shutil.copyfileobj(incoming,outgoing)
    target.chmod(0o755)
    for name in ('npm','npx'):
        link=Path('/usr/bin')/name
        if link.is_symlink():
            if os.readlink(link)!='/opt/node/bin/'+name:
                raise ValueError('unexpected existing Node launcher link')
            link.unlink()
        elif link.exists():
            raise ValueError('refuse to replace an undeclared system launcher')
        link.symlink_to('../lib/node_modules/npm/bin/'+name+'-cli.js')
    if hashlib.sha256(target.read_bytes()).hexdigest()!=NODE_SHA256:
        raise ValueError('copied Node identity changed')
    Path('/usr/lib/hol-benchmark-node-runtime.v1').write_text(
        'node-sha256='+NODE_SHA256+'\nlayout=usr-readonly-closure.v1\n')
    Path('/usr/lib/hol-benchmark-node-runtime.v1').chmod(0o444)


if __name__=='__main__':
    install()
