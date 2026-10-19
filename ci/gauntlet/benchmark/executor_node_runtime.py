"""Inert Node/npm capability check for the existing readonly /usr sandbox root."""
from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

from .json_data import strict_json_loads

ROOT_UID=0


def image_node_runtime_identity(root: Path):
    """No interpreter execution, absolute-link following or image code import."""
    root=Path(root)
    def owned_directory(path):
        metadata=path.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid!=ROOT_UID or metadata.st_mode & 0o022:
            raise ValueError('Node runtime ancestry lacks readonly Root custody')
    def read(relative,*,maximum,executable=False):
        path=root/relative
        parent=root
        for part in Path(relative).parts[:-1]:
            parent=parent/part;owned_directory(parent)
        expected=path.lstat()
        if not stat.S_ISREG(expected.st_mode):
            raise ValueError('ordinary Node runtime file required; no links or special entries')
        descriptor=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        with os.fdopen(descriptor,'rb') as stream:
            before=os.fstat(stream.fileno())
            if (not stat.S_ISREG(before.st_mode) or before.st_uid!=ROOT_UID or before.st_mode & 0o022
                    or (before.st_dev,before.st_ino)!=(expected.st_dev,expected.st_ino)
                    or not 0<before.st_size<=maximum or executable and not before.st_mode & 0o111):
                raise ValueError('bounded readonly Node runtime file required')
            hasher=hashlib.sha256();chunks=[];total=0
            while chunk:=stream.read(1024**2):
                total+=len(chunk)
                if total>maximum:raise ValueError('Node runtime byte budget')
                hasher.update(chunk)
                if maximum<=1024**2:chunks.append(chunk)
            after=os.fstat(stream.fileno())
            stable=lambda value:(value.st_dev,value.st_ino,value.st_size,value.st_mtime_ns,value.st_ctime_ns)
            if stable(before)!=stable(after) or total!=before.st_size:
                raise ValueError('Node runtime changed during inert inspection')
        return {'path':'/'+relative,'sha256':hasher.hexdigest(),'size':total,
                'uid':before.st_uid,'mode':stat.S_IMODE(before.st_mode)},b''.join(chunks)
    try:
        owned_directory(root)
        node,_=read('usr/bin/node',maximum=128*1024**2,executable=True)
        launcher=root/'usr/bin/npm'
        metadata=launcher.lstat()
        if (not stat.S_ISLNK(metadata.st_mode) or metadata.st_uid!=ROOT_UID
                or os.readlink(launcher) not in {'../lib/node_modules/npm/bin/npm-cli.js',
                                               '/usr/lib/node_modules/npm/bin/npm-cli.js'}):
            raise ValueError('npm launcher escapes the declared readonly /usr closure')
        npm,_=read('usr/lib/node_modules/npm/bin/npm-cli.js',maximum=1024**2)
        package,raw=read('usr/lib/node_modules/npm/package.json',maximum=1024**2)
        document=strict_json_loads(raw)
        if type(document) is not dict or document.get('name')!='npm' or type(document.get('version')) is not str:
            raise ValueError('declared npm package identity unavailable')
        return {'schema':'executor-node-runtime.v1','profile':'usr-readonly-closure.v1','available':True,
                'node':node,'npm':npm,'npm_package':package,'npm_version':document['version'],
                'candidate_code_executed':False}
    except (OSError,ValueError) as error:
        return {'schema':'executor-node-runtime.v1','profile':'usr-readonly-closure.v1','available':False,
                'reason':type(error).__name__+': '+str(error)[:1024],'candidate_code_executed':False}
