"""Bounded inert inventory of every file required by the isolated grader."""
from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

from .developer_oracles import ASSET_NAMES

SOURCE=Path(__file__).resolve().parent


def probe_source_identity():
    files={}
    for name in ASSET_NAMES:
        path=SOURCE/name
        if path.is_symlink() or not path.is_file():
            raise ValueError('ordinary developer probe asset required: '+name)
        descriptor=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_CLOEXEC',0))
        with os.fdopen(descriptor,'rb') as stream:
            before=os.fstat(stream.fileno())
            raw=stream.read(2*1024**2+1)
            after=os.fstat(stream.fileno())
        identity=lambda info:(info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns)
        if (not stat.S_ISREG(before.st_mode) or len(raw)>2*1024**2
                or len(raw)!=before.st_size or identity(before)!=identity(after)):
            raise ValueError('bounded stable developer probe asset required: '+name)
        files[str(path)]=hashlib.sha256(raw).hexdigest()
    return {'schema':'developer-probe-inputs.v1','files':files}
