"""Externally pinned task/provider mounts; never repair physical task custody.

Only the directory leaf belongs to the agent. Every parent remains under Root
custody so an agent cannot exchange the selected mount source before binding.
"""
from __future__ import annotations

import hashlib
import re
import stat
from pathlib import Path

from .json_data import strict_json_loads

FIELDS={'source','destination','custody_root','device','inode','mode'}


def metadata(path):
    info=path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid!=10001 or info.st_gid!=10001
            or stat.S_IMODE(info.st_mode)&~0o755 or info.st_mode&0o700!=0o700):
        raise ValueError('unchanged agent directory ownership and safe mode required')
    return {'device':info.st_dev,'inode':info.st_ino,'mode':stat.S_IMODE(info.st_mode)}


def literal(value,*,physical=True):
    if type(value) is not str or len(value)>4096:
        raise ValueError('bounded literal absolute mount path required')
    path=Path(value)
    if (not path.is_absolute() or '..' in path.parts or str(path)!=value
            or (physical and path.resolve()!=path)):
        raise ValueError('canonical literal absolute mount path required')
    return path


def overlap(left,right):
    return left.is_relative_to(right) or right.is_relative_to(left)


def read_mounts(stage,expected_digest,*,workspace,trusted,runtime_mountpoint=None):
    specification=stage/'task-mounts.json'
    if expected_digest is None:
        if specification.exists() or specification.is_symlink():
            raise ValueError('task mounts require an external declaration digest')
        source=stage/'task'
        pinned=metadata(source)
        if pinned['mode']!=0o700:
            raise ValueError('default physical task requires private mode0700')
        return [{'source':str(source),'destination':workspace,**pinned}]
    if type(expected_digest) is not str or not re.fullmatch('[0-9a-f]{64}',expected_digest):
        raise ValueError('external task declaration SHA256 required')
    trusted(specification)
    with specification.open('rb') as stream:
        raw=stream.read(32769)
    if len(raw)>32768 or hashlib.sha256(raw).hexdigest()!=expected_digest:
        raise ValueError('task declaration digest/byte budget mismatch')
    value=strict_json_loads(raw)
    if (type(value) is not dict or set(value)!={'schema','workspace','providers'}
            or value['schema']!='product-cell-task-mounts.v1' or type(value['workspace']) is not dict
            or type(value['providers']) is not list or len(value['providers'])>8):
        raise ValueError('exact bounded task mount declaration required')
    result=[]
    reserved=[Path(p) for p in ('/usr','/etc','/proc','/product','/public','/dev','/tmp','/run','/opt/node')]
    runtime=stage/'runtime.json'
    if runtime_mountpoint is None and (runtime.exists() or runtime.is_symlink()):
        trusted(runtime)
        with runtime.open('rb') as stream:
            runtime_raw=stream.read(8193)
        if len(runtime_raw)>8192:
            raise ValueError('runtime mount specification byte budget')
        runtime_value=strict_json_loads(runtime_raw)
        if (type(runtime_value) is not dict
                or set(runtime_value)!={'schema','prefix','mountpoint','tree_digest'}
                or runtime_value['schema']!='product-vm-runtime-mount.v1'):
            raise ValueError('exact runtime mount specification required')
        runtime_mountpoint=runtime_value['mountpoint']
    if runtime_mountpoint is not None:
        reserved.append(literal(runtime_mountpoint,physical=False))
    for index,row in enumerate([value['workspace'],*value['providers']]):
        if type(row) is not dict or set(row)!=FIELDS:
            raise ValueError('exact task mount row required')
        source,custody=(literal(row[k]) for k in ('source','custody_root'))
        destination=literal(row['destination'],physical=False)
        if (source==custody or not source.is_relative_to(custody)
                or overlap(source,stage)):
            raise ValueError('task source must be separate from cell state and below its custody root')
        if index==0:
            if str(destination)!=workspace:
                raise ValueError('fixed declared workspace destination required')
        elif (destination!=source or len(destination.parts)<4 or destination.parts[1] not in {'home','opt'}):
            raise ValueError('provider destination must preserve its literal synthetic backing path')
        if any(overlap(destination,path) for path in reserved):
            raise ValueError('task mount would shadow immutable or private paths')
        for prior in result:
            if overlap(source,Path(prior['source'])) or overlap(destination,Path(prior['destination'])):
                raise ValueError('task/provider mounts must be disjoint and unique')
        for parent in source.parents:
            trusted(parent,directory=True)
        if custody.stat().st_mode&0o077:
            raise ValueError('private Root custody directory required')
        actual=metadata(source)
        if any(type(row[k]) is not int or row[k]<0 or row[k]!=actual[k] for k in actual):
            raise ValueError('physical task inode/device/mode differs from external pin')
        result.append({'source':str(source),'destination':str(destination),**actual})
    return result


def bind_mounts(rows,new,*,mount,run):
    """Use the existing reviewed idmap helper; retain source identity and mode."""
    for row in rows:
        source=Path(row['source'])
        pinned={key:row[key] for key in ('device','inode','mode')}
        if metadata(source)!=pinned:
            raise ValueError('physical task changed before idmapped mount')
        target=new.joinpath(*Path(row['destination']).parts[1:])
        # These are fresh namespace scaffolding, not physical task parents.
        for directory in reversed(target.parents):
            if directory.is_relative_to(new) and not directory.exists():
                directory.mkdir(mode=0o755)
                directory.chmod(0o755)
        target.mkdir(mode=0o700)
        result=run(['/usr/bin/mount','--no-mtab','--bind','-o','X-mount.idmap=b:10001:10004:1',
                    str(source),str(target)],capture_output=True,timeout=5,
                   env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','HOME':'/nonexistent'})
        if result.returncode:
            raise RuntimeError('private idmapped mount failed: '+result.stderr[:8192].decode(errors='replace'))
        mount(None,target,flags=32|4096|2|4)  # remount bind,nosuid,nodev
        mapped=target.stat()
        if (metadata(source)!=pinned or mapped.st_uid!=10004 or mapped.st_gid!=10004
                or (mapped.st_dev,mapped.st_ino,stat.S_IMODE(mapped.st_mode))!=
                   (row['device'],row['inode'],row['mode'])):
            raise ValueError('kernel task ownership mapping differs from pinned physical custody')


def observe_mounts(rows,pid):
    """Read the live mount view from the outside collector, not actor JSON."""
    observations=[]
    for row in rows:
        pinned={key:row[key] for key in ('device','inode','mode')}
        if metadata(Path(row['source']))!=pinned:
            raise ValueError('physical task changed before outside observation')
        mapped=(Path(f'/proc/{pid}/root')/row['destination'].lstrip('/')).stat()
        if (mapped.st_uid!=10004 or mapped.st_gid!=10004
                or (mapped.st_dev,mapped.st_ino,stat.S_IMODE(mapped.st_mode))!=
                   (row['device'],row['inode'],row['mode'])):
            raise ValueError('outside kernel mount observation differs from physical custody')
        observations.append({'source':row['source'],'destination':row['destination'],
            'physical':{**pinned,'uid':10001,'gid':10001},
            'product_view':{**pinned,'uid':mapped.st_uid,'gid':mapped.st_gid},'observer_pid':pid})
    return observations
