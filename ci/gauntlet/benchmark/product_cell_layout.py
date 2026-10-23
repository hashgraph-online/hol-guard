"""Immutable public layout declaration shared by the actor and exec gate."""
from pathlib import Path

from .json_data import strict_json_loads

DEFAULT={'workspace':'/task','path':'/usr/bin:/bin'}
WORKSPACES=frozenset({'/task','/runtime/home/project'})
PATHS=frozenset({'/usr/bin:/bin','/usr/local/bin:/usr/bin:/bin'})


def load_layout():
    path=Path('/etc/hol-cell-layout.json')
    if not path.exists() and not path.is_symlink():
        return dict(DEFAULT)
    info=path.lstat()
    if path.is_symlink() or not path.is_file() or info.st_uid!=0 or info.st_mode&0o022:
        raise ValueError('immutable Root layout declaration required')
    with path.open('rb') as stream:
        raw=stream.read(2049)
    if len(raw)>2048:
        raise ValueError('layout declaration byte budget')
    value=strict_json_loads(raw)
    if (type(value) is not dict or set(value)!={'schema','workspace','path'}
            or value['schema']!='product-cell-layout.v1'
            or type(value['workspace']) is not str or type(value['path']) is not str
            or value['workspace'] not in WORKSPACES or value['path'] not in PATHS):
        raise ValueError('fixed declared cell workspace and executable path required')
    return {key:value[key] for key in ('workspace','path')}
