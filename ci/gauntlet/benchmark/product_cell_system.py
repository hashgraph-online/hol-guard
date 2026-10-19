"""Read an externally pinned Root declaration of an owned image filesystem.

The outside image lease proves the image ID/mount provenance; this constructor
side checks the same inode and exclusively Root-owned ancestry before binding it.
Nothing from the image is imported or executed here.
"""
import hashlib
import re
from pathlib import Path

from .json_data import strict_json_loads
from .product_cell_layout import WORKSPACES


def read_system(stage,expected_digest,*,trusted):
    specification=stage/'system.json'
    if expected_digest is None:
        if specification.exists() or specification.is_symlink():
            raise ValueError('system filesystem needs an external declaration digest')
        return Path('/'),'/task'
    if type(expected_digest) is not str or not re.fullmatch('[0-9a-f]{64}',expected_digest):
        raise ValueError('external system declaration SHA256 required')
    trusted(specification)
    with specification.open('rb') as stream:
        raw=stream.read(4097)
    if len(raw)>4096 or hashlib.sha256(raw).hexdigest()!=expected_digest:
        raise ValueError('system declaration digest/byte budget mismatch')
    value=strict_json_loads(raw)
    if (type(value) is not dict or set(value)!={'schema','root','device','inode','image_id','workspace'}
            or value['schema']!='product-cell-image-system.v1'
            or type(value['image_id']) is not str or not re.fullmatch('sha256:[0-9a-f]{64}',value['image_id'])
            or type(value['workspace']) is not str or type(value['root']) is not str
            or value['workspace'] not in WORKSPACES
            or any(type(value[key]) is not int or value[key]<0 for key in ('device','inode'))):
        raise ValueError('exact image-system declaration required')
    root=Path(value['root'])
    if not root.is_absolute() or root==Path('/') or '..' in root.parts or str(root)!=value['root']:
        raise ValueError('literal separate image filesystem required')
    for path in (root,*root.parents):
        trusted(path,directory=True)
    info=root.stat()
    if (info.st_dev,info.st_ino)!=(value['device'],value['inode']):
        raise ValueError('declared image filesystem inode changed')
    trusted(root/'usr',directory=True)
    return root,value['workspace']
