"""Root-owned, exclusive lease of a pinned benchmark dependency image.

Only Podman inspects/mounts the image. No image command or candidate code runs
as Root. Callers must close cells before releasing this lease. Existing mounts
are refused, never borrowed or unmounted by this owner.
"""
from __future__ import annotations

import hashlib
import os
import re
import subprocess
from pathlib import Path

from .json_data import canonical_json, strict_json_loads
from .product_vm_rootfs import _trusted


def _podman(*arguments):
    result = subprocess.run(['/usr/bin/podman', *arguments], check=True,
                            capture_output=True, timeout=60,
                            env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': '/root'})
    if len(result.stdout) > 1024 * 1024 or len(result.stderr) > 65536:
        raise ValueError('image lease output budget exceeded')
    return result.stdout


class ImageLease:
    def __init__(self, image_id):
        if os.geteuid() != 0 or type(image_id) is not str or not re.fullmatch('sha256:[0-9a-f]{64}', image_id):
            raise ValueError('Root and exact immutable image ID required')
        self.image_id = image_id
        self.root = None
        self.owned = False

    def _mounted(self):
        rows = strict_json_loads(_podman('image', 'mount', '--format', 'json'))
        if type(rows) is not list or len(rows) > 4096:
            raise ValueError('bounded image mount inventory required')
        for row in rows:
            if type(row) is not dict or type(row.get('id')) is not str:
                raise ValueError('invalid image mount inventory')
        return [row for row in rows if row['id'].removeprefix('sha256:') == self.image_id[7:]]

    def acquire(self):
        if self.owned or self.root is not None:
            raise ValueError('image lease cannot be reacquired')
        rows = strict_json_loads(_podman('image', 'inspect', self.image_id))
        if (type(rows) is not list or len(rows) != 1 or type(rows[0]) is not dict
                or rows[0].get('Id', '').removeprefix('sha256:') != self.image_id[7:]
                or rows[0].get('Os') != 'linux' or rows[0].get('Architecture') != 'arm64'):
            raise ValueError('exact Linux ARM64 image identity required')
        if self._mounted():
            raise ValueError('image already mounted; refusing to borrow another lease')
        # A helper failure can occur after creating the mount. Reserve cleanup
        # ownership before invoking it, after refusing preexisting mounts.
        self.owned = True
        raw = _podman('image', 'mount', self.image_id)
        root = Path(raw.decode('utf-8').strip())
        if not root.is_absolute() or root == Path('/') or root.resolve() != root:
            raise ValueError('canonical separate mounted image root required')
        for path in (root, *root.parents):
            _trusted(path, directory=True)
        mounted = self._mounted()
        if len(mounted) != 1 or mounted[0].get('mountpoint') != str(root):
            raise ValueError('mounted image provenance mismatch')
        self.root = root
        return self

    def declare(self, stage, *, workspace='/runtime/home/project'):
        if not self.owned or self.root is None or workspace not in {'/task', '/runtime/home/project'}:
            raise ValueError('active validated image lease and fixed workspace required')
        for path in (stage, *stage.parents):
            _trusted(path, directory=True)
        info = self.root.stat()
        value = {'schema': 'product-cell-image-system.v1', 'root': str(self.root),
                 'device': info.st_dev, 'inode': info.st_ino,
                 'image_id': self.image_id, 'workspace': workspace}
        raw = (canonical_json(value) + '\n').encode()
        with (stage / 'system.json').open('xb') as stream:
            stream.write(raw)
        (stage / 'system.json').chmod(0o444)
        return hashlib.sha256(raw).hexdigest()

    def close(self):
        if self.owned:
            if self._mounted():
                _podman('image', 'unmount', self.image_id)
            if self._mounted():
                raise RuntimeError('owned image mount survived cleanup')
            self.owned = False
