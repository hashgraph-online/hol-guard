"""Trusted private-PID1 rootfs constructor for the proposed product VM.

Invoke under unshare --mount --pid --net --ipc --uts --cgroup --fork. The
constructor never imports Guard or a captured solution. Its fixed payload is a
root-owned trusted initializer and capability control, not an enabled executor.
No existing mount masks, global sysctls or host namespace mounts are modified.
"""
from __future__ import annotations

import ctypes as c
import hashlib
import os
import platform
import re
import stat
import subprocess
import sys
from pathlib import Path

MS_RDONLY, MS_NOSUID, MS_NODEV = 1, 2, 4
MS_REMOUNT, MS_BIND, MS_REC, MS_PRIVATE = 32, 4096, 16384, 1 << 18
INITIALIZER_SHA256 = '751a643297edbee73cdb6007d7c953ccd1e110654a6f4a88c05ac6e1e3b13af3'
SAFE_DEVICES = ('null', 'zero', 'full', 'random', 'urandom', 'tty')
ETC_FILES = ('group', 'hosts', 'ld.so.cache', 'nsswitch.conf', 'passwd', 'protocols', 'services')


def _trusted(path, *, directory=False):
    info = path.lstat()
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    if (not kind(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022
            or path.resolve() != path):
        raise ValueError(f'canonical root-owned immutable input required: {path}')


def _runtime(stage, new, bind):
    """Expose only an externally pinned inert runtime at its declared path."""
    specification = stage/'runtime.json'
    if not specification.exists() and not specification.is_symlink():
        return
    _trusted(specification)
    from .json_data import strict_json_loads
    from .runtime_bundle import inventory
    raw = specification.read_bytes()
    if len(raw) > 8192:
        raise ValueError('runtime mount specification byte budget')
    value = strict_json_loads(raw)
    if (type(value) is not dict or set(value) != {'schema','prefix','mountpoint','tree_digest'}
            or value['schema'] != 'product-vm-runtime-mount.v1'):
        raise ValueError('exact runtime mount specification required')
    prefix, destination = Path(value['prefix']), Path(value['mountpoint'])
    if (not prefix.is_absolute() or not destination.is_absolute() or '..' in destination.parts
            or str(destination) != value['mountpoint'] or len(destination.parts) < 3
            or destination.parts[1] not in {'home', 'runtime', 'opt'}
            or destination==Path('/opt/node') or destination.is_relative_to('/opt/node')):
        raise ValueError('runtime mountpoint must be separate from system/control paths')
    for path in (prefix, *prefix.parents):
        _trusted(path, directory=True)
    if inventory(prefix)[2] != value['tree_digest']:
        raise ValueError('runtime prefix differs from externally pinned mount specification')
    target = new.joinpath(*destination.parts[1:])
    for directory in (*reversed(target.parents),target):
        if directory.is_relative_to(new) and not directory.exists():
            directory.mkdir(mode=0o755)
            directory.chmod(0o755)
    bind(prefix, target)


def _allocator_policy(system, new):
    """Copy only the fixed policy from a caller-pinned executor image."""
    preload=system/'etc/ld.so.preload'
    if not preload.exists():
        return
    _trusted(preload)
    if preload.read_bytes()!=b'/usr/lib/hol-gauntlet/libmalloc-policy.so\n':
        raise ValueError('unexpected allocator preload configuration in executor image')
    library=system/'usr/lib/hol-gauntlet/libmalloc-policy.so'
    for parent in library.parents:
        if parent.is_relative_to(system):
            _trusted(parent,directory=True)
    _trusted(library)
    (new/'etc/ld.so.preload').write_bytes(preload.read_bytes())
    (new/'etc/ld.so.preload').chmod(0o444)


def construct(stage: Path, *, initializer_digest=INITIALIZER_SHA256, product_state: Path | None = None,
              loopback_parent_namespace: str | None = None, expected_system_digest: str | None = None,
              idmap_runtime: str = 'ubuntu2404-product-v1', expected_task_digest: str | None = None):
    """Build an entirely new mount tree; exit is mandatory on any failure."""
    if (platform.system() != 'Linux' or platform.machine() != 'aarch64'
            or os.getpid() != 1 or os.getuid() != 0 or os.getgid() != 0):
        raise ValueError('private aarch64 Root PID1 required')
    if os.readlink('/proc/self/ns/mnt') == os.readlink('/proc/1/ns/mnt'):
        # Before replacing proc, /proc/1 is the guest host's systemd. Reject
        # execution in its mount namespace before the first mount operation.
        raise ValueError('private mount namespace required before construction')
    if not stage.is_absolute() or '..' in stage.parts:
        raise ValueError('literal absolute stage path required')
    for ancestor in (stage, *stage.parents):
        _trusted(ancestor, directory=True)
        # /var/tmp itself is sticky writable; trusted per-run stages therefore
        # belong under a separately root-owned nonwritable parent, never /tmp.
    from .product_cell_system import read_system
    system,workspace=read_system(stage,expected_system_digest,trusted=_trusted)
    from .product_cell_task_mounts import bind_mounts, read_mounts
    task_mounts=read_mounts(stage,expected_task_digest,workspace=workspace,trusted=_trusted)
    from .product_cell_idmap import verify
    verify(idmap_runtime,trusted=_trusted)
    if loopback_parent_namespace is not None:
        from .product_vm_network import raise_private_loopback
        raise_private_loopback(loopback_parent_namespace)
    public = stage/'public'
    _trusted(public, directory=True)
    public_paths=list(public.rglob('*'))
    if len(public_paths)>128:
        raise ValueError('trusted public bootstrap entry budget')
    public_bytes=0
    for path in public_paths:
        _trusted(path,directory=path.is_dir() and not path.is_symlink())
        if path.is_file():
            public_bytes+=path.stat().st_size
        if path.stat().st_size > 2 * 1024 * 1024 or public_bytes>8*1024*1024:
            raise ValueError('trusted public bootstrap file byte budget')
    initializer = public/'initializer'
    if (type(initializer_digest) is not str or not re.fullmatch('[0-9a-f]{64}',initializer_digest)
            or hashlib.sha256(initializer.read_bytes()).hexdigest() != initializer_digest):
        raise ValueError('initializer digest mismatch')
    _trusted(system/'usr', directory=True)
    new = stage/'rootfs'
    new.mkdir(mode=0o755)
    lib = c.CDLL(None, use_errno=True)
    lib.mount.argtypes = [c.c_char_p, c.c_char_p, c.c_char_p, c.c_ulong, c.c_char_p]
    lib.mount.restype = c.c_int
    lib.umount2.argtypes, lib.umount2.restype = [c.c_char_p, c.c_int], c.c_int
    lib.syscall.restype = c.c_long

    def mount(source, target, kind=None, flags=0, data=None):
        def encode(value):
            return None if value is None else os.fsencode(value)
        if lib.mount(encode(source), encode(target), encode(kind), flags, encode(data)):
            raise OSError(c.get_errno(), f'private mount failed: {target}')

    def bind(source, target):
        mount(source, target, flags=MS_BIND)
        mount(None, target, flags=MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV)

    mount(None, '/', flags=MS_REC | MS_PRIVATE)
    # The inherited proc mount still names the guest host PID namespace. The
    # trusted mount helper creates a user namespace and writes /proc/<child>/
    # uid_map using private PID numbers, so it needs a matching proc view first.
    # This new private namespace has no container proc masks to remove.
    mount('proc', '/proc', 'proc', MS_NOSUID | MS_NODEV | 8)
    mount('tmpfs', new, 'tmpfs', MS_NOSUID | MS_NODEV, 'size=8m,mode=0755')
    for name in ('usr', 'etc', 'dev', 'proc', 'tmp', 'public', 'oldroot', 'run', 'product'):
        (new/name).mkdir(mode=0o755)
        (new/name).chmod(0o755)
    bind(system/'usr', new/'usr')
    if expected_system_digest is not None:
        # The pinned developer image's /usr/bin/node and npm symlinks target
        # this fixed dependency directory. Never expose an arbitrary image /opt.
        _trusted(system/'opt',directory=True)
        _trusted(system/'opt/node',directory=True)
        (new/'opt').mkdir(mode=0o755)
        (new/'opt').chmod(0o755)
        (new/'opt/node').mkdir(mode=0o755)
        (new/'opt/node').chmod(0o755)
        bind(system/'opt/node',new/'opt/node')
    for name, target in (('bin', 'usr/bin'), ('sbin', 'usr/sbin'), ('lib', 'usr/lib')):
        (new/name).symlink_to(target)
    _runtime(stage, new, bind)
    # Each copied file is inert public OS configuration, never guest credentials.
    for name in ETC_FILES:
        source = system/'etc'/name
        _trusted(source)
        (new/'etc'/name).write_bytes(source.read_bytes())
        (new/'etc'/name).chmod(0o444)
    if expected_system_digest is not None:
        # This fixed allocator policy belongs to the caller-pinned executor
        # image, never the candidate prefix or ambient host configuration.
        _allocator_policy(system,new)
    if expected_system_digest is not None:
        from .json_data import canonical_json
        layout=new/'etc/hol-cell-layout.json'
        layout.write_text(canonical_json({'schema':'product-cell-layout.v1','workspace':workspace,
                          'path':'/usr/local/bin:/usr/bin:/bin'})+'\n')
        layout.chmod(0o444)
    if loopback_parent_namespace is not None:
        network_profile=new/'etc/hol-cell-network-profile'
        network_profile.write_text('private-loopback-v1\n')
        network_profile.chmod(0o444)
    # Preserve Ubuntu alternatives required by normal /bin/sh execution.
    (new/'etc/alternatives').mkdir(mode=0o755)
    _trusted(system/'etc/alternatives', directory=True)
    bind(system/'etc/alternatives', new/'etc/alternatives')
    bind(public, new/'public')
    mount('tmpfs', new/'dev', 'tmpfs', MS_NOSUID, 'size=64k,mode=0755')
    for name in SAFE_DEVICES:
        target = new/'dev'/name
        target.touch(mode=0o600)
        mount('/dev/'+name, target, flags=MS_BIND)
    (new/'dev/fd').symlink_to('/proc/self/fd')
    mount(None, new/'dev', flags=MS_REMOUNT | MS_RDONLY | MS_NOSUID)
    mount('tmpfs', new/'tmp', 'tmpfs', MS_NOSUID | MS_NODEV,
          'size=128m,mode=0700,uid=10004,gid=10004')
    if product_state is None:
        mount('tmpfs', new/'product', 'tmpfs', MS_NOSUID | MS_NODEV,
              'size=128m,mode=0700,uid=10004,gid=10004')
    else:
        if (not product_state.is_absolute() or product_state.resolve()!=product_state
                or product_state.parent!=stage):
            raise ValueError('persistent product state must be a declared direct child of the owned stage')
        metadata=product_state.lstat()
        if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid!=10004 or metadata.st_gid!=10004
                or stat.S_IMODE(metadata.st_mode)!=0o700):
            raise ValueError('persistent product state requires private UID/GID10004 custody')
        mount(product_state,new/'product',flags=MS_BIND)
        mount(None,new/'product',flags=MS_REMOUNT|MS_BIND|MS_NOSUID|MS_NODEV)
    bind_mounts(task_mounts,new,mount=mount,run=subprocess.run)
    # Normal proc in a fresh PID namespace. Sensitive-interface equivalence
    # requires separate proof before candidate use; this is a control only.
    mount('proc', new/'proc', 'proc', MS_NOSUID | MS_NODEV | 8)
    os.chdir(new)
    # __NR_pivot_root=41 on the explicitly supported aarch64 ABI.
    if lib.syscall(c.c_long(41), c.c_char_p(b'.'), c.c_char_p(b'oldroot')):
        raise OSError(c.get_errno(), 'private pivot_root failed')
    os.chdir('/')
    if lib.umount2(b'/oldroot', 2):
        raise OSError(c.get_errno(), 'old root detach failed')
    os.rmdir('/oldroot')
    mount(None, '/', flags=MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV)
    os.execv('/public/initializer', ['/public/initializer', '/usr/bin/python3', '-I', '-B',
                                    '/public/actor.py', '/public'])


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('exact trusted stage argument required')
    construct(Path(sys.argv[1]))
