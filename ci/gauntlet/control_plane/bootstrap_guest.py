"""Trusted inert VM installer; upgrades retain prior files and require an idle lease."""
from __future__ import annotations

import fcntl
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
import sys
import zipfile

BASE = Path('/opt/hol-gauntlet')
OUTPUT = Path('/var/lib/hol-gauntlet/outputs')


def secure(path, directory=True):
    for item in [path, *path.parents]:
        info = item.lstat()
        if info.st_uid != 0 or info.st_mode & 0o022 or item.resolve() != item:
            raise ValueError('Root-owned canonical ancestry required')
        if (item != path or directory) and not stat.S_ISDIR(info.st_mode):
            raise ValueError('ordinary directory required')
        if item == path and not directory and not stat.S_ISREG(info.st_mode):
            raise ValueError('ordinary file required')


def decode(raw):
    if len(raw) > 32*1024**2:
        raise ValueError('bootstrap byte limit')
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        infos = archive.infolist()
        names = [info.filename for info in infos]
        if (len(names) != len(set(names)) or len(names) > 2048
                or sum(i.file_size for i in infos) > 64*1024**2):
            raise ValueError('bootstrap inventory limit')
        entries = {}
        for info in infos:
            name = info.filename
            if (name not in {'settings.json', 'request.json'} and not name.startswith('ci/')
                    or PurePosixPath(name).as_posix() != name or '..' in PurePosixPath(name).parts
                    or '\\' in name or any(ord(c) < 32 for c in name)
                    or info.is_dir() or stat.S_ISLNK(info.external_attr >> 16)
                    or info.file_size > 8*1024**2):
                raise ValueError('bootstrap path/object limit')
            entries[name] = archive.read(info)
    settings = json.loads(entries.pop('settings.json'))
    request = json.loads(entries.pop('request.json', b'{"upgrade":false}'))
    if set(request) != {'upgrade'} or type(request['upgrade']) is not bool:
        raise ValueError('explicit boolean upgrade request required')
    # Operator intent is excluded from source identity: repair followed by up
    # selects the same immutable generation for identical source/settings.
    identity = {name: hashlib.sha256(data).hexdigest() for name, data in entries.items()}
    identity['settings'] = settings
    generation = hashlib.sha256(json.dumps(identity, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return entries, settings, request['upgrade'], generation


def update_file(path, data, *, upgrade):
    secure(path.parent)
    if path.exists() or path.is_symlink():
        secure(path, directory=False)
        previous = path.read_bytes()
        if previous == data:
            return
        if not upgrade:
            raise ValueError('existing ' + path.name + ' differs; run gauntlet repair for a retained upgrade')
        backup = path.with_name(path.name + '.previous-' + hashlib.sha256(previous).hexdigest())
        if backup.exists():
            secure(backup, directory=False)
            if backup.read_bytes() != previous:
                raise ValueError('retained upgrade backup differs')
        else:
            os.link(path, backup)
        temporary = path.with_name(path.name + '.next-' + hashlib.sha256(data).hexdigest())
        with temporary.open('xb') as stream:
            stream.write(data)
        temporary.chmod(0o444)
        os.replace(temporary, path)
    else:
        with path.open('xb') as stream:
            stream.write(data)
        path.chmod(0o444)


def install(raw):
    if os.geteuid() != 0:
        raise ValueError('Root bootstrap required')
    entries, settings, upgrade, generation = decode(raw)
    os.umask(0o022)
    secure(BASE.parent)
    BASE.mkdir(mode=0o755, exist_ok=True)
    secure(BASE)
    lease_path = BASE/'worker.lock'
    descriptor = os.open(lease_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(descriptor)
        if info.st_uid != 0 or info.st_mode & 0o077 or not stat.S_ISREG(info.st_mode):
            raise ValueError('private Root worker lease required')
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        secure(OUTPUT.parent.parent)
        OUTPUT.parent.mkdir(mode=0o755, exist_ok=True)
        secure(OUTPUT.parent)
        OUTPUT.mkdir(mode=0o700, exist_ok=True)
        secure(OUTPUT)
        (BASE/'candidates').mkdir(mode=0o755, exist_ok=True)
        secure(BASE/'candidates')
        controller = BASE/('controller-' + generation[:16])
        if not controller.exists():
            controller.mkdir(mode=0o755)
            for name, data in entries.items():
                path = controller/name
                path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
                with path.open('xb') as stream:
                    stream.write(data)
                path.chmod(0o444)
        else:
            secure(controller)
            for name, data in entries.items():
                path = controller/name
                secure(path, directory=False)
                if path.read_bytes() != data:
                    raise ValueError('retained controller differs')
        for target, source in [('worker.py', 'vm_worker.py'), ('stage.py', 'stage_candidate.py'),
                               ('build.py', 'vm_build.py'), ('network.py', 'vm_network.py'),
                               ('live.py', 'vm_live.py'), ('features.py', 'vm_features.py')]:
            update_file(BASE/target, entries['ci/gauntlet/control_plane/' + source], upgrade=upgrade)
        settings['controller'] = str(controller)
        # The minimal system installer stays stdlib-only. Controller modules
        # run with their already-provisioned, Root-owned dependency interpreter.
        provision='''import json,sys
from pathlib import Path
r=json.loads(sys.stdin.read());sys.path.insert(0,r['controller'])
from ci.gauntlet.control_plane.bootstrap_guest import secure
from ci.gauntlet.control_plane.executor_image import install
print(json.dumps(install(Path(r['controller']),r['settings'],secure)))
'''
        result=subprocess.run([settings['controller_python'],'-I','-B','-c',provision],
            input=json.dumps({'controller':str(controller),'settings':settings}),
            capture_output=True,text=True,timeout=80,check=False,
            env={'PATH':'/usr/bin:/bin','HOME':'/root'})
        if result.returncode or len(result.stdout)>1024**2:
            raise RuntimeError('Trusted executor provisioning failed: '+result.stderr[-5000:])
        settings.update(json.loads(result.stdout))
        if any(name.startswith('codex_plugin_scanner') for name in sys.modules):
            raise ValueError('candidate imported into Root bootstrap')
        settings_path = BASE/'stage-settings.json'
        # Normalize JSON formatting before deciding whether an upgrade is needed.
        if settings_path.exists():
            secure(settings_path, directory=False)
            unchanged = json.loads(settings_path.read_text()) == settings
        else:
            unchanged = False
        if not unchanged:
            update_file(settings_path, (json.dumps(settings, sort_keys=True) + '\n').encode(), upgrade=upgrade)
        return {'status': 'installed', 'controller': str(controller), 'upgraded': upgrade,
                'executor_image_id':settings['executor_image_id'], 'allocator_profile':settings['allocator_profile'],
                'bootstrap_sha256': hashlib.sha256(raw).hexdigest()}
    finally:
        os.close(descriptor)


if __name__ == '__main__':
    print(json.dumps(install(sys.stdin.buffer.read(32*1024**2 + 1))))
