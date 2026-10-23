"""Provision the fixed Ubuntu networking dependency during an idle VM repair."""
import fcntl
import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import sys

SYSTEM_PATH = '/usr/sbin:/usr/bin:/sbin:/bin'


def ensure_slirp(trusted):
    binary = shutil.which('slirp4netns', path=SYSTEM_PATH)
    installed = False
    if binary is None:
        environment = {'PATH':SYSTEM_PATH, 'HOME':'/root', 'LANG':'C.UTF-8',
                       'DEBIAN_FRONTEND':'noninteractive'}
        # Only the missing dependency is installed; no general package upgrade.
        subprocess.run(['/usr/bin/apt-get', 'update'], check=True, timeout=120,
                       env=environment, stdout=sys.stderr, stderr=sys.stderr)
        subprocess.run(['/usr/bin/apt-get', 'install', '--yes', '--no-install-recommends', 'slirp4netns'],
                       check=True, timeout=120, env=environment, stdout=sys.stderr, stderr=sys.stderr)
        installed = True
        binary = shutil.which('slirp4netns', path=SYSTEM_PATH)
    if binary is None:
        raise RuntimeError('slirp4netns is still unavailable after package installation')
    trusted(Path(binary).resolve())
    version = subprocess.run([binary, '--version'], check=True, timeout=10,
                             capture_output=True, text=True)
    return {'status':'ready', 'backend':'slirp4netns', 'executable':binary,
            'version':version.stdout.splitlines()[0][:200], 'installed':installed}


def execute():
    if os.geteuid()!=0 or sys.platform!='linux' or not sys.flags.isolated:
        raise ValueError('isolated Linux Root repair required')
    helpers = runpy.run_path('/opt/hol-gauntlet/worker.py', run_name='trusted_worker_helpers')
    lease = Path('/opt/hol-gauntlet/worker.lock')
    helpers['trusted'](lease)
    with lease.open('r+') as stream:
        fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return ensure_slirp(helpers['trusted'])


if __name__=='__main__':
    print(json.dumps(execute()))
