"""Trusted live inode observation; never imports or executes candidate code."""
from __future__ import annotations

import hashlib
import json
import subprocess
import threading
from pathlib import Path

# Runs trusted stdlib only inside the already measured agent mount namespace.
# Fixed public interoperability paths; candidate Git configuration is not read.
MEASURE = r"""
import hashlib,json,os
from pathlib import Path
project=Path('/runtime/home/project')
worktree=Path('/runtime/home/.worktrees/weekly-report')
marker=worktree/'.git'
try:
 text=marker.read_text().strip()
 if marker.is_symlink() or not text.startswith('gitdir: /runtime/home/project/.git/worktrees/'):
  raise ValueError('not declared linked worktree')
 metadata=Path(text.removeprefix('gitdir: '))
 if (metadata/'gitdir').read_text().strip()!=str(marker): raise ValueError('backpointer mismatch')
 if (metadata/'HEAD').read_text().strip()!='ref: refs/heads/weekly-report': raise ValueError('wrong branch')
 files={}
 for name in ('index.js','package.json'):
  source=project/'node_modules/event-tally'/name
  target=worktree/'node_modules/event-tally'/name
  with source.open('rb') as src,target.open('rb') as dst:
   a,b=os.fstat(src.fileno()),os.fstat(dst.fileno()); x,y=src.read(8193),dst.read(8193)
   if max(len(x),len(y))>8192: raise ValueError('bounded package file required')
   files[name]={'source_device':a.st_dev,'source_inode':a.st_ino,'target_device':b.st_dev,
                'target_inode':b.st_ino,'source_sha256':hashlib.sha256(x).hexdigest(),
                'target_sha256':hashlib.sha256(y).hexdigest()}
 print(json.dumps({'uid':os.getuid(),'mount_namespace':os.readlink('/proc/self/ns/mnt'),
                  'pid_namespace':os.readlink('/proc/self/ns/pid'),'files':files}))
except (OSError,ValueError): print('{}')
"""


class WorktreeReuseObserver:
    def __init__(self, container: str, namespace: dict, source: Path):
        self.container, self.namespace = container, namespace
        self.expected = {name: hashlib.sha256((source / "node_modules/event-tally" / name).read_bytes()).hexdigest()
                         for name in ("index.js", "package.json")}
        self.measurements = []
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._observe, daemon=True)

    def start(self):
        self.thread.start()

    def _observe(self):
        while not self.stop_event.is_set() and not self.measurements:
            try:
                result = subprocess.run(["/usr/bin/podman", "exec", self.container, "/usr/bin/python3", "-I",
                                         "-c", MEASURE], capture_output=True, timeout=3, check=False,
                                        env={"PATH": "/usr/bin:/bin", "HOME": "/root"})
                if result.returncode == 0 and len(result.stdout) <= 8192:
                    observation = json.loads(result.stdout)
                    if self._valid(observation):
                        self.measurements.append(observation)
            except (OSError, ValueError, subprocess.SubprocessError):
                pass
            self.stop_event.wait(0.2)

    def _valid(self, value: dict) -> bool:
        if (value.get("uid") != 10001 or value.get("mount_namespace") != self.namespace["mount_namespace"]
                or value.get("pid_namespace") != self.namespace["pid_namespace"]):
            return False
        for name, expected in self.expected.items():
            measured = value.get("files", {}).get(name, {})
            if (measured.get("source_sha256") != expected or measured.get("target_sha256") != expected
                    or type(measured.get("source_inode")) is not int
                    or type(measured.get("source_device")) is not int
                    or measured.get("source_inode") != measured.get("target_inode")
                    or measured.get("source_device") != measured.get("target_device")):
                return False
        return True

    def stop(self):
        self.stop_event.set()
        self.thread.join(timeout=5)
        if self.thread.is_alive():
            raise RuntimeError("trusted worktree inode observer did not stop")
