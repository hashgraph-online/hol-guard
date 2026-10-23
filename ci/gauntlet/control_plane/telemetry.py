"""Real resource probes; an unavailable probe is unknown, never healthy."""
from __future__ import annotations

import json
import os
import platform
import re
import shutil
import subprocess
import time

GIB = 1024**3
VM_PROBE = '''import json,os,shutil,time
from pathlib import Path
m={k:int(v.split()[0])*1024 for k,v in (s.split(":",1) for s in Path("/proc/meminfo").read_text().splitlines())}
d=shutil.disk_usage("/")
print(json.dumps({"status":"running","checked_at":time.time(),"cpus":os.cpu_count(),
"load":os.getloadavg()[0],"memory_total":m["MemTotal"],"memory_available":m["MemAvailable"],
"disk_total":d.total,"disk_free":d.free}))'''


def host(path):
    disk = shutil.disk_usage(path)
    value = {'status': 'online', 'checked_at': time.time(), 'platform': platform.system(),
             'cpus': os.cpu_count(), 'load': os.getloadavg()[0],
             'disk_total': disk.total, 'disk_free': disk.free,
             'memory_total': None, 'memory_available': None}
    try:
        if platform.system() == 'Darwin':
            total = subprocess.run(['/usr/sbin/sysctl', '-n', 'hw.memsize'],
                                   capture_output=True, text=True, check=True, timeout=5)
            pages = subprocess.run(['/usr/bin/vm_stat'], capture_output=True, text=True, check=True, timeout=5)
            size = int(re.search(r'page size of (\d+) bytes', pages.stdout)[1])
            fields = {k.strip(): int(v.strip().rstrip('.')) for k, v in
                      (line.split(':', 1) for line in pages.stdout.splitlines()[1:] if ':' in line)}
            value['memory_total'] = int(total.stdout)
            value['memory_available'] = size * sum(fields.get(k, 0) for k in
                                                   ('Pages free', 'Pages inactive', 'Pages speculative'))
            value['memory_note'] = 'Free plus inactive/speculative pages; estimate of reclaimable memory.'
        else:
            from pathlib import Path
            fields = {k: int(v.split()[0])*1024 for k, v in
                      (s.split(':', 1) for s in Path('/proc/meminfo').read_text().splitlines())}
            value.update(memory_total=fields['MemTotal'], memory_available=fields['MemAvailable'])
    except (OSError, ValueError, subprocess.SubprocessError, TypeError) as error:
        value['memory_error'] = str(error)[:300]
    return value


def vm(config):
    try:
        result = subprocess.run([config['limactl'], 'shell', config['vm'], '--',
                                 '/usr/bin/python3', '-c', VM_PROBE],
                                capture_output=True, text=True, timeout=12)
        if result.returncode:
            raise RuntimeError(result.stderr.strip()[:1000] or 'VM probe failed')
        value = json.loads(result.stdout)
        value['name'] = config['vm']
        return value
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        return {'status': 'unavailable', 'name': config['vm'], 'checked_at': time.time(), 'error': str(error)[:1000]}


def admission(snapshot, config):
    reasons = []
    if 'deployment' in snapshot and snapshot['deployment'].get('status') != 'installed':
        reasons.append('Reviewed VM controller deployment is not installed')
    h, v = snapshot.get('host', {}), snapshot.get('vm', {})
    if time.time() - h.get('checked_at', 0) > 90 or time.time() - v.get('checked_at', 0) > 90:
        reasons.append('Resource telemetry is stale')
    if h.get('disk_free', 0) < config['host_disk_floor_gib']*GIB:
        reasons.append('Host disk headroom below configured floor')
    if v.get('status') != 'running':
        reasons.append('Benchmark VM unavailable')
    elif v.get('disk_free', 0) < config['vm_disk_floor_gib']*GIB:
        reasons.append('VM disk headroom below configured floor')
    if v.get('status')=='running':
        if v.get('memory_total',0)<(config['vm_memory_gib']-1)*GIB:
            reasons.append('VM memory is below its configured allocation; run gauntlet repair')
        if v.get('disk_total',0)<(config['vm_disk_gib']-3)*GIB:
            reasons.append('VM filesystem is below its configured disk allocation; run gauntlet repair')
    if v.get('status') == 'running' and v.get('memory_available', 0) < GIB:
        reasons.append('VM has less than 1 GiB available memory')
    return reasons
