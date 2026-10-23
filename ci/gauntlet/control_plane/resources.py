"""Resize only the idle, existing benchmark VM; never recreate or delete disks."""
import fcntl
import json
import subprocess
import time

from .config import atomic_json

QUIET = '''import fcntl,runpy,subprocess
from pathlib import Path
h=runpy.run_path('/opt/hol-gauntlet/worker.py',run_name='trusted_worker_helpers')
p=Path('/opt/hol-gauntlet/worker.lock');h['trusted'](p)
with p.open('r+') as lease:
 fcntl.flock(lease,fcntl.LOCK_EX|fcntl.LOCK_NB)
 result=subprocess.run(['/usr/bin/podman','ps','--filter','name=^hol-gauntlet-build-','--format','{{.Names}}'],check=True,capture_output=True,text=True,timeout=15)
 if result.stdout.strip():raise ValueError('benchmark build containers are still active')
print('idle')
'''


def wait_idle(state, timeout=3600):
    from .lifecycle import assert_idle
    deadline = time.monotonic() + timeout
    while True:
        jobs = [json.loads(p.read_text()) for p in (state/'private/jobs').glob('*.json')]
        if any(j['state']=='unknown' for j in jobs):
            raise RuntimeError('Unresolved VM execution must be reconciled before resizing')
        if not any(j['state'] in {'running','preparing'} for j in jobs):
            assert_idle(state)
            return
        if time.monotonic() >= deadline:
            raise RuntimeError('Timed out waiting for the active job; VM memory was not changed')
        time.sleep(2)


def configure(args, state, config_path, config):
    from .lifecycle import assert_idle, vm_inventory, ensure_vm_running
    target = dict(config)
    resize_requested = getattr(args, 'vm_memory_gib', None) is not None
    for argument, key in (('vm_memory_gib','vm_memory_gib'),('build_memory_gib','build_memory_gib')):
        value = getattr(args, argument, None)
        if value is not None:
            target[key] = value
    with (state/'private/agent.lock').open('a+') as lease:
        fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
        clean_startup_config=(config if all(getattr(args,name,None) is None for name in
            ('vm_memory_gib','vm_disk_gib','build_memory_gib')) else None)
        assert_idle(state,clean_startup_config=clean_startup_config)
        inventory = vm_inventory(config)
        if inventory.get('status') not in {'Running','Stopped'}:
            raise RuntimeError('VM state cannot be verified; memory was not changed')
        if type(inventory.get('memory')) is not int or inventory['memory'] <= 0:
            raise ValueError('VM memory allocation cannot be verified')
        if not resize_requested:
            if inventory['memory'] % 1024**3:
                raise ValueError('VM memory is not a whole GiB; specify the requested allocation explicitly')
            target['vm_memory_gib'] = inventory['memory']//1024**3
        memory, build = target['vm_memory_gib'], target['build_memory_gib']
        if (type(memory) is not int or not 4 <= memory <= 128 or type(build) is not int
                or not 1 <= build <= memory - 2):
            raise ValueError('VM memory must be 4–128 GiB; reserve at least 2 GiB outside the build container')
        expected = memory*1024**3
        from .disk_resources import plan as disk_plan, verify as verify_disk
        disk_flags=disk_plan(args,state,target,inventory)
        if any(json.loads(path.read_text()).get('state')=='unknown' for path in
               (state/'private/jobs').glob('*.json')) and (inventory['memory']!=expected or disk_flags):
            raise RuntimeError('Cleaned startup recovery permits a controller upgrade without resizing the VM')
        if inventory['memory'] != expected or disk_flags:
            if inventory['status']=='Running':
                print('Verifying the VM worker is idle before its resource restart…',flush=True)
                result = subprocess.run([config['limactl'],'shell',config['vm'],'--','sudo','-n',
                    config['guest_python'],'-I','-B','-c',QUIET],capture_output=True,text=True,timeout=25)
                if result.returncode or result.stdout.strip()!='idle':
                    raise RuntimeError('VM is active or cannot be verified idle; no resize: '+result.stderr[-1500:])
                subprocess.run([config['limactl'],'stop','--tty=false',config['vm']],check=True,timeout=150)
                if vm_inventory(config).get('status')!='Stopped':
                    raise RuntimeError('VM did not stop cleanly; memory was not edited')
            print('Setting existing VM memory to '+str(memory)+' GiB; disk '+str(target['vm_disk_gib'])+' GiB…',flush=True)
            subprocess.run([config['limactl'],'edit','--tty=false','--memory='+str(memory),*disk_flags,config['vm']],
                           check=True,timeout=30)
        ensure_vm_running(target)
        actual = vm_inventory(target)
        if actual.get('status')!='Running' or actual.get('memory')!=expected:
            raise RuntimeError('VM did not confirm the requested memory; observer remains stopped')
        from .telemetry import vm
        guest = vm(target)
        if guest.get('status')!='running' or guest.get('memory_total',0)<(memory-1)*1024**3:
            raise RuntimeError('Guest memory did not confirm the requested allocation; observer remains stopped')
        verify_disk(args,target,actual,guest)
        atomic_json(config_path,target)
        return target
