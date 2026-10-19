"""Unprivileged PID1 cell service; never collector/signing/model authority.

Only trusted public code is imported in this process. Product commands execute
as separately gated children with inherited seccomp/LSM/resource restrictions.
All replies are actor data, not outside kernel observations or policy truth.
"""
from __future__ import annotations

import base64
import ctypes
import os
import select
import signal
import subprocess
import time
import uuid
from pathlib import Path

from .json_data import strict_json_loads
from .product_cell_layout import load_layout
from .product_cell_protocol import CellCodec, read_bootstrap
from .product_vm_seccomp import install
from .vm_bridge_io import BridgeIO
from .vm_bridge_rpc import serve_one

GATE='/public/ci/gauntlet/benchmark/product_exec_gate.py'
READY=b'HOL_PRODUCT_EXEC_READY_V1\n'
# Bound glibc's per-thread arena reservation instead of widening RLIMIT_AS.
# Actual 1 GiB controls otherwise exhausted address space after 17 threads.
PRODUCT_ENV={'PATH':'/usr/bin:/bin','HOME':'/product/home','LANG':'C.UTF-8',
             'MALLOC_ARENA_MAX':'2'}
LIMITS={'active_children':64,'total_spawns':1024,'read_wait_ms':100}


class CellActor:
    def __init__(self):
        self.children={}
        self.orphans_reaped=0
        self.spawn_count=0
        self.layout=load_layout()

    def _get(self,payload,fields):
        if type(payload) is not dict or set(payload)!=fields or payload.get('handle') not in self.children:
            raise ValueError('exact owned cell process handle/fields required')
        return self.children[payload['handle']]

    def hello(self,payload):
        if payload:
            raise ValueError('hello accepts no arguments')
        return {'schema':'product-cell-actor.v2','local_pid':os.getpid(),'uid':os.getuid(),'gid':os.getgid(),
                'limits':dict(LIMITS)}

    def spawn(self,payload):
        if type(payload) is not dict or set(payload)!={'argv'}:
            raise ValueError('exact cell spawn fields required')
        argv=payload['argv']
        if (type(argv) is not list or not 1<=len(argv)<=128
                or any(type(arg) is not str or '\x00' in arg for arg in argv)
                or not argv[0].startswith('/') or sum(len(arg.encode()) for arg in argv)>1024**2
                or len(self.children)>=LIMITS['active_children'] or self.spawn_count>=LIMITS['total_spawns']):
            raise ValueError('bounded absolute unprivileged product argv required')
        self.spawn_count+=1
        process=subprocess.Popen(['/usr/bin/python3','-I','-B',GATE,*argv],stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,close_fds=True,start_new_session=True,
            cwd=self.layout['workspace'],env={**PRODUCT_ENV,'PATH':self.layout['path']},bufsize=0)
        handle=str(uuid.uuid4())
        item={'process':process,'argv':argv,'released':False,'input_bytes':0,'output_bytes':0,
              'stdout_eof':False,'stderr_eof':False}
        self.children[handle]=item
        for stream in (process.stdin,process.stdout,process.stderr):
            os.set_blocking(stream.fileno(),False)
        marker=bytearray()
        deadline=time.monotonic()+3
        while len(marker)<len(READY):
            left=deadline-time.monotonic()
            if left<=0 or not select.select([process.stdout],[],[],left)[0]:
                raise TimeoutError('trusted child did not reach measurement gate')
            data=os.read(process.stdout.fileno(),len(READY)-len(marker))
            if not data:
                raise EOFError('trusted child gate exited')
            marker.extend(data)
        if marker!=READY:
            raise ValueError('trusted child gate marker mismatch')
        return {'handle':handle,'local_pid':process.pid,'gate_ready':True}

    def release(self,payload):
        item=self._get(payload,{'handle'})
        if item['released']:
            raise ValueError('product process gate is single use')
        if os.write(item['process'].stdin.fileno(),b'\x01')!=1:
            raise OSError('product process gate made no progress')
        item['released']=True
        return {'released':True}

    def write(self,payload):
        item=self._get(payload,{'handle','data'})
        if not item['released'] or type(payload['data']) is not str or len(payload['data'])>350000:
            raise ValueError('bounded product stdin requires released process')
        data=base64.b64decode(payload['data'],validate=True)
        if len(data)>256*1024 or item['input_bytes']+len(data)>8*1024**2:
            raise ValueError('product stdin byte budget')
        try:
            count=os.write(item['process'].stdin.fileno(),data) if data else 0
        except BlockingIOError:
            count=0
        item['input_bytes']+=count
        return {'written':count}

    def end_input(self,payload):
        item=self._get(payload,{'handle'})
        if not item['released']:
            raise ValueError('unreleased gate cannot receive product EOF')
        item['process'].stdin.close()
        return {'stdin_closed':True}

    def read(self,payload):
        if type(payload) is not dict or set(payload) not in ({'handle'},{'handle','wait_ms'}):
            raise ValueError('exact bounded product read fields required')
        wait=payload.get('wait_ms',0)
        if type(wait) is not int or not 0<=wait<=LIMITS['read_wait_ms']:
            raise ValueError('bounded product read wait required')
        item=self._get(payload,set(payload))
        readers=[getattr(item['process'],name) for name in ('stdout','stderr') if not item[name+'_eof']]
        if readers and wait:
            select.select(readers,[],[],wait/1000)
        output={}
        for name in ('stdout','stderr'):
            if item[name+'_eof']:
                output[name]=''
                continue
            stream=getattr(item['process'],name)
            try:
                data=os.read(stream.fileno(),32768)
                if not data:
                    item[name+'_eof']=True
            except BlockingIOError:
                data=b''
            item['output_bytes']+=len(data)
            if item['output_bytes']>8*1024**2:
                raise ValueError('product combined output byte budget')
            output[name]=base64.b64encode(data).decode('ascii')
        return {**output,'stdout_eof':item['stdout_eof'],'stderr_eof':item['stderr_eof'],
                'returncode':item['process'].poll(),'output_bytes':item['output_bytes']}

    def retire(self,payload):
        item=self._get(payload,{'handle'})
        if (not item['released'] or item['process'].poll() is None
                or not item['stdout_eof'] or not item['stderr_eof']):
            raise ValueError('only terminal drained product processes can retire')
        for stream in (item['process'].stdin,item['process'].stdout,item['process'].stderr):
            if not stream.closed:
                stream.close()
        del self.children[payload['handle']]
        return {'retired':True}

    def reap(self):
        while True:
            try:
                pid,status=os.waitpid(-1,os.WNOHANG)
            except ChildProcessError:
                break
            if not pid:
                break
            process=next((item['process'] for item in self.children.values() if item['process'].pid==pid),None)
            if process is None:
                self.orphans_reaped+=1
            else:
                process.returncode=os.waitstatus_to_exitcode(status)

    def close(self,payload):
        if payload:
            raise ValueError('close accepts no arguments')
        for item in self.children.values():
            process=item['process']
            if process.poll() is None:
                process.kill()
                process.wait(timeout=1)
            for stream in (process.stdin,process.stdout,process.stderr):
                if not stream.closed:
                    stream.close()
        return {'closed':True,'outside_descendant_cleanup_required':True}


def main():
    if os.getpid()!=1 or os.getuid()!=10004 or os.getgid()!=10004:
        raise ValueError('unprivileged private PID1 cell actor required')
    libc=ctypes.CDLL(None,use_errno=True)
    if libc.prctl(4,0,0,0,0)!=0:
        raise OSError(ctypes.get_errno(),'lock cell actor dumpability')
    declaration=Path('/etc/hol-cell-network-profile')
    network_profile=declaration.read_text().strip() if declaration.exists() else 'unix-only-v1'
    install(Path('/public/product_vm_seccomp_oci_v1.json').read_bytes(),network_profile=network_profile)
    signal.signal(signal.SIGCHLD,lambda *_:None)
    for name in ('home','guard'):
        (Path('/product')/name).mkdir(mode=0o700,exist_ok=True)
    (Path('/product/guard')/'config.toml').write_text('mode="enforce"\nsync=false\ntelemetry=false\n'
        'desktop_notifications=false\napproval_wait_timeout_seconds=1\n')
    os.write(1,b'HOL_CELL_FILTER_READY_V1\n')
    bootstrap=strict_json_loads(read_bootstrap(0))
    if (type(bootstrap) is not dict or set(bootstrap)!={'schema','key_hex','session','boot_id'}
            or bootstrap['schema']!='product-cell-private-bootstrap.v1'
            or bootstrap['boot_id']!=Path('/proc/sys/kernel/random/boot_id').read_text().strip()):
        raise ValueError('private cell bootstrap mismatch')
    codec=CellCodec(bytes.fromhex(bootstrap['key_hex']),session=bootstrap['session'],local_role='cell-actor',
                    local_boot=bootstrap['boot_id'],peer_boot=bootstrap['boot_id'])
    channel=BridgeIO(0,1,codec)
    actor=CellActor()
    methods={name:getattr(actor,name) for name in
             ('hello','spawn','release','write','end_input','read','retire','close')}
    try:
        for _ in range(10000):
            operation=serve_one(channel,methods,deadline=time.monotonic()+4000)
            actor.reap()
            if operation=='close':
                break
    finally:
        actor.close({})


if __name__=='__main__':
    main()
