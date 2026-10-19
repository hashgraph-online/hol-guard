"""Root collector for persistent unprivileged cells on the owned product VM.

Actor replies never replace outside kernel observations. No Guard/product import
runs here. Session/task preparation and frozen artifact pins are trusted inputs.
"""
from __future__ import annotations

import base64
import hashlib
import os
import secrets
import select
import struct
import subprocess
import time
import uuid
from pathlib import Path

from .json_data import canonical_json, strict_json_loads
from .product_cell_protocol import CellCodec
from .product_vm_rootfs import _trusted
from .vm_bridge_io import BridgeIO
from .vm_bridge_rpc import BridgeClient

ENV={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','HOME':'/nonexistent'}


def command(argv,timeout=10,check=True):
    return subprocess.run(argv,capture_output=True,text=True,timeout=timeout,check=check,env=ENV)


def kernel_identity(pid):
    status=dict(line.split(':',1) for line in Path(f'/proc/{pid}/status').read_text().splitlines() if ':' in line)
    namespaces=('pid','mnt','net','ipc','uts','cgroup')
    return {'pid':pid,'status':status,'start_time':Path(f'/proc/{pid}/stat').read_text().rsplit(')',1)[1].split()[19],
            'namespaces':{name:os.readlink(f'/proc/{pid}/ns/{name}') for name in namespaces},
            'argv':[part.decode() for part in Path(f'/proc/{pid}/cmdline').read_bytes().rstrip(b'\0').split(b'\0')],
            'fds':{path.name:os.readlink(path) for path in Path(f'/proc/{pid}/fd').iterdir()},
            'lsm_label':Path(f'/proc/{pid}/attr/current').read_text().strip(),
            'mountinfo':Path(f'/proc/{pid}/mountinfo').read_text()}


def verify_actor(identity,*,profile,namespaces=None,filtered=True,allowed_cpu=None):
    status=identity['status']
    if (status['Uid'].split()!=['10004']*4 or status['Gid'].split()!=['10004']*4
            or status['Groups'].strip() or status['NoNewPrivs'].strip()!='1'
            or any(int(status[name],16) for name in ('CapEff','CapPrm','CapInh','CapBnd','CapAmb'))
            or identity['lsm_label']!=profile+' (enforce)'
            or (filtered and (status['Seccomp'].strip()!='2' or int(status['Seccomp_filters'])<2))
            or (namespaces is not None and identity['namespaces']!=namespaces)):
        raise ValueError('outside kernel actor identity/namespace/filter boundary mismatch')
    if allowed_cpu is not None and status.get('Cpus_allowed_list','').strip()!=str(allowed_cpu):
        raise ValueError('actual actor CPU affinity differs from narrowed resource profile')


def cpu_configuration(profile):
    if profile=='quota-v1':
        return None,[]
    if profile!='single-core-v1':
        raise ValueError('versioned cell CPU resource profile required')
    cpu=min(os.sched_getaffinity(0))
    return cpu,['--property=AllowedCPUs='+str(cpu),'--property=CPUAffinity='+str(cpu)]


class ProductCell:
    def __init__(self,stage: Path,artifacts: Path,*,initializer_sha256: str,
                 expected_manifest_digest: str,wall_seconds=600,network_profile='unix-only-v1',
                 expected_system_digest=None,idmap_runtime='ubuntu2404-product-v1',cpu_profile='quota-v1',
                 expected_task_digest=None):
        if network_profile not in {'unix-only-v1','private-loopback-v1'}:
            raise ValueError('separately declared cell network profile required')
        if os.geteuid()!=0 or type(wall_seconds) is not int or not 10<=wall_seconds<=4000:
            raise ValueError('Root collector and finite cell wall limit required')
        for path in (stage,artifacts):
            for parent in (path,*path.parents):
                _trusted(parent,directory=True)
        from .product_cell_system import read_system
        self.system_root,self.workspace_path=read_system(stage,expected_system_digest,trusted=_trusted)
        self.system_digest=expected_system_digest
        from .product_cell_task_mounts import read_mounts
        self.task_mounts=read_mounts(stage,expected_task_digest,workspace=self.workspace_path,trusted=_trusted)
        self.task_digest=expected_task_digest
        from .product_cell_idmap import verify
        verify(idmap_runtime,trusted=_trusted)
        self.idmap_runtime=idmap_runtime
        self.allowed_cpu,self.cpu_properties=cpu_configuration(cpu_profile)
        self.cpu_profile=cpu_profile
        manifest_path=artifacts/'manifest.json'
        _trusted(manifest_path)
        manifest_raw=manifest_path.read_bytes()
        if len(manifest_raw)>1024**2 or hashlib.sha256(manifest_raw).hexdigest()!=expected_manifest_digest:
            raise ValueError('cell artifacts differ from external manifest pin')
        manifest=strict_json_loads(manifest_raw)
        self.artifact_manifest_digest=expected_manifest_digest
        if (type(manifest) is not dict or set(manifest)!={'schema','files'}
                or manifest['schema']!='product-cell-artifacts.v1' or type(manifest['files']) is not dict
                or not 1<=len(manifest['files'])<=128):
            raise ValueError('invalid cell artifact manifest')
        public=set()
        for name,pin in manifest['files'].items():
            relative=Path(name)
            if relative.is_absolute() or '..' in relative.parts or str(relative)!=name:
                raise ValueError('noncanonical cell artifact path')
            source=artifacts/relative
            _trusted(source)
            if source.stat().st_size>2*1024**2 or hashlib.sha256(source.read_bytes()).hexdigest()!=pin:
                raise ValueError('cell artifact bytes differ from external pin')
            if relative.parts[0]=='public':
                target=stage/relative
                _trusted(target)
                if target.read_bytes()!=source.read_bytes():
                    raise ValueError('staged actor bootstrap differs from pinned source')
                public.add(relative.relative_to('public').as_posix())
        actual={path.relative_to(stage/'public').as_posix() for path in (stage/'public').rglob('*') if path.is_file()}
        if actual!=public:
            raise ValueError('undeclared or missing actor public bootstrap file')
        self.stage,self.artifacts=stage,artifacts
        self.initializer_sha256,self.wall_seconds=initializer_sha256,wall_seconds
        self.network_profile=network_profile
        self.name='hol-product-cell-'+uuid.uuid4().hex
        self.unit=self.name+'.service'
        self.process,self.client,self.cgroup,self.pid=None,None,None,None
        self.loaded,self.closed=False,False
        self.children={}
        self.observations=[]
        self.cleanup_errors=[]
        self.boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()

    def _marker(self,expected,timeout=5):
        result=bytearray()
        deadline=time.monotonic()+timeout
        while len(result)<len(expected):
            left=deadline-time.monotonic()
            if left<=0 or not select.select([self.process.stdout],[],[],left)[0]:
                raise TimeoutError('cell startup gate deadline')
            data=os.read(self.process.stdout.fileno(),len(expected)-len(result))
            if not data:
                raise EOFError('cell startup gate exited')
            result.extend(data)
        if result!=expected:
            raise ValueError('cell startup marker mismatch')

    def _pids(self):
        return {int(value) for value in (self.cgroup/'cgroup.procs').read_text().split()}

    def _find(self,local_pid):
        matches=[]
        for pid in self._pids():
            try:
                identity=kernel_identity(pid)
            except FileNotFoundError:
                continue
            if identity['status']['NSpid'].split()[-1]==str(local_pid):
                matches.append(identity)
        if len(matches)!=1:
            raise ValueError('unique actual owned namespace process required')
        return matches[0]

    def start(self):
        try:
            profile=self.stage/'cell.apparmor'
            profile.write_text((self.artifacts/'product_vm.apparmor').read_text().replace('HOL_PRODUCT_VM_PROFILE',self.name))
            command(['/usr/sbin/apparmor_parser','--add',str(profile)])
            self.loaded=True
            code=str(self.artifacts/'code')
            launch=('import sys;from pathlib import Path;sys.path.insert(0,sys.argv[1]);'
                    'from ci.gauntlet.benchmark.product_vm_rootfs import construct;'
                    'construct(Path(sys.argv[2]),initializer_digest=sys.argv[3],product_state=Path(sys.argv[2])/"state",'
                    'loopback_parent_namespace=sys.argv[4] or None,expected_system_digest=sys.argv[5] or None,'
                    'idmap_runtime=sys.argv[6],expected_task_digest=sys.argv[7] or None)')
            parent_net=os.readlink('/proc/self/ns/net') if self.network_profile=='private-loopback-v1' else ''
            argv=['/usr/bin/systemd-run','--quiet','--collect','--wait','--pipe','--unit='+self.unit,
                  '--property=MemoryMax=1G','--property=TasksMax=128','--property=CPUQuota=100%',
                  '--property=RuntimeMaxSec='+str(self.wall_seconds),'--property=TimeoutStopSec=2',
                  '--property=KillMode=control-group',*self.cpu_properties,'/usr/bin/aa-exec','-p',self.name,'--',
                  '/usr/bin/unshare','--mount','--pid','--net','--ipc','--uts','--cgroup','--fork','--kill-child=KILL',
                  '/usr/bin/python3','-I','-B','-c',launch,code,str(self.stage),self.initializer_sha256,parent_net,
                  self.system_digest or '',self.idmap_runtime,self.task_digest or '']
            self.process=subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                                          close_fds=True,env=ENV,bufsize=0,start_new_session=True)
            for stream in (self.process.stdin,self.process.stdout,self.process.stderr):
                os.set_blocking(stream.fileno(),False)
            self.cgroup=Path('/sys/fs/cgroup/system.slice')/self.unit
            self._marker(b'HOL_CELL_READY_V1\n')
            initial=self._find(1)
            verify_actor(initial,profile=self.name,filtered=False,allowed_cpu=self.allowed_cpu)
            if set(initial['fds'])!={'0','1','2'}:
                raise ValueError('initial cell inherited extra descriptors')
            if any(value==os.readlink('/proc/self/ns/'+name) for name,value in initial['namespaces'].items()):
                raise ValueError('cell did not isolate every declared namespace')
            self.pid=initial['pid']
            from .product_cell_task_mounts import observe_mounts
            self.observations.append({'kind':'idmapped-task-mounts','declaration_digest':self.task_digest,
                'mounts':observe_mounts(self.task_mounts,self.pid)})
            if self.network_profile=='private-loopback-v1':
                from .product_vm_network import observe
                self.observations.append({'kind':'private-loopback-network','topology':observe(self.pid)})
            self.observations.append({'kind':'before-cell-gate','identity':initial})
            os.write(self.process.stdin.fileno(),b'\x01')
            self._marker(b'HOL_CELL_FILTER_READY_V1\n')
            filtered=self._find(1)
            verify_actor(filtered,profile=self.name,namespaces=initial['namespaces'],allowed_cpu=self.allowed_cpu)
            self.namespaces=filtered['namespaces']
            self.observations.append({'kind':'filtered-cell','identity':filtered})
            ceilings={name:(self.cgroup/name).read_text().strip() for name in ('memory.max','pids.max','cpu.max')}
            if ceilings!={'memory.max':'1073741824','pids.max':'128','cpu.max':'100000 100000'}:
                raise ValueError('actual shared cell resource ceilings differ')
            if self.allowed_cpu is not None:
                effective=(self.cgroup/'cpuset.cpus.effective').read_text().strip()
                if effective!=str(self.allowed_cpu):
                    raise ValueError('actual cell cpuset differs from narrowed resource profile')
                ceilings['cpuset.cpus.effective']=effective
            self.observations.append({'kind':'resource-ceilings','values':ceilings,'cpu_profile':self.cpu_profile})
            key=secrets.token_bytes(32)
            session=str(uuid.uuid4())
            bootstrap=canonical_json({'schema':'product-cell-private-bootstrap.v1','session':session,
                                      'key_hex':key.hex(),'boot_id':self.boot}).encode()
            packet=struct.pack('!I',len(bootstrap))+bootstrap
            if os.write(self.process.stdin.fileno(),packet)!=len(packet):
                raise OSError('private cell bootstrap write incomplete')
            codec=CellCodec(key,session=session,local_role='cell-supervisor',local_boot=self.boot,peer_boot=self.boot)
            self.client=BridgeClient(BridgeIO(self.process.stdout.fileno(),self.process.stdin.fileno(),codec))
            hello=self.client.call('hello',{},timeout=5)
            if hello!={'schema':'product-cell-actor.v2','local_pid':1,'uid':10004,'gid':10004,
                       'limits':{'active_children':64,'total_spawns':1024,'read_wait_ms':100}}:
                raise ValueError('cell actor hello mismatch')
            return self
        except BaseException:
            self.close()
            raise

    def _call(self,operation,payload,deadline=None):
        left=5 if deadline is None else min(5,deadline-time.monotonic())
        if left<=0:
            raise TimeoutError('outside collector operation deadline exceeded')
        return self.client.call(operation,payload,timeout=left)

    def spawn(self,argv,*,deadline=None):
        result=self._call('spawn',{'argv':argv},deadline)
        if set(result)!={'handle','local_pid','gate_ready'} or result['gate_ready'] is not True:
            raise ValueError('invalid actor process gate reply')
        identity=self._find(result['local_pid'])
        verify_actor(identity,profile=self.name,namespaces=self.namespaces,allowed_cpu=self.allowed_cpu)
        expected=['/usr/bin/python3','-I','-B','/public/ci/gauntlet/benchmark/product_exec_gate.py',*argv]
        if identity['argv']!=expected or set(identity['fds'])!={'0','1','2'}:
            raise ValueError('actual gated process argv/descriptors mismatch')
        self.children[result['handle']]=identity
        self.observations.append({'kind':'gated-product-process','handle':result['handle'],'identity':identity})
        return result['handle']

    def release(self,handle,*,deadline=None):
        original=self.children[handle]
        actual=kernel_identity(original['pid'])
        if (actual['start_time']!=original['start_time'] or actual['pid'] not in self._pids()
                or actual['argv']!=original['argv'] or set(actual['fds'])!={'0','1','2'}):
            raise ValueError('owned product process identity changed before release')
        verify_actor(actual,profile=self.name,namespaces=self.namespaces,allowed_cpu=self.allowed_cpu)
        return self._call('release',{'handle':handle},deadline)

    def capture(self,argv,raw=b'',*,timeout=30):
        return self._capture(argv,raw,timeout=timeout,maximum=60)

    def capture_execution(self,argv,raw=b'',*,timeout=330,cancelled=None,observer=None):
        """Root-internal long sink capture; the management wire keeps its60s cap."""
        return self._capture(argv,raw,timeout=timeout,maximum=min(930,self.wall_seconds),
                             cancelled=cancelled,observer=observer)

    def _capture(self,argv,raw,*,timeout,maximum,cancelled=None,observer=None):
        if type(timeout) is not int or not 1<=timeout<=maximum or type(raw) is not bytes or len(raw)>8*1024**2:
            raise ValueError('bounded cell capture inputs required')
        deadline=time.monotonic()+timeout
        buffers=[bytearray(),bytearray()]
        try:
            if cancelled is not None and cancelled():
                raise InterruptedError('outside collector product capture cancelled before admission')
            handle=self.spawn(argv,deadline=deadline)
            self.release(handle,deadline=deadline)
            offset=0
            ended=False
            while True:
                if cancelled is not None and cancelled():
                    raise InterruptedError('outside collector product capture cancelled')
                if time.monotonic()>=deadline:
                    raise TimeoutError('outside collector product deadline exceeded')
                if observer is not None:
                    observer()
                if offset<len(raw):
                    encoded=base64.b64encode(raw[offset:offset+65536]).decode('ascii')
                    result=self._call('write',{'handle':handle,'data':encoded},deadline)
                    offset+=result['written']
                elif not ended:
                    self._call('end_input',{'handle':handle},deadline)
                    ended=True
                chunk=self._call('read',{'handle':handle,'wait_ms':0 if offset<len(raw) else 100},deadline)
                for index,name in enumerate(('stdout','stderr')):
                    buffers[index].extend(base64.b64decode(chunk[name],validate=True))
                if sum(map(len,buffers))>8*1024**2:
                    raise ValueError('outside collector product output byte budget')
                if chunk['returncode'] is not None and chunk['stdout_eof'] and chunk['stderr_eof']:
                    self.retire(handle,deadline=deadline)
                    return subprocess.CompletedProcess(argv,chunk['returncode'],bytes(buffers[0]),bytes(buffers[1]))
                time.sleep(0.005)
        except BaseException as error:
            self.observations.append({'kind':'capture-failure','exception_type':type(error).__name__,
                'argv':argv,'stdout':base64.b64encode(buffers[0]).decode('ascii'),
                'stderr':base64.b64encode(buffers[1]).decode('ascii')})
            self.close()
            raise

    def retire(self,handle,*,deadline=None):
        original=self.children[handle]
        if Path(f'/proc/{original["pid"]}').exists():
            raise ValueError('product process survived terminal actor reply')
        result=self._call('retire',{'handle':handle},deadline)
        if result!={'retired':True}:
            raise ValueError('invalid owned process retirement reply')
        del self.children[handle]
        self.observations.append({'kind':'retired-product-process','handle':handle,'pid':original['pid']})
        return result

    def close(self):
        if self.closed:
            return
        if self.process is not None:
            try:
                command(['/usr/bin/systemctl','stop',self.unit],timeout=5,check=False)
            except (OSError,subprocess.SubprocessError) as error:
                self.cleanup_errors.append(type(error).__name__+': '+str(error))
            try:
                try:
                    self.process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=2)
                errors=bytearray()
                while len(errors)<65536 and select.select([self.process.stderr],[],[],0)[0]:
                    chunk=os.read(self.process.stderr.fileno(),min(65536-len(errors),65536))
                    if not chunk:
                        break
                    errors.extend(chunk)
                self.observations.append({'kind':'cell-stderr','data':errors.decode(errors='replace')})
            except (OSError,subprocess.SubprocessError) as error:
                self.cleanup_errors.append(type(error).__name__+': '+str(error))
            for stream in (self.process.stdin,self.process.stdout,self.process.stderr):
                stream.close()
            if self.cgroup.exists():
                self.cleanup_errors.append('owned product cgroup survived stop')
        if self.loaded:
            try:
                command(['/usr/sbin/apparmor_parser','--remove',str(self.stage/'cell.apparmor')])
                self.loaded=False
            except (OSError,subprocess.SubprocessError) as error:
                self.cleanup_errors.append(type(error).__name__+': '+str(error))
        self.observations.append({'kind':'terminal-cleanup',
            'cgroup_absent':self.cgroup is None or not self.cgroup.exists(),
            'rootfs_mount_absent':str(self.stage/'rootfs') not in Path('/proc/self/mountinfo').read_text()})
        if not self.observations[-1]['rootfs_mount_absent']:
            self.cleanup_errors.append('owned product rootfs mount survived stop')
        if self.cleanup_errors:
            raise RuntimeError('product cell cleanup incomplete: '+'; '.join(self.cleanup_errors))
        self.closed=True
