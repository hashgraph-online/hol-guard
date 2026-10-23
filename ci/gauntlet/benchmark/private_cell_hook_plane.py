"""Normal installed OMP hooks/sinks in an explicitly versioned private cell.

The caller prepares fixed Root-owned cell inputs and allocates the private task.
This plane owns cell/image cleanup. Product JSON remains unauthenticated product
evidence; outside kernel observations do not make policy claims trusted.
"""
from __future__ import annotations

import base64
import hashlib
import os
import threading
import time
from pathlib import Path

from .contained_request_file import contained_request_file
from .contracts import canonical_json, digest, strict_json_loads
from .installed_guard import _PROBE
from .native_builtin_plane import decode_hook_response
from .native_contained_plane import _BACKEND
from .native_product_container import (
    process_identity,
    root_prefix_digest,
    validate_identity_claim,
    verify_product_boundary,
)
from .product_cell_image import ImageLease
from .product_cell_supervisor import ProductCell
from .runtime_bundle import inventory


class PrivateCellHookPlane:
    boundary_schema = 'private-cell-boundary.v1'
    supports_contained_execution = True  # Route implementation, not conformance.
    requires_contained_output_binding = True
    config_path = '/product/home/omp.json'
    home_path = '/product/home'

    def __init__(self, *, cell: ProductCell, image_lease: ImageLease, python: Path,
                 expected_tree_digest: str, expected_native_source: str,
                 expected_native_sha256: str, expected_bwrap_sha256: str,
                 package_version: str = '3.43.1',expected_prefix_digest: str | None = None):
        from .product_version import validate_version
        validate_version(package_version)
        if (os.geteuid()!=0 or not isinstance(cell,ProductCell) or not isinstance(image_lease,ImageLease)
                or cell.process is not None or cell.closed or not image_lease.owned
                or cell.system_root!=image_lease.root or cell.workspace_path!='/runtime/home/project'):
            raise ValueError('fresh Root cell and its owned declared dependency image lease required')
        for pin in (expected_tree_digest,expected_native_sha256,expected_bwrap_sha256):
            if type(pin) is not str or len(pin)!=64 or any(c not in '0123456789abcdef' for c in pin):
                raise ValueError('exact external runtime/backend SHA256 required')
        if (type(expected_native_source) is not str or len(expected_native_source)!=40
                or any(c not in '0123456789abcdef' for c in expected_native_source)):
            raise ValueError('exact separately compiled native source required')
        with (cell.stage/'runtime.json').open('rb') as stream:
            raw=stream.read(8193)
        if len(raw)>8192:
            raise ValueError('runtime declaration byte budget')
        specification=strict_json_loads(raw)
        if (type(specification) is not dict
                or set(specification)!={'schema','prefix','mountpoint','tree_digest'}
                or specification['schema']!='product-vm-runtime-mount.v1'
                or specification['tree_digest']!=expected_tree_digest
                or python!=Path(specification['mountpoint'])/'bin/python'
                or inventory(Path(specification['prefix']))[2]!=expected_tree_digest):
            raise ValueError('installed runtime differs from externally pinned cell mount')
        self.cell,self.image_lease,self.python=cell,image_lease,python
        self.runtime_prefix=Path(specification['prefix'])
        self.prefix_digest=root_prefix_digest(self.runtime_prefix)
        if expected_prefix_digest is not None and self.prefix_digest!=expected_prefix_digest:
            raise ValueError('installed runtime prefix differs from separately frozen digest')
        self.workspace_path=cell.workspace_path
        self.expected_tree_digest=expected_tree_digest
        self.source_sha,self.native_sha256=expected_native_source,expected_native_sha256
        self.bwrap_digest,self.package_version=expected_bwrap_sha256,package_version
        from .release_mcp_entry import LIBRARY_VERSIONS
        if package_version in LIBRARY_VERSIONS:
            self.home_path='/runtime/home'
        self.controller_identity=process_identity(os.getpid())
        self.product_identity=None
        self.identity_claim,self.backend_observation=None,None
        self.started,self.closed,self.cleanup_complete=False,False,False
        self.observations,self.hook_observations,self.executions=[],[],[]
        self.cleanup_errors=[]
        self.observation_bytes=0
        self._lock=threading.RLock()

    def _emit(self,collection,row):
        size=len(canonical_json(row).encode())
        if self.observation_bytes+size>12*1024**2 or len(collection)>=500:
            raise ValueError('private cell plane observation budget exhausted')
        self.observation_bytes+=size
        collection.append(row)

    def _command(self,*arguments):
        return [str(self.python),'-I','-B','-m','codex_plugin_scanner.cli','guard',*arguments]

    def start(self):
        if self.started or self.closed:
            raise ValueError('one-shot fresh private hook plane required')
        try:
            self.cell.start()
            self.product_identity=process_identity(self.cell.pid)
            self.product_user_namespace=os.readlink(f'/proc/{self.cell.pid}/ns/user')
            verify_product_boundary(self.product_identity,self.controller_identity)
            self._emit(self.observations,{'kind':'private-cell-boundary','schema':self.boundary_schema,
                'identity':self.product_identity,'observer_boot':self.cell.boot,
                'image_id':self.image_lease.image_id,'system_digest':self.cell.system_digest})
            result=self.cell.capture([str(self.python),'-I','-B','-c',_PROBE])
            if result.returncode:
                raise ValueError('installed private-cell Guard identity probe failed')
            self.identity_claim=strict_json_loads(result.stdout)
            validate_identity_claim(self.identity_claim,source_sha=self.source_sha,package_version=self.package_version)
            if self.identity_claim['runtime_sha256']!=self.native_sha256:
                raise ValueError('installed native bytes differ from frozen identity')
            backend=self.cell.capture(['/usr/bin/python3','-I','-B','-c',_BACKEND])
            if backend.returncode:
                raise ValueError('private cell backend probe failed')
            self.backend_observation=strict_json_loads(backend.stdout)
            if self.backend_observation['sha256']!=self.bwrap_digest:
                raise ValueError('private cell backend bytes differ from frozen identity')
            config=self.cell.capture(['/usr/bin/python3','-I','-B','-c',
                "from pathlib import Path;Path('/product/home/omp.json').write_text('{}\\n')"])
            if config.returncode:
                raise ValueError('private public OMP context initialization failed')
            # The task mount is under /runtime/home; Guard authorizes workspace
            # paths against the daemon's HOME and explicit Guard state parent.
            # Keep state in /product, while presenting the actual task home.
            daemon=self.cell.spawn(['/usr/bin/env','HOME=/runtime/home',*self._command('daemon','--serve','--guard-home','/product/guard',
                                                 '--home',self.home_path,'--port','18765',
                                                 '--workspace',self.workspace_path)])
            self.cell.release(daemon)
            self.cell._call('end_input',{'handle':daemon})
            deadline=time.monotonic()+60
            for _ in range(60):
                self._poll_daemon(daemon,deadline)
                status=self._daemon_status(deadline)
                self._poll_daemon(daemon,deadline)
                self._emit(self.observations,{'kind':'daemon-readiness','returncode':status.returncode,
                                             'stdout':status.stdout.decode(errors='replace')})
                if status.returncode==0 and strict_json_loads(status.stdout).get('running') is True:
                    break
                if time.monotonic()>=deadline:
                    raise TimeoutError('normal private-cell daemon readiness deadline')
                time.sleep(0.1)
            else:
                raise TimeoutError('normal private-cell daemon readiness attempts exhausted')
            from .private_cell_readiness import require_native_workspace
            require_native_workspace(self, deadline=deadline)
            self.started=True
            return self
        except BaseException:
            self.close()
            raise

    def _daemon_status(self,deadline):
        # The normal status CLI can perform native lifecycle work as the daemon
        # becomes ready. Its cold-start query must fit the shared setup budget,
        # rather than losing the entire cell at an unrelated ten-second cutoff.
        remaining=int(deadline-time.monotonic())
        if remaining<1:
            raise TimeoutError('normal private-cell daemon readiness deadline')
        return self.cell.capture(self._command('daemon','status','--json','--guard-home',
                                              '/product/guard','--home',self.home_path),
                                 timeout=min(30,remaining))

    def _poll_daemon(self,handle,deadline):
        chunk=self.cell._call('read',{'handle':handle,'wait_ms':0},deadline)
        output={name:base64.b64decode(chunk[name],validate=True) for name in ('stdout','stderr')}
        if any(output.values()) or chunk['returncode'] is not None:
            self._emit(self.observations,{'kind':'daemon-channel','returncode':chunk['returncode'],
                **{name:data.decode(errors='replace') for name,data in output.items()}})
        if chunk['returncode'] is not None:
            raise RuntimeError('normal private-cell daemon exited before readiness: '+str(chunk['returncode']))

    def verify_sdk_boundary(self,actual):
        if not self.started or self.closed or process_identity(self.cell.pid)!=self.product_identity:
            raise ValueError('live unchanged measured private-cell actor required')
        if (actual.get('uid_slots')!=[10001]*4 or actual.get('gid_slots')!=[10001]*4
                or actual.get('supplementary_groups') not in ([],[10001]) or actual.get('capability_sets')!=
                    dict.fromkeys(('CapEff','CapPrm','CapInh','CapBnd','CapAmb'),'0000000000000000')):
            raise ValueError('SDK retains saved IDs, extra groups or capabilities')
        verify_product_boundary(self.product_identity,self.controller_identity)
        if any(actual[field] in {self.controller_identity[field],self.product_identity[field]}
               for field in ('mount_namespace','pid_namespace','network_namespace')):
            raise ValueError('SDK must occupy separate agent/controller/product namespaces')

    def _capture(self,command,raw,*,timeout,cancelled=None):
        before=self.cell._pids()
        samples={}
        def observe():
            for pid in self.cell._pids()-before:
                try:
                    identity=process_identity(pid)
                    argv=Path(f'/proc/{pid}/cmdline').read_bytes()
                    user_namespace=os.readlink(f'/proc/{pid}/ns/user')
                except FileNotFoundError:
                    continue
                key=(pid,identity['start_time'],hashlib.sha256(argv).hexdigest())
                if key not in samples:
                    if len(samples)>=1000:
                        raise ValueError('private sink kernel sample budget exhausted')
                    if (identity['effective_uid']!=10004 or any(identity[field]==self.controller_identity[field]
                            for field in ('mount_namespace','pid_namespace','network_namespace'))
                            or (int(identity['effective_capabilities'],16)
                                and user_namespace==self.product_user_namespace)):
                        raise ValueError('sample escaped private product UID/namespace/host capability boundary')
                    samples[key]={'pid':pid,'identity':identity,'command_sha256':key[2],
                                  'user_namespace':user_namespace}
        try:
            result=self.cell.capture_execution(command,raw,timeout=timeout,cancelled=cancelled,observer=observe)
        except BaseException as error:
            if self.cell.closed:
                self.started=False
            self._emit(self.observations,{'kind':'actual-native-capture-failure',
                'exception_type':type(error).__name__,'command':command,'timeout_seconds':timeout,
                'kernel_process_samples':list(samples.values()),'cell_closed':self.cell.closed,
                'product_claims_authenticated':False})
            raise
        return result,list(samples.values())

    def invoke_hook(self,payload,*,timeout=30):
        if not self.started or self.closed or type(timeout) is not int or not 1<=timeout<=60:
            raise ValueError('live private hook plane and bounded deadline required')
        if (type(payload) is not dict or payload.get('config_path')!=self.config_path
                or payload.get('hook_event_name') not in {'UserPromptSubmit','PreToolUse','PostToolUse'}):
            raise ValueError('declared private hook context and supported event required')
        raw=(canonical_json(payload)+'\n').encode()
        if len(raw)>1024**2:
            raise ValueError('private hook payload byte budget')
        command=self._command('hook','--json','--harness','omp','--guard-home','/product/guard',
                              '--home',self.home_path,'--workspace',self.workspace_path)
        from .release_hook_entry import LIBRARY_VERSIONS, hook_command
        if getattr(self,'package_version',None) in LIBRARY_VERSIONS:
            command=hook_command(self.python,version=self.package_version,timeout=timeout,
                                 home=self.home_path,workspace=self.workspace_path)
        with self._lock:
            result,samples=self._capture(command,raw,timeout=timeout)
            response=decode_hook_response(result.stdout,returncode=result.returncode,event=payload.get('hook_event_name'))
            if response.get('decision') in {'deny','block'} and not response.get('required_execution_profile'):
                self._emit(self.observations,{'kind':'hook-denial-diagnostic',
                    'tool_input':payload.get('tool_input'),'response':response,
                    'stderr':result.stderr.decode(errors='replace')[-6000:],
                    'product_claims_authenticated':False})
            self._emit(self.hook_observations,{'sequence':len(self.hook_observations)+1,
                'timeout_seconds':timeout,
                'hook_event_name':payload['hook_event_name'],
                'payload_digest':digest(payload),'response':response,'response_digest':digest(response),
                'raw_response':strict_json_loads(result.stdout),'returncode':result.returncode,
                'stderr_digest':hashlib.sha256(result.stderr).hexdigest(),'kernel_process_samples':samples})
            return response

    def execute_contained(self,payload,*,timeout=300,cancelled=None):
        if (not self.started or self.closed or type(timeout) is not int or not 1<=timeout<=900
                or payload.get('hook_event_name')!='PreToolUse' or payload.get('tool_name')!='bash'):
            raise ValueError('live private executor and exact bounded Bash snapshot required')
        raw=canonical_json({'schema':'guard-contained-test-request.v1','workspace':self.workspace_path,
                            'payload':payload}).encode()
        if len(raw)>1024**2:
            raise ValueError('private contained snapshot byte budget')
        request_sha=hashlib.sha256(raw).hexdigest()
        with self._lock,contained_request_file(
                self.cell.stage/'state/home',raw,cleanup_errors=self.cleanup_errors) as name:
            command=self._command('execute-contained-test','--harness','omp','--guard-home','/product/guard',
                '--home',self.home_path,'--workspace',self.workspace_path,'--request-file',
                '/product/home/'+name+'/request.json','--request-sha256',request_sha,'--timeout-seconds',str(timeout))
            completed,samples=self._capture(command,b'',timeout=timeout+30,cancelled=cancelled)
            result={'schema_version':'1.0','exit_code':completed.returncode,
                'stdout':completed.stdout.decode(errors='replace'),'stderr':completed.stderr.decode(errors='replace'),
                'stdout_sha256':hashlib.sha256(completed.stdout).hexdigest(),
                'stderr_sha256':hashlib.sha256(completed.stderr).hexdigest(),
                'payload_digest':digest(payload),'request_sha256':request_sha,'kernel_process_samples':samples,
                'native_command':command,'product_claims_authenticated':False,'containment_conformance_established':False}
            self._emit(self.executions,result)
            return result

    def close(self):
        if self.closed and self.cleanup_complete:
            return
        try:
            self.cell.close()
        except Exception as error:
            self.cleanup_errors.append('cell: '+str(error))
        if self.cell.closed:
            try:
                self.image_lease.close()
            except Exception as error:
                self.cleanup_errors.append('image: '+str(error))
        self.closed=True
        self.started=False
        self.cleanup_complete=self.cell.closed and not self.image_lease.owned and not self.cleanup_errors
        if not self.cleanup_complete:
            raise RuntimeError('private hook plane cleanup incomplete: '+'; '.join(self.cleanup_errors))

    def declaration(self):
        return {'schema':'private-cell-hook-plane.v2','boundary_schema':self.boundary_schema,
            'kind':'private-cell-native-hook-plane','controller_identity':self.controller_identity,
            'profile':'private-cell-native-hooks-v1','workspace_path':self.workspace_path,
            'runtime_prefix':str(self.runtime_prefix),'prefix_digest':self.prefix_digest,
            'prefix_unchanged':root_prefix_digest(self.runtime_prefix)==self.prefix_digest,
            'runtime_tree_digest':self.expected_tree_digest,'source_sha':self.source_sha,
            'native_sha256':self.native_sha256,'bwrap_sha256':self.bwrap_digest,
            'image_id':self.image_lease.image_id,'system_digest':self.cell.system_digest,
            'artifact_manifest_digest':self.cell.artifact_manifest_digest,
            'product_user_namespace':getattr(self,'product_user_namespace',None),
            'initializer_sha256':self.cell.initializer_sha256,'task_digest':self.cell.task_digest,
            'task_mounts':self.cell.task_mounts,'network_profile':self.cell.network_profile,
            'cpu_profile':self.cell.cpu_profile,'idmap_runtime':self.cell.idmap_runtime,
            'wall_seconds':self.cell.wall_seconds,
            'identity_claim':self.identity_claim,'backend_observation':self.backend_observation,
            'observations':self.observations,'hooks':self.hook_observations,'executions':self.executions,
            'cell_observations':self.cell.observations,'cleanup_complete':self.cleanup_complete,
            'cleanup_errors':self.cleanup_errors,'product_claims_authenticated':False,
            'containment_execution_supported':False,'containment_conformance_established':False,
            'qualification_eligible':False}
