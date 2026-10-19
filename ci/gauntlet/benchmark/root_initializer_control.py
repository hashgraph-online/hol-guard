"""Root-only bounded initializer controls; never a protected execution backend."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import select
import subprocess
import time
import uuid
from pathlib import Path

from .ci_runner import private_state, write_new
from .contracts import digest
from .native_product_container import _podman, process_identity

IMAGE = 'sha256:fb372d771d49494e81b7f853d51ce7a6ae208013015a1b237f0becdbdc301dda'
BWRAP = 'a524f7613e4467041d3155c30df873d84766220b91f5aa373611eeea714a043a'
HERE = Path(__file__).resolve().parent
MASK_FILES = ('kcore','keys','latency_stats','timer_list')
MASK_DIRS = ('acpi','scsi')


class InitializerStartError(RuntimeError):
    def __init__(self,output,status):
        super().__init__('initializer did not reach measured blocked gate')
        self.output,self.status = bytes(output),bytes(status)


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream,'sha256').hexdigest()


def command(argv, *, timeout=15, check=True):
    return subprocess.run(argv,check=check,timeout=timeout,capture_output=True,text=True,
                          env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','HOME':'/nonexistent','LANG':'C'})


def sysctls():
    return {str(path):path.read_text() if path.exists() else None for path in map(Path,
        ('/proc/sys/kernel/unprivileged_userns_clone','/proc/sys/kernel/apparmor_restrict_unprivileged_userns',
         '/proc/sys/user/max_user_namespaces'))}


def _ready(process, status_fd):
    output,status = bytearray(),bytearray()
    os.set_blocking(process.stdout.fileno(),False)
    os.set_blocking(status_fd,False)
    deadline = time.monotonic()+8
    while time.monotonic()<deadline and process.poll() is None:
        ready,_,_ = select.select([process.stdout.fileno(),status_fd],[],[],0.05)
        for fd in ready:
            data = os.read(fd,16384)
            target = output if fd==process.stdout.fileno() else status
            target.extend(data)
            if len(output)+len(status)>65536:
                raise ValueError('initializer handshake exceeds bound')
        rows = [json.loads(row) for row in status.splitlines() if row.startswith(b'{') and row.endswith(b'}')]
        pids = [row['child-pid'] for row in rows if 'child-pid' in row]
        if pids and b'HOL_INITIALIZER_READY_V1\n' in output:
            return pids[0],bytes(output),bytes(status)
    raise InitializerStartError(output,status)


def _measure(pid, profile, unit):
    path = Path(f'/proc/{pid}')
    status = dict(line.split(':',1) for line in (path/'status').read_text().splitlines() if ':' in line)
    identity = process_identity(pid)
    if (status['Uid'].split()!=['10004']*4 or status['Gid'].split()!=['10004']*4
            or status['Groups'].strip() or status['NoNewPrivs'].strip()!='1'
            or any(int(status[name].strip(),16)!=0 for name in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb'))
            or status['NSpid'].split()[-1]!='1'):
        raise ValueError('actual kernel privilege drop differs from initializer contract')
    descriptors = {fd.name:os.readlink(fd) for fd in (path/'fd').iterdir()}
    if set(descriptors)!={'0','1','2'}:
        raise ValueError('initializer retained undeclared descriptor authority')
    label = (path/'attr/current').read_text().strip()
    if not label.startswith(profile+' '):
        raise ValueError('actual scoped LSM identity changed')
    namespaces = {name:os.readlink(path/'ns'/name) for name in ('mnt','pid','net','ipc','uts')}
    controller_namespaces = {name:os.readlink('/proc/self/ns/'+name) for name in namespaces}
    if any(value==controller_namespaces[name] for name,value in namespaces.items()):
        raise ValueError('initializer shares a forbidden controller namespace')
    cgroup_relative = next(row.split(':',2)[2] for row in (path/'cgroup').read_text().splitlines()
                           if row.startswith('0::'))
    if not cgroup_relative.endswith('/'+unit):
        raise ValueError('initializer escaped its owned service cgroup')
    cgroup = Path('/sys/fs/cgroup')/cgroup_relative.lstrip('/')
    limits = {name:(cgroup/name).read_text().strip() for name in ('memory.max','pids.max','cpu.max')}
    quota,period = limits['cpu.max'].split()
    if limits['memory.max']!='1073741824' or limits['pids.max']!='128' or quota=='max' or int(quota)>int(period):
        raise ValueError('actual cgroup limits exceed declared control bounds')
    mountinfo = (path/'mountinfo').read_text()
    mounts = {row.split()[4]:row for row in mountinfo.splitlines()}
    if 'ro' not in mounts['/'].split()[5].split(','):
        raise ValueError('actual initializer root filesystem is not readonly')
    for name in (*MASK_FILES,*MASK_DIRS):
        if '/proc/'+name not in mounts:
            raise ValueError('declared proc mask is absent')
    return {'identity':identity,'status':status,'descriptors':descriptors,'namespaces':namespaces,
            'controller_identity':process_identity(os.getpid()),'controller_namespaces':controller_namespaces,
            'lsm_label':label,'cgroup':str(cgroup),'limits':limits,'mountinfo':mountinfo,
            'rlimits':(path/'limits').read_text()}


def _case(root, image_root, *, profile, gate, program):
    unit = 'hol-initializer-'+uuid.uuid4().hex+'.service'
    case = root/unit.removesuffix('.service')
    case.mkdir(mode=0o700)
    temporary = case/'temporary'
    temporary.mkdir(mode=0o700)
    os.chown(temporary,10004,10004)
    bwrap = [str(image_root/'usr/bin/bwrap'),'--die-with-parent','--new-session',
             '--unshare-pid','--as-pid-1','--unshare-net','--unshare-ipc','--unshare-uts','--unshare-cgroup']
    for name in ('usr','etc','var','opt'):
        if (image_root/name).is_dir():
            bwrap += ['--ro-bind',str(image_root/name),'/'+name]
    for name in ('bin','sbin','lib','lib32','lib64'):
        source = image_root/name
        if source.is_symlink():
            bwrap += ['--symlink',os.readlink(source),'/'+name]
        elif source.is_dir():
            bwrap += ['--ro-bind',str(source),'/'+name]
    bwrap += ['--proc','/proc','--dev','/dev',
             '--bind',str(temporary),'/tmp','--tmpfs','/run',
             '--ro-bind',str(root/'initializer'),'/initializer',
             '--ro-bind',str(root/'probe.py'),'/probe.py',
             '--json-status-fd','3','--clearenv']
    for name in MASK_FILES:
        bwrap += ['--ro-bind','/dev/null','/proc/'+name]
    for name in MASK_DIRS:
        bwrap += ['--tmpfs','/proc/'+name,'--remount-ro','/proc/'+name]
    bwrap += ['--remount-ro','/','--chdir','/','--','/initializer',*program]
    # systemd supplies the bounded, owned cgroup before the trusted initializer.
    # No product/task capabilities or syscall/LSM bypass flags are supplied.
    argv = ['/usr/bin/systemd-run','--quiet','--collect','--wait','--pipe','--unit='+unit,
            '--property=MemoryMax=1G','--property=TasksMax=128','--property=CPUQuota=100%',
            '--property=RuntimeMaxSec=20','--property=TimeoutStopSec=2','--property=KillMode=control-group',
            '/usr/bin/python3','-I','-B','-c',
            'import os,sys;os.dup2(2,3,inheritable=True);os.execv(sys.argv[1],sys.argv[1:])',
            '/usr/bin/aa-exec','-p',profile,'--',*bwrap]
    record = {'unit':unit,'gate':gate,'argv':argv,'released':False,'qualification_eligible':False}
    process = None
    pid,observed = None,None
    try:
        started = time.monotonic()
        process = subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
            start_new_session=True,bufsize=0,
            env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','HOME':'/nonexistent'})
        pid,output,status = _ready(process,process.stderr.fileno())
        observed = _measure(pid,profile,unit)
        record['kernel_before_gate'] = observed
        write_new(case/'kernel-before-gate.json',observed)
        if gate=='cancel':
            command(['/usr/bin/systemctl','stop',unit],timeout=8)
        elif gate=='deadline':
            process.wait(timeout=25)  # Keep the gate open until the real service deadline expires.
        else:
            if gate!='eof':
                process.stdin.write(b'\x01' if gate=='allow' else b'\x00')
                process.stdin.flush()
                record['released'] = gate=='allow'
            process.stdin.close()
            process.stdin = None
        os.set_blocking(process.stdout.fileno(),True)
        os.set_blocking(process.stderr.fileno(),True)
        rest,errors = process.communicate(timeout=25)
        output += rest
        if len(output)+len(errors)>256*1024:
            raise ValueError('trusted capability output exceeds bound')
        record.update(returncode=process.returncode,stdout=output.decode(errors='replace'),
                      stderr=errors.decode(errors='replace'),status_records=status.decode(errors='replace'),
                      elapsed_seconds=time.monotonic()-started)
        if ((gate=='allow' and process.returncode!=0) or
                (gate in {'eof','wrong'} and process.returncode!=126) or
                (gate in {'cancel','deadline'} and process.returncode==0) or
                (gate=='deadline' and record['elapsed_seconds']<19)):
            raise ValueError('actual gated execution outcome differs from declared control')
        if program[0]=='/usr/bin/touch':
            marker = temporary/'execution-marker'
            info = marker.lstat() if marker.exists() else None
            record['execution_marker'] = None if info is None else {
                'uid':info.st_uid,'gid':info.st_gid,'mode':info.st_mode&0o777,'bytes':info.st_size}
            if ((gate=='allow' and record['execution_marker']!={'uid':10004,'gid':10004,'mode':0o600,'bytes':0})
                    or (gate!='allow' and info is not None)):
                raise ValueError('independent command effect differs from its controller gate')
    except Exception as error:
        record['error'] = type(error).__name__+': '+str(error)
        if isinstance(error,InitializerStartError):
            record['startup_stdout'] = error.output.decode(errors='replace')
            record['startup_status_stderr'] = error.status.decode(errors='replace')
        if process is not None and process.poll() is not None:
            rest,errors = process.communicate(timeout=2)
            record['terminal_stdout'] = rest.decode(errors='replace')[:65536]
            record['terminal_stderr'] = errors.decode(errors='replace')[:65536]
    finally:
        # Stop only this newly generated owned unit; systemd kills its descendants.
        stopped = command(['/usr/bin/systemctl','stop',unit],timeout=8,check=False)
        record['stop_result'] = {'returncode':stopped.returncode,'stderr':stopped.stderr}
        if process is not None:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=5)
            for stream in (process.stdin,process.stdout,process.stderr):
                if stream is not None:
                    stream.close()
        still_same = False
        if pid is not None and Path(f'/proc/{pid}').exists():
            still_same = observed is None or process_identity(pid)==observed['identity']
        cgroup_path = Path(observed['cgroup']) if observed else Path('/sys/fs/cgroup/system.slice')/unit
        cgroup_gone = not cgroup_path.exists()
        state = command(['/usr/bin/systemctl','show',unit,'--property=LoadState','--property=ActiveState'],
                        check=False)
        record['unit_after_cleanup'] = state.stdout
        terminal = not any('ActiveState='+value in state.stdout for value in
                           ('active','activating','deactivating','reloading'))
        record['owned_cleanup_complete'] = not still_same and cgroup_gone and terminal
        write_new(case/'result.json',record)
    return record


def run(root, *, expected_source_sha256):
    source = HERE/'root_executor_initializer.c'
    if sha(source)!=expected_source_sha256:
        raise ValueError('initializer source differs from external pin')
    root = private_state(root,create=True)
    before = sysctls()
    profile = 'hol-initializer-'+uuid.uuid4().hex
    loaded,image_root = False,None
    record = {'schema':'root-initializer-capability-control.v1','source_sha256':expected_source_sha256,
              'qualification_eligible':False,'protected_execution_eligible':False,
              'guard_exercised':False,'model_exercised':False,'candidate_code_executed':False,
              'scope':'trusted initializer/capability control; not a product executor',
              'limitations':['no Guard imports or candidate/task code',
                  'no seccomp equivalence or task idmapping claim',
                  'Root initialization alone is not conformance'],
              'sysctls_before':before,'cases':[]}
    write_new(root/'plan.json',{'schema':'root-initializer-control-plan.v1',
        'source_sha256':expected_source_sha256,'controller_sha256':sha(Path(__file__)),
        'maximum_namespace_cases':6,'service_wall_seconds':20,'stop_grace_seconds':2,
        'memory_bytes':1073741824,'pids':128,'cpu_cores':1,'concurrency':1,
        'model_requests':0,'guard_imports':False,'candidate_code_permitted':False})
    try:
        inputs = [('initializer.c',source.read_bytes()),('probe.py',(HERE/'root_initializer_probe.py').read_bytes())]
        for name,data in inputs:
            with (root/name).open('xb') as stream:
                stream.write(data)
            (root/name).chmod(0o444)
        if sha(root/'initializer.c')!=expected_source_sha256:
            raise ValueError('copied initializer source differs before compilation')
        record['controller_sha256'] = sha(Path(__file__))
        record['probe_sha256'] = sha(root/'probe.py')
        compiler = Path('/usr/bin/cc').resolve()
        record['compiler'] = {'path':str(compiler),'sha256':sha(compiler),
                              'version':command([str(compiler),'--version']).stdout}
        build = command([str(compiler),'-O2','-Wall','-Wextra','-Werror','-static',
            '-fstack-protector-strong','-D_FORTIFY_SOURCE=3',str(root/'initializer.c'),'-o',str(root/'initializer')],timeout=60)
        (root/'initializer').chmod(0o555)
        record['build'] = {'stdout':build.stdout,'stderr':build.stderr,'initializer_sha256':sha(root/'initializer')}
        ordinary = command([str(root/'initializer'),'/usr/bin/true'],check=False)
        record['outside_pid_namespace'] = {'returncode':ordinary.returncode,'stderr':ordinary.stderr}
        assert ordinary.returncode==126
        profile_path = root/'control.apparmor'
        profile_path.write_text((HERE/'developer_browser.apparmor').read_text().replace('HOL_WORKER_PROFILE',profile))
        command(['/usr/sbin/apparmor_parser','--add',str(profile_path)])
        loaded = True
        image_root = Path(_podman('image','mount',IMAGE).stdout.strip())
        if sha(image_root/'usr/bin/bwrap')!=BWRAP:
            raise ValueError('actual control image Bubblewrap differs from frozen pin')
        record['image_id'],record['bwrap_sha256'] = IMAGE,BWRAP
        marker = ['/usr/bin/touch','/tmp/execution-marker']
        for gate,program in [('allow',marker),('eof',marker),
                             ('wrong',marker),('cancel',marker),('deadline',marker),
                             ('allow',['/usr/bin/python3','-I','-B','/probe.py'])]:
            result = _case(root,image_root,profile=profile,gate=gate,program=program)
            record['cases'].append(result)
            print(json.dumps({'unit':result['unit'],'gate':gate,'error':result.get('error'),
                              'returncode':result.get('returncode'),'cleanup':result['owned_cleanup_complete']}),flush=True)
            if result.get('error') or not result['owned_cleanup_complete']:
                raise ValueError('initializer control failed; retained without further cases')
        probe = json.loads(record['cases'][-1]['stdout'].splitlines()[-1])
        assert probe['schema']=='root-initializer-nested-probe.v1'
        record['nested_probe'] = probe
        record['control_completed'] = True
    except Exception as error:
        record['error'] = type(error).__name__+': '+str(error)
        record['control_completed'] = False
    finally:
        cleanup_errors = []
        unresolved = any(not case['owned_cleanup_complete'] for case in record['cases'])
        if unresolved:
            cleanup_errors.append('owned unit cleanup unresolved; retain its LSM profile/image mount')
        if image_root is not None and not unresolved:
            try:
                _podman('image','unmount',IMAGE)
            except Exception as error:
                cleanup_errors.append('image: '+type(error).__name__+': '+str(error))
        if loaded and not unresolved:
            try:
                command(['/usr/sbin/apparmor_parser','--remove',str(root/'control.apparmor')])
            except Exception as error:
                cleanup_errors.append('LSM: '+type(error).__name__+': '+str(error))
        record['cleanup_errors'] = cleanup_errors
        if cleanup_errors:
            record['control_completed'] = False
        record['sysctls_after'] = sysctls()
        record['global_sysctls_unchanged'] = record['sysctls_after']==before
        record['record_digest'] = digest(record)
        write_new(root/'control.json',record)
    print(json.dumps({key:value for key,value in record.items() if key not in {'cases','compiler'}}),flush=True)
    return 0 if record['control_completed'] and record['global_sysctls_unchanged'] else 1


if __name__=='__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,required=True)
    parser.add_argument('--expected-source-sha256',required=True)
    arguments = parser.parse_args()
    raise SystemExit(run(arguments.root,expected_source_sha256=arguments.expected_source_sha256))
