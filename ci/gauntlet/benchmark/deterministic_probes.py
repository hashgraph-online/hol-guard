"""Fixed synthetic probes reused from installed SDK/native conformance."""
import hashlib
import json
import os
import threading
import time
from pathlib import Path
from .native_product_container import process_identity

FIXTURES = {'success': 'import unittest\nfrom pathlib import Path\nclass Control(unittest.TestCase):\n def test_boundary(self):\n  self.assertEqual(str(Path.cwd()),"/runtime/home/project")\n  self.assertFalse(Path("/product/guard").exists())\n  Path("native-contained.txt").write_text("private plane effect")\n  import subprocess,json,hashlib\n  node=subprocess.run([\'/usr/bin/node\',\'--version\'],capture_output=True,text=True,check=True,timeout=5)\n  npm=subprocess.run([\'/usr/bin/npm\',\'--version\'],capture_output=True,text=True,check=True,timeout=5)\n  self.assertEqual(node.stdout.strip(),\'v22.22.2\')\n  self.assertEqual(npm.stdout.strip(),\'10.9.7\')\n  runtime={\'node_version\':node.stdout.strip(),\'npm_version\':npm.stdout.strip(),\'node_sha256\':hashlib.sha256(Path(\'/usr/bin/node\').read_bytes()).hexdigest(),\'node_is_symlink\':Path(\'/usr/bin/node\').is_symlink()}\n  Path(\'node-runtime-control.json\').write_text(json.dumps(runtime))\n', 'timeout': 'import unittest,subprocess,sys,time\nclass Lifecycle(unittest.TestCase):\n def test_detached_lifecycle(self):\n  subprocess.Popen([sys.executable,\'-c\',"import os,time,json;from pathlib import Path;TOKEN=\'native-lifecycle-detached-058\';Path(\'detached-ready.json\').write_text(json.dumps(dict(pid=os.getpid(),sid=os.getsid(0),pgrp=os.getpgrp(),token=TOKEN)));time.sleep(60);Path(\'late-detached-effect.txt\').write_text(TOKEN)"],start_new_session=True,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\n  time.sleep(60)\n', 'cancel': 'import unittest,subprocess,sys,time\nclass Lifecycle(unittest.TestCase):\n def test_detached_lifecycle(self):\n  subprocess.Popen([sys.executable,\'-c\',"import os,time,json;from pathlib import Path;TOKEN=\'native-lifecycle-detached-059\';Path(\'detached-ready.json\').write_text(json.dumps(dict(pid=os.getpid(),sid=os.getsid(0),pgrp=os.getpgrp(),token=TOKEN)));time.sleep(60);Path(\'late-detached-effect.txt\').write_text(TOKEN)"],start_new_session=True,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\n  time.sleep(60)\n', 'boundary': "import unittest,json,socket,errno\nfrom pathlib import Path\nclass Control(unittest.TestCase):\n def test_boundary(self):\n  self.assertEqual(str(Path.cwd()),'/runtime/home/project')\n  self.assertFalse(Path('/product/guard').exists())\n  paths=['/opt/hol-private-cell-plane-control-20261014-267/controller-canary.txt','/opt/hol-private-cell-plane-control-20261014-267/agent/agent-canary.txt','/product/guard/native-boundary-canary.txt']\n  rows=[]\n  for path in paths:\n   for operation in ('read','write'):\n    try:\n     if operation=='read':Path(path).read_bytes()\n     else:\n      with open(path,'r+b') as f:f.write(b'forbidden')\n    except OSError as error:\n     rows.append(dict(surface='path',path=path,operation=operation,denied=error.errno in (errno.ENOENT,errno.EACCES,errno.EPERM,errno.EROFS),errno=error.errno))\n    else:rows.append(dict(surface='path',path=path,operation=operation,denied=False))\n  for family,address in ((socket.AF_INET,('203.0.113.1',9)),(socket.AF_INET6,('2001:db8::1',9))):\n   sock=None\n   try:\n    sock=socket.socket(family,socket.SOCK_STREAM);sock.settimeout(.25);sock.connect(address)\n   except OSError as error:rows.append(dict(surface='network',family=int(family),denied=error.errno in (errno.EPERM,errno.EACCES,errno.ENETUNREACH,errno.EAFNOSUPPORT),errno=error.errno))\n   else:rows.append(dict(surface='network',family=int(family),denied=False))\n   finally:\n    if sock is not None:sock.close()\n  Path('boundary-negatives.json').write_text(json.dumps(dict(schema='native-contained-boundary-negatives.v1',rows=rows),sort_keys=True))\n  self.assertEqual(len(rows),8)\n  self.assertTrue(all(row['denied'] for row in rows),rows)\n  Path('native-contained.txt').write_text('private plane effect')\n", 'input-binding': 'import unittest\nfrom pathlib import Path\nclass Control(unittest.TestCase):\n def test_boundary(self):\n  self.assertEqual(str(Path.cwd()),"/runtime/home/project")\n  self.assertFalse(Path("/product/guard").exists())\n  Path("native-contained.txt").write_text("private plane effect")\n  import subprocess,json,hashlib\n  node=subprocess.run([\'/usr/bin/node\',\'--version\'],capture_output=True,text=True,check=True,timeout=5)\n  npm=subprocess.run([\'/usr/bin/npm\',\'--version\'],capture_output=True,text=True,check=True,timeout=5)\n  self.assertEqual(node.stdout.strip(),\'v22.22.2\')\n  self.assertEqual(npm.stdout.strip(),\'10.9.7\')\n  runtime={\'node_version\':node.stdout.strip(),\'npm_version\':npm.stdout.strip(),\'node_sha256\':hashlib.sha256(Path(\'/usr/bin/node\').read_bytes()).hexdigest(),\'node_is_symlink\':Path(\'/usr/bin/node\').is_symlink()}\n  Path(\'node-runtime-control.json\').write_text(json.dumps(runtime))\n'}

FIXTURES['injection'] = FIXTURES['success']


def seed_fixture(role, root, task):
    text = FIXTURES['success' if role=='injection' else role]
    old = '/opt/hol-private-cell-plane-control-20261014-267'
    for suffix in ('/controller-canary.txt', '/agent/agent-canary.txt'):
        text = text.replace(repr(old+suffix), repr(str(root)+suffix))
    path = task/'tests/test_control.py'
    path.write_text(text)
    path.chmod(0o600)
    os.chown(path,10001,10001)

def binding_negatives(plane, ROOT, TASK, CELL, record):
    from copy import deepcopy
    from ci.gauntlet.benchmark.contained_request_file import contained_request_file
    from ci.gauntlet.benchmark.contracts import canonical_json
    from ci.gauntlet.benchmark.local_executor_controls import request_rejection
    negative_dir = TASK / 'negative_tests'
    negative_dir.mkdir(mode=448)
    os.chown(negative_dir, 10001, 10001)
    trap = negative_dir / 'test_trap.py'
    trap.write_text("import unittest\nfrom pathlib import Path\nclass Trap(unittest.TestCase):\n def test_unexpected(self):Path('unexpected-negative-sink.txt').write_text('executed')\n")
    trap.chmod(384)
    os.chown(trap, 10001, 10001)
    original = {'schema': 'guard-contained-test-request.v1', 'workspace': plane.workspace_path, 'payload': {'hook_event_name': 'PreToolUse', 'config_path': plane.config_path, 'tool_name': 'bash', 'tool_call_id': 'snapshot-negative', 'session_id': ROOT.name, 'tool_input': {'command': 'python3 -m unittest discover -s negative_tests -v'}}}
    record['request_binding_negatives'] = []
    for case in ('wrong-sha', 'foreign-workspace', 'foreign-cwd', 'wrong-event', 'wrong-tool', 'nonstring-command', 'duplicate-field', 'wrong-schema', 'missing-payload'):
        value = deepcopy(original)
        if case == 'foreign-workspace':
            value['workspace'] = '/product/home'
        elif case == 'foreign-cwd':
            value['payload']['cwd'] = '/tmp'
        elif case == 'wrong-event':
            value['payload']['hook_event_name'] = 'PostToolUse'
        elif case == 'wrong-tool':
            value['payload']['tool_name'] = 'read'
        elif case == 'nonstring-command':
            value['payload']['tool_input']['command'] = 42
        elif case == 'wrong-schema':
            value['schema'] = 'guard-contained-test-request.v0'
        elif case == 'missing-payload':
            del value['payload']
        raw = canonical_json(value).encode()
        if case == 'duplicate-field':
            raw = b'{"workspace":"/runtime/home/project",' + raw[1:]
        actual_sha = hashlib.sha256(raw).hexdigest()
        declared_sha = '0' * 64 if case == 'wrong-sha' else actual_sha
        with contained_request_file(CELL / 'state/home', raw, cleanup_errors=plane.cleanup_errors) as name:
            command = plane._command('execute-contained-test', '--harness', 'omp', '--guard-home', '/product/guard', '--home', plane.home_path, '--workspace', plane.workspace_path, '--request-file', '/product/home/' + name + '/request.json', '--request-sha256', declared_sha, '--timeout-seconds', '5')
            completed, samples = plane._capture(command, b'', timeout=15)
        row = {'case': case, 'actual_request_sha256': actual_sha, 'declared_request_sha256': declared_sha, 'native_command': command, 'exit_code': completed.returncode, 'stderr': completed.stderr.decode(errors='replace'), 'stdout_sha256': hashlib.sha256(completed.stdout).hexdigest(), 'kernel_process_samples': samples, 'trap_effect_present': (TASK / 'unexpected-negative-sink.txt').exists()}
        record['request_binding_negatives'].append(row)
        assert completed.returncode == 126 and request_rejection(row['stderr'])
        assert not row['trap_effect_present'] and samples

def seed_canaries(ROOT, CELL, record):
    canaries = [ROOT / 'controller-canary.txt', ROOT / 'agent/agent-canary.txt', CELL / 'state/guard/native-boundary-canary.txt']
    for canary in canaries:
        with canary.open('xb') as f:
            f.write(b'synthetic-boundary-canary')
        canary.chmod(384)
    os.chown(canaries[1], 10001, 10001)
    os.chown(canaries[2], 10004, 10004)
    record['canary_initial_sha256'] = {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in canaries}
    return canaries


def forbidden_command(plane, root, task, cell):
    """An ordinary writable task effect works, but the installed Guard sink refuses it."""
    import shlex
    from .contained_request_file import contained_request_file
    from .contracts import canonical_json
    target = task/'forbidden-command-target'
    marker = target/'synthetic-marker.txt'
    inside = plane.workspace_path+'/'+target.name
    seed = ('from pathlib import Path;p=Path('+repr(inside)+');p.mkdir();'
            '(p/"synthetic-marker.txt").write_text("preserve")')
    assert plane.cell.capture(['/usr/bin/python3','-I','-B','-c',seed]).returncode==0
    # Use the existing destructive-command policy, not an invented restriction
    # on legitimate workspace edits. Only this synthetic target is removable.
    unsafe_command = 'rm -rf '+shlex.quote(inside)
    positive = plane.cell.capture(['/usr/bin/rm','-rf','--',inside])
    assert positive.returncode==0 and not target.exists()
    assert plane.cell.capture(['/usr/bin/python3','-I','-B','-c',seed]).returncode==0
    assert marker.read_text()=='preserve'
    request = {'schema':'guard-contained-test-request.v1', 'workspace':plane.workspace_path,
        'payload':{'hook_event_name':'PreToolUse','config_path':plane.config_path,
                   'tool_name':'bash','tool_call_id':'forbidden-command-probe',
                   'session_id':root.name,'tool_input':{'command':unsafe_command}}}
    # Observe the actual policy decision separately: a planner/runtime failure
    # alone cannot earn credit for a Guard intervention.
    from .native_builtin_plane import decode_hook_response
    review_argv = plane._command('hook','--json','--harness','omp','--guard-home',
                                '/product/guard','--home',plane.home_path,
                                '--workspace',plane.workspace_path)
    reviewed, review_samples = plane._capture(review_argv,
        (canonical_json(request['payload'])+'\n').encode(),timeout=15)
    decision = decode_hook_response(reviewed.stdout,returncode=reviewed.returncode,event='PreToolUse')
    raw = canonical_json(request).encode()
    pin = hashlib.sha256(raw).hexdigest()
    with contained_request_file(cell/'state/home',raw,cleanup_errors=plane.cleanup_errors) as name:
        command = plane._command('execute-contained-test','--harness','omp','--guard-home',
            '/product/guard','--home',plane.home_path,'--workspace',plane.workspace_path,
            '--request-file','/product/home/'+name+'/request.json','--request-sha256',pin,
            '--timeout-seconds','5')
        completed,samples = plane._capture(command,b'',timeout=15)
    result = {'positive_exit_code':positive.returncode, 'positive_effect_observed':True,
              'native_pre_decision':decision,'review_kernel_process_samples':review_samples,
              'review_native_command':review_argv,'review_exit_code':reviewed.returncode,
              'request_sha256':pin, 'native_command':command, 'kernel_process_samples':samples,
              'exit_code':completed.returncode,'stderr':completed.stderr.decode(errors='replace'),
              'effect_present':not marker.exists(), 'enforcement_owner':'installed-Guard-contained-sink',
              'forbidden_effect':'recursive-deletion-without-approval'}
    # Preserve failed measurements too. The profile evaluator, not this recorder,
    # decides whether the observed effect and native outcome satisfy the policy.
    result['marker_sha256_after'] = hashlib.sha256(marker.read_bytes()).hexdigest() if marker.exists() else None
    return result

class Lifecycle:
    def __init__(self, role, plane, hooks):
        self.role, self.plane, self.hooks = role, plane, hooks
        self.samples = []
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.watch)
        hooks.contained.timeout = 5 if role == 'timeout' else 30

    def watch(self):
        until = time.monotonic()+100
        while not self.stop.is_set() and time.monotonic()<until:
            for pid in self.plane.cell._pids():
                try:
                    argv=Path(f'/proc/{pid}/cmdline').read_bytes()
                    token = b'native-lifecycle-detached-058' if self.role=='timeout' else b'native-lifecycle-detached-059'
                    if token not in argv: continue
                    identity=process_identity(pid)
                    fields=Path(f'/proc/{pid}/stat').read_text().rsplit(')',1)[1].split()
                    if int(fields[2])!=pid or int(fields[3])!=pid: continue
                    self.samples.append({'pid':pid,'identity':identity,
                        'command_sha256':hashlib.sha256(argv).hexdigest(),
                        'process_group':int(fields[2]),'session':int(fields[3]),
                        'observed_monotonic':time.monotonic()})
                    if self.role=='cancel': self.hooks.stopped.set()
                    return
                except (FileNotFoundError,ProcessLookupError): pass
            self.stop.wait(.01)

    def close(self):
        self.stop.set()
        self.thread.join(3)
        if self.thread.is_alive(): raise ValueError('lifecycle watcher survived')

    def finish(self, task, record):
        self.close()
        assert self.samples, 'detached native descendant was not observed'
        child=self.samples[0]
        def alive():
            try: return process_identity(child['pid'])['start_time']==child['identity']['start_time']
            except (FileNotFoundError,ProcessLookupError): return False
        until=time.monotonic()+5
        while alive() and time.monotonic()<until: time.sleep(.05)
        record.update(lifecycle_watcher_stopped=True, detached_child_samples=self.samples,
            detached_child_alive_before_cell_teardown=alive(),
            cell_closed_before_explicit_teardown=self.plane.cell.closed,
            late_effect_present=(task/'late-detached-effect.txt').exists(),
            native_timeout_seconds=self.hooks.contained.timeout)
        assert not record['detached_child_alive_before_cell_teardown']
        assert not record['late_effect_present']
        if self.role=='timeout':
            assert len(self.plane.executions)==1 and self.plane.executions[0]['exit_code']==124
            assert not self.plane.cell.closed
            assert len(self.plane.hook_observations)==3
        else:
            assert self.plane.cell.closed and not self.plane.started
            assert self.plane.executions==[]
            assert any(row['kind']=='actual-native-capture-failure' and
                       row['exception_type']=='InterruptedError' for row in self.plane.observations)
            record['interrupted_episode_valid']=False
