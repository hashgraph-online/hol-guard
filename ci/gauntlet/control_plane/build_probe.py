"""Diagnose a retained failed build in a disposable unprivileged VM container."""
import json
from pathlib import Path
import subprocess
import sys
from .config import load

ENTRY = r'''import json,os,subprocess,tarfile,zipfile
from pathlib import Path
assert os.getuid()==65532
Path('/work/home').mkdir()
with tarfile.open('/input/source.tar.gz') as archive:archive.extractall('/work',filter='data')
subprocess.run(['git','clone','--no-hardlinks','--branch','local-'+os.environ['HOL_GUARD_BUILD_SHA'],'/work/repository.git','/work/source'],check=True)
os.chdir('/work/source')
subprocess.run(['uv','sync','--frozen','--no-dev','--group','ci-test','--no-install-project','--python','3.12'],check=True)
Path('artifact').mkdir()
with zipfile.ZipFile('/input/candidate.zip') as archive:
 declaration=json.loads(archive.read('artifact.json'))
 name=declaration['wheel'];assert '/' not in name and name.endswith('.whl')
 Path('artifact',name).write_bytes(archive.read(name))
subprocess.run(['uv','pip','install','--python','.venv/bin/python','--no-deps','artifact/'+name],check=True)
runtime='/work/source/.venv/lib/python3.12/site-packages/codex_plugin_scanner/_native/hol-guard-runtime'
cap=json.loads(subprocess.check_output([runtime,'capabilities','--json'],text=True))
print('NATIVE CAPABILITIES',json.dumps(cap),flush=True)
probe=Path('tests/test_gauntlet_native_probe.py')
probe.write_text("""def test_native_context_probe(monkeypatch,tmp_path):
 from codex_plugin_scanner.guard import native_request_context as m
 from codex_plugin_scanner.guard import native_runtime
 status=native_runtime.native_runtime_status()
 print('RUNTIME STATUS',repr(status))
 print('GUARD HOME',m._resolve_digest_home(None))
 from codex_plugin_scanner.guard import native_execution as execution
 from codex_plugin_scanner.guard.native_resident_client import native_resident_client_failure_code
 wire=execution.native_resident_client_request
 def observed_wire(**kwargs):
  result=wire(**kwargs)
  print('RAW RESPONSE',repr(result[:2000] if result else result),'FAILURE',native_resident_client_failure_code())
  return result
 monkeypatch.setattr(execution,'native_resident_client_request',observed_wire)
 original=m._resident_request
 def observed(**kwargs):
  result=original(**kwargs)
  print('RESIDENT RESPONSE',repr(result))
  return result
 monkeypatch.setattr(m,'_resident_request',observed)
 result=m._call({'kind':'restricted_pytest','body':{'operation':'contained_kind','input':{'command':['python3','-m','pytest','-q'],'search_path':'/usr/bin:/bin'}}},source='direct_command',guard_home=None,budget_ms=9000)
 print('CONTEXT RESULT',repr(result))
 diagnostic=m._resolve_digest_home(None)/'native-runtime/managed-resident-phases.v1.log'
 if diagnostic.exists():print('MANAGED PHASES',diagnostic.read_text()[-10000:])
 import os,secrets,subprocess,time
 from codex_plugin_scanner.guard.native_policy_snapshot import provision_native_policy_verifier_key
 home=tmp_path/'manual';home.mkdir(mode=0o700)
 state=home/'native-runtime';state.mkdir(mode=0o700)
 provision_native_policy_verifier_key(home,b'x'*32)
 process=subprocess.Popen([str(status.identity.path),'serve-managed','--state-dir',str(state),'--generation','1','--owner-process-id',str(os.getpid()),'--runtime-sha256',status.identity.sha256],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
 process.stdin.write(secrets.token_hex(32).encode()+bytes([10]));process.stdin.flush()
 time.sleep(1)
 print('DIRECT SERVER EXIT',process.poll())
 if process.poll() is None:process.terminate()
 out,err=process.communicate(timeout=5)
 print('DIRECT SERVER STDERR',err.decode()[:3000])
 assert isinstance(result,dict)
""")
env=dict(os.environ,HOL_GUARD_TEST_USE_INSTALLED='1',HOL_GUARD_NATIVE='force',HOL_GUARD_NATIVE_BINARY=runtime)
result=subprocess.run(['uv','run','--no-sync','python','-B','-m','pytest','-s','-q','-o','addopts=','tests/test_gauntlet_native_probe.py'],env=env)
Path('/output/result.json').write_text(json.dumps({'exit_code':result.returncode}))
raise SystemExit(result.returncode)
'''

ROOT = r'''import fcntl,hashlib,json,os,re,runpy,subprocess,sys,uuid
from pathlib import Path
r=json.loads(sys.stdin.read());job=r['job'];assert re.fullmatch('[0-9a-f]{16}',job)
h=runpy.run_path('/opt/hol-gauntlet/worker.py',run_name='helpers')
base=Path('/var/lib/hol-gauntlet/builds')/job
receipt=h['read_json'](base/'result.json')
assert receipt['status']=='build-failed' and receipt['failure_phase']=='product-contracts'
assert hashlib.sha256((base/'candidate.zip').read_bytes()).hexdigest()==receipt['retained_archive_sha256']
image=receipt['builder_image'];assert re.fullmatch('sha256:[0-9a-f]{64}',image)
with Path('/opt/hol-gauntlet/worker.lock').open('r+') as lease:
 fcntl.flock(lease,fcntl.LOCK_EX|fcntl.LOCK_NB)
 out=base/('probe-'+uuid.uuid4().hex);out.mkdir(mode=0o700);os.chown(out,65532,65532)
 profile='hol-gauntlet-probe-'+out.name[6:]
 policy=base/(out.name+'.apparmor');policy.write_text(r['profile'].replace('HOL_GAUNTLET_BUILD_PROFILE',profile))
 subprocess.run(['/usr/sbin/apparmor_parser','--replace',str(policy)],check=True)
 argv=['/usr/bin/podman','run','--rm','--name','hol-gauntlet-probe-'+job,'--user','65532:65532','--cap-drop=ALL','--security-opt=no-new-privileges','--security-opt=apparmor='+profile,'--timeout=240','--memory=12g','--memory-swap=12g','--cpus=2','--pids-limit=512','--network=slirp4netns','--env','HOL_GUARD_BUILD_SHA='+receipt['source_sha'],'--volume',str(base/'source.tar.gz')+':/input/source.tar.gz:ro','--volume',str(base/'candidate.zip')+':/input/candidate.zip:ro','--volume',str(out)+':/output:rw','--entrypoint','/usr/local/bin/gauntlet-python',image,'-I','-B','-c',r['entry']]
 logpath=base/(out.name+'.log')
 with logpath.open('x') as log:result=subprocess.run(argv,stdout=log,stderr=subprocess.STDOUT,timeout=300)
 subprocess.run(['/usr/sbin/apparmor_parser','--remove',str(policy)],check=True)
 print(json.dumps({'exit_code':result.returncode,'log':str(logpath),'result':str(out/'result.json')}))
assert not any(n.startswith('codex_plugin_scanner') for n in sys.modules)
'''

if __name__=='__main__':
 root=Path(__file__).resolve().parents[3]
 config=load(root/'.gauntlet-ops/config.json')
 result=subprocess.run([config['limactl'],'shell',config['vm'],'--','sudo','-n',config['guest_python'],'-I','-B','-c',ROOT],input=json.dumps({'job':sys.argv[1],'entry':ENTRY,'profile':Path(__file__).with_name('Builder.apparmor').read_text()}),capture_output=True,text=True,timeout=330)
 print(result.stdout);print(result.stderr,file=sys.stderr)
 raise SystemExit(result.returncode)
