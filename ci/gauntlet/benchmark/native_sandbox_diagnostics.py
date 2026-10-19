"""Bounded unprivileged backend diagnostics; never grant execution admission."""
from .json_data import strict_json_loads

NATIVE = '''import json,sys
from pathlib import Path
try:
 from codex_plugin_scanner.guard.native_restricted_pytest import restricted_native
 from codex_plugin_scanner.guard.native_context import bind_context_digest_home,reset_context_digest_home
 binding=bind_context_digest_home(Path('/product/guard'))
 try:
  plan=restricted_native('prepare_workspace_contained',{
   'text':'python3 -m unittest discover -s tests -v',
   'workspace':Path('/runtime/home/project'),'cwd':Path('/runtime/home/project'),
   'platform':sys.platform,'home':Path(sys.argv[1]),'git_environment':{}},dict)
 finally:
  reset_context_digest_home(binding)
 native={'prepared':True,'fields':sorted(plan)}
except Exception as e:
 native={'prepared':False,'reason_code':getattr(e,'reason_code',None),
         'error':type(e).__name__+': '+str(e)[:2000]}
print(json.dumps(native))
'''

HOOK = '''import http.client,json,os,sys,urllib.parse
from pathlib import Path
from codex_plugin_scanner.guard.daemon.manager import load_guard_daemon_auth_token
from codex_plugin_scanner.guard.hook_execution_environment import collect_hook_execution_environment
from codex_plugin_scanner.guard.store import GuardStore
os.environ['HOME']=sys.argv[1]
token=load_guard_daemon_auth_token(Path('/product/guard'))
query=urllib.parse.urlencode({'workspace':'/runtime/home/project','home':sys.argv[1],'guard-home':'/product/guard'})
responses=[]
for case in ('prompt','no-environment','client-environment'):
 payload={'session_id':'sandbox-diagnostic','config_path':'/product/home/omp.json',
  'hook_event_name':'UserPromptSubmit' if case=='prompt' else 'PreToolUse'}
 if case=='prompt':payload['prompt']='Run existing standard-library tests.'
 else:payload.update(tool_call_id=case,tool_name='bash',tool_input={'command':'python3 -m unittest discover -s tests -v'})
 if case=='client-environment':payload['guard_execution_environment']=collect_hook_execution_environment()
 connection=http.client.HTTPConnection('127.0.0.1',18765,timeout=5)
 try:
  connection.request('POST','/v1/hooks/omp?'+query,body=json.dumps(payload).encode(),
   headers={'Content-Type':'application/json','X-Guard-Token':token})
  response=connection.getresponse();body=response.read(16385)
  value=json.loads(body) if len(body)<=16384 else {'error':'hook diagnostic byte budget'}
  responses.append({'case':case,'status':response.status,'response':value})
 finally:connection.close()
store=GuardStore(Path('/product/guard'),prime_policy_integrity=False,allow_system_keyring=False)
events=store.list_events(limit=5)
print(json.dumps({'responses':responses,'events':events}))
'''

PROBE = '''import json,subprocess,sys,tempfile
from pathlib import Path
base=['/usr/bin/bwrap','--die-with-parent','--new-session','--unshare-all',
 '--cap-drop','ALL','--ro-bind','/','/','--proc','/proc','--dev','/dev','--tmpfs','/tmp']
def run(command):
 try:
  r=subprocess.run(command,capture_output=True,timeout=5)
  return {'returncode':r.returncode,'stderr':r.stderr.decode(errors='replace')[-2000:]}
 except Exception as e:return {'error':type(e).__name__+': '+str(e)[:1000]}
bwrap=run(base+['--','/bin/true'])
with tempfile.TemporaryDirectory(prefix='hol-gauntlet-overlay-probe-',dir='/tmp') as name:
 root=Path(name);lower=root/'lower';upper=root/'upper';work=root/'work'
 for path in (lower,upper,work,lower/'d'):path.mkdir()
 (lower/'gone').write_text('unchanged');(lower/'d/old').write_text('unchanged')
 overlay=run(base+['--overlay-src',str(lower),'--overlay',str(upper),str(work),str(lower),
  '--chdir',str(lower),'--','/bin/sh','-c','echo x > new && rm gone && rm -rf d && mkdir d'])
 overlay.update(new_written=(upper/'new').exists(),lower_unchanged=(lower/'gone').exists() and (lower/'d/old').exists(),
                upper_names=sorted(p.name for p in upper.iterdir())[:30])
try:
 result=subprocess.run([sys.executable,'-I','-B','-c',__NATIVE__,sys.argv[1]],capture_output=True,timeout=12)
 native=json.loads(result.stdout) if len(result.stdout)<=8192 else {'error':'native diagnostic byte budget'}
except subprocess.TimeoutExpired:native={'prepared':False,'diagnostic_timeout':True}
except Exception as e:native={'prepared':False,'error':type(e).__name__+': '+str(e)[:1000]}
try:
 result=subprocess.run([sys.executable,'-I','-B','-c',__HOOK__,sys.argv[1]],capture_output=True,timeout=18)
 hooks=json.loads(result.stdout) if len(result.stdout)<=16384 else {'error':'hook diagnostic byte budget'}
except subprocess.TimeoutExpired:hooks={'diagnostic_timeout':True}
except Exception as e:hooks={'error':type(e).__name__+': '+str(e)[:1000],
                         'stderr':result.stderr.decode(errors='replace')[-2000:]}
print(json.dumps({'bwrap_namespace_probe':bwrap,'bwrap_overlay_probe':overlay,
                  'native_workspace_plan':native,'native_hook_diagnostic':hooks}))
'''.replace('__NATIVE__',repr(NATIVE)).replace('__HOOK__',repr(HOOK))


def observe(plane):
    result=plane.cell.capture([str(plane.python),'-I','-B','-c',PROBE,plane.home_path],timeout=45)
    response=strict_json_loads(result.stdout) if len(result.stdout)<=24576 else {'error':'diagnostic byte budget'}
    plane._emit(plane.observations,{'kind':'native-sandbox-preparation',
        'returncode':result.returncode,'response':response,'product_claims_authenticated':False})
