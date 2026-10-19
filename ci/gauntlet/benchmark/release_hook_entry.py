"""Normal native OMP bridge for releases whose CLI drops containment receipts."""
from .release_mcp_entry import LIBRARY_VERSIONS

ENTRY = '''import json,subprocess,sys,urllib.parse
from pathlib import Path
from codex_plugin_scanner.guard.adapters.pi_extension_native_hook import pi_native_hook_runtime
raw=sys.stdin.buffer.read(1024**2+1)
if len(raw)>1024**2:raise SystemExit(69)
runtime=pi_native_hook_runtime(guard_home=Path('/product/guard'))
if runtime is None:raise SystemExit(69)
query=urllib.parse.urlencode({'home':sys.argv[2],'workspace':sys.argv[3],'guard-home':'/product/guard'})
timeout=max(.1,int(sys.argv[1])-1)
budget=max(1,min(60000,int(timeout*1000*.7)))
payload=json.loads(raw)
payload.pop('guard_remaining_seconds',None)
payload['guard_remaining_ms']=budget
config={'harness':'omp','guard_home':'/product/guard','query':query,'timeout_ms':budget}
result=subprocess.run([str(runtime),'pi-hook-bridge',json.dumps(config,separators=(',',':'))],
 input=(json.dumps(payload,separators=(',',':'))+'\\n').encode(),capture_output=True,timeout=timeout)
if result.returncode or len(result.stdout)>8*1024**2:raise SystemExit(69)
envelope=json.loads(result.stdout)
status=envelope.get('status');body=envelope.get('body')
if type(status) is not int or not 100<=status<=599 or type(body) is not str or len(body.encode())>1024**2:raise SystemExit(69)
sys.stdout.write(body)
raise SystemExit(0 if status==200 else 69)
'''


def hook_command(python, *, version, timeout, home, workspace):
    if (version not in LIBRARY_VERSIONS or type(timeout) is not int or not 1<=timeout<=60
            or home!='/runtime/home' or workspace!='/runtime/home/project'):
        raise ValueError('fixed release hook context and bounded timeout required')
    return [str(python),'-I','-B','-c',ENTRY,str(timeout),home,workspace]
