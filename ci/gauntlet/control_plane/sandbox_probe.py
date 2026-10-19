"""Run diagnostic-only native setup through the normal isolated product cell."""
import json
import subprocess

PROBE_RUNTIME = '''import fcntl,json,os,re,runpy,sys,uuid
from pathlib import Path
r=json.loads(sys.stdin.read(8193));sha=r['source_sha'];job=r['job_id'];mode=r.get('mode','backend')
if set(r) not in ({'source_sha','job_id'},{'source_sha','job_id','mode'}) or mode not in ('backend','cold-prompt') or not re.fullmatch('[0-9a-f]{40}',sha) or not re.fullmatch('[0-9a-f]{16}',job):raise ValueError('fixed source/job and diagnostic mode required')
h=runpy.run_path('/opt/hol-gauntlet/worker.py',run_name='trusted_worker_helpers')
base=Path('/opt/hol-gauntlet');h['trusted'](base/'worker.lock')
with (base/'worker.lock').open('r+') as lease:
 fcntl.flock(lease,fcntl.LOCK_EX|fcntl.LOCK_NB)
 settings=h['read_json'](base/'stage-settings.json');controller=Path(settings['controller'])
 h['trusted'](controller,directory=True);sys.path.insert(0,str(controller))
 from ci.gauntlet.benchmark.ci_runner_config import load_config,verify_assets
 from ci.gauntlet.benchmark.ci_runner_preflight import controller_environment
 from ci.gauntlet.benchmark.contracts import digest
 from ci.gauntlet.benchmark.private_cell_factory import PrivateCellConfig,build_private_cell
 from ci.gauntlet.benchmark.developer_product_runtime import OperationBudget
 from ci.gauntlet.control_plane.stage_outcome import failed_roles
 candidate=base/'candidates'/sha
 terminal=h['read_json'](candidate/'stage-result.json')
 if terminal.get('source_sha')!=sha or terminal.get('status')!='conformance-failed' or terminal.get('cleanup_verified') is not True:raise ValueError('cleaned failed staging required before probe')
 controls=Path('/home/hc-'+sha[:16])
 if not failed_roles({p.parent.name:h['read_json'](p) for p in controls.glob('*/control.json')}):raise ValueError('failed conformance controls required')
 config=h['read_json'](candidate/'provisional.json')
 if config.get('runtime',{}).get('guard_source_sha')!=sha:raise ValueError('candidate configuration source differs')
 h['trusted'](Path('/home'),directory=True)
 root=Path('/home/hp-'+job+'-'+uuid.uuid4().hex[:8]);root.mkdir(mode=0o700)
 config_path=candidate/'provisional.json'
 if 'staging_template_config' in settings:
  template=h['read_json'](Path(settings['staging_template_config']))
  if digest(template)!=settings['staging_template_config_digest']:raise ValueError('diagnostic executor template digest differs')
  config['assets']['private_cell']=template['assets']['private_cell']
  config['runtime']['guard_executor_image_id']=template['runtime']['guard_executor_image_id']
  config_path=root/'diagnostic-config.json';config_path.write_text(json.dumps(config))
 loaded=load_config(config_path,expected_digest=digest(config),asset_root=Path(settings['asset_root']))
 verify_assets(loaded);s=loaded['runtime']
 custody=root/'tasks';custody.mkdir(mode=0o700)
 task=custody/'checkout';task.mkdir(mode=0o755);os.chown(task,10001,10001)
 plane=None;result={'source_sha':sha,'job_id':job,'probe_mode':mode,'diagnostic_only':True,'benchmark_admitted':False,'model_tokens':0,'executor_image_id':s['guard_executor_image_id']}
 try:
  with controller_environment(loaded):
   plane=build_private_cell(root=root/'cell',config=PrivateCellConfig.parse(s['guard_private_cell']),
    python=Path(s['guard_python']),source_sha=s['guard_source_sha'],prefix_digest=s['guard_prefix_digest'],
    bwrap_sha256=s['guard_bwrap_sha256'],image_id=s['guard_executor_image_id'],
    workspace_source=task,workspace_custody_root=custody,provider_mounts=(),provider_custody_root=None,
    wall_seconds=120,operation_budget=OperationBudget(1),package_version=s['guard_package_version'])
   if mode=='cold-prompt':
    original=plane._command
    def diagnostic_command(*args):
     command=original(*args)
     return ['/usr/bin/env','HOL_GUARD_NATIVE_DIAGNOSTIC=1',*command] if args[:2]==('daemon','--serve') else command
    plane._command=diagnostic_command
   plane.start()
   if mode=='cold-prompt':
    prompt='Read the delegated developer-spec document through docs.read, then run the existing standard-library tests with python3 -m unittest discover -s tests -v. Do not change tests.'
    result['prompt_response']=plane.invoke_hook({'hook_event_name':'UserPromptSubmit','prompt':prompt,'config_path':plane.config_path,'session_id':'success'})
    result['resources']={}
    for name in ('memory.events','memory.peak','memory.current','pids.events','pids.peak','cpu.stat'):
     path=plane.cell.cgroup/name
     if path.exists():result['resources'][name]=path.read_text()[:2000]
    result['process_resources']=[]
    for pid in sorted(plane.cell._pids())[:32]:
     try:
      text=Path('/proc/'+str(pid)+'/status').read_text()
      fields={line.split(':',1)[0]:line.split(':',1)[1].strip() for line in text.splitlines() if ':' in line}
      row={k:fields[k] for k in ('Name','VmSize','VmPeak','VmRSS','Threads') if k in fields};row['pid']=pid
      row['address_space_limit']=[line for line in Path('/proc/'+str(pid)+'/limits').read_text().splitlines() if line.startswith('Max address space')]
      result['process_resources'].append(row)
     except FileNotFoundError:pass
   else:
    from ci.gauntlet.benchmark.native_sandbox_diagnostics import observe
    observe(plane)
   result['observations']=[e for e in plane.observations if e.get('kind') in {'native-sandbox-preparation','native-workspace-readiness'}]
 except Exception as e:result['error']=type(e).__name__+': '+str(e)[:2000]
 finally:
  if plane is not None:
   plane.close();result['cleanup_complete']=plane.cleanup_complete
 if any(n.startswith('codex_plugin_scanner') for n in sys.modules):raise ValueError('candidate imported as Root')
 (root/'result.json').write_text(json.dumps(result,indent=2)+'\\n');result['retained']=str(root/'result.json')
 print(json.dumps(result))
'''


def collect(config, job, directory, *, mode='backend'):
    if job.get('state')!='conformance-failed':
        raise ValueError('completed conformance failure required for a diagnostic probe')
    if mode not in {'backend','cold-prompt'}:
        raise ValueError('fixed diagnostic mode required')
    request={'source_sha':job['sha'],'job_id':job['id']}
    if mode!='backend':
        request['mode']=mode
    result=subprocess.run([config['limactl'],'shell',config['vm'],'--','sudo','-n',
        config['guest_python'],'-I','-B','-c',PROBE_RUNTIME],
        input=json.dumps(request),
        capture_output=True,text=True,timeout=130)
    if result.returncode or len(result.stdout)>32768:
        raise RuntimeError('Native sandbox diagnostic failed: '+(result.stderr or result.stdout)[-2500:])
    value=json.loads(result.stdout)
    if value.get('source_sha')!=job['sha'] or value.get('job_id')!=job['id'] or value.get('diagnostic_only') is not True or value.get('probe_mode')!=mode:
        raise ValueError('native sandbox diagnostic identity mismatch')
    if value.get('cleanup_complete') is not True or value.get('benchmark_admitted') is not False:
        raise RuntimeError('Diagnostic cleanup or admission boundary not confirmed; keep admissions held')
    directory.mkdir(parents=True,exist_ok=True)
    name='runtime-probe.json' if mode=='backend' else 'cold-prompt-probe.json'
    (directory/name).write_text(json.dumps(value,indent=2)+'\n')
    return value
