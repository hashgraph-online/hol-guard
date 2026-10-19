"""Verify observer ownership and repair only the configured, existing VM."""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import time

from .config import atomic_json


def observer_source():
    return hashlib.sha256(Path(__file__).with_name('agent.py').read_bytes()).hexdigest()


def observer_ready(state, pid):
    try:
        value = json.loads((state/'public/snapshot.json').read_text())
        observer = value.get('observer', {})
        return (observer.get('pid') == pid and observer.get('source_sha256') == observer_source()
                and observer.get('schema') == 'hol-gauntlet-observer.v2'
                and time.time() - value['updated_at'] < 30)
    except (OSError, ValueError, KeyError, TypeError):
        return False


def wait_observer(state, pid, *, timeout=8):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if observer_ready(state, pid):
            return
        time.sleep(0.1)
    raise RuntimeError('Dashboard is reachable, but the current observer did not publish a verified heartbeat. '
                       'An older or restricted observer may own the lease; run gauntlet repair in the host terminal.')


def assert_idle(state, *, clean_startup_config=None):
    for path in (state/'private/jobs').glob('*.json'):
        job = json.loads(path.read_text())
        if job.get('state') in {'running', 'preparing', 'unknown'}:
            if clean_startup_config is not None and job.get('state') == 'unknown':
                from .stage_recovery import clean_startup_repair_allowed
                if clean_startup_repair_allowed(clean_startup_config, job):
                    continue
            raise RuntimeError('Job ' + job['id'] + ' is active or unresolved; reconcile it before repairing the controller')


def stop_observer(state, *, timeout=30):
    from .cli import process_alive
    atomic_json(state/'private/stop-request.json', {'requested_at': time.time()})
    pidfile = state/'private/agent.pid.json'
    if pidfile.exists():
        record = json.loads(pidfile.read_text())
        if process_alive(record, 'ci.gauntlet.control_plane.cli', state):
            os.kill(record['pid'], signal.SIGTERM)
    deadline = time.monotonic() + timeout
    with (state/'private/agent.lock').open('a+') as lease:
        while True:
            try:
                fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise RuntimeError('Observer still owns its lease; no VM changes were made')
                time.sleep(0.1)
    # Retire only the session-owned PID record, after its lease is released.
    if pidfile.exists():
        pidfile.unlink()


def vm_inventory(config):
    result = subprocess.run([config['limactl'], 'list', '--format', 'json', config['vm']],
                            capture_output=True, text=True, timeout=20, check=True)
    try:
        value = json.loads(result.stdout)
        rows = value if isinstance(value, list) else [value]
    except ValueError:
        rows = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
    matches = [row for row in rows if row.get('name') == config['vm']]
    if len(matches) != 1:
        raise RuntimeError('Configured benchmark VM is missing; existing disks were not changed or recreated')
    return matches[0]


def ensure_vm_running(config):
    value = vm_inventory(config)
    if value.get('status') == 'Stopped':
        print('Starting existing VM ' + config['vm'] + '…', flush=True)
        subprocess.run([config['limactl'], 'start', '--tty=false', '--timeout=120s', config['vm']],
                       check=True, timeout=150)
        value = vm_inventory(config)
    if value.get('status') != 'Running':
        raise RuntimeError('Lima reports ' + str(value.get('status')) + '; inspect its errors before starting or changing the VM')
    return {'status': 'running', 'name': config['vm']}


VERIFY_VM = '''import fcntl,json,runpy,sys
from pathlib import Path
h=runpy.run_path("/opt/hol-gauntlet/worker.py",run_name="trusted_worker_helpers")
s=h["read_json"](Path("/opt/hol-gauntlet/stage-settings.json"))
h["trusted"](Path(s["controller"]),directory=True)
baseline=s.get("template_controller",s["controller"])
h["trusted"](Path(baseline),directory=True)
# A retained baseline proof is verified by its own reviewed execution sources.
# New release deployments still require fresh controls under the new controller.
sys.path.insert(0,baseline)
from ci.gauntlet.benchmark.ci_runner_config import load_config,verify_assets
from ci.gauntlet.benchmark.ci_runner_preflight import controller_environment
from ci.gauntlet.benchmark.ci_pipeline import vm_lease
from ci.gauntlet.benchmark.local_campaign_custody import freeze_isolation
p=Path("/opt/hol-gauntlet/worker.lock");h["trusted"](p)
with p.open("r+") as lease:
 fcntl.flock(lease,fcntl.LOCK_EX|fcntl.LOCK_NB)
 with vm_lease():
  loaded=load_config(Path(s["template_config"]),expected_digest=s["template_config_digest"],asset_root=Path(s["asset_root"]))
  with controller_environment(loaded):
   assets=verify_assets(loaded)
   isolation=freeze_isolation(loaded["runtime"])
if any(n.startswith("codex_plugin_scanner") for n in sys.modules):raise ValueError("candidate imported as Root")
print(json.dumps({"status":"ready","executor_ready":True,"assets_verified":len(assets),
 "conformance_verified":isolation["local_executor_admission"]["local_execution_supported"],
 "controller":s["controller"],"baseline_verifier":baseline,"guard_source_sha":loaded["runtime"]["guard_source_sha"],
 "model_requests":0,"model_tokens":0}))
'''


def verify_vm(config):
    result = subprocess.run([config['limactl'], 'shell', config['vm'], '--', 'sudo', '-n',
                             config['guest_python'], '-I', '-B', '-c', VERIFY_VM],
                            capture_output=True, text=True, timeout=120)
    if result.returncode:
        raise RuntimeError('VM readiness failed: ' + (result.stderr or result.stdout)[-3000:])
    value = json.loads(result.stdout)
    if value.get('status') != 'ready' or value.get('conformance_verified') is not True:
        raise RuntimeError('VM did not verify its installed executor and conformance')
    return value


def prepare_build_network(config):
    c = config
    result = subprocess.run([c['limactl'], 'shell', c['vm'], '--', 'sudo', '-n', c['guest_python'],
                            '-I', '-B', '/opt/hol-gauntlet/network.py'],
                            capture_output=True, text=True, timeout=270)
    if result.returncode:
        raise RuntimeError('VM build networking setup failed: ' + (result.stderr or result.stdout)[-3000:])
    value = json.loads(result.stdout)
    if value.get('status')!='ready' or value.get('backend')!='slirp4netns':
        raise ValueError('VM did not verify its build network helper')
    return value


def repair(args, state, config_path, config):
    from .bootstrap import install
    from .cli import ROOT, up
    from .github import GitHub
    if getattr(args, 'wait_idle', False) is True:
        from .resources import wait_idle
        print('Waiting for the current job to finish before repair/resize…', flush=True)
        wait_idle(state)
    print('Checking for active or unresolved jobs…', flush=True)
    assert_idle(state, clean_startup_config=config)
    print('Stopping the previous Gauntlet observer…', flush=True)
    stop_observer(state)
    assert_idle(state, clean_startup_config=config)
    from .resources import configure
    config = configure(args, state, config_path, config)
    print('Checking the configured VM…', flush=True)
    ensure_vm_running(config)
    print('Installing a retained controller upgrade (no candidate/model execution)…', flush=True)
    local = config['discovery_mode'] == 'release-tags' and config['release_build_backend'] == 'local-vm'
    try:
        installed = install(config, ROOT, upgrade=True)
        if local:
            print('Checking slirp4netns; installing the Ubuntu package if missing…', flush=True)
            installed['build_network'] = prepare_build_network(config)
        print('Verifying pinned assets, installed executor and conformance…', flush=True)
        installed['readiness'] = verify_vm(config)
        atomic_json(state/'private/bootstrap.json', installed)
    except Exception as error:
        atomic_json(state/'private/bootstrap.json', {'status': 'blocked', 'error': str(error)[:3000]})
        raise
    print('Checking release tags using Git…' if local else 'Checking GitHub using the host credential broker…', flush=True)
    github = GitHub(config)
    try:
        if local:
            tags = [github.release(tag) for tag in config['release_tags']]
            connection = {'status': 'connected', 'repository': config['repository'], 'release_tags': tags}
        else:
            repository = github.api(github.repo)
            connection = {'status': 'connected', 'repository': repository['full_name']}
    except Exception as error:
        connection = {'status': 'disconnected', 'error': str(error)[:1500]}
    atomic_json(state/'private/connection-preflight.json', connection)
    if getattr(args, 'retry_builds', False):
        from .agent import Agent
        from .retry import enqueue
        with (state/'private/agent.lock').open('a+') as lease:
            fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
            queued = enqueue(Agent(config, state))
        print('Queued ' + str(len(queued)) + ' verified build retries; failed evidence retained.', flush=True)
    if getattr(args,'no_start',False):
        print('VM verified; observer remains stopped for diagnosis. Run gauntlet up to resume admissions.',flush=True)
        return
    up(args, state, config_path)
    if connection['status'] != 'connected':
        raise RuntimeError('VM and dashboard started, but GitHub is unavailable: ' + connection['error'])
    print('Observer, dashboard, VM and GitHub connection verified. PR gate remains optional.', flush=True)
