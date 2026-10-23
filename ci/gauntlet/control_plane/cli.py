"""One-command local deployment and explicit later gate activation."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import secrets
import socket
import subprocess
import sys
import threading
import time
import urllib.request

from .config import DEFAULTS, atomic_json, load

ROOT = Path(__file__).resolve().parents[3]
PACKAGE = Path(__file__).parent
DEFAULT_PORT = 8791


def dashboard_identity(state):
    public = state/'public'
    public.mkdir(mode=0o755, exist_ok=True)
    public.chmod(0o755)
    path = public/'dashboard-id.json'
    if not path.exists():
        atomic_json(path, {'instance_id': secrets.token_hex(16)}, mode=0o644)
    value = json.loads(path.read_text())['instance_id']
    if not isinstance(value, str) or len(value) != 32:
        raise ValueError('invalid dashboard instance identity')
    return value


def dashboard_ready(url, expected_id):
    with urllib.request.urlopen(url + '/healthz', timeout=2) as response:
        value = json.loads(response.read(16385))
    return (isinstance(value, dict) and value.get('service') == 'hol-gauntlet-dashboard'
            and value.get('instance_id') == expected_id and value.get('server') == 'online')


def check_dashboard_port(port, expected_id):
    if type(port) is not int or not 1024 <= port <= 65535:
        raise ValueError('dashboard port must be between 1024 and 65535')
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            # Match ThreadingHTTPServer's reusable bind after our own restart;
            # a closed dashboard can leave a short TCP TIME_WAIT interval.
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            probe.bind(('127.0.0.1', port))
    except OSError as error:
        if error.errno != errno.EADDRINUSE:
            raise
        try:
            if dashboard_ready(f'http://127.0.0.1:{port}', expected_id):
                return
        except (OSError, ValueError, TypeError, KeyError):
            pass
        raise RuntimeError(f'Port {port} belongs to another service. It was left untouched; '
                           'choose another port with up --port NUMBER') from error


def prepare(args):
    state = args.state.resolve()
    state.mkdir(mode=0o700, parents=True, exist_ok=True)
    (state/'private').mkdir(mode=0o700, exist_ok=True)
    (state/'public').mkdir(mode=0o755, exist_ok=True)
    config_path = args.config.resolve() if args.config else state/'config.json'
    if not config_path.exists():
        config = dict(DEFAULTS)
        for key in ('gh', 'limactl'):
            config[key] = shutil.which(key) or config[key]
        with config_path.open('x') as stream:
            json.dump(config, stream, indent=2)
            stream.write('\n')
        config_path.chmod(0o600)
    return state, config_path, load(config_path)


def process_alive(record, module, state):
    if not record or record.get('module') != module or record.get('state') != str(state):
        return False
    try:
        result = subprocess.run(['/bin/ps', '-ww', '-p', str(record['pid']), '-o', 'command='],
                                text=True, capture_output=True, timeout=5, check=True)
        return module in result.stdout and str(state) in result.stdout
    except PermissionError as error:
        raise RuntimeError('Process inspection is denied; use this command from the ordinary host terminal') from error
    except (OSError, KeyError, subprocess.SubprocessError):
        return False


def start_process(state, name, module, argv, *, source_sha256=None):
    pidfile = state/'private'/(name + '.pid.json')
    previous = json.loads(pidfile.read_text()) if pidfile.exists() else None
    if process_alive(previous, module, state):
        if source_sha256 is None or previous.get('source_sha256') == source_sha256:
            return previous['pid']
        os.kill(previous['pid'], signal.SIGTERM)
        deadline = time.monotonic()+10
        while process_alive(previous, module, state):
            if time.monotonic() >= deadline:
                raise RuntimeError('Previous Gauntlet dashboard did not stop for the reviewed source update')
            time.sleep(0.1)
    log = (state/'private'/(name + '-' + str(time.time_ns()) + '.log')).open('x')
    try:
        process = subprocess.Popen([sys.executable, '-B', '-m', module, *argv], cwd=ROOT,
                                   stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                                   start_new_session=True)
    finally:
        log.close()
    record = {'pid': process.pid, 'module': module, 'state': str(state)}
    if source_sha256 is not None:
        record['source_sha256'] = source_sha256
    atomic_json(pidfile, record)
    return process.pid


def docker_available(context=None):
    if not shutil.which('docker'):
        return False, 'Docker CLI is not installed'
    command = ['docker', *(['--context', context] if context else []),
               'info', '--format', '{{.ServerVersion}}']
    result = subprocess.run(command,
                            capture_output=True, text=True, timeout=15)
    return result.returncode == 0, result.stderr.strip()


def rust_dashboard_compose(state, port, *action, context):
    if re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', context or '') is None:
        raise ValueError('fixed Docker context name required for Rust dashboard')
    project = 'hol-gauntlet-rust-' + hashlib.sha256(str(state).encode()).hexdigest()[:12]
    environment = dict(os.environ, GAUNTLET_PUBLIC_STATE=str(state/'public'),
                       GAUNTLET_RUST_PORT=str(port), GAUNTLET_RUST_IMAGE=project + ':local')
    command = ['docker', '--context', context, 'compose', '-p', project, '-f',
               str(ROOT/'ci/gauntlet-rs/dashboard.compose.yml'), *action]
    timeout = 1200 if action == ('build',) else 120
    subprocess.run(command, env=environment, check=True, timeout=timeout)


def wait_dashboard_identity(port, instance_id):
    url = f'http://127.0.0.1:{port}'
    for _ in range(40):
        try:
            if dashboard_ready(url, instance_id):
                return url
        except (OSError, ValueError, TypeError, KeyError):
            pass
        time.sleep(0.25)
    raise RuntimeError('Dashboard did not report the existing Gauntlet instance identity')


def stop_owned_python_dashboard(state):
    pidfile = state/'private/dashboard.pid.json'
    previous = json.loads(pidfile.read_text()) if pidfile.exists() else None
    module = 'ci.gauntlet.control_plane.server'
    if not process_alive(previous, module, state):
        return False
    os.kill(previous['pid'], signal.SIGTERM)
    deadline = time.monotonic() + 10
    while process_alive(previous, module, state):
        if time.monotonic() >= deadline:
            raise RuntimeError('Owned Python dashboard did not stop for Rust handoff')
        time.sleep(0.1)
    return True


@contextmanager
def dashboard_rollback_on_termination():
    if threading.current_thread() is not threading.main_thread():
        yield
        return
    previous = signal.getsignal(signal.SIGTERM)

    def terminate(_signum, _frame):
        raise KeyboardInterrupt('Dashboard handoff interrupted')

    signal.signal(signal.SIGTERM, terminate)
    try:
        yield
    finally:
        signal.signal(signal.SIGTERM, previous)


def switch_dashboard_to_rust(state, port=None, docker_context=None):
    mode_file = state/'private/dashboard-mode.json'
    existing = json.loads(mode_file.read_text()) if mode_file.exists() else None
    if existing and existing['mode'] not in {'native', 'rust'}:
        raise RuntimeError('Restore or stop the existing Docker dashboard before Rust handoff')
    if port is None:
        port = existing['port'] if existing else DEFAULT_PORT
    if docker_context is None:
        docker_context = (existing.get('docker_context') if existing and existing['mode'] == 'rust'
                          else subprocess.run(['docker', 'context', 'show'], check=True,
                                              capture_output=True, text=True, timeout=10).stdout.strip())
    if re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', docker_context or '') is None:
        raise ValueError('fixed Docker context name required for Rust dashboard')
    if existing and existing['mode'] == 'rust' and existing.get('docker_context') != docker_context:
        raise ValueError('existing Rust dashboard belongs to another Docker context')
    instance_id = dashboard_identity(state)
    check_dashboard_port(port, instance_id)
    available, diagnostic = docker_available(docker_context)
    if not available:
        raise RuntimeError('Rust dashboard requires Docker: ' + diagnostic)
    rust_dashboard_compose(state, port, 'build', context=docker_context)
    stopped_python = False
    with dashboard_rollback_on_termination():
        try:
            if existing is not None and existing['mode'] == 'native':
                stopped_python = stop_owned_python_dashboard(state)
            rust_dashboard_compose(state, port, 'up', '--no-build', '-d', '--wait',
                                   context=docker_context)
            url = wait_dashboard_identity(port, instance_id)
            atomic_json(mode_file, {'mode': 'rust', 'port': port,
                                    'docker_context': docker_context})
        except BaseException as handoff_error:
            cleanup_error = None
            if not existing or existing['mode'] != 'rust':
                try:
                    rust_dashboard_compose(state, port, 'down', context=docker_context)
                except Exception as error:
                    cleanup_error = error
            if existing and existing['mode'] == 'native' and not stopped_python:
                pidfile = state/'private/dashboard.pid.json'
                previous = json.loads(pidfile.read_text()) if pidfile.exists() else None
                stopped_python = bool(previous and not process_alive(
                    previous, 'ci.gauntlet.control_plane.server', state))
            if stopped_python:
                try:
                    start_process(state, 'dashboard', 'ci.gauntlet.control_plane.server',
                                  ['--state', str(state/'public'), '--port', str(port)],
                                  source_sha256=hashlib.sha256((PACKAGE/'server.py').read_bytes()).hexdigest())
                    wait_dashboard_identity(port, instance_id)
                    record = json.loads((state/'private/dashboard.pid.json').read_text())
                    if not process_alive(record, 'ci.gauntlet.control_plane.server', state):
                        raise RuntimeError('Python dashboard process exited during rollback')
                except Exception as rollback_error:
                    raise RuntimeError('Rust handoff failed and Python dashboard rollback failed') from rollback_error
            if cleanup_error is not None:
                raise RuntimeError('Rust handoff failed and partial container cleanup failed') from cleanup_error
            raise handoff_error
    print(url)
    return url


def restore_python_dashboard(state):
    mode_file = state/'private/dashboard-mode.json'
    existing = json.loads(mode_file.read_text()) if mode_file.exists() else None
    if not existing or existing['mode'] != 'rust':
        raise RuntimeError('No Rust dashboard mode is recorded')
    port = existing['port']
    instance_id = dashboard_identity(state)
    check_dashboard_port(port, instance_id)
    with dashboard_rollback_on_termination():
        try:
            rust_dashboard_compose(state, port, 'down', context=existing['docker_context'])
            start_process(state, 'dashboard', 'ci.gauntlet.control_plane.server',
                          ['--state', str(state/'public'), '--port', str(port)],
                          source_sha256=hashlib.sha256((PACKAGE/'server.py').read_bytes()).hexdigest())
            url = wait_dashboard_identity(port, instance_id)
            record = json.loads((state/'private/dashboard.pid.json').read_text())
            if not process_alive(record, 'ci.gauntlet.control_plane.server', state):
                raise RuntimeError('Python dashboard process exited during restore')
            atomic_json(mode_file, {'mode': 'native', 'port': port})
        except BaseException:
            stop_owned_python_dashboard(state)
            rust_dashboard_compose(state, port, 'up', '--no-build', '-d', '--wait',
                                   context=existing['docker_context'])
            wait_dashboard_identity(port, instance_id)
            raise
    print(url)
    return url


def up(args, state, config_path):
    mode_file = state/'private/dashboard-mode.json'
    existing = json.loads(mode_file.read_text()) if mode_file.exists() else None
    # Migrate the original colliding default; retain explicitly chosen ports.
    port = args.port if args.port is not None else (
        existing['port'] if existing and existing['port'] != 8787 else DEFAULT_PORT)
    instance_id = dashboard_identity(state)
    check_dashboard_port(port, instance_id)
    # Installing only reviewed collector/controller bytes is idempotent. If the
    # VM is offline, still launch the dashboard and show the exact prerequisite.
    from .bootstrap import install
    config = load(config_path)
    try:
        result = install(config, ROOT)
        atomic_json(state/'private/bootstrap.json', result)
    except Exception as error:
        atomic_json(state/'private/bootstrap.json', {'status': 'blocked', 'error': str(error)[:1500]})
        print('VM bootstrap blocked: ' + str(error), file=sys.stderr)
    available, diagnostic = (docker_available(existing.get('docker_context')
                                              if existing and existing['mode'] == 'rust' else None)
                             if not args.native else (False, 'Native mode explicitly selected'))
    if existing:
        if existing['mode'] not in {'native', 'docker', 'rust'}:
            raise RuntimeError('Unknown dashboard mode requires operator reconciliation')
        if existing['mode'] == 'rust' and args.native:
            raise RuntimeError('Use dashboard-rust-restore to return to the Python dashboard')
        native = existing['mode'] == 'native'
        if not native and not available:
            raise RuntimeError('Existing deployment uses Docker; restore its daemon or run down before changing mode')
    else:
        native = not available
    rust = existing is not None and existing['mode'] == 'rust'
    if rust:
        rust_dashboard_compose(state, port, 'build', context=existing['docker_context'])
        rust_dashboard_compose(state, port, 'up', '--no-build', '-d', '--wait',
                               context=existing['docker_context'])
    elif native:
        if not available:
            print('Dashboard uses native Python. ' + (diagnostic or 'Docker unavailable'), file=sys.stderr)
        if existing and existing['port'] != port:
            pidfile = state/'private/dashboard.pid.json'
            if pidfile.exists():
                previous = json.loads(pidfile.read_text())
                if process_alive(previous, 'ci.gauntlet.control_plane.server', state):
                    os.kill(previous['pid'], signal.SIGTERM)
                # Only Gauntlet's own PID record is retired. Torch is untouched.
                pidfile.unlink()
        start_process(state, 'dashboard', 'ci.gauntlet.control_plane.server',
                      ['--state', str(state/'public'), '--port', str(port)],
                      source_sha256=hashlib.sha256((PACKAGE/'server.py').read_bytes()).hexdigest())
    else:
        environment = dict(os.environ, GAUNTLET_PUBLIC_STATE=str(state/'public'), GAUNTLET_PORT=str(port))
        subprocess.run(['docker', 'compose', '-p', 'hol-gauntlet-ops', '-f', str(PACKAGE/'compose.yml'),
                        'up', '--build', '-d', '--wait'], env=environment, check=True)
    mode = {'mode': 'rust' if rust else ('native' if native else 'docker'), 'port': port}
    if rust:
        mode['docker_context'] = existing['docker_context']
    atomic_json(mode_file, mode)
    url = f'http://127.0.0.1:{port}'
    for _ in range(20):
        try:
            if dashboard_ready(url, instance_id):
                pid = start_process(state, 'agent', 'ci.gauntlet.control_plane.cli',
                                    ['--state', str(state), '--config', str(config_path), 'agent'])
                from .lifecycle import wait_observer
                wait_observer(state, pid)
                print(url)
                if not args.no_open and sys.platform == 'darwin':
                    subprocess.run(['/usr/bin/open', url], check=False)
                return
        except (OSError, ValueError):
            time.sleep(0.25)
    raise RuntimeError('Dashboard did not become reachable; inspect private service logs in ' + str(state/'private'))


def down(state):
    atomic_json(state/'private/stop-request.json', {'requested_at': time.time()})
    for name, module in (('agent', 'ci.gauntlet.control_plane.cli'), ('dashboard', 'ci.gauntlet.control_plane.server')):
        path = state/'private'/(name + '.pid.json')
        if path.exists():
            record = json.loads(path.read_text())
            if process_alive(record, module, state):
                os.kill(record['pid'], signal.SIGTERM)
    path = state/'private/dashboard-mode.json'
    if path.exists():
        mode = json.loads(path.read_text())
        if mode['mode'] == 'docker':
            environment = dict(os.environ, GAUNTLET_PUBLIC_STATE=str(state/'public'), GAUNTLET_PORT=str(mode['port']))
            subprocess.run(['docker', 'compose', '-p', 'hol-gauntlet-ops', '-f', str(PACKAGE/'compose.yml'), 'down'],
                           env=environment, check=True)
        elif mode['mode'] == 'rust':
            rust_dashboard_compose(state, mode['port'], 'down', context=mode['docker_context'])
        path.unlink()
    print('Local services stopped. VM, retained jobs/evidence and repository rules are unchanged.')


def doctor(state, config):
    from .github import GitHub
    from .telemetry import host, vm, admission
    result = {'host': host(state), 'vm': vm(config)}
    try:
        github = GitHub(config)
        if config['discovery_mode'] == 'release-tags' and config['release_build_backend'] == 'local-vm':
            tags = [github.release(tag) for tag in config['release_tags']]
            result['github'] = {'status': 'connected', 'repository': config['repository'], 'release_tags': tags}
        else:
            repo = github.api('repos/' + config['repository'])
            result['github'] = {'status': 'connected', 'repository': repo['full_name']}
    except Exception as error:
        result['github'] = {'status': 'disconnected', 'error': str(error)}
    result['admission_reasons'] = admission(result, config)
    print(json.dumps(result, indent=2))
    return 0 if not result['admission_reasons'] and result['github']['status'] == 'connected' else 2


def reconcile(args, state, config):
    import fcntl
    from .agent import Agent
    with (state/'private/agent.lock').open('a+') as lease:
        fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
        agent = Agent(config, state)
        job = next((j for j in agent.jobs if j['id'] == args.job_id), None)
        if not job or job['state'] != 'unknown':
            raise ValueError('exact unresolved job required; stop the agent before reconciliation')
        result = agent.worker(job, 'reconcile')
        if result.get('status') == 'unknown':
            print(json.dumps(result, indent=2))
            return 2
        agent.finish(job, result)
        agent.publish()
        print('Reconciled retained result without replay: ' + job['state'])
        return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state', type=Path, default=ROOT/'.gauntlet-ops')
    parser.add_argument('--config', type=Path)
    commands = parser.add_subparsers(dest='command', required=True)
    start = commands.add_parser('up', help='start dashboard and passive release observer; never changes merge rules')
    start.add_argument('--native', action='store_true', help='run dashboard directly in Python')
    start.add_argument('--port', type=int, help='dashboard port (default: 8791; retains a custom deployment port)')
    start.add_argument('--no-open', action='store_true')
    rust_dashboard = commands.add_parser('dashboard-rust-up',
        help='switch only the dashboard HTTP service to the isolated Rust container')
    rust_dashboard.add_argument('--port', type=int,
        help='dashboard port (default: retained deployment port or 8791)')
    rust_dashboard.add_argument('--docker-context',
        help='explicit Docker context; saved for later up, restore and down commands')
    commands.add_parser('dashboard-rust-restore',
        help='restore only the Python dashboard HTTP service')
    fix = commands.add_parser('repair', help='restart the observer, start the existing VM and retain a controller upgrade; no gate activation')
    fix.add_argument('--native', action='store_true')
    fix.add_argument('--port', type=int)
    fix.add_argument('--no-open', action='store_true')
    fix.add_argument('--no-start', action='store_true', help='verify the VM and install controller changes, leaving admissions stopped for diagnosis')
    fix.add_argument('--retry-builds', action='store_true',
                     help='verify terminal local build failures and queue new attempts with retained evidence')
    fix.add_argument('--vm-memory-gib', type=int, help='resize the idle existing VM, then verify its memory')
    fix.add_argument('--build-memory-gib', type=int, help='set the build container RAM limit; reserves at least 2 GiB for the VM')
    fix.add_argument('--vm-disk-gib', type=int, help='grow the idle existing VM disk and verify guest filesystem capacity')
    fix.add_argument('--wait-idle', action='store_true', help='wait up to one hour for active work; unresolved jobs still require reconciliation')
    for command in ('down', 'doctor', 'status', 'agent', 'diagnose','hold','resume'):
        commands.add_parser(command)
    gate = commands.add_parser('gate', help='print an additive ruleset plan; --apply explicitly changes GitHub')
    gate.add_argument('operation', choices=['enable', 'disable'])
    gate.add_argument('--apply', action='store_true')
    recover = commands.add_parser('reconcile')
    recover.add_argument('job_id')
    retry_stage = commands.add_parser('retry-staging', help='retain verified cleaned conformance failures and reuse their exact successful build')
    retry_stage.add_argument('job_id')
    runtime_probe=commands.add_parser('probe-runtime', help='diagnose the native sandbox in a fresh isolated cell while the VM worker is idle')
    runtime_probe.add_argument('job_id')
    runtime_probe.add_argument('--cold-prompt',action='store_true',help='measure the first native prompt and kernel resource counters before other diagnostic work')
    stage_audit=commands.add_parser('audit-staging', help='verify six retained staging controls while preserving the strict benchmark verdict')
    stage_audit.add_argument('job_id')
    candidate=commands.add_parser('test-local',help='queue a clean committed local candidate alongside retained releases; no GitHub writes')
    candidate.add_argument('checkout',type=Path)
    candidate.add_argument('--native',action='store_true')
    candidate.add_argument('--no-open',action='store_true')
    candidate.add_argument('--port',type=int)
    live=commands.add_parser('live-local',help='run the source-bound twelve-cell Qwen 3.6 E2E profile for a passing local candidate')
    live.add_argument('checkout',type=Path)
    feature_ai=commands.add_parser('feature-ai-local',help='run the bounded two-cell Qwen MCP delegation probe for a passing local candidate')
    feature_ai.add_argument('checkout',type=Path)
    feature_ai.add_argument('--protocol-exposure',action='store_true',
                            help='require a hostile MCP structured-content marker in a completed model request')
    live_refresh=commands.add_parser('refresh-live-candidate',help='restage a passing exact-commit build under current model-E2E execution sources')
    live_refresh.add_argument('checkout',type=Path)
    live_recover=commands.add_parser('live-reconcile',help='verify one uncertain live E2E receipt and stop only its owned model')
    live_recover.add_argument('job_id')
    features=commands.add_parser('features-local',help='audit the exact built wheel across Guard feature contracts in the ARM VM; no model requests')
    features.add_argument('checkout',type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        state, config_path, config = prepare(args)
        if args.command == 'up':
            up(args, state, config_path)
        elif args.command == 'dashboard-rust-up':
            switch_dashboard_to_rust(state, args.port, args.docker_context)
        elif args.command == 'dashboard-rust-restore':
            restore_python_dashboard(state)
        elif args.command == 'repair':
            from .lifecycle import repair
            repair(args, state, config_path, config)
        elif args.command == 'down':
            down(state)
        elif args.command == 'agent':
            from .agent import Agent
            Agent(config, state).run()
        elif args.command == 'hold':
            atomic_json(state/'private/hold-admissions.json',{'requested_at':time.time()})
            print('Admission hold saved; active VM work is not interrupted.')
            from .lifecycle import observer_source
            current=json.loads((state/'public/snapshot.json').read_text()) if (state/'public/snapshot.json').exists() else {}
            if current.get('observer',{}).get('source_sha256')!=observer_source():
                print('The observer predates this update; use repair --wait-idle to activate the hold.')
        elif args.command == 'resume':
            (state/'private/hold-admissions.json').unlink(missing_ok=True)
            print('Admission hold removed; the observer will resume queued work at its next poll.')
        elif args.command == 'doctor':
            return doctor(state, config)
        elif args.command == 'diagnose':
            from .diagnostics import collect, summary
            for path in sorted((state/'private/jobs').glob('*.json')):
                job=json.loads(path.read_text())
                if job.get('archived_at') or job.get('state') not in {'unknown','failed','conformance-failed','invalid-evidence'}:
                    continue
                value=collect(config,job,state/'private/local-builds'/job['id'])
                print(job.get('tag',job['id'])+': '+summary(value))
                print('Private diagnostic: '+str(state/'private/local-builds'/job['id']/'stage-diagnostic.json'))
        elif args.command == 'status':
            from .server import snapshot
            print(json.dumps(snapshot(state/'public'), indent=2))
        elif args.command == 'reconcile':
            return reconcile(args, state, config)
        elif args.command == 'retry-staging':
            from .stage_recovery import retry
            retry(state, config, args.job_id)
        elif args.command == 'audit-staging':
            from .stage_audit import audit
            audit(state, config, args.job_id)
        elif args.command == 'test-local':
            from .local_candidate import enqueue
            enqueue(state,config,args.checkout)
            up(args,state,config_path)
        elif args.command == 'live-local':
            from .live_local import run
            return run(config,state,args.checkout)
        elif args.command == 'feature-ai-local':
            from .live_local import run
            return run(config,state,args.checkout,
                       profile='feature-ai-protocol' if args.protocol_exposure else 'feature-ai')
        elif args.command == 'refresh-live-candidate':
            from .live_local import refresh_candidate
            return refresh_candidate(config,state,args.checkout)
        elif args.command == 'live-reconcile':
            from .live_local import reconcile as reconcile_live
            return reconcile_live(config,state,args.job_id)
        elif args.command == 'features-local':
            from .feature_audit import run as run_feature_audit
            return run_feature_audit(config,state,args.checkout)
        elif args.command == 'probe-runtime':
            from .sandbox_probe import collect
            path=state/'private/jobs'/(args.job_id+'.json')
            if not re.fullmatch('[0-9a-f]{16}',args.job_id):
                raise ValueError('fixed job identity required')
            job=json.loads(path.read_text())
            atomic_json(state/'private/hold-admissions.json',{'requested_at':time.time(),'reason':'native sandbox diagnosis'})
            result=collect(config,job,state/'private/local-builds'/job['id'],mode='cold-prompt' if args.cold_prompt else 'backend')
            print(json.dumps(result,indent=2))
        elif args.command == 'gate':
            from . import gate
            from .github import GitHub
            from .server import snapshot
            enabled = args.operation == 'enable'
            result = (gate.apply(GitHub(config), enabled, snapshot(state/'public')) if args.apply else gate.plan(enabled))
            print(json.dumps(result, indent=2))
            if not args.apply:
                print('Plan only. Add --apply to change only the Gauntlet-owned ruleset.', file=sys.stderr)
        return 0
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(type(error).__name__ + ': ' + str(error), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
