"""Host-side PR queue and telemetry. Never imports or checks out PR source."""
from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path
import secrets
import signal
import subprocess
import threading
import time

from .config import SHA, atomic_json
from .artifacts import StagingUncertain
from .github import GitHub
from .telemetry import admission, host, vm
from .lifecycle import observer_source
from .releases import admitted, archive_unwatched

TERMINAL = {'passed', 'diagnostic-passed', 'failed', 'build-failed', 'conformance-failed', 'invalid-evidence', 'superseded', 'archived'}


def eligible(pr):
    return (pr.get('state') == 'open' and not pr.get('draft') and pr['base']['ref'] == 'main'
            and SHA.fullmatch(pr['head']['sha']) is not None)


class Agent:
    def __init__(self, config, state):
        self.config, self.state = config, Path(state)
        self.jobs_dir = self.state/'private/jobs'
        self.public = self.state/'public'
        self.jobs_dir.mkdir(parents=True, exist_ok=True)
        self.public.mkdir(parents=True, exist_ok=True)
        self.public.chmod(0o755)
        self.github = GitHub(config)
        self.lock = threading.RLock()
        self.status_lock = threading.Lock()
        self.stop = threading.Event()
        self.snapshot = {'schema': 'hol-gauntlet-dashboard.v1', 'repository': config['repository'],
                         'observer': {'schema': 'hol-gauntlet-observer.v2', 'pid': os.getpid(),
                                      'source_sha256': observer_source(), 'started_at': time.time()},
                         'context': 'hol-gauntlet/deterministic', 'profile': 'deterministic',
                         'gate': {'required': None}, 'github': {'status': 'connecting'}, 'jobs': [],
                         'deployment': {'status': 'unknown'}, 'discovery_mode': config['discovery_mode'],
                         'release_tags': config['release_tags'],
                         'release_build_backend': config['release_build_backend'],
                         'admissions_held': (self.state/'private/hold-admissions.json').exists(),
                         'allocation': {k: config[k] for k in ('vm_cpus', 'vm_memory_gib', 'vm_disk_gib', 'build_memory_gib',
                                        'host_disk_floor_gib', 'vm_disk_floor_gib')}}
        self.jobs = [json.loads(p.read_text()) for p in self.jobs_dir.glob('*.json')]

    def activity(self, job, phase, message):
        with self.lock:
            now = time.time()
            if job.get('phase') != phase:
                job.update(phase=phase, phase_started_at=now)
            events = job.setdefault('events', [])
            if not events or events[-1]['message'] != message or events[-1]['phase'] != phase:
                events.append({'at': now, 'phase': phase, 'message': message[:500]})
                job['events'] = events[-60:]
            self.save(job)
            self.publish()

    def recover(self):
        for job in self.jobs:
            if job['state'] in {'running', 'preparing'}:
                job.update(state='unknown', reason='Agent restarted during work; reconcile the same VM job before continuing')
                self.save(job)

    def save(self, job):
        with self.lock:
            job['updated_at'] = time.time()
            atomic_json(self.jobs_dir/(job['id'] + '.json'), job)

    def publish(self):
        with self.lock:
            # Publish only operational summaries. No credential, config, raw
            # candidate logs, private runtime state or signing material.
            keys = ('id', 'pr', 'title', 'url', 'sha', 'base_sha', 'state', 'reason', 'created_at',
                    'started_at', 'finished_at', 'updated_at', 'status_error', 'result', 'posted_state',
                    'kind', 'tag', 'phase', 'phase_started_at', 'events', 'vm_progress', 'progress_error',
                    'build_run', 'build_dispatch', 'source_error')
            keys += ('local_build', 'stage_error', 'stage_result', 'diagnostic_result')
            self.snapshot['jobs'] = [{k: job[k] for k in keys if k in job}
                                     for job in sorted(self.jobs, key=lambda j: j['created_at'], reverse=True)
                                     if not job.get('archived_at')][:200]
            for row in self.snapshot['jobs']:
                if 'local_build' in row:
                    row['local_build'] = {k: v for k, v in row['local_build'].items()
                        if k in {'source_sha', 'job_id', 'tag', 'status', 'builder_image',
                                 'error', 'failure_phase', 'exit_code', 'log_path', 'version'}}
            self.snapshot['archived_jobs'] = sum(bool(j.get('archived_at')) for j in self.jobs)
            self.snapshot['updated_at'] = time.time()
            atomic_json(self.public/'snapshot.json', self.snapshot, mode=0o644)

    def post(self, job, state, description):
        if job.get('kind') in {'release', 'local-candidate'} or job.get('archived_at'):
            return  # release experiments have local evidence only, no PR status effects
        with self.lock, self.status_lock:
            # A delayed discovery/publication cannot overwrite a terminal
            # success with an obsolete queued/pending state.
            actual = ('success' if job['state'] == 'passed' else 'failure' if job['state'] == 'failed'
                      else 'error' if job['state'] in {'invalid-evidence', 'superseded', 'unknown'} else 'pending')
            if actual != state:
                state, description = actual, 'Gauntlet ' + job['state']
            if job.get('posted_state') == state:
                return
            try:
                self.github.status(job['sha'], state, description)
                job['posted_state'] = state
                job.pop('status_error', None)
            except Exception as error:
                job['status_error'] = str(error)[:1000]
            self.save(job)

    def discover(self):
        if self.config['discovery_mode'] == 'release-tags':
            from .releases import discover
            discover(self)
        else:
            self.discover_prs()
        self.connections()

    def discover_prs(self):
        pulls = self.github.pulls()
        current = {p['number']: p for p in pulls if eligible(p)}
        publications = []
        with self.lock:
            for job in self.jobs:
                if job.get('kind') == 'local-candidate':
                    continue
                if not admitted(self.config, job):
                    continue
                pr = current.get(job['pr'])
                if job['state'] in {'queued', 'waiting', 'waiting-candidate'} and (
                        pr is None or pr['head']['sha'] != job['sha']):
                    job.update(state='superseded', reason='PR closed, draft, or replaced by another commit', finished_at=time.time())
                    self.save(job)
                    publications.append((job, 'error', 'Gauntlet run superseded before execution'))
            known = {(j['pr'], j['sha']) for j in self.jobs if j.get('pr') is not None}
            for pr in current.values():
                sha = pr['head']['sha']
                if (pr['number'], sha) in known:
                    continue
                job = {'id': secrets.token_hex(8), 'pr': pr['number'], 'sha': sha,
                       'base_sha': pr['base']['sha'], 'title': pr['title'][:300],
                       'url': pr['html_url'], 'state': 'queued', 'created_at': time.time(),
                       'reason': 'Waiting for resource and exact-commit candidate admission'}
                self.jobs.append(job)
                self.save(job)
                publications.append((job, 'pending', 'Gauntlet queued (optional until explicitly required)'))
            # Retry publication only; never rerun a terminal benchmark.
            for job in self.jobs:
                if admitted(self.config, job) and job.get('status_error'):
                    state = 'success' if job['state'] == 'passed' else 'failure' if job['state'] == 'failed' else (
                        'error' if job['state'] in {'invalid-evidence', 'superseded', 'unknown'} else 'pending')
                    publications.append((job, state, 'Gauntlet ' + job['state']))
            self.snapshot['github'] = {'status': 'connected', 'checked_at': time.time(), 'open_prs': len(current)}
        for job, state, description in publications:
            self.post(job, state, description)

    def connections(self):
        local = (self.config['discovery_mode'] == 'release-tags'
                 and self.config['release_build_backend'] == 'local-vm')
        if local:
            with self.lock:
                self.snapshot['artifact_build'] = {'status': 'local', 'name': 'Disposable ARM64 VM builder'}
                self.snapshot['ci_runs'] = []
                self.snapshot.pop('ci_error', None)
        else:
            self.build_connection()
        try:
            gate = self.github.gate()
        except Exception as error:
            gate = {'required': None, 'error': str(error)[:1000]}
        with self.lock:
            self.snapshot['gate'] = gate

    def build_connection(self):
        try:
            workflow = self.github.api(self.github.repo + '/actions/workflows/' + self.config['artifact_workflow'])
            build = {'status': 'connected' if workflow.get('state') == 'active' else 'disabled',
                     'name': workflow.get('name'), 'url': workflow.get('html_url')}
        except Exception as error:
            build = {'status': 'missing' if 'HTTP 404' in str(error) else 'unavailable',
                     'error': str(error)[:1000]}
        with self.lock:
            self.snapshot['artifact_build'] = build
        try:
            endpoint = ('/actions/workflows/' + self.config['artifact_workflow'] + '/runs?per_page=20'
                        if self.config['discovery_mode'] == 'release-tags' else '/actions/runs?per_page=20')
            runs = self.github.api(self.github.repo + endpoint)['workflow_runs']
            with self.lock:
                self.snapshot['ci_runs'] = [{k: row.get(k) for k in
                    ('id', 'name', 'status', 'conclusion', 'event', 'head_sha', 'html_url', 'created_at', 'updated_at')}
                                           for row in runs]
                self.snapshot.pop('ci_error', None)
        except Exception as error:
            with self.lock:
                self.snapshot['ci_error'] = str(error)[:1000]

    def worker(self, job, action, timeout=30):
        request = {'action': action, 'source_sha': job['sha'], 'job_id': job['id']}
        if 'deployment_digest' in job:
            request['deployment_digest'] = job['deployment_digest']
        c = self.config
        result = subprocess.run([c['limactl'], 'shell', c['vm'], '--', 'sudo', '-n',
                                 c['guest_python'], '-I', '-B', '/opt/hol-gauntlet/worker.py'],
                                input=json.dumps(request), capture_output=True, text=True, timeout=timeout)
        if result.returncode:
            raise RuntimeError((result.stderr or result.stdout)[:1500] or 'VM worker refused request')
        if len(result.stdout) > 1024**2:
            raise ValueError('worker response exceeds byte limit')
        return json.loads(result.stdout)

    def finish(self, job, result):
        if (result.get('source_sha') != job['sha'] or result.get('job_id') != job['id']
                or result.get('deployment_digest') != job.get('deployment_digest')):
            raise ValueError('VM result identity mismatch')
        code = result.get('exit_code')
        passed = code == 0 and result.get('status') == 'passed' and result.get('report_sha256')
        job.update(state='passed' if passed else 'failed' if code == 1 else 'invalid-evidence',
                   result=result, finished_at=time.time(), reason='Benchmark completed; retained evidence remains in VM')
        self.save(job)
        self.activity(job, 'completed', 'Terminal evidence classified: ' + job['state'])
        self.post(job, 'success' if passed else 'failure' if code == 1 else 'error',
                  'Gauntlet ' + job['state'] + ' (deterministic, zero inference)')

    def run_job(self, job):
        phase = 'admission'
        try:
            if not admitted(self.config, job) or job.get('source_error'):
                return
            # Recheck GitHub immediately before work. No fork/PR source is ever
            # executed on the Mac or imported into the privileged controller.
            if job.get('kind') == 'local-candidate':
                from .local_candidate import verify
                try:
                    verify(job)
                    valid = True
                except ValueError:
                    valid = False
            elif job.get('kind') == 'release':
                release = self.github.release(job['tag'])
                valid = release['sha'] == job['sha']
            else:
                pr = self.github.pull(job['pr'])
                valid = eligible(pr) and pr['head']['sha'] == job['sha']
            if not valid:
                with self.lock:
                    job.update(state='superseded', reason='Source reference changed before admission', finished_at=time.time())
                    if job.get('kind') == 'local-candidate':
                        job['archived_at'] = time.time()
                    self.save(job)
                    self.post(job, 'error', 'Gauntlet superseded before admission')
                return
            self.activity(job, 'admission', 'Rechecking release identity, controller and exact-commit candidate')
            with self.lock:
                job['state'] = 'preparing'
                job['reason'] = 'Checking the exact-commit artifact build and candidate deployment'
                self.save(job)
                self.publish()
            argv = self.config['prepare_argv'] if job.get('kind') not in {'release','local-candidate'} else []
            if argv and not job.get('preparation_attempted'):
                phase = 'staging'
                # This is an explicitly configured, reviewed operator adapter,
                # never a command read from PR content or a shell fragment.
                job['preparation_attempted'] = True
                self.save(job)
                with (self.state/'private'/(job['id'] + '-prepare.log')).open('x') as log:
                    subprocess.run([*argv, '--source-sha', job['sha'], '--pull-request', str(job['pr']),
                                    '--vm', self.config['vm']], stdout=log, stderr=subprocess.STDOUT,
                                   check=True, timeout=self.config['job_timeout_seconds'])
            ready = self.worker(job, 'inspect')
            if not ready.get('ready') and not argv:
                if job.get('kind') == 'local-candidate' or (job.get('kind') == 'release' and self.config['release_build_backend'] == 'local-vm'):
                    from .local_vm import prepare
                    ready_artifact = prepare(self, job)
                else:
                    from .artifacts import prepare_candidate
                    if job.get('kind') == 'release':
                        from .releases import request_build
                        request_build(self, job)
                    ready_artifact = prepare_candidate(self.config, self.github, job, self.state,
                        on_event=lambda stage, message: self.activity(job, stage, message))
                if ready_artifact:
                    ready = self.worker(job, 'inspect')
            with self.lock:
                if job['state'] in {'build-failed','conformance-failed','diagnostic-passed'}:
                    return
                if not ready.get('ready'):
                    build = job.get('build_run', {})
                    if build.get('status') == 'completed' and build.get('conclusion') != 'success':
                        job.update(state='build-failed', finished_at=time.time(),
                                   reason='Hosted artifact build ' + str(build.get('conclusion')) + '; VM benchmark did not execute')
                        self.activity(job, 'build-failed', job['reason'])
                        return
                    job.update(state='waiting-candidate', reason='Waiting for the hosted ARM artifact build or an exact-commit deployment')
                    self.save(job)
                    self.activity(job, 'artifact-build', 'Waiting for exact-commit ARM64 build; see build run details')
                    return
                job.update(state='running', deployment_digest=ready['deployment_digest'], started_at=time.time(),
                           reason='Six installed controls running in the isolated VM')
                self.save(job)
                self.publish()
            phase = 'execution'
            self.activity(job, 'benchmark', 'Starting six deterministic controls in the isolated VM')
            result = self.worker(job, 'run', self.config['job_timeout_seconds'])
            with self.lock:
                self.finish(job, result)
        except Exception as error:
            with self.lock:
                # An observation failure cannot prove remote termination or
                # cleanup. Block all new admissions until reconciliation.
                state = 'waiting' if phase == 'admission' and not isinstance(error, StagingUncertain) else 'unknown'
                job.update(state=state, reason=str(error)[:1500])
                self.save(job)
                self.activity(job, 'blocked' if state == 'waiting' else 'interrupted', job['reason'])
                self.post(job, 'pending' if state == 'waiting' else 'error',
                          'Gauntlet waiting for worker' if state == 'waiting' else
                          'Gauntlet observation interrupted; reconciliation required')
        finally:
            self.publish()

    def observe_loop(self):
        while not self.stop.is_set():
            try:
                h, v = host(self.state), vm(self.config)
                path = self.state/'private/bootstrap.json'
                deployment = json.loads(path.read_text()) if path.exists() else {'status': 'unknown'}
                with self.lock:
                    active_jobs = [j for j in self.jobs if j['state'] in {'preparing', 'running', 'unknown'}]
                for job in active_jobs:
                    try:
                        progress = self.worker(job, 'progress', timeout=12)
                        if progress.get('source_sha') != job['sha'] or progress.get('job_id') != job['id']:
                            raise ValueError('VM progress identity mismatch')
                        with self.lock:
                            job['vm_progress'] = progress
                            job.pop('progress_error', None)
                            self.save(job)
                    except Exception as error:
                        with self.lock:
                            job['progress_error'] = str(error)[:500]
                with self.lock:
                    self.snapshot.update(host=h, vm=v, deployment=deployment)
                    self.snapshot['admission_reasons'] = admission(self.snapshot, self.config)
                    self.publish()
            except Exception as error:
                with self.lock:
                    self.snapshot['telemetry_error'] = str(error)[:1000]
                    self.publish()
            self.stop.wait(self.config['telemetry_seconds'])

    def run(self):
        self.state.mkdir(parents=True, exist_ok=True)
        lease = (self.state/'private/agent.lock').open('a+')
        fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
        stop_request = self.state/'private/stop-request.json'
        if stop_request.exists():
            stop_request.unlink()
        self.recover()
        archive_unwatched(self)
        self.publish()
        signal.signal(signal.SIGTERM, lambda *_: self.stop.set())
        signal.signal(signal.SIGINT, lambda *_: self.stop.set())
        threading.Thread(target=self.observe_loop, daemon=True).start()
        active = None
        try:
            while not self.stop.is_set() and not stop_request.exists():
                try:
                    held=(self.state/'private/hold-admissions.json').exists()
                    with self.lock:
                        self.snapshot['admissions_held']=held
                    self.discover()
                    with self.lock:
                        halted = any(j['state'] == 'unknown' for j in self.jobs)
                        if (not held and not halted and (active is None or not active.is_alive())
                                and not admission(self.snapshot, self.config)):
                            job = next((j for j in self.jobs if admitted(self.config, j)
                                        and not j.get('status_error') and not j.get('source_error') and j['state'] in
                                        {'queued', 'waiting', 'waiting-candidate'}), None)
                            if job:
                                active = threading.Thread(target=self.run_job, args=(job,), daemon=True)
                                active.start()
                except Exception as error:
                    with self.lock:
                        self.snapshot['github'] = {'status': 'disconnected', 'checked_at': time.time(),
                                                   'error': str(error)[:1500]}
                self.publish()
                self.stop.wait(self.config['poll_seconds'])
        finally:
            # Do not kill a remote run on dashboard/agent shutdown. Next start
            # marks its retained running record unknown and reconciles it.
            lease.close()
