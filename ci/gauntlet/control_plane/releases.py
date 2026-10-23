"""Explicit stable-release queue; historical PR records are retained, never run."""
from __future__ import annotations

import secrets
import time
import fcntl
import json
from pathlib import Path

from .config import SHA, DEFAULTS, atomic_json, load


def configure_release_queue(state, config_path):
    """Apply the two-tag migration only after the observer releases its lease."""
    from .agent import Agent
    from .lifecycle import assert_idle
    state = Path(state)
    with (state/'private/agent.lock').open('a+') as lease:
        fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert_idle(state)
        config = load(config_path)
        config.update(discovery_mode='release-tags', release_tags=list(DEFAULTS['release_tags']),
                      release_build_backend='local-vm')
        atomic_json(config_path, config)
        agent = Agent(config, state)
        path = state/'public/snapshot.json'
        if path.exists():
            agent.snapshot.update(json.loads(path.read_text()))
        agent.snapshot.update(discovery_mode='release-tags', release_tags=config['release_tags'],
            release_build_backend='local-vm', artifact_build={'status': 'local', 'name': 'Disposable ARM64 VM builder'},
            observer={'schema': 'hol-gauntlet-observer.stopped', 'reason': 'Release queue migration; restart required'},
            github={'status': 'awaiting-restart'}, ci_runs=[],
            ci_error='Restart the host observer to discover the two stable releases')
        archive_unwatched(agent)
        for job in agent.jobs:
            if admitted(config, job) and job['state'] in {'queued', 'waiting', 'waiting-candidate'} and not job.get('local_build'):
                job.update(state='queued', reason='Waiting for local VM build after observer restart')
                agent.activity(job, 'queued', 'Local source build selected; no GitHub Actions dependency')
        agent.publish()
        return {'release_tags': config['release_tags'], 'archived_jobs': agent.snapshot['archived_jobs']}


def admitted(config, job):
    if job.get('archived_at'):
        return False
    if job.get('kind') == 'local-candidate':
        return job.get('operator_queued') is True and SHA.fullmatch(job.get('sha', '')) is not None
    if config['discovery_mode'] == 'release-tags':
        return job.get('kind') == 'release' and job.get('tag') in config['release_tags']
    return job.get('kind') != 'release'


def archive_unwatched(agent):
    for job in agent.jobs:
        if job.get('kind') == 'local-candidate' and job['state'] == 'superseded' and not job.get('archived_at'):
            job['archived_at'] = time.time()
            agent.save(job)
            continue
        if admitted(agent.config, job) or job.get('archived_at'):
            continue
        # A remote operation with uncertain termination must remain visible and
        # block admission, even when it belongs to a previous discovery mode.
        if job['state'] in {'running', 'preparing', 'unknown'}:
            continue
        job['archived_at'] = time.time()
        if job['state'] in {'queued', 'waiting', 'waiting-candidate'}:
            job.update(state='archived', reason='Removed from active queue by release-only configuration',
                       finished_at=time.time())
        agent.save(job)


def discover(agent):
    errors = []
    with agent.lock:
        archive_unwatched(agent)
    for tag in agent.config['release_tags']:
        try:
            release = agent.github.release(tag)
            with agent.lock:
                existing = next((j for j in agent.jobs if j.get('kind') == 'release'
                                 and j.get('tag') == tag and not j.get('archived_at')), None)
                if existing:
                    if existing['sha'] != release['sha']:
                        existing['source_error'] = 'Release tag moved; original commit retained and execution blocked'
                        agent.save(existing)
                        errors.append({'tag': tag, 'error': existing['source_error']})
                    continue
                job = {'id': secrets.token_hex(8), 'kind': 'release', 'tag': tag,
                       'sha': release['sha'], 'title': tag, 'url': release['url'],
                       'state': 'queued', 'created_at': time.time(),
                       'reason': 'Waiting for serial release artifact admission'}
                agent.jobs.append(job)
                agent.activity(job, 'queued', 'Stable release resolved to ' + release['sha'][:12])
        except Exception as error:
            errors.append({'tag': tag, 'error': str(error)[:1000]})
    with agent.lock:
        agent.snapshot['github'] = {'status': 'connected' if not errors else 'attention',
            'checked_at': time.time(), 'release_tags': agent.config['release_tags'], 'release_errors': errors}


def build_title(job):
    return 'Gauntlet ' + job['tag'] + ' ' + job['sha'] + ' ' + job['id']


def request_build(agent, job):
    """Persist before dispatch: an ambiguous response never causes duplicate builds."""
    if job.get('build_dispatch'):
        return
    g = agent.github
    try:
        workflow = g.api(g.repo + '/actions/workflows/' + agent.config['artifact_workflow'])
    except RuntimeError as error:
        if 'HTTP 404' in str(error):
            raise RuntimeError('Release artifact workflow is missing from GitHub; publish the reviewed workflow and build adapter on main') from error
        raise
    if workflow.get('state') != 'active':
        raise RuntimeError('Release artifact workflow must be published and active on main')
    head = g.api(g.repo + '/commits/main')['sha']
    if not SHA.fullmatch(head):
        raise ValueError('trusted workflow commit required')
    job['build_dispatch'] = {'controller_sha': head, 'requested_at': time.time(), 'status': 'requesting'}
    agent.activity(job, 'artifact-build', 'Requesting isolated ARM64 build for ' + job['tag'])
    try:
        g.api(g.repo + '/actions/workflows/' + agent.config['artifact_workflow'] + '/dispatches',
              'POST', {'ref': 'main', 'inputs': {'tag': job['tag'], 'source_sha': job['sha'], 'job_id': job['id']}})
        job['build_dispatch']['status'] = 'requested'
    except Exception:
        job['build_dispatch']['status'] = 'uncertain'
        agent.save(job)
        raise RuntimeError('Build dispatch response uncertain; inspect GitHub before retrying this release')
    agent.save(job)
