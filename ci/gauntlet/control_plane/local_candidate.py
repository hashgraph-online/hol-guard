"""Explicit operator admission of an immutable local branch; no GitHub writes."""
from __future__ import annotations

import fcntl
import json
from pathlib import Path
import re
import secrets
import subprocess
import time

from .config import SHA


def git(path, *args):
    return subprocess.check_output(['git','-c','core.hooksPath=/dev/null',
        '-c','core.fsmonitor=false','-C',str(path),*args],text=True,timeout=30).strip()


def identity(path):
    path=Path(path).resolve(strict=True)
    if git(path,'status','--porcelain','--untracked-files=all'):
        raise ValueError('Commit the candidate changes before admission; clean immutable source required')
    sha=git(path,'rev-parse','HEAD')
    branch=git(path,'symbolic-ref','--short','HEAD')
    if not SHA.fullmatch(sha) or not branch.startswith('codex/gauntlet-'):
        raise ValueError('Explicit Gauntlet candidate branch and full commit required')
    # Read version as inert Git data; never import or run the candidate on host.
    toml=git(path,'show',sha+':pyproject.toml')
    version=re.search(r'^version = "([0-9]+\.[0-9]+\.[0-9]+(?:a[1-9][0-9]*)?)"$',toml,re.M)
    if not version:
        raise ValueError('Literal stable or alpha package version required')
    return {'source_path':str(path),'sha':sha,'branch':branch,'version':version[1]}


def verify(job):
    actual=identity(job['source_path'])
    if any(job.get(k)!=v for k,v in actual.items()) or job.get('tag')!='local-'+actual['sha']:
        raise ValueError('Candidate branch changed since operator admission')


def enqueue(state,config,path):
    from .agent import Agent
    from .lifecycle import assert_idle,stop_observer
    actual=identity(path)
    for record in (state/'private/jobs').glob('*.json'):
        existing=json.loads(record.read_text())
        if existing.get('sha')==actual['sha'] and not existing.get('archived_at'):
            raise ValueError('This exact candidate is already queued; observer left running and execution retained')
    assert_idle(state)
    stop_observer(state)
    with (state/'private/agent.lock').open('a+') as lease:
        fcntl.flock(lease,fcntl.LOCK_EX|fcntl.LOCK_NB)
        assert_idle(state)
        agent=Agent(config,state)
        if any(j.get('sha')==actual['sha'] and not j.get('archived_at') for j in agent.jobs):
            raise ValueError('This exact candidate is already queued; retained execution is not replayed')
        job={**actual,'id':secrets.token_hex(8),'kind':'local-candidate','operator_queued':True,
             'tag':'local-'+actual['sha'],'title':'Local candidate · '+actual['branch'],
             'state':'queued','created_at':time.time(),'reason':'Waiting for isolated ARM64 build and strict benchmark'}
        agent.jobs.append(job)
        agent.activity(job,'queued','Local branch captured at '+actual['sha']+'; GitHub writes disabled')
        print(json.dumps({'job_id':job['id'],**actual}))
