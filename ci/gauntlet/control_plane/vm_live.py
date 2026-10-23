"""Root-owned VM adapter for one exact-commit Qwen 3.6 E2E campaign.

Installed outside candidate source. Candidate code executes only in the existing
restricted product cells; this module handles inert inputs and retained records.
"""
from __future__ import annotations

import base64
import fcntl
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import runpy
import stat
import subprocess
import sys
import time

BASE = Path('/opt/hol-gauntlet')
ROOT = BASE/'live'
OUTPUT = Path('/var/lib/hol-gauntlet/live')
MODEL_ID = 'mlx-community/Qwen3.6-35B-A3B-8bit'
PROFILE_BASE = Path('/opt/hol-beta-e2e-inputs-007/config.json')
PROFILE_BASE_DIGEST = '876c00cc3ecc0d99ff366e536cae852c87cb9ff7d547f7d6e8d0192fc41a81c4'


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def write_new(path, value):
    with Path(path).open('xb') as stream:
        stream.write(canonical(value)+b'\n')
    Path(path).chmod(0o444)


def fixed(request, action):
    expected = ({'action', 'job_id', 'source_sha', 'provider_sha256', 'model_sha256'}
                if action == 'prepare' else {'action', 'job_id', 'source_sha'})
    allowed = ((expected, expected | {'stage_id'}, expected | {'profile'},
                expected | {'stage_id', 'profile'}) if action == 'prepare' else (expected,))
    if (set(request) not in allowed or request.get('action') != action
            or re.fullmatch('[0-9a-f]{16}', request.get('job_id', '')) is None
            or re.fullmatch('[0-9a-f]{40}', request.get('source_sha', '')) is None):
        raise ValueError('exact live request identity required')
    if 'stage_id' in request and re.fullmatch('[0-9a-f]{16}', request['stage_id']) is None:
        raise ValueError('fixed live staging identity required')
    if 'profile' in request and request['profile'] not in {'feature-ai', 'feature-ai-protocol'}:
        raise ValueError('only the reviewed optional feature AI profile may be requested')
    if action == 'prepare' and any(re.fullmatch('[0-9a-f]{64}', request[k]) is None
            for k in ('provider_sha256', 'model_sha256')):
        raise ValueError('external public manifest digests required')


def capture(inbox, expected):
    fd = os.open(inbox, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= 64*1024:
            raise ValueError('bounded ordinary manifest required')
        raw = stream.read(65537)
    if len(raw) != info.st_size or digest(raw) != expected:
        raise ValueError('transferred manifest differs from external digest')
    return raw, json.loads(raw)


def inputs(request, settings, helpers):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    job = request['job_id']
    inbox = Path(settings['guest_inbox'])
    provider_raw, provider = capture(inbox/('hol-live-'+job+'-provider.json'),
                                      request['provider_sha256'])
    model_raw, model = capture(inbox/('hol-live-'+job+'-model.json'),
                                request['model_sha256'])
    if (set(provider) != {'anchor', 'binding', 'signed_result'}
            or provider['anchor'].get('qualification') is not False
            or provider['signed_result']['record'].get('started') is not True
            or provider['signed_result']['record'].get('qualification') is not False):
        raise ValueError('fresh owned provider startup proof required')
    record = provider['signed_result']['record']
    anchor = provider['anchor']
    Ed25519PublicKey.from_public_bytes(base64.b64decode(anchor['public_key'], validate=True)).verify(
        base64.b64decode(provider['signed_result']['signature'], validate=True), canonical(record))
    binding = provider['binding']
    requested_profile = request.get('profile', 'beta-e2e')
    if (record.get('job_id') != job
            or record.get('profile') != requested_profile
            or record.get('candidate_source_sha') != request['source_sha']
            or binding.get('job_id') != job
            or binding.get('profile') != requested_profile
            or binding.get('candidate_source_sha') != request['source_sha']
            or record.get('binding_sha256') != digest(canonical(binding)+b'\n')
            or record.get('quota_before_any_control', {}).get('binding_sha256') !=
               record.get('binding_sha256')):
        raise ValueError('provider startup differs from requested candidate and binding')
    if (anchor['config_sha256'] != record['config_sha256']
            or record['loaded'] != model.get('loaded')
            or model.get('model_identity') != provider['binding'].get('model_identity')
            or model.get('model_identity_digest') != provider['binding'].get('model_identity_digest')
            or record['loaded'].get('model_id') != MODEL_ID
            or record['loaded'].get('weights_verified_before_and_after_load') is not True
            or record['quota_before_any_control']['quota']['pending_requests'] != 0
            or record['quota_before_any_control']['quota']['reserved_tokens'] != 0):
        raise ValueError('provider/model startup identities differ')
    if provider['binding']['maximum_accounted_tokens'] > provider['binding']['lifetime_token_cap']:
        raise ValueError('live allowance exceeds lifetime ceiling')
    return provider_raw, model_raw, provider


def live_staged(sha, stage_id, helpers):
    root = BASE/'live-candidates'/sha/stage_id
    path = helpers['trusted'](root/'deployment.json')
    row = helpers['read_json'](path)
    if (set(row) != {'schema','source_sha','config','config_digest','asset_root',
                     'controller','python'}
            or row['schema'] != 'hol-gauntlet-deployment.v1'
            or row['source_sha'] != sha or row['config'] != str(root/'config.json')
            or row['asset_root'] != '/opt'
            or re.fullmatch('[0-9a-f]{64}', row['config_digest']) is None):
        raise ValueError('source-bound live staging manifest required')
    helpers['trusted'](row['controller'], directory=True)
    helpers['trusted'](row['config'])
    return row


def prepare(request, settings, helpers):
    fixed(request, 'prepare')
    trusted, deployment = helpers['trusted'], helpers['deployment']
    from ci.gauntlet.benchmark.beta_profile import (
        build_feature_ai_profile, build_profile, feature_ai_protocol_mapping)
    from ci.gauntlet.benchmark.ci_runner_config import load_config, verify_assets
    from ci.gauntlet.benchmark.ci_runner_preflight import preflight
    from ci.gauntlet.benchmark.contracts import digest as config_digest

    sha, job = request['source_sha'], request['job_id']
    staged = (live_staged(sha, request['stage_id'], helpers)
              if 'stage_id' in request else deployment(sha)[0])
    if staged is None:
        raise ValueError('exact source-bound staged candidate required')
    template = load_config(trusted(PROFILE_BASE), expected_digest=PROFILE_BASE_DIGEST,
                           asset_root=trusted('/opt', directory=True))
    candidate = load_config(trusted(staged['config']),
        expected_digest=staged['config_digest'], asset_root=trusted(staged['asset_root'], directory=True))
    if candidate['runtime']['guard_source_sha'] != sha:
        raise ValueError('staged Guard source differs')
    provider_raw, model_raw, provider = inputs(request, settings, helpers)
    ROOT.mkdir(mode=0o755, exist_ok=True)
    ROOT.chmod(0o755)
    root = ROOT/job
    root.mkdir(mode=0o755)
    root.chmod(0o755)
    for name, raw in [('provider-manifest.json', provider_raw),
                      ('model-manifest.json', model_raw)]:
        with (root/name).open('xb') as stream:
            stream.write(raw)
        (root/name).chmod(0o444)
    profile = request.get('profile', 'beta-e2e')
    campaign, selection, policy = (build_profile() if profile == 'beta-e2e' else
        build_feature_ai_profile(protocol=profile == 'feature-ai-protocol'))
    config = json.loads(canonical(template['config']))
    def asset(name, value):
        path = root/name
        write_new(path, value)
        return {'path': path.relative_to('/opt').as_posix(),
                'sha256': digest(path.read_bytes())}
    config.update(id='live-'+sha+'-'+job,
                  campaign=asset('campaign.json', campaign),
                  policy=asset('policy.json', policy),
                  selection=selection, shards=len(selection))
    for role in ('guard_prefix', 'wheel', 'native', 'compiler', 'conformance', 'private_cell'):
        config['assets'][role] = candidate['config']['assets'][role]
    for name in ('guard_source_sha', 'guard_package_version', 'guard_bwrap_sha256',
                 'guard_executor_image_id', 'private_cell'):
        config['runtime'][name] = candidate['config']['runtime'][name]
    if profile == 'feature-ai-protocol':
        config['runtime']['mcp_protocol_profiles'] = feature_ai_protocol_mapping(selection)
    binding = provider['binding']
    status = provider['signed_result']['record']['quota_before_any_control']
    config['provider'].update(binding_sha256=digest(canonical(binding)+b'\n'),
        adapter_sha256=status['adapter']['adapter_sha256'],
        server_sha256=binding['engine_server_sha256'],
        model_identity_digest=binding['model_identity_digest'],
        quota_config_digest=binding['quota_config_digest'],
        quota_allowance_digest=binding['quota_allowance_digest'],
        token_cap=binding['lifetime_token_cap'])
    for role, name, raw in [('provider_manifest','provider-manifest.json',provider_raw),
                            ('model_manifest','model-manifest.json',model_raw)]:
        config['assets'][role] = {'path':(root/name).relative_to('/opt').as_posix(),
                                   'kind':'file', 'sha256':digest(raw)}
    config_path = root/'config.json'
    write_new(config_path, config)
    expected = config_digest(config)
    loaded = load_config(config_path, expected_digest=expected, asset_root=Path('/opt'))
    planned = campaign['budgets']['model_tokens'] * len(selection)
    if (loaded['config']['selection'] != selection
            or loaded['selection_reservations']['model_token_reservation'] != planned):
        raise ValueError('complete unchanged selected matrix reservation required')
    verify_assets(loaded)
    diagnosis = preflight(loaded)
    write_new(root/'preflight.json', diagnosis)
    manifest = {'schema':'hol-gauntlet-live-deployment.v1', 'job_id':job,
        'source_sha':sha, 'controller':settings['controller'],
        'profile': profile, 'selected_cases': len(selection),
        'stage_id':request.get('stage_id'),
        'python':settings['controller_python'], 'config':str(config_path),
        'config_digest':expected, 'asset_root':'/opt',
        'provider_binding_sha256':config['provider']['binding_sha256'],
        'provider_known_tokens_before':status['quota']['known_tokens'],
        'planned_tokens':planned, 'preflight_passed':diagnosis['passed']}
    write_new(root/'deployment.json', manifest)
    if any(name.startswith('codex_plugin_scanner') for name in sys.modules):
        raise ValueError('candidate product imported into Root controller')
    return {'status':'ready' if diagnosis['passed'] else 'preflight-failed',
        'source_sha':sha,'job_id':job,'config_digest':expected,
        'preflight_errors':diagnosis['errors'],
        'unsupported_cells':diagnosis['unsupported_cells'],
        'selected_cases':len(selection),'model_tokens':0}


def status(request, helpers):
    fixed(request, 'status')
    job, sha = request['job_id'], request['source_sha']
    root = ROOT/job
    manifest = helpers['read_json'](root/'deployment.json')
    if manifest['source_sha'] != sha or manifest['job_id'] != job:
        raise ValueError('live deployment identity differs')
    total = manifest.get('selected_cases', 12)
    output = OUTPUT/job
    receipt = output/'receipt.json'
    result = {'status':'prepared' if manifest['preflight_passed'] else 'preflight-failed',
        'source_sha':sha,'job_id':job,'selected_cases':total,
        'completed_cases':0,'model_tokens':None,'checked_at':time.time()}
    if (output/'started.json').exists():
        started = helpers['read_json'](output/'started.json')
        result.update(status='running',started_at=started['started_at'],
                      pid=started['pid'])
        result['process_alive'] = (helpers['process_identity'](started['pid']).get('start_ticks')
                                   == started.get('process_start_ticks'))
        if not result['process_alive']:
            result['status'] = 'unknown'
    if output.exists():
        complete = []
        for index in range(total):
            path = output/'result'/(f'shard-{index:03d}.json')
            if not path.exists():
                break
            phase = helpers['read_json'](path)
            complete.append({'index':index,'exit_code':phase.get('exit_code')})
        result['completed_cases'] = len(complete)
        result['current_case'] = len(complete) if len(complete) < total else None
        result['cases'] = complete
        if result['current_case'] is not None:
            configuration = helpers['read_json'](root/'config.json')
            campaign = helpers['read_json'](root/'campaign.json')
            episode = configuration['selection'][result['current_case']]
            cell = next(row for row in campaign['inventory'] if row['id'] == episode)
            result['current_case_label'] = (cell['workflow_id']+' · '
                                            +cell['condition'].replace('-', ' '))
    try:
        connection = http.client.HTTPConnection('192.168.5.2', 8002, timeout=3)
        connection.request('GET','/v1/benchmark-quota',headers={'Connection':'close'})
        response = connection.getresponse()
        raw = response.read(65537)
        connection.close()
        provider = json.loads(raw)
        if (response.status == 200 and len(raw) <= 65536
                and provider['binding_sha256'] == manifest['provider_binding_sha256']
                and provider['quota']['known_tokens'] == provider['quota']['charged_tokens']):
            result['model_tokens'] = (provider['quota']['known_tokens']
                                       - manifest['provider_known_tokens_before'])
            result['provider_pending_requests'] = provider['quota']['pending_requests']
    except (OSError, ValueError, KeyError):
        pass  # Unavailable usage stays unknown, never zero.
    if receipt.exists():
        terminal = helpers['read_json'](receipt)
        if terminal.get('source_sha') != sha or terminal.get('job_id') != job:
            raise ValueError('terminal live identity differs')
        result.update(status=terminal['status'],exit_code=terminal['exit_code'],
            model_tokens=terminal['model_tokens'], report_sha256=terminal.get('report_sha256'),
            finished_at=terminal['finished_at'], cells=terminal.get('cells',[]),
            model_ingestion_proven=terminal.get('model_ingestion_proven'))
    return result


def run(request, settings, helpers):
    fixed(request, 'run')
    job, sha = request['job_id'], request['source_sha']
    root = ROOT/job
    manifest = helpers['read_json'](root/'deployment.json')
    if (manifest['source_sha'] != sha or manifest['job_id'] != job
            or manifest['controller'] != settings['controller']
            or manifest['preflight_passed'] is not True):
        raise ValueError('fresh source-bound passing live preflight required')
    lock = BASE/'worker.lock'
    with lock.open('a+') as lease:
        fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
        output = OUTPUT/job
        output.mkdir(parents=True, mode=0o700)
        state = Path('/home/hl-'+job)
        started = {'schema':'hol-gauntlet-live-start.v1','source_sha':sha,
            'job_id':job,'started_at':time.time(),'pid':os.getpid()}
        with (output/'started.json').open('x') as stream:
            json.dump(started,stream)
        code = ('import sys;sys.path.insert(0,sys.argv.pop(1));'
                'from ci.gauntlet.benchmark.__main__ import main;raise SystemExit(main())')
        command = [manifest['python'],'-I','-B','-c',code,manifest['controller'],
            'ci','check','--profile',manifest.get('profile', 'beta-e2e'),
            '--config',manifest['config'],
            '--expected-config-digest',manifest['config_digest'],
            '--expected-guard-source-sha',sha,'--asset-root','/opt',
            '--state-root',str(state),'--output-dir',str(output/'result')]
        with (output/'run.log').open('x') as log:
            process = subprocess.Popen(command,cwd=manifest['controller'],
                env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','HOME':'/root'},
                stdout=log,stderr=subprocess.STDOUT)
            started['pid']=process.pid
            started['process_start_ticks']=helpers['process_identity'](process.pid).get('start_ticks')
            with (output/'started.json').open('w') as stream:
                json.dump(started,stream)
            code = process.wait()
        terminal = terminal_from_report(root, output, manifest, code, helpers)
        with (output/'receipt.json').open('x') as stream:
            json.dump(terminal,stream)
        return terminal


def terminal_from_report(root, output, manifest, code, helpers):
    sha, job = manifest['source_sha'], manifest['job_id']
    profile = manifest.get('profile', 'beta-e2e')
    selected = manifest.get('selected_cases', 12)
    report = output/'result/report/result.json'
    terminal = {'source_sha':sha,'job_id':job,'exit_code':code,
        'finished_at':time.time(),'status':'invalid-evidence',
        'model_tokens':None,'cells':[]}
    if not report.exists():
        return terminal
    data = helpers['read_json'](report)
    if (data.get('schema') != 'gauntlet-ci-check.v1'
            or data.get('profile') != profile
            or data.get('expected_guard_source_sha') != sha
            or data.get('guard_source_sha') != sha
            or data.get('runner_config_digest') != manifest['config_digest']
            or data.get('exit_code') != code
            or data.get('selected_cases') != selected):
        raise ValueError('live report identity or coverage differs')
    cells = data.get('cells', [])
    policy = helpers['read_json'](root/'policy.json')
    rules = {row['episode_id']:row['outcome'] for row in policy['cells']}
    if (len(rules) != selected or len(cells) != selected
            or {c.get('episode_id') for c in cells} != set(rules)):
        raise ValueError('live report omitted or duplicated a frozen case')
    if data.get('status') == 'passed' and (
            code != 0 or data.get('model_usage_known') is not True
            or type(data.get('model_tokens')) is not int or data['model_tokens'] <= 0
            or any(c.get('status') != ('measured-baseline'
                if rules[c['episode_id']] == 'attacked-baseline-measurement' else 'passed')
                for c in cells)):
        raise ValueError('passing live report lacks all policy-valid model-backed cells')
    if profile == 'feature-ai-protocol' and data.get('status') == 'passed' and any(
            c.get('model_ingestion_proven') is not True
            or c.get('protocol_exposure_stage') != 'model-context-forwarded'
            for c in cells):
        raise ValueError('passing protocol probe lacks model-ingestion evidence for each cell')
    terminal.update(status=data['status'],model_tokens=data.get('model_tokens'),
        model_ingestion_proven=(profile == 'feature-ai-protocol' and data['status'] == 'passed'
                                and all(c.get('model_ingestion_proven') is True for c in cells)),
        cells=[{'episode_id':c.get('episode_id'),'status':c.get('status'),
                'task_status':c.get('task_status'),
                'security_status':c.get('security_status'),
                'security_violation_observed':c.get('security_violation_observed'),
                'baseline_measurement_only':c.get('baseline_measurement_only'),
                'model_ingestion_proven':c.get('model_ingestion_proven'),
                'protocol_exposure_stage':c.get('protocol_exposure_stage'),
                'supported_surfaces':c.get('supported_surfaces', []),
                'reasons':c.get('reasons',[])} for c in cells],
        report_sha256=digest(report.read_bytes()))
    return terminal


def finalize(request, settings, helpers):
    """Recover a completed worker whose wrapper failed after writing its report."""
    fixed(request, 'finalize')
    job, sha = request['job_id'], request['source_sha']
    root, output = ROOT/job, OUTPUT/job
    manifest = helpers['read_json'](root/'deployment.json')
    if (manifest['source_sha'] != sha or manifest['job_id'] != job
            or (output/'receipt.json').exists()):
        raise ValueError('unresolved exact live deployment required')
    with (BASE/'worker.lock').open('r+') as lease:
        fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
        started = helpers['read_json'](output/'started.json')
        if (started['source_sha'] != sha or started['job_id'] != job
                or helpers['process_identity'](started['pid']).get('start_ticks')
                   == started.get('process_start_ticks')):
            raise ValueError('live worker identity differs or is still running')
        report = output/'result/report/result.json'
        data = helpers['read_json'](report)
        log = output/'run.log'
        if log.stat().st_size > 2*1024**2:
            raise ValueError('retained worker stdout exceeds recovery bound')
        rows = [json.loads(line) for line in log.read_text().splitlines()
                if line.startswith('{')]
        if len(rows) != 1 or rows[0] != data:
            raise ValueError('retained worker stdout and report differ')
        terminal = terminal_from_report(root,output,manifest,data['exit_code'],helpers)
        with (output/'receipt.json').open('x') as stream:
            json.dump(terminal,stream)
        return terminal


def main():
    if os.geteuid() != 0 or not sys.flags.isolated or sys.platform != 'linux':
        raise ValueError('isolated trusted Linux Root adapter required')
    helpers = runpy.run_path(str(BASE/'worker.py'), run_name='trusted_worker_helpers')
    settings = helpers['read_json'](BASE/'stage-settings.json')
    controller = helpers['trusted'](settings['controller'], directory=True)
    sys.path.insert(0,str(controller))
    raw = sys.stdin.buffer.read(8193)
    if len(raw) > 8192:
        raise ValueError('live request exceeds bound')
    request = json.loads(raw)
    action = request.get('action')
    result = (prepare(request,settings,helpers) if action == 'prepare' else
              run(request,settings,helpers) if action == 'run' else
              finalize(request,settings,helpers) if action == 'finalize' else
              status(request,helpers) if action == 'status' else None)
    if result is None:
        raise ValueError('unknown live action')
    print(json.dumps(result,sort_keys=True,allow_nan=False))


if __name__ == '__main__':
    os.umask(0o077)
    main()
