"""One local CI interface over the existing controller, retention audit and gate."""
from __future__ import annotations

import os
import signal
import stat
import sys
import threading
from contextlib import contextmanager
from pathlib import Path

from .campaign_paths import validate_ci_state_root, validate_private_cell_state_root
from .ci_gate import gate_campaign
from .ci_gate_report import write_gate_artifacts
from .ci_runner_config import SHA, file_digest, load_config, read_public
from .ci_runner_preflight import controller_environment, observe_provider, preflight, verify_provider_status
from .contracts import canonical_json, digest


def private_state(root, *, create=False, immutable_ancestry=False):
    root = Path(root)
    if sys.platform != 'linux' or os.geteuid() != 0:
        raise ValueError('CI runner requires an isolated Linux Root controller')
    if not root.is_absolute() or root.resolve() != root:
        raise ValueError('canonical absolute state directory required')
    for parent in root.parents:
        info = parent.lstat()
        sticky = (not immutable_ancestry and parent in {Path('/tmp'),Path('/var/tmp')}
                  and info.st_mode & stat.S_ISVTX)
        if info.st_uid != 0 or (info.st_mode & 0o022 and not sticky):
            raise ValueError('CI state ancestry must be protected from agent/product writers')
    if create:
        root.mkdir(mode=0o700)
    info = root.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError('CI state must be exclusively Root-owned and private')
    return root


def write_new(path, value):
    with path.open('x') as stream:
        stream.write(canonical_json(value)+'\n')
        stream.flush()
        os.fsync(stream.fileno())


def _policy(loaded, selection):
    selected = set(selection)
    return {**loaded['policy'], 'cells':[row for row in loaded['policy']['cells']
                                       if row['episode_id'] in selected]}


def freeze(loaded, root):
    from .local_campaign import freeze_local_campaign
    root = Path(root)
    if root.is_relative_to(loaded['asset_root']) or loaded['asset_root'].is_relative_to(root):
        raise ValueError('immutable public assets and mutable CI state must be disjoint')
    if loaded.get('attempt_layout')=='compact-v1':
        validate_ci_state_root(root)
    if 'guard_private_cell' in loaded['runtime']:
        validate_private_cell_state_root(root)
    root = private_state(root,create=True,immutable_ancestry='guard_private_cell' in loaded['runtime'])
    with controller_environment(loaded):
        diagnosis = preflight(loaded)
        write_new(root/'preflight.json',diagnosis)
        # Missing runtime inputs cannot be frozen. Unsupported cells may be
        # retained in an exact selection; run still requires a passing preflight.
        if 'assets' not in diagnosis or 'isolation' not in diagnosis:
            raise ValueError('cannot freeze without verified artifact and isolation identities; diagnostics retained')
        shards = []
        for index,selection in enumerate(loaded['shards']):
            path = root/f'shard-{index:03d}'
            preview = freeze_local_campaign(path,campaign=loaded['campaign'],episode_ids=selection,
                runtime=loaded['runtime'],max_episodes=len(selection),
                attempt_layout=loaded.get('attempt_layout','legacy-v1'))
            shards.append({'index':index,'directory':path.name,'selection':selection,
                           'policy_digest':digest(_policy(loaded,selection)),**preview})
    manifest = {'schema':'gauntlet-ci-freeze.v1','runner_config_digest':loaded['config_digest'],
                'asset_root':str(loaded['asset_root']),'shards':shards,
                'selection':loaded['config']['selection'],'preflight_digest':digest(diagnosis),
                'qualification_eligible':False}
    write_new(root/'manifest.json',manifest)
    return {'schema':'gauntlet-ci-freeze-result.v1','manifest_digest':digest(manifest),
            'runner_config_digest':loaded['config_digest'],'preflight_passed':diagnosis['passed'],
            'selected_cases':len(manifest['selection']),'shards':len(shards),'qualification_eligible':False}


def load_frozen(loaded, root, *, expected_manifest_digest):
    from .local_campaign import load_local_campaign
    if type(expected_manifest_digest) is not str or SHA.fullmatch(expected_manifest_digest) is None:
        raise ValueError('external frozen-manifest pin required')
    if loaded.get('attempt_layout')=='compact-v1':
        validate_ci_state_root(root)
    if 'guard_private_cell' in loaded['runtime']:
        validate_private_cell_state_root(root)
    root = private_state(root,immutable_ancestry='guard_private_cell' in loaded['runtime'])
    manifest = read_public(root/'manifest.json')
    if (digest(manifest) != expected_manifest_digest
            or manifest.get('schema') != 'gauntlet-ci-freeze.v1'
            or manifest['runner_config_digest'] != loaded['config_digest']
            or manifest['asset_root'] != str(loaded['asset_root'])
            or manifest['selection'] != loaded['config']['selection']
            or digest(read_public(root/'preflight.json')) != manifest['preflight_digest']
            or len(manifest['shards']) != len(loaded['shards'])):
        raise ValueError('frozen selection or caller inputs differ from external manifest pin')
    states = []
    for index,row in enumerate(manifest['shards']):
        if (row['index'] != index or row['directory'] != f'shard-{index:03d}'
                or row['selection'] != loaded['shards'][index]
                or row['policy_digest'] != digest(_policy(loaded,row['selection']))):
            raise ValueError('shard partition differs from exact frozen union')
        private_state(root/row['directory'])
        state = load_local_campaign(root/row['directory'])
        config = state['config']
        if (config['config_digest'] != row['config_digest']
                or digest(config['preview']) != row['preview_digest']
                or config['preview'] != row['preview']
                or config['runtime'] != loaded['runtime']
                or config['campaign'] != loaded['campaign']
                or [cell['id'] for cell in config['cells']] != row['selection']
                or config['execution_lane'] != 'live'):
            raise ValueError('shard runtime, source, campaign or selection changed')
        states.append(state)
    return manifest,states


@contextmanager
def controller_lock(root):
    path = root/'ci-controller.lock'
    descriptor = os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        os.write(descriptor,str(os.getpid()).encode())
        os.fsync(descriptor)
        yield
    finally:
        os.close(descriptor)
        path.unlink()


def aggregate_admission(root, manifest, budgets, cell, reserve):
    """Serialize all shards against one campaign's retained all-attempt costs."""
    from .local_campaign import _ledger, _token_halt
    finished = [row['event'] for shard in manifest['shards']
                for row in _ledger(root/shard['directory']) if row['event']['type'] == 'finish']
    if any(_token_halt(event['report']) for event in finished):
        return 'aggregate-model-token-usage-unknown'
    if any(event.get('retry') is False
           and event['report'].get('execution_valid') is False
           and event['report'].get('inference_started') is False
           and event['report'].get('retryable_infrastructure') is True
           and event['report'].get('controller_failure_class') == 'mcp-connect-before-inference'
           for event in finished):
        # A terminal startup fault is already retained. Do not spend on later
        # cells under the broken tuple; declared bounded retries keep working.
        return 'aggregate-terminal-startup-failure'
    tokens = sum(event['charged_tokens'] for event in finished)
    seconds = sum(event['elapsed_seconds'] for event in finished)
    if (tokens+reserve['model_token_reservation'] > budgets['campaign_tokens']
            or seconds+reserve['controller_seconds_reservation'] > budgets['campaign_seconds']):
        return 'aggregate-campaign-budget-limit'
    return None


def run_shard(loaded, root, *, expected_manifest_digest, shard):
    from .local_campaign import run_local_campaign
    root = private_state(root)
    with controller_environment(loaded),controller_lock(root):
        manifest,states = load_frozen(loaded,root,expected_manifest_digest=expected_manifest_digest)
        if type(shard) is not int or not 0 <= shard < len(manifest['shards']):
            raise ValueError('exact bounded shard index required')
        diagnosis = preflight(loaded)
        attempts = root/'controller-attempts'
        attempts.mkdir(mode=0o700,exist_ok=True)
        # Every invocation gets fresh evidence, including preflight failures.
        import tempfile
        output = Path(tempfile.mkdtemp(prefix=f'shard-{shard:03d}-',dir=attempts))
        write_new(output/'preflight.json',diagnosis)
        if not diagnosis['passed']:
            response = {'schema':'gauntlet-ci-run.v1','status':'preflight-failed','exit_code':2,
                        'diagnostic_directory':str(output),'qualification_eligible':False,
                        'selected_cases':len(manifest['selection']),
                        'cells':[{'episode_id':key,'status':'failed','reasons':['preflight-failed']}
                                 for key in manifest['selection']]}
            write_new(output/'result.json',response)
            return response
        before = diagnosis['provider']
        write_new(output/'provider-before.json',before)
        row = manifest['shards'][shard]
        old_charge = sum(event['event']['charged_tokens'] for event in states[shard]['ledger']
                         if event['event']['type'] == 'finish')
        def admission(cell,reserve):
            return aggregate_admission(root,manifest,loaded['campaign']['budgets'],cell,reserve)
        result = None
        try:
            result = run_local_campaign(root/row['directory'],preview_digest=row['preview_digest'],
                                        admission_check=admission)
            write_new(output/'controller-result.json',result)
        except BaseException as error:
            write_new(output/'controller-error.json',{'type':type(error).__name__,'message':str(error)[:4096]})
            raise
        finally:
            # A timeout/disconnect never refunds or erases provider reservations.
            # Failure of this read propagates and prevents a passing invocation.
            after = observe_provider(loaded,validate=False)
            write_new(output/'provider-after.json',after)
            verify_provider_status(after['status'],loaded['config']['provider'])
        delta = after['status']['quota']['known_tokens']-before['status']['quota']['known_tokens']
        if delta < 0:
            raise ValueError('provider counter rolled back during execution')
        from .local_campaign import load_local_campaign
        current = load_local_campaign(root/row['directory'])
        new_charge = sum(event['event']['charged_tokens'] for event in current['ledger']
                         if event['event']['type'] == 'finish')
        if delta != new_charge-old_charge:
            raise ValueError('actual provider token delta differs from independently audited attempt charges')
        gate = gate_campaign(root/row['directory'],_policy(loaded,row['selection']),
            expected_policy_digest=row['policy_digest'],expected_config_digest=row['config_digest'])
        write_gate_artifacts(output/'gate',gate)
        response = {'schema':'gauntlet-ci-run.v1','status':gate['status'],
                    'exit_code':gate['exit_code'],'provider_tokens_delta':delta,
                    'diagnostic_directory':str(output),'controller_status':result['status'],
                    'runner_config_digest':loaded['config_digest'],'manifest_digest':expected_manifest_digest,
                    'shard':shard,'ledger_charge_before':old_charge,'ledger_charge_after':new_charge,
                    'files':{name:file_digest(output/name) for name in
                             ('preflight.json','provider-before.json','provider-after.json','controller-result.json')},
                    'qualification_eligible':False}
        write_new(output/'result.json',response)
        return response


def audit_invocations(loaded, root, manifest, *, expected_manifest_digest, charged_tokens):
    """Missing, altered or partial quota witnesses cannot become a passing report."""
    directory = Path(root)/'controller-attempts'
    if not directory.exists():
        return ['provider-witnesses-missing'] if charged_tokens else []
    private_state(directory)
    paths = sorted(directory.iterdir())
    if len(paths) > 10000:
        raise ValueError('controller invocation count exceeds bound')
    errors,delta = [],0
    for path in paths:
        private_state(path)
        row = read_public(path/'result.json')
        diagnosis = read_public(path/'preflight.json')
        if diagnosis['config_digest'] != loaded['config_digest']:
            raise ValueError('invocation preflight belongs to another runner configuration')
        if row['status'] == 'preflight-failed':
            if diagnosis['passed'] is not False:
                raise ValueError('failed invocation changed its preflight outcome')
            errors.append('retained-controller-preflight-failure')
            continue
        expected_files = {'preflight.json','provider-before.json','provider-after.json','controller-result.json'}
        if (row['runner_config_digest'] != loaded['config_digest']
                or row['manifest_digest'] != expected_manifest_digest or diagnosis['passed'] is not True
                or type(row['shard']) is not int or not 0 <= row['shard'] < len(manifest['shards'])
                or set(row['files']) != expected_files
                or any(file_digest(path/name) != sha for name,sha in row['files'].items())):
            raise ValueError('invocation inputs or retained provider evidence changed')
        snapshots = [read_public(path/name)['status'] for name in ('provider-before.json','provider-after.json')]
        before,after = [verify_provider_status(value,loaded['config']['provider']) for value in snapshots]
        observed = after['known_tokens']-before['known_tokens']
        if (observed < 0 or type(row['provider_tokens_delta']) is not int
                or row['provider_tokens_delta'] != observed
                or any(type(row[name]) is not int or row[name] < 0 for name in
                       ('ledger_charge_before','ledger_charge_after'))
                or row['ledger_charge_after']-row['ledger_charge_before'] != observed):
            raise ValueError('invocation provider counter and ledger charges differ')
        delta += observed
    if delta != charged_tokens:
        errors.append('aggregate-provider-and-ledger-cost-mismatch')
    return errors


def report(loaded, root, *, expected_manifest_digest):
    with controller_environment(loaded):
        manifest,states = load_frozen(loaded,root,expected_manifest_digest=expected_manifest_digest)
        rows,errors = [],[]
        tokens,seconds = 0,0
        for shard,_state in zip(manifest['shards'],states,strict=True):
            gate = gate_campaign(Path(root)/shard['directory'],_policy(loaded,shard['selection']),
                expected_policy_digest=shard['policy_digest'],expected_config_digest=shard['config_digest'])
            rows.extend(gate['cells'])
            errors.extend(gate['errors'])
            tokens += gate['charged_model_tokens_all_attempts']
            seconds += gate['active_seconds_all_attempts']
        errors.extend(audit_invocations(loaded,root,manifest,
            expected_manifest_digest=expected_manifest_digest,charged_tokens=tokens))
        if tokens > loaded['campaign']['budgets']['campaign_tokens']:
            errors.append('aggregate-campaign-model-token-cap-exceeded')
        if seconds > loaded['campaign']['budgets']['campaign_seconds']:
            errors.append('aggregate-campaign-active-time-cap-exceeded')
        passed = not errors and all(row['status'] != 'failed' for row in rows)
        return {'schema':'gauntlet-ci-result.v1','status':'passed' if passed else 'failed',
                'exit_code':0 if passed else 1,'cells':rows,'errors':sorted(set(errors)),
                'selected_cases':len(loaded['config']['selection']),
                'runner_config_digest':loaded['config_digest'],'manifest_digest':expected_manifest_digest,
                'charged_model_tokens_all_attempts':tokens,'active_seconds_all_attempts':seconds,
                'qualification_eligible':False,'trust_status':'local-integrity-only'}


def main(args):
    loaded = None
    previous_handler = None
    if threading.current_thread() is threading.main_thread():
        previous_handler = signal.getsignal(signal.SIGTERM)
        def on_terminate(_signal,_frame):
            raise KeyboardInterrupt('CI controller received SIGTERM')
        signal.signal(signal.SIGTERM,on_terminate)
    try:
        loaded = load_config(args.config,expected_digest=args.expected_config_digest,asset_root=args.asset_root)
        with controller_environment(loaded):
            if args.action == 'preflight':
                result = preflight(loaded)
                result.update(status='passed' if result['passed'] else 'preflight-failed',
                              exit_code=0 if result['passed'] else 2,
                              cells=[{'episode_id':key,'status':'passed' if result['passed'] else 'failed',
                                      'reasons':[] if result['passed'] else ['preflight-failed']}
                                     for key in loaded['config']['selection']])
                result['diagnostics'] = result['errors']
                result['errors'] = [error['code'] for error in result['diagnostics']]
            elif args.action == 'freeze':
                result = freeze(loaded,args.state_root)
                result.update(status='frozen' if result['preflight_passed'] else 'frozen-preflight-failed',
                              exit_code=0 if result['preflight_passed'] else 2,
                              errors=[] if result['preflight_passed'] else ['preflight-failed'],cells=[])
            else:
                if args.action in {'run','resume'}:
                    result = run_shard(loaded,args.state_root,
                        expected_manifest_digest=args.expected_manifest_digest,shard=args.shard)
                else:
                    result = report(loaded,args.state_root,expected_manifest_digest=args.expected_manifest_digest)
    except (Exception,KeyboardInterrupt) as error:
        ids = loaded['config']['selection'] if loaded is not None else []
        cancelled = isinstance(error,KeyboardInterrupt)
        result = {'schema':'gauntlet-ci-result.v1','status':'cancelled' if cancelled else 'invalid-evidence',
                  'exit_code':130 if cancelled else 2,
                  'errors':['runner-'+type(error).__name__],
                  'diagnostic':str(error)[:4096],'selected_cases':len(ids),
                  'cells':[{'episode_id':key,'status':'failed','reasons':['runner-invalid-evidence']} for key in ids],
                  'qualification_eligible':False,'trust_status':'local-integrity-only'}
    finally:
        if previous_handler is not None:
            signal.signal(signal.SIGTERM,previous_handler)
    write_gate_artifacts(args.output_dir,result)
    print(canonical_json(result))
    return result['exit_code']
