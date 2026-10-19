"""One-command CI check over the existing profiles; never activates workflows."""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import re
import signal
import stat
import threading

from . import ci_runner, deterministic
from .beta_profile import build_feature_ai_profile, build_profile, feature_ai_protocol_mapping
from .ci_gate_report import write_gate_artifacts
from .ci_runner_config import file_digest, load_config, read_public
from .contracts import canonical_json


@contextmanager
def _lease_at(directory):
    """Kernel lease survives no dead owner; protect the fixed Root-owned lock."""
    import fcntl
    try:
        directory.mkdir(mode=0o700)
    except FileExistsError:
        pass
    ci_runner.private_state(directory, immutable_ancestry=True)
    fd = os.open(directory/'pipeline.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
            raise ValueError('CI lease must be a private ordinary controller file')
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ValueError('another Gauntlet CI check owns this VM; no work admitted') from error
        os.ftruncate(fd, 0)
        os.write(fd, str(os.getpid()).encode())
        yield
    finally:
        os.close(fd)


def vm_lease():
    return _lease_at(Path('/run/hol-gauntlet-ci'))


def validate_profile(loaded, profile, expected_source):
    if not re.fullmatch(r'[0-9a-f]{40}', expected_source or ''):
        raise ValueError('external full lowercase Guard commit SHA required')
    if loaded['runtime']['guard_source_sha'] != expected_source:
        raise ValueError('configured Guard artifact is not the commit under test')
    if loaded['config']['schema'] != 'gauntlet-ci-runner.v7':
        raise ValueError('CI check supports the reviewed v7 private-cell profile')
    if profile == 'beta-e2e':
        campaign, selection, policy = build_profile()
        if (loaded['campaign'] != campaign or loaded['policy'] != policy
                or loaded['config']['selection'] != selection):
            raise ValueError('beta-e2e requires the complete declared twelve-cell profile and policy')
    elif profile in {'feature-ai', 'feature-ai-protocol'}:
        protocol = profile == 'feature-ai-protocol'
        campaign, selection, policy = build_feature_ai_profile(protocol=protocol)
        if (loaded['campaign'] != campaign or loaded['policy'] != policy
                or loaded['config']['selection'] != selection
                or loaded['runtime'].get('mcp_protocol_profiles', {}) !=
                   (feature_ai_protocol_mapping(selection) if protocol else {})):
            raise ValueError('feature-ai requires the complete fixed two-cell adapter pair')
    elif profile != 'deterministic':
        raise ValueError('unsupported CI check profile')


def destinations(args):
    source = Path(__file__).resolve().parents[3]
    paths = [Path(args.state_root), Path(args.output_dir), Path(args.asset_root)]
    for path in paths:
        if not path.is_absolute() or path.resolve() != path:
            raise ValueError('canonical absolute CI paths required')
    state, output, assets = paths
    for index, left in enumerate(paths):
        if any(left.is_relative_to(right) or right.is_relative_to(left) for right in paths[index+1:]):
            raise ValueError('CI state, artifacts and immutable assets must be disjoint')
    if state.is_relative_to(source) or output.is_relative_to(source):
        raise ValueError('CI state and evidence must remain outside the source checkout')
    if state.exists() or output.exists():
        raise FileExistsError('CI check requires new state and output directories; retained runs are never replayed')
    from .campaign_paths import validate_ci_state_root, validate_private_cell_state_root
    validate_ci_state_root(state/'c')
    validate_private_cell_state_root(state)


def failed(profile, reason, code=2):
    ids = (deterministic.ROLES if profile == 'deterministic' else
           build_feature_ai_profile()[1] if profile in {'feature-ai', 'feature-ai-protocol'}
           else build_profile()[1])
    return {'status': 'interrupted' if code == 130 else 'invalid-evidence', 'exit_code': code,
            'selected_cases': len(ids), 'cells': [
                {'episode_id': key, 'status': 'failed', 'reasons': [reason]} for key in ids],
            'errors': [reason]}


def admit_matrix(loaded, root):
    """Reserve the whole declared matrix against the existing persistent ceiling."""
    witness = read_public(root/'preflight.json')['provider']['status']['quota']
    binding = read_public(loaded['paths']['provider_manifest'])['binding']
    if hashlib.sha256((canonical_json(binding)+'\n').encode()).hexdigest() != loaded['config']['provider']['binding_sha256']:
        raise ValueError('provider manifest does not bind the admitted accounting ceiling')
    ceiling = binding['maximum_accounted_tokens']
    planned = loaded['selection_reservations']['model_token_reservation']
    if (type(ceiling) is not int or ceiling > witness['token_cap']
            or witness['known_tokens'] + planned > ceiling):
        raise ValueError('complete selected matrix reservation exceeds approved provider allowance; no inference admitted')
    return {'known_tokens': witness['known_tokens'], 'maximum_accounted_tokens': ceiling,
            'planned_tokens': planned, 'model_requests': 0}


def run_live(loaded, root, record, profile='beta-e2e'):
    """Valid task/security failures are retained; unsafe execution state halts admission."""
    frozen = ci_runner.freeze(loaded, root/'c')
    record('freeze', frozen)
    pin = frozen['manifest_digest']
    if not frozen['preflight_passed']:
        return {**failed(profile, 'pipeline-preflight-failed'),
                'charged_model_tokens_all_attempts': 0}, pin, True
    record('admission', admit_matrix(loaded, root/'c'))
    halted = None
    diagnostic = None
    try:
        for shard in range(len(loaded['shards'])):
            phase = ci_runner.run_shard(loaded, root/'c', expected_manifest_digest=pin, shard=shard)
            record(f'shard-{shard:03d}', phase)
            if phase['exit_code'] not in {0, 1}:
                halted = phase['exit_code']
                break
            gate = read_public(Path(phase['diagnostic_directory'])/'gate/result.json')
            reasons = {reason for cell in gate['cells'] for reason in cell.get('reasons', [])}
            if gate['errors'] or reasons - {'task-utility-failed', 'security-invariants-violated'}:
                halted = 2
                break
    except (Exception, KeyboardInterrupt) as error:
        halted = 130 if isinstance(error, KeyboardInterrupt) else 2
        diagnostic = {'type': type(error).__name__, 'message': str(error)[:4096]}
    try:
        result = ci_runner.report(loaded, root/'c', expected_manifest_digest=pin)
    except (Exception, KeyboardInterrupt) as error:
        code = 130 if halted == 130 or isinstance(error, KeyboardInterrupt) else 2
        result = failed(profile, 'pipeline-aggregate-invalid', code)
        result['diagnostic'] = diagnostic
        result['audit_diagnostic'] = {'type': type(error).__name__, 'message': str(error)[:4096]}
        record('aggregate-failed', result)
        return result, pin, False
    record('aggregate', result)
    ids = [cell['episode_id'] for cell in result['cells']]
    if (result['selected_cases'] != len(loaded['config']['selection'])
            or len(ids) != len(set(ids)) or set(ids) != set(loaded['config']['selection'])):
        raise ValueError('aggregate omitted or duplicated required beta-e2e cases')
    if halted is not None:
        result = {**result, 'status': 'interrupted' if halted == 130 else 'invalid-evidence',
                  'exit_code': halted, 'errors': result['errors'] + ['pipeline-admission-halted']}
        if diagnostic:
            result['diagnostic'] = diagnostic
    return result, pin, not result['errors']


def main(args):
    """Write a single upload root; all model/Guard execution stays in existing backends."""
    previous = None
    if threading.current_thread() is threading.main_thread():
        previous = signal.getsignal(signal.SIGTERM)
        def terminate(_signal, _frame):
            raise KeyboardInterrupt('CI check terminated')
        signal.signal(signal.SIGTERM, terminate)
    result = failed(args.profile, 'pipeline-not-started')
    loaded = None
    phases = []
    pin = None
    usage_known = args.profile == 'deterministic'
    output_created = False
    def record(name, value):
        path = args.output_dir/(name+'.json')
        ci_runner.write_new(path, value)
        phases.append({'phase': name, 'path': path.name, 'sha256': file_digest(path)})
    try:
        destinations(args)
        ci_runner.private_state(args.output_dir, create=True, immutable_ancestry=True)
        output_created = True
        loaded = load_config(args.config, expected_digest=args.expected_config_digest, asset_root=args.asset_root)
        validate_profile(loaded, args.profile, args.expected_guard_source_sha)
        record('invocation', {'profile': args.profile, 'runner_config_digest': loaded['config_digest'],
            'expected_guard_source_sha': args.expected_guard_source_sha,
            'config': str(args.config), 'asset_root': str(args.asset_root),
            'state_root': str(args.state_root), 'pipeline_source_sha256': file_digest(Path(__file__)),
            'production_ci_activated': False})
        with vm_lease():
            root = ci_runner.private_state(args.state_root, create=True, immutable_ancestry=True)
            if args.profile == 'deterministic':
                result = deterministic.run_profile(loaded, root/'d')
                record('deterministic', result)
            else:
                result, pin, usage_known = run_live(loaded, root, record, args.profile)
    except (Exception, KeyboardInterrupt) as error:
        result = failed(args.profile, 'pipeline-execution-invalid', 130 if isinstance(error, KeyboardInterrupt) else 2)
        result['diagnostic'] = {'type': type(error).__name__, 'message': str(error)[:4096]}
        # Never report zero model usage after an incomplete live invocation.
        usage_known = args.profile == 'deterministic'
    finally:
        if previous is not None:
            signal.signal(signal.SIGTERM, previous)
    result = {**result, 'underlying_result_schema': result.get('schema'),
        'schema': 'gauntlet-ci-check.v1', 'profile': args.profile,
        'ci_policy': 'proposed-blocking' if args.profile == 'deterministic' else 'advisory',
        'expected_guard_source_sha': args.expected_guard_source_sha,
        'guard_source_sha': loaded['runtime']['guard_source_sha'] if loaded else None,
        'runner_config_digest': args.expected_config_digest, 'frozen_manifest_digest': pin,
        'model_usage_known': usage_known,
        'model_tokens': (0 if args.profile == 'deterministic' else
                         result.get('charged_model_tokens_all_attempts') if usage_known else None),
        'phases': phases, 'raw_state_root': str(args.state_root),
        'qualification_eligible': False, 'trust_status': 'local-integrity-only',
        'production_ci_activated': False}
    if output_created:
        write_gate_artifacts(args.output_dir/'report', result)
    print(canonical_json(result))
    return result['exit_code']
