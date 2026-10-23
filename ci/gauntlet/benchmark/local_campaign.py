"""Frozen, sequential local diagnostics. This controller never certifies a product.

Only the live lane invokes the actual pilot. The injected runner is restricted to
an explicitly frozen unit-scheduling lane, whose results are never live evidence.
Resume retains every attempt and refuses incomplete or modified evidence.
"""
from __future__ import annotations

import base64
import json
import os
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

from .authored_challenges import BASE_WORKFLOWS, load_authored_challenges, load_authored_snapshot
from .campaign import verify_campaign
from .campaign_execution import cell_cleanup, developer_cell, execute_cell, reservation, token_charge
from .campaign_execution import unsupported_cell as _unsupported
from .campaign_identity import hash_file as _hash
from .campaign_identity import public_identities as _identities
from .campaign_paths import attempt_directory, attempt_path, configure_layout, validate_layout
from .catalog import load_catalog, load_fixture
from .contracts import canonical_json, digest
from .local_campaign_custody import bind_isolation, cleanup_complete, freeze_isolation, verify_isolation_freeze
from .model_endpoint import model_endpoint
from .statistics import fixed_template_interval
from .world import verify_receipts

SOURCE = Path(__file__).resolve().parent
EVIDENCE_FILES = ('report.json', 'initial-state.json', 'final-state.json',
                  'effect-receipts.json', 'transport-events.json', 'model-budget.json',
                  'agent-events.jsonl', 'agent-stderr.txt', 'public-episode.json', 'upstream-transport-events.json',
                  'agent-runtime/agent-events.jsonl', 'agent-runtime/agent-stderr.txt',
                  'agent-runtime/isolation.json', 'agent-runtime/public/episode.json')
STARTUP_ERRORS = {'Error: MCP endpoint connection failed',
                  'Error: declared MCP endpoint did not finish connecting'}


def _read(path):
    return json.loads(path.read_text(encoding='utf-8'))


def _write(path, value):
    with path.open('x', encoding='utf-8') as stream:
        stream.write(canonical_json(value) + '\n')
        stream.flush()
        os.fsync(stream.fileno())


def freeze_local_campaign(root: Path, *, campaign: dict, episode_ids: list[str],
                          runtime: dict, max_episodes: int,
                          execution_lane: str = 'live', attempt_layout: str = 'legacy-v1') -> dict:
    """Create immutable selection plus a mandatory budget preview before inference.

    Runtime artifacts must be explicitly supplied public file paths. Model ID and
    a local endpoint alone do not independently pin provider/model weight bytes.
    """
    root = Path(root)
    if not root.is_absolute() or root.resolve().is_relative_to(SOURCE):
        raise ValueError('campaign directory must be absolute and outside source')
    if execution_lane not in {'live', 'unit-scheduling'}:
        raise ValueError('unknown execution lane')
    campaign = verify_campaign(campaign)
    if (type(max_episodes) is not int or not 1 <= max_episodes <= 10000
            or not episode_ids or len(episode_ids) > max_episodes
            or len(set(episode_ids)) != len(episode_ids)):
        raise ValueError('exact bounded unique episode selection required')
    by_id = {row['id']: row for row in campaign['inventory']}
    if not set(episode_ids) <= set(by_id):
        raise ValueError('episode selection is outside frozen inventory')
    allowed = {'bun', 'sdk_root', 'model_id', 'base_url', 'protected_adapter', 'artifacts'}
    if 'isolated' in runtime:
        allowed.add('isolated')
    if 'product_isolated' in runtime:
        allowed.add('product_isolated')
    if 'zod_cache' in runtime:
        allowed.add('zod_cache')
    if runtime.get('protected_adapter') == 'hol-guard':
        allowed |= {'guard_python', 'guard_source_sha'}
        allowed |= set(runtime) & {'guard_package_version'}
    allowed |= set(runtime) & {'guard_prefix_digest', 'guard_bwrap_sha256', 'guard_executor_image_id'}
    allowed |= set(runtime) & {'guard_private_cell','guard_conformance','mcp_protocol_profiles','mcp_agent_surfaces'}
    if set(runtime) != allowed or not isinstance(runtime['artifacts'], list):
        raise ValueError('runtime requires exact explicit public artifact inventory')
    runtime = json.loads(canonical_json(runtime))
    from .mcp_agent_profile import validate
    validate(runtime.get('mcp_agent_surfaces'))
    if 'mcp_protocol_profiles' in runtime:
        from .mcp_protocol_campaign import validate_mapping
        runtime['mcp_protocol_profiles'] = validate_mapping(runtime['mcp_protocol_profiles'], campaign['inventory'])
    runtime.setdefault('isolated', False)
    if type(runtime['isolated']) is not bool:
        raise ValueError('isolated runtime declaration must be an explicit boolean')
    if ('product_isolated' in runtime and type(runtime['product_isolated']) is not bool):
        raise ValueError('product isolation must be an explicit boolean')
    if runtime.get('product_isolated') and (not runtime['isolated']
            or runtime['protected_adapter'] != 'hol-guard'):
        raise ValueError('product isolation requires isolated HOL Guard runtime')
    from .campaign_identity import validate_product_pins
    validate_product_pins(runtime)
    if runtime['protected_adapter'] == 'hol-guard' and not Path(runtime['guard_python']).is_absolute():
        raise ValueError('Guard Python must be an absolute installed venv path')
    # Preserve lexical venv path: resolving Python's symlink loses sys.prefix.
    for key in ('bun', 'sdk_root', *(['zod_cache'] if 'zod_cache' in runtime else [])):
        if not Path(runtime[key]).is_absolute():
            raise ValueError('runtime paths must be absolute')
        runtime[key] = str(Path(runtime[key]).resolve())
    if len(runtime['artifacts']) > 256:
        raise ValueError('runtime artifact inventory exceeds bound')
    for value in runtime['artifacts']:
        if not Path(value).is_absolute():
            raise ValueError('runtime artifact paths must be absolute')
    model_endpoint(runtime['base_url'])
    budgets = campaign['budgets']
    if (budgets['concurrency'] != 1 or budgets['max_retries'] not in {0, 1}
            or not 1 <= budgets['episode_seconds'] <= 1800
            or not 1 <= budgets['tool_operations'] <= 500
            or not 1 <= budgets['model_tokens'] <= 1000000):
        raise ValueError('budgets exceed sequential pilot bounds')
    cells = [by_id[key] for key in episode_ids]
    workflows = {row['id']: row for row in load_catalog() + load_authored_challenges()}
    for cell in cells:
        if cell['workflow_id'] not in workflows:
            raise ValueError('only public or implementation-team-authored inventory supported')
        if cell['workflow_digest'] != digest(workflows[cell['workflow_id']]):
            raise ValueError('workflow definition changed since compilation')
    supported_cells = [cell for cell in cells if _unsupported(cell, runtime, budgets) is None]
    runnable = len(supported_cells)
    reserves = [reservation(cell, budgets) for cell in supported_cells]
    attempts = runnable * (1 + budgets['max_retries'])
    preview = {'selected_episodes': len(cells), 'runnable_episodes': runnable,
               'unsupported_episodes': len(cells) - runnable, 'maximum_attempts': attempts,
               'maximum_tool_operations': sum(r['tool_operation_reservation'] for r in reserves)
                                          * (1 + budgets['max_retries']),
               'model_token_reservation': sum(r['model_token_reservation'] for r in reserves)
                                         * (1 + budgets['max_retries']),
               'maximum_model_tokens': None,
               'model_token_limit_semantics': 'observed-response stop threshold; provider may cross it in one response',
               'maximum_controller_seconds': sum(r['controller_seconds_reservation'] for r in reserves)
                                             * (1 + budgets['max_retries']),
               'campaign_model_token_cap': budgets['campaign_tokens'],
               'campaign_active_seconds_cap': budgets['campaign_seconds']}
    config = {'schema': 'gauntlet-local-campaign.v1', 'campaign': campaign,
              'cells': cells, 'runtime': runtime, 'execution_lane': execution_lane,
              'isolation_tuple': freeze_isolation(runtime), 'identities': _identities(runtime), 'preview': preview,
              'controller_python': {'executable': sys.executable, 'prefix': sys.prefix,
                                    'version': sys.version},
              'qualification_eligible': False,
              'qualification_reasons': [
                                        ('local isolation diagnostic' if runtime['isolated']
                                         else 'local shared-UID diagnostic'),
                                        'no independently pinned model/provider weights',
                                        'no blind authored-challenge custody or certification']}
    configure_layout(config,attempt_layout)
    config['config_digest'] = digest(config)
    root.mkdir(mode=0o700)
    (root / attempt_directory(config)).mkdir(mode=0o700)
    descriptor = os.open(root / 'attempts.jsonl', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(descriptor)
    _write(root / 'frozen.json', config)
    return {'config_digest': config['config_digest'], 'preview': preview,
            'preview_digest': digest(preview), 'qualification_eligible': False}


def _ledger(root):
    path = root / 'attempts.jsonl'
    if not path.exists():
        return []
    rows = []
    for line in path.read_text(encoding='utf-8').splitlines():
        row = json.loads(line)
        if (row['sequence'] != len(rows) or row['previous_hash'] != (digest(rows[-1]) if rows else '0' * 64)
                or row['event_digest'] != digest(row['event'])):
            raise ValueError('append-only attempt ledger modified')
        rows.append(row)
    return rows


def _append(root, rows, event):
    row = {'sequence': len(rows), 'previous_hash': digest(rows[-1]) if rows else '0' * 64,
           'event_digest': digest(event), 'event': event}
    with (root / 'attempts.jsonl').open('a', encoding='utf-8') as stream:
        stream.write(canonical_json(row) + '\n')
        stream.flush()
        os.fsync(stream.fileno())
    rows.append(row)


def _audit_attempt(path, report):
    if report.get('group') == 'developer':
        from .developer_campaign import audit_developer_attempt
        return audit_developer_attempt(path, report)
    if report.get('group') == 'approval':
        from .approval_campaign import audit_approval_attempt
        return audit_approval_attempt(path, report)
    if _read(path / 'report.json') != report:
        raise ValueError('runner report differs from retained report')
    receipts = _read(path / 'effect-receipts.json')
    verify_receipts(receipts, base64.b64decode(report['producer_public_key'], validate=True),
                    expected_count=report['receipt_count'],
                    expected_final_hash=report['receipt_final_hash'])
    initial, final = _read(path / 'initial-state.json'), _read(path / 'final-state.json')
    workflow_id = report['workflow_id']
    if workflow_id in BASE_WORKFLOWS:
        from .challenge_oracles import score_authored_challenge
        expected = load_authored_snapshot(workflow_id, report['variant'])
        score = score_authored_challenge(workflow_id, initial, final, receipts, receipts_verified=True)
    else:
        from .business_oracles import score_business_workflow
        expected = load_fixture(workflow_id, report['variant'])
        score = score_business_workflow(workflow_id, initial, final, receipts, receipts_verified=True)
    if initial != expected or report['score'] != score:
        raise ValueError('retained seed or independently recomputed outcome differs')
    from .business_model_budget import audit_business_model_budget
    budget_hashes = audit_business_model_budget(path, report)
    hashes = {name: _hash(path / name) for name in EVIDENCE_FILES if (path / name).exists()}
    if any(hashes.get(name) != value for name, value in budget_hashes.items()):
        raise ValueError('retained business model evidence differs from verified bytes')
    if not {'report.json', 'initial-state.json', 'final-state.json',
            'effect-receipts.json', 'transport-events.json'} <= set(hashes):
        raise ValueError('completed attempt lacks required retained evidence')
    return hashes


def _bind_report(config, cell, report, *, attempt_path):
    runtime = config['runtime']
    from .mcp_agent_profile import bind_report
    bind_report(runtime, report)
    from .mcp_protocol_campaign import bind_protocol_report
    bind_protocol_report(runtime, cell, report, attempt_path)
    expected = (cell['workflow_id'], cell['variant'],
                runtime['protected_adapter'] if cell['protected'] else 'unprotected', runtime['model_id'])
    actual = tuple(report[key] for key in ('workflow_id', 'variant', 'adapter', 'model_id'))
    if actual != expected:
        raise ValueError('pilot result identity differs from frozen episode')
    if developer_cell(cell):
        if report.get('group') != 'developer':
            raise ValueError('developer cell lacks developer-specific evidence')
        if config['execution_lane'] == 'live':
            from .developer_campaign_isolation import bind_developer_isolation
            bind_developer_isolation(config, report, attempt_path=attempt_path)
    elif cell['group'] == 'approval':
        if report.get('group') != 'approval':
            raise ValueError('approval cell lacks approval-specific evidence')
        if config['execution_lane'] == 'live':
            from .approval_campaign import bind_approval_isolation
            bind_approval_isolation(config, report, attempt_path=attempt_path)
    else:
        if report.get('group') in {'approval', 'developer'}:
            raise ValueError(f'business cell cannot substitute {report["group"]} evidence')
        bind_isolation(config, report, attempt_path=attempt_path)
        if config['execution_lane'] == 'live':
            from .business_model_budget import bind_business_model_budget
            bind_business_model_budget(config, report)
            budgets = config['campaign']['budgets']
            expected_budgets = {'wall_seconds': budgets['episode_seconds'],
                'tool_calls': budgets['tool_operations'], 'model_tokens': budgets['model_tokens']}
            if any(report.get('budgets', {}).get(key) != value for key, value in expected_budgets.items()):
                raise ValueError('actual business budget differs from frozen campaign reservation')
    # Developer custody is bound above by bind_developer_isolation using its
    # distinct signed builtin/MCP evidence, not the business report contract.
    if expected[2] == 'hol-guard' and config['execution_lane'] == 'live' and not developer_cell(cell):
        if runtime.get('product_isolated'):
            from .campaign_product_custody import bind_product_report
            bind_product_report(config, report, attempt_path=attempt_path)
        elif digest(report['guard_identity']) != config['identities']['installed-guard-public-identity']:
            raise ValueError('pilot Guard identity differs from frozen installed artifact')


def load_local_campaign(root: Path) -> dict:
    """Verify identity and all retained completed evidence; never reconstruct rows."""
    root = Path(root)
    config = _read(root / 'frozen.json')
    if config['config_digest'] != digest({k: v for k, v in config.items() if k != 'config_digest'}):
        raise ValueError('frozen configuration changed')
    validate_layout(config)
    verify_campaign(config['campaign'])
    verify_isolation_freeze(config)
    if config['controller_python'] != {'executable': sys.executable, 'prefix': sys.prefix,
                                       'version': sys.version}:
        raise ValueError('controller Python runtime changed')
    if config['identities'] != _identities(config['runtime']):
        raise ValueError('frozen source, fixture, SDK or runtime bytes changed')
    rows = _ledger(root)
    pending = None
    selected = {row['id']: row for row in config['cells']}
    terminal = set()
    attempts = Counter()
    for row in rows:
        event = row['event']
        key = event['episode_id']
        if key not in selected or key in terminal:
            raise ValueError('ledger contains unscheduled or repeated terminal episode')
        if event['type'] == 'unsupported':
            if pending is not None:
                raise ValueError('unsupported row overlaps active attempt')
            terminal.add(key)
        elif event['type'] == 'start':
            if (pending is not None or event['attempt'] != attempts[key]
                    or event['attempt'] > config['campaign']['budgets']['max_retries']):
                raise ValueError('overlapping or nonsequential attempts')
            pending = (key, event['attempt'])
        elif event['type'] == 'finish':
            if pending != (key, event['attempt']):
                raise ValueError('finish does not match started attempt')
            path = attempt_path(root,config,key,event['attempt'])
            _bind_report(config, selected[key], event['report'], attempt_path=path)
            if event['hashes'] != _audit_attempt(path, event['report']):
                raise ValueError('retained attempt evidence modified')
            if not cell_cleanup(event['report'], isolated=config['runtime']['isolated']):
                raise ValueError('child cleanup unresolved; controller reconciliation required')
            if event['retry'] and (event['attempt'] >= config['campaign']['budgets']['max_retries']
                                   or not _retryable(path, event['report'])):
                raise ValueError('retained retry lacks controller evidence')
            attempts[key] += 1
            if not event['retry']:
                terminal.add(key)
            pending = None
        else:
            raise ValueError('unknown attempt ledger event')
    if pending:
        raise ValueError('incomplete attempt retained; cleanup requires controller reconciliation')
    return {'config': config, 'ledger': rows, 'terminal_ids': sorted(terminal)}


def _retryable(path, report):
    if (report.get('execution_valid') is not False or report.get('inference_started') is not False
            or report.get('controller_failure_class') != 'mcp-connect-before-inference'
            or report.get('retryable_infrastructure') is not True
            or not cleanup_complete(report, isolated=report.get('execution_lane') == 'isolated-linux')
            or report.get('receipt_count') != 0 or report.get('budget_exhausted')):
        return False
    events_path = path / ('agent-runtime/agent-events.jsonl' if report.get('execution_lane') == 'isolated-linux'
                          else 'agent-events.jsonl')
    if not events_path.is_file() or _read(path / 'effect-receipts.json'):
        return False
    events = [json.loads(line) for line in events_path.read_text().splitlines()]
    errors = [e for e in events if e.get('type') == 'episode_error']
    return (not any(e.get('type') in {'inference_start', 'episode_start'} for e in events)
            and report.get('controller_error') is None
            and report.get('model_tokens') in {None, 0}
            and bool(errors) and all(e.get('phase') == 'startup'
                                    and e.get('retryableInfrastructure') is True
                                    and e.get('error') in STARTUP_ERRORS for e in errors))


def run_local_campaign(root: Path, *, preview_digest: str, runner=None, admission_check=None) -> dict:
    """Execute the previewed selection sequentially; live calls always use run_pilot."""
    root = Path(root)
    lock = root / 'controller.lock'
    descriptor = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        state = load_local_campaign(root)
        config, rows = state['config'], state['ledger']
        if preview_digest != digest(config['preview']):
            raise ValueError('explicit frozen budget preview digest required')
        if runner is not None and config['execution_lane'] != 'unit-scheduling':
            raise ValueError('injected runners cannot produce live evidence')
        if runner is None:
            if config['execution_lane'] != 'live':
                raise ValueError('unit scheduling requires its explicit injected runner')
            from .pilot import run_pilot
            runner = run_pilot
        runtime, budgets = config['runtime'], config['campaign']['budgets']
        finished = [r['event'] for r in rows if r['event']['type'] == 'finish']
        for event in finished:
            halt = _token_halt(event['report'])
            if halt:
                return _summary(config, rows, halt)
        charged_tokens = sum(e['charged_tokens'] for e in finished)
        elapsed = sum(e['elapsed_seconds'] for e in finished)
        if charged_tokens > budgets['campaign_tokens']:
            return _summary(config, rows, 'campaign-model-token-cap-exceeded')
        if elapsed > budgets['campaign_seconds']:
            return _summary(config, rows, 'campaign-active-time-cap-exceeded')
        for cell in config['cells']:
            key = cell['id']
            if key in state['terminal_ids']:
                continue
            unsupported = _unsupported(cell, runtime, budgets)
            if unsupported:
                _append(root, rows, {'type': 'unsupported', 'episode_id': key, 'reason': unsupported})
                continue
            attempts = sum(e['episode_id'] == key for e in finished)
            while attempts <= budgets['max_retries']:
                reserve = reservation(cell, budgets)
                if config['identities'] != _identities(runtime):
                    raise ValueError('frozen implementation changed before inference')
                verify_isolation_freeze(config)
                if admission_check is not None:
                    reason = admission_check(cell, reserve)
                    if reason:
                        return _summary(config, rows, reason)
                if (charged_tokens + reserve['model_token_reservation'] > budgets['campaign_tokens']
                        or elapsed + reserve['controller_seconds_reservation'] > budgets['campaign_seconds']):
                    return _summary(config, rows, 'campaign-budget-limit')
                path = attempt_path(root,config,key,attempts)
                if path.exists():
                    raise ValueError('fresh attempt directory already exists')
                _append(root, rows, {'type': 'start', 'episode_id': key, 'attempt': attempts})
                started = time.monotonic()
                report = execute_cell(path, cell, runtime, budgets, runner=runner,
                                      execution_lane=config['execution_lane'])
                duration = time.monotonic() - started
                hashes = _audit_attempt(path, report)
                _bind_report(config, cell, report, attempt_path=path)
                retry = attempts < budgets['max_retries'] and _retryable(path, report)
                charge = token_charge(report, budgets)
                if _retryable(path, report):
                    charge = 0
                event = {'type': 'finish', 'episode_id': key, 'attempt': attempts,
                         'report': report, 'hashes': hashes, 'retry': retry,
                         'charged_tokens': charge, 'elapsed_seconds': duration}
                _append(root, rows, event)
                finished.append(event)
                charged_tokens += charge
                elapsed += duration
                attempts += 1
                if not cell_cleanup(report, isolated=runtime['isolated']):
                    raise ValueError('child cleanup unresolved; stop all further inference')
                halt = _token_halt(report)
                if halt:
                    return _summary(config, rows, halt)
                if charged_tokens > budgets['campaign_tokens']:
                    return _summary(config, rows, 'campaign-model-token-cap-exceeded')
                if elapsed > budgets['campaign_seconds']:
                    return _summary(config, rows, 'campaign-active-time-cap-exceeded')
                if not retry:
                    break
        return _summary(config, rows, 'finished')
    finally:
        os.close(descriptor)
        lock.unlink()


def _token_halt(report):
    tokens = report.get('model_tokens')
    if report.get('inference_started') and (report.get('model_usage_known') is not True
                                           or type(tokens) is not int or tokens < 0):
        return 'model-token-usage-unknown'
    return None


def _summary(config, rows, status):
    events = [row['event'] for row in rows]
    final = [e for e in events if e['type'] == 'finish' and not e['retry']]
    reports = [e['report'] for e in final]
    oracle_valid = [r for r in reports if r['score']['evidence_validity'] == 'valid']
    security_known = [r for r in reports if r['score']['evidence_validity'] == 'valid'
                      or r['score']['security_status'] == 'violated']
    valid = [r for r in oracle_valid if r['execution_valid']]
    groups = defaultdict(list)
    for report in security_known:
        groups[(report['workflow_id'], report['variant'], report['adapter'])].append(report)
    return {'schema': 'gauntlet-local-campaign-summary.v1', 'status': status,
            'execution_lane': config['execution_lane'], 'qualification_eligible': False,
            'isolation_requested': config['runtime']['isolated'],
            'product_prevention_credit': None, 'config_digest': config['config_digest'],
            'selected_denominator': len(config['cells']), 'terminal_outcomes': len(final),
            'unsupported': sum(e['type'] == 'unsupported' for e in events),
            'all_attempts': sum(e['type'] == 'finish' for e in events),
            'execution_valid_denominator': sum(r['execution_valid'] for r in reports),
            'oracle_valid_denominator': len(oracle_valid),
            'utility_denominator': len(valid), 'security_denominator': len(security_known),
            'task_status_counts': dict(Counter(r['score']['task_status'] for r in valid)),
            'security_status_counts': dict(Counter(r['score']['security_status'] for r in security_known)),
            'exposure_counts_all_terminal': dict(Counter(r['exposure'] for r in reports)),
            'secure_completion_count': sum(r['score']['secure_completion'] for r in valid),
            'approval_authorized_outcome_count': sum(r.get('group') == 'approval'
                and r['score']['authorized_terminal_state'] for r in valid),
            'charged_model_tokens': sum(e['charged_tokens'] for e in events if e['type'] == 'finish'),
            'response_token_threshold_overruns': sum(
                type(r.get('model_tokens')) is int and r['model_tokens'] > config['campaign']['budgets']['model_tokens']
                for r in reports),
            'fixed_template_intervals': [
                {'workflow_id': key[0], 'variant': key[1], 'adapter': key[2],
                 'secure_completion': fixed_template_interval(
                     sum(r['score']['secure_completion'] for r in values if r['execution_valid']
                         and r['score']['evidence_validity'] == 'valid'),
                     sum(r['execution_valid'] and r['score']['evidence_validity'] == 'valid' for r in values)),
                 'security_held': fixed_template_interval(
                     sum(r['score']['security_status'] == 'invariants-held' for r in values), len(values))}
                for key, values in sorted(groups.items())],
            'limitations': ['no pooled IID suite interval', 'no inferred model ingestion',
                            'all attempts retained; terminal task failures never retried',
                            'local artifact integrity is not independently anchored certification']}
