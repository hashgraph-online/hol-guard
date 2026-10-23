"""Approval-specific campaign execution and independent retained-evidence audit.

External decisions are service/controller effects, never Guard approval credit.
The driver must reserve both real model phases before scheduling one cell.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .approval_oracles import score_approval_variant
from .approval_pilot import phase_usage, run_approval_pilot
from .business_model_budget import SCHEMA as MODEL_BUDGET_SCHEMA
from .business_model_budget import verify_model_budget
from .catalog import load_approval_variants, load_fixture
from .contracts import canonical_json, digest, strict_json_loads
from .model_endpoint import DEFAULT_BASE_URL
from .world import verify_receipts

EVIDENCE_FILES = ('approval-report.json', 'report.json', 'initial-state.json', 'preparation-state.json',
                  'final-state.json', 'effect-receipts.json', 'transport-events.json',
                  'upstream-transport-events.json', 'approval-context.json', 'approval-claims.json',
                  'approval-decision.json')
PHASE_FILES = ('agent-events.jsonl', 'agent-stderr.txt', 'isolation.json', 'public/episode.json',
               'model-bridge-stderr.txt', 'model-budget.json')


def approval_reservation(budgets: dict) -> dict:
    for name, upper in (('episode_seconds', 1800), ('tool_operations', 500), ('model_tokens', 1000000)):
        if type(budgets.get(name)) is not int or not 1 <= budgets[name] <= upper:
            raise ValueError('approval phase budget exceeds explicit executor bounds')
    return {'maximum_phases': 2, 'model_token_reservation': 2 * budgets['model_tokens'],
            'tool_operation_reservation': 2 * budgets['tool_operations'],
            'controller_seconds_reservation': 2 * (budgets['episode_seconds'] + 90) + 60,
            'per_phase_launch_cleanup_seconds': 90, 'native_lifecycle_seconds': 60,
            'model_token_limit_semantics': 'per-phase observed-response stop threshold, not a hard token ceiling',
            'controller_seconds_semantics': 'subprocess/lifecycle reservation; evidence hashing not hard wall bounded'}


def _read(path: Path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 128 * 1024**2:
        raise ValueError('retained approval evidence must be a bounded regular file')
    return strict_json_loads(path.read_text())


def _write(path: Path, value):
    # Approval evidence contains synthetic private records and the public
    # verification key. Keep it in the controller's owner-only attempt directory.
    parent_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        parent = os.fstat(parent_fd)
        if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.getuid() or stat.S_IMODE(parent.st_mode) != 0o700:
            raise ValueError('approval evidence requires an owner-only attempt directory')
        fd = os.open(
            path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600, dir_fd=parent_fd,
        )
    finally:
        os.close(parent_fd)
    with os.fdopen(fd, 'w', encoding='utf-8') as stream:
        # Only the private synthetic approval attempt is written here; a
        # public verification key is not a secret. Real credentials are absent.
        # codeql[py/clear-text-storage-sensitive-data]
        stream.write(canonical_json(value) + '\n')
        stream.flush()
        os.fsync(stream.fileno())


def _hash(path: Path):
    if path.is_symlink() or not path.is_file():
        raise ValueError('approval identity file missing or replaced by symlink')
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _variant(cell: dict) -> dict:
    variant = next((row for row in load_approval_variants() if row['id'] == cell.get('variant')), None)
    if cell.get('group') != 'approval' or variant is None or variant['workflow_id'] != cell.get('workflow_id'):
        raise ValueError('approval cell must bind an exact same-workflow catalog variant')
    return variant


def _recompute(raw: dict) -> dict:
    receipts = raw['world_receipts']
    anchor = raw['world_receipt_anchor']
    verify_receipts(receipts, base64.b64decode(raw['public_key'], validate=True),
                    expected_count=anchor['count'], expected_final_hash=anchor['final_hash'])
    phase = raw['preparation']
    return score_approval_variant(raw['variant'], raw['initial_snapshot'], raw['final_snapshot'], receipts,
        preparation_snapshot=phase['snapshot'], preparation_receipt_count=phase['receipt_count'],
        approval_args=raw['approval_args'] or {}, trusted_phase_digest=raw['trusted_phase_digest'],
        grant=raw['external_decision'], controller_receipts=raw['controller_claims'],
        trusted_controller_key=base64.b64decode(raw['controller_approval_anchor'], validate=True),
        receipts_verified=True)


def _phase_observations(path: Path, raw: dict) -> list[dict]:
    observed = []
    for index, phase in enumerate(raw['phases']):
        if index >= 2:
            raise ValueError('approval envelope has more than two declared phases')
        name = ('preparation', 'continuation')[index]
        root = path / name
        envelope = _read(root / 'isolation.json')
        if envelope != phase['isolation']:
            raise ValueError('retained phase declaration differs from signed approval envelope')
        Ed25519PublicKey.from_public_bytes(base64.b64decode(raw['public_key'], validate=True)).verify(
            base64.b64decode(envelope['signature'], validate=True), canonical_json(envelope['record']).encode())
        events_path = root / 'agent-events.jsonl'
        if phase['events_sha256'] is None:
            if events_path.exists():
                raise ValueError('unobserved phase event stream appeared retrospectively')
            events, malformed = [], False
        else:
            if _hash(events_path) != phase['events_sha256']:
                raise ValueError('actual phase event bytes changed')
            events, malformed = [], False
            for line in events_path.read_text().splitlines():
                try:
                    events.append(json.loads(line))
                except ValueError:
                    malformed = True
        record = envelope['record']
        config_path = root / 'public/episode.json'
        if config_path.exists() and digest(_read(config_path)) != record['public_config_digest']:
            raise ValueError('retained public phase configuration changed')
        usage = phase_usage(events)
        budget = phase.get('model_budget_evidence') or record.get('model_budget_evidence')
        if budget is not None:
            if _read(root / 'model-budget.json') != budget or record.get('model_budget_evidence') != budget:
                raise ValueError('phase provider budget differs from retained signed isolation')
            usage = verify_model_budget(budget,
                trusted_public_key=base64.b64decode(raw['public_key'], validate=True),
                model_id=raw['model_id'], max_tokens=raw['budgets_per_phase']['tokens'],
                base_url=raw.get('model_base_url', DEFAULT_BASE_URL),
                config_digest=record['public_config_digest'],
                maximum_requests=raw['budgets_per_phase']['tool_calls'] + 20)
        elif malformed:
            usage['model_usage_known'] = False
        endings = [row for row in events if row.get('type') == 'episode_end']
        if phase.get('usage', usage) != usage or phase['episode_end'] != (endings[-1] if endings else None):
            raise ValueError('phase token accounting or terminal observer differs from actual event stream')
        inference = usage.get('inference_started', any(row.get('type') == 'inference_start' for row in events))
        valid = (record['exit_code'] == 0 and record['controller_error'] is None and not malformed
                 and bool(endings) and not any(row.get('type') == 'episode_error' for row in events)
                 and record['isolation_observed'] and record['assets_unchanged'] and record['cleanup_complete'])
        if raw.get('model_budget_evidence_version') == MODEL_BUDGET_SCHEMA:
            valid = (valid and budget is not None and usage['model_usage_known'] and inference
                     and usage['cleanup_complete'])
        observed.append({'name': name, 'usage': usage, 'inference_started': inference,
                         'execution_valid': bool(valid), 'isolation': envelope,
                         'model_budget_evidence': budget,
                         'budget_exhausted': usage.get('budget_exhausted', False)
                            or any(row.get('status') == 'budget-exhausted' for row in endings)})
    for partial in raw.get('partial_phase_events', []):
        name = partial['name']
        if name not in {'preparation', 'continuation'} or any(phase['name'] == name for phase in observed):
            raise ValueError('partial approval phase conflicts with a measured phase')
        event_file = path / name / 'agent-events.jsonl'
        if _hash(event_file) != partial['events_sha256']:
            raise ValueError('partial actual model observer bytes changed')
        events = []
        for line in event_file.read_text().splitlines():
            try:
                events.append(json.loads(line))
            except ValueError:
                continue
        usage = phase_usage(events)
        usage['model_usage_known'] = False
        budget = partial.get('model_budget_evidence')
        if budget is not None:
            if _read(path / name / 'model-budget.json') != budget:
                raise ValueError('partial phase provider budget changed')
            usage = verify_model_budget(budget, trusted_public_key=base64.b64decode(raw['public_key'], validate=True),
                model_id=raw['model_id'], max_tokens=raw['budgets_per_phase']['tokens'],
                base_url=raw.get('model_base_url', DEFAULT_BASE_URL),
                maximum_requests=raw['budgets_per_phase']['tool_calls'] + 20)
        if usage != partial['usage']:
            raise ValueError('partial actual model accounting changed')
        observed.append({'name': name, 'usage': usage, 'inference_started': usage.get('inference_started', any(
            row.get('type') == 'inference_start' for row in events)), 'execution_valid': False,
            'model_budget_evidence': budget, 'isolation': None,
            'budget_exhausted': usage.get('budget_exhausted', False)
                or any(row.get('status') == 'budget-exhausted' for row in events)})
    for phase in raw.get('unstarted_phase_budgets', []):
        name, budget = phase['name'], phase['model_budget_evidence']
        if name not in {'preparation', 'continuation'} or any(p['name'] == name for p in observed):
            raise ValueError('unstarted phase budget conflicts with actual measured phase')
        mode = 'relay-startup-incomplete' if phase.get('launch_requested') else 'not-launched'
        if (path / name).exists() or budget['record']['mode'] != mode:
            raise ValueError('unstarted phase forwarding boundary exists')
        usage = verify_model_budget(budget, trusted_public_key=base64.b64decode(raw['public_key'], validate=True),
                                   model_id=raw['model_id'], max_tokens=raw['budgets_per_phase']['tokens'],
                base_url=raw.get('model_base_url', DEFAULT_BASE_URL),
                                   maximum_requests=raw['budgets_per_phase']['tool_calls'] + 20)
        observed.append({'name': name, 'usage': usage, 'inference_started': False, 'execution_valid': False,
                         'isolation': None, 'model_budget_evidence': budget, 'budget_exhausted': False})
    observed.sort(key=lambda phase: phase['name'] == 'continuation')
    return observed


def _normalized(path: Path, cell: dict, raw: dict, *, execution_lane='live') -> dict:
    variant = _variant(cell)
    if raw['variant'] != variant or raw['decision_mode'] != 'catalog':
        raise ValueError('campaign cannot substitute an approval variant or scenario transition')
    if raw['initial_snapshot'] != load_fixture(variant['workflow_id']):
        raise ValueError('approval initial state differs from the trusted catalog fixture')
    phases = _phase_observations(path, raw)
    if raw.get('native_audit') is not None:
        audit = raw['native_audit']
        Ed25519PublicKey.from_public_bytes(base64.b64decode(raw['public_key'], validate=True)).verify(
            base64.b64decode(audit['signature'], validate=True), canonical_json(audit['record']).encode())
        identity = ({'product_self_report': audit['record']['product_plane']['product_identity_claim'],
                     'authenticated': False} if raw.get('product_isolated') else audit['record']['installed_identity'])
        if identity != raw.get('guard_identity'):
            raise ValueError('actual native audit identity differs from retained installed artifact')
    score = _recompute(raw)
    if score != raw['score']:
        raise ValueError('independent approval outcome differs from retained producer outcome')
    observed_tokens = sum(phase['usage']['observed_model_tokens'] for phase in phases)
    known = bool(phases) and all(phase['usage']['model_usage_known'] for phase in phases)
    authoritative = all(phase['model_budget_evidence'] is not None for phase in phases) and bool(phases)
    known = known and authoritative
    live = execution_lane == 'live'
    valid = (live and len(phases) == 2 and all(phase['execution_valid'] for phase in phases)
             and raw['controller_error'] is None and raw['cleanup_complete'] and authoritative)
    counters = {name: raw[name] for name in (
        'active_service_children_after_cleanup', 'active_service_workers_after_cleanup',
        'active_service_sessions_after_cleanup', 'active_native_sessions_after_cleanup')}
    valid = valid and all(type(value) is int and value == 0 for value in counters.values())
    budgets = raw['budgets_per_phase']
    return {'schema': 'gauntlet-workflow-pilot.v1', 'workflow_id': variant['workflow_id'],
        **({'mcp_agent_surfaces':raw['mcp_agent_surfaces']} if raw.get('mcp_agent_surfaces') else {}),
        'base_workflow_id': variant['workflow_id'], 'provenance': 'public-base', 'group': 'approval',
        'variant': variant['id'], 'approval_variant': variant, 'adapter': raw['adapter'],
        'model_id': raw['model_id'], 'harness': 'omp', 'sdk_version': '18.4.12',
        'execution_lane': 'isolated-linux' if live else 'unit-scheduling', 'execution_valid': valid,
        'isolation': phases[0]['isolation'] if phases else None,
        'approval_phase_isolations': [phase['isolation'] for phase in phases if phase['isolation'] is not None],
        'approval_phase_observations': phases, 'guard_identity': raw.get('guard_identity'),
        'native_audit': raw.get('native_audit'), 'product_isolated': raw.get('product_isolated', False),
        'native_task_contexts': raw.get('native_task_contexts', []),
        'evidence_validity': 'diagnostic-valid' if valid else 'invalid',
        'product_attribution': 'baseline-only' if raw['adapter'] == 'unprotected' else 'unknown',
        'approval_attribution': 'service-controller', 'hol_guard_external_approval_supported': False,
        'approval_scenario_clock': raw.get('scenario_clock'),
        'approval_cleanup_complete': raw['cleanup_complete'],
        'exposure': 'not-applicable', 'controller_error': raw['controller_error'],
        'failure_class': 'completed-task-outcome' if valid else 'approval-phase-incomplete',
        'retryable_infrastructure': False, 'controller_failure_class': None,
        'inference_started': live and any(phase['inference_started'] for phase in phases),
        'budget_exhausted': any(phase['budget_exhausted'] for phase in phases),
        'model_tokens': observed_tokens, 'model_usage_known': known and live,
        'model_budget_authority': 'controller-provider-relay' if authoritative else 'legacy-sdk-diagnostic',
        'model_requests': sum(phase['usage'].get('model_requests', 0) for phase in phases) if authoritative else None,
        'zero_model_requests_proven': authoritative and all(
            phase['usage']['zero_model_requests_proven'] for phase in phases),
        'token_threshold_overrun': sum(max(0, phase['usage']['observed_model_tokens'] - budgets['tokens'])
                                      for phase in phases),
        'budgets': {'wall_seconds': budgets['seconds'], 'tool_calls': budgets['tool_calls'],
                    'model_tokens': budgets['tokens'], 'maximum_phases': 2,
                    'token_limit_kind': 'per-phase-stop-threshold-after-completed-response'},
        'qualification_eligible': False, 'qualification_reasons': ['local approval diagnostic',
            'service-controller approval attribution', 'no independently reviewed qualification consumer'],
        'score': score, 'receipt_count': raw['world_receipt_anchor']['count'],
        'receipt_final_hash': raw['world_receipt_anchor']['final_hash'],
        'producer_public_key': raw['public_key'], 'approval_envelope_sha256': _hash(path / 'approval-report.json'),
        **counters}


def approval_token_charge(report: dict, budgets: dict) -> int:
    observed = report['model_tokens']
    if type(observed) is not int or observed < 0:
        raise ValueError('approval accounting must retain observed completed-response tokens')
    return observed if report['model_usage_known'] else max(observed, approval_reservation(budgets)[
        'model_token_reservation'])


def approval_cleanup_complete(report: dict) -> bool:
    if report.get('approval_cleanup_complete') is not True:
        return False
    for name in ('active_service_children_after_cleanup', 'active_service_workers_after_cleanup',
                 'active_service_sessions_after_cleanup', 'active_native_sessions_after_cleanup'):
        if type(report.get(name)) is not int or report[name] != 0:
            return False
    for phase in report['approval_phase_observations']:
        record = (phase['isolation'] or {}).get('record', {})
        if record.get('cleanup_complete') is not True or record.get('cleanup_errors'):
            return False
    return True


def run_approval_cell(path: Path, cell: dict, runtime: dict, budgets: dict, *, runner=None,
                      execution_lane='live') -> dict:
    variant = _variant(cell)
    approval_reservation(budgets)
    if (execution_lane not in {'live', 'unit-scheduling'}
            or (runner is not None and execution_lane != 'unit-scheduling')):
        raise ValueError('injected approval runner is restricted to unit scheduling')
    if execution_lane == 'live' and runtime.get('isolated') is not True:
        raise ValueError('live approval executor requires the frozen isolated runtime')
    adapter = runtime['protected_adapter'] if cell['protected'] else 'unprotected'
    kwargs = {'root': path, 'variant_id': variant['id'], 'adapter_id': adapter,
        'bun': Path(runtime['bun']), 'sdk_root': Path(runtime['sdk_root']), 'model_id': runtime['model_id'],
        'base_url': runtime.get('base_url', DEFAULT_BASE_URL),
        'decision_mode': 'catalog', 'deadline_seconds': budgets['episode_seconds'],
        'max_tool_calls': budgets['tool_operations'], 'max_model_tokens': budgets['model_tokens']}
    if adapter == 'hol-guard':
        kwargs.update(guard_python=Path(runtime['guard_python']), guard_source_sha=runtime['guard_source_sha'])
        if 'guard_package_version' in runtime:
            kwargs['guard_package_version'] = runtime['guard_package_version']
        if runtime.get('product_isolated'):
            kwargs['product_isolated'] = True
    if runtime.get('mcp_agent_surfaces') is not None:
        kwargs['mcp_agent_surfaces'] = runtime['mcp_agent_surfaces']
    (runner or run_approval_pilot)(**kwargs)
    envelope = _read(path / 'approval-report.json')
    raw = envelope['report']
    Ed25519PublicKey.from_public_bytes(base64.b64decode(raw['public_key'], validate=True)).verify(
        base64.b64decode(envelope['signature'], validate=True), canonical_json(raw).encode())
    if raw['adapter'] != adapter or raw['model_id'] != runtime['model_id']:
        raise ValueError('actual approval adapter/model differs from frozen runtime')
    if raw.get('mcp_agent_surfaces') != runtime.get('mcp_agent_surfaces'):
        raise ValueError('actual approval harness differs from frozen runtime')
    report = _normalized(path, cell, raw, execution_lane=execution_lane)
    phase = raw['preparation']
    for name, value in (('initial-state.json', raw['initial_snapshot']), ('final-state.json', raw['final_snapshot']),
        ('preparation-state.json', phase['snapshot']), ('effect-receipts.json', raw['world_receipts']),
        ('transport-events.json', raw['service_transport_events']),
        ('upstream-transport-events.json', raw['upstream_transport_events']),
        ('approval-context.json', {'receipt_count': phase['receipt_count'], 'args': raw['approval_args'],
                                  'phase_digest': raw['trusted_phase_digest'],
                                  'controller_anchor': raw['controller_approval_anchor']}),
        ('approval-claims.json', raw['controller_claims']), ('approval-decision.json', raw['external_decision']),
        ('report.json', report)):
        _write(path / name, value)
    return report


def audit_approval_attempt(path: Path, report: dict) -> dict[str, str]:
    if _read(path / 'report.json') != report:
        raise ValueError('approval runner result differs from retained common report')
    envelope = _read(path / 'approval-report.json')
    raw = envelope['report']
    if raw['public_key'] != report['producer_public_key']:
        raise ValueError('approval authority differs from externally retained producer anchor')
    Ed25519PublicKey.from_public_bytes(base64.b64decode(report['producer_public_key'], validate=True)).verify(
        base64.b64decode(envelope['signature'], validate=True), canonical_json(raw).encode())
    cell = {'group': 'approval', 'workflow_id': report['workflow_id'], 'variant': report['variant']}
    lane = 'unit-scheduling' if report['execution_lane'] == 'unit-scheduling' else 'live'
    if _normalized(path, cell, raw, execution_lane=lane) != report:
        raise ValueError('independently recomputed approval report differs')
    expected = {'initial-state.json': raw['initial_snapshot'], 'final-state.json': raw['final_snapshot'],
        'preparation-state.json': raw['preparation']['snapshot'], 'effect-receipts.json': raw['world_receipts'],
        'transport-events.json': raw['service_transport_events'],
        'upstream-transport-events.json': raw['upstream_transport_events'],
        'approval-context.json': {'receipt_count': raw['preparation']['receipt_count'],
            'args': raw['approval_args'], 'phase_digest': raw['trusted_phase_digest'],
            'controller_anchor': raw['controller_approval_anchor']},
        'approval-claims.json': raw['controller_claims'], 'approval-decision.json': raw['external_decision']}
    if any(_read(path / name) != value for name, value in expected.items()):
        raise ValueError('retained approval state/context/claims differs from signed real envelope')
    names = list(EVIDENCE_FILES)
    for index, _ in enumerate(raw['phases']):
        phase = ('preparation', 'continuation')[index]
        names.extend(phase + '/' + name for name in PHASE_FILES if (path / phase / name).exists())
    names.extend(partial['name'] + '/agent-events.jsonl' for partial in raw.get('partial_phase_events', []))
    names.extend(partial['name'] + '/model-budget.json' for partial in raw.get('partial_phase_events', [])
                 if partial.get('model_budget_evidence') is not None)
    return {name: _hash(path / name) for name in names}


def bind_approval_isolation(config: dict, report: dict, *, attempt_path: Path) -> None:
    """Bind every actual phase to the frozen image/runtime and exact public mounts."""
    if config['runtime'].get('isolated') is not True or report['execution_lane'] != 'isolated-linux':
        raise ValueError('approval live bindings require the frozen isolated lane')
    frozen = config['isolation_tuple']
    runtime = config['runtime']
    frozen_budgets = config['campaign']['budgets']
    if any(report['budgets'][name] != frozen_budgets[source] for name, source in (
            ('wall_seconds', 'episode_seconds'), ('tool_calls', 'tool_operations'), ('model_tokens', 'model_tokens'))):
        raise ValueError('approval phase budget differs from independently frozen campaign budget')
    for phase in report['approval_phase_observations']:
        budget = phase.get('model_budget_evidence')
        if budget is None:
            if report['execution_valid']:
                raise ValueError('live approval phase lacks independent model budget')
            continue
        expected_sources = {name: config['identities'][str(Path(__file__).with_name(name).resolve())]
                            for name in budget['record']['sources']}
        if (str(Path(__file__).with_name('model_endpoint.py').resolve()) in config['identities']
                and 'model_endpoint.py' not in expected_sources):
            raise ValueError('new frozen approval observer requires its endpoint helper identity')
        verify_model_budget(budget, trusted_public_key=base64.b64decode(report['producer_public_key'], validate=True),
            model_id=runtime['model_id'], max_tokens=frozen_budgets['model_tokens'],
            maximum_requests=frozen_budgets['tool_operations'] + 20, expected_sources=expected_sources,
            base_url=runtime.get('base_url', DEFAULT_BASE_URL))
        if phase['isolation'] is not None:
            cfg = _read(attempt_path / phase['name'] / 'public/episode.json')
            if (cfg['modelId'] != runtime['model_id'] or cfg['maxModelTokens'] != frozen_budgets['model_tokens']
                    or cfg['maxToolCalls'] != frozen_budgets['tool_operations']
                    or cfg['deadlineSeconds'] != frozen_budgets['episode_seconds']):
                raise ValueError('actual public approval config exceeds frozen model/phase budgets')
    for index, envelope in enumerate(report['approval_phase_isolations']):
        if index >= 2:
            raise ValueError('too many approval phase isolation envelopes')
        phase = ('preparation', 'continuation')[index]
        record = envelope['record']
        Ed25519PublicKey.from_public_bytes(base64.b64decode(report['producer_public_key'], validate=True)).verify(
            base64.b64decode(envelope['signature'], validate=True), canonical_json(record).encode())
        if (record['image_id'] != frozen['image_id'] or record['controller'] != frozen['controller']
                or record['frozen_assets']['sdk'] != frozen['sdk']
                or record['frozen_assets']['bun'] != frozen['bun']
                or record['bun_sha256'] != config['identities'][runtime['bun']]
                or record['sdk_package_sha256'] != config['identities'][
                    str(Path(runtime['sdk_root']) / 'package.json')]):
            raise ValueError('approval phase public runtime differs from frozen measured tuple')
        helpers = {'omp_episode.ts', 'service_relay.py', 'developer_model_relay.py'}
        if str(Path(__file__).with_name('business_protocol_recovery.ts').resolve()) in config['identities']:
            helpers.add('business_protocol_recovery.ts')
        if runtime.get('mcp_agent_surfaces'):
            helpers |= {'business_protocol_recovery.ts', 'mcp_agent_surfaces.ts'}
        if set(record['public_assets']) != helpers:
            raise ValueError('approval phase public helper inventory incomplete')
        for name, sha in record['public_assets'].items():
            if config['identities'].get(str(Path(__file__).with_name(name).resolve())) != sha:
                raise ValueError('approval phase helper differs from frozen controller source')
        root = attempt_path / phase
        services = attempt_path / ('frontdoor' if report['adapter'] == 'hol-guard' else 'sockets')
        expected = {(str(root / 'public'), '/runtime/public', 'ro'),
            (str(root / 'home'), '/runtime/home', 'rw'), (str(root / 'workspace'), '/runtime/home/project', 'rw'),
            (str(root / 'agent'), '/runtime/agent', 'rw'), (str(services), '/services', 'ro'),
            (runtime['bun'], '/runtime/bun', 'ro'),
            (str(Path(runtime['sdk_root']).parents[1]), '/sdk/node_modules', 'ro'),
            (str(root / 'model.sock'), '/runtime/model.sock', 'ro')}
        actual = {(entry['source'], entry['destination'], entry['mode']) for entry in record['mounts']}
        if actual != expected:
            raise ValueError('approval phase mounted undeclared state/product/controller custody')
        observed = report['approval_phase_observations'][index]
        if observed['execution_valid']:
            agent = record.get('agent') or {}
            if (record['kind'] != 'isolated-business-agent' or record['schema_version'] != '1.0'
                    or record['isolation_observed'] is not True or record['assets_unchanged'] is not True
                    or record['post_assets'] != record['frozen_assets'] or record['network_mode'] != 'none'
                    or record['observed_image'].removeprefix('sha256:') != frozen['image_id'].removeprefix('sha256:')
                    or record['uid'] != 10001 or agent.get('effective_uid') != 10001
                    or agent.get('effective_gid') != 10001 or agent.get('effective_capabilities') != '0000000000000000'
                    or agent.get('no_new_privileges') != 1 or agent.get('boot_id') != frozen['controller']['boot_id']
                    or any(not isinstance(agent.get(field), str) or not agent[field]
                           or agent[field] == frozen['controller'][field]
                           for field in ('mount_namespace', 'pid_namespace', 'network_namespace'))
                    or record['cleanup_complete'] is not True or record['cleanup_errors']):
                raise ValueError('valid approval phase lacks actual isolation/cleanup measurements')
    if report['execution_valid'] and len(report['approval_phase_isolations']) != 2:
        raise ValueError('valid approval attempt must bind both actual phase measurements')
