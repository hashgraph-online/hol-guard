"""Local diagnostic actual-inference pilot; never a qualification shortcut."""
from __future__ import annotations

import base64
import hashlib
import json
import subprocess
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .adapters import omp_mcp_configs
from .artifact_contracts import artifact_contract, public_effect_budgets
from .business_model_budget import legacy_sdk_usage, seal_model_budget, verify_model_budget
from .business_oracles import score_business_workflow
from .catalog import BUSINESS_IDS, get_workflow, load_fixture
from .contracts import canonical_json, strict_json_loads
from .exposure import summarize_exposure
from .model_endpoint import model_endpoint
from .public_interface import business_prompt
from .service_supervisor import ServiceSupervisor
from .world import World, verify_receipts


def run_pilot(*, root: Path, workflow_id: str, variant: str, bun: Path,
              sdk_root: Path, model_id: str, base_url: str,
              deadline_seconds: int = 300, max_tool_calls: int = 60,
              adapter_id: str = 'unprotected', challenge_id: str | None = None,
              max_model_tokens: int = 32_000, guard_python: Path | None = None,
              guard_source_sha: str | None = None, isolated: bool = False,
              product_isolated: bool = False, guard_package_version: str | None = None,
              mcp_protocol_profile: dict | None = None, mcp_agent_surfaces=None) -> dict:
    """Run one live business workflow, retaining negative outcomes honestly.

    The optional Linux lane observes separate agent namespaces and private
    controller custody. Neither lane promotes a trusted qualification verifier.
    """
    model_endpoint(base_url)
    from .mcp_agent_profile import apply_episode, fields as agent_fields, validate
    validate(mcp_agent_surfaces)
    from .mcp_protocol_campaign import declaration, report_fields
    if mcp_protocol_profile is not None:
        mcp_protocol_profile = declaration(mcp_protocol_profile)
    from .product_version import version_options, verify_claim_version
    version_pins = version_options(guard_package_version)
    if adapter_id not in {'unprotected', 'example-policy', 'hol-guard'}:
        raise ValueError('pilot adapter must have an implemented live transport')
    if adapter_id == 'hol-guard' and (guard_python is None or guard_source_sha is None):
        raise ValueError('managed pilot requires installed Python and exact Guard source SHA')
    if type(isolated) is not bool:
        raise ValueError('isolated must be an explicit boolean')
    if type(product_isolated) is not bool or (product_isolated and
            (not isolated or adapter_id != 'hol-guard')):
        raise ValueError('product isolation requires the isolated HOL Guard lane')
    if isolated:
        import os
        import sys
        if sys.platform != 'linux' or os.geteuid() != 0:
            raise ValueError('isolated pilot requires the owned Linux root controller')
    if challenge_id is None:
        if workflow_id not in BUSINESS_IDS:
            raise ValueError('pilot currently supports business workflows only')
        workflow = get_workflow(workflow_id)
        initial = load_fixture(workflow_id, variant)
        clean = load_fixture(workflow_id)
        public_contract = artifact_contract(workflow_id)
        provenance = 'public-base'
    else:
        from .authored_challenges import (
            BASE_WORKFLOWS,
            PROVENANCE,
            authored_public_contract,
            load_authored_challenges,
            load_authored_snapshot,
        )
        if BASE_WORKFLOWS.get(challenge_id) != workflow_id or workflow_id not in BUSINESS_IDS:
            raise ValueError('challenge identity must match its business workflow')
        workflow = next(row for row in load_authored_challenges() if row['id'] == challenge_id)
        initial = load_authored_snapshot(challenge_id, variant)
        clean = load_authored_snapshot(challenge_id)
        public_contract = authored_public_contract(challenge_id)
        provenance = PROVENANCE
    if not root.is_absolute() or not bun.is_absolute() or not sdk_root.is_absolute():
        raise ValueError('pilot paths must be absolute')
    if (not 1 <= deadline_seconds <= 1800 or not 1 <= max_tool_calls <= 500
            or type(max_model_tokens) is not int or not 1 <= max_model_tokens <= 1_000_000):
        raise ValueError('invalid pilot budgets')
    root.mkdir(mode=0o700)
    workspace = root / 'workspace'
    workspace.mkdir(mode=0o700)
    guard_identity = None
    if adapter_id == 'hol-guard' and not isolated:
        from .installed_guard import inspect_installed_guard
        home = root / 'guard-user-home'
        home.mkdir(mode=0o700)
        guard_home = root / 'guard-home'
        guard_home.mkdir(mode=0o700)
        with (guard_home / 'config.toml').open('x', encoding='utf-8') as stream:
            stream.write('mode = "enforce"\nsync = false\ntelemetry = false\n'
                         'desktop_notifications = false\napproval_wait_timeout_seconds = 1\n')
        guard_identity = inspect_installed_guard(guard_python, expected_sha=guard_source_sha, home=home)
        if guard_package_version is not None:
            verify_claim_version(guard_identity, guard_package_version)
    key = Ed25519PrivateKey.generate()
    world = World.create(root / 'world.db', initial, signing_key=key)
    events_path = root / 'agent-events.jsonl'
    error_path = root / 'agent-stderr.txt'
    completed = None
    controller_error = None
    isolation = None
    model_budget = None
    config = None
    business_launch_requested = False
    native_frontdoor = None
    native_audit = None
    native_task_contexts = []
    policy_options = {}
    if adapter_id == 'example-policy':
        from .example_proxy import example_policy_factory
        policy_options['policy_factory'] = example_policy_factory(world, workflow['authorization'])
    supervisor = ServiceSupervisor(world, root / 'sockets',
                                   protocol_profile=mcp_protocol_profile,
                                   artifact_workflow_id=challenge_id or workflow_id,
                                   families=tuple(workflow['services']),
                                   session_timeout=deadline_seconds + 30,
                                   idle_timeout=deadline_seconds + 30,
                                   allowed_uid=10004 if product_isolated else
                                               0 if isolated and adapter_id == 'hol-guard' else
                                               10001 if isolated else None,
                                   socket_gid=10004 if product_isolated else
                                              10001 if isolated and adapter_id != 'hol-guard' else None,
                                   **policy_options)
    try:
        supervisor.start()
        endpoints = [supervisor.endpoint(family) for family in workflow['services']]
        services_directory = supervisor.directory
        if isolated and adapter_id == 'hol-guard':
            from .native_mcp_supervisor import NativeMcpSupervisor
            product_plane = None
            if product_isolated:
                from .native_product_container import NativeProductContainer
                product_plane = NativeProductContainer(runtime_root=root / 'product-runtime',
                    python=guard_python, expected_source_sha=guard_source_sha,
                    upstream_directory=supervisor.directory, wall_seconds=deadline_seconds + 90,
                    task_write_budget=workflow['authorization']['write_budget'],
                    read_only_tools=tuple(
                        f'{family}.{operation}' for family in workflow['services']
                        for operation in ('read', 'search', 'list', 'read_attachment')
                    ),
                    reserved_record_ids=tuple(sorted(row['id'] for row in initial['records'])),
                    required_source_ids=tuple(sorted(
                        row['id'] for row in initial['records']
                        if workflow_id == 'business-sales-lead-qualification'
                        and row['collection'] == 'crm.contacts'
                        and row['tenant_id'] == workflow['authorization']['tenant']
                    )),
                    tool_write_limits={
                        {'crm.contacts': 'crm.update', 'tickets.tickets': 'tickets.update',
                         'mail.drafts': 'mail.create_draft'}[collection]: limit
                        for collection, limit in public_effect_budgets(workflow_id).items()
                    } if workflow_id in {'business-sales-lead-qualification',
                                         'business-support-ticket-resolution'} else {},
                    **version_pins)
            native_frontdoor = NativeMcpSupervisor(root / 'frontdoor', upstream=supervisor,
                python=guard_python, expected_source_sha=guard_source_sha,
                private_root=root / 'private-product', session_timeout=deadline_seconds + 30,
                idle_timeout=deadline_seconds + 30, product_plane=product_plane)
            native_frontdoor.start()
            guard_identity = native_frontdoor.identity
            endpoints = [native_frontdoor.endpoint(family) for family in workflow['services']]
            services_directory = native_frontdoor.directory
        elif guard_identity is not None:
            from .installed_guard import guard_endpoints
            endpoints = guard_endpoints(endpoints, python=guard_python, home=home,
                                        guard_home=guard_home, workspace=workspace,
                                        config_path=root / 'public-episode.json', identity=guard_identity)
        config = {
            'schema': 'gauntlet-omp-episode.v1', 'sdkRoot': str(sdk_root),
            'workspace': str(workspace), 'agentDir': str(root / 'agent-config'),
            'modelId': model_id, 'baseUrl': base_url,
            'prompt': business_prompt(workflow, initial, public_contract),
            'deadlineSeconds': deadline_seconds, 'maxToolCalls': max_tool_calls,
            'maxModelTokens': max_model_tokens,
            'endpoints': omp_mcp_configs(endpoints, workspace=workspace),
        }
        config_path = root / 'public-episode.json'
        apply_episode(config, mcp_agent_surfaces)
        config_path.write_text(json.dumps(config, indent=2), encoding='utf-8')
        if product_isolated:
            from .mcp_task_context import prepare_task_context
            context, allowed = prepare_task_context(native_frontdoor, config['prompt'],
                controller_key=key, phase='episode')
            native_task_contexts.append(context)
            if not allowed:
                raise ValueError('normal native public task hook refused model execution')
        if isolated:
            from .business_agent_container import run_isolated_business_episode
            business_launch_requested = True
            observed = run_isolated_business_episode(runtime_root=root / 'agent-runtime',
                config=config, services_directory=services_directory, bun=bun, sdk_root=sdk_root,
                controller_key=key, **({'mcp_protocol_profile': mcp_protocol_profile}
                                       if mcp_protocol_profile is not None else {}))
            isolation = observed['isolation']
            model_budget = observed.get('model_budget_evidence')
            controller_error = observed['controller_error']
            events_path = Path(observed['events_path'])
            error_path = Path(observed['stderr_path'])
            if observed['exit_code'] is not None:
                completed = subprocess.CompletedProcess([], observed['exit_code'])
        else:
            runner = Path(__file__).with_name('omp_episode.ts')
            with events_path.open('xb') as output, error_path.open('xb') as errors:
                completed = subprocess.run([str(bun), str(runner), str(config_path)],
                                           cwd=workspace, stdout=output, stderr=errors,
                                           timeout=deadline_seconds + 60, check=False)
    except subprocess.TimeoutExpired:
        controller_error = 'harness exceeded controller wall-clock deadline'
    except Exception as exc:
        controller_error = f'{type(exc).__name__}: {exc}'
    finally:
        if native_frontdoor is not None:
            native_frontdoor.close()
            try:
                native_audit = native_frontdoor.collect_audit(controller_key=key)
            except Exception as exc:
                controller_error = controller_error or f'native audit: {type(exc).__name__}: {exc}'
        supervisor.close()
    final = world.snapshot()
    receipts = world.receipts()
    final_hash = hashlib.sha256(canonical_json(receipts[-1]).encode()).hexdigest() if receipts else '0' * 64
    public_key = key.public_key().public_bytes_raw()
    verify_receipts(receipts, public_key, expected_count=len(receipts),
                    expected_final_hash=final_hash)
    if challenge_id is None:
        score = score_business_workflow(workflow_id, initial, final, receipts,
                                        receipts_verified=True)
    else:
        from .challenge_oracles import score_authored_challenge
        score = score_authored_challenge(challenge_id, initial, final, receipts,
                                         receipts_verified=True)
    events = []
    if events_path.is_file():
        for line in events_path.read_text(encoding='utf-8').splitlines():
            try:
                events.append(json.loads(line))
            except ValueError:
                controller_error = 'harness emitted malformed observer JSON'
    execution_valid = (completed is not None and completed.returncode == 0
                       and controller_error is None
                       and any(e.get('type') == 'episode_start' for e in events)
                       and any(e.get('type') == 'episode_end' for e in events)
                       and not any(e.get('type') == 'episode_error' for e in events))
    if isolated:
        execution_valid = (execution_valid and isolation is not None
                           and isolation['record']['isolation_observed']
                           and isolation['record']['assets_unchanged']
                           and isolation['record']['cleanup_complete'])
    if supervisor.active_sessions or supervisor.active_children or supervisor.active_workers:
        execution_valid = False
        controller_error = controller_error or 'service cleanup incomplete'
    retryable_startup = (not execution_valid and controller_error is None
                         and not any(e.get('type') == 'inference_start' for e in events)
                         and any(e.get('type') == 'episode_error'
                                 and e.get('phase') == 'startup'
                                 and e.get('retryableInfrastructure') is True
                                 and e.get('error') in {
                                     'Error: MCP endpoint connection failed',
                                     'Error: declared MCP endpoint did not finish connecting',
                                 } for e in events))
    episode_end = next((e for e in reversed(events) if e.get('type') == 'episode_end'), {})
    if isolated and model_budget is None and config is not None and isolation is None:
        # No result/isolation can exist after model forwarding without retained
        # budget evidence. A missing retained file is unresolved, not zero usage.
        retained_budget = root / 'agent-runtime/model-budget.json'
        if retained_budget.exists():
            try:
                if (retained_budget.is_symlink() or not retained_budget.is_file()
                        or retained_budget.stat().st_size > 8 * 1024**2):
                    raise ValueError('retained budget is not a bounded regular controller file')
                model_budget = strict_json_loads(retained_budget.read_text())
            except Exception as error:
                controller_error = controller_error or f'invalid retained model budget: {error}'
                execution_valid = False
        elif not business_launch_requested:
            model_budget = seal_model_budget(None, config, controller_key=key,
                                            mcp_protocol_profile=mcp_protocol_profile)
    usage = legacy_sdk_usage(events)
    if model_budget is not None:
        try:
            usage = verify_model_budget(model_budget, trusted_public_key=public_key, model_id=model_id,
                max_tokens=max_model_tokens, base_url=base_url,
                maximum_requests=max_tool_calls + 20,
                config_digest=isolation['record']['public_config_digest'] if isolation else None)
            execution_valid = (execution_valid and usage['model_usage_known'] and usage['model_requests'] > 0
                               and usage['cleanup_complete'])
        except Exception as error:
            controller_error = controller_error or f'invalid model budget evidence: {error}'
            execution_valid = False  # Preserve actual World history and failed producer evidence below.
            record = model_budget.get('record') if type(model_budget) is dict else None
            budget = record.get('budget') if type(record) is dict else None
            observed_lower_bound = budget.get('observed_tokens') if type(budget) is dict else None
            if type(observed_lower_bound) is int and observed_lower_bound >= 0:
                usage['observed_model_tokens'] = max(usage['observed_model_tokens'], observed_lower_bound)
    elif isolated:
        execution_valid = False
    transport_events = native_frontdoor.events if native_frontdoor is not None else supervisor.events
    exposure = summarize_exposure(clean, initial, transport_events, events)
    report = {
        'schema': 'gauntlet-workflow-pilot.v1', 'workflow_id': workflow['id'],
        'base_workflow_id': workflow_id, 'provenance': provenance,
        'guard_identity': guard_identity, 'product_isolated': product_isolated,
        'execution_lane': 'isolated-linux' if isolated else 'shared-uid-diagnostic',
        'isolation': isolation, 'native_audit': native_audit,
        'native_task_contexts': native_task_contexts,
        'variant': variant, 'adapter': adapter_id, 'model_id': model_id, 'model_base_url': base_url,
        'execution_valid': execution_valid,
        'evidence_validity': 'diagnostic-valid' if execution_valid else 'invalid',
        'exposure': exposure['stage'], 'exposure_details': exposure,
        'product_attribution': 'baseline-only' if adapter_id == 'unprotected' else 'unknown',
        'exit_code': completed.returncode if completed else None,
        'controller_error': controller_error,
        'failure_class': 'startup-transport' if retryable_startup else
                         'completed-task-outcome' if execution_valid else 'execution-invalid',
        'retryable_infrastructure': retryable_startup,
        'controller_failure_class': 'mcp-connect-before-inference' if retryable_startup else None,
        'inference_started': usage.get('inference_started', any(e.get('type') == 'inference_start' for e in events)),
        'budget_exhausted': usage.get('budget_exhausted', False) or episode_end.get('status') == 'budget-exhausted',
        'model_tokens': usage['observed_model_tokens'], 'model_usage_known': usage['model_usage_known'],
        'model_budget_authority': usage['model_budget_authority'], 'model_budget_evidence': model_budget,
        'model_requests': usage.get('model_requests'),
        'zero_model_requests_proven': usage['zero_model_requests_proven'],
        'token_threshold_overrun': max(0, usage['observed_model_tokens'] - max_model_tokens),
        'budgets': {'wall_seconds': deadline_seconds, 'tool_calls': max_tool_calls,
                    'model_tokens': max_model_tokens,
                    'token_limit_kind': 'stop-threshold-after-completed-response',
                'token_accounting': 'controller provider total_tokens including cached prompt input'},
        'qualification_eligible': False,
        'qualification_reasons': ['single diagnostic episode',
                                  *([] if isolated else ['shared controller/harness UID']),
                                  'no independent holdout custody', 'no eligible trusted verifier'],
        'score': score, 'receipt_count': len(receipts),
        'receipt_final_hash': final_hash,
        'producer_public_key': base64.b64encode(public_key).decode(),
        'active_service_children_after_cleanup': supervisor.active_children,
        'active_service_workers_after_cleanup': supervisor.active_workers,
        'active_service_sessions_after_cleanup': supervisor.active_sessions,
        'active_native_sessions_after_cleanup': native_frontdoor.active_sessions if native_frontdoor else 0,
        **agent_fields(mcp_agent_surfaces),
        **report_fields(mcp_protocol_profile, supervisor.events,
                        model_budget['record']['budget'] if model_budget else None,
                        agent_surfaces=mcp_agent_surfaces),
    }
    if model_budget is not None:
        (root / 'model-budget.json').write_text(canonical_json(model_budget) + '\n')
    for name, value in (('initial-state.json', initial), ('final-state.json', final),
                        ('effect-receipts.json', receipts), ('transport-events.json', transport_events),
                        ('upstream-transport-events.json', supervisor.events),
                        ('report.json', report)):
        with (root / name).open('x', encoding='utf-8') as stream:
            json.dump(value, stream, indent=2)
            stream.write('\n')
    return report
