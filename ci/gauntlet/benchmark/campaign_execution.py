"""Declared per-cell execution reservations and actual controller routing."""
from __future__ import annotations

from pathlib import Path

from .authored_challenges import BASE_WORKFLOWS
from .catalog import DEVELOPER_IDS
from .local_campaign_custody import cleanup_complete


def unsupported_cell(cell, runtime, budgets):
    from .catalog import BUSINESS_IDS
    from .mcp_protocol_campaign import support_reason
    if reason := support_reason(runtime, cell):
        return reason
    semantic = BASE_WORKFLOWS.get(cell['workflow_id'], cell['workflow_id'])
    if cell['protected'] and runtime['protected_adapter'] not in {'example-policy', 'hol-guard'}:
        return 'requested protected transport not implemented'
    if cell['group'] == 'approval':
        return None if runtime.get('isolated') else 'live approval executor requires isolated runtime'
    if developer_cell(cell):
        from .developer_campaign import developer_support
        return developer_support(cell, runtime, budgets)
    return None if semantic in BUSINESS_IDS else 'live developer executor not integrated'


def developer_cell(cell):
    if cell['group'] == 'approval':
        return False
    return BASE_WORKFLOWS.get(cell['workflow_id'], cell['workflow_id']) in DEVELOPER_IDS


def reservation(cell, budgets):
    if developer_cell(cell):
        from .developer_campaign import developer_reservation
        return developer_reservation(budgets)
    if cell['group'] == 'approval':
        from .approval_campaign import approval_reservation
        return approval_reservation(budgets)
    return {'model_token_reservation': budgets['model_tokens'],
            'tool_operation_reservation': budgets['tool_operations'],
            'controller_seconds_reservation': budgets['episode_seconds'] + 60}


def cell_cleanup(report, *, isolated):
    if report.get('group') == 'developer':
        from .developer_campaign import developer_cleanup_complete
        return developer_cleanup_complete(report)
    if report.get('group') == 'approval':
        from .approval_campaign import approval_cleanup_complete
        return approval_cleanup_complete(report)
    return cleanup_complete(report, isolated=isolated)


def token_charge(report, budgets):
    if report.get('group') == 'developer':
        from .developer_campaign import developer_token_charge
        return developer_token_charge(report, budgets)
    if report.get('group') == 'approval':
        from .approval_campaign import approval_token_charge
        return approval_token_charge(report, budgets)
    tokens = report.get('model_tokens')
    if report.get('model_usage_known') is True and type(tokens) is int and tokens >= 0:
        return tokens
    if type(tokens) is int and tokens >= 0:
        return max(tokens, budgets['model_tokens'])
    return budgets['model_tokens']


def execute_cell(path, cell, runtime, budgets, *, runner, execution_lane):
    from .mcp_protocol_campaign import selected_profile
    if cell['group'] == 'approval' and selected_profile(runtime, cell) is not None:
        raise ValueError('approval protocol-profile mediation is not implemented')
    if developer_cell(cell):
        from .developer_campaign import run_developer_cell
        return run_developer_cell(path, cell, runtime, budgets,
            runner=runner if execution_lane == 'unit-scheduling' else None,
            execution_lane=execution_lane)
    if cell['group'] == 'approval':
        from .approval_campaign import run_approval_cell
        return run_approval_cell(path, cell, runtime, budgets,
            runner=runner if execution_lane == 'unit-scheduling' else None,
            execution_lane=execution_lane)
    key = cell['workflow_id']
    guard = ({'guard_python': Path(runtime['guard_python']),
              'guard_source_sha': runtime['guard_source_sha']}
             if cell['protected'] and runtime['protected_adapter'] == 'hol-guard' else {})
    if guard and runtime.get('product_isolated'):
        guard['product_isolated'] = True
    if guard and 'guard_package_version' in runtime:
        guard['guard_package_version'] = runtime['guard_package_version']
    profile = selected_profile(runtime, cell)
    if profile is not None:
        guard['mcp_protocol_profile'] = profile
    if runtime.get('mcp_agent_surfaces') is not None:
        guard['mcp_agent_surfaces'] = runtime['mcp_agent_surfaces']
    return runner(root=path, workflow_id=BASE_WORKFLOWS.get(key, key),
        challenge_id=key if key in BASE_WORKFLOWS else None, variant=cell['variant'],
        adapter_id=runtime['protected_adapter'] if cell['protected'] else 'unprotected',
        bun=Path(runtime['bun']), sdk_root=Path(runtime['sdk_root']),
        model_id=runtime['model_id'], base_url=runtime['base_url'],
        deadline_seconds=budgets['episode_seconds'], max_tool_calls=budgets['tool_operations'],
        max_model_tokens=budgets['model_tokens'], isolated=runtime['isolated'], **guard)
