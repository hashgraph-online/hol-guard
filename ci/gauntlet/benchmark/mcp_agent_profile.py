"""Versioned common harness selection; never an override for product authority."""
from __future__ import annotations

from .contracts import strict_json_loads

PROFILE = 'mcp-agent-surfaces.v1'
TOOLS = {'mcp_inspect_server', 'mcp_call_tool', 'mcp_read_resource', 'mcp_get_prompt', 'mcp_reconnect_server'}
EPISODES = {'gauntlet-omp-episode.v1': 'gauntlet-omp-episode.v2',
            'developer-omp-episode.v1': 'developer-omp-episode.v2'}


def validate(value):
    if value is not None and (type(value) is not str or value != PROFILE):
        raise ValueError('exact supported MCP agent-surface profile required')
    return value


def fields(value):
    return {'mcp_agent_surfaces': validate(value)} if value is not None else {}


def apply_episode(config, value):
    validate(value)
    if value is not None:
        if config.get('schema') not in EPISODES or 'mcpAgentSurfaces' in config:
            raise ValueError('new MCP agent profile requires an ordinary v1 episode input')
        config.update(schema=EPISODES[config['schema']], mcpAgentSurfaces=value)
    return config


def config_profile(config):
    if config.get('schema') in EPISODES.values():
        if config.get('mcpAgentSurfaces') != PROFILE:
            raise ValueError('v2 episode requires the frozen MCP agent-surface profile')
        return PROFILE
    if 'mcpAgentSurfaces' in config:
        raise ValueError('MCP agent profile cannot enter an older episode schema')
    return None


def identity_hits(messages):
    """Read actual tool-result data only, without executing captured strings.

    The provider observer independently binds these reported identities to actual
    initialized configured servers and clock order. A hit alone grants no credit.
    """
    found, visited = set(), 0
    families = {'calendar', 'chat', 'crm', 'docs', 'mail', 'tables', 'tickets'}
    def walk(value, depth=0):
        nonlocal visited
        visited += 1
        if depth > 16 or visited > 10000:
            return
        if type(value) is dict:
            if (type(value.get('configuredServer')) is str and value['configuredServer'] in families
                    and type(value.get('serverInfo')) is dict
                    and value['serverInfo'].get('name') == 'benchmark-collision'):
                found.add(value['configuredServer'])
            for child in value.values():
                walk(child, depth + 1)
        elif type(value) is list:
            for child in value:
                walk(child, depth + 1)
        elif type(value) is str and value.startswith(('{', '[')) and len(value) <= 131072:
            try:
                walk(strict_json_loads(value), depth + 1)
            except (ValueError, RecursionError):
                pass
    for message in messages if type(messages) is list else []:
        if type(message) is dict and message.get('role') in {'tool', 'toolResult'}:
            walk(message.get('content'))
    return sorted(found)


def bind_report(runtime, report):
    """Called after signatures/retained-file audits, before granting acceptance."""
    expected = validate(runtime.get('mcp_agent_surfaces'))
    if report.get('mcp_agent_surfaces') != expected:
        raise ValueError('actual harness profile differs from frozen runtime')
    if expected is None:
        return
    if report.get('group') == 'developer':
        # Developer normalization copies this only from its signed producer.
        evidence = report.get('developer_model_harness_profile')
        if evidence != expected:
            raise ValueError('developer provider observer lacks frozen harness binding')
    elif report.get('group') == 'approval':
        phases = report.get('approval_phase_observations', [])
        if not phases or any((phase.get('model_budget_evidence') or {}).get('record', {}).get(
                'mcp_agent_surfaces') != expected for phase in phases):
            raise ValueError('approval phases lack the frozen harness binding')
        if report.get('execution_valid') is True:
            for phase in phases:
                verify_inventory(phase['model_budget_evidence']['record']['budget'])
    elif (report.get('model_budget_evidence') or {}).get('record', {}).get('mcp_agent_surfaces') != expected:
        raise ValueError('business provider observer lacks frozen harness binding')
    elif report.get('execution_valid') is True:
        verify_inventory(report['model_budget_evidence']['record']['budget'])


def verify_inventory(budget, *, developer=False):
    """Actual provider tool declarations, independent of SDK inventory claims."""
    expected = TOOLS | ({'read', 'write', 'edit', 'bash'} if developer else set())
    completed = {row.get('model_request_id') for row in budget['records']
        if row.get('kind') == 'model-response' and row.get('method') == 'POST'
        and type(row.get('model_request_id')) is int
        and row.get('complete') is True and row.get('status') == 200 and row.get('error') is None
        and type(row.get('provider_tokens')) is int and row['provider_tokens'] > 0}
    witnessed = False
    for row in budget['records']:
        if row.get('kind') != 'model-request':
            continue
        if type(row.get('model_request_id')) is not int or row['model_request_id'] < 1:
            raise ValueError('provider inventory needs exact request identities')
        names = row.get('tool_names')
        if type(names) is not list or any(type(name) is not str for name in names):
            raise ValueError('provider tool inventory witness missing or malformed')
        if names and (set(names) != expected or len(names) != len(expected)):
            raise ValueError('actual provider tool inventory differs from selected harness')
        witnessed |= bool(names) and row.get('model_request_id') in completed
    if not witnessed:
        raise ValueError('completed provider request did not exercise the selected tool inventory')
