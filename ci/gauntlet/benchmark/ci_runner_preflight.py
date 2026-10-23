"""Non-inference capability and durable-provider checks for local CI."""
from __future__ import annotations

import http.client
import os
import sys
from contextlib import contextmanager

from .ci_runner_config import SHA, verify_assets
from .contracts import strict_json_loads
from .model_endpoint import model_endpoint


@contextmanager
def controller_environment(loaded):
    """Pin Node discovery and private creation; restore caller state on every exit."""
    previous_path = os.environ.get('PATH')
    previous_umask = os.umask(0o077)
    os.environ['PATH'] = str(loaded['paths']['node'].parent) + ':/usr/sbin:/usr/bin:/sbin:/bin'
    try:
        yield
    finally:
        os.umask(previous_umask)
        if previous_path is None:
            os.environ.pop('PATH',None)
        else:
            os.environ['PATH'] = previous_path


def verify_provider_status(value, pins):
    """Check operational accounting against caller pins, never SDK assertions."""
    if (type(value) is not dict or set(value) != {'adapter','binding_sha256','qualification','quota'}
            or value['qualification'] is not False or value['binding_sha256'] != pins['binding_sha256']):
        raise ValueError('provider binding differs from externally pinned deployment')
    adapter = value['adapter']
    expected = {'schema':'gauntlet-mlx-quota-adapter.v1','server_sha256':pins['server_sha256'],
        'adapter_sha256':pins['adapter_sha256'],'quota_config_digest':pins['quota_config_digest'],
        'producer_mode':'serial-original-tokenization-and-generation',
        'counting':'full prompt including cached input plus every producer-emitted response token',
        'batching':False,'draft':False,'qualification_eligible':False}
    if 'quota_allowance_digest' in pins:
        allowance = pins['quota_allowance_digest']
        if type(allowance) is not str or SHA.fullmatch(allowance) is None:
            raise ValueError('provider allowance requires an external authorization digest')
        expected['quota_allowance_digest'] = allowance
    if (type(adapter) is not dict or set(adapter) != set(expected)
            or any(type(adapter[key]) is not type(expected[key]) or adapter[key] != expected[key]
                   for key in expected)):
        raise ValueError('provider adapter differs from frozen serial exact-token profile')
    quota = value['quota']
    integers = {'charged_tokens','known_tokens','reserved_tokens','requests','maximum_requests',
                'pending_requests','remaining_tokens','token_cap'}
    keys = integers | {'schema','config_digest','model_identity_digest','halted','journal_hash',
                       'qualification_eligible'}
    if 'quota_allowance_digest' in pins:
        keys.add('allowance_digest')
    if (type(quota) is not dict or set(quota) != keys
            or any(type(quota[name]) is not int or quota[name] < 0 for name in integers)
            or quota['schema'] != 'gauntlet-provider-quota-status.v1'
            or quota['config_digest'] != pins['quota_config_digest']
            or ('quota_allowance_digest' in pins
                and quota['allowance_digest'] != pins['quota_allowance_digest'])
            or quota['model_identity_digest'] != pins['model_identity_digest']
            or quota['token_cap'] != pins['token_cap']
            or quota['maximum_requests'] != pins['maximum_requests']
            or quota['requests'] > quota['maximum_requests']
            or quota['qualification_eligible'] is not False
            or type(quota['journal_hash']) is not str or SHA.fullmatch(quota['journal_hash']) is None
            or quota['halted'] is not False or quota['pending_requests'] != 0
            or quota['reserved_tokens'] != 0 or quota['known_tokens'] != quota['charged_tokens']
            or quota['remaining_tokens'] != quota['token_cap']-quota['charged_tokens']):
        raise ValueError('provider budget has changed identity, uncertain usage or inconsistent counts')
    return quota


def observe_provider(loaded, *, validate=True):
    """Only two fixed GET paths on the existing pinned local route; no redirects."""
    route = model_endpoint(loaded['runtime']['base_url'])
    results = {}
    for path in ('/v1/models','/v1/benchmark-quota'):
        connection = http.client.HTTPConnection(route['host'],route['port'],timeout=5)
        try:
            connection.request('GET',path,headers={'Connection':'close'})
            response = connection.getresponse()
            raw = response.read(65537)
            if response.status != 200 or len(raw) > 65536:
                raise ValueError('local provider metadata is unavailable or exceeds its bound')
            results[path] = strict_json_loads(raw)
        finally:
            connection.close()
    models = results['/v1/models']
    if (type(models) is not dict or type(models.get('data')) is not list
            or [row.get('id') for row in models['data'] if type(row) is dict]
               != [loaded['runtime']['model_id']] or len(models['data']) != 1):
        raise ValueError('actual advertised model differs from exact frozen model')
    if validate:
        verify_provider_status(results['/v1/benchmark-quota'],loaded['config']['provider'])
    return {'route':route,'models':models,'status':results['/v1/benchmark-quota']}


def preflight(loaded):
    """Collect diagnostic failures; none may silently become skipped cases."""
    from .local_campaign import _unsupported
    result = {'schema':'gauntlet-ci-preflight.v1','config_digest':loaded['config_digest'],
              'passed':False,'errors':[],'unsupported_cells':[],
              'selected_cases':len(loaded['config']['selection']),
              'selection_reservations':loaded['selection_reservations'],
              'shards':loaded['shards'],'qualification_eligible':False,
              'trust_status':'local-integrity-only'}
    def check(name, operation):
        try:
            result[name] = operation()
        except Exception as error:
            result['errors'].append({'code':name+'-failed','type':type(error).__name__,
                                     'message':str(error)[:2048]})
    check('assets',lambda:verify_assets(loaded))
    from .developer_seed_inputs import seed_source_identity
    check('developer_seed_inputs',seed_source_identity)
    from .developer_probe_inputs import probe_source_identity
    check('developer_probe_inputs',probe_source_identity)
    if sys.platform != 'linux' or os.geteuid() != 0:
        result['errors'].append({'code':'isolated-linux-root-required'})
    else:
        from .local_campaign_custody import freeze_isolation
        check('isolation',lambda:freeze_isolation(loaded['runtime']))
        check('provider',lambda:observe_provider(loaded))
        if 'provider' in result:
            quota = result['provider']['status']['quota']
            if quota['remaining_tokens'] == 0 or quota['requests'] >= quota['maximum_requests']:
                result['errors'].append({'code':'provider-budget-exhausted'})
    selected = set(loaded['config']['selection'])
    unsupported_surfaces = {'native-contained-execution','guard-external-approval'}
    rules = {row['episode_id']:row for row in loaded['policy']['cells']}
    for cell in loaded['campaign']['inventory']:
        if cell['id'] not in selected:
            continue
        reason = _unsupported(cell,loaded['runtime'],loaded['campaign']['budgets'])
        from .authored_challenges import BASE_WORKFLOWS
        from .campaign_execution import developer_cell
        if (cell.get('protected') is True and developer_cell(cell)
                and BASE_WORKFLOWS.get(cell['workflow_id'],cell['workflow_id'])!='python-cli-with-tests'):
            node=result.get('isolation',{}).get('developer_product',{}).get('node_runtime',{})
            if (node.get('available') is not True
                    or node.get('node',{}).get('sha256')!=loaded['config']['assets']['node']['sha256']):
                reason='executor-node-runtime-closure-unavailable'
        supported=set()
        admission=result.get('isolation',{}).get('local_executor_admission',{})
        if (developer_cell(cell) and admission.get('local_execution_supported') is True
                and admission.get('public_inputs_verified') is True):
            supported.add('native-contained-execution')
        surfaces = set(rules[cell['id']]['required_surfaces']) & (unsupported_surfaces-supported)
        if reason or surfaces:
            result['unsupported_cells'].append({'episode_id':cell['id'],
                'reason':reason or 'required surface lacks reviewed conformance',
                'surfaces':sorted(surfaces)})
    if result['unsupported_cells']:
        result['errors'].append({'code':'required-cells-unsupported'})
    result['passed'] = not result['errors']
    return result
