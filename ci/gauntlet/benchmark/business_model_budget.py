"""Signed controller-provider usage; SDK token placeholders have no authority."""
from __future__ import annotations

import base64
import hashlib
import re
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .contracts import canonical_json, digest, strict_json_loads
from .model_endpoint import DEFAULT_BASE_URL, generation_parameters, model_endpoint, verify_model_endpoint

SCHEMA = 'gauntlet-business-model-budget.v1'


def seal_model_budget(relay, config, *, controller_key, startup_incomplete=False, base_url=None,
                      mcp_protocol_profile=None):
    """Capture actual observer state after cleanup, or an uncreated relay path.

Only the trusted launch controller calls this. An uncreated relay means its
model-forwarding boundary never existed, not that an SDK claimed zero usage.
"""
    from .mcp_agent_profile import config_profile, fields
    agent_profile = config_profile(config)
    budget = relay.evidence() if relay is not None else {
        'model_id': config['modelId'], 'max_tokens': config['maxModelTokens'],
        'maximum_requests': config['maxToolCalls'] + 20, 'model_requests': 0,
        'observed_tokens': 0, 'usage_known': True, 'threshold_overrun': 0,
        'cleanup_complete': True, 'records': [], 'scope': 'controller did not create model forwarding boundary'}
    cleanup = {'server_thread_stopped': relay is None or not relay.thread.is_alive(),
               'socket_removed': relay is None or not relay.path.exists(),
               'connections_drained': budget['cleanup_complete'] is True}
    if startup_incomplete:
        budget['usage_known'] = budget['cleanup_complete'] = False
        cleanup = {name: False for name in cleanup}
    provider = model_endpoint(base_url or config.get('baseUrl', DEFAULT_BASE_URL))
    if relay is not None:
        verify_model_endpoint(budget.get('provider'), provider['base_url'])
    names = ['developer_budget.py', 'developer_model_relay.py', 'business_model_budget.py', 'model_endpoint.py']
    if mcp_protocol_profile is not None:
        names += ['mcp_protocol_campaign.py', 'mcp_protocol_profiles.py']
    if agent_profile is not None:
        names += ['mcp_agent_profile.py']
        if relay is not None and budget.get('mcp_agent_surfaces') != agent_profile:
            raise ValueError('actual provider relay lacks the selected harness binding')
    source = {name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest() for name in names}
    record = {'schema': SCHEMA, 'mode': 'relay-startup-incomplete' if startup_incomplete else
              'provider-relay' if relay is not None else 'not-launched',
              'public_config_digest': digest(config), 'budget': budget, 'cleanup': cleanup,
              'sources': source, 'provider': provider,
              'sdk_stdout_authoritative': False, 'qualification': False, **fields(agent_profile)}
    if mcp_protocol_profile is not None:
        from .mcp_protocol_campaign import declaration, profile_markers
        record['mcp_protocol_profile'] = declaration(mcp_protocol_profile)
        if relay is not None and any(relay.markers.get(key) != value
                for key, value in profile_markers(mcp_protocol_profile).items()):
            raise ValueError('actual provider relay lacks declared protocol markers')
    return {'record': record,
            'signature': base64.b64encode(controller_key.sign(canonical_json(record).encode())).decode()}


def verify_model_budget(envelope, *, trusted_public_key, model_id, max_tokens, config_digest=None,
                        maximum_requests=None, expected_sources=None, base_url=DEFAULT_BASE_URL):
    """Independently derive cost/knownness from externally signed observer rows."""
    if type(envelope) is not dict or set(envelope) != {'record', 'signature'}:
        raise ValueError('model budget requires a signed controller envelope')
    record = envelope['record']
    Ed25519PublicKey.from_public_bytes(trusted_public_key).verify(
        base64.b64decode(envelope['signature'], validate=True), canonical_json(record).encode())
    if (record['schema'] != SCHEMA or record['mode'] not in {
            'provider-relay', 'not-launched', 'relay-startup-incomplete'}
            or record['sdk_stdout_authoritative'] is not False or record['qualification'] is not False
            or (config_digest is not None and record['public_config_digest'] != config_digest)):
        raise ValueError('model budget source, scope or configuration mismatch')
    provider = record['provider']
    legacy = provider == {'host': '192.168.5.2', 'port': 8001}
    verify_model_endpoint(None if legacy else provider, base_url)
    budget = record['budget']
    if 'mcp_protocol_profile' in record:
        from .mcp_protocol_campaign import declaration
        declaration(record['mcp_protocol_profile'])
    names = {'developer_budget.py', 'developer_model_relay.py', 'business_model_budget.py'}
    if not legacy:
        names.add('model_endpoint.py')
    if 'mcp_protocol_profile' in record:
        names |= {'mcp_protocol_campaign.py', 'mcp_protocol_profiles.py'}
    if 'mcp_agent_surfaces' in record:
        from .mcp_agent_profile import PROFILE
        if record['mcp_agent_surfaces'] != PROFILE:
            raise ValueError('unknown signed MCP harness profile')
        names.add('mcp_agent_profile.py')
        if record['mode'] == 'provider-relay' and budget.get('mcp_agent_surfaces') != PROFILE:
            raise ValueError('signed provider/harness binding mismatch')
    if (set(record['sources']) != names
            or any(type(sha) is not str or re.fullmatch(r'[0-9a-f]{64}', sha) is None
                   for sha in record['sources'].values())
            or (expected_sources is not None and record['sources'] != expected_sources)):
        raise ValueError('model budget observer source inventory mismatch')
    if not legacy:
        verify_model_endpoint(budget.get('provider', provider), base_url)
    if (budget['model_id'] != model_id or budget['max_tokens'] != max_tokens
            or type(budget['max_tokens']) is not int or budget['max_tokens'] < 1
            or type(budget['threshold_overrun']) is not int or budget['threshold_overrun'] < 0
            or type(budget['model_requests']) is not int or budget['model_requests'] < 0
            or type(budget['observed_tokens']) is not int or budget['observed_tokens'] < 0
            or type(budget['usage_known']) is not bool or type(budget['cleanup_complete']) is not bool
            or type(budget['maximum_requests']) is not int or not 1 <= budget['maximum_requests'] <= 1000
            or (maximum_requests is not None and budget['maximum_requests'] != maximum_requests)
            or set(record['cleanup']) != {'server_thread_stopped', 'socket_removed', 'connections_drained'}
            or any(type(value) is not bool for value in record['cleanup'].values())):
        raise ValueError('model budget differs from exact declared model or threshold')
    rows = budget['records']
    if type(rows) is not list or len(rows) > 3000:
        raise ValueError('model budget observer rows exceed bounded interface')
    requests, responses, total, pending, all_complete = [], [], 0, None, True
    for sequence, row in enumerate(rows, 1):
        if type(row['sequence']) is not int or row['sequence'] != sequence or row['model_id'] != model_id:
            raise ValueError('model budget observer sequence or identity mismatch')
        if row['kind'] == 'model-request':
            if 'generation_parameters' in row:
                sampling = row['generation_parameters']
                if type(sampling) is not dict or generation_parameters(sampling) != sampling:
                    raise ValueError('model observer sampling fields exceed declared scalar interface')
            if (type(row['model_request_id']) is not int or pending is not None
                    or row['model_request_id'] != len(requests) + 1
                    or total >= max_tokens or not all_complete or len(requests) >= budget['maximum_requests']):
                raise ValueError('model request exceeded single active request or observed threshold')
            requests.append(row)
            pending = row['model_request_id']
        elif row['kind'] == 'model-response':
            method, tokens = row['method'], row['provider_tokens']
            if (type(row['complete']) is not bool or (row['error'] is not None and type(row['error']) is not str)
                    or (row['status'] is not None and (type(row['status']) is not int
                                                      or not 100 <= row['status'] <= 599))
                    or type(row['cumulative_tokens']) is not int or row['cumulative_tokens'] < 0):
                raise ValueError('provider response observation types are malformed')
            if method not in {'GET', 'POST'} or (tokens is not None and (type(tokens) is not int or tokens < 1)):
                raise ValueError('invalid provider response method or known cost')
            if method == 'GET':
                if tokens is not None or row['model_request_id'] is not None:
                    raise ValueError('model discovery cannot claim inference tokens')
            else:
                if type(row['model_request_id']) is not int or pending is None or row['model_request_id'] != pending:
                    raise ValueError('provider response lacks exact corresponding request')
                responses.append(row)
                pending = None
                total += tokens or 0
            if row['cumulative_tokens'] != total:
                raise ValueError('provider cost accumulation differs from actual observer rows')
            all_complete &= (row['complete'] is True and row['status'] == 200 and row['error'] is None
                             and (method == 'GET' or tokens is not None))
        else:
            raise ValueError('unknown model budget observer record')
    if len(requests) != budget['model_requests'] or total != budget['observed_tokens']:
        raise ValueError('model budget aggregate differs from actual request/response history')
    cleanup = budget['cleanup_complete'] and all(value is True for value in record['cleanup'].values())
    if record['mode'] == 'not-launched' and (rows or requests or total or not cleanup):
        raise ValueError('uncreated model boundary has contradictory request/cleanup evidence')
    complete = pending is None and len(requests) == len(responses) and all_complete and cleanup
    # Unresolved cleanup cannot establish the final cost of active activity.
    if budget['usage_known'] is True and not complete and cleanup:
        raise ValueError('provider observer falsely claims complete model accounting')
    overrun = max(0, total - max_tokens)
    if budget['threshold_overrun'] != overrun:
        raise ValueError('model budget threshold overrun does not match observed tokens')
    return {'observed_model_tokens': total, 'model_usage_known': complete and budget['usage_known'],
            'model_requests': len(requests), 'inference_started': bool(requests),
            'token_threshold_overrun': overrun, 'budget_exhausted': total >= max_tokens,
            'cleanup_complete': cleanup, 'model_budget_authority': 'controller-provider-relay',
            'zero_model_requests_proven': not requests and complete and budget['usage_known']}


def legacy_sdk_usage(events):
    """Retain an explicitly untrusted diagnostic lower bound, never known usage."""
    total = 0
    for row in events:
        if row.get('type') == 'agent_event':
            event = row.get('event', {})
            message = event.get('message', {})
            used = message.get('usage', {}).get('totalTokens')
            if event.get('type') == 'message_end' and message.get('role') == 'assistant' and type(used) is int:
                total += max(0, used)
        elif row.get('type') == 'episode_end' and type(row.get('modelTokens')) is int:
            total = max(total, row['modelTokens'])
    return {'observed_model_tokens': total, 'model_usage_known': False,
            'model_budget_authority': 'legacy-sdk-diagnostic', 'zero_model_requests_proven': False}


def audit_business_model_budget(path, report):
    """Campaign resume hook; signature and derived cost cannot be replaced by SDK output."""
    envelope = report.get('model_budget_evidence')
    if envelope is None:
        if report.get('model_budget_authority') == 'controller-provider-relay':
            raise ValueError('authoritative business model budget missing')
        return {}
    retained = path / 'model-budget.json'
    if retained.is_symlink() or not retained.is_file() or retained.stat().st_size > 8 * 1024**2:
        raise ValueError('retained business model budget missing or unbounded')
    if strict_json_loads(retained.read_text()) != envelope:
        raise ValueError('retained model budget differs from actual pilot report')
    isolation = report.get('isolation') or {}
    cfg = isolation.get('record', {}).get('public_config_digest')
    usage = verify_model_budget(envelope,
        trusted_public_key=base64.b64decode(report['producer_public_key'], validate=True),
        model_id=report['model_id'], max_tokens=report['budgets']['model_tokens'], config_digest=cfg,
        maximum_requests=report['budgets']['tool_calls'] + 20,
        base_url=report.get('model_base_url', DEFAULT_BASE_URL))
    expected = {'model_tokens': usage['observed_model_tokens'], 'model_usage_known': usage['model_usage_known'],
                'model_budget_authority': usage['model_budget_authority'],
                'model_requests': usage['model_requests'],
                'zero_model_requests_proven': usage['zero_model_requests_proven'],
                'token_threshold_overrun': usage['token_threshold_overrun']}
    if any(report.get(name) != value for name, value in expected.items()):
        raise ValueError('reported business model usage differs from independently recomputed provider evidence')
    if isolation and isolation['record'].get('model_budget_evidence') != envelope:
        raise ValueError('signed isolation omits exact business model budget binding')
    return {'model-budget.json': hashlib.sha256(retained.read_bytes()).hexdigest()}


def bind_business_model_budget(config, report):
    """Bind provider observation to externally frozen controller source/budgets.

    Legacy reports remain diagnostic; absence never creates provider evidence.
    Caller separately authenticates the report producer and retained isolation.
    """
    envelope = report.get('model_budget_evidence')
    if envelope is None:
        if report.get('model_budget_authority') == 'controller-provider-relay':
            raise ValueError('authoritative business model budget missing')
        return None
    names = tuple(envelope['record']['sources'])
    if (str(Path(__file__).with_name('model_endpoint.py').resolve()) in config['identities']
            and 'model_endpoint.py' not in names):
        raise ValueError('new frozen observer requires its endpoint helper identity')
    sources = {name: config['identities'][str(Path(__file__).with_name(name).resolve())] for name in names}
    isolation = report.get('isolation') or {}
    record = isolation.get('record', {})
    if isolation and record.get('model_budget_evidence') != envelope:
        raise ValueError('signed isolation budget binding mismatch')
    budgets = config['campaign']['budgets']
    usage = verify_model_budget(envelope,
        trusted_public_key=base64.b64decode(report['producer_public_key'], validate=True),
        model_id=config['runtime']['model_id'], max_tokens=budgets['model_tokens'],
        maximum_requests=budgets['tool_operations'] + 20, expected_sources=sources,
        config_digest=record.get('public_config_digest'), base_url=config['runtime'].get('base_url', DEFAULT_BASE_URL))
    fields = {'model_tokens': 'observed_model_tokens', 'model_usage_known': 'model_usage_known',
              'model_requests': 'model_requests', 'zero_model_requests_proven': 'zero_model_requests_proven',
              'token_threshold_overrun': 'token_threshold_overrun',
              'model_budget_authority': 'model_budget_authority'}
    if any(report.get(name) != usage[key] for name, key in fields.items()):
        raise ValueError('reported business budget differs from frozen provider evidence')
    return usage
