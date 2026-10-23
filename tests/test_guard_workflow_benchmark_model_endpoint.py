"""Controller routing conformance; no upstream model or VM calls."""
import base64
import copy
import json
import tempfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ci.gauntlet.benchmark.business_agent_container import mapped_config
from ci.gauntlet.benchmark.business_model_budget import seal_model_budget, verify_model_budget
from ci.gauntlet.benchmark.developer_budget import DeveloperBudgetRelay
from ci.gauntlet.benchmark.model_endpoint import (
    DEFAULT_BASE_URL,
    generation_parameters,
    model_endpoint,
    verify_model_endpoint,
)


@pytest.mark.parametrize('port', [8001, 8002])
@pytest.mark.parametrize('host', ['host.lima.internal', '192.168.5.2', '127.0.0.1', 'localhost'])
def test_exact_declared_alias_maps_only_to_pinned_lima_route(port, host):
    url = f'http://{host}:{port}/v1'
    assert model_endpoint(url) == {'base_url': url, 'host': '192.168.5.2', 'port': port}


@pytest.mark.parametrize('url', [
    'http://remote.test:8002/v1', 'http://192.168.5.3:8002/v1', 'https://host.lima.internal:8002/v1',
    'http://user@host.lima.internal:8002/v1', 'http://host.lima.internal:80/v1',
    'http://host.lima.internal:8003/v1', 'http://host.lima.internal:8002/v1/',
    'http://host.lima.internal:8002/v1/other', 'http://host.lima.internal:8002/v1?x=1',
    'http://host.lima.internal:8002/v1#x', 'http://host.lima.internal:08002/v1',
    'http://host.lima.internal:8002/%76%31', 'http://host.lima.internal:8002/v1\n', None,
])
def test_no_arbitrary_egress_credentials_paths_or_port_spelling(url):
    with pytest.raises(ValueError):
        model_endpoint(url)


@pytest.mark.parametrize('url,port', [(DEFAULT_BASE_URL, 8001), ('http://host.lima.internal:8002/v1', 8002)])
def test_actual_connection_factory_receives_only_pinned_host_and_declared_port(monkeypatch, url, port):
    observed = []

    class Connection:
        sock = None
        def __init__(self, host, chosen_port, timeout):
            observed.append((host, chosen_port, timeout))
        def close(self):
            pass

    monkeypatch.setattr('ci.gauntlet.benchmark.developer_budget.http.client.HTTPConnection', Connection)
    with tempfile.TemporaryDirectory(prefix='endpoint-', dir='/tmp') as directory:
        relay = DeveloperBudgetRelay(Path(directory) / 'm.sock', model_id='fixture', max_tokens=10,
                                     max_requests=1, base_url=url)
        try:
            connection = relay._connection()  # Construct only; no connect/request/candidate execution.
            assert observed == [('192.168.5.2', port, 180)]
            connection.close()
        finally:
            relay.close()
        assert relay.evidence()['provider'] == model_endpoint(url)
        assert relay.evidence()['model_requests'] == 0


def test_signed_budget_pins_original_url_and_fixed_route_and_helper_source():
    url = 'http://host.lima.internal:8002/v1'
    config = {'modelId': 'fixture', 'maxModelTokens': 10, 'maxToolCalls': 1, 'baseUrl': url}
    key = Ed25519PrivateKey.generate()
    envelope = seal_model_budget(None, config, controller_key=key)
    kwargs = {'trusted_public_key': key.public_key().public_bytes_raw(), 'model_id': 'fixture',
              'max_tokens': 10, 'maximum_requests': 21}
    assert 'model_endpoint.py' in envelope['record']['sources']
    assert verify_model_budget(envelope, **kwargs, base_url=url)['zero_model_requests_proven']
    for changed in [DEFAULT_BASE_URL, 'http://127.0.0.1:8002/v1']:
        with pytest.raises(ValueError, match='frozen controller declaration'):
            verify_model_budget(envelope, **kwargs, base_url=changed)
    tampered = copy.deepcopy(envelope)
    tampered['record']['provider']['port'] = 8001
    tampered['signature'] = base64.b64encode(key.sign(json.dumps(tampered['record'],
        sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode())).decode()
    with pytest.raises(ValueError):
        verify_model_budget(tampered, **kwargs, base_url=url)
    with pytest.raises(ValueError):
        verify_model_endpoint(None, url)


def test_agent_mapping_preserves_loopback_bridge_despite_dedicated_upstream():
    config = {'schema': 'gauntlet-omp-episode.v1', 'baseUrl': 'http://host.lima.internal:8002/v1',
              'modelId': 'fixture', 'prompt': 'Prepare authorized artifacts', 'deadlineSeconds': 30,
              'maxToolCalls': 1, 'maxModelTokens': 10, 'endpoints': {'docs': {}}}
    assert mapped_config(config)['baseUrl'] == 'http://127.0.0.1:8001/v1'
    assert config['baseUrl'] == 'http://host.lima.internal:8002/v1'


@pytest.mark.parametrize('value', [float('nan'), float('inf'), -float('inf'), {}, [], 'secret', True])
def test_sampling_rejects_nonfinite_container_string_and_boolean_values(value):
    with pytest.raises(ValueError):
        generation_parameters({'temperature': value})


def test_request_records_only_actual_allowlisted_sampling_fields_and_no_defaults():
    with tempfile.TemporaryDirectory(prefix='sampling-', dir='/tmp') as directory:
        relay = DeveloperBudgetRelay(Path(directory) / 'm.sock', model_id='fixture', max_tokens=100,
                                     max_requests=1)
        request = {'model': 'fixture', 'messages': [{'content': 'private prompt not recorded'}],
                   'temperature': 0.25, 'top_p': 0.9, 'top_k': 40, 'min_p': None, 'seed': 42,
                   'max_tokens': 50, 'max_completion_tokens': 25, 'repetition_penalty': 1.0,
                   'presence_penalty': 0, 'frequency_penalty': 0.1,
                   'response_format': {'secret': 'never record'}, 'chat_template_kwargs': {'secret': 'no'}}
        try:
            relay._validate('POST', '/v1/chat/completions', json.dumps(request).encode())
            record = relay.evidence()['records'][0]
            assert record['generation_parameters'] == generation_parameters(request)
            assert len(record['generation_parameters']) == 10
            assert 'private prompt' not in json.dumps(record) and 'secret' not in json.dumps(record)
            assert generation_parameters({'model': 'fixture'}) == {}
            # Finish only the observer fixture, without forwarding or making a provider request.
            relay._observe('POST', '/v1/chat/completions', None, '', b'', False)
        finally:
            relay.close()
