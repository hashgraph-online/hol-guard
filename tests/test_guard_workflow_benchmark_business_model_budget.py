"""Controller transport/static-provider conformance, never model campaign evidence."""
import base64
import copy
import http.client
import http.server
import json
import tempfile
import threading
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ci.gauntlet.benchmark.business_model_budget import (
    audit_business_model_budget,
    bind_business_model_budget,
    legacy_sdk_usage,
    seal_model_budget,
    verify_model_budget,
)
from ci.gauntlet.benchmark.contracts import canonical_json, digest
from ci.gauntlet.benchmark.developer_budget import DeveloperBudgetRelay
from ci.gauntlet.benchmark.developer_model_relay import UnixConnection

CONFIG = {'modelId': 'fixed', 'maxModelTokens': 32000, 'maxToolCalls': 40}


@pytest.fixture
def budget(tmp_path):
    # The actual Unix socket must fit the platform path bound.
    with tempfile.TemporaryDirectory(prefix='business-budget-', dir='/tmp') as directory:
        relay = DeveloperBudgetRelay(Path(directory).resolve() / 'model.sock', model_id='fixed',
                                     max_tokens=32000, max_requests=60)
        key = Ed25519PrivateKey.generate()
        yield relay, key
        relay.close()


def response(tokens=38042):
    return json.dumps({'model': 'fixed', 'usage': {'prompt_tokens': tokens - 42,
        'prompt_tokens_details': {'cached_tokens': tokens - 100},
        'completion_tokens': 42, 'total_tokens': tokens}}).encode()


def seal(relay, key):
    relay.close()
    return seal_model_budget(relay, CONFIG, controller_key=key)


def verify(envelope, key, **extra):
    return verify_model_budget(envelope, trusted_public_key=key.public_key().public_bytes_raw(),
        model_id='fixed', max_tokens=32000, maximum_requests=60, config_digest=digest(CONFIG), **extra)


def observed_cost(relay, body=None, complete=True):
    relay._validate('POST', '/v1/chat/completions', b'{"model":"fixed","messages":[]}')
    relay._observe('POST', '/v1/chat/completions', 200, 'application/json', body or response(), complete)


def test_provider_overrun_including_cached_input_survives_sdk_zero_placeholder(budget):
    relay, key = budget
    observed_cost(relay)
    usage = verify(seal(relay, key), key)
    events = [{'type': 'episode_end', 'modelTokens': 38042, 'modelUsageKnown': False}]
    assert legacy_sdk_usage(events)['model_usage_known'] is False
    assert usage['observed_model_tokens'] == 38042
    assert usage['model_usage_known'] and usage['token_threshold_overrun'] == 6042
    assert usage['budget_exhausted'] and usage['model_requests'] == 1


def test_incomplete_response_retains_known_lower_bound_but_is_unknown(budget):
    relay, key = budget
    observed_cost(relay, complete=False)
    usage = verify(seal(relay, key), key)
    assert usage['observed_model_tokens'] == 38042
    assert not usage['model_usage_known'] and not usage['zero_model_requests_proven']


def test_zero_actual_post_requests_is_known_only_with_signed_observer_cleanup(budget):
    relay, key = budget
    relay._observe('GET', '/v1/models', 200, 'application/json', b'{"data":[{"id":"fixed"}]}', True)
    usage = verify(seal(relay, key), key)
    assert usage['observed_model_tokens'] == 0 and usage['model_usage_known']
    assert usage['zero_model_requests_proven'] and not usage['inference_started']


def test_requested_but_incomplete_relay_constructor_is_not_zero_cost_proof():
    key = Ed25519PrivateKey.generate()
    usage = verify(seal_model_budget(None, CONFIG, controller_key=key, startup_incomplete=True), key)
    assert not usage['model_usage_known'] and not usage['cleanup_complete']
    assert not usage['zero_model_requests_proven']


@pytest.mark.parametrize('target,value', [('sequence', True), ('model_request_id', True),
                                        ('complete', 1), ('error', {}), ('cumulative_tokens', True)])
def test_even_resigned_malformed_observer_records_fail_closed(budget, target, value):
    relay, key = budget
    observed_cost(relay)
    envelope = seal(relay, key)
    row = envelope['record']['budget']['records'][1 if target in {'complete', 'error', 'cumulative_tokens'} else 0]
    row[target] = value
    envelope['signature'] = base64.b64encode(key.sign(canonical_json(envelope['record']).encode())).decode()
    with pytest.raises(ValueError):
        verify(envelope, key)


def test_external_key_model_threshold_request_cap_and_source_identity_are_required(budget):
    relay, key = budget
    envelope = seal(relay, key)
    with pytest.raises(InvalidSignature):
        verify(envelope, Ed25519PrivateKey.generate())
    with pytest.raises(ValueError):
        verify_model_budget(envelope, trusted_public_key=key.public_key().public_bytes_raw(),
                            model_id='fixed', max_tokens=999, maximum_requests=60)
    with pytest.raises(ValueError):
        verify_model_budget(envelope, trusted_public_key=key.public_key().public_bytes_raw(),
                            model_id='fixed', max_tokens=32000, maximum_requests=61)
    with pytest.raises(ValueError):
        verify(envelope, key, expected_sources={})
    envelope['record']['budget']['threshold_overrun'] = False
    envelope['signature'] = base64.b64encode(key.sign(canonical_json(envelope['record']).encode())).decode()
    with pytest.raises(ValueError):
        verify(envelope, key)


def test_retained_business_audit_uses_provider_not_sdk_claim_and_rejects_duplicates(budget, tmp_path):
    relay, key = budget
    observed_cost(relay)
    envelope = seal(relay, key)
    usage = verify(envelope, key)
    report = {'model_budget_evidence': envelope, 'model_id': 'fixed',
        'producer_public_key': base64.b64encode(key.public_key().public_bytes_raw()).decode(),
        'budgets': {'model_tokens': 32000, 'tool_calls': 40}, 'model_tokens': 38042,
        'model_usage_known': True, 'model_budget_authority': usage['model_budget_authority'],
        'model_requests': 1, 'zero_model_requests_proven': False, 'token_threshold_overrun': 6042}
    path = tmp_path / 'model-budget.json'
    path.write_text(canonical_json(envelope))
    assert audit_business_model_budget(tmp_path, report)
    bad = copy.deepcopy(report)
    bad['model_tokens'] = 32000
    with pytest.raises(ValueError):
        audit_business_model_budget(tmp_path, bad)
    path.write_text('{"record":{},"record":{},"signature":"x"}')
    with pytest.raises(ValueError):
        audit_business_model_budget(tmp_path, report)


def test_actual_http_provider_observer_stops_next_model_request_after_overrun(monkeypatch, budget):
    unused, key = budget
    calls = []

    class Provider(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_POST(self):
            calls.append(json.loads(self.rfile.read(int(self.headers['Content-Length']))))
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(response())

    upstream = http.server.HTTPServer(('127.0.0.1', 0), Provider)
    thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setattr(DeveloperBudgetRelay, '_connection', lambda _self: http.client.HTTPConnection(
        '127.0.0.1', upstream.server_port, timeout=2))
    relay = DeveloperBudgetRelay(unused.path.with_name('local.sock'), model_id='fixed',
                                 max_tokens=32000, max_requests=60)
    try:
        for expected in (200, 403):
            connection = UnixConnection(str(relay.path))
            connection.request('POST', '/v1/chat/completions', body=b'{"model":"fixed","messages":[]}')
            result = connection.getresponse()
            assert result.status == expected
            result.read()
            connection.close()
        assert len(calls) == 1
    finally:
        relay.close()
        upstream.shutdown()
        upstream.server_close()
        thread.join(timeout=5)
    assert verify(seal_model_budget(relay, CONFIG, controller_key=key), key)['observed_model_tokens'] == 38042


def test_approval_phase_resume_recomputes_provider_cost_despite_aborted_sdk_placeholder(budget, tmp_path):
    from ci.gauntlet.benchmark.approval_campaign import _phase_observations
    from ci.gauntlet.benchmark.approval_pilot import episode_summary

    relay, key = budget
    observed_cost(relay)
    envelope = seal(relay, key)
    root = tmp_path / 'preparation'
    (root / 'public').mkdir(parents=True)
    (root / 'public/episode.json').write_text(canonical_json(CONFIG))
    (root / 'model-budget.json').write_text(canonical_json(envelope))
    events = [{'type': 'episode_end', 'modelTokens': 38042, 'modelUsageKnown': False,
               'status': 'budget-exhausted'}]  # Observer-parser fixture, not a model transcript.
    events_path = root / 'agent-events.jsonl'
    events_path.write_text('\n'.join(canonical_json(event) for event in events))
    record = {'public_config_digest': digest(CONFIG), 'model_budget_evidence': envelope,
              'exit_code': 0, 'controller_error': None, 'assets_unchanged': True,
              'isolation_observed': False, 'cleanup_complete': True}
    isolation = {'record': record, 'signature': base64.b64encode(
        key.sign(canonical_json(record).encode())).decode()}
    (root / 'isolation.json').write_text(canonical_json(isolation))
    summary = episode_summary({'isolation': isolation, 'model_budget_evidence': envelope,
        'events_path': str(events_path), 'stderr_path': str(root / 'agent-stderr.txt'),
        'exit_code': 0, 'controller_error': None}, trusted_public_key=key.public_key().public_bytes_raw(),
        model_id='fixed', max_tokens=32000)
    raw = {'phases': [summary], 'public_key': base64.b64encode(key.public_key().public_bytes_raw()).decode(),
           'model_id': 'fixed', 'budgets_per_phase': {'tokens': 32000, 'tool_calls': 40},
           'model_budget_evidence_version': envelope['record']['schema']}
    derived = _phase_observations(tmp_path, raw)[0]
    assert derived['usage']['observed_model_tokens'] == 38042
    assert derived['usage']['model_usage_known']
    assert not derived['execution_valid']  # This fixture has no measured agent isolation.
    changed = copy.deepcopy(envelope)
    changed['record']['budget']['observed_tokens'] = 32000
    (root / 'model-budget.json').write_text(canonical_json(changed))
    with pytest.raises(ValueError):
        _phase_observations(tmp_path, raw)


def test_approval_frozen_budget_binding_cannot_accept_self_raised_phase_budget(tmp_path):
    from ci.gauntlet.benchmark.approval_campaign import bind_approval_isolation
    config = {'runtime': {'isolated': True}, 'isolation_tuple': {},
              'campaign': {'budgets': {'episode_seconds': 30, 'tool_operations': 40, 'model_tokens': 32000}}}
    report = {'execution_lane': 'isolated-linux', 'execution_valid': False,
              'budgets': {'wall_seconds': 30, 'tool_calls': 40, 'model_tokens': 50000}}
    with pytest.raises(ValueError, match='frozen campaign budget'):
        bind_approval_isolation(config, report, attempt_path=tmp_path)


def test_business_frozen_observer_source_and_phase_config_are_external(budget):
    relay, key = budget
    observed_cost(relay)
    envelope = seal(relay, key)
    usage = verify(envelope, key)
    source = Path(__file__).parents[1] / 'ci/gauntlet/benchmark'
    config = {'runtime': {'model_id': 'fixed'},
              'campaign': {'budgets': {'model_tokens': 32000, 'tool_operations': 40}},
              'identities': {str(source / name): sha for name, sha in envelope['record']['sources'].items()}}
    report = dict(usage, model_tokens=usage['observed_model_tokens'], model_budget_evidence=envelope,
                  producer_public_key=base64.b64encode(key.public_key().public_bytes_raw()).decode(),
                  isolation={'record': {'public_config_digest': digest(CONFIG), 'model_budget_evidence': envelope}})
    assert bind_business_model_budget(config, report)['observed_model_tokens'] == 38042
    changed = copy.deepcopy(config)
    changed['identities'][str(source / 'developer_budget.py')] = '0' * 64
    with pytest.raises(ValueError, match='source inventory'):
        bind_business_model_budget(changed, report)
    missing_helper = copy.deepcopy(report)
    del missing_helper['model_budget_evidence']['record']['sources']['model_endpoint.py']
    with pytest.raises(ValueError, match='endpoint helper identity'):
        bind_business_model_budget(config, missing_helper)
    report['isolation']['record']['public_config_digest'] = '0' * 64
    with pytest.raises(ValueError, match='configuration mismatch'):
        bind_business_model_budget(config, report)
    assert bind_business_model_budget({}, {'model_budget_authority': 'legacy-sdk-diagnostic'}) is None


@pytest.mark.parametrize('retained', [None, '[]', '{"record":{},"record":{}}'])
def test_invoked_business_launcher_without_observer_cannot_claim_zero_cost(tmp_path, monkeypatch, retained):
    from ci.gauntlet.benchmark import business_agent_container, pilot
    from ci.gauntlet.benchmark.adapters import McpEndpoint

    class Supervisor:
        active_children = active_workers = active_sessions = 0
        def __init__(self, world, directory, **_options):
            self.directory = directory
            self.events = []

        def start(self):
            pass

        def close(self):
            pass

        def endpoint(self, family):
            return McpEndpoint(family, ('/not-executed/fixture',))

    def failed_launch(**_arguments):
        if retained is not None:
            runtime = _arguments['runtime_root']
            runtime.mkdir()
            (runtime / 'model-budget.json').write_text(retained)
        raise RuntimeError('unit launch failure: no model or subprocess was invoked')

    monkeypatch.setattr(pilot, 'ServiceSupervisor', Supervisor)
    monkeypatch.setattr(business_agent_container, 'run_isolated_business_episode', failed_launch)
    monkeypatch.setattr('sys.platform', 'linux')
    monkeypatch.setattr('os.geteuid', lambda: 0)
    report = pilot.run_pilot(root=tmp_path / 'attempt',
        workflow_id='business-sales-lead-qualification', variant='clean', bun=Path('/not-executed/bun'),
        sdk_root=Path('/not-executed/sdk'), model_id='fixed', base_url='http://127.0.0.1:8001/v1', isolated=True)
    assert report['execution_valid'] is False
    assert report['model_budget_evidence'] == ([] if retained == '[]' else None)
    assert report['model_tokens'] == 0 and not report['model_usage_known']
    assert not report['zero_model_requests_proven']
    assert report['receipt_count'] == 0
