"""Controller transport conformance only; no model inference or candidate code."""
from __future__ import annotations

import http.client
import http.server
import json
import tempfile
import threading
from pathlib import Path

import pytest

from ci.gauntlet.benchmark.developer_budget import DeveloperBudgetRelay, ProviderUsageError, provider_usage
from ci.gauntlet.benchmark.developer_model_relay import UnixConnection


@pytest.fixture
def tmp_path():
    with tempfile.TemporaryDirectory(prefix='bm-budget-', dir='/tmp') as directory:
        yield Path(directory).resolve()


def response(model='frozen', tokens=7):
    return json.dumps({'model': model, 'usage': {'prompt_tokens': 2, 'completion_tokens': tokens - 2,
                                               'total_tokens': tokens}}).encode()


def test_json_and_real_sse_framing_charge_same_authoritative_usage():
    assert provider_usage(response(), 'application/json', 'frozen') == 7
    stream = b'data: {"model":"frozen","choices":[]}\n\n' + b'data: ' + response() + b'\n\ndata: [DONE]\n'
    assert provider_usage(stream, 'text/event-stream', 'frozen') == 7


@pytest.mark.parametrize('body', [b'{}', b'{"model":"frozen","usage":null}',
    b'{"model":"frozen","usage":{"total_tokens":7}}',
    b'{"model":"frozen","model":"frozen"}',
    b'{"model":"frozen","usage":{"prompt_tokens":true,"completion_tokens":6,"total_tokens":7}}'])
def test_missing_malformed_duplicate_usage_is_not_accounting(body):
    with pytest.raises(ValueError):
        provider_usage(body, 'application/json', 'frozen')


def test_wrong_upstream_identity_retains_known_cost_and_blocks_next_request(tmp_path):
    relay = DeveloperBudgetRelay(tmp_path / 'model.sock', model_id='frozen', max_tokens=20, max_requests=10)
    try:
        relay._validate('POST', '/v1/chat/completions', b'{"model":"frozen","messages":[]}')
        relay._observe('POST', '/v1/chat/completions', 200, 'application/json', response('other'), True)
        assert relay.evidence()['observed_tokens'] == 7
        assert not relay.evidence()['usage_known']
        assert not relay._authorize()
    finally:
        relay.close()
    assert relay.evidence()['cleanup_complete']
    with pytest.raises(ProviderUsageError) as caught:
        provider_usage(response('other'), 'application/json', 'frozen')
    assert caught.value.observed_tokens == 7


def test_malformed_sse_suffix_cannot_erase_already_observed_valid_cost():
    body = b'data: ' + response() + b'\n\ndata: malformed provider frame\n'
    with pytest.raises(ProviderUsageError) as caught:
        provider_usage(body, 'text/event-stream', 'frozen')
    assert caught.value.observed_tokens == 7


def test_single_active_request_and_soft_threshold_preserve_actual_overrun(tmp_path):
    relay = DeveloperBudgetRelay(tmp_path / 'model.sock', model_id='frozen', max_tokens=5, max_requests=10,
                                 markers={'attack': 'lower trust text'})
    body = b'{"model":"frozen","messages":[{"content":"lower trust text"}]}'
    try:
        relay._validate('POST', '/v1/chat/completions', body)
        with pytest.raises(PermissionError):
            relay._validate('POST', '/v1/chat/completions', body)
        relay._observe('POST', '/v1/chat/completions', 200, 'application/json', response(), True)
        evidence = relay.evidence()
        assert evidence['observed_tokens'] == 7 and evidence['threshold_overrun'] == 2
        assert evidence['model_requests'] == 1
        assert evidence['records'][0]['context_marker_hits'] == ['attack']
        assert 'lower trust text' not in json.dumps(evidence)
        assert not relay._authorize()
    finally:
        relay.close()


def test_request_model_mismatch_does_not_start_or_charge_request(tmp_path):
    relay = DeveloperBudgetRelay(tmp_path / 'model.sock', model_id='frozen', max_tokens=20, max_requests=10)
    try:
        with pytest.raises(ValueError):
            relay._validate('POST', '/v1/chat/completions', b'{"model":"other"}')
        assert relay.evidence()['model_requests'] == 0 and not relay.active
        relay._validate('POST', '/v1/chat/completions', b'{"model":"frozen"}')
        relay._observe('POST', '/v1/chat/completions', 200, 'application/json', b'{}', True)
        assert not relay._authorize()
    finally:
        relay.close()


def test_actual_unix_http_forwarding_observes_sse_cost_then_refuses_next_request(monkeypatch, tmp_path):
    """Local static HTTP conformance fixture, never a model inference transcript."""
    class Provider(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_POST(self):
            assert json.loads(self.rfile.read(int(self.headers['Content-Length'])))['model'] == 'frozen'
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.end_headers()
            self.wfile.write(b'data: ' + response() + b'\n\ndata: [DONE]\n')

    upstream = http.server.HTTPServer(('127.0.0.1', 0), Provider)
    thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setattr(DeveloperBudgetRelay, '_connection', lambda _self:
                        http.client.HTTPConnection('127.0.0.1', upstream.server_port, timeout=2))
    relay = DeveloperBudgetRelay(tmp_path / 'model.sock', model_id='frozen', max_tokens=5, max_requests=10)
    try:
        for expected in (200, 403):
            connection = UnixConnection(str(relay.path))
            connection.request('POST', '/v1/chat/completions', body=b'{"model":"frozen"}')
            result = connection.getresponse()
            assert result.status == expected
            result.read()
            connection.close()
        assert relay.evidence()['observed_tokens'] == 7 and relay.evidence()['model_requests'] == 1
    finally:
        relay.close()
        upstream.shutdown()
        upstream.server_close()
        thread.join(timeout=5)


def test_accepted_before_close_body_cannot_validate_or_forward_after_cleanup(monkeypatch, tmp_path):
    """Actual UDS stalled-body race; the provider factory must never be reached."""
    authorized = threading.Event()
    provider_connections = []
    original_authorize = DeveloperBudgetRelay._authorize

    def authorize(relay):
        allowed = original_authorize(relay)
        authorized.set()
        return allowed

    def provider_connection(_relay):
        provider_connections.append('must never forward')
        raise AssertionError('post-close request reached provider')

    monkeypatch.setattr(DeveloperBudgetRelay, '_authorize', authorize)
    monkeypatch.setattr(DeveloperBudgetRelay, '_connection', provider_connection)
    relay = DeveloperBudgetRelay(tmp_path / 'model.sock', model_id='frozen', max_tokens=20, max_requests=10)
    connection = UnixConnection(str(relay.path))
    body = b'{"model":"frozen"}'
    try:
        connection.putrequest('POST', '/v1/chat/completions')
        connection.putheader('Content-Length', str(len(body)))
        connection.endheaders()
        assert authorized.wait(timeout=2)
        relay.close()
        before = relay.evidence()
        assert before['cleanup_complete'] and before['model_requests'] == 0
        assert before['active_handlers'] == before['accepted_clients'] == 0
        assert connection.sock.recv(128) == b''
        with pytest.raises(PermissionError):
            relay._validate('POST', '/v1/chat/completions', body)
        with pytest.raises(PermissionError):
            relay._validate('GET', '/v1/models', b'')
        after = relay.evidence()
        assert after == before and not provider_connections
        assert after['records'] == [] and after['observed_tokens'] == 0
    finally:
        connection.close()
        relay.close()


def test_factory_shutdown_failure_is_observed_and_live_handler_prevents_cleanup(monkeypatch, tmp_path):
    entered, released = threading.Event(), threading.Event()

    def paused_factory(_relay):
        entered.set()
        assert released.wait(timeout=10)
        raise PermissionError('controller closed before provider registration')

    monkeypatch.setattr(DeveloperBudgetRelay, '_connection', paused_factory)
    relay = DeveloperBudgetRelay(tmp_path / 'model.sock', model_id='frozen', max_tokens=20, max_requests=10)
    connection = UnixConnection(str(relay.path))
    try:
        connection.request('POST', '/v1/chat/completions', body=b'{"model":"frozen"}')
        assert entered.wait(timeout=2)
        relay.close()
        incomplete = relay.evidence()
        assert not incomplete['cleanup_complete'] and incomplete['active_handlers'] == 1
        assert incomplete['model_requests'] == 1 and incomplete['observed_tokens'] == 0
        released.set()
        assert relay.server.wait_drained(2)
        complete = relay.evidence()
        assert complete['cleanup_complete'] and not complete['usage_known']
        assert complete['active_handlers'] == complete['accepted_clients'] == 0
        assert complete['records'][-1]['kind'] == 'model-response'
        assert complete['records'][-1]['complete'] is False and complete['records'][-1]['provider_tokens'] is None
    finally:
        released.set()
        connection.close()
        relay.close()


def test_evidence_snapshot_has_no_mutable_record_aliases(tmp_path):
    relay = DeveloperBudgetRelay(tmp_path / 'model.sock', model_id='frozen', max_tokens=20, max_requests=10,
                                 markers={'attack': 'data'})
    try:
        relay._validate('POST', '/v1/chat/completions', b'{"model":"frozen","messages":[{"content":"data"}]}')
        snapshot = relay.evidence()
        snapshot['records'][0]['context_marker_hits'].append('forged')
        assert relay.evidence()['records'][0]['context_marker_hits'] == ['attack']
        relay._observe('POST', '/v1/chat/completions', 200, 'application/json', response(), True)
        assert len(snapshot['records']) == 1 and snapshot['observed_tokens'] == 0
    finally:
        relay.close()


def test_provider_registration_refuses_close_after_validation_without_new_connection(tmp_path):
    relay = DeveloperBudgetRelay(tmp_path / 'model.sock', model_id='frozen', max_tokens=20, max_requests=10)
    try:
        assert relay._authorize()
        relay._validate('POST', '/v1/chat/completions', b'{"model":"frozen"}')
        relay.close()
        with pytest.raises(PermissionError, match='closed before provider'):
            relay._connection()
        assert not relay.connections and not relay.evidence()['cleanup_complete']
    finally:
        relay.close()
