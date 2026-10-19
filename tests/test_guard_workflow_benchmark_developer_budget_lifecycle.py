"""Actual loopback/UDS lifecycle fixtures, never a model endpoint or episode."""
import http.client
import http.server
import json
import tempfile
import threading
from pathlib import Path

import pytest

from ci.gauntlet.benchmark import developer_budget as budget
from ci.gauntlet.benchmark.developer_model_relay import UnixConnection


@pytest.fixture
def tmp_path():
    with tempfile.TemporaryDirectory(prefix='bm-drain-', dir='/tmp') as directory:
        yield Path(directory).resolve()


def usage(tokens=38042):
    return json.dumps({'model': 'frozen', 'choices': [{'finish_reason': 'stop'}],
        'usage': {'prompt_tokens': 2, 'completion_tokens': tokens-2, 'total_tokens': tokens}}).encode()


def test_duplicate_cumulative_usage_is_unknown_maximum_not_sum(tmp_path):
    body = b'data: ' + usage() + b'\n\ndata: ' + usage() + b'\n\ndata: [DONE]\n\n'
    with pytest.raises(budget.ProviderUsageError) as caught:
        budget.provider_usage(body, 'text/event-stream', 'frozen')
    assert caught.value.observed_tokens == 38042
    relay = budget.DeveloperBudgetRelay(tmp_path/'model.sock', model_id='frozen', max_tokens=100000, max_requests=10)
    try:
        relay._validate('POST', '/v1/chat/completions', b'{"model":"frozen"}')
        relay._observe('POST', '/v1/chat/completions', 200, 'text/event-stream', body, True)
        assert relay.evidence()['observed_tokens'] == 38042 and not relay.evidence()['usage_known']
    finally:
        relay.close()


@pytest.mark.parametrize('suffix', [b'', b'data: malformed\n\ndata: [DONE]\n\n'])
def test_missing_terminal_or_malformed_tail_cannot_promote_observed_usage(suffix):
    with pytest.raises(budget.ProviderUsageError) as caught:
        budget.provider_usage(b'data: '+usage()+b'\n\n'+suffix, 'text/event-stream', 'frozen')
    assert caught.value.observed_tokens == 38042


@pytest.mark.parametrize('mode', ['eof', 'truncated', 'root-interrupt', 'drain-timeout'])
def test_http10_response_socket_owned_through_client_disconnect_and_root_shutdown(monkeypatch, tmp_path, mode):
    # Normal budget connection retains all ownership callbacks; only its fixed
    # network address is replaced with this isolated static fixture server.
    release = threading.Event()
    tail_release = threading.Event()
    sent = threading.Event()
    calls = []
    class Provider(http.server.BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.0'
        def log_message(self, *_): pass
        def do_POST(self):
            calls.append(self.rfile.read(int(self.headers['Content-Length'])))
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.end_headers()
            self.wfile.write(b'data: '+usage()+b'\n\n')
            self.wfile.flush()
            sent.set()
            assert release.wait(timeout=10)
            if mode != 'root-interrupt':
                try:
                    # Force a downstream write after the usage reader closes.
                    self.wfile.write(b': padding\n'*10000)
                    if mode == 'eof':
                        self.wfile.write(b'data: [DONE]\n\n')
                    self.wfile.flush()
                    if mode == 'drain-timeout':
                        assert tail_release.wait(timeout=10)
                except (BrokenPipeError, ConnectionResetError):
                    pass
    upstream = http.server.HTTPServer(('127.0.0.1', 0), Provider)
    provider_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    provider_thread.start()
    original_connection = http.client.HTTPConnection
    monkeypatch.setattr(budget.http.client, 'HTTPConnection', lambda *args, **kwargs:
        original_connection('127.0.0.1', upstream.server_port, timeout=2))
    relay = budget.DeveloperBudgetRelay(tmp_path/'model.sock', model_id='frozen', max_tokens=100000, max_requests=10)
    client = UnixConnection(str(relay.path))
    response = None
    try:
        client.request('POST', '/v1/chat/completions', body=b'{"model":"frozen"}')
        response = client.getresponse()
        first = response.read1(4096)
        assert usage() in first and sent.wait(timeout=2)
        assert relay.evidence()['active_provider_sockets'] == 1
        if mode == 'root-interrupt':
            # will_close has removed HTTPConnection.sock; the retained response
            # socket must still interrupt this blocked read without fake EOF credit.
            relay.close()
            row = relay.evidence()['records'][-1]
            assert row['controller_interrupted'] and not row['provider_complete']
            assert not relay.evidence()['usage_known'] and relay.evidence()['observed_tokens'] == 38042
            assert relay.evidence()['cleanup_complete']
            assert relay.evidence()['active_handlers'] == relay.evidence()['active_provider_sockets'] == 0
        else:
            response.close()
            client.close()
            release.set()
            assert relay.server.wait_drained(7 if mode == 'drain-timeout' else 2)
            evidence = relay.evidence()
            row = evidence['records'][-1]
            assert row['provider_complete'] is (mode != 'drain-timeout')
            assert not row['downstream_delivery_complete']
            assert evidence['observed_tokens'] == 38042
            assert evidence['usage_known'] is (mode == 'eof')
            assert not row['controller_interrupted'] and evidence['model_requests'] == 1
        assert len(calls) == 1
    finally:
        release.set()
        tail_release.set()
        if response is not None:
            response.close()
        client.close()
        relay.close()
        upstream.shutdown()
        upstream.server_close()
        provider_thread.join(timeout=5)
