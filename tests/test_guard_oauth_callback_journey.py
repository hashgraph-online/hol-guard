"""Real loopback callback terminal-state coverage for canonical enrollment."""
from __future__ import annotations

import concurrent.futures
import threading
import urllib.error
import urllib.parse
import urllib.request

import pytest

from codex_plugin_scanner.guard.cli import oauth_loopback_callback
from codex_plugin_scanner.guard.cli.connect_flow import start_guard_loopback_callback_listener


def request(session, **params):
    url = session.redirect_uri + '?' + urllib.parse.urlencode(params, doseq=True)
    try:
        with urllib.request.urlopen(url, timeout=2) as response:
            return response.status, response.read().decode()
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode()


@pytest.fixture
def session():
    listener = start_guard_loopback_callback_listener(expected_state='synthetic-state')
    try:
        yield listener
    finally:
        listener.close()


@pytest.mark.parametrize('later', [{'code': 'replacement'}, {'error': 'access_denied'}])
def test_first_success_is_immutable(session, later):
    assert request(session, state=session.state, code='original')[0] == 200
    assert request(session, state=session.state, **later)[0] == 409
    assert session.wait_for_callback(1).code == 'original'


def test_first_denial_cannot_be_replaced_by_success(session):
    assert request(session, state=session.state, error='access_denied')[0] == 200
    assert request(session, state=session.state, code='late')[0] == 409
    with pytest.raises(RuntimeError, match='denied'):
        session.wait_for_callback(1)


def test_expired_wait_rejects_a_late_callback(session):
    with pytest.raises(TimeoutError):
        session.wait_for_callback(0.01)
    assert request(session, state=session.state, code='late')[0] == 410
    with pytest.raises(TimeoutError):
        session.wait_for_callback(1)


def test_wrong_state_and_missing_code_do_not_consume_a_session(session):
    assert request(session, state='old-session', code='stale')[0] == 400
    assert request(session, state=session.state)[0] == 400
    assert request(session, state=session.state, code='current')[0] == 200
    assert session.wait_for_callback(1).code == 'current'


@pytest.mark.parametrize('params', [
    {'state': ['', 'synthetic-state'], 'code': 'valid'},
    {'state': 'synthetic-state', 'code': ['', 'valid']},
    {'state': 'synthetic-state', 'error': ['', 'access_denied']},
])
def test_blank_duplicate_parameters_are_ambiguous_and_do_not_consume_session(session, params):
    assert request(session, **params)[0] == 400
    assert request(session, state=session.state, code='unambiguous')[0] == 200
    assert session.wait_for_callback(1).code == 'unambiguous'


def test_callback_cannot_win_after_wait_deadline_before_waiter_reacquires_lock(session, monkeypatch):
    now = [10.0]
    monkeypatch.setattr(oauth_loopback_callback, 'monotonic', lambda: now[0], raising=False)
    wait_entered = threading.Event()
    resume_waiter = threading.Event()

    def suspended_wait(_timeout):
        wait_entered.set()
        assert resume_waiter.wait(2)
        return False

    monkeypatch.setattr(session._terminal._ready, 'wait', suspended_wait)
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        waiting = executor.submit(session.wait_for_callback, 1)
        try:
            assert wait_entered.wait(2)
            now[0] = 11.0
            assert request(session, state=session.state, code='too-late')[0] == 410
        finally:
            resume_waiter.set()
        with pytest.raises(TimeoutError):
            waiting.result(timeout=2)


def test_callback_received_before_wait_keeps_its_result(session, monkeypatch):
    now = [10.0]
    monkeypatch.setattr(oauth_loopback_callback, 'monotonic', lambda: now[0], raising=False)
    assert request(session, state=session.state, code='already-received')[0] == 200
    now[0] = 100.0
    assert session.wait_for_callback(0).code == 'already-received'


def test_concurrent_valid_callbacks_have_one_terminal_winner(session):
    def send(code):
        return code, request(session, state=session.state, code=code)[0]
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(send, ['first', 'second']))
    assert sorted(status for _, status in results) == [200, 409]
    winner = next(code for code, status in results if status == 200)
    assert session.wait_for_callback(1).code == winner


def test_closing_a_session_cancels_its_pending_wait():
    listener = start_guard_loopback_callback_listener(expected_state='cancelled-state')
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        waiting = executor.submit(listener.wait_for_callback, 20)
        listener.close()
        with pytest.raises(RuntimeError, match='closed'):
            waiting.result(timeout=2)
