"""Retry transient GET transport failures without weakening Sonar evidence checks."""

from __future__ import annotations

import io
import ssl
from types import SimpleNamespace
from unittest.mock import Mock
from urllib.error import HTTPError, URLError

import pytest

from scripts.ci import sonar_quality_client as module
from scripts.ci.sonar_quality_client import ORIGIN, SonarClient


@pytest.fixture
def clock(monkeypatch):
    """A clock the client alone reads.

    `module.time` is the `time` module itself, so patching its attributes
    replaces `time.sleep` for everything running in the worker process,
    including a thread another test left behind. Rebinding the name inside the
    client's module keeps the mock to the calls this test makes.
    """

    now = [0.0]
    sleep = Mock(side_effect=lambda duration: now.__setitem__(0, now[0] + duration))
    monkeypatch.setattr(module, "time", SimpleNamespace(monotonic=lambda: now[0], sleep=sleep))
    return now, sleep


@pytest.mark.parametrize("failure", [ConnectionResetError(), URLError(ConnectionResetError()), TimeoutError()])
def test_transient_failure_retries_the_same_authenticated_get(clock, failure):
    client = SonarClient("test-only-token")
    client.opener = Mock()
    client.opener.open.side_effect = [failure, io.BytesIO(b'{"projectStatus":{"status":"ERROR"}}')]
    assert client.gate("analysis-id") == {"status": "ERROR"}
    first, second = client.opener.open.call_args_list
    assert first.args[0] is second.args[0]
    assert first.args[0].get_method() == "GET"
    assert first.args[0].full_url == ORIGIN + "/api/qualitygates/project_status?analysisId=analysis-id"
    assert first.args[0].get_header("Authorization") == "Bearer test-only-token"
    clock[1].assert_called_once_with(0.25)


def test_persistent_transport_failure_has_three_attempts_within_one_budget(clock):
    client = SonarClient("test-only-token", timeout=1.5)
    client.opener = Mock()
    client.opener.open.side_effect = URLError(ConnectionResetError())
    with pytest.raises(URLError):
        client.gate("analysis-id")
    assert client.opener.open.call_count == 3
    assert [call.kwargs["timeout"] for call in client.opener.open.call_args_list] == [1.5, 1.25, 0.5]
    assert [call.args[0] for call in clock[1].call_args_list] == [0.25, 0.75]


def test_reset_while_reading_closes_response_before_retry(clock):
    client = SonarClient("test-only-token")
    client.opener = Mock()
    response = Mock()
    response.__enter__ = Mock(return_value=response)
    response.__exit__ = Mock(return_value=False)
    response.read.side_effect = ConnectionResetError()

    def recover(*_args, **_kwargs):
        if client.opener.open.call_count == 1:
            return response
        response.__exit__.assert_called_once()
        return io.BytesIO(b'{"projectStatus":{"status":"OK"}}')

    client.opener.open.side_effect = recover
    assert client.gate("analysis-id") == {"status": "OK"}
    assert client.opener.open.call_count == 2


def test_deadline_prevents_an_extra_attempt(clock):
    client = SonarClient("test-only-token", timeout=0.1)
    client.opener = Mock()
    client.opener.open.side_effect = URLError(ConnectionResetError())
    with pytest.raises(TimeoutError, match="timed out"):
        client.gate("analysis-id")
    client.opener.open.assert_called_once()
    clock[1].assert_called_once_with(0.1)
    assert clock[0][0] == 0.1


def test_response_arriving_after_the_deadline_is_not_accepted(clock):
    client = SonarClient("test-only-token", timeout=1)
    client.opener = Mock()

    def late_response(*_args, **_kwargs):
        clock[0][0] = 2
        return io.BytesIO(b'{"projectStatus":{"status":"OK"}}')

    client.opener.open.side_effect = late_response
    with pytest.raises(TimeoutError, match="timed out"):
        client.gate("analysis-id")
    client.opener.open.assert_called_once()
    clock[1].assert_not_called()


@pytest.mark.parametrize(
    "failure",
    [HTTPError(ORIGIN, status, "Rejected", {}, None) for status in (302, 401, 403, 429, 500)]
    + [URLError(ssl.SSLCertVerificationError()), URLError("unknown failure")],
)
def test_http_and_tls_failures_are_not_retried(clock, failure):
    client = SonarClient("test-only-token")
    client.opener = Mock()
    client.opener.open.side_effect = failure
    with pytest.raises(type(failure)):
        client.gate("analysis-id")
    client.opener.open.assert_called_once()
    clock[1].assert_not_called()


def test_invalid_payload_is_not_retried_after_a_recovered_transport(clock):
    client = SonarClient("test-only-token")
    client.opener = Mock()
    client.opener.open.side_effect = [ConnectionResetError(), io.BytesIO(b"malformed")]
    with pytest.raises(ValueError):
        client.gate("analysis-id")
    assert client.opener.open.call_count == 2
