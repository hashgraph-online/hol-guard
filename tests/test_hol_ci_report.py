from __future__ import annotations

import hashlib
import io
import json
from http.client import BadStatusLine, IncompleteRead
from urllib.error import HTTPError, URLError

import pytest

from codex_plugin_scanner.hol_ci_report import (
    HOL_CI_REPORT_URL,
    build_ci_report_body,
    ci_report_audience,
    report_folder,
    send_ci_report,
)

SHA = "b" * 40


def _body(**overrides: object) -> str:
    values: dict[str, object] = {
        "repository": "acme/tool",
        "commit_sha": SHA,
        "workflow_run_id": "123",
        "scanner_version": "3.58.0",
        "plugin_dir": "./plugins/acme/",
        "score": 92,
        "grade": "A",
        "max_severity": "medium",
        "severity_counts": {"critical": 0, "high": 0, "medium": 2, "low": 1, "info": 4},
    }
    values.update(overrides)
    return build_ci_report_body(**values)  # type: ignore[arg-type]


class _Response(io.BytesIO):
    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


class _Opener:
    def __init__(self, *responses: object) -> None:
        self.responses = list(responses)
        self.requests: list[object] = []

    def __call__(self, request: object, timeout: int) -> _Response:
        self.requests.append(request)
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return _Response(json.dumps(response).encode())


def test_body_holds_only_the_summary() -> None:
    payload = json.loads(_body())
    assert payload == {
        "schema": "hol.plugin-ci-report.v1",
        "repository": "acme/tool",
        "commit_sha": SHA,
        "workflow_run_id": "123",
        "scanner_version": "3.58.0",
        "plugin_path": "plugins/acme",
        "score": 92,
        "grade": "A",
        "max_severity": "medium",
        "findings": {"critical": 0, "high": 0, "medium": 2, "low": 1, "info": 4},
    }


@pytest.mark.parametrize(
    ("plugin_dir", "expected"),
    [
        (".", ""),
        ("", ""),
        ("plugins/a", "plugins/a"),
        ("plugins\\a", "plugins/a"),
        ("../x", ""),
        ("/abs", ""),
        ("a/$(x)", ""),
        ("\\\\server\\share\\plugin", ""),
        ("\\plugin", ""),
        ("C:\\work\\plugin", ""),
        ("c:plugin", ""),
    ],
)
def test_report_folder(plugin_dir: str, expected: str) -> None:
    assert report_folder(plugin_dir) == expected


def test_send_binds_the_token_audience_to_the_body() -> None:
    body = _body()
    opener = _Opener({"value": "oidc-token"}, {"listings": 1})
    status = send_ci_report(
        body, request_url="https://token.example/req?api-version=2", request_token="rt", opener=opener
    )
    assert status == "sent (1 HOL listing(s) updated)"
    token_request, post = opener.requests
    digest = hashlib.sha256(body.encode()).hexdigest()
    assert token_request.full_url.endswith(f"&audience=hol-plugin-ci-report%3A{digest}")  # type: ignore[attr-defined]
    assert ci_report_audience(body) == f"hol-plugin-ci-report:{digest}"
    assert post.full_url == HOL_CI_REPORT_URL  # type: ignore[attr-defined]
    assert post.data == body.encode()  # type: ignore[attr-defined]
    assert post.get_header("Authorization") == "Bearer oidc-token"  # type: ignore[attr-defined]


def test_send_skips_without_id_token_permission() -> None:
    opener = _Opener()
    assert "id-token: write" in send_ci_report(_body(), request_url="", request_token="", opener=opener)
    assert opener.requests == []


@pytest.mark.parametrize(
    "failure",
    [
        HTTPError(HOL_CI_REPORT_URL, 429, "slow", {}, None),  # type: ignore[arg-type]
        URLError("offline"),
        TimeoutError(),
        IncompleteRead(b"{"),
        BadStatusLine("garbled"),
    ],
)
def test_send_never_raises(failure: Exception) -> None:
    opener = _Opener({"value": "oidc-token"}, failure)
    assert send_ci_report(
        _body(), request_url="https://token.example/req", request_token="rt", opener=opener
    ).startswith("not sent")


def test_send_handles_a_missing_token() -> None:
    opener = _Opener({"count": 1})
    assert send_ci_report(_body(), request_url="https://token.example/req", request_token="rt", opener=opener) == (
        "not sent: RuntimeError"
    )
