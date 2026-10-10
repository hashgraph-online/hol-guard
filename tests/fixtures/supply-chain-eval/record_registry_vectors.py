"""Record registry range-resolution vectors from the Python resolver.

Provenance tool, not part of the test suite. It must run against a checkout
that still contains the Python resolver
(``supply_chain_package_services._registry_resolved_target_version`` at commit
7a712222b1), for example::

    PYTHONPATH=<base-worktree>/src python record_registry_vectors.py registry-cases.v1.json

Each case runs the real Python resolver with only the HTTP exchange replaced
by a recorded upstream response, and captures the URL, headers and timeouts it
requested together with the version it resolved. The vectors are
language-neutral; the Rust resident replays every case against its own
resolver and a fake registry, so no verdict is ever derived from Rust output.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from cloud_vector_cases import BASE_COMMIT

from codex_plugin_scanner.guard.runtime import supply_chain_package_services as services

_OK = "payload"
_ERRORS = {"os_error": OSError("boom"), "value_error": ValueError("bad"), "runtime_error": RuntimeError("bad")}

NPM_VERSIONS = {"versions": {"1.0.0": {}, "1.2.3": {}, "1.10.0": {}, "2.0.0": {}, "2.1.0-beta.1": {}}}
PYPI_RELEASES = {
    "releases": {
        "1.0.0": [],
        "1.2.3": [],
        "1.4.0": [],
        "1.9.9": [],
        "2.0.0": [],
        "2.1.0rc1": [],
        "0.2.5": [],
        "0.0.3": [],
        "not-a-version": [],
    }
}


def _target(**fields: object) -> dict[str, object]:
    return dict(fields)


def _case(name: str, target: dict[str, object], requested_range: str, response: dict[str, object]) -> dict[str, object]:
    return {"name": name, "target": target, "range": requested_range, "response": response}


def case_specs() -> list[dict[str, object]]:
    npm = {"kind": _OK, "payload": NPM_VERSIONS}
    pypi = {"kind": _OK, "payload": PYPI_RELEASES}
    return [
        _case("npm caret", _target(name="left-pad", ecosystem="npm"), "^1.0.0", npm),
        _case("npm latest", _target(name="left-pad", ecosystem="npm"), "latest", npm),
        _case("npm default ecosystem", _target(name="left-pad"), "~1.2.0", npm),
        _case("npm scoped namespace", _target(name="codex", namespace="@openai", ecosystem="npm"), "latest", npm),
        _case("npm name stripped", _target(name="  left-pad  ", ecosystem="npm"), "^2.0.0", npm),
        _case("npm special characters", _target(name="a b+c", namespace="@sc ope", ecosystem="npm"), "^1.0.0", npm),
        _case("npm no matching version", _target(name="left-pad", ecosystem="npm"), "^9.0.0", npm),
        _case(
            "npm versions not an object",
            _target(name="left-pad"),
            "^1.0.0",
            {"kind": _OK, "payload": {"versions": ["1.0.0"]}},
        ),
        _case("npm versions empty", _target(name="left-pad"), "^1.0.0", {"kind": _OK, "payload": {"versions": {}}}),
        _case("npm versions absent", _target(name="left-pad"), "^1.0.0", {"kind": _OK, "payload": {}}),
        _case("npm os error", _target(name="left-pad"), "^1.0.0", {"kind": "error", "error": "os_error"}),
        _case("npm value error", _target(name="left-pad"), "^1.0.0", {"kind": "error", "error": "value_error"}),
        _case("npm runtime error", _target(name="left-pad"), "^1.0.0", {"kind": "error", "error": "runtime_error"}),
        _case(
            "source url skips registry", _target(name="left-pad", source_url="https://example.com/x.tgz"), "^1.0.0", npm
        ),
        _case("blank source url is ignored", _target(name="left-pad", source_url="   "), "^1.0.0", npm),
        _case("missing name", _target(ecosystem="npm"), "^1.0.0", npm),
        _case("blank name", _target(name="  ", ecosystem="npm"), "^1.0.0", npm),
        _case("non string name", _target(name=7, ecosystem="npm"), "^1.0.0", npm),
        _case("unsupported ecosystem", _target(name="serde", ecosystem="cargo"), "^1.0.0", npm),
        _case("ecosystem is case sensitive", _target(name="left-pad", ecosystem="NPM"), "^1.0.0", npm),
        _case("non string ecosystem defaults to npm", _target(name="left-pad", ecosystem=5), "^1.0.0", npm),
        _case("pypi range", _target(name="requests", ecosystem="pypi"), ">=1.0,<2", pypi),
        _case("pypi name normalized", _target(name="Foo_Bar.Baz", ecosystem="pypi"), ">=1.0,<2", pypi),
        _case("pypi caret major", _target(name="requests", ecosystem="pypi"), "^1.2.3", pypi),
        _case("pypi caret zero minor", _target(name="requests", ecosystem="pypi"), "^0.2.3", pypi),
        _case("pypi caret zero patch", _target(name="requests", ecosystem="pypi"), "^0.0.3", pypi),
        _case("pypi caret single segment", _target(name="requests", ecosystem="pypi"), "^1", pypi),
        _case("pypi tilde minor", _target(name="requests", ecosystem="pypi"), "~1.2.3", pypi),
        _case("pypi tilde single segment", _target(name="requests", ecosystem="pypi"), "~1", pypi),
        _case("pypi compatible release", _target(name="requests", ecosystem="pypi"), "~=1.4", pypi),
        _case("pypi caret invalid base", _target(name="requests", ecosystem="pypi"), "^abc", pypi),
        _case("pypi caret empty base", _target(name="requests", ecosystem="pypi"), "^", pypi),
        _case("pypi tilde padded base", _target(name="requests", ecosystem="pypi"), "~ 1.2.3", pypi),
        _case("pypi invalid specifier", _target(name="requests", ecosystem="pypi"), "garbage", pypi),
        _case("pypi blank range", _target(name="requests", ecosystem="pypi"), "   ", pypi),
        _case("pypi exact match", _target(name="requests", ecosystem="pypi"), "==2.0.0", pypi),
        _case("pypi no matching release", _target(name="requests", ecosystem="pypi"), ">=3", pypi),
        _case("pypi prerelease allowed when pinned", _target(name="requests", ecosystem="pypi"), ">=2.1.0rc1", pypi),
        _case(
            "pypi releases not an object",
            _target(name="requests", ecosystem="pypi"),
            ">=1",
            {"kind": _OK, "payload": {"releases": []}},
        ),
        _case("pypi releases absent", _target(name="requests", ecosystem="pypi"), ">=1", {"kind": _OK, "payload": {}}),
        _case(
            "pypi os error", _target(name="requests", ecosystem="pypi"), ">=1", {"kind": "error", "error": "os_error"}
        ),
        _case("pypi namespace joined", _target(name="pkg", namespace="org", ecosystem="pypi"), ">=1", pypi),
    ]


def record(spec: dict[str, object]) -> dict[str, object]:
    seen: list[dict[str, object]] = []
    response = spec["response"]
    assert isinstance(response, dict)

    def fake_urlopen(*, request: object, timeout_seconds: int, retry_timeout_seconds: int) -> dict[str, object]:
        headers = {key.lower(): value for key, value in request.header_items()}  # type: ignore[attr-defined]
        seen.append(
            {
                "url": request.full_url,  # type: ignore[attr-defined]
                "accept": headers.get("accept"),
                "user_agent": headers.get("user-agent"),
                "timeout_seconds": timeout_seconds,
                "retry_timeout_seconds": retry_timeout_seconds,
            }
        )
        if response["kind"] == "error":
            raise _ERRORS[str(response["error"])]
        payload = response["payload"]
        if not isinstance(payload, dict):
            raise RuntimeError("Guard Cloud sync returned an invalid response payload.")
        return payload

    original = services._urlopen_json_with_timeout_retry
    services._urlopen_json_with_timeout_retry = fake_urlopen  # type: ignore[assignment]
    try:
        target = spec["target"]
        assert isinstance(target, dict)
        resolved = services._registry_resolved_target_version(target=target, requested_range=str(spec["range"]))
    finally:
        services._urlopen_json_with_timeout_retry = original  # type: ignore[assignment]
    return {**spec, "requests": seen, "expect": resolved}


def main() -> None:
    out = Path(sys.argv[1])
    cases = [record(spec) for spec in case_specs()]
    out.write_text(
        json.dumps(
            {
                "schema": "guard-supply-chain-registry-vectors.v1",
                "description": (
                    "Registry range-resolution vectors recorded from the Python resolver at commit "
                    f"{BASE_COMMIT} by record_registry_vectors.py. requests is what the resolver asked the "
                    "registry for; expect is the version it resolved (null is unresolved)."
                ),
                "recorded_from_commit": BASE_COMMIT,
                "cases": cases,
            },
            indent=1,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
