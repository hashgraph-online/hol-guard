"""Schemas for browser driver profiles and provider integration manifests.

Both examples are the synthetic ones from the browser protection PRD (sections 5.2 and 6.2).
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
DRIVER_SCHEMA = ROOT / "contracts" / "browser-drivers" / "driver.v1.schema.json"
PROVIDER_SCHEMA = ROOT / "contracts" / "provider-integrations" / "provider.v1.schema.json"

DRIVER_EXAMPLE: dict[str, Any] = {
    "schemaVersion": "guard.browser-driver.v1",
    "id": "browser.example-pilot",
    "name": "Example Pilot browser tools",
    "publisher": {"name": "Example Org", "verified": False},
    "match": {
        "mcpServerNames": ["example-pilot"],
        "packages": ["@example-org/pilot-mcp"],
        "toolNamespaces": ["mcp__example-pilot__"],
        "harnessTools": [],
    },
    "profileMode": {
        "default": "unknown",
        "flags": {"isolated": ["--isolated"], "shared": ["--use-my-profile"], "remoteDebugging": ["--cdp-url"]},
    },
    "tools": [
        {"name": "open_page", "verb": "Navigate", "url": ["url"]},
        {"name": "press", "verb": "Click", "element": {"name": ["label", "ref"]}},
        {"name": "fill", "verb": "Type", "element": {"name": ["label"]}, "text": ["value"]},
        {"name": "run_js", "verb": "Evaluate", "script": ["code"]},
        {
            "name": "act",
            "discriminator": "action",
            "cases": {
                "left_click": {"verb": "Click"},
                "type": {"verb": "Type", "text": ["text"]},
                "screenshot": {"verb": "Screenshot"},
                "key": {"verb": "Key", "text": ["text"]},
            },
        },
        {"name": "send_protocol", "cdpPassthrough": {"method": ["method"], "params": ["params"]}},
    ],
    "volatileFields": ["tabId", "timeout"],
}

PROVIDER_EXAMPLE: dict[str, Any] = {
    "schemaVersion": "guard.provider-integration.v1",
    "id": "provider.exampleshield",
    "name": "ExampleShield",
    "publisher": {"name": "ExampleShield Inc.", "url": "https://exampleshield.example", "verified": False},
    "summary": "Checks the scripts on a page against your ExampleShield inventory.",
    "surfaces": ["browser"],
    "auth": {
        "kind": "api-key",
        "header": "x-provider-key",
        "keyFormat": {"minLength": 24, "maxLength": 128, "charset": "base64url"},
        "obtainUrl": "https://exampleshield.example/keys",
    },
    "hosts": ["api.exampleshield.example"],
    "capabilities": [
        {
            "id": "browser.origin-reputation",
            "request": {
                "method": "POST",
                "path": "/v1/guard/origin",
                "body": {"origin": {"fact": "target.origin"}},
            },
            "response": {
                "verdict": {
                    "pointer": "/verdict",
                    "map": {"clean": "ok", "suspicious": "caution", "malicious": "danger"},
                },
                "reasonCodes": {"pointer": "/reasons", "allow": ["phishing", "malware", "new_domain", "typosquat"]},
                "ttlSeconds": {"pointer": "/ttl", "min": 60, "max": 86400},
            },
            "shares": ["target.origin"],
        }
    ],
    "verify": {"method": "GET", "path": "/v1/guard/key"},
    "limits": {"timeoutMs": 1200, "maxResponseBytes": 16384, "maxRequestsPerMinute": 30},
    "privacyUrl": "https://exampleshield.example/privacy",
    "termsUrl": "https://exampleshield.example/terms",
}


def _validator(path: Path) -> Draft202012Validator:
    schema = json.loads(path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


DRIVER = _validator(DRIVER_SCHEMA)
PROVIDER = _validator(PROVIDER_SCHEMA)


def _facts_used(manifest: dict[str, Any]) -> list[set[str]]:
    """Facts each capability's request body reads. The native compiler applies the same rule."""
    return [
        {value["fact"] for value in capability["request"].get("body", {}).values()}
        for capability in manifest["capabilities"]
    ]


def shares_match_request(manifest: dict[str, Any]) -> bool:
    """`shares` must equal the facts the request uses, because the connect dialog renders from it."""
    return all(
        set(capability["shares"]) == used
        for capability, used in zip(manifest["capabilities"], _facts_used(manifest), strict=True)
    )


def provider_cross_field_errors(manifest: dict[str, Any]) -> list[str]:
    """Rules a JSON schema cannot express. The native compiler must apply each before admission."""
    errors = [] if shares_match_request(manifest) else ["shares differ from the facts the request uses"]
    ids = [capability["id"] for capability in manifest["capabilities"]]
    if len(ids) != len(set(ids)):
        errors.append("capability ids repeat")
    key_format = manifest["auth"].get("keyFormat")
    if key_format and key_format["minLength"] > key_format["maxLength"]:
        errors.append("keyFormat minLength exceeds maxLength")
    for capability in manifest["capabilities"]:
        ttl = capability["response"].get("ttlSeconds")
        if ttl and ttl["min"] > ttl["max"]:
            errors.append("ttlSeconds min exceeds max")
    return errors


def driver_cross_field_errors(profile: dict[str, Any], verified_publishers: frozenset[str]) -> list[str]:
    """Rules a JSON schema cannot express. ``verified_publishers`` is the maintainer-owned list."""
    errors = []
    names = [tool["name"] for tool in profile["tools"]]
    if len(names) != len(set(names)):
        errors.append("tool names repeat")
    if profile["publisher"]["verified"] and profile["publisher"]["name"] not in verified_publishers:
        errors.append("publisher claims verification it does not have")
    return errors


def _mutated(example: dict[str, Any], edit) -> dict[str, Any]:
    document = copy.deepcopy(example)
    edit(document)
    return document


def test_driver_example_is_valid() -> None:
    assert list(DRIVER.iter_errors(DRIVER_EXAMPLE)) == []
    assert driver_cross_field_errors(DRIVER_EXAMPLE, frozenset()) == []


def test_provider_example_is_valid() -> None:
    assert list(PROVIDER.iter_errors(PROVIDER_EXAMPLE)) == []
    assert provider_cross_field_errors(PROVIDER_EXAMPLE) == []


def test_first_party_profile_may_claim_a_reserved_name() -> None:
    document = _mutated(DRIVER_EXAMPLE, lambda d: d.update(id="browser.playwright-mcp"))
    document["publisher"]["verified"] = True
    document["publisher"]["url"] = "https://example.com/docs"
    document["match"]["mcpServerNames"] = ["playwright"]
    document["match"]["toolNamespaces"] = ["mcp__playwright__"]
    document["match"]["packages"] = ["@playwright/mcp"]
    assert list(DRIVER.iter_errors(document)) == []


def test_unverified_profile_may_use_names_that_only_contain_a_reserved_word() -> None:
    document = _mutated(
        DRIVER_EXAMPLE,
        lambda d: d["match"].update(toolNamespaces=["mcp__pilot-browser__"], packages=["@example-org/chrome-pilot"]),
    )
    assert list(DRIVER.iter_errors(document)) == []


@pytest.mark.parametrize(
    "edit",
    [
        pytest.param(lambda d: d["match"].update(mcpServerNames=["pilot.*"]), id="regex-in-server-name"),
        pytest.param(lambda d: d["match"].update(mcpServerNames=["^example-pilot$"]), id="anchored-regex"),
        pytest.param(lambda d: d["match"].update(toolNamespaces=["mcp__(pilot|other)__"]), id="regex-namespace"),
        pytest.param(lambda d: d["match"].update(packages=["@example-org/pilot-[a-z]+"]), id="regex-package"),
        pytest.param(lambda d: d["match"].update(mcpServerNames=["playwright"]), id="reserved-playwright"),
        pytest.param(lambda d: d["match"].update(mcpServerNames=["chrome"]), id="reserved-chrome"),
        pytest.param(lambda d: d["match"].update(harnessTools=["bash"]), id="reserved-shell"),
        pytest.param(lambda d: d["match"].update(harnessTools=["python3"]), id="reserved-interpreter"),
        pytest.param(lambda d: d["match"].update(toolNamespaces=["mcp__playwright__"]), id="reserved-namespace"),
        pytest.param(lambda d: d["match"].update(toolNamespaces=["chrome-devtools__"]), id="reserved-bare-namespace"),
        pytest.param(lambda d: d["match"].update(packages=["puppeteer"]), id="reserved-package"),
        pytest.param(lambda d: d["match"].update(packages=["@example-org/playwright"]), id="reserved-scoped-package"),
        pytest.param(lambda d: d["match"].update(packages=["@playwright/mcp"]), id="reserved-package-scope"),
        pytest.param(lambda d: d["match"].update(mcpServerNames=["chrome\n"]), id="reserved-name-trailing-newline"),
        pytest.param(lambda d: d["match"].update(mcpServerNames=["example-pilot\n"]), id="name-trailing-newline"),
        pytest.param(lambda d: d["publisher"].update(url="https://256.0.0.1/docs"), id="ip-publisher-url"),
        pytest.param(
            lambda d: d["match"].update(mcpServerNames=[], packages=[], toolNamespaces=[]), id="matches-nothing"
        ),
        pytest.param(lambda d: d["match"].update(mcpServerNames=["Example-Pilot"]), id="uppercase-name"),
        pytest.param(lambda d: d["tools"].append({"name": "peek", "verb": "Inspect"}), id="verb-outside-enum"),
        pytest.param(lambda d: d["tools"][0].update(grant="always"), id="unknown-tool-field"),
        pytest.param(lambda d: d.update(id="example-pilot"), id="id-outside-namespace"),
        pytest.param(lambda d: d.update(icon="https://cdn.example/icon.svg"), id="remote-icon"),
        pytest.param(lambda d: d.update(schemaVersion="guard.browser-driver.v2"), id="wrong-version"),
        pytest.param(lambda d: d.update(allowAll=True), id="unknown-top-level-field"),
    ],
)
def test_driver_schema_rejects(edit) -> None:
    assert not DRIVER.is_valid(_mutated(DRIVER_EXAMPLE, edit))


def _first_capability(document: dict[str, Any]) -> dict[str, Any]:
    return document["capabilities"][0]


@pytest.mark.parametrize(
    "edit",
    [
        pytest.param(lambda d: d.update(hosts=["*.exampleshield.example"]), id="wildcard-host"),
        pytest.param(lambda d: d.update(hosts=["203.0.113.7"]), id="ipv4-host"),
        pytest.param(lambda d: d.update(hosts=["[2001:db8::1]"]), id="ipv6-host"),
        pytest.param(lambda d: d.update(hosts=["api.exampleshield.example:8443"]), id="non-443-port"),
        pytest.param(lambda d: d.update(hosts=["localhost"]), id="loopback-name"),
        pytest.param(lambda d: d.update(hosts=["api.exampleshield.localhost"]), id="loopback-suffix"),
        pytest.param(lambda d: d.update(hosts=["https://api.exampleshield.example"]), id="host-with-scheme"),
        pytest.param(
            lambda d: _first_capability(d)["request"].update(path="/v1/guard/origin?" + "k=v"),
            id="query-credential-in-path",
        ),
        pytest.param(lambda d: d["verify"].update(path="/v1/guard/key?" + "k=v"), id="query-credential-verify"),
        pytest.param(lambda d: _first_capability(d)["request"].update(path="//status"), id="authority-path"),
        pytest.param(lambda d: _first_capability(d)["request"].update(path="/v1/guard/../admin"), id="dot-dot-segment"),
        pytest.param(lambda d: _first_capability(d)["request"].update(path="/v1/./guard"), id="dot-segment"),
        pytest.param(lambda d: _first_capability(d)["request"].update(path="/v1//guard"), id="empty-segment"),
        pytest.param(lambda d: d["verify"].update(path="/v1/guard/.."), id="trailing-dot-dot"),
        pytest.param(lambda d: d["verify"].update(path="//"), id="authority-verify-path"),
        pytest.param(lambda d: d["verify"].update(path="/status\n"), id="path-trailing-newline"),
        pytest.param(lambda d: d.update(summary="Checks scripts.\n"), id="summary-trailing-newline"),
        pytest.param(lambda d: d.update(hosts=["api.exampleshield.example\n"]), id="host-trailing-newline"),
        pytest.param(lambda d: d.update(privacyUrl="https://256.0.0.1/privacy"), id="ip-privacy-url"),
        pytest.param(lambda d: d["auth"].update({"in": "query"}), id="query-credential-auth"),
        pytest.param(lambda d: d["auth"].update(header="cookie"), id="cookie-header"),
        pytest.param(lambda d: d["auth"].update(kind="oauth"), id="auth-kind-outside-list"),
        pytest.param(
            lambda d: _first_capability(d)["request"]["body"].update(page={"template": "{{url}}"}),
            id="templated-body",
        ),
        pytest.param(
            lambda d: _first_capability(d)["request"]["body"].update(page={"fact": "page.html"}),
            id="fact-outside-closed-set",
        ),
        pytest.param(lambda d: _first_capability(d).update(id="browser.allow"), id="capability-outside-list"),
        pytest.param(
            lambda d: _first_capability(d)["response"]["verdict"]["map"].update(trusted="allow"),
            id="allow-verdict",
        ),
        pytest.param(lambda d: d.update(icon="https://exampleshield.example/icon.png"), id="remote-icon"),
        pytest.param(lambda d: d.update(icon="data:image/png;base64,AAAA"), id="inline-icon"),
        pytest.param(lambda d: d["limits"].update(timeoutMs=2001), id="timeout-over-cap"),
        pytest.param(lambda d: d["limits"].update(maxResponseBytes=65537), id="response-over-cap"),
        pytest.param(lambda d: d["limits"].update(maxRequestsPerMinute=61), id="rate-over-cap"),
        pytest.param(lambda d: d.update(privacyUrl="http://exampleshield.example/privacy"), id="plain-http-url"),
        pytest.param(lambda d: d.update(summary="<b>Trusted</b> by everyone"), id="markup-in-summary"),
        pytest.param(lambda d: d.update(id="exampleshield"), id="id-outside-namespace"),
        pytest.param(lambda d: d.update(surfaces=["shell"]), id="surface-outside-list"),
        pytest.param(lambda d: d.update(effect="enforce"), id="manifest-sets-effect"),
    ],
)
def test_provider_schema_rejects(edit) -> None:
    assert not PROVIDER.is_valid(_mutated(PROVIDER_EXAMPLE, edit))


def test_provider_icon_accepts_react_icon_names_and_none() -> None:
    for icon in ("FiShield", "none"):
        assert PROVIDER.is_valid(_mutated(PROVIDER_EXAMPLE, lambda d, icon=icon: d.update(icon=icon)))


def test_provider_accepts_root_and_plain_paths_and_urls() -> None:
    document = _mutated(PROVIDER_EXAMPLE, lambda d: d["verify"].update(path="/"))
    document["termsUrl"] = "https://example.com/terms"
    assert list(PROVIDER.iter_errors(document)) == []


def test_signed_enrollment_is_a_closed_shape() -> None:
    enrolled = _mutated(PROVIDER_EXAMPLE, lambda d: d.update(auth={"kind": "signed-enrollment"}))
    assert PROVIDER.is_valid(enrolled)
    enrolled["auth"]["header"] = "x-provider-key"
    assert not PROVIDER.is_valid(enrolled)


@pytest.mark.parametrize(
    "shares",
    [
        pytest.param(["target.origin", "target.path_prefix"], id="shares-more-than-used"),
        pytest.param(["target.site_group"], id="shares-different-fact"),
    ],
)
def test_shares_must_equal_the_facts_the_request_uses(shares: list[str]) -> None:
    document = _mutated(PROVIDER_EXAMPLE, lambda d: _first_capability(d).update(shares=shares))
    # The schema cannot compare two fields, so the compiler rule is checked separately.
    assert PROVIDER.is_valid(document)
    assert not shares_match_request(document)


def test_shares_rule_catches_an_unlisted_body_fact() -> None:
    document = _mutated(
        PROVIDER_EXAMPLE,
        lambda d: _first_capability(d)["request"]["body"].update(page={"fact": "page.script_hashes"}),
    )
    assert PROVIDER.is_valid(document)
    assert not shares_match_request(document)


def test_paths_may_contain_dots_inside_a_segment() -> None:
    document = _mutated(PROVIDER_EXAMPLE, lambda d: d["verify"].update(path="/v1.2/guard/.well-known/key"))
    assert list(PROVIDER.iter_errors(document)) == []


def test_a_self_declared_verified_publisher_is_not_trusted() -> None:
    document = _mutated(DRIVER_EXAMPLE, lambda d: d["match"].update(mcpServerNames=["playwright"]))
    document["publisher"]["verified"] = True
    # The schema accepts the shape; only the maintainer-owned list can make the claim true.
    assert DRIVER.is_valid(document)
    assert driver_cross_field_errors(document, frozenset()) == ["publisher claims verification it does not have"]
    assert driver_cross_field_errors(document, frozenset({"Example Org"})) == []


@pytest.mark.parametrize(
    ("edit", "error"),
    [
        pytest.param(
            lambda d: d["capabilities"].append(copy.deepcopy(d["capabilities"][0])),
            "capability ids repeat",
            id="duplicate-capability",
        ),
        pytest.param(
            lambda d: d["auth"]["keyFormat"].update(minLength=128, maxLength=24),
            "keyFormat minLength exceeds maxLength",
            id="inverted-key-length",
        ),
        pytest.param(
            lambda d: _first_capability(d)["response"]["ttlSeconds"].update(min=86400, max=60),
            "ttlSeconds min exceeds max",
            id="inverted-ttl",
        ),
    ],
)
def test_provider_cross_field_rules(edit, error: str) -> None:
    document = _mutated(PROVIDER_EXAMPLE, edit)
    assert PROVIDER.is_valid(document)
    assert provider_cross_field_errors(document) == [error]


def test_driver_tool_names_must_be_unique() -> None:
    document = _mutated(DRIVER_EXAMPLE, lambda d: d["tools"].append({"name": "press", "verb": "Type"}))
    assert DRIVER.is_valid(document)
    assert driver_cross_field_errors(document, frozenset()) == ["tool names repeat"]
