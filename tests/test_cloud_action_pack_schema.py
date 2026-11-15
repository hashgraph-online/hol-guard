"""The cloud action pack schema accepts the shipped packs and refuses unsafe shapes."""

import copy
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "contracts" / "extensions" / "cloud-action-pack.v1.schema.json"
PACKS = sorted((ROOT / "contributions" / "cloud-actions").glob("*.json"))


def _validator() -> Draft202012Validator:
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def _slack() -> dict:
    return json.loads((ROOT / "contributions" / "cloud-actions" / "slack.json").read_text(encoding="utf-8"))


def _post(pack: dict) -> dict:
    return next(action for action in pack["actions"] if action["actionId"] == "slack.chat.post_message")


def test_the_shipped_packs_match_the_schema() -> None:
    assert [path.name for path in PACKS] == [
        "airtable.json",
        "asana.json",
        "atlassian.json",
        "azure-devops-mcp.json",
        "bigquery.json",
        "box.json",
        "buildkite-mcp.json",
        "calendar.json",
        "calendly.json",
        "clickup.json",
        "cloudflare.json",
        "discord.json",
        "docs.json",
        "drive.json",
        "dropbox.json",
        "figma.json",
        "github-mcp.json",
        "github.json",
        "gitlab-mcp.json",
        "gmail.json",
        "hubspot-mcp.json",
        "hubspot.json",
        "huggingface-mcp.json",
        "intercom-mcp.json",
        "intercom.json",
        "linear.json",
        "mailchimp.json",
        "monday-mcp.json",
        "monday.json",
        "neon-mcp.json",
        "notion-mcp.json",
        "notion.json",
        "onedrive.json",
        "outlook.json",
        "pagerduty-mcp.json",
        "paypal-mcp.json",
        "postman-mcp.json",
        "quickbooks.json",
        "render-mcp.json",
        "salesforce-mcp.json",
        "sendgrid.json",
        "sentry-mcp.json",
        "sheets.json",
        "slack.json",
        "stripe-mcp.json",
        "stripe.json",
        "supabase-mcp.json",
        "teams.json",
        "trello.json",
        "vercel-mcp.json",
        "webflow-mcp.json",
        "zendesk.json",
        "zoom.json",
    ]
    validator = _validator()
    for path in PACKS:
        errors = list(validator.iter_errors(json.loads(path.read_text(encoding="utf-8"))))
        assert errors == [], (path.name, [error.message for error in errors])


def _set_header(name: str):
    def change(pack: dict) -> None:
        _post(pack)["executor"]["request"]["headers"] = [{"name": name, "value": "x"}]

    return change


def _unknown_field(pack: dict) -> None:
    _post(pack)["script"] = "fetch()"


def _expression(pack: dict) -> None:
    _post(pack)["executor"]["request"]["body"] = {"eval": "args.text"}


def _http_host(pack: dict) -> None:
    pack["hosts"] = ["https://slack.com"]


def _unanchored(pack: dict) -> None:
    _post(pack)["arguments"]["channel"]["pattern"] = "C[A-Z0-9]+"


def _url_executor(pack: dict) -> None:
    _post(pack)["executor"] = {"kind": "fetch", "url": "https://example.com"}


def _both_links(pack: dict) -> None:
    _post(pack)["link"] = {"tool": "a", "permissionId": "b"}


def _transports(transports: object):
    def change(pack: dict) -> None:
        pack["transports"] = transports

    return change


def _transports_without_sign_in(pack: dict) -> None:
    pack["auth"] = {"mode": "none", "scopes": []}
    pack["transports"] = {"partner": [{"partner": "composio", "toolkit": "slack"}]}


def _transports_with_broker_action(pack: dict) -> None:
    _post(pack)["executor"] = {"kind": "broker"}
    pack["transports"] = {"partner": [{"partner": "composio", "toolkit": "slack"}]}


_TENANT = {"title": "Workspace subdomain", "pattern": "^[a-z0-9-]{1,30}$", "maxLength": 30}


def _connection(connection: object):
    def change(pack: dict) -> None:
        pack["connection"] = connection

    return change


def _connection_without_sign_in(pack: dict) -> None:
    pack["auth"] = {"mode": "none", "scopes": []}
    pack["connection"] = {"values": {"tenant": _TENANT}}


def _connection_with_broker_action(pack: dict) -> None:
    _post(pack)["executor"] = {"kind": "broker"}
    pack["connection"] = {"values": {"tenant": _TENANT}}


def _templated_host(host: str):
    def change(pack: dict) -> None:
        pack["connection"] = {"values": {"tenant": _TENANT}}
        pack["hosts"] = [host]

    return change


def _form_value(value: dict):
    def change(pack: dict) -> None:
        _post(pack)["executor"]["request"]["body"] = {"form": [{"name": "channel", "value": value}]}

    return change


@pytest.mark.parametrize(
    "change",
    [
        _set_header("authorization"),
        _set_header("x-api-key"),
        _set_header("cookie"),
        _set_header("Accept"),
        _set_header("x-forwarded-for"),
        _set_header("host"),
        _unknown_field,
        _expression,
        _http_host,
        _unanchored,
        _url_executor,
        _both_links,
        _form_value({"object": []}),
        _form_value({"const": {}}),
        _form_value({"const": 1.5}),
        _transports({"partner": [{"partner": "nango", "toolkit": "slack"}]}),
        _transports({"partner": [{"partner": "composio", "toolkit": "Slack"}]}),
        _transports({"partner": [{"partner": "composio", "toolkit": "slack", "url": "https://x.test"}]}),
        _transports({"partner": []}),
        _transports({"partner": [{"partner": "composio", "toolkit": "slack\n"}]}),
        _transports(
            {"partner": [{"partner": "composio", "toolkit": "slack"}, {"partner": "composio", "toolkit": "slackbot"}]}
        ),
        _transports_without_sign_in,
        _transports_with_broker_action,
        _connection(None),
        _connection({"values": {}}),
        _connection({"values": {f"value_{index}": _TENANT for index in range(5)}}),
        _connection({"values": {"tenant": {**_TENANT, "pattern": "[a-z]+"}}}),
        _connection({"values": {"tenant": {**_TENANT, "maxLength": 0}}}),
        _connection({"values": {"tenant": {**_TENANT, "maxLength": 129}}}),
        _connection({"values": {"Tenant": _TENANT}}),
        _connection({"values": {"tenant": {**_TENANT, "default": "acme"}}}),
        _connection({"values": {"tenant": _TENANT}, "region": "eu"}),
        _connection_without_sign_in,
        _connection_with_broker_action,
        _templated_host("{tenant}.slack.com/x"),
        _templated_host("mail.{tenant}.slack.com"),
        _templated_host("{Tenant}.slack.com"),
    ],
    ids=[
        "authorization-header",
        "api-key-header",
        "cookie-header",
        "uppercase-header",
        "forwarded-header",
        "host-header",
        "unknown-field",
        "expression-body",
        "scheme-in-host",
        "unanchored-pattern",
        "unknown-executor",
        "two-links",
        "nested-form-value",
        "object-form-constant",
        "fractional-form-constant",
        "unknown-partner",
        "uppercase-toolkit",
        "transport-url",
        "empty-transports",
        "toolkit-trailing-newline",
        "repeated-partner",
        "transports-without-sign-in",
        "transports-with-broker-action",
        "null-connection",
        "empty-connection",
        "five-connection-values",
        "unanchored-connection-pattern",
        "zero-connection-length",
        "long-connection-length",
        "uppercase-connection-name",
        "connection-default",
        "connection-extra-key",
        "connection-without-sign-in",
        "connection-with-broker-action",
        "templated-host-with-path",
        "templated-inner-label",
        "uppercase-template-name",
    ],
)
def test_the_schema_refuses_unsafe_packs(change) -> None:
    pack = copy.deepcopy(_slack())
    change(pack)
    assert list(_validator().iter_errors(pack)) != []


def test_the_schema_accepts_a_partner_transport() -> None:
    pack = copy.deepcopy(_slack())
    pack["transports"] = {"partner": [{"partner": "composio", "toolkit": "slack"}]}
    assert list(_validator().iter_errors(pack)) == []


def test_the_schema_accepts_connection_values_and_a_templated_host() -> None:
    pack = copy.deepcopy(_slack())
    _templated_host("{tenant}.slack.com")(pack)
    for action in pack["actions"]:
        if action["executor"]["kind"] == "declarative-http":
            action["executor"]["request"]["host"] = "{tenant}.slack.com"
    _post(pack)["fixtures"][0]["connection"] = {"tenant": "acme"}
    assert list(_validator().iter_errors(pack)) == []
