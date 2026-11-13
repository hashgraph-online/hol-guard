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
        "box.json",
        "calendar.json",
        "docs.json",
        "drive.json",
        "dropbox.json",
        "github.json",
        "gmail.json",
        "hubspot-mcp.json",
        "hubspot.json",
        "notion-mcp.json",
        "notion.json",
        "onedrive.json",
        "outlook.json",
        "salesforce-mcp.json",
        "sheets.json",
        "slack.json",
        "stripe-mcp.json",
        "stripe.json",
        "teams.json",
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
    ],
)
def test_the_schema_refuses_unsafe_packs(change) -> None:
    pack = copy.deepcopy(_slack())
    change(pack)
    assert list(_validator().iter_errors(pack)) != []
