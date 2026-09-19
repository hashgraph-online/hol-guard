"""Only tracked repository locations may leave the SARIF diagnostic boundary."""

import json
from typing import Any

import pytest

from scripts.ci.codeql_result_locations import public_locations


def result(uri: object = "src/public.py", line: object = 7, rule: object = "py/example") -> dict[str, Any]:
    return {
        "runs": [
            {
                "results": [
                    {
                        "ruleId": rule,
                        "message": {"text": "withheld-message"},
                        "codeFlows": [{"secret": "withheld-flow"}],
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": uri},
                                    "region": {"startLine": line, "snippet": {"text": "withheld-source"}},
                                }
                            }
                        ],
                    }
                ]
            }
        ]
    }


def test_only_exact_allowlisted_fields_are_emitted() -> None:
    output = public_locations(result(), {"src/public.py"})
    assert output == [{"rule_id": "py/example", "path": "src/public.py", "start_line": 7}]
    assert "withheld" not in json.dumps(output)


@pytest.mark.parametrize(
    "uri",
    [
        "../src/public.py",
        "/src/public.py",
        "file:///src/public.py",
        "https://[invalid",
        "https://example.test/x",
        "src/%70ublic.py",
        "src/../src/public.py",
        "src\\public.py",
        "src//public.py",
        "src/public.py?key=secret",
        "src/public.py#secret",
        "src/public.py\nsecret",
        "untracked.txt",
        None,
    ],
)
def test_noncanonical_url_absolute_and_untracked_paths_are_not_reported(uri: object) -> None:
    assert public_locations(result(uri), {"src/public.py"}) == []


@pytest.mark.parametrize("line", [True, False, 0, -1, "7", 7.0, None, 10_000_001])
def test_line_is_a_bounded_positive_integer(line: object) -> None:
    assert public_locations(result(line=line), {"src/public.py"}) == []


@pytest.mark.parametrize("rule", [None, "", "py/example\nsecret", "x" * 129])
def test_rule_id_is_bounded_plain_text(rule: object) -> None:
    assert public_locations(result(rule=rule), {"src/public.py"}) == []


def test_malformed_and_duplicate_results_are_safe() -> None:
    assert public_locations({"runs": [None, {"results": [None, {}]}]}, set()) == []
    payload = result()
    payload["runs"] *= 2
    assert len(public_locations(payload, {"src/public.py"})) == 1


def test_output_is_bounded() -> None:
    payload = {"runs": [{"results": [result(line=i)["runs"][0]["results"][0] for i in range(1, 700)]}]}
    assert len(public_locations(payload, {"src/public.py"})) == 500
