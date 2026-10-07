"""Adversarial, no-execution tests for the open-PR source converter."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import scripts.command_source_backlog as backlog
from scripts.command_source_backlog import (
    SOURCE_SCHEMA,
    build_request,
    canonical_json,
    convert_python_source,
    sha256_bytes,
)


def _module(matcher: str = "_M") -> str:
    return f"""from __future__ import annotations

_LAUNCHERS = (("demo",), ("demo-cli",))
{matcher} = AnyMatcher(matchers=tuple(
    executable_matcher(*launcher, "delete", options_with_values=frozenset(("--output",)))
    for launcher in _LAUNCHERS
))
RULES = (CommandSafetyRule(
    rule_id="command.demo.delete",
    title="Delete demo resource",
    description="Reviews demo deletion.",
    severity="high",
    risk_classes=("destructive_shell",),
    action_classes=("demo delete",),
    safer_alternatives=("Inspect the plan.",),
    matcher={matcher},
    safe_variants=(safe_flag_variant({matcher}, variant_id="help", title="Help", flag="--help"),),
),)
SPECS = (CommandExtensionSpec(
    extension_id="command.demo",
    name="Demo",
    description="Demo protection.",
    action_classes=("demo delete",),
    risk_classes=("destructive_shell",),
    safer_alternatives=("Inspect the plan.",),
    reference_urls=(),
),)
"""


def test_static_generated_pattern_becomes_native_source() -> None:
    result = convert_python_source(_module(), filename="command_demo_extensions.py")

    assert result.ok, [item.as_dict() for item in result.diagnostics]
    assert result.source["schema"] == SOURCE_SCHEMA
    extension = result.source["extension"]
    assert extension["extension_id"] == "command.demo"
    matcher = extension["rules"][0]["matcher"]
    assert matcher["op"] == "any.v1"
    assert matcher["matchers"][0]["op"] == "executable.v1"
    assert matcher["matchers"][0]["config"]["executables"] == ["demo", "demo.cmd", "demo.exe"]
    assert matcher["matchers"][1]["config"]["executables"] == ["demo-cli", "demo-cli.cmd", "demo-cli.exe"]
    assert matcher["matchers"][0]["config"]["subcommands"] == ["delete"]
    assert extension["rules"][0]["safe_variants"][0]["matcher"]["matchers"][0]["config"]["required_flags"] == ["--help"]


@pytest.mark.parametrize(
    ("source", "code"),
    [
        ("import os\n", "dynamic_import_rejected"),
        ("from .command_rules import Evil\n", "dynamic_import_rejected"),
        ("class Evil:\n    def match(self, value):\n        return True\n", "custom_code_rejected"),
        ("def make():\n    return AnyMatcher(matchers=())\n", "custom_code_rejected"),
        ("target = []\ntarget.append('dynamic')\n", "top_level_expression_rejected"),
        ("target = []\ntarget[0] = 'mutation'\n", "mutation_expression_rejected"),
        ("_M = OperandGatedFlagMatcher(flag='--danger')\n", "known_constructor_arguments_invalid"),
    ],
)
def test_untrusted_or_unadmitted_constructs_are_rejected(source: str, code: str) -> None:
    result = convert_python_source(source, filename="untrusted.py")

    assert not result.ok
    assert code in {item.code for item in result.diagnostics}


def test_rejected_source_is_never_executed(tmp_path: Path) -> None:
    marker = tmp_path / "executed"
    source = f"__import__('pathlib').Path({str(marker)!r}).write_text('bad')\n"

    result = convert_python_source(source, filename="malicious.py")

    assert not result.ok
    assert not marker.exists()


def test_dynamic_comprehension_and_unknown_calls_have_precise_diagnostics() -> None:
    dynamic = "_M = AnyMatcher(matchers=tuple(x for x in values if x))\n"
    unknown = "_M = make_matcher('delete')\n"

    dynamic_result = convert_python_source(dynamic, filename="dynamic.py")
    unknown_result = convert_python_source(unknown, filename="unknown.py")

    assert dynamic_result.diagnostics[0].code == "dynamic_comprehension_rejected"
    assert unknown_result.diagnostics[0].code == "dynamic_call_rejected"


@pytest.mark.parametrize(
    "source",
    [
        "from .evil import AnyMatcher\n_M = AnyMatcher(matchers=())\n",
        "from .command_rules import Evil\n",
        "from .command_rules import AnyMatcher\nAnyMatcher = Evil\n",
    ],
)
def test_import_identity_and_constructor_rebinding_are_closed(source: str) -> None:
    result = convert_python_source(source, filename="imports.py")

    assert not result.ok
    assert result.diagnostics[0].code in {"dynamic_import_rejected", "constructor_rebinding_rejected"}


def test_budget_rejects_repeated_static_doubling(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(backlog, "MAX_STRING_BYTES", 64)
    source = "value = 'a'\n" + "value = value + value\n" * 8

    result = convert_python_source(source, filename="budget.py")

    assert not result.ok
    assert result.diagnostics[0].code == "string_budget_exceeded"


def test_deep_expression_is_rejected_and_static_star_is_bounded() -> None:
    nested = "value = " + "[" * 80 + "'x'" + "]" * 80
    deep_result = convert_python_source(nested, filename="deep.py")
    starred_result = convert_python_source("value = (*('x',),)\n", filename="starred.py")
    dynamic_star_result = convert_python_source("value = (*(make(),),)\n", filename="dynamic-star.py")

    assert deep_result.diagnostics[0].code == "ast_depth_exceeded"
    assert starred_result.diagnostics[0].code == "no_rules_found"
    assert dynamic_star_result.diagnostics[0].code == "dynamic_call_rejected"


def test_repeated_matcher_dag_is_bounded_before_serialization(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(backlog, "MAX_EVALUATED_ITEMS", 20)
    source = "m0 = ExecutableMatcher(executables=('demo',))\n" + "\n".join(
        f"m{index} = AnyMatcher(matchers=(m{index - 1}, m{index - 1}))" for index in range(1, 8)
    )

    result = convert_python_source(source, filename="dag.py")

    assert not result.ok
    assert result.diagnostics[0].code == "expanded_value_budget_exceeded"


def test_nested_tuple_dag_is_rejected_before_set_hashing() -> None:
    source = (
        "value0 = ('x',)\n"
        + "\n".join(f"value{index} = (value{index - 1}, value{index - 1})" for index in range(1, 40))
        + "\nvalues = frozenset((value39,))\n"
    )

    result = convert_python_source(source, filename="nested-set.py")

    assert not result.ok
    assert result.diagnostics[0].code == "non_scalar_set_rejected"


def test_build_request_is_native_addition_envelope_and_digest_is_stable() -> None:
    source = {"schema": SOURCE_SCHEMA, "extension": {"extension_id": "command.demo"}}
    trust = {"schemaVersion": "guard.extension-trust-class-map.v1", "publishers": {}, "classes": {}}

    request = build_request([source], trust)

    assert request["schema"] == "guard.command-extension-build.v1"
    assert request["base"] == "packaged"
    first = canonical_json(request)
    second = canonical_json(json.loads(first))
    assert first == second
    assert sha256_bytes(first) == sha256_bytes(second)
