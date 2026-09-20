"""Shared immutable nodes must not bypass the converter's output limits."""

import pytest

import scripts.command_source_backlog as backlog


def _shared_matcher_source(depth: int) -> str:
    lines = ['M0 = executable_matcher("demo", "delete")']
    lines.extend(f"M{index} = AnyMatcher(matchers=(M{index - 1}, M{index - 1}))" for index in range(1, depth + 1))
    lines.append(f"""RULES = (CommandSafetyRule(
        rule_id="command.demo.delete", title="Delete", description="Review deletion.",
        severity="high", risk_classes=("destructive_shell",), action_classes=("demo delete",),
        safer_alternatives=("Inspect first.",), matcher=M{depth}, safe_variants=(),
    ),)""")
    return "\n".join(lines)


def test_shared_matcher_graph_is_bounded_before_recursive_discovery(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(backlog, "MAX_EVALUATED_ITEMS", 512)

    def forbidden(*_args):
        pytest.fail("unbounded graph reached recursive discovery")

    monkeypatch.setattr(backlog, "_walk_constructor_values", forbidden)
    result = backlog.convert_python_source(_shared_matcher_source(8), extension_id="command.demo")
    assert not result.ok
    assert "expanded_value_budget_exceeded" in {item.code for item in result.diagnostics}


def test_small_shared_matcher_graph_remains_convertible(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(backlog, "MAX_EVALUATED_ITEMS", 512)
    result = backlog.convert_python_source(_shared_matcher_source(1), extension_id="command.demo")
    assert result.ok, [item.as_dict() for item in result.diagnostics]
    matcher = result.source["extension"]["rules"][0]["matcher"]
    assert len(matcher["matchers"]) == 2


def test_shared_string_expansion_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(backlog, "MAX_JSON_BYTES", 128)
    repeated = "a" * 65
    with pytest.raises(backlog.ConversionRejected, match="output byte budget"):
        backlog._validate_expanded_values((repeated, repeated), filename="bounded.py")
