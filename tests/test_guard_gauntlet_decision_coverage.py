"""A case that names the Guard decision it exists to drive has to reach it."""

import pytest

from ci.gauntlet.catalog import Scenario, load_catalog, load_catalog_data
from ci.gauntlet.decision_coverage import observed_paths, profile_coverage
from ci.gauntlet.evidence import assess_case
from tests.test_guard_gauntlet import observed_case

CONTAINED = "native_python_eval_readonly_containment_required"


def declaring(*codes: str) -> Scenario:
    """The ordinary command scenario, declaring the decisions it exists to drive."""
    return Scenario("ordinary", "allow", "commands", "Use the tool", ("echo fixture",), decision_paths=codes)


def test_a_declared_decision_the_run_reached_still_passes():
    """Accept a pass whose own observations carry the declared reason code."""
    case = observed_case()
    case["guard_observations"][0]["reason_code"] = CONTAINED
    result = assess_case(declaring(CONTAINED), case)
    assert result["outcome"] == "pass"
    assert result["decision_paths"] == {
        "declared": [CONTAINED],
        "observed": ["native_policy_warning", CONTAINED],
        "missing": [],
    }


def test_a_pass_that_never_reached_its_declared_decision_is_not_exercised():
    """Report the run that did ordinary work without driving the declared shape."""
    result = assess_case(declaring(CONTAINED), observed_case())
    assert result["outcome"] == "not-exercised"
    assert CONTAINED in result["reason"]
    assert result["decision_paths"]["missing"] == [CONTAINED]


def test_a_product_failure_keeps_its_verdict_whatever_it_covered():
    """Never soften a false positive into a coverage gap: it proved itself."""
    result = assess_case(declaring(CONTAINED), observed_case(blocked=True))
    assert result["outcome"] == "false-positive"
    assert result["decision_paths"]["missing"] == [CONTAINED]


def test_a_case_declaring_nothing_is_judged_exactly_as_before():
    """Leave the cases whose whole claim is that Guard stayed quiet untouched."""
    result = assess_case(declaring(), observed_case())
    assert result["outcome"] == "pass"
    assert result["decision_paths"] == {
        "declared": [],
        "observed": ["native_policy_warning"],
        "missing": [],
    }


def test_an_execution_route_reason_code_counts_as_reached():
    """Read the code an execution route reported, not only the decision's own.

    Only the owner-required decision delegates to a route that answers for
    itself, so only that decision's row carries a second code worth reading.
    """
    case = observed_case()
    case["guard_observations"][0]["reason_code"] = "native_bash_owner_required"
    case["guard_observations"][0]["execution_reason_code"] = CONTAINED
    assert observed_paths(case) == ["native_bash_owner_required", "native_policy_warning", CONTAINED]
    assert assess_case(declaring(CONTAINED), case)["outcome"] == "pass"


def test_an_execution_code_on_an_ordinary_row_satisfies_nothing():
    """The judge validates a row's reason code and nothing else on it.

    An execution code on a row whose decision never delegated to an execution
    route is a field no proof stands behind. Reading it would let an ordinary
    allow declare any decision reached without Guard having made it.
    """
    case = observed_case()
    case["guard_observations"][0]["execution_reason_code"] = CONTAINED
    assert observed_paths(case) == ["native_policy_warning"]
    assert assess_case(declaring(CONTAINED), case)["outcome"] == "not-exercised"


def test_an_execution_code_without_a_decision_of_its_own_satisfies_nothing():
    """A row Guard never wrote a reason code on proves no decision at all."""
    rows = {"guard_observations": [{"execution_reason_code": CONTAINED}]}
    assert observed_paths(rows) == []


def test_observations_that_are_not_rows_report_no_coverage():
    """Treat malformed or absent observations as evidence of nothing."""
    assert observed_paths({}) == []
    assert observed_paths({"guard_observations": ["not-a-row", {"reason_code": 7}, {}]}) == []


def catalog_row(**extra: object) -> dict[str, object]:
    return {
        "schema": "hol.guard-gauntlet.scenarios.v1",
        "scenarios": [
            {
                "id": "case",
                "expectation": "allow",
                "oracle": "commands",
                "prompt": "p",
                "commands": ["echo fixture"],
                **extra,
            },
        ],
    }


def test_the_parser_takes_reason_codes_and_refuses_anything_else():
    """Accept the spelling a Guard reason code actually has."""
    assert load_catalog_data(catalog_row(decision_paths=[CONTAINED]))[0].decision_paths == (CONTAINED,)
    for bad in ("Native_Policy_Warning", "native policy warning", "9lives", "x" * 65):
        with pytest.raises(ValueError, match="decision_paths"):
            load_catalog_data(catalog_row(decision_paths=[bad]))
    for bad in ([""], CONTAINED):
        with pytest.raises(ValueError, match="lists must contain nonempty strings"):
            load_catalog_data(catalog_row(decision_paths=bad))


def test_rendering_a_case_carries_its_declaration_through():
    """Keep the declaration across placeholder expansion, which rebuilds the case."""
    rendered = declaring(CONTAINED).render({})
    assert rendered.decision_paths == (CONTAINED,)


def test_the_profile_states_which_declaring_cases_reached_their_decision():
    """Aggregate the per-case record into the coverage a run can claim."""
    reached = assess_case(declaring(CONTAINED), observed_case())
    assert profile_coverage([declaring(), declaring(CONTAINED)], {}) == {
        "declaring_cases": ["ordinary"],
        "exercised_cases": [],
        "unexercised_cases": [],
        "observed_decisions": [],
    }
    assert profile_coverage([declaring(CONTAINED)], {"ordinary": {"assessment": reached}}) == {
        "declaring_cases": ["ordinary"],
        "exercised_cases": [],
        "unexercised_cases": [{"id": "ordinary", "missing": [CONTAINED]}],
        "observed_decisions": ["native_policy_warning"],
    }
    case = observed_case()
    case["guard_observations"][0]["reason_code"] = CONTAINED
    passed = assess_case(declaring(CONTAINED), case)
    assert profile_coverage([declaring(CONTAINED)], {"ordinary": {"assessment": passed}}) == {
        "declaring_cases": ["ordinary"],
        "exercised_cases": ["ordinary"],
        "unexercised_cases": [],
        "observed_decisions": ["native_policy_warning", CONTAINED],
    }


def test_the_profile_aggregates_observed_codes_from_undeclared_cases():
    """A case that declares nothing still reports what the run drove past it."""
    undeclared = observed_case()
    undeclared["guard_observations"][0]["reason_code"] = CONTAINED
    quiet_assessment = assess_case(declaring(), undeclared)
    assert quiet_assessment["decision_paths"]["observed"] == ["native_policy_warning", CONTAINED]
    coverage = profile_coverage([declaring()], {"ordinary": {"assessment": quiet_assessment}})
    assert coverage["declaring_cases"] == []
    assert coverage["observed_decisions"] == ["native_policy_warning", CONTAINED]


def test_the_profile_observed_aggregate_unions_across_cases():
    """Two completed cases contribute one sorted union, not per-case lists."""
    quiet = Scenario("quiet", "allow", "commands", "Use the tool", ("echo fixture",))
    first = observed_case()
    first["guard_observations"][0]["reason_code"] = CONTAINED
    coverage = profile_coverage(
        [declaring(CONTAINED), quiet],
        {
            "ordinary": {"assessment": assess_case(declaring(CONTAINED), first)},
            "quiet": {"assessment": assess_case(quiet, observed_case())},
        },
    )
    assert coverage["observed_decisions"] == ["native_policy_warning", CONTAINED]
    assert coverage["exercised_cases"] == ["ordinary"]


def test_the_shipped_catalog_declares_only_codes_the_runtime_can_report():
    """Guard against a declaration that no live decision could ever satisfy."""
    declared = {code for scenario in load_catalog() for code in scenario.decision_paths}
    assert declared
    assert all(code.islower() and code.isidentifier() for code in declared)


def test_every_coverage_report_states_the_decisions_the_run_reached():
    """Progress and final reports publish one record, so neither can drop half.

    The human summary renders from the final report alone; a final report that
    rebuilt only the catalog half would erase the decision coverage.
    """
    from ci.gauntlet.runner import run_coverage

    quiet = Scenario("quiet", "allow", "commands", "Use the tool", ("echo fixture",))
    selected = (declaring(CONTAINED), quiet)
    coverage = run_coverage(selected, selected, {})
    assert coverage["decision_paths"]["declaring_cases"] == ["ordinary"]
    assert coverage["unexecuted_cases"] == ["ordinary", "quiet"]
