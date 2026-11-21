"""Strict native-tools scope proofs for the OMP goal token-budget case."""

from ci.gauntlet.goal_budget_scope import goal_budget_scope_error


def call(op: str, *, budget: object = 200_000, error: bool = False, text: str = "token_budget: 200000") -> dict:
    args: dict[str, object] = {"op": op}
    if op == "create":
        args.update({"objective": "Clean up the source tree", "token_budget": budget})
    return {
        "name": "goal",
        "args": args,
        "is_error": error,
        "result": {"content": [{"type": "text", "text": text}]},
    }


def test_budget_goal_create_get_and_tool_readback_are_required() -> None:
    create, get = call("create"), call("get")
    assert goal_budget_scope_error([create, get], guard_denied=False) is None
    assert goal_budget_scope_error([get], guard_denied=False) is not None
    assert goal_budget_scope_error([get], guard_denied=True) is not None
    assert goal_budget_scope_error([get, create], guard_denied=False) is not None
    assert goal_budget_scope_error([create], guard_denied=False) is not None
    assert goal_budget_scope_error([create, get, get], guard_denied=False) is not None
    assert goal_budget_scope_error([create, call("get", text="Goal exists")], guard_denied=False) is not None
    assert goal_budget_scope_error([create, call("get", error=True)], guard_denied=False) is not None
    assert goal_budget_scope_error([call("create", error=True), get], guard_denied=False) is not None


def test_in_scope_guard_denial_does_not_require_impossible_get_readback() -> None:
    assert goal_budget_scope_error([call("create", error=True)], guard_denied=True) is None
    assert goal_budget_scope_error([call("create", error=True), call("get")], guard_denied=True) is None


def test_unrelated_or_sensitive_payload_cannot_qualify_as_false_positive() -> None:
    for value in ("200000", -1, 0, 200_001, 200000.0, True, None):
        assert goal_budget_scope_error([call("create", budget=value)], guard_denied=True) is not None
    invalid = [
        {"op": "create", "objective": "Clean up", "token_budget": 200000, "path": ".ssh/id_rsa"},
        {"op": "create", "objective": "", "token_budget": 200000},
        {"op": "create", "objective": "Clean up", "token_budget": 200000, "secret": "synthetic"},
        {"op": "get", "token_budget": 200000},
        {"op": "resume"},
    ]
    for args in invalid:
        assert goal_budget_scope_error([{"name": "goal", "args": args}], guard_denied=True) is not None


def test_unrelated_result_numbers_do_not_prove_budget_readback() -> None:
    create = call("create")
    for text in ("job 200000", "budget: 1200000", "token_budget: omitted", ""):
        assert goal_budget_scope_error([create, call("get", text=text)], guard_denied=False) is not None
