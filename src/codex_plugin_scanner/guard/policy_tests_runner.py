"""Run the ``x-hol.tests`` examples stored in a policy document.

Each case is one event and the decision it must produce. The runner reports ``pass``, ``fail`` or
``ambiguous`` per case; an invalid or duplicated test list is ``x_hol_tests_invalid`` and never runs.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import lru_cache
from importlib import resources
from typing import Final, Literal, TypeAlias, cast

from jsonschema import Draft202012Validator

from .business_policy_document_import import has_business_rules
from .policy_decision_engine import PolicyEventError, compile_local_rows, decide_rows, parse_event
from .policy_document import GuardPolicyDocument, canonical_policy_document_bytes, policy_document_digest

TESTS_EXTENSION: Final = "x-hol.tests"
BUSINESS_RULES_CODE: Final = "business_rules_not_evaluated_locally"
TestStatus: TypeAlias = Literal["pass", "fail", "ambiguous"]


class PolicyTestsInvalidError(ValueError):
    """The stored test list is malformed (``x_hol_tests_invalid``)."""

    code = "x_hol_tests_invalid"

    def __init__(self, problems: tuple[str, ...]) -> None:
        self.problems = problems
        super().__init__("; ".join(problems[:5]) or self.code)


@dataclass(frozen=True, slots=True)
class PolicyTestResult:
    id: str
    name: str | None
    status: TestStatus
    expected_effect: str
    expected_rule_id: str | None
    actual_effect: str
    actual_rule_id: str | None
    message: str

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "name": self.name,
            "status": self.status,
            "expected": {"effect": self.expected_effect, "ruleId": self.expected_rule_id},
            "actual": {"effect": self.actual_effect, "ruleId": self.actual_rule_id},
            "message": self.message,
        }


@dataclass(frozen=True, slots=True)
class PolicyTestRun:
    document_id: str
    digest: str
    results: tuple[PolicyTestResult, ...]

    @property
    def passed(self) -> int:
        return sum(1 for result in self.results if result.status == "pass")

    @property
    def failed(self) -> int:
        return len(self.results) - self.passed

    def to_dict(self) -> dict[str, object]:
        return {
            "document": {"id": self.document_id, "digest": self.digest},
            "total": len(self.results),
            "passed": self.passed,
            "failed": self.failed,
            "ok": self.failed == 0,
            "results": [result.to_dict() for result in self.results],
        }


@lru_cache(maxsize=1)
def _tests_validator() -> Draft202012Validator:
    text = (
        resources.files("codex_plugin_scanner.guard")
        .joinpath("schemas")
        .joinpath("guard-policy-x-hol-tests-v1alpha1.schema.json")
        .read_text(encoding="utf-8")
    )
    return Draft202012Validator(json.loads(text))


def stored_tests(document: GuardPolicyDocument) -> list[dict[str, object]]:
    """The validated ``spec["x-hol.tests"]`` list, or an empty list when the document has none."""

    spec = json.loads(canonical_policy_document_bytes(document)).get("spec", {})
    value = spec.get(TESTS_EXTENSION) if isinstance(spec, dict) else None
    if value is None:
        return []
    problems = tuple(
        f"{'/'.join(str(part) for part in error.absolute_path) or '$'}: {error.message[:120]}"
        for error in sorted(_tests_validator().iter_errors(value), key=lambda item: list(item.absolute_path))
    )
    if problems:
        raise PolicyTestsInvalidError(problems)
    cases = cast(list[dict[str, object]], value)
    seen: set[str] = set()
    duplicates: list[str] = []
    for case in cases:
        identifier = str(case["id"])
        if identifier in seen:
            duplicates.append(identifier)
        seen.add(identifier)
    if duplicates:
        raise PolicyTestsInvalidError(tuple(f"duplicate test id: {identifier}" for identifier in duplicates))
    rule_ids = {rule.id for rule in document.rules}
    unknown = [
        f"{case['id']}: expects unknown rule {expect['ruleId']}"
        for case in cases
        if isinstance(expect := case["expect"], dict) and expect.get("ruleId") not in (None, *rule_ids)
    ]
    if unknown:
        raise PolicyTestsInvalidError(tuple(unknown))
    return cases


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _unsupported_results(cases: list[dict[str, object]]) -> tuple[PolicyTestResult, ...]:
    """Business rules have no local rows, so no example can be decided here; say so instead of passing."""

    message = f"{BUSINESS_RULES_CODE}: business rules are not evaluated locally, so this example was not run."
    results: list[PolicyTestResult] = []
    for case in cases:
        expect = cast(dict[str, object], case["expect"])
        results.append(
            PolicyTestResult(
                str(case["id"]),
                cast("str | None", case.get("name")),
                "fail",
                str(expect["effect"]),
                cast("str | None", expect.get("ruleId")),
                "unsupported",
                None,
                message,
            )
        )
    return tuple(results)


def run_policy_tests(document: GuardPolicyDocument, *, now: str | None = None) -> PolicyTestRun:
    """Decide every stored example and compare it with the expectation."""

    cases = stored_tests(document)
    if has_business_rules(document):
        return PolicyTestRun(document.metadata.id, policy_document_digest(document), _unsupported_results(cases))
    rows = compile_local_rows(document)
    evaluation_time = now or _now()
    results: list[PolicyTestResult] = []
    for case in cases:
        expect = cast(dict[str, object], case["expect"])
        expected_effect = str(expect["effect"])
        expected_rule = cast("str | None", expect.get("ruleId"))
        name = cast("str | None", case.get("name"))
        try:
            decision = decide_rows(tuple(rows), parse_event(case["event"]), now=evaluation_time)
        except PolicyEventError as error:
            results.append(
                PolicyTestResult(
                    str(case["id"]), name, "fail", expected_effect, expected_rule, "error", None, str(error)
                )
            )
            continue
        actual_effect = str(decision["effect"])
        actual_rule = cast("str | None", decision["ruleId"])
        status: TestStatus = "pass"
        message = "Decision matches."
        if actual_effect != expected_effect:
            status, message = "fail", f"Expected effect {expected_effect}, got {actual_effect}."
        elif expected_rule is not None and actual_rule != expected_rule:
            status, message = "fail", f"Expected rule {expected_rule}, got {actual_rule or 'no rule'}."
        elif expected_rule is not None and decision["ambiguous"]:
            status = "ambiguous"
            tied = ", ".join(cast("list[str]", decision["tiedRuleIds"]))
            message = f"x_hol_tests_ambiguous: rule {actual_rule} ties with {tied}; tighten a match so one rule wins."
        results.append(
            PolicyTestResult(
                str(case["id"]), name, status, expected_effect, expected_rule, actual_effect, actual_rule, message
            )
        )
    return PolicyTestRun(document.metadata.id, policy_document_digest(document), tuple(results))


__all__ = [
    "BUSINESS_RULES_CODE",
    "TESTS_EXTENSION",
    "PolicyTestResult",
    "PolicyTestRun",
    "PolicyTestsInvalidError",
    "run_policy_tests",
    "stored_tests",
]
