"""Validation helpers for public HOL Guard policy recipe artifacts.

Recipes are inert starting points. They do not mutate Guard configuration or
bypass the normal policy approval/bundle-verification path.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import date
from typing import Literal, cast

SCHEMA_VERSION = "guard-policy-recipe/v1"
_RECIPE_ID_RE = re.compile(r"^GPR-[0-9]{3}$")
_SLUG_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_ALLOWED_ACTIONS = frozenset({"allow", "block", "review"})
_ALLOWED_MATCHER_KINDS = frozenset({"path", "package", "command", "mcp", "tool", "domain"})
_ALLOWED_RISKS = frozenset({"low", "medium", "high", "critical"})
_ALLOWED_EXPECTED = frozenset({"allow", "block", "review", "unmatched"})
_GLOB_META_RE = re.compile(r"[*?\[\]{}]|[@+!]\(")

RecipeAction = Literal["allow", "block", "review"]
RecipeMatcherKind = Literal["path", "package", "command", "mcp", "tool", "domain"]
RecipeExpected = Literal["allow", "block", "review", "unmatched"]


@dataclass(frozen=True)
class PolicyRecipeMatcher:
    kind: RecipeMatcherKind
    value: str


@dataclass(frozen=True)
class PolicyRecipeFixture:
    label: str
    matcher_kind: RecipeMatcherKind
    value: str
    expected: RecipeExpected


@dataclass(frozen=True)
class PolicyRecipe:
    schema_version: Literal["guard-policy-recipe/v1"]
    recipe_id: str
    slug: str
    title: str
    summary: str
    action: RecipeAction
    matcher: PolicyRecipeMatcher
    template_id: str
    risk: Literal["low", "medium", "high", "critical"]
    threat_slugs: tuple[str, ...]
    limitations: tuple[str, ...]
    tests: tuple[PolicyRecipeFixture, ...]
    emergency_eligible: bool
    reviewed_at: str


def _required_string(record: Mapping[str, object], key: str, *, maximum: int) -> str:
    value = record.get(key)
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ValueError(f"{key} must be a non-empty string <= {maximum} characters")
    return value


def _record(value: object, key: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{key} must be an object")
    return cast(Mapping[str, object], value)


def _strict_keys(record: Mapping[str, object], expected: set[str], label: str) -> None:
    unknown = set(record) - expected
    missing = expected - set(record)
    if unknown:
        raise ValueError(f"{label} contains unsupported fields: {', '.join(sorted(unknown))}")
    if missing:
        raise ValueError(f"{label} is missing required fields: {', '.join(sorted(missing))}")


def parse_policy_recipe(value: object) -> PolicyRecipe:
    record = _record(value, "recipe")
    _strict_keys(
        record,
        {
            "schemaVersion",
            "id",
            "slug",
            "title",
            "summary",
            "action",
            "matcher",
            "templateId",
            "risk",
            "threatSlugs",
            "limitations",
            "tests",
            "emergencyEligible",
            "reviewedAt",
        },
        "recipe",
    )
    if record.get("schemaVersion") != SCHEMA_VERSION:
        raise ValueError("unsupported policy recipe schema version")
    recipe_id = _required_string(record, "id", maximum=7)
    if not _RECIPE_ID_RE.fullmatch(recipe_id):
        raise ValueError("invalid policy recipe id")
    slug = _required_string(record, "slug", maximum=120)
    if not _SLUG_RE.fullmatch(slug):
        raise ValueError("invalid policy recipe slug")

    action_value = record.get("action")
    if not isinstance(action_value, str) or action_value not in _ALLOWED_ACTIONS:
        raise ValueError("invalid policy recipe action")
    action = cast(RecipeAction, action_value)

    matcher_record = _record(record.get("matcher"), "matcher")
    _strict_keys(matcher_record, {"kind", "value"}, "matcher")
    kind_value = matcher_record.get("kind")
    if not isinstance(kind_value, str) or kind_value not in _ALLOWED_MATCHER_KINDS:
        raise ValueError("invalid matcher kind")
    kind = cast(RecipeMatcherKind, kind_value)
    matcher_value = _required_string(matcher_record, "value", maximum=160)
    if _GLOB_META_RE.search(matcher_value):
        raise ValueError("wildcard matchers are not allowed in public policy recipes")

    risk_value = record.get("risk")
    if not isinstance(risk_value, str) or risk_value not in _ALLOWED_RISKS:
        raise ValueError("invalid policy recipe risk")

    threat_slugs_raw = record.get("threatSlugs")
    if not isinstance(threat_slugs_raw, Sequence) or isinstance(threat_slugs_raw, (str, bytes)):
        raise ValueError("threatSlugs must be an array")
    threat_slugs: list[str] = []
    for item in threat_slugs_raw:
        if not isinstance(item, str) or not _SLUG_RE.fullmatch(item):
            raise ValueError("invalid threat slug")
        threat_slugs.append(item)
    if len(threat_slugs) > 8:
        raise ValueError("too many threat slugs")

    limitations_raw = record.get("limitations")
    if not isinstance(limitations_raw, Sequence) or isinstance(limitations_raw, (str, bytes)):
        raise ValueError("limitations must be an array")
    limitations = tuple(str(item) for item in limitations_raw if isinstance(item, str) and 10 <= len(item) <= 500)
    if len(limitations) != len(limitations_raw) or not limitations or len(limitations) > 8:
        raise ValueError("invalid policy recipe limitations")

    tests_raw = record.get("tests")
    if not isinstance(tests_raw, Sequence) or isinstance(tests_raw, (str, bytes)) or not 2 <= len(tests_raw) <= 8:
        raise ValueError("tests must contain between 2 and 8 fixtures")
    fixtures: list[PolicyRecipeFixture] = []
    fixture_identities: set[tuple[str, str, str]] = set()
    for raw_fixture in tests_raw:
        fixture_record = _record(raw_fixture, "fixture")
        _strict_keys(fixture_record, {"label", "matcherKind", "value", "expected"}, "fixture")
        fixture_kind_value = fixture_record.get("matcherKind")
        if not isinstance(fixture_kind_value, str) or fixture_kind_value not in _ALLOWED_MATCHER_KINDS:
            raise ValueError("invalid fixture matcher kind")
        expected_value = fixture_record.get("expected")
        if not isinstance(expected_value, str) or expected_value not in _ALLOWED_EXPECTED:
            raise ValueError("invalid fixture expected result")
        fixture = PolicyRecipeFixture(
            label=_required_string(fixture_record, "label", maximum=120),
            matcher_kind=cast(RecipeMatcherKind, fixture_kind_value),
            value=_required_string(fixture_record, "value", maximum=160),
            expected=cast(RecipeExpected, expected_value),
        )
        identity = (fixture.matcher_kind, fixture.value, fixture.expected)
        if identity in fixture_identities:
            raise ValueError("duplicate policy recipe fixture")
        fixture_identities.add(identity)
        fixtures.append(fixture)

    if not any(
        fixture.matcher_kind == kind and fixture.value == matcher_value and fixture.expected == action
        for fixture in fixtures
    ):
        raise ValueError("tests must include a matching fixture for the recipe action")
    if not any(fixture.expected == "unmatched" for fixture in fixtures):
        raise ValueError("tests must include an unmatched boundary fixture")

    emergency = record.get("emergencyEligible")
    if not isinstance(emergency, bool):
        raise ValueError("emergencyEligible must be boolean")
    reviewed_at = _required_string(record, "reviewedAt", maximum=10)
    try:
        parsed_reviewed_at = date.fromisoformat(reviewed_at)
    except ValueError as error:
        raise ValueError("reviewedAt must be a valid YYYY-MM-DD date") from error
    if parsed_reviewed_at.isoformat() != reviewed_at:
        raise ValueError("reviewedAt must be YYYY-MM-DD")

    recipe = PolicyRecipe(
        schema_version=SCHEMA_VERSION,
        recipe_id=recipe_id,
        slug=slug,
        title=_required_string(record, "title", maximum=120),
        summary=_required_string(record, "summary", maximum=500),
        action=action,
        matcher=PolicyRecipeMatcher(kind=kind, value=matcher_value),
        template_id=_required_string(record, "templateId", maximum=120),
        risk=cast(Literal["low", "medium", "high", "critical"], risk_value),
        threat_slugs=tuple(threat_slugs),
        limitations=limitations,
        tests=tuple(fixtures),
        emergency_eligible=emergency,
        reviewed_at=reviewed_at,
    )
    validate_policy_recipe_fixtures(recipe)
    return recipe


def evaluate_policy_recipe_fixture(recipe: PolicyRecipe, fixture: PolicyRecipeFixture) -> RecipeExpected:
    if fixture.matcher_kind != recipe.matcher.kind or fixture.value != recipe.matcher.value:
        return "unmatched"
    return recipe.action


def validate_policy_recipe_fixtures(recipe: PolicyRecipe) -> None:
    for fixture in recipe.tests:
        actual = evaluate_policy_recipe_fixture(recipe, fixture)
        if actual != fixture.expected:
            raise ValueError(f"fixture failed: {fixture.label}: expected {fixture.expected}, got {actual}")


def canonical_policy_recipe_json(value: Mapping[str, object]) -> str:
    return json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True, separators=(",", ": ")) + "\n"


def policy_recipe_sha256(value: Mapping[str, object]) -> str:
    return hashlib.sha256(canonical_policy_recipe_json(value).encode("utf-8")).hexdigest()
