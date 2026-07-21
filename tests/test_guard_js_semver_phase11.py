"""Phase 11 JavaScript semver regression tests.

Representative truth cases were checked against npm ``semver@7.7.3``; the
production matcher remains self-contained and does not require Node.
"""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.runtime import supply_chain_package_eval as supply_chain_package_eval_module
from codex_plugin_scanner.guard.runtime.js_semver import (
    highest_js_version_for_selector,
    parse_js_semver,
    version_matches_js_selector,
)
from codex_plugin_scanner.guard.runtime.supply_chain_package_eval import (
    _exact_version,  # pyright: ignore[reportPrivateUsage]
)


@pytest.mark.parametrize(
    ("version", "selector", "expected"),
    [
        ("1.2.3-beta.1", "^1.2.0", False),
        ("1.2.3-beta.1", "~1.2.0", False),
        ("1.2.3-beta.1", ">=1.2.0 <2.0.0", False),
        ("1.2.3-beta.1", "*", False),
        ("1.3.0-beta.1", "^1.2.3", False),
        ("1.2.3-beta.1", "", False),
        ("1.2.3-beta.1", "latest", False),
        ("1.2.3", "^1.2.0", True),
        ("1.9.9", ">=1.2.0 <2.0.0", True),
        ("2.0.0", "*", True),
        ("2.0.0", "", True),
        ("2.0.0+linux.x64", "latest", True),
    ],
)
def test_ordinary_ranges_do_not_admit_prereleases(version: str, selector: str, expected: bool) -> None:
    assert version_matches_js_selector(version, selector) is expected


@pytest.mark.parametrize(
    ("version", "selector", "expected"),
    [
        ("1.2.3-beta.1", "1.2.3-beta.1", True),
        ("1.2.3-beta.1+build.9", "=1.2.3-beta.1+build.2", True),
        ("1.2.3-beta.2", ">=1.2.3-beta.1 <2.0.0", True),
        ("1.2.3-rc.1", "^1.2.3-beta.1", True),
        ("1.2.3-beta.2", "~1.2.3-beta.1", True),
        ("0.0.0-beta.2", ">=0.0.0-alpha.1 >=0.0.0", True),
        ("0.0.0-beta.2", "0 >=0.0.0-alpha.1", True),
        ("1.2.3", ">=1.2.3-beta.1 <2.0.0", True),
        ("1.2.4-beta.1", ">=1.2.3-beta.1 <2.0.0", False),
        ("1.3.0-beta.1", "~1.2.3-beta.1", False),
        ("2.0.0-beta.1", "^1.2.3-beta.1", False),
    ],
)
def test_explicit_prerelease_comparator_only_admits_the_same_base(
    version: str,
    selector: str,
    expected: bool,
) -> None:
    assert version_matches_js_selector(version, selector) is expected


@pytest.mark.parametrize(
    ("version", "selector", "expected"),
    [
        ("1.2.3-beta.2", ">=1.2.3-beta.1 <1.2.3 || >=2.0.0 <3.0.0", True),
        ("2.1.0-alpha.2", ">=1.2.3-beta.1 <1.2.3 || >=2.0.0 <3.0.0", False),
        ("2.1.0-alpha.2", ">=1.2.3-beta.1 <1.2.3 || >=2.1.0-alpha.1 <3.0.0", True),
        ("3.1.0-alpha.1", ">=1.2.3-beta.1 <2.0.0 || >=3.0.0 <4.0.0", False),
    ],
)
def test_prerelease_admission_is_local_to_each_or_clause(version: str, selector: str, expected: bool) -> None:
    assert version_matches_js_selector(version, selector) is expected


@pytest.mark.parametrize(
    ("version", "selector", "expected"),
    [
        ("0.2.9", "^0.2.3", True),
        ("0.3.0", "^0.2.3", False),
        ("0.2.3-beta.2", "^0.2.3-beta.1", True),
        ("0.2.4-beta.1", "^0.2.3-beta.1", False),
        ("0.2.4", "^0.2.3-beta.1", True),
        ("0.0.3", "^0.0.3", True),
        ("0.0.4", "^0.0.3", False),
        ("0.0.8", "^0.0", True),
        ("0.1.0", "^0.0", False),
    ],
)
def test_zero_major_caret_ranges_match_npm_boundaries(version: str, selector: str, expected: bool) -> None:
    assert version_matches_js_selector(version, selector) is expected


@pytest.mark.parametrize(
    ("version", "selector", "expected"),
    [
        ("1.2.9", "~1.2.3", True),
        ("1.3.0", "~1.2.3", False),
        ("1.8.0", "~1", True),
        ("2.0.0", "~1", False),
        ("1.2.9", "1.2.x", True),
        ("1.2.9", "1.2", True),
        ("1.9.0", "1.x", True),
        ("2.0.0", "1.x", False),
        ("1.2.9", ">1.2", False),
        ("1.3.0", ">1.2", True),
        ("1.2.9", "<=1.2", True),
        ("1.3.0", "<=1.2", False),
        ("1.2.3", "1.2.3 - 2.3.4", True),
        ("2.3.4", "1.2.3 - 2.3.4", True),
        ("2.3.5", "1.2.3 - 2.3.4", False),
        ("2.3.9", "1.2 - 2.3", True),
        ("2.4.0", "1.2 - 2.3", False),
    ],
)
def test_supported_npm_range_forms_use_npm_boundaries(version: str, selector: str, expected: bool) -> None:
    assert version_matches_js_selector(version, selector) is expected


@pytest.mark.parametrize(
    ("version", "selector", "expected"),
    [
        ("1.2.3+build.9", "1.2.3+build.1", True),
        ("1.2.3+build.9", ">=1.2.3+build.1 <=1.2.3+build.2", True),
        ("1.2.3-beta.2+sha.9", ">=1.2.3-beta.1+sha.1 <1.2.3", True),
        ("1.2.3-alpha.10", ">1.2.3-alpha.2 <1.2.3", True),
        ("1.2.3-alpha.2", ">1.2.3-alpha.10 <1.2.3", False),
        ("1.2.3-1", ">1.2.3-alpha <1.2.3", False),
    ],
)
def test_build_metadata_and_prerelease_precedence_match_semver(
    version: str,
    selector: str,
    expected: bool,
) -> None:
    assert version_matches_js_selector(version, selector) is expected


@pytest.mark.parametrize(
    ("version", "selector"),
    [
        ("1.2.3", "workspace:*"),
        ("1.2.3", ">=1.2.3 || not-a-range"),
        ("1.2.3", "1.2.3 ||"),
        ("1.2.3", "|| 1.2.3"),
        ("1.2.3", ">=1.2.3 # comment"),
        ("1.2.3", "1.2.x-beta.1"),
        ("1.2.3", "1.2.3 - nope"),
        ("1.2.3", "!=1.2.3"),
        ("1.2.3", "==1.2.3"),
        ("1.2.3", "V1.2.3"),
        ("1.2.3", "1.2.3\u0661"),
        ("1.2.3", ">= 1.2.3"),
        ("1.2.3", ">=1.2.3, <2.0.0"),
    ],
)
def test_invalid_or_unsupported_selector_syntax_fails_closed(version: str, selector: str) -> None:
    assert not version_matches_js_selector(version, selector)


@pytest.mark.parametrize(
    "version",
    [
        "1.2",
        "01.2.3",
        "1.02.3",
        "1.2.03",
        "1.2.3-01",
        "1.2.3-beta..1",
        "1.2.3+build..1",
        "1.2.3\u0661",
        " 1.2.3",
        "1.2.3 ",
    ],
)
def test_invalid_candidate_versions_fail_closed(version: str) -> None:
    assert parse_js_semver(version) is None
    assert not version_matches_js_selector(version, "*")


def test_semver_parser_resource_limits_fail_closed() -> None:
    assert parse_js_semver(f"1.2.3+{'x' * 257}") is None
    assert not version_matches_js_selector("1.2.3", ">=1.0.0 " * 65)
    assert not version_matches_js_selector("1.2.3", " || ".join([">=1.0.0"] * 33))
    assert not version_matches_js_selector("1.2.3", "x" * 1025)
    maximum = "9007199254740991"
    assert version_matches_js_selector(f"{maximum}.0.0", f">={maximum}")
    assert not version_matches_js_selector(f"{maximum}.0.0", maximum)
    assert not version_matches_js_selector(f"0.0.{maximum}", f"^0.0.{maximum}")
    assert not version_matches_js_selector(f"{maximum}.0.0", f"0 - {maximum}")


def test_highest_version_selection_never_prefers_an_inadmissible_prerelease() -> None:
    versions = ["1.9.9", "2.0.0-alpha.1", "1.5.0", "invalid"]

    assert highest_js_version_for_selector(versions, ">=1.0.0 <3.0.0") == "1.9.9"
    assert highest_js_version_for_selector(versions, "*") == "1.9.9"


def test_highest_version_selection_keeps_explicitly_admitted_prereleases() -> None:
    versions = ["1.2.2", "1.2.3-beta.1", "1.2.3-beta.10", "1.2.3-beta.2", "1.2.4-alpha.1"]

    assert highest_js_version_for_selector(versions, ">=1.2.3-beta.1 <1.2.3") == "1.2.3-beta.10"


def test_release_has_higher_precedence_than_its_prereleases() -> None:
    versions = ["1.2.3-beta.10", "1.2.3", "1.2.3-rc.1"]

    assert highest_js_version_for_selector(versions, ">=1.2.3-beta.1 <2.0.0") == "1.2.3"


@pytest.mark.parametrize(
    ("selector", "expected"),
    [
        (">=1.0.0 <3.0.0", "1.9.9"),
        ("latest", "1.9.9"),
        (">=2.0.0-alpha.1 <2.0.0", "2.0.0-alpha.10"),
        (">=1.0.0 || not-a-range", None),
    ],
)
def test_npm_registry_resolution_applies_prerelease_admission_at_the_selection_sink(
    monkeypatch: pytest.MonkeyPatch,
    selector: str,
    expected: str | None,
) -> None:
    def registry_response(**_kwargs: object) -> dict[str, object]:
        return {
            "versions": {
                "1.5.0": {},
                "1.9.9": {},
                "2.0.0-alpha.1": {},
                "2.0.0-alpha.10": {},
            }
        }

    monkeypatch.setattr(
        supply_chain_package_eval_module,
        "_urlopen_json_with_timeout_retry",
        registry_response,
    )

    assert (
        supply_chain_package_eval_module._npm_registry_resolved_version(  # pyright: ignore[reportPrivateUsage]
            package_name="example-package",
            requested_range=selector,
        )
        == expected
    )


def test_exact_version_ignores_all_js_source_prefixes() -> None:
    assert _exact_version("github:hashgraph-online/hol-guard") is None
    assert _exact_version("gitlab:hashgraph-online/hol-guard") is None
    assert _exact_version("bitbucket:hashgraph-online/hol-guard") is None
