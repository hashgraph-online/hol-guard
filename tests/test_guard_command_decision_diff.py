"""Contracts for the signed deterministic command decision-diff report."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import cast

from tests.guard_command_corpus import load_seed_manifest
from tests.guard_command_decision_diff import (
    BASE_RELEASE_SHA,
    REPORT_PATH,
    REPORT_SCHEMA_VERSION,
    canonical_json_bytes,
    generate_decision_diff_report,
    report_framed_sha256,
    source_binding_id,
)

_OPAQUE_ID = re.compile(r"c-[0-9a-f]{24}")


def _fixture() -> dict[str, object]:
    value = cast(object, json.loads(REPORT_PATH.read_text(encoding="utf-8")))
    assert isinstance(value, dict)
    return cast(dict[str, object], value)


def test_report_is_exactly_reproducible_and_source_bound() -> None:
    report = generate_decision_diff_report()
    assert REPORT_PATH.read_bytes() == canonical_json_bytes(report)
    assert report["schema_version"] == REPORT_SCHEMA_VERSION
    assert report["base_release_sha"] == BASE_RELEASE_SHA
    assert re.fullmatch(r"[0-9a-f]{64}", report_framed_sha256(report))

    bindings = cast(dict[str, object], report["bindings"])
    sources = cast(dict[str, object], bindings["sources_sha256"])
    assert len(sources) >= 40
    assert all(re.fullmatch(r"source-[0-9a-f]{24}", source) for source in sources)
    assert all(re.fullmatch(r"[0-9a-f]{64}", str(digest)) for digest in sources.values())
    critical_paths = {
        "src/codex_plugin_scanner/guard/runtime/command_decision_adapter.py",
        "src/codex_plugin_scanner/guard/runtime/command_extensions.py",
        "src/codex_plugin_scanner/guard/runtime/command_model.py",
        "src/codex_plugin_scanner/guard/runtime/effect_contract.py",
        "src/codex_plugin_scanner/guard/runtime/extension_evidence.py",
        "src/codex_plugin_scanner/guard/runtime/command_contained_routine_candidates.py",
        "src/codex_plugin_scanner/guard/runtime/command_verified_read_candidates.py",
        "src/codex_plugin_scanner/guard/runtime/local_package_script_evidence.py",
        "src/codex_plugin_scanner/guard/runtime/verified_github_reads.py",
        "src/codex_plugin_scanner/guard/runtime/verified_read_execution.py",
        "src/codex_plugin_scanner/guard/runtime/verified_read_common.py",
        "src/codex_plugin_scanner/guard/cli/commands_verified_read.py",
        "src/codex_plugin_scanner/guard/cli/commands_parser_local.py",
        "src/codex_plugin_scanner/guard/cli/commands_router.py",
        "src/codex_plugin_scanner/guard/cli/commands_parser.py",
        "src/codex_plugin_scanner/guard/cli/commands_support.py",
        "src/codex_plugin_scanner/guard/contained_package_script_execution.py",
        "src/codex_plugin_scanner/guard/package_shim_gate.py",
        "src/codex_plugin_scanner/guard/shims.py",
        "tests/test_guard_contained_package_script_execution.py",
        "tests/test_guard_package_shims.py",
    }
    assert {source_binding_id(path) for path in critical_paths} <= sources.keys()


def test_report_reconciles_every_case_without_lowering_or_widening_gaps() -> None:
    report = _fixture()
    manifest = load_seed_manifest()
    corpus = cast(dict[str, object], report["corpus"])
    assert corpus["benign_count"] == 1000
    assert corpus["adversarial_count"] == 50000
    assert corpus["total_count"] == 51000
    assert corpus["canonical_digests"] == manifest["canonical_digests"]

    comparison = cast(dict[str, object], report["current_vs_proposed"])
    assert comparison["lowered_count"] == 0
    assert comparison["disposition_changed_count"] == 0
    assert (
        sum(
            int(str(cast(dict[str, object], group)["count"]))
            for group in cast(list[object], comparison["transition_groups"])
        )
        == 51000
    )

    legacy = cast(dict[str, object], report["legacy_to_current"])
    assert legacy["lowered_count"] == 0
    groups = {
        str(group["key"]): int(str(group["count"]))
        for group in cast(list[dict[str, object]], legacy["transition_groups"])
    }
    assert groups == {"allow|review": 30581, "review|review": 20419}

    reconciliation = cast(dict[str, object], report["oracle_reconciliation"])
    assert reconciliation["known_gap_equality"] is True
    assert reconciliation["reconciled_count"] == 51000
    assert reconciliation["unreconciled_count"] == 0
    assert all(
        not str(key).startswith(("CDX-060|", "CDX-061|"))
        for key in cast(dict[str, object], reconciliation["legacy_known_gaps"])
    )
    category_groups = cast(list[dict[str, object]], reconciliation["category_groups"])
    assert sum(int(str(group["count"])) for group in category_groups) == 51000
    assert all(
        str(group["key"]).split("|", maxsplit=1)[0] in cast(dict[str, object], reconciliation["truth_table"])
        for group in category_groups
    )


def test_report_contains_only_privacy_safe_deterministic_evidence() -> None:
    payload = REPORT_PATH.read_text(encoding="utf-8")
    report = _fixture()
    privacy = cast(dict[str, object], report["privacy"])
    assert privacy == {
        "case_material": "opaque-case-identifiers-only",
        "commands_included": False,
        "local_paths_included": False,
        "resource_measurements_included": False,
    }
    assert not re.search(r"(/Users/|/home/|/tmp/|C:\\\\Users\\\\|elapsed|rss_mib|command_text)", payload)
    assert not _OPAQUE_ID.search(payload)


def test_fresh_process_report_is_environment_independent_and_bounded() -> None:
    script = Path(__file__).with_name("guard_command_decision_diff.py")
    expected_digest = report_framed_sha256(_fixture())
    metrics: list[dict[str, object]] = []
    manifest = load_seed_manifest()
    for hash_seed, timezone, locale in (("1", "UTC", "C"), ("8731", "US/Pacific", "C.UTF-8")):
        environ = os.environ.copy()
        environ.update({"PYTHONHASHSEED": hash_seed, "TZ": timezone, "LC_ALL": locale})
        completed = subprocess.run(
            [sys.executable, str(script), "--metrics"],
            check=True,
            capture_output=True,
            timeout=45,
            env=environ,
        )
        value = cast(object, json.loads(completed.stdout))
        assert isinstance(value, dict)
        metrics.append(cast(dict[str, object], value))
    assert [item["report_framed_sha256"] for item in metrics] == [expected_digest, expected_digest]
    assert all(
        float(str(item["elapsed_seconds"])) < int(str(manifest["evaluation_budget_seconds"])) for item in metrics
    )
    assert all(float(str(item["rss_mib"])) < int(str(manifest["evaluation_rss_budget_mib"])) for item in metrics)
