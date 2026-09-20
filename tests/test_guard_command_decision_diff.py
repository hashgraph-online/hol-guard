"""Contracts for the signed deterministic command decision-diff report."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard.action_lattice import guard_action_severity, is_guard_action
from tests.guard_command_corpus import load_seed_manifest
from tests.guard_command_corpus_native_contract import (
    expected_native_groups,
    expected_native_rejection_groups,
    expected_original_gap_groups,
)
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


def teardown_module() -> None:
    from codex_plugin_scanner.guard.cli.commands_support import _sync_namespace

    _sync_namespace()


def test_decision_diff_import_does_not_shadow_scanner_package_exports() -> None:
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import tests.guard_command_decision_diff; "
                "from codex_plugin_scanner import __version__, scan_plugin; "
                "from codex_plugin_scanner.submission import build_submission_payload; "
                "assert __version__; assert callable(scan_plugin); "
                "assert callable(build_submission_payload)"
            ),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr


def test_fresh_worker_import_loads_packaged_resources_without_scanner_exports() -> None:
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import sys; "
                "from importlib.resources import files; "
                "from tests import guard_command_decision_diff_runner as runner; "
                "guard_root = runner.REPO_ROOT / 'src' / 'codex_plugin_scanner' / 'guard'; "
                "resource = 'contracts/data/extensions/command-catalog.v1.json'; "
                "assert files('codex_plugin_scanner.guard').joinpath(resource).read_bytes() "
                "== (guard_root / resource).read_bytes(); "
                "assert 'scan_plugin' not in sys.modules['codex_plugin_scanner'].__dict__"
            ),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr


def test_decision_diff_import_restores_preloaded_package_bindings() -> None:
    scripts = (
        (
            "import sys; "
            "import codex_plugin_scanner as scanner; "
            "marker = object(); previous = getattr(scanner, 'guard', marker); "
            "import tests.guard_command_decision_diff; "
            "assert getattr(scanner, 'guard', marker) is previous; "
            "from codex_plugin_scanner.guard import models; "
            "assert models is sys.modules['codex_plugin_scanner.guard.models']"
        ),
        (
            "import sys; "
            "import codex_plugin_scanner.guard as guard; "
            "import codex_plugin_scanner.guard.runtime as runtime; "
            "guard_modules = {k: v for k, v in guard.__dict__.items() "
            "if getattr(v, '__name__', '').startswith('codex_plugin_scanner.')}; "
            "runtime_modules = {k: v for k, v in runtime.__dict__.items() "
            "if getattr(v, '__name__', '').startswith('codex_plugin_scanner.')}; "
            "import tests.guard_command_decision_diff; "
            "assert guard_modules == {k: v for k, v in guard.__dict__.items() "
            "if getattr(v, '__name__', '').startswith('codex_plugin_scanner.')}; "
            "assert runtime_modules == {k: v for k, v in runtime.__dict__.items() "
            "if getattr(v, '__name__', '').startswith('codex_plugin_scanner.')}; "
            "from codex_plugin_scanner.guard.runtime import effect_decision; "
            "assert effect_decision is sys.modules['codex_plugin_scanner.guard.runtime.effect_decision']"
        ),
    )
    for script in scripts:
        completed = subprocess.run(
            [sys.executable, "-c", script],
            check=False,
            capture_output=True,
            text=True,
        )
        assert completed.returncode == 0, completed.stderr


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
        "contracts/extensions/command-catalog.v1.json",
        "contracts/extensions/native-command-program.v1.json",
        "docs/guard/native-command-corpus-contract.md",
        "docs/guard/declarative-authoring-adr.md",
        "rust/crates/guard-command/src/native_command_source_evaluation_batch.rs",
        "rust/crates/guard-command/src/native_command_source.rs",
        "rust/crates/guard-command/src/bin/guard-command-source.rs",
        "tests/guard_command_corpus_native.py",
        "tests/guard_command_corpus_native_contract.py",
        "tests/test_guard_command_corpus_native_contract.py",
        "tests/guard_test_invariants.py",
        "tests/native_command_test_support.py",
        "tests/test_native_command_test_support_batch.py",
        "tests/test_guard_native_classification_baseline.py",
        "src/codex_plugin_scanner/guard/runtime/command_decision_adapter.py",
        "src/codex_plugin_scanner/guard/runtime/command_extensions.py",
        "src/codex_plugin_scanner/guard/runtime/command_model.py",
        "src/codex_plugin_scanner/guard/runtime/effect_contract.py",
        "src/codex_plugin_scanner/guard/runtime/extension_evidence.py",
        "src/codex_plugin_scanner/guard/runtime/command_contained_routine_candidates.py",
        "src/codex_plugin_scanner/guard/runtime/command_verified_read_candidates.py",
        "src/codex_plugin_scanner/guard/runtime/command_workspace_write_candidates.py",
        "src/codex_plugin_scanner/guard/runtime/containment_outputs.py",
        "src/codex_plugin_scanner/guard/runtime/local_package_script_evidence.py",
        "src/codex_plugin_scanner/guard/runtime/verified_github_reads.py",
        "src/codex_plugin_scanner/guard/runtime/verified_read_execution.py",
        "src/codex_plugin_scanner/guard/runtime/verified_read_common.py",
        "src/codex_plugin_scanner/guard/cli/commands_verified_read.py",
        "src/codex_plugin_scanner/guard/cli/commands_contained_write.py",
        "src/codex_plugin_scanner/guard/cli/commands_parser_local.py",
        "src/codex_plugin_scanner/guard/cli/commands_router.py",
        "src/codex_plugin_scanner/guard/cli/commands_parser.py",
        "src/codex_plugin_scanner/guard/cli/commands_support.py",
        "src/codex_plugin_scanner/guard/contained_package_script_execution.py",
        "src/codex_plugin_scanner/guard/contained_workspace_write_execution.py",
        "src/codex_plugin_scanner/guard/durable_harness_launcher.py",
        "src/codex_plugin_scanner/guard/package_shim_gate.py",
        "src/codex_plugin_scanner/guard/package_shim_frozen.py",
        "src/codex_plugin_scanner/guard/shims.py",
        "tests/test_guard_contained_package_script_execution.py",
        "tests/test_guard_contained_workspace_write_contract.py",
        "tests/test_guard_contained_workspace_write_execution.py",
        "tests/test_guard_package_shims.py",
    }
    assert {source_binding_id(path) for path in critical_paths} <= sources.keys()


def test_report_gates_native_parity_and_preserves_every_original_oracle_difference() -> None:
    report = _fixture()
    manifest = load_seed_manifest()
    corpus = cast(dict[str, object], report["corpus"])
    assert corpus["benign_count"] == 1000
    assert corpus["adversarial_count"] == 50000
    assert corpus["total_count"] == 51000
    assert corpus["canonical_digests"] == manifest["canonical_digests"]

    comparison = cast(dict[str, object], report["current_vs_proposed"])
    assert comparison["lowered_count"] == 0
    assert comparison["action_changed_count"] == 0
    assert comparison["disposition_changed_count"] == 0
    assert (
        sum(
            int(str(cast(dict[str, object], group)["count"]))
            for group in cast(list[object], comparison["transition_groups"])
        )
        == 51000
    )

    for group in cast(list[dict[str, object]], comparison["transition_groups"]):
        current_action, current_disposition, proposed_action, proposed_disposition = str(group["key"]).split("|")
        assert (current_action, current_disposition) == (proposed_action, proposed_disposition)

    native_floor = cast(dict[str, object], report["native_floor_to_current"])
    assert native_floor["lowered_count"] == 0
    floor_groups = cast(list[dict[str, object]], native_floor["transition_groups"])
    assert sum(int(str(group["count"])) for group in floor_groups) == 51_000
    for group in floor_groups:
        before, after = str(group["key"]).split("|")
        assert is_guard_action(before) and is_guard_action(after)
        assert guard_action_severity(before) <= guard_action_severity(after)

    native_contract = cast(dict[str, object], report["native_contract"])
    assert native_contract["equality"] is True
    assert native_contract["matched_count"] == 51_000
    assert native_contract["unexpected_count"] == 0
    assert _group_signatures(native_contract["groups"]) == expected_native_groups()
    assert _group_signatures(native_contract["native_rejection_groups"]) == expected_native_rejection_groups()
    assert native_contract["native_rejection_count"] == 27_084

    reconciliation = cast(dict[str, object], report["oracle_reconciliation"])
    assert reconciliation["known_gap_equality"] is False
    assert reconciliation["categorized_count"] == 51_000
    assert reconciliation["uncategorized_count"] == 0
    assert reconciliation["below_original_count"] == 0
    assert reconciliation["above_original_count"] == 11_558
    original_gaps = cast(dict[str, list[object]], reconciliation["known_gaps"])
    gap_signatures = {key: (int(str(value[0])), str(value[1])) for key, value in original_gaps.items()}
    assert gap_signatures == expected_original_gap_groups()
    category_groups = cast(list[dict[str, object]], reconciliation["category_groups"])
    assert sum(int(str(group["count"])) for group in category_groups) == 51000
    assert all(
        str(group["key"]).split("|", maxsplit=1)[0] in cast(dict[str, object], reconciliation["truth_table"])
        for group in category_groups
    )


def _group_signatures(value: object) -> dict[str, tuple[int, str]]:
    assert isinstance(value, list)
    groups = cast(list[dict[str, object]], value)
    result = {str(group["key"]): (int(str(group["count"])), str(group["case_ids_framed_sha256"])) for group in groups}
    assert len(result) == len(groups)
    return result


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


@pytest.mark.parametrize(
    ("hash_seed", "timezone", "locale"),
    [("1", "UTC", "C"), ("8731", "US/Pacific", "C.UTF-8")],
    ids=["utc", "pacific"],
)
def test_fresh_process_report_is_environment_independent_and_bounded(
    hash_seed: str, timezone: str, locale: str
) -> None:
    script = Path(__file__).with_name("guard_command_decision_diff.py")
    expected_digest = report_framed_sha256(_fixture())
    manifest = load_seed_manifest()
    evaluation_budget_seconds = int(str(manifest["evaluation_budget_seconds"]))
    spawn_overhead_seconds = 15
    environ = os.environ.copy()
    environ.update({"PYTHONHASHSEED": hash_seed, "TZ": timezone, "LC_ALL": locale})
    completed = subprocess.run(
        [sys.executable, str(script), "--metrics"],
        check=True,
        capture_output=True,
        timeout=evaluation_budget_seconds + spawn_overhead_seconds,
        env=environ,
    )
    value = cast(object, json.loads(completed.stdout))
    assert isinstance(value, dict)
    metrics = cast(dict[str, object], value)
    assert metrics["report_framed_sha256"] == expected_digest
    assert float(str(metrics["elapsed_seconds"])) < evaluation_budget_seconds + spawn_overhead_seconds, metrics
    assert float(str(metrics["rss_mib"])) < int(str(manifest["evaluation_rss_budget_mib"])), metrics
