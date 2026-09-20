"""Exercise the actual workflow validator with synthetic XML and binary bytes."""

from __future__ import annotations

import hashlib
import io
import json
import os
import tempfile
import unittest
import xml.etree.ElementTree as ET
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

WORKFLOW = Path(__file__).resolve().parents[1] / "scripts/ci/native_origin_resident.sh"
VALIDATOR = Path(__file__).resolve().parents[1] / "scripts/ci/native_origin_resident_evidence.py"
CASE = "test_sensitive_read_origins_reach_actual_auto_resident"
SECOND = "test_sensitive_read_signed_lockdown_and_withdrawal_reach_actual_auto_resident"
GENERIC = "test_generic_origins_reach_actual_auto_resident"
GENERIC_CONTROL = "test_generic_signed_lockdown_and_withdrawal_reach_actual_auto_resident"
GENERIC_DEFAULT_SYNC = "test_ordinary_generic_sync_requires_actual_auto_resident_acceptance[defaults]"
GENERIC_SCOPED_SYNC = "test_ordinary_generic_sync_requires_actual_auto_resident_acceptance[scoped]"
DEFAULTS_ENFORCE = "test_signed_defaults_preserve_both_hook_events_in_actual_auto_resident[enforce]"
DEFAULTS_OBSERVE = "test_signed_defaults_preserve_both_hook_events_in_actual_auto_resident[observe]"
SOURCE = "a" * 40


class SensitiveResidentEvidenceTests(unittest.TestCase):
    def execute(
        self,
        xml: str | None,
        *,
        source: str = SOURCE,
        dirty: bool = False,
        binary: bool = True,
    ):
        code = compile(VALIDATOR.read_text(), str(VALIDATOR), "exec")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "artifacts/native-sensitive-resident"
            evidence.mkdir(parents=True)
            if xml is not None:
                (evidence / "results.xml").write_text(xml)
            if binary:
                runtime = root / "rust/target/release/hol-guard-runtime"
                runtime.parent.mkdir(parents=True)
                runtime.write_bytes(b"synthetic-validator-test-binary")
            prior = Path.cwd()
            failure = None
            try:
                os.chdir(root)
                with (
                    patch.dict(os.environ, {"GITHUB_SHA": SOURCE}),
                    patch(
                        "subprocess.check_output",
                        side_effect=[" M synthetic-file" if dirty else "", source],
                    ),
                    redirect_stdout(io.StringIO()),
                ):
                    try:
                        exec(code, {})
                    except (AssertionError, ET.ParseError) as error:
                        failure = type(error).__name__
            finally:
                os.chdir(prior)
            report = evidence / "proof.json"
            return failure, json.loads(report.read_text()) if report.exists() else None

    def case(self, children: str = "", name: str = CASE):
        return (
            f'<testcase name="{name}">{children}</testcase><testcase name="{SECOND}"/>'
            f'<testcase name="{GENERIC}"/><testcase name="{GENERIC_CONTROL}"/>'
            f'<testcase name="{GENERIC_DEFAULT_SYNC}"/><testcase name="{GENERIC_SCOPED_SYNC}"/>'
            f'<testcase name="{DEFAULTS_ENFORCE}"/><testcase name="{DEFAULTS_OBSERVE}"/>'
        )

    def test_only_exact_completed_case_emits_passing_source_scoped_report(self):
        failure, report = self.execute("<testsuite>" + self.case() + "</testsuite>")
        self.assertIsNone(failure)
        assert report is not None
        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["schema"], "native-origin-resident-proof.v1")
        self.assertEqual(report["assertionCount"], 8)
        self.assertEqual(report["defaultsHookModes"], ["enforce", "observe"])
        self.assertEqual(report["defaultsHookEvents"], ["PreToolUse", "PostToolUse"])
        self.assertEqual(report["genericSignedSyncShapes"], ["defaults", "scoped"])
        self.assertEqual(report["genericOriginVectorCount"], 260)
        self.assertEqual(report["sourceSha"], SOURCE)
        self.assertEqual(
            report["runtimeBinarySha256"],
            hashlib.sha256(b"synthetic-validator-test-binary").hexdigest(),
        )
        self.assertTrue(report["stagedFeatureNegotiation"])
        self.assertEqual(report["canonicalEnforcement"], "explicit-test-only")
        self.assertEqual(report["sourceAdmission"], "loaded-mdm-test-file-and-ordinary-signed-sync")
        self.assertTrue(report["nativeAutoRequired"])
        for field in (
            "productionAdvertisement",
            "installedWheel",
        ):
            self.assertEqual(report[field], "not-evaluated")

    def test_workflow_requires_auto_and_the_exact_slow_fixture(self):
        source = WORKFLOW.read_text()
        self.assertIn("export HOL_GUARD_NATIVE=auto", source)
        self.assertNotIn("export HOL_GUARD_NATIVE=force", source)
        self.assertIn("export HOL_GUARD_NATIVE_BINARY=", source)
        self.assertIn("test_sensitive_resident_fixture_uses_actual_loaded_origins", source)
        self.assertIn("pytest -q -m slow tests/test_native_sensitive_policy_resident.py", source)
        self.assertIn("tests/test_native_generic_sync_resident.py --junitxml=", source)

    def test_absent_wrong_and_duplicate_case_identities_fail(self):
        for xml in (
            None,
            "<testsuite/>",
            f'<testsuite><testcase name="{CASE}"/></testsuite>',
            f'<testsuite><testcase name="{SECOND}"/></testsuite>',
            f'<testsuite><testcase name="{CASE}"/><testcase name="{SECOND}"/></testsuite>',
            "<testsuite>" + self.case(name="wrong") + "</testsuite>",
            "<testsuite>" + self.case() * 2 + "</testsuite>",
        ):
            with self.subTest(xml=xml):
                failure, report = self.execute(xml)
                self.assertEqual(failure, "AssertionError")
                assert report is not None
                self.assertEqual(report["status"], "fail")

    def test_every_nonpass_marker_fails_including_suite_level_markers(self):
        for marker in ("failure", "error", "skipped"):
            for xml in (
                "<testsuite>" + self.case(f"<{marker}/>") + "</testsuite>",
                "<testsuite>" + self.case() + f"<{marker}/></testsuite>",
                "<testsuite>"
                + self.case().replace(
                    f'<testcase name="{GENERIC}"/>', f'<testcase name="{GENERIC}"><{marker}/></testcase>'
                )
                + "</testsuite>",
                "<testsuite>"
                + self.case().replace(
                    f'<testcase name="{GENERIC_CONTROL}"/>',
                    f'<testcase name="{GENERIC_CONTROL}"><{marker}/></testcase>',
                )
                + "</testsuite>",
            ):
                with self.subTest(marker=marker, xml=xml):
                    failure, report = self.execute(xml)
                    self.assertEqual(failure, "AssertionError")
                    assert report is not None
                    self.assertFalse(report["allAssertionsPassed"])

    def test_each_generic_sync_shape_must_complete_and_pass(self):
        for name in (GENERIC_DEFAULT_SYNC, GENERIC_SCOPED_SYNC, DEFAULTS_ENFORCE, DEFAULTS_OBSERVE):
            for replacement in (
                "",
                f'<testcase name="{name}"><skipped/></testcase>',
                f'<testcase name="{name}"><failure/></testcase>',
            ):
                with self.subTest(name=name, replacement=replacement):
                    xml = (
                        "<testsuite>" + self.case().replace(f'<testcase name="{name}"/>', replacement) + "</testsuite>"
                    )
                    failure, report = self.execute(xml)
                    self.assertEqual(failure, "AssertionError")
                    assert report is not None
                    self.assertFalse(report["allAssertionsPassed"])

    def test_declared_nonpass_suite_counts_cannot_be_ignored(self):
        for field in ("errors", "failures", "skipped"):
            failure, report = self.execute(
                f'<testsuites {field}="1"><testsuite>' + self.case() + "</testsuite></testsuites>"
            )
            self.assertEqual(failure, "AssertionError")
            assert report is not None
            self.assertEqual(report["status"], "fail")

    def test_wrong_or_dirty_source_and_absent_binary_fail(self):
        for source, dirty, binary in (("b" * 40, False, True), (SOURCE, True, True), (SOURCE, False, False)):
            failure, report = self.execute(
                "<testsuite>" + self.case() + "</testsuite>", source=source, dirty=dirty, binary=binary
            )
            self.assertEqual(failure, "AssertionError")
            assert report is not None
            self.assertEqual(report["status"], "fail")

    def test_malformed_xml_never_creates_a_passing_report(self):
        failure, report = self.execute("<testsuite")
        self.assertEqual(failure, "ParseError")
        self.assertIsNone(report)


if __name__ == "__main__":
    unittest.main()
