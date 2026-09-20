import hashlib
import json
import os
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

directory = Path("artifacts/native-installation-retirement")
directory.mkdir(parents=True, exist_ok=True)
result = directory / "results.xml"
root = ET.parse(result).getroot() if result.is_file() else None
cases = list(root.iter("testcase")) if root is not None else []
expected = {
    "test_installation_retirement_fences_actual_resident_across_processes[commit-v3]",
    "test_installation_retirement_fences_actual_resident_across_processes[commit-v4]",
    "test_installation_retirement_fences_actual_resident_across_processes[sql-refusal-v3]",
    "test_installation_retirement_fences_actual_resident_across_processes[sql-refusal-v4]",
}
passed = (
    len(cases) == len(expected)
    and {case.get("name") for case in cases} == expected
    and all(all(case.find(tag) is None for tag in ("skipped", "failure", "error")) for case in cases)
)
if root is not None:
    passed = passed and not any(node.tag in {"skipped", "failure", "error"} for node in root.iter())
    passed = passed and all(
        suite.get(field, "0") == "0"
        for suite in root.iter()
        if suite.tag in {"testsuite", "testsuites"}
        for field in ("errors", "failures", "skipped")
    )
clean = subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=no"], text=True).strip() == ""
source = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
binary = Path("rust/target/release/hol-guard-runtime")
passed = passed and clean and source == os.environ["GITHUB_SHA"] and binary.is_file()
report = {
    "schema": "native-installation-retirement-proof.v1",
    "sourceSha": source,
    "exactCleanSourceVerified": clean and source == os.environ["GITHUB_SHA"],
    "runtimeBinarySha256": hashlib.sha256(binary.read_bytes()).hexdigest() if binary.is_file() else None,
    "assertionCount": len(cases),
    "allAssertionsPassed": passed,
    "separateRotationProcess": True,
    "nativeAutoRequired": True,
    "stagedFeatureNegotiation": True,
    "canonicalEnforcement": "explicit-test-only",
    "publicationShapes": ["v3", "v4"],
    "mutationOutcomes": ["commit", "sql-refusal"],
    "hookEvents": ["PreToolUse", "PostToolUse"],
    "originalOriginProofDenominator": 8,
    "productionAdvertisement": "not-evaluated",
    "installedWheel": "not-evaluated",
    "status": "pass" if passed else "fail",
}
(directory / "proof.json").write_text(json.dumps(report, indent=2) + "\n")
print(json.dumps(report))
assert passed, "All four installation retirement cases must execute and pass against exact clean source."
