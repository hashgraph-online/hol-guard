import hashlib
import json
import os
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

directory = Path("artifacts/native-managed-resident")
directory.mkdir(parents=True, exist_ok=True)
result = directory / "results.xml"
cases = list(ET.parse(result).getroot().iter("testcase")) if result.is_file() else []
expected = {
    "test_signed_managed_lockdown_is_consumed_by_actual_resident[enforce]",
    "test_signed_managed_lockdown_is_consumed_by_actual_resident[observe]",
}
passed = (
    len(cases) == len(expected)
    and {case.get("name") for case in cases} == expected
    and all(all(case.find(tag) is None for tag in ("skipped", "failure", "error")) for case in cases)
)
clean = subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=no"], text=True).strip() == ""
source = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
binary = Path("rust/target/release/hol-guard-runtime")
passed = passed and clean and source == os.environ["GITHUB_SHA"] and binary.is_file()
report = {
    "schema": "native-managed-resident-proof.v1",
    "sourceSha": source,
    "exactCleanSourceVerified": clean and source == os.environ["GITHUB_SHA"],
    "runtimeBinarySha256": hashlib.sha256(binary.read_bytes()).hexdigest() if binary.is_file() else None,
    "assertionCount": len(cases),
    "allAssertionsPassed": passed,
    "stagedFeatureNegotiation": True,
    "productionAdvertisement": "not-evaluated",
    "installedWheel": "not-evaluated",
    "status": "pass" if passed else "fail",
}
(directory / "proof.json").write_text(json.dumps(report, indent=2) + "\n")
print(json.dumps(report))
assert passed, "Both managed resident cases must execute and pass against exact clean source."
