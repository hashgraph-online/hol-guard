"""Summarize original JUnit and require exact named RSP-100 witnesses."""

from __future__ import annotations

import hashlib
from pathlib import Path
from xml.etree import ElementTree


def summarize_pytest(xml: Path, *, approval_nodes: list[str], additional_nodes: list[str]) -> dict[str, object]:
    counts = {"xml_exists": xml.exists(), "positive_shape_controls_passed": False}
    if xml.exists():
        root = ElementTree.fromstring(xml.read_bytes())
        suites = list(root.iter("testsuite"))
        controls = {}
        for shape in ("plain", "secret", "schema", "description", "browser"):
            name = f"test_production_graph_admits_each_supported_risk_shape[{shape}]"
            found = [case for case in root.iter("testcase") if case.get("name") == name]
            controls[shape] = len(found) == 1 and not any(
                child.tag in ("failure", "error", "skipped") for child in found[0]
            )
        approval_controls = {}
        for name in approval_nodes:
            found = [case for case in root.iter("testcase") if case.get("name") == name]
            approval_controls[name] = len(found) == 1 and not any(
                child.tag in ("failure", "error", "skipped") for child in found[0]
            )
        additional_controls = {}
        for name in additional_nodes:
            found = [case for case in root.iter("testcase") if case.get("name") == name]
            additional_controls[name] = len(found) == 1 and not any(
                child.tag in ("failure", "error", "skipped") for child in found[0]
            )
        counts.update(
            {
                "tests": sum(int(suite.get("tests", "0")) for suite in suites),
                "failures": sum(int(suite.get("failures", "0")) for suite in suites),
                "errors": sum(int(suite.get("errors", "0")) for suite in suites),
                "skipped": sum(int(suite.get("skipped", "0")) for suite in suites),
                "positive_shape_controls": controls,
                "positive_shape_controls_passed": all(controls.values()),
                "positive_approval_controls": approval_controls,
                "positive_approval_controls_passed": all(approval_controls.values()),
                "additional_required_controls": additional_controls,
                "additional_required_controls_passed": all(additional_controls.values()),
                "xml_sha256": hashlib.sha256(xml.read_bytes()).hexdigest(),
                "cohorts": {
                    name: {
                        "tests": len(cases),
                        "skipped": sum(any(child.tag == "skipped" for child in case) for case in cases),
                        "failures": sum(any(child.tag in ("failure", "error") for child in case) for case in cases),
                    }
                    for name in sorted({case.get("classname", "") for case in root.iter("testcase")})
                    for cases in [[case for case in root.iter("testcase") if case.get("classname", "") == name]]
                },
                "skip_cases": [
                    {"class": case.get("classname"), "name": case.get("name"), "message": child.get("message")}
                    for case in root.iter("testcase")
                    for child in case
                    if child.tag == "skipped"
                ],
            }
        )
    return counts
