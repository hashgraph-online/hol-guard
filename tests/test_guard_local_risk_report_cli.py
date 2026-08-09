from __future__ import annotations

import argparse

from codex_plugin_scanner.guard.cli.commands import add_guard_root_parser


def test_risk_report_parser_defaults_to_json() -> None:
    parser = argparse.ArgumentParser()
    add_guard_root_parser(parser)

    args = parser.parse_args(["risk-report"])

    assert args.guard_command == "risk-report"
    assert args.format == "json"
    assert args.output is None


def test_risk_report_parser_accepts_local_html_output() -> None:
    parser = argparse.ArgumentParser()
    add_guard_root_parser(parser)

    args = parser.parse_args(["risk-report", "--format", "html", "--output", "guard-report.html"])

    assert args.guard_command == "risk-report"
    assert args.format == "html"
    assert args.output == "guard-report.html"
