"""Codex Plugin Scanner - CLI entry point."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .models import GRADE_LABELS
from .scanner import scan_plugin

VERSION = "1.0.0"


def format_text(result) -> str:
    """Format scan result as terminal output. Uses rich if available, falls back to plain text."""
    try:
        from rich.console import Console

        console = Console()
        console.print(f"[bold cyan]🔗 Codex Plugin Scanner v{VERSION}[/bold cyan]")
        console.print(f"Scanning: {result.plugin_dir}")
        console.print()

        for category in result.categories:
            cat_score = sum(c.points for c in category.checks)
            cat_max = sum(c.max_points for c in category.checks)
            console.print(f"[bold yellow]── {category.name} ({cat_score}/{cat_max}) ──[/bold yellow]")

            for check in category.checks:
                icon = "✅" if check.passed else "⚠️"
                name_style = "[green]" if check.passed else "[red]"
                pts = f"[green]+{check.points}[/green]" if check.passed else "[red]+0[/red]"
                console.print(f"  {icon} {name_style}{check.name:<42}[/]{pts}")
            console.print()

        separator = "━" * 37
        grade = result.grade
        grade_colors = {"A": "bold green", "B": "green", "C": "yellow", "D": "red", "F": "bold red"}
        label = GRADE_LABELS.get(grade, "Unknown")
        gc = grade_colors.get(grade, "red")

        console.print(f"[bold]{separator}[/bold]")
        console.print(f"Final Score: [bold]{result.score}[/bold]/100 ([{gc}]{grade} - {label}[/{gc}])")
        console.print(f"[bold]{separator}[/bold]")
        return ""
    except ImportError:
        pass

    # Fallback: plain text output
    lines = [f"🔗 Codex Plugin Scanner v{VERSION}", f"Scanning: {result.plugin_dir}", ""]
    for category in result.categories:
        cat_score = sum(c.points for c in category.checks)
        cat_max = sum(c.max_points for c in category.checks)
        lines.append(f"── {category.name} ({cat_score}/{cat_max}) ──")
        for check in category.checks:
            icon = "✅" if check.passed else "⚠️"
            pts = f"+{check.points}" if check.passed else "+0"
            lines.append(f"  {icon} {check.name:<42} {pts}")
        lines.append("")
    separator = "━" * 37
    label = GRADE_LABELS.get(result.grade, "Unknown")
    lines += [separator, f"Final Score: {result.score}/100 ({result.grade} - {label})", separator]
    return "\n".join(lines)


def format_json(result) -> str:
    """Format scan result as JSON."""
    data = {
        "score": result.score,
        "grade": result.grade,
        "categories": [
            {
                "name": cat.name,
                "score": sum(c.points for c in cat.checks),
                "max": sum(c.max_points for c in cat.checks),
                "checks": [
                    {
                        "name": c.name,
                        "passed": c.passed,
                        "points": c.points,
                        "maxPoints": c.max_points,
                        "message": c.message,
                    }
                    for c in cat.checks
                ],
            }
            for cat in result.categories
        ],
        "timestamp": result.timestamp,
        "pluginDir": result.plugin_dir,
    }
    return json.dumps(data, indent=2)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="codex-plugin-scanner",
        description="Scan a Codex plugin directory for best practices and security",
    )
    parser.add_argument("plugin_dir", help="Path to the plugin directory to scan")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    parser.add_argument("--output", "-o", help="Write JSON report to file")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    args = parser.parse_args(argv)

    resolved = Path(args.plugin_dir).resolve()
    if not resolved.is_dir():
        print(f'Error: "{resolved}" is not a directory.', file=sys.stderr)
        sys.exit(1)

    result = scan_plugin(args.plugin_dir)

    if args.json or args.output:
        output = format_json(result)
        if args.output:
            out_path = Path(args.output)
            out_path.write_text(output, encoding="utf-8")
            print(f"Report written to {out_path}")
        else:
            print(output)
    else:
        text = format_text(result)
        if text:
            print(text)


if __name__ == "__main__":
    main()
