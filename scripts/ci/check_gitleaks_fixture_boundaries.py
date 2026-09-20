"""Prove exact synthetic fixture exceptions retain detection of new credentials."""

from __future__ import annotations

import argparse
import ast
import base64
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import tomllib

DEFAULT_GLOBAL_STOPWORDS = (
    "abcdefghijklmnopqrstuvwxyz",
    "014df517-39d1-4453-b7b3-9930c563627c",
)


PEM_PATHS = (
    "tests/test_guard_cli.py",
    "tests/test_guard_kubernetes_runtime.py",
    "tests/test_guard_package_firewall_entitlement.py",
    "tests/test_guard_product_flow.py",
    "tests/test_guard_source_view_secret_fixtures.py",
    "tests/test_guard_store_migrations.py",
    "tests/test_guard_surface_server.py",
)


def _literal_pattern(value: str) -> str:
    escaped = re.sub(r"([\\.+*?()|\[\]{}^$])", r"\\\1", value)
    return "^" + escaped.replace("ghp_", r"\x67hp_") + "$"


def _exact_value(pattern: str) -> str:
    if not pattern.startswith("^") or not pattern.endswith("$"):
        raise ValueError("fixture exceptions must match complete values")
    value = re.sub(
        r"\\x([0-9a-fA-F]{2})|\\(.)",
        lambda match: chr(int(match[1], 16)) if match[1] is not None else match[2],
        pattern[1:-1],
    )
    if pattern != _literal_pattern(value) or re.fullmatch(pattern, value) is None:
        raise ValueError("fixture exception is not one exact value")
    return value


def _new_value(rule_id: str) -> str:
    value = "a13b5c7d9e024f68" * 4
    if rule_id == "generic-api-key":
        return f'control_secret = "{value}"'
    if rule_id == "github-pat":
        return 'control_token = "ghp_' + value[:36] + '"'
    if rule_id == "curl-auth-header":
        return '\x63url -H "Authorization: Bearer ' + value + '" https://example.invalid'
    if rule_id == "curl-auth-user":
        return '\x63url \x2du "control:' + value + '" https://example.invalid'
    raise ValueError("unrecognized fixture rule")


def _canary_source(source: str, known: str) -> str:
    """Expose an encoded synthetic literal only in an equivalent canary input."""
    if known in source:
        return source
    parsed = ast.parse(source)
    original_tree = ast.dump(parsed, include_attributes=False)
    raw = source.encode("utf-8")
    lines = raw.splitlines(keepends=True)
    literals = [
        node
        for node in ast.walk(parsed)
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and known in node.value
    ]
    if len(literals) != 1:
        raise ValueError("audited fixture value must identify one source literal")
    for node in literals:
        start = sum(map(len, lines[: node.lineno - 1])) + node.col_offset
        end = sum(map(len, lines[: node.end_lineno - 1])) + node.end_col_offset
        candidate = (raw[:start] + repr(node.value).encode("utf-8") + raw[end:]).decode("utf-8")
        if known not in candidate:
            continue
        try:
            equivalent = ast.dump(ast.parse(candidate), include_attributes=False) == original_tree
        except SyntaxError:
            continue
        if equivalent:
            return candidate
    raise ValueError("audited fixture value is no longer in an equivalent source literal")


def _detect(
    scanner: Path,
    root: Path,
    *,
    case: str,
    path: str,
    rule_id: str,
    content: str,
    config: Path,
) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="gitleaks-fixture-", dir=root) as temporary:
        work = Path(temporary)
        target = work / path
        target.parent.mkdir(parents=True)
        target.write_text(content, encoding="utf-8")
        shutil.copyfile(config, work / ".gitleaks.toml")
        report = work / "findings.json"
        result = subprocess.run(
            [
                str(scanner),
                "dir",
                "--no-banner",
                "--redact=100",
                "--exit-code",
                "1",
                "--report-format",
                "json",
                "--report-path",
                str(report),
                ".",
            ],
            cwd=work,
            capture_output=True,
            timeout=20,
            check=False,
        )
        findings = json.loads(report.read_text()) if report.is_file() else []
        matched = [item for item in findings if item.get("RuleID") == rule_id]
        evidence = {
            "case": case,
            "path": path,
            "ruleId": rule_id,
            "scanExit": result.returncode,
            "findingCount": len(findings),
            "expectedRuleCount": len(matched),
        }
        evidence["controlPassed"] = result.returncode == 1 and bool(matched)
        return evidence


def main(scanner: Path) -> None:
    os.umask(0o077)
    scanner = scanner.resolve(strict=True)
    repository = Path(__file__).resolve().parents[2]
    config = repository / ".gitleaks.toml"
    settings = tomllib.loads(config.read_text())
    if settings.get("extend") != {"useDefault": True}:
        raise ValueError("default scanner rules must remain enabled")
    if settings.get("allowlist") != {"stopwords": list(DEFAULT_GLOBAL_STOPWORDS)}:
        raise ValueError("only the pinned default global stopwords may be preserved")
    evidence = []
    canonicalized_fixtures = 0
    with tempfile.TemporaryDirectory(prefix="gitleaks-boundaries-") as temporary:
        root = Path(temporary)
        for rule in settings["rules"]:
            rule_id = rule["id"]
            if rule_id == "private-key" or set(rule) != {"id", "allowlists"}:
                raise ValueError("fixture config must not redefine default detectors")
            for entry in rule["allowlists"]:
                expected_target = "match" if rule_id == "curl-auth-user" else "secret"
                if entry.get("condition") != "AND" or entry.get("regexTarget") != expected_target:
                    raise ValueError("fixture exceptions require exact path and value")
                if set(entry) != {"description", "condition", "regexTarget", "paths", "regexes"}:
                    raise ValueError("unrecognized fixture exception criterion")
                if len(entry["paths"]) != 1:
                    raise ValueError("each fixture exception requires one path")
                path = _exact_value(entry["paths"][0])
                if Path(path).is_absolute() or ".." in Path(path).parts:
                    raise ValueError("fixture path must remain in the repository")
                source = (repository / path).read_text()
                for index, expression in enumerate(entry["regexes"]):
                    known = _exact_value(expression)
                    fixture_source = _canary_source(source, known)
                    canonicalized_fixtures += int(fixture_source != source)
                    lines = fixture_source.splitlines(keepends=True)
                    if expected_target == "match":
                        start = fixture_source.find(known)
                        end = start + len(known.rstrip("\r\n"))
                        positions = (
                            range(fixture_source[:start].count("\n"), fixture_source[:end].count("\n") + 1)
                            if start >= 0
                            else []
                        )
                    else:
                        position = next((i for i, line in enumerate(lines) if known in line), None)
                        positions = [position] if position is not None else []
                    if not positions:
                        raise ValueError("audited fixture value is no longer in its source")
                    for position in positions:
                        for kind in ("same-line", "adjacent-line"):
                            changed = list(lines)
                            separator = " " if kind == "same-line" else "\n"
                            changed[position] = (
                                changed[position].rstrip("\r\n") + separator + _new_value(rule_id) + "\n"
                            )
                            case = f"{rule_id}:{index}:{kind}"
                            if expected_target == "match":
                                case += f":line-{position + 1}"
                            evidence.append(
                                _detect(
                                    scanner,
                                    root,
                                    case=case,
                                    path=path,
                                    rule_id=rule_id,
                                    content="".join(changed),
                                    config=config,
                                )
                            )
                    evidence.append(
                        _detect(
                            scanner,
                            root,
                            case=f"{rule_id}:{index}:different-path",
                            path="tests/gitleaks-boundary-controls/" + Path(path).name,
                            # The default filter prefers the specific PAT finding here.
                            rule_id=(
                                "github-pat"
                                if rule_id == "generic-api-key" and path == "tests/test_guard_runtime.py"
                                else rule_id
                            ),
                            content=fixture_source,
                            config=config,
                        )
                    )

        for path in PEM_PATHS:
            source = (repository / path).read_text()
            marker = re.compile("-----BEGIN" + r"[ A-Z0-9_-]{0,100}PRIVATE KEY", re.IGNORECASE)
            constants = (
                node.value
                for node in ast.walk(ast.parse(source))
                if isinstance(node, ast.Constant) and isinstance(node.value, str)
            )
            header = next(line for value in constants for line in value.splitlines() if marker.search(line))
            # Parse adjacent literals without importing or executing the fixture.
            # Retain its actual header line while adding a complete generated body.
            # This exercises the pinned detector's multiline match without using a key.
            body = base64.b64encode(bytes(range(256))).decode("ascii")
            footer = "-----END " + "PRIVATE KEY-----"
            control = header + "\n" + body + "\n" + footer + "\n"
            evidence.append(
                _detect(
                    scanner,
                    root,
                    case="private-key:unchanged-header-multiline",
                    path=path,
                    rule_id="private-key",
                    content=control,
                    config=config,
                )
            )
    print(
        json.dumps(
            {
                "scanner": "gitleaks v8.24.2",
                "controlsRun": len(evidence),
                "controlsPassed": sum(bool(item["controlPassed"]) for item in evidence),
                "controlsFailed": sum(not item["controlPassed"] for item in evidence),
                "astEquivalentFixtureInputs": canonicalized_fixtures,
                "rawFindingValuesRetained": False,
                "controls": evidence,
            },
            sort_keys=True,
        )
    )
    if not all(item["controlPassed"] for item in evidence):
        raise RuntimeError("a fixture exception suppressed a new credential control")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gitleaks", type=Path, required=True)
    main(parser.parse_args().gitleaks)
