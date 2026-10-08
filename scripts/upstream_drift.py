#!/usr/bin/env python3
"""Report reviewed command extensions whose pinned upstream has moved.

Command sources record the upstream they were reviewed against: a GitHub
tree/blob URL at a full commit, or an npm package page at an exact version.
This check compares each pin with the upstream's current release (the latest
GitHub release, else the default branch; npm ``latest``) and names the proofs
that no longer describe current upstream behavior: extension packs that list
the extension and Gauntlet scenarios bound to it.

The check only reads. It never edits a source, trust binding or proof, and it
never publishes. A drift report exits 1 so a scheduled run leaves a failed job
with the report in its summary; the fix is a reviewed source update.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

REPOSITORY = Path(__file__).resolve().parents[1]
SCHEMA = "hol.guard.upstream-drift.v1"
_GITHUB_PIN = re.compile(r"^https://github\.com/([\w.-]+)/([\w.-]+)/(?:tree|blob)/([0-9a-f]{40})(?:/|$)")
_NPM_PIN = re.compile(r"^https://www\.npmjs\.com/package/((?:@[\w.-]+/)?[\w.-]+)/v/([\w.+-]+)$")
_TIMEOUT_SECONDS = 20
_DETAIL_LIMIT = 300

Fetch = Callable[[str], Any]


class NotFoundError(Exception):
    """An upstream endpoint answered 404."""


@dataclass(frozen=True)
class Pin:
    """One upstream an extension source was reviewed against."""

    extension_id: str
    kind: str
    project: str
    pinned: str
    source: str


@dataclass
class Finding:
    """Comparison of one pin with its upstream's current release."""

    pin: Pin
    status: str
    current: str | None = None
    detail: str = ""
    affected_packs: list[str] = field(default_factory=list)
    affected_scenarios: list[str] = field(default_factory=list)


def pins(repository: Path) -> list[Pin]:
    """Return every exact upstream pin recorded by a reviewed command source."""
    found = []
    for path in sorted((repository / "contributions/command-sources").glob("*.json")):
        extension = json.loads(path.read_text(encoding="utf-8")).get("extension")
        if not isinstance(extension, dict):
            continue
        source = path.relative_to(repository).as_posix()
        for url in extension.get("reference_urls") or ():
            if match := _GITHUB_PIN.match(url):
                owner, name, sha = match.groups()
                found.append(Pin(extension["extension_id"], "github", f"{owner}/{name}", sha, source))
            elif match := _NPM_PIN.match(url):
                package, version = match.groups()
                found.append(Pin(extension["extension_id"], "npm", package, version, source))
    return found


def pack_members(repository: Path) -> dict[str, list[str]]:
    """Map extension ids to the extension packs that list them."""
    members: dict[str, list[str]] = {}
    for path in sorted((repository / "contributions/extension-packs").glob("*.json")):
        pack = json.loads(path.read_text(encoding="utf-8"))
        for entry in pack.get("extensions") or ():
            members.setdefault(entry["extensionId"], []).append(pack["packId"])
    return members


def gauntlet_scenarios(repository: Path) -> dict[str, list[str]]:
    """Map extension ids to Gauntlet scenarios whose oracle is bound to them."""
    sys.path.insert(0, str(repository))
    try:
        from ci.gauntlet.catalog import load_catalog
        from ci.gauntlet.extension_adapters import extension_adapter
    finally:
        sys.path.remove(str(repository))
    bound: dict[str, list[str]] = {}
    for scenario in load_catalog(repository / "ci/gauntlet/scenarios.json"):
        if scenario.oracle == "blocked-extension":
            bound.setdefault(extension_adapter(scenario.commands[0]).extension_id, []).append(scenario.id)
    return bound


def http_json(url: str) -> Any:
    """GET a JSON document from GitHub or npm, using a read token if one is set."""
    request = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "hol-guard-drift"})
    token = os.environ.get("GITHUB_TOKEN")
    if token and url.startswith("https://api.github.com/"):
        request.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(request, timeout=_TIMEOUT_SECONDS) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        if error.code == 404:
            raise NotFoundError(url) from error
        raise RuntimeError(f"GET {url} returned HTTP {error.code} {error.reason}") from error
    except urllib.error.URLError as error:
        raise RuntimeError(f"GET {url} failed: {error.reason}") from error


def _github(pin: Pin, fetch: Fetch) -> tuple[str, str | None, str]:
    api = f"https://api.github.com/repos/{pin.project}"
    try:
        target = fetch(f"{api}/releases/latest")["tag_name"]
    except NotFoundError:
        target = fetch(api)["default_branch"]
    head = urllib.parse.quote(target, safe="")
    comparison = fetch(f"{api}/compare/{pin.pinned}...{head}")
    status = "current" if comparison["status"] in {"identical", "behind"} else "drifted"
    return status, target, f"{comparison.get('ahead_by', 0)} commit(s) after the reviewed pin"


def _npm(pin: Pin, fetch: Fetch) -> tuple[str, str | None, str]:
    package = urllib.parse.quote(pin.project, safe="@")
    latest = fetch(f"https://registry.npmjs.org/{package}")["dist-tags"]["latest"]
    return ("current" if latest == pin.pinned else "drifted"), latest, "npm latest dist-tag"


def check(
    found: Iterable[Pin],
    fetch: Fetch,
    packs: dict[str, list[str]],
    scenarios: dict[str, list[str]],
) -> list[Finding]:
    """Compare each pin; upstream errors are reported, never treated as current."""
    findings = []
    for pin in found:
        try:
            status, current, detail = (_github if pin.kind == "github" else _npm)(pin, fetch)
        except Exception as error:
            reason = " ".join(str(error).split())[:_DETAIL_LIMIT]
            status, current, detail = "unknown", None, f"upstream check failed: {type(error).__name__}: {reason}"
        finding = Finding(pin, status, current, detail)
        if status != "current":
            finding.affected_packs = packs.get(pin.extension_id, [])
            finding.affected_scenarios = scenarios.get(pin.extension_id, [])
        findings.append(finding)
    return findings


def summary(findings: list[Finding]) -> str:
    """Render a maintainer-facing Markdown summary."""
    lines = ["## Upstream drift", ""]
    stale = [item for item in findings if item.status != "current"]
    if not stale:
        lines.append(f"All {len(findings)} reviewed upstream pins match their current release.")
        return "\n".join(lines) + "\n"
    lines += [
        "| Extension | Upstream | Reviewed | Current | Status | Stale proofs |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for item in stale:
        proofs = ", ".join(item.affected_packs + item.affected_scenarios) or "none"
        lines.append(
            f"| `{item.pin.extension_id}` | {item.pin.kind}:{item.pin.project} | `{item.pin.pinned[:12]}` "
            f"| `{item.current or '?'}` | {item.status}: {item.detail} | {proofs} |"
        )
    lines += ["", "Review the upstream change, then update the command source pin and rerun the listed proofs."]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--repository", type=Path, default=REPOSITORY)
    parser.add_argument("--json", type=Path, help="write the machine-readable report here")
    args = parser.parse_args(argv)
    findings = check(
        pins(args.repository), http_json, pack_members(args.repository), gauntlet_scenarios(args.repository)
    )
    if args.json:
        report = {"schema": SCHEMA, "findings": [asdict(item) for item in findings]}
        args.json.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    text = summary(findings)
    print(text, end="")
    if step_summary := os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(step_summary, "a", encoding="utf-8") as handle:
            handle.write(text)
    return 0 if all(item.status == "current" for item in findings) else 1


if __name__ == "__main__":
    raise SystemExit(main())
