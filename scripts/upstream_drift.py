#!/usr/bin/env python3
"""Report reviewed command extensions whose pinned upstream has moved.

Command sources record the upstream they were reviewed against: a GitHub
tree/blob URL at a full commit, or an npm package page at an exact version.
This check compares each pin with the upstream's current release (the latest
GitHub release, else the default branch; npm ``latest``) and names the proofs
that no longer describe current upstream behavior: extension packs that list
the extension and Gauntlet scenarios bound to it.

Some extensions also depend on a provider API description that the CLI reads at
runtime. For those, ``contributions/upstream-schemas`` records the reviewed
Google Discovery shape of each method the rules match, the request schemas it
reaches and the method list of its resource. A changed method or request shape,
a removed method or a new sibling method is reported the same way as a moved
release pin.

The check only reads. It never edits a source, trust binding or proof, and it
never publishes. A drift report exits 1 so a scheduled run leaves a failed job
with the report in its summary; the fix is a reviewed source update.
"""

from __future__ import annotations

import argparse
import hashlib
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
_DISCOVERY_URL = "https://www.googleapis.com/discovery/v1/apis/{name}/{version}/rest"
_DISCOVERY_SCHEMA = "hol.guard.upstream-discovery-pins.v1"
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
    expected: tuple[tuple[str, str], ...] = ()


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


def _child(mapping: dict[str, Any] | None, name: str) -> Any:
    """Look up a Discovery resource or method the way gws does: case-insensitively."""
    for key, value in (mapping or {}).items():
        if key.lower() == name.lower():
            return value
    return None


def _without_descriptions(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _without_descriptions(item)
            for key, item in sorted(value.items())
            if not (key == "description" and isinstance(item, str))
        }
    if isinstance(value, list):
        return [_without_descriptions(item) for item in value]
    return value


def _references(value: Any) -> Iterable[str]:
    if isinstance(value, dict):
        if isinstance(value.get("$ref"), str):
            yield value["$ref"]
        for item in value.values():
            yield from _references(item)
    elif isinstance(value, list):
        for item in value:
            yield from _references(item)


def discovery_projection(document: dict[str, Any], routes: Iterable[str]) -> dict[str, dict[str, Any]]:
    """Project each route's request surface, its resource's method list and every request schema it reaches.

    Routes use the lowercase command path the gws rules match, for example
    ``users.messages.batchdelete``. A route the document lacks projects to ``None``.
    """
    projection: dict[str, dict[str, Any]] = {"methods": {}, "resources": {}, "schemas": {}}
    schemas = document.get("schemas") or {}
    pending: list[str] = []
    for route in routes:
        *path, name = route.split(".")
        node: dict[str, Any] | None = document
        for part in path:
            node = _child((node or {}).get("resources"), part)
        methods = (node or {}).get("methods") or {}
        projection["resources"][".".join(path)] = sorted(methods) if node is not None else None
        method = _child(methods, name)
        if method is None:
            projection["methods"][route] = None
            continue
        request = (method.get("request") or {}).get("$ref")
        pending += [request] if request else []
        projection["methods"][route] = {
            "httpMethod": method.get("httpMethod"),
            "path": method.get("path"),
            "parameters": _without_descriptions(method.get("parameters") or {}),
            "request": request,
            "scopes": sorted(method.get("scopes") or ()),
            "supportsMediaUpload": bool(method.get("supportsMediaUpload")),
        }
    while pending:
        name = pending.pop()
        if name in projection["schemas"]:
            continue
        shape = _without_descriptions(schemas.get(name)) if name in schemas else None
        projection["schemas"][name] = shape
        pending += list(_references(shape))
    return projection


def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _expected(projection: dict[str, dict[str, Any]]) -> tuple[tuple[str, str], ...]:
    return tuple(
        (f"{kind} {key}", _digest(value))
        for kind in sorted(projection)
        for key, value in sorted(projection[kind].items())
    )


def discovery_pins(repository: Path) -> list[Pin]:
    """Return one pin per reviewed Discovery API, carrying a digest per projected key."""
    found = []
    for path in sorted((repository / "contributions/upstream-schemas").glob("*.json")):
        pins_file = json.loads(path.read_text(encoding="utf-8"))
        if pins_file.get("schema") != _DISCOVERY_SCHEMA:
            continue
        source = path.relative_to(repository).as_posix()
        for api in pins_file["apis"]:
            expected = _expected(api["projection"])
            project = f"{api['name']}/{api['version']}"
            found.append(Pin(pins_file["extension_id"], "discovery", project, api["revision"], source, expected))
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


def _discovery(pin: Pin, fetch: Fetch) -> tuple[str, str | None, str]:
    name, version = pin.project.split("/")
    document = fetch(_DISCOVERY_URL.format(name=name, version=version))
    expected = dict(pin.expected)
    routes = [key.split(" ", 1)[1] for key in expected if key.startswith("methods ")]
    current = dict(_expected(discovery_projection(document, routes)))
    changed = sorted(key for key in expected if current.get(key) != expected[key])
    revision = document.get("revision")
    if not changed:
        return "current", revision, "reviewed method shapes unchanged"
    return "drifted", revision, "changed: " + ", ".join(changed)


_CHECKS: dict[str, Callable[[Pin, Fetch], tuple[str, str | None, str]]] = {
    "github": _github,
    "npm": _npm,
    "discovery": _discovery,
}


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
            status, current, detail = _CHECKS[pin.kind](pin, fetch)
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
    lines.append("")
    if any(item.pin.kind != "discovery" for item in stale):
        lines.append("Review the upstream change, then update the command source pin and rerun the listed proofs.")
    if any(item.pin.kind == "discovery" for item in stale):
        lines.append(
            "For a Discovery change, review the listed methods, resources and schemas, then run "
            "`python -m scripts.upstream_drift --refresh-discovery-pins`, commit the pin diff "
            "and rerun the listed proofs."
        )
    return "\n".join(lines) + "\n"


def _pins_text(pins_file: dict[str, Any]) -> str:
    """Write one projected key per line so the file stays short and each review diff names its key."""
    lines = ["{"]
    for key in ("schema", "extension_id", "description"):
        lines.append(f"  {json.dumps(key)}: {json.dumps(pins_file[key])},")
    lines.append('  "apis": [')
    for index, api in enumerate(pins_file["apis"]):
        lines.append("    {")
        for key in ("name", "version", "revision"):
            lines.append(f"      {json.dumps(key)}: {json.dumps(api[key])},")
        lines.append('      "projection": {')
        kinds = sorted(api["projection"])
        for kind_index, kind in enumerate(kinds):
            entries = sorted(api["projection"][kind].items())
            lines.append(f"        {json.dumps(kind)}: {{")
            for entry_index, (key, value) in enumerate(entries):
                comma = "," if entry_index < len(entries) - 1 else ""
                lines.append(f"          {json.dumps(key)}: {json.dumps(value, sort_keys=True)}{comma}")
            lines.append("        }" + ("," if kind_index < len(kinds) - 1 else ""))
        lines.append("      }")
        lines.append("    }" + ("," if index < len(pins_file["apis"]) - 1 else ""))
    lines += ["  ]", "}"]
    return "\n".join(lines) + "\n"


def refresh_discovery_pins(repository: Path, fetch: Fetch) -> list[Path]:
    """Re-pin each listed route to the current Discovery shape after a maintainer review.

    A route whose reviewed method has disappeared is not re-pinned as absent: the
    rule that matches it needs a reviewed change first.
    """
    written = []
    for path in sorted((repository / "contributions/upstream-schemas").glob("*.json")):
        pins_file = json.loads(path.read_text(encoding="utf-8"))
        if pins_file.get("schema") != _DISCOVERY_SCHEMA:
            continue
        for api in pins_file["apis"]:
            document = fetch(_DISCOVERY_URL.format(name=api["name"], version=api["version"]))
            reviewed = api["projection"]["methods"]
            projection = discovery_projection(document, sorted(reviewed))
            removed = sorted(
                route for route, shape in projection["methods"].items() if shape is None and reviewed[route]
            )
            if removed:
                raise ValueError(
                    f"{api['name']}/{api['version']} no longer has {', '.join(removed)}; update the rule first"
                )
            api["revision"] = document.get("revision")
            api["projection"] = projection
        path.write_text(_pins_text(pins_file), encoding="utf-8")
        written.append(path)
    return written


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--repository", type=Path, default=REPOSITORY)
    parser.add_argument("--json", type=Path, help="write the machine-readable report here")
    parser.add_argument(
        "--refresh-discovery-pins",
        action="store_true",
        help="rewrite the Discovery pins from current documents; run only after reviewing the reported change",
    )
    args = parser.parse_args(argv)
    if args.refresh_discovery_pins:
        for path in refresh_discovery_pins(args.repository, http_json):
            print(f"re-pinned {path.relative_to(args.repository).as_posix()}")
        return 0
    findings = check(
        pins(args.repository) + discovery_pins(args.repository),
        http_json,
        pack_members(args.repository),
        gauntlet_scenarios(args.repository),
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
