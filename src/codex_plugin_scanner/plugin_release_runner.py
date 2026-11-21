"""Steps of the HOL Plugin Release composite action.

``evidence`` builds the release evidence and its CycloneDX SBOM from the
scanner outputs, the Plugin Kit check report and the plugin's lockfiles,
``register`` sends it to HOL when enabled, and ``summary`` writes the job
summary, annotates what changed since the previous release and applies the
check gate. Each step reads
its inputs from the environment the action sets.
"""

from __future__ import annotations

import json
import os
import re
import sys
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path

from .plugin_release_evidence import (
    build_plugin_release_evidence,
    plugin_release_evidence_json,
    plugin_release_evidence_sha256,
)
from .plugin_release_registration import DEFAULT_ENDPOINT, register_plugin_release_evidence
from .plugin_release_sbom import build_plugin_release_sbom


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def _write_outputs(values: Mapping[str, str]) -> None:
    target = _env("GITHUB_OUTPUT")
    if not target:
        return
    with Path(target).open("a", encoding="utf-8") as handle:
        for key, value in values.items():
            handle.write(f"{key}={value.replace(chr(10), ' ').replace(chr(13), ' ')}\n")


def _int_env(name: str) -> int:
    value = _env(name)
    return int(value) if value.isdigit() else 0


def evidence_step() -> int:
    check_report = json.loads(Path(_env("CHECK_PATH")).read_text(encoding="utf-8"))
    if not isinstance(check_report, Mapping):
        raise ValueError("Plugin Kit check report must be a JSON object")
    evidence = build_plugin_release_evidence(
        repository=_env("REPOSITORY"),
        commit_sha=_env("COMMIT_SHA"),
        ref=_env("REF"),
        workflow_run_id=_env("RUN_ID"),
        guard_version=_env("HOL_GUARD_VERSION"),
        scan_profile=_env("PROFILE") or "default",
        score=_int_env("SCORE"),
        grade=_env("GRADE") or "unknown",
        max_severity=_env("MAX_SEVERITY") or "none",
        findings_total=_int_env("FINDINGS_TOTAL"),
        check_report=check_report,
        visibility="private" if _env("VISIBILITY") == "private" else "public",
    )
    sbom_path = _env("SBOM_PATH")
    sbom = (
        build_plugin_release_sbom(
            plugin_dir=Path(_env("PLUGIN_DIR") or "."),
            servers=evidence.mcp_servers,
            repository=evidence.repository,
            commit_sha=evidence.commit_sha,
            plugin_name=evidence.plugin_name,
            plugin_version=evidence.plugin_version,
            guard_version=evidence.guard_version,
        )
        if sbom_path
        else None
    )
    if sbom is None:
        sbom_path = ""
    else:
        Path(sbom_path).write_text(sbom.document, encoding="utf-8")
        evidence = replace(evidence, sbom=sbom.summary)
    path = Path(_env("EVIDENCE_PATH"))
    path.write_text(plugin_release_evidence_json(evidence), encoding="utf-8")
    _write_outputs(
        {
            "evidence_path": str(path),
            "sbom_path": sbom_path,
            "sbom_components": str(evidence.sbom.components) if evidence.sbom else "0",
            "evidence_sha256": plugin_release_evidence_sha256(evidence),
            "check_passed": "true" if evidence.check_passed else "false",
            "supported_runtimes": str(sum(1 for runtime in evidence.runtimes if runtime.supported)),
        }
    )
    return 0


def register_step() -> int:
    if _env("REGISTER_RELEASE") != "true":
        _write_outputs({"release_status": "disabled", "release_url": "", "offer_url": "", "changes": ""})
        return 0
    try:
        result = register_plugin_release_evidence(
            evidence_json=Path(_env("EVIDENCE_PATH")).read_text(encoding="utf-8"),
            attestation_url=_env("ATTESTATION_URL"),
            attestation_id=_env("ATTESTATION_ID"),
            endpoint=_env("RELEASE_ENDPOINT") or DEFAULT_ENDPOINT,
            oidc_request_url=_env("ACTIONS_ID_TOKEN_REQUEST_URL"),
            oidc_request_token=os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN", ""),
        )
    except Exception as error:  # Registration is best effort; the attested evidence still stands.
        status_code = getattr(error, "code", None)
        detail = f" {status_code}" if isinstance(status_code, int) else ""
        print(f"HOL Plugin Release registration unavailable: {type(error).__name__}{detail}")
        result = {"status": "unavailable"}
    status = result.get("status")
    changes = release_changes(result.get("changes"))
    url = result.get("releaseUrl")
    offer = result.get("offerUrl")
    allowed = _env("OFFER_LINE", "true") != "false"
    offer_url = offer if allowed and isinstance(offer, str) and _is_offer_url(offer) else ""
    _write_outputs(
        {
            "release_status": status if isinstance(status, str) else "unavailable",
            "release_url": url if isinstance(url, str) and url.startswith("https://") else "",
            "offer_url": offer_url,
            "changes": json.dumps(changes, sort_keys=True, separators=(",", ":")) if changes else "",
        }
    )
    return 0


_FLAG_KINDS = frozenset({"server", "egress", "env", "package", "hooks", "severity", "check"})
_MAX_FLAGS = 20


def release_changes(value: object) -> dict[str, object] | None:
    """What HOL found new since the previous checked release, kept to known flag kinds and short text."""

    if not isinstance(value, Mapping):
        return None
    previous = value.get("previousVersion")
    flags = value.get("flags")
    if not isinstance(previous, str) or not previous or not isinstance(flags, list):
        return None
    kept: list[dict[str, str]] = []
    for flag in flags:
        if len(kept) == _MAX_FLAGS:
            break
        if not isinstance(flag, Mapping):
            continue
        kind, text = flag.get("kind"), flag.get("text")
        if isinstance(kind, str) and kind in _FLAG_KINDS and isinstance(text, str):
            plain = "".join(character for character in text if character.isprintable())[:300]
            if plain:
                kept.append({"kind": kind, "text": plain})
    return {"previousVersion": previous[:100], "flags": kept}


_OFFER_URL = re.compile(r"https://hol\.org/guard/plugins/promote\?[A-Za-z0-9._~%=&-]{1,300}")


def _is_offer_url(value: object) -> bool:
    """HOL may only point the line at its own promote page; the text is ours."""

    return isinstance(value, str) and _OFFER_URL.fullmatch(value) is not None


_SEVERITY_ORDER = ("none", "info", "low", "medium", "high", "critical")


def _plain(value: object, *, limit: int = 100) -> str:
    """Plugin-supplied text as one line with no Markdown or HTML meaning."""

    text = "".join(character for character in str(value) if character.isprintable())[:limit]
    return re.sub(r"([\\`*_{}\[\]()<>#+!|~&-])", r"\\\1", text)


def _annotation(text: str) -> str:
    """A GitHub workflow command message cannot start a new command or line."""

    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _changes_lines(changes: Mapping[str, object] | None) -> list[str]:
    if changes is None:
        return []
    previous = _plain(changes.get("previousVersion"))
    flags = changes.get("flags")
    texts = [str(flag.get("text")) for flag in (flags if isinstance(flags, list) else []) if isinstance(flag, Mapping)]
    if not texts:
        return [f"- Changes since {previous}: nothing new to review"]
    return [
        f"- Changes since {previous}, review before upgrading:",
        *(f"  - {_plain(text, limit=300)}" for text in texts),
    ]


def _summary_lines(
    evidence: Mapping[str, object],
    *,
    attestation_url: str,
    status: str,
    url: str,
    offer_url: str = "",
    changes: Mapping[str, object] | None = None,
) -> list[str]:
    runtimes = evidence.get("runtimes")
    supported = [
        str(item.get("runtime"))
        for item in (runtimes if isinstance(runtimes, list) else [])
        if isinstance(item, Mapping) and item.get("supported") is True
    ]
    servers = evidence.get("mcp_servers")
    server_count = len(servers) if isinstance(servers, list) else 0
    plugin_name = _plain(evidence.get("plugin_name") or "unnamed")
    plugin_version = _plain(evidence.get("plugin_version") or "")
    lines = [
        "## HOL Plugin Release",
        "",
        f"- Plugin: {plugin_name} {plugin_version}".rstrip(),
        f"- Scan: score {evidence.get('score')} ({evidence.get('grade')}), "
        f"{evidence.get('findings_total')} findings, highest severity {evidence.get('max_severity')}",
        f"- Plugin Kit check: {'passed' if evidence.get('check_passed') else 'failed'} "
        f"({evidence.get('check_errors')} errors, {evidence.get('check_warnings')} warnings)",
        f"- Packaged for {len(supported)} runtimes: {', '.join(supported) or 'none'}",
        f"- MCP servers: {server_count}; hooks: {'yes' if evidence.get('hooks') else 'no'}",
    ]
    sbom = evidence.get("sbom")
    if isinstance(sbom, Mapping):
        lines.append(
            f"- SBOM: CycloneDX {_plain(sbom.get('spec_version'))}, {_plain(sbom.get('components'))} components, "
            f"SHA-256 {_plain(sbom.get('sha256'))}"
        )
    else:
        lines.append("- SBOM: none, no package-lock.json, uv.lock, pinned requirements or launched packages found")
    lines.extend(_changes_lines(changes))
    if attestation_url:
        lines.append(f"- Provenance attestation: {attestation_url}")
    if status == "disabled":
        lines.append("- HOL listing: not sent (register_release is off)")
    elif url:
        lines.append(f"- HOL listing: {status}, {url}")
    else:
        lines.append(f"- HOL listing: {status}")
    if _is_offer_url(offer_url):
        lines.append(
            f"- HOL Blue adds full owner insights and the checkmark to this listing: {offer_url} "
            "(at most once in 28 days; set `offer_line: false` to hide it)"
        )
    lines.extend(["", f"_{evidence.get('claim')}_", ""])
    return lines


def summary_step() -> int:
    evidence = json.loads(Path(_env("EVIDENCE_PATH")).read_text(encoding="utf-8"))
    if not isinstance(evidence, Mapping):
        raise ValueError("release evidence must be a JSON object")
    try:
        changes = release_changes(json.loads(_env("CHANGES"))) if _env("CHANGES") else None
    except ValueError:
        changes = None
    lines = _summary_lines(
        evidence,
        attestation_url=_env("ATTESTATION_URL"),
        status=_env("RELEASE_STATUS") or "unavailable",
        url=_env("RELEASE_URL"),
        offer_url=_env("OFFER_URL"),
        changes=changes,
    )
    flags = changes.get("flags") if changes else None
    for flag in flags if isinstance(flags, list) else []:
        print(f"::warning title=HOL Plugin Release::{_annotation(str(flag.get('text')))}")
    summary_path = _env("GITHUB_STEP_SUMMARY")
    if summary_path:
        with Path(summary_path).open("a", encoding="utf-8") as handle:
            handle.write("\n".join(lines))
    else:
        print("\n".join(lines))
    if _env("FAIL_ON_CHECK_ERRORS", "true") == "true" and evidence.get("check_passed") is not True:
        print("The Plugin Kit check reported errors; see `hol-guard plugin check` locally.", file=sys.stderr)
        return 1
    threshold = _env("FAIL_ON_SEVERITY", "none")
    severity = evidence.get("max_severity")
    if (
        threshold in _SEVERITY_ORDER[1:]
        and severity in _SEVERITY_ORDER
        and _SEVERITY_ORDER.index(str(severity)) >= _SEVERITY_ORDER.index(threshold)
    ):
        print(f'Findings met or exceeded the "{threshold}" severity threshold.', file=sys.stderr)
        return 1
    return 0


_STEPS = {"evidence": evidence_step, "register": register_step, "summary": summary_step}


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1 or args[0] not in _STEPS:
        print(f"usage: plugin_release_runner {{{','.join(_STEPS)}}}", file=sys.stderr)
        return 2
    return _STEPS[args[0]]()


if __name__ == "__main__":
    raise SystemExit(main())
