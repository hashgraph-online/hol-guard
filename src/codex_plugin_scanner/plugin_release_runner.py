"""Steps of the HOL Plugin Release composite action.

``evidence`` builds the release evidence from the scanner outputs and the
Plugin Kit check report, ``register`` sends it to HOL when enabled, and
``summary`` writes the job summary and applies the check gate. Each step reads
its inputs from the environment the action sets.
"""

from __future__ import annotations

import json
import os
import re
import sys
from collections.abc import Mapping
from pathlib import Path

from .plugin_release_evidence import (
    build_plugin_release_evidence,
    plugin_release_evidence_json,
    plugin_release_evidence_sha256,
)
from .plugin_release_registration import DEFAULT_ENDPOINT, register_plugin_release_evidence


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
    path = Path(_env("EVIDENCE_PATH"))
    path.write_text(plugin_release_evidence_json(evidence), encoding="utf-8")
    _write_outputs(
        {
            "evidence_path": str(path),
            "evidence_sha256": plugin_release_evidence_sha256(evidence),
            "check_passed": "true" if evidence.check_passed else "false",
            "supported_runtimes": str(sum(1 for runtime in evidence.runtimes if runtime.supported)),
        }
    )
    return 0


def register_step() -> int:
    if _env("REGISTER_RELEASE") != "true":
        _write_outputs({"release_status": "disabled", "release_url": ""})
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
        print(f"HOL Plugin Release registration unavailable: {type(error).__name__}")
        result = {"status": "unavailable"}
    status = result.get("status")
    url = result.get("releaseUrl")
    _write_outputs(
        {
            "release_status": status if isinstance(status, str) else "unavailable",
            "release_url": url if isinstance(url, str) and url.startswith("https://") else "",
        }
    )
    return 0


_SEVERITY_ORDER = ("none", "info", "low", "medium", "high", "critical")


def _plain(value: object, *, limit: int = 100) -> str:
    """Plugin-supplied text as one line with no Markdown or HTML meaning."""

    text = "".join(character for character in str(value) if character.isprintable())[:limit]
    return re.sub(r"([\\`*_{}\[\]()<>#+!|~&-])", r"\\\1", text)


def _summary_lines(evidence: Mapping[str, object], *, attestation_url: str, status: str, url: str) -> list[str]:
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
    if attestation_url:
        lines.append(f"- Provenance attestation: {attestation_url}")
    if status == "disabled":
        lines.append("- HOL listing: not sent (register_release is off)")
    elif url:
        lines.append(f"- HOL listing: {status}, {url}")
    else:
        lines.append(f"- HOL listing: {status}")
    lines.extend(["", f"_{evidence.get('claim')}_", ""])
    return lines


def summary_step() -> int:
    evidence = json.loads(Path(_env("EVIDENCE_PATH")).read_text(encoding="utf-8"))
    if not isinstance(evidence, Mapping):
        raise ValueError("release evidence must be a JSON object")
    lines = _summary_lines(
        evidence,
        attestation_url=_env("ATTESTATION_URL"),
        status=_env("RELEASE_STATUS") or "unavailable",
        url=_env("RELEASE_URL"),
    )
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
