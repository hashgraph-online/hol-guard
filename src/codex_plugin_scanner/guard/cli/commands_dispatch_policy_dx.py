"""Local policy authoring commands: init, validate, test, check, status and explain.

``init``, ``validate``, ``test`` and ``check`` only read a policy file, so they run without a Guard home or
store and are safe in CI. ``status`` and ``explain <id>`` read the device's store.
Exit codes: 0 success, 1 a negative result (a failing test), 4 invalid input or an untrusted file.
"""

from __future__ import annotations

import json
import sys
import time
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TextIO, cast

from ..approval_gate import ApprovalGateError
from ..business_policy_document_import import has_business_rules
from ..native_command_policy_decision import TOO_LARGE as COMMAND_TOO_LARGE
from ..native_command_policy_decision import CommandPolicyDecisionUnavailableError
from ..native_policy_document import NativePolicyDocumentError
from ..native_policy_document_decision import TOO_LARGE, PolicyDocumentDecisionUnavailableError
from ..native_policy_snapshot_constants import NativePolicySnapshotError
from ..policy_authority import PolicyAuthorityError
from ..policy_decision_engine import PolicyEventError, compile_local_rows, decide_command, decide_rows, parse_event
from ..policy_decision_explain import explain_receipt_decision
from ..policy_delivery_status import format_policy_status, policy_status_payload
from ..policy_document import GuardPolicyDocument, policy_document_digest
from ..policy_document_diagnostics import PolicyValidationReport, StructuredDiagnostic, validate_policy_file
from ..policy_document_io import PolicyCompilationError, PolicyFileTrustError, write_private_policy_text
from ..policy_document_yaml import PolicyDocumentError
from ..policy_starters import DEFAULT_STARTER, POLICY_STARTERS, find_starter, render_starter_yaml
from ..policy_tests_runner import (
    BUSINESS_RULES_CODE,
    PolicyTestRun,
    PolicyTestsInvalidError,
    run_policy_tests,
    stored_tests,
)
from ..store import GuardStore

FILE_COMMANDS = frozenset({"init", "validate", "test", "check"})
DEFAULT_POLICY_FILE = "guard-policy.yaml"
TEXT_DIAGNOSTIC_LIMIT = 20
MAX_EVENT_BYTES = 65_536
WATCH_POLL_SECONDS = 0.5

_COMMAND_ERRORS = (
    ApprovalGateError,
    PolicyAuthorityError,
    PolicyCompilationError,
    PolicyDocumentError,
    PolicyFileTrustError,
    NativePolicySnapshotError,
    NativePolicyDocumentError,
)


def wants_json(args: Any) -> bool:
    return bool(getattr(args, "json", False)) or getattr(args, "output_format", None) == "json"


def _emit(stream: TextIO | None, payload: dict[str, object], *, as_json: bool, text: str | None = None) -> None:
    target = stream or sys.stdout
    if as_json:
        target.write(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n")
        return
    message = text if text is not None else payload.get("message")
    rendered = message if isinstance(message, str) else ""
    target.write(rendered if rendered.endswith("\n") or not rendered else rendered + "\n")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _render_diagnostic(file: str, item: StructuredDiagnostic) -> list[str]:
    where = f"{file}:{item.line}:{item.col}" if item.line is not None else file
    lines = [f"  {where} {item.severity} {item.code} {item.path}", f"    {item.message}"]
    if item.expected is not None:
        lines.append(f"    expected: {json.dumps(item.expected, sort_keys=True)}")
    if item.suggestion is not None:
        lines.append(f"    suggestion: {item.suggestion}")
    return lines


def _render_report(file: str, report: PolicyValidationReport) -> str:
    shown = report.diagnostics[:TEXT_DIAGNOSTIC_LIMIT]
    lines = [f"{file}: {report.status} ({len(report.diagnostics)} problem(s))"]
    for item in shown:
        lines.extend(_render_diagnostic(file, item))
    hidden = len(report.diagnostics) - len(shown)
    if hidden > 0:
        lines.append(f"  ... {hidden} more; run with --format json to see every problem.")
    return "\n".join(lines)


def _report_payload(report: PolicyValidationReport) -> dict[str, object]:
    document = report.document
    digest = policy_document_digest(document) if document is not None else None
    rows = len(report.compiled)
    reason = report.local_store_reason
    if not report.valid:
        message = "Invalid Guard policy: " + ", ".join(sorted({item.code for item in report.errors})[:5])
    elif document is not None and reason is None and not report.compiled and document.rules:
        message = f"Valid Guard policy: {document.metadata.id} ({len(document.rules)} business rules)"
    elif reason is None and document is not None:
        message = f"Valid Guard policy: {document.metadata.id} ({rows} rows)"
    else:
        message = f"Valid Guard 3.0 policy: {document.metadata.id if document else ''}"
    payload: dict[str, object] = {
        "valid": report.valid,
        "status": report.status,
        "document_id": document.metadata.id if document is not None else None,
        "digest": digest,
        "compiled_rows": rows,
        "local_store_compilable": report.valid and reason is None,
        "local_store_reason": reason,
        "diagnostics": [item.to_dict() for item in report.diagnostics],
        "message": message,
    }
    if not report.valid and report.errors:
        payload["error"] = report.errors[0].code
    return payload


def _validated(file: Path) -> PolicyValidationReport:
    return validate_policy_file(file, diagnostic_limit=None)


def _run_validate(args: Any, output_stream: TextIO | None) -> int:
    file = str(args.file)
    report = _validated(Path(file))
    payload = _report_payload(report)
    text = _render_report(file, report) if not report.valid or report.diagnostics else str(payload["message"])
    _emit(output_stream, payload, as_json=wants_json(args), text=text)
    return 0 if report.valid else 4


def _run_init(args: Any, output_stream: TextIO | None) -> int:
    as_json = wants_json(args)
    if bool(getattr(args, "list_starters", False)):
        listing = [{"id": starter.id, "name": starter.name, "summary": starter.summary} for starter in POLICY_STARTERS]
        text = "\n".join(f"{item['id']:<17} {item['summary']}" for item in listing)
        _emit(output_stream, {"starters": listing, "message": text}, as_json=as_json, text=text)
        return 0
    starter = find_starter(str(getattr(args, "starter", None) or DEFAULT_STARTER))
    if starter is None:
        _emit(output_stream, {"error": "unknown_starter", "message": "Unknown starter."}, as_json=as_json)
        return 4
    target = Path(str(getattr(args, "output", None) or DEFAULT_POLICY_FILE))
    if target.exists() and not bool(getattr(args, "force", False)):
        message = f"{target} already exists. Choose another --output, or pass --force to replace it."
        _emit(output_stream, {"error": "policy_file_exists", "message": message}, as_json=as_json)
        return 4
    write_private_policy_text(target, render_starter_yaml(starter))
    written = _validated(target).document
    tests = len(stored_tests(written)) if written is not None else 0
    message = (
        f"Wrote {target} from the {starter.id} starter with {tests} example tests.\n"
        f"Next: hol-guard policy test {target}"
    )
    _emit(
        output_stream,
        {"written": str(target), "starter": starter.id, "tests": tests, "message": message},
        as_json=as_json,
        text=message,
    )
    return 0


def _load_valid_document(file: str, output_stream: TextIO | None, *, as_json: bool) -> GuardPolicyDocument | None:
    report = _validated(Path(file))
    if report.valid and report.document is not None:
        return report.document
    payload = _report_payload(report)
    _emit(output_stream, payload, as_json=as_json, text=_render_report(file, report))
    return None


def _render_test_run(file: str, run: PolicyTestRun) -> str:
    lines = [f"{file}: {run.document_id}"]
    for result in run.results:
        label = result.name or result.id
        lines.append(f"  {result.status.upper():<9} {result.id}  {label}")
        if result.status != "pass":
            lines.append(f"            {result.message}")
    if not run.results:
        lines.append("  No x-hol.tests found. Add examples under spec.x-hol.tests.")
    lines.append(f"{run.passed} passed, {run.failed} failed, {len(run.results)} total")
    return "\n".join(lines)


def _undecided(
    error: PolicyDocumentDecisionUnavailableError | CommandPolicyDecisionUnavailableError,
) -> dict[str, object]:
    """Say which side could not decide: an absent runtime, or a refused document.

    A document the runtime declines to rank names what it declined, and telling
    its author to fix an unavailable runtime instead sends them after the wrong
    thing entirely.
    """

    subject = "command" if isinstance(error, CommandPolicyDecisionUnavailableError) else "document"
    if error.code in {TOO_LARGE, COMMAND_TOO_LARGE}:
        message = "This document carries more rules than one decision can ask about."
    elif error.refused:
        message = f"The native runtime refused to decide this {subject} ({error.code})."
    else:
        message = "The native runtime is unavailable, so this cannot be decided here."
    return {"error": error.code, "message": message}


def _test_once(args: Any, file: str, output_stream: TextIO | None) -> int:
    as_json = wants_json(args)
    document = _load_valid_document(file, output_stream, as_json=as_json)
    if document is None:
        return 4
    try:
        run = run_policy_tests(document, now=_now())
    except PolicyDocumentDecisionUnavailableError as error:
        # The runtime ranks the rules; without it there is no second opinion to fall back on.
        _emit(output_stream, _undecided(error), as_json=as_json)
        return 4
    except PolicyTestsInvalidError as error:
        payload: dict[str, object] = {
            "error": error.code,
            "problems": list(error.problems),
            "message": f"{error.code}: " + "; ".join(error.problems[:5]),
        }
        _emit(output_stream, payload, as_json=as_json)
        return 4
    payload = run.to_dict()
    _emit(output_stream, payload, as_json=as_json, text=_render_test_run(file, run))
    return 0 if run.failed == 0 else 1


def _signature(path: Path) -> tuple[int, int] | None:
    try:
        metadata = path.stat()
    except OSError:
        return None
    return metadata.st_mtime_ns, metadata.st_size


def _run_test(
    args: Any,
    output_stream: TextIO | None,
    *,
    sleep: Callable[[float], None] = time.sleep,
) -> int:
    file = str(args.file)
    code = _test_once(args, file, output_stream)
    if not bool(getattr(args, "watch", False)):
        return code
    max_runs = getattr(args, "watch_max_runs", None)
    runs = 1
    seen = _signature(Path(file))
    try:
        while max_runs is None or runs < int(max_runs):
            sleep(WATCH_POLL_SECONDS)
            current = _signature(Path(file))
            if current == seen:
                continue
            seen = current
            code = _test_once(args, file, output_stream)
            runs += 1
    except KeyboardInterrupt:
        pass
    return code


def _read_event_text(raw: str, input_text: str | None) -> str:
    if raw != "-":
        return raw
    if input_text is not None:
        return input_text
    return sys.stdin.read(MAX_EVENT_BYTES + 1)


def _render_decision(decision: dict[str, object]) -> str:
    rule = decision.get("ruleId")
    lookup = cast("dict[str, object]", decision["lookup"])
    action = decision.get("action")
    outcome = action if rule and decision["effect"] == "default" and isinstance(action, str) else decision["effect"]
    head = f"Decision: {outcome}" + (f" by rule {rule}" if rule else " (no rule matched)")
    if decision.get("matchLimitExceeded"):
        head += " (more than 256 rules matched; blocked without a rule)"
    lines = [head]
    if lookup.get("artifactId"):
        lines.append(f"  Looked up: {lookup['artifactId']} at {lookup['at']}")
    if decision.get("ambiguous"):
        lines.append(f"  Ambiguous: ties with {', '.join(cast('list[str]', decision['tiedRuleIds']))}")
    candidates = cast("list[dict[str, object]]", decision["candidates"])
    if candidates:
        lines.append("  Rules considered:")
    for item in candidates:
        reason = f" ({item['reason']})" if item.get("reason") else ""
        lines.append(f"    {item['state']!s:<12} {item['ruleId']}{reason}")
    return "\n".join(lines)


def _run_check(args: Any, output_stream: TextIO | None, input_text: str | None) -> int:
    as_json = wants_json(args)
    file = str(args.file)
    document = _load_valid_document(file, output_stream, as_json=as_json)
    if document is None:
        return 4
    command_text = getattr(args, "command_text", None)
    if has_business_rules(document):
        message = "Business rules are not evaluated locally, so this file cannot be checked here."
        _emit(output_stream, {"error": BUSINESS_RULES_CODE, "message": message}, as_json=as_json)
        return 4
    try:
        if command_text is not None:
            decision = decide_command(document, str(command_text), now=_now())
        else:
            raw = _read_event_text(str(args.event), input_text)
            if len(raw.encode("utf-8")) > MAX_EVENT_BYTES:
                raise PolicyEventError("event_too_large", "The event is larger than 64 KiB.")
            try:
                value = json.loads(raw)
            except ValueError as error:
                raise PolicyEventError("event_invalid_json", "The event is not valid JSON.") from error
            decision = decide_rows(compile_local_rows(document), parse_event(value), now=_now())
    except (PolicyDocumentDecisionUnavailableError, CommandPolicyDecisionUnavailableError) as error:
        # The runtime matches the patterns and ranks the rules; without it there is no second
        # opinion to fall back on.
        _emit(output_stream, _undecided(error), as_json=as_json)
        return 4
    except PolicyEventError as error:
        _emit(output_stream, {"error": error.code, "message": str(error)}, as_json=as_json)
        return 4
    decision["document"] = {"id": document.metadata.id, "digest": policy_document_digest(document)}
    _emit(output_stream, decision, as_json=as_json, text=_render_decision(decision))
    return 0


def run_policy_file_command(
    args: Any,
    *,
    input_text: str | None = None,
    output_stream: TextIO | None = None,
    **_kwargs: Any,
) -> int:
    command = str(args.policy_command)
    try:
        if command == "init":
            return _run_init(args, output_stream)
        if command == "validate":
            return _run_validate(args, output_stream)
        if command == "test":
            return _run_test(args, output_stream)
        if command == "check":
            return _run_check(args, output_stream, input_text)
    except _COMMAND_ERRORS as error:
        code = str(getattr(error, "code", error.__class__.__name__))
        _emit(output_stream, {"error": code, "message": str(error)}, as_json=wants_json(args))
        return 4
    raise ValueError("unknown_policy_file_command")


def confirm_policy_import(
    args: Any,
    diff_text: str | None,
    output_stream: TextIO | None,
    input_text: str | None,
) -> dict[str, object] | None:
    """Print the diff and ask before an apply; ``None`` means proceed, a dict is the refusal payload."""

    if bool(getattr(args, "yes", False)):
        return None
    if wants_json(args):
        # JSON output is parsed by tools: never mix a prompt into it, and never ask for a change that was not shown.
        return {
            "error": "confirmation_required",
            "message": "Run a dry run to review the diff, then re-run with --yes to apply it without a prompt.",
        }
    target = output_stream or sys.stdout
    target.write((diff_text or "No policy changes.").rstrip("\n") + "\n")
    if input_text is None and not sys.stdin.isatty():
        return {
            "error": "confirmation_required",
            "message": "Review the diff, then re-run with --yes to apply it without a prompt.",
        }
    answer = input_text if input_text is not None else input("Apply these changes? [y/N] ")
    if answer.strip().lower() in {"y", "yes"}:
        return None
    return {"error": "import_declined", "message": "Import cancelled; no changes written."}


def run_policy_status(args: Any, store: GuardStore, output_stream: TextIO | None) -> int:
    payload = policy_status_payload(store, offline=bool(getattr(args, "offline", False)))
    _emit(output_stream, payload, as_json=wants_json(args), text=format_policy_status(payload))
    return 0


def run_policy_explain_decision(args: Any, store: GuardStore, output_stream: TextIO | None) -> int:
    as_json = wants_json(args)
    decision_id = str(args.decision_id)
    payload = explain_receipt_decision(store, decision_id)
    if payload is None:
        _emit(
            output_stream,
            {"error": "decision_not_found", "message": "No recorded decision has that id."},
            as_json=as_json,
        )
        return 4
    decision = payload.get("decision")
    receipt = cast("dict[str, object]", payload["receipt"])
    lines = [
        f"Decision {decision_id}: {receipt.get('recordedDecision')} for {receipt.get('artifactId')} "
        f"in {receipt.get('harness')} at {receipt.get('timestamp')}",
        "Replayed against the policy that is Live now:",
    ]
    lines.append(_render_decision(cast("dict[str, object]", decision)) if decision else f"  {payload.get('note')}")
    if decision and payload.get("note"):
        lines.append(f"  Note: {payload['note']} (receipts do not record the publisher or workspace).")
    _emit(output_stream, payload, as_json=as_json, text="\n".join(lines))
    return 0


__all__ = [
    "FILE_COMMANDS",
    "confirm_policy_import",
    "run_policy_explain_decision",
    "run_policy_file_command",
    "run_policy_status",
    "wants_json",
]
