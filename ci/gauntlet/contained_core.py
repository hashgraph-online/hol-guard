"""Bind OMP's contained-test rewrite in core Gauntlet cases to the original call Guard reviewed.

Rust denies some ordinary commands with ``sandbox-required`` and the generated OMP adapter
re-runs them through ``hol-guard execute-contained-test``. That route is accepted only when the
denial receipt, the canonical wrapper argv, the captured adapter request bytes, the post-tool
observation, the result presentation and a successful host result all name the same call.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import shlex
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

from .input_evidence import Redaction, input_digest, input_matches, redact_value

PROOF_SCHEMA = "guard-contained-test-request-proof.v1"
PROOF_KEYS = frozenset({"schema", "tool_call_id", "workspace", "payload_sha256", "request_sha256"})
CAPTURE_EVENT = "contained_request_capture"
_REQUEST_LIMIT = 1_048_576
_HEX64 = re.compile(r"[0-9a-f]{64}")
# Mirrors the generated adapter: each containment reason admits exactly one execution profile.
CONTAINMENT_PROFILES = {
    "native_bash_owner_required": "native-bash-owner-v1",
    "native_python_eval_readonly_containment_required": "python-eval-readonly-v1",
    "native_node_eval_readonly_containment_required": "node-eval-readonly-v1",
    "native_bun_eval_readonly_containment_required": "node-eval-readonly-v1",
    "native_package_test_readonly_containment_required": "package-test-readonly-v1",
    "native_node_build_output_containment_required": "node-build-output-v1",
    "native_node_tool_readonly_containment_required": "node-tool-readonly-v1",
    "native_git_readonly_containment_required": "git-readonly-v1",
    "native_pytest_readonly_containment_required": "pytest-readonly-v2",
    "native_vitest_readonly_containment_required": "vitest-readonly-v1",
    "native_node_test_readonly_containment_required": "node-test-readonly-v1",
    "native_workspace_containment_required": "workspace-contained-v1",
}
# How a contained command reports a sandbox refusal: a denied file operation, a read-only mount,
# or a network request the sandbox cut off. curl exits 6 or 7 when it cannot resolve or connect.
_SANDBOX_DENIAL = re.compile(
    r"Operation not permitted|Permission denied|Read-only file system|EPERM|EACCES|EROFS"
    r"|Could not resolve host|ENOTFOUND|EAI_AGAIN|getaddrinfo|Network is unreachable|ECONNREFUSED"
    r"|Temporary failure in name resolution|Name or service not known"
    r"|nodename nor servname provided|Connection refused"
)
_CURL_NETWORK_EXITS = frozenset({6, 7})
# On Windows the adapter runs the sink with Guard's own Python and this fixed bootstrap,
# naming the package root with forward slashes so the shell keeps it intact.
_WINDOWS_PYTHON = re.compile(r"[A-Za-z]:\\(?:[^\\/:*?\"<>|']+\\)*python\.exe", re.IGNORECASE)
_WINDOWS_BOOTSTRAP = re.compile(
    r"import sys;sys\.path\.insert\(0, '[A-Za-z]:/[^'\\]*'\);"
    r"from codex_plugin_scanner\.cli import main;raise SystemExit\(main\(sys\.argv\[1:\]\)\)"
)
# Redaction folds the shell-quoted spelling of a fixture path into its placeholder. A Windows
# path needs quoting, so its placeholder is left bare where a POSIX one stays inside quotes.
_PLACEHOLDERS = frozenset({"{{workspace}}", "{{home}}", "{{fixture}}", "{{scratch}}"})


def contained_public_path(value: object) -> bool:
    return isinstance(value, str) and (
        value.startswith("/")
        or value.startswith(("{{fixture}}/", "{{workspace}}/", "{{home}}/", "{{contained_project}}/"))
    )


def _quoted(argv: list[str], *, bare_placeholders: bool) -> str:
    return " ".join(
        value if bare_placeholders and value in _PLACEHOLDERS else "'" + value.replace("'", "'\\''") + "'"
        for value in argv
    )


def windows_sink(argv: list[str]) -> bool:
    """Whether a normalized wrapper argv names the Windows sink's Python, not a wrapper script."""
    return bool(argv) and _WINDOWS_PYTHON.fullmatch(argv[0]) is not None


def contained_wrapper_argv(command: object, expected_workspace: str) -> tuple[list[str] | None, str | None]:
    """Validate the canonical ``execute-contained-test`` argv the adapter exports.

    The adapter leaves out ``--home`` when Guard's home directory is the agent's own HOME, so a
    run in the account's real home has ten items instead of twelve. On Windows the adapter starts
    Guard's Python with a fixed bootstrap and the ``guard`` subcommand; that prefix is folded into
    its first item, so callers index the same argv on every platform.
    """
    if not isinstance(command, str):
        return None, "contained wrapper command is missing"
    try:
        argv = shlex.split(command)
    except ValueError:
        return None, "contained wrapper command is not valid shell argv"
    windows = (
        len(argv) > 5
        and _WINDOWS_PYTHON.fullmatch(argv[0]) is not None
        and argv[1:3] == ["-I", "-c"]
        and _WINDOWS_BOOTSTRAP.fullmatch(argv[3]) is not None
        and argv[4] == "guard"
    )
    if command != _quoted(argv, bare_placeholders=False) and not (
        windows and command == _quoted(argv, bare_placeholders=True)
    ):
        return None, "contained wrapper command is not canonical"
    if windows:
        argv = [argv[0], *argv[5:]]
    if len(argv) not in (10, 12) or not (windows or contained_public_path(argv[0])):
        return None, "contained wrapper is not an approved path"
    guard_home = argv[3].startswith("{{fixture}}\\") if windows else contained_public_path(argv[3])
    if argv[1] != "execute-contained-test" or argv[2] != "--guard-home" or not guard_home:
        return None, "contained wrapper guard-home binding is malformed"
    if argv[4:6] != ["--workspace", expected_workspace]:
        return None, "contained wrapper workspace binding differs from the reviewed caller"
    if argv[6] != "--request-file":
        return None, "contained wrapper request-file flag is missing"
    request = PureWindowsPath(argv[7]) if windows else Path(argv[7])
    if (
        not request.is_absolute()
        or (windows and re.match(r"[A-Za-z]:\\", argv[7]) is None)
        or request.name != "request.json"
        or not request.parent.name.startswith("hol-guard-contained-test-")
    ):
        return None, "contained wrapper request path is not adapter-owned"
    if argv[8] != "--request-sha256" or _HEX64.fullmatch(argv[9]) is None:
        return None, "contained wrapper request digest is malformed"
    # The home binding alone may name the redacted home directory itself.
    if len(argv) == 12 and (argv[10] != "--home" or not (argv[11] == "{{home}}" or contained_public_path(argv[11]))):
        return None, "contained wrapper home binding is malformed"
    return argv, None


def workspace_identity_matches(observed: object, expected: object) -> bool:
    """Treat macOS /tmp aliases as one workspace without accepting relative paths."""
    if not isinstance(observed, str) or not isinstance(expected, str):
        return False
    observed_path = Path(observed)
    expected_path = Path(expected)
    if not observed_path.is_absolute() or not expected_path.is_absolute():
        return False
    try:
        return observed_path.resolve() == expected_path.resolve()
    except (OSError, RuntimeError, ValueError):
        return False


def receipt_is_authoritative(observation: dict[str, Any], expected_reason: str, expected_profile: str) -> bool:
    """Require the Rust receipt that denied the original input for containment."""
    native = observation.get("native_observation")
    receipt = native.get("native_receipt") if isinstance(native, dict) else None
    if not isinstance(native, dict) or not isinstance(receipt, dict):
        return False
    if (
        observation.get("decision") != "deny"
        or observation.get("reason_code") != expected_reason
        or observation.get("policy_action") != "sandbox-required"
        or native.get("required_execution_profile") != expected_profile
        or receipt.get("authority") != "rust"
        or receipt.get("harness") != "omp"
        or receipt.get("event_name") != "PreToolUse"
        or receipt.get("decision") != "deny"
        or receipt.get("policy_action") != "sandbox-required"
        or receipt.get("reason_code") != expected_reason
        or receipt.get("request_id") != observation.get("probe_request_id")
    ):
        return False
    if not all(isinstance(value, str) and value for value in (receipt.get("decision_id"), receipt.get("request_id"))):
        return False
    binding = receipt.get("command_extensions")
    if not isinstance(binding, dict):
        return False
    return all(
        isinstance(binding.get(key), str) and _HEX64.fullmatch(binding[key]) is not None
        for key in ("program_digest", "catalog_digest", "trust_digest")
    )


def _payload(call_id: str, tool_input: object) -> dict[str, Any]:
    return {"hook_event_name": "PreToolUse", "tool_call_id": call_id, "tool_name": "bash", "tool_input": tool_input}


def request_proofs(host_log: Path, workspace: Path, replacements: dict[Redaction, str]) -> list[dict[str, Any]]:
    """Bounded public proofs of the adapter request bytes the trusted host observer captured.

    The adapter deletes its request once the wrapper runs, so the observer reads the exact file the
    executed wrapper names. Bytes for another workspace, call or schema never become a proof.
    """
    captured: dict[str, bytes | None] = {}
    for line in host_log.read_text(encoding="utf-8").splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if not isinstance(event, dict) or event.get("type") != CAPTURE_EVENT:
            continue
        call_id, encoded = event.get("toolCallId"), event.get("request")
        if not isinstance(call_id, str) or not isinstance(encoded, str):
            continue
        try:
            raw = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError):
            raw = None
        # Two captures for one call are ambiguous, so neither proves anything.
        captured[call_id] = None if call_id in captured or raw is None or len(raw) > _REQUEST_LIMIT else raw
    proofs = []
    for call_id, raw in captured.items():
        try:
            request = json.loads(raw) if raw is not None else None
        except ValueError:
            continue
        payload = request.get("payload") if isinstance(request, dict) else None
        if (
            raw is None
            or not isinstance(request, dict)
            or not isinstance(payload, dict)
            or request.get("schema") != "guard-contained-test-request.v1"
            or not workspace_identity_matches(request.get("workspace"), str(workspace))
            or payload.get("hook_event_name") != "PreToolUse"
            or payload.get("tool_call_id") != call_id
            or payload.get("tool_name") != "bash"
            or not isinstance(payload.get("tool_input"), dict)
        ):
            continue
        proofs.append(
            {
                "schema": PROOF_SCHEMA,
                "tool_call_id": call_id,
                "workspace": "{{workspace}}",
                "payload_sha256": input_digest(_payload(call_id, redact_value(payload["tool_input"], replacements))),
                "request_sha256": hashlib.sha256(raw).hexdigest(),
            }
        )
    return proofs


def _sandbox_refused(call: dict[str, Any], details: dict[str, Any], reviewed: Any) -> bool:
    """Whether a failed contained run shows the sandbox, not the command itself, stopped it."""
    result = call.get("result")
    content = result.get("content") if isinstance(result, dict) else None
    text = (
        " ".join(str(part.get("text", "")) for part in content if isinstance(part, dict))
        if isinstance(content, list)
        else ""
    )
    command = reviewed.get("command") if isinstance(reviewed, dict) else None
    return bool(_SANDBOX_DENIAL.search(text)) or (
        isinstance(command, str) and _curl_exit(command) and details.get("exitCode") in _CURL_NETWORK_EXITS
    )


def _curl_exit(command: str) -> bool:
    """Whether curl may supply the command's exit status.

    The shell reports the status of the last `;`, `||` or newline group. Within that group a
    failing `&&` step stops the chain and supplies its own status, and a step's status is that of
    the last stage of its pipeline, so any step whose pipeline ends in curl may.
    """
    group = re.split(r"\|\||[;\n]", command.replace("&&", "\0").strip())[-1]
    return any(re.match(r"(?:\S*/)?curl\s", step.split("|")[-1].strip() + " ") for step in group.split("\0"))


def _binding_error(
    call: dict[str, Any],
    pre: dict[str, Any],
    post: list[dict[str, Any]],
    proofs: list[Any],
    own_exit_ok: bool = False,
    contained_ok: bool = False,
) -> tuple[str, str] | None:
    reason = pre.get("reason_code")
    profile = CONTAINMENT_PROFILES.get(reason) if isinstance(reason, str) else None
    if call.get("name") != "bash" or pre.get("tool") != "bash" or profile is None:
        return "harness-error", "host execution differs from the input reviewed by Guard"
    if not receipt_is_authoritative(pre, reason, profile):
        return "harness-error", "contained rewrite lacks an authoritative Rust containment receipt"
    wrapper = call.get("args", {}).get("command")
    if reason == "native_bash_owner_required":
        from .bash_owner_wrapper import normalized_argv

        argv, wrapper_error = normalized_argv(wrapper, call["id"])
    else:
        argv, wrapper_error = contained_wrapper_argv(wrapper, "{{workspace}}")
    if wrapper_error or argv is None:
        return "harness-error", wrapper_error or "contained wrapper is unavailable"
    # Only a full task can run in the account's own home, where the adapter omits the binding.
    homes = ([], ["--home", "{{home}}"]) if own_exit_ok else (["--home", "{{home}}"],)
    windows = windows_sink(argv)
    executable = windows or PurePosixPath(argv[0]).name == "hol-guard"
    guard_home = "{{fixture}}\\guard-home" if windows else "{{fixture}}/guard-home"
    if not executable or argv[3] != guard_home or argv[10:] not in homes:
        return "harness-error", "contained wrapper is not bound to the case's Guard installation"
    post_input = post[0].get("input") if len(post) == 1 else None
    if (
        len(post) != 1
        or post[0].get("tool") != "bash"
        or post[0].get("decision") != "allow"
        or not isinstance(post_input, dict)
        or post_input.get("command") != wrapper
    ):
        return "harness-error", "contained post observation is not bound to the executed wrapper"
    matches = [proof for proof in proofs if isinstance(proof, dict) and proof.get("tool_call_id") == call["id"]]
    proof = matches[0] if len(matches) == 1 else {}
    if set(proof) != PROOF_KEYS or proof["schema"] != PROOF_SCHEMA or proof["workspace"] != "{{workspace}}":
        return "harness-error", "contained request bytes were not captured for the executed wrapper"
    if proof["request_sha256"] != argv[9]:
        return "harness-error", "captured contained request digest differs from the executed wrapper"
    if proof["payload_sha256"] != input_digest(_payload(call["id"], pre.get("input"))):
        return "harness-error", "captured contained request payload differs from the input Guard reviewed"
    result = call.get("result")
    details = result.get("details") if isinstance(result, dict) else None
    presentation = details.get("holGuardContainedTest") if isinstance(details, dict) else None
    if (
        not isinstance(details, dict)
        or not isinstance(presentation, dict)
        or presentation.get("schema") != "guard-contained-test-presentation.v1"
        or presentation.get("toolCallId") != call["id"]
        or presentation.get("input") != pre.get("input")
        or presentation.get("command") != wrapper
    ):
        return "harness-error", "contained result presentation is not bound to the original command and wrapper"
    # OMP reports exitCode only for a failed command; a present code must be zero. In a full task the
    # agent's own commands fail too (a missing directory, a test it has yet to fix), and the host would
    # have returned the same code, so there a non-zero exit counts only when the sandbox refused it.
    exit_code = details.get("exitCode", 0)
    if call.get("is_error") is not False or exit_code != 0:
        own_failure = own_exit_ok and isinstance(exit_code, int) and exit_code not in (0, 126)
        if not own_failure or _sandbox_refused(call, details, pre.get("input")):
            if contained_ok:
                # A protection case's rerun is not ordinary work, so a refusal here is a missing
                # containment proof, not Guard interrupting a developer. The case still fails.
                return (
                    "harness-error",
                    f"the contained rerun of the protected command did not complete (exit {exit_code})",
                )
            return "false-positive", f"Guard's contained run of ordinary work failed (exit {exit_code})"
    return None


def contained_calls(
    expectation: str,
    case: dict[str, Any],
    calls: list[dict[str, Any]],
    *,
    approval_retry: bool = False,
    contained_ok: bool = False,
) -> tuple[dict[str, dict[str, Any]], tuple[str, str] | None]:
    """Reviewed inputs of fully bound contained calls, or the outcome for a rewrite that is not bound.

    Only a call Guard denied for containment whose host input differs from the reviewed input is a
    contained rewrite; any other deny keeps the ordinary judgement and still counts as interruption.

    ``contained_ok`` is the author's declaration that a protection case accepts Guard's own
    contained route as its stop. It widens only which containment reasons open this path; every
    binding ``_binding_error`` requires — the Rust denial receipt, the canonical wrapper argv, the
    guard-home and workspace bindings, the captured request bytes and a successful result — still
    has to hold, so an unproven rewrite is never bound and never passes.
    """
    if expectation != "allow" and not approval_retry and not contained_ok:
        return {}, None
    reasons = frozenset(CONTAINMENT_PROFILES) if contained_ok else frozenset({"native_bash_owner_required"})
    observations = [row for row in case.get("guard_observations", []) if isinstance(row, dict)]
    proofs = case.get("contained_request_proofs", [])
    if not isinstance(proofs, list):
        return {}, ("harness-error", "contained request proofs are malformed")
    bound: dict[str, dict[str, Any]] = {}
    for call in calls:
        rows = [row for row in observations if row.get("tool_call_id") == call.get("id")]
        pre = [row for row in rows if row.get("event") == "PreToolUse"]
        reviewed = pre[0].get("input") if len(pre) == 1 else None
        if expectation != "allow" and (not pre or pre[0].get("reason_code") not in reasons):
            continue
        if (
            not isinstance(reviewed, dict)
            or pre[0].get("decision") != "deny"
            or pre[0].get("policy_action") != "sandbox-required"
            or not isinstance(call.get("args"), dict)
            or input_matches(call.get("name", ""), call["args"], reviewed)
        ):
            continue
        post = [row for row in rows if row.get("event") == "PostToolUse"]
        error = _binding_error(
            call,
            pre[0],
            post,
            proofs,
            own_exit_ok=case.get("full_task_mode") is not None or approval_retry,
            contained_ok=contained_ok,
        )
        if error:
            return {}, error
        bound[call["id"]] = reviewed
    return bound, None


def effective_calls(calls: list[dict[str, Any]], contained: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """Judge a bound contained call by the command Guard reviewed, not the wrapper that ran it."""
    return [{**call, "args": dict(contained[call["id"]])} if call["id"] in contained else call for call in calls]


def is_contained_deny(row: Any, contained: dict[str, dict[str, Any]]) -> bool:
    """The by-design containment deny of a bound call; never any other Guard decision."""
    return (
        isinstance(row, dict)
        and row.get("tool_call_id") in contained
        and row.get("event") == "PreToolUse"
        and row.get("decision") == "deny"
        and row.get("policy_action") == "sandbox-required"
    )
