"""Exercise the installed Pi/OMP extension against a scoped Guard daemon.

The native-wheel workflow already builds and installs the wheel. This probe
checks the generated extension boundary through the installed daemon's native
resident route; negative cases deliberately inject malformed CLI results to
prove the extension remains fail-closed.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib
import json
import os
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
from collections.abc import Mapping
from importlib import metadata
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[2]
_TEXT_LIMIT = 12_000
_NODE_PROBE_TIMEOUT = 5.0
_DAEMON_READINESS_TIMEOUT = 5.0
_DAEMON_CLEANUP_TIMEOUT = 10.0
_NODE_PROBE_SOURCE = 'const typedValue: string = "node-capability-probe";\nprocess.stdout.write(typedValue);\n'
_ENV_ALLOWLIST = {
    "COMSPEC",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "PATH",
    "PATHEXT",
    "SYSTEMROOT",
    "TEMP",
    "TMPDIR",
    "USERPROFILE",
}


class ProbeError(RuntimeError):
    """Raised when the installed Pi/native boundary cannot be proven."""


class ProbeCleanupError(ProbeError):
    """Raised when startup cleanup must be retained for a bounded retry."""


class ProbeCleanupUnsafeError(ProbeCleanupError):
    """Raised when daemon containment is unproven and the scratch root may be mutable."""


class _DaemonCallTimeoutError(ProbeCleanupUnsafeError):
    """Internal signal interruption for a bounded daemon lifecycle call."""


def _is_source_checkout_package(package_path: Path, repo_root: Path) -> bool:
    return package_path.is_relative_to((repo_root / "src" / "codex_plugin_scanner").resolve())


def _installed_package_path(repo_root: Path) -> Path:
    package = importlib.import_module("codex_plugin_scanner")
    raw_path = getattr(package, "__file__", None)
    if not isinstance(raw_path, str) or not raw_path:
        raise ProbeError("installed package origin is unavailable")
    raw_package_path = Path(raw_path)
    try:
        if stat.S_ISLNK(os.lstat(raw_package_path).st_mode):
            raise ProbeError("installed package module is symlinked")
    except OSError as exc:
        raise ProbeError("installed package module origin could not be inspected") from exc
    package_path = raw_package_path.resolve()
    if _is_source_checkout_package(package_path, repo_root):
        raise ProbeError(f"probe imported source tree package: {package_path}")
    try:
        distribution = metadata.distribution("hol-guard")
        distribution_files = distribution.files
        direct_url_text = distribution.read_text("direct_url.json")
    except (metadata.PackageNotFoundError, OSError, ValueError) as exc:
        raise ProbeError("installed hol-guard distribution metadata is unavailable") from exc
    if not distribution_files:
        raise ProbeError("installed hol-guard distribution file manifest is unavailable")
    if direct_url_text is not None:
        if not isinstance(direct_url_text, str) or not direct_url_text.strip():
            raise ProbeError("installed hol-guard direct URL metadata is empty")
        try:
            direct_url = json.loads(direct_url_text)
        except (TypeError, ValueError) as exc:
            raise ProbeError("installed hol-guard direct URL metadata is invalid") from exc
        if not isinstance(direct_url, Mapping):
            raise ProbeError("installed hol-guard direct URL metadata is invalid")
        directory_info = direct_url.get("dir_info")
        if directory_info is not None and not isinstance(directory_info, Mapping):
            raise ProbeError("installed hol-guard direct URL metadata is invalid")
        if isinstance(directory_info, Mapping):
            editable = directory_info.get("editable")
            if editable is not None and editable is not False:
                raise ProbeError("editable hol-guard installation is not accepted")
    try:
        resolved_distribution_files = set()
        for path in distribution_files:
            manifest_path = distribution.locate_file(path)
            if stat.S_ISLNK(os.lstat(manifest_path).st_mode):
                raise ProbeError("installed hol-guard distribution manifest contains a symlink")
            resolved_distribution_files.add(manifest_path.resolve())
    except ProbeError:
        raise
    except (OSError, RuntimeError, TypeError) as exc:
        raise ProbeError("installed hol-guard distribution file locations are unavailable") from exc
    if package_path not in resolved_distribution_files and not (
        package_path.suffix == ".pyc" and package_path.with_suffix(".py") in resolved_distribution_files
    ):
        raise ProbeError("installed package module is outside the hol-guard distribution manifest")
    return package_path


def _short_temp_parent() -> str | None:
    candidate = Path("/tmp")
    if candidate.is_dir() and os.access(candidate, os.W_OK | os.X_OK):
        return str(candidate)
    return None


def _short(value: bytes | str, limit: int = 1_500) -> str:
    text = value.decode("utf-8", errors="replace") if isinstance(value, bytes) else value
    return text if len(text) <= limit else text[:limit] + "..."


def _run(
    argv: list[str],
    *,
    env: Mapping[str, str],
    cwd: Path,
    timeout: float,
    label: str,
) -> subprocess.CompletedProcess[bytes]:
    try:
        completed = subprocess.run(
            argv,
            cwd=cwd,
            env=dict(env),
            capture_output=True,
            check=False,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ProbeError(f"{label} did not complete: {exc}") from exc
    if completed.returncode != 0:
        raise ProbeError(
            f"{label} failed with exit {completed.returncode}: "
            f"stdout={_short(completed.stdout)!r} stderr={_short(completed.stderr)!r}"
        )
    return completed


def _isolated_env(*, home: Path, python_path: Path) -> dict[str, str]:
    env = {key: value for key, value in os.environ.items() if key in _ENV_ALLOWLIST}
    bin_dir = home / ".local" / "bin"
    env["PATH"] = os.pathsep.join((str(bin_dir), str(python_path.parent), env.get("PATH", "")))
    env["HOME"] = str(home)
    env["USERPROFILE"] = str(home)
    env["PYTHONNOUSERSITE"] = "1"
    env["PYTHONUNBUFFERED"] = "1"
    env["XDG_CONFIG_HOME"] = str(home / "config")
    env["XDG_CACHE_HOME"] = str(home / "cache")
    env["XDG_DATA_HOME"] = str(home / "data")
    env["XDG_STATE_HOME"] = str(home / "state")
    env.pop("PYTHONPATH", None)
    for key in tuple(os.environ):
        if key.startswith("HOL_GUARD_") or key.startswith("GUARD_"):
            env.pop(key, None)
    return env


def _probe_python_path() -> Path:
    # Keep the venv launcher so its site-packages remain active; resolving a
    # symlink can escape the wheel-installed environment.
    return Path(sys.executable)


def _node_command() -> list[str]:
    node = shutil.which("node")
    if not node:
        raise ProbeError("Node is required for the generated Pi extension probe")
    try:
        with tempfile.TemporaryDirectory(prefix="hg-node-capability-", dir=_short_temp_parent()) as directory:
            module = Path(directory) / "capability-probe.ts"
            module.write_text(_NODE_PROBE_SOURCE, encoding="utf-8")
            for flags in (("--experimental-strip-types",), ()):
                try:
                    result = subprocess.run(
                        [node, *flags, str(module)],
                        capture_output=True,
                        check=False,
                        timeout=_NODE_PROBE_TIMEOUT,
                    )
                except (OSError, subprocess.TimeoutExpired):
                    continue
                if result.returncode == 0 and result.stdout == b"node-capability-probe":
                    return [node, "--no-warnings", *flags]
    except OSError as exc:
        raise ProbeError("Node TypeScript capability probe could not complete") from exc
    raise ProbeError("Node cannot execute erasable TypeScript modules")


def _cases() -> list[dict[str, Any]]:
    return [
        {"id": "small", "content": [{"type": "text", "text": "const value = 1;\r\n"}]},
        {"id": "empty", "content": []},
        {
            "id": "multiblock-crlf-unicode",
            "content": [
                {"type": "text", "text": "first line\r\n"},
                {"type": "metadata", "value": "ignored"},
                {"type": "text", "text": "second line: \U0001f600\n"},
            ],
        },
        {"id": "large-nonsource", "content": [{"type": "text", "text": "safe\r\n" * 2_500}]},
    ]


def _negative_cases() -> list[dict[str, Any]]:
    return [
        {"id": "negative-empty", "content": [{"type": "text", "text": "safe"}]},
        {"id": "negative-malformed", "content": [{"type": "text", "text": "safe"}]},
        {"id": "negative-missing-decision", "content": [{"type": "text", "text": "safe"}]},
        {"id": "negative-missing-proof", "content": [{"type": "text", "text": "safe"}]},
        {"id": "negative-mismatch-proof", "content": [{"type": "text", "text": "safe"}]},
        {"id": "negative-nonzero-allow", "content": [{"type": "text", "text": "safe"}]},
        {"id": "negative-observe", "content": [{"type": "text", "text": "record only"}]},
    ]


def _text_digest(content: list[dict[str, Any]]) -> tuple[str, int, str]:
    text = "".join(item["text"] for item in content if item.get("type") == "text" and isinstance(item.get("text"), str))
    return hashlib.sha256(text.encode("utf-8")).hexdigest(), len(text), text[:_TEXT_LIMIT]


def _canonical_content_digest(content: list[dict[str, Any]]) -> str:
    canonical = json.dumps(content, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _write_cli_wrapper(path: Path, *, python_path: Path, log_path: Path, negative: bool) -> None:
    source = f"""\
#!/usr/bin/env python3
import base64
import json
import os
import subprocess
import sys

PYTHON = {str(python_path)!r}
LOG = {str(log_path)!r}

def record(payload):
    with open(LOG, "ab") as handle:
        handle.write(json.dumps(payload, sort_keys=True).encode("utf-8") + b"\\n")

stdin_bytes = sys.stdin.buffer.read()
try:
    request = json.loads(stdin_bytes.decode("utf-8"))
except (UnicodeDecodeError, json.JSONDecodeError):
    request = {{}}
case_id = request.get("tool_call_id") if isinstance(request, dict) else None
if not isinstance(case_id, str):
    case_id = "unknown"
if {negative!s}:
    mismatch = "0" * 64
    responses = {{
        "negative-empty": (0, b"", b""),
        "negative-malformed": (0, b"not-json\\n", b""),
        "negative-missing-decision": (0, b'{{"policy_action":"allow"}}\\n', b""),
        "negative-missing-proof": (0, b'{{"decision":"allow","model_output_action":"allow_original"}}\\n', b""),
        "negative-mismatch-proof": (
            0,
            b'{{"decision":"allow","model_output_action":"allow_original","reviewed_output_sha256":"'
            + mismatch.encode()
            + b'"}}\\n',
            b"",
        ),
        "negative-nonzero-allow": (2, b'{{"decision":"allow"}}\\n', b"cli failed\\n"),
        "negative-observe": (0, b'{{"decision":"allow","observe_mode":true}}\\n', b""),
    }}
    returncode, stdout, stderr = responses.get(case_id, responses["negative-malformed"])
else:
    child_env = dict(os.environ)
    child_env.pop("PYTHONPATH", None)
    child_env["PYTHONNOUSERSITE"] = "1"
    try:
        completed = subprocess.run(
            [PYTHON, "-m", "codex_plugin_scanner.cli", *sys.argv[1:]],
            input=stdin_bytes,
            capture_output=True,
            check=False,
            env=child_env,
        )
        returncode, stdout, stderr = completed.returncode, completed.stdout, completed.stderr
    except OSError as exc:
        returncode, stdout, stderr = 127, b"", str(exc).encode("utf-8", errors="replace")
record({{
    "case_id": case_id,
    "returncode": returncode,
    "stdin_b64": base64.b64encode(stdin_bytes).decode("ascii"),
    "stdout_b64": base64.b64encode(stdout).decode("ascii"),
    "stderr_b64": base64.b64encode(stderr).decode("ascii"),
}})
sys.stdout.buffer.write(stdout)
sys.stderr.buffer.write(stderr)
sys.exit(returncode)
"""
    path.write_text(textwrap.dedent(source), encoding="utf-8")
    path.chmod(0o700)


def _write_node_runner(path: Path) -> None:
    path.write_text(
        """\
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { pathToFileURL } from "node:url";

const extensionPath = process.argv[2];
const casesPath = process.argv[3];
const cwd = process.argv[4];
const contentDigest = (canonical) => createHash("sha256").update(canonical).digest("hex");
const fetchEvidence = [];
const originalFetch = globalThis.fetch;
if (typeof originalFetch !== "function") throw new Error("fetch is unavailable");
globalThis.fetch = async (input, init) => {
  let requestUrl;
  try {
    requestUrl = new URL(
      typeof input === "string" || input instanceof URL ? String(input) : input.url,
    );
  } catch {
    return originalFetch(input, init);
  }
  if (!["127.0.0.1", "localhost", "::1", "[::1]"].includes(requestUrl.hostname)) {
    return originalFetch(input, init);
  }
  const method =
    init && typeof init.method === "string"
      ? init.method.toUpperCase()
      : typeof Request !== "undefined" && input instanceof Request
        ? input.method.toUpperCase()
        : "GET";
  const response = await originalFetch(input, init);
  const proof = {};
  try {
    const body = await response.clone().json();
    if (body && typeof body === "object" && !Array.isArray(body)) {
      for (const key of [
        "decision",
        "model_output_action",
        "reviewed_output_sha256",
        "observe_mode",
        "policy_action",
      ]) {
        const value = body[key];
        if (typeof value === "string" || typeof value === "boolean") proof[key] = value;
      }
    }
  } catch {}
  fetchEvidence.push({ method, pathname: requestUrl.pathname, status: response.status, ...proof });
  return response;
};
const extensionModule = await import(pathToFileURL(extensionPath).href);
const handlers = new Map();
const notifications = [];
const pi = {
  on(name, handler) { handlers.set(name, handler); },
  sendMessage(...args) { notifications.push({ kind: "sendMessage", args }); },
};
extensionModule.default(pi);
const handler = handlers.get("tool_result");
if (typeof handler !== "function") throw new Error("generated extension did not register tool_result");
const cases = JSON.parse(readFileSync(casesPath, "utf8"));
const results = [];
for (const testCase of cases) {
  const before = notifications.length;
  const fetchStart = fetchEvidence.length;
  const event = {
    toolCallId: testCase.id,
    toolName: "Bash",
    content: structuredClone(testCase.content),
    details: { probe: testCase.id },
    isError: false,
  };
  const inputContentBefore = JSON.stringify(event.content);
  const result = await handler(
    event,
    { cwd, ui: { notify(message, kind) { notifications.push({ message, kind }); } } },
  );
  const inputContentAfter = JSON.stringify(event.content);
  const fetchEnd = fetchEvidence.length;
  for (const fetch of fetchEvidence.slice(fetchStart, fetchEnd)) fetch.case_id = testCase.id;
  results.push({
    id: testCase.id,
    preserved: result === undefined,
    result: result === undefined ? null : result,
    notifications: notifications.slice(before),
    input_content_before_sha256: contentDigest(inputContentBefore),
    input_content_after_sha256: contentDigest(inputContentAfter),
    input_content_unchanged: inputContentBefore === inputContentAfter,
  });
}
process.stdout.write(JSON.stringify({ results, fetches: fetchEvidence }));
""",
        encoding="utf-8",
    )


def _generate_extension(
    path: Path,
    *,
    guard_home: Path,
    home: Path,
    settings_path: Path,
) -> None:
    from codex_plugin_scanner.guard.adapters.pi_extension_source import managed_extension_source

    path.write_text(
        managed_extension_source(
            guard_home=guard_home,
            home_dir=home,
            settings_path=settings_path,
            harness="omp",
            display_name="Oh My Pi",
        ),
        encoding="utf-8",
    )


def _run_node_cases(
    *,
    node: list[str],
    extension: Path,
    runner: Path,
    cases: Path,
    cwd: Path,
    env: Mapping[str, str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    completed = _run(
        [*node, str(runner), str(extension), str(cases), str(cwd)],
        env=env,
        cwd=cwd,
        timeout=180,
        label="generated Pi extension",
    )
    try:
        payload = json.loads(completed.stdout.decode("utf-8"))
        results = payload["results"]
        fetches = payload["fetches"]
    except (KeyError, TypeError, ValueError, UnicodeDecodeError) as exc:
        raise ProbeError("generated Pi extension returned invalid result JSON") from exc
    if not isinstance(results, list) or not all(isinstance(result, dict) for result in results):
        raise ProbeError("generated Pi extension returned an invalid result list")
    if not isinstance(fetches, list) or not all(isinstance(fetch, dict) for fetch in fetches):
        raise ProbeError("generated Pi extension returned invalid fetch evidence")
    return results, fetches


def _read_records(path: Path) -> dict[str, list[dict[str, Any]]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ProbeError(f"CLI wrapper did not write its capture log: {exc}") from exc
    grouped: dict[str, list[dict[str, Any]]] = {}
    for line in lines:
        try:
            record = json.loads(line)
            case_id = record["case_id"]
        except (KeyError, TypeError, ValueError) as exc:
            raise ProbeError("CLI wrapper capture log contains invalid JSON") from exc
        if not isinstance(case_id, str) or not isinstance(record, dict):
            raise ProbeError("CLI wrapper capture log has an invalid record")
        grouped.setdefault(case_id, []).append(record)
    return grouped


def _payload_from_record(record: Mapping[str, Any]) -> dict[str, Any]:
    try:
        raw = base64.b64decode(str(record["stdin_b64"]), validate=True)
        payload = json.loads(raw.decode("utf-8"))
    except (KeyError, ValueError, UnicodeDecodeError) as exc:
        raise ProbeError("CLI wrapper captured invalid request payload") from exc
    if not isinstance(payload, dict):
        raise ProbeError("CLI wrapper captured a non-object request payload")
    return payload


def _response_from_record(record: Mapping[str, Any]) -> dict[str, Any] | None:
    try:
        stdout = base64.b64decode(str(record["stdout_b64"]), validate=True).decode("utf-8")
    except (KeyError, ValueError, UnicodeDecodeError) as exc:
        raise ProbeError("CLI wrapper captured invalid stdout") from exc
    for line in reversed(stdout.splitlines()):
        try:
            value = json.loads(line)
        except ValueError:
            continue
        if isinstance(value, dict) and "decision" in value:
            return value
    return None


def _assert_real_results(
    results: list[dict[str, Any]],
    cases: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    result_ids = [result.get("id") for result in results]
    if len(results) != len(cases) or any(not isinstance(result_id, str) for result_id in result_ids):
        raise ProbeError("generated extension did not return every real case")
    if len(set(result_ids)) != len(result_ids):
        raise ProbeError("generated extension returned duplicate real case IDs")
    by_id = {result["id"]: result for result in results}
    expected_ids = {str(case["id"]) for case in cases}
    if set(by_id) != expected_ids:
        raise ProbeError("generated extension did not return every real case")
    evidence: dict[str, dict[str, Any]] = {}
    for case in cases:
        case_id = str(case["id"])
        result = by_id[case_id]
        digest, chars, excerpt = _text_digest(case["content"])
        canonical_digest = _canonical_content_digest(case["content"])
        if (
            result.get("input_content_before_sha256") != canonical_digest
            or result.get("input_content_after_sha256") != canonical_digest
        ):
            raise ProbeError(f"{case_id} mutated the canonical input event")
        preserved = result.get("preserved") is True
        if preserved:
            if result.get("input_content_unchanged") is not True:
                raise ProbeError(f"{case_id} mutated the canonical input event")
        elif case_id != "large-nonsource":
            raise ProbeError(f"{case_id} did not preserve the exact reviewed output")
        else:
            returned = result.get("result")
            content = returned.get("content") if isinstance(returned, dict) else None
            first = content[0] if isinstance(content, list) and content else None
            text = first.get("text") if isinstance(first, dict) else None
            if not isinstance(text, str) or text != excerpt:
                raise ProbeError("large-nonsource did not return the exact bounded reviewed excerpt")
        evidence[case_id] = {
            "sha256": digest,
            "chars": chars,
            "excerpt_chars": len(excerpt),
            "preserved": preserved,
            "input_content_unchanged": result.get("input_content_unchanged") is True,
        }
    return evidence


def _assert_fetch_evidence(
    fetches: list[dict[str, Any]],
    results: list[dict[str, Any]],
    cases: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Validate redacted daemon responses correlated to each generated case."""
    allowed_keys = {
        "case_id",
        "method",
        "pathname",
        "status",
        "decision",
        "model_output_action",
        "reviewed_output_sha256",
        "observe_mode",
        "policy_action",
    }
    if len(fetches) != len(cases):
        raise ProbeError("generated extension did not make exactly one daemon request per real case")
    result_ids = [result.get("id") for result in results]
    if len(results) != len(cases) or any(not isinstance(result_id, str) for result_id in result_ids):
        raise ProbeError("daemon fetch evidence could not correlate every real case")
    if len(set(result_ids)) != len(result_ids):
        raise ProbeError("daemon fetch evidence found duplicate real case IDs")
    by_id = {result["id"]: result for result in results}
    expected_ids = {str(case["id"]) for case in cases}
    if set(by_id) != expected_ids:
        raise ProbeError("daemon fetch evidence could not correlate every real case")
    fetches_by_case: dict[str, list[dict[str, Any]]] = {}
    for fetch in fetches:
        case_id = fetch.get("case_id")
        if not isinstance(case_id, str):
            raise ProbeError("daemon fetch evidence is missing its case correlation")
        fetches_by_case.setdefault(case_id, []).append(fetch)
    if set(fetches_by_case) != expected_ids or any(len(case_fetches) != 1 for case_fetches in fetches_by_case.values()):
        raise ProbeError("daemon fetch evidence did not contain exactly one response per real case")
    evidence: dict[str, dict[str, Any]] = {}
    for case in cases:
        case_id = str(case["id"])
        fetch = fetches_by_case[case_id][0]
        if set(fetch) - allowed_keys:
            raise ProbeError(f"daemon fetch evidence contains unapproved fields for {case_id}")
        if fetch.get("method") != "POST" or fetch.get("pathname") != "/v1/hooks/omp":
            raise ProbeError(f"generated extension used an unexpected daemon route for {case_id}")
        if fetch.get("status") != 200:
            raise ProbeError(f"daemon hook response was not successful for {case_id}")
        result = by_id[case_id]
        digest, chars, _ = _text_digest(case["content"])
        preserved = result.get("preserved") is True
        if preserved:
            expected_proof = {
                "decision": "allow",
                "model_output_action": "allow_original",
                "reviewed_output_sha256": digest,
            }
        else:
            expected_proof = {
                "decision": "allow",
                "model_output_action": "replace_with_reviewed_excerpt",
            }
            if case_id != "large-nonsource":
                raise ProbeError(f"{case_id} was not preserved and is not an excerpt case")
        for key, expected in expected_proof.items():
            if fetch.get(key) != expected:
                raise ProbeError(f"daemon response proof mismatch for {case_id}: {key}")
        evidence[case_id] = {
            "case_id": case_id,
            "method": fetch["method"],
            "pathname": fetch["pathname"],
            "status": fetch["status"],
            **expected_proof,
            "sha256": digest,
            "chars": chars,
            "preserved": preserved,
        }
    return evidence


def _assert_native_route_metrics(snapshot: Mapping[str, Any], expected: int) -> dict[str, int]:
    routes = snapshot.get("routes")
    if not isinstance(routes, Mapping):
        raise ProbeError("daemon hook metrics did not expose route counts")
    normalized: dict[str, int] = {}
    for route, count in routes.items():
        if not isinstance(route, str) or not isinstance(count, int) or count < 0:
            raise ProbeError("daemon hook metrics contained invalid route counts")
        normalized[route] = count
    if normalized.get("native_resident") != expected or sum(normalized.values()) != expected:
        raise ProbeError(f"positive daemon cases were not all native_resident: {normalized}")
    return normalized


def _wait_for_native_route_metrics(daemon: Any, expected: int, *, timeout_seconds: float = 5.0) -> dict[str, int]:
    metrics = getattr(getattr(daemon, "_server", None), "hook_worker", None)
    metrics = getattr(metrics, "metrics", None)
    snapshot = getattr(metrics, "snapshot", None)
    if not callable(snapshot):
        raise ProbeError("installed daemon did not expose hook route metrics")
    deadline = time.monotonic() + timeout_seconds
    last_routes: dict[str, int] = {}
    while time.monotonic() < deadline:
        current = snapshot()
        if isinstance(current, Mapping):
            routes = current.get("routes")
            if isinstance(routes, Mapping):
                last_routes = {str(route): int(count) for route, count in routes.items() if isinstance(count, int)}
            if last_routes.get("native_resident") == expected and sum(last_routes.values()) == expected:
                return _assert_native_route_metrics(current, expected)
        time.sleep(0.01)
    raise ProbeError(f"timed out waiting for native resident route metrics: {last_routes}")


def _assert_no_positive_cli_fallback(path: Path) -> None:
    if path.exists():
        raise ProbeError("positive generated extension unexpectedly used the CLI fallback")


def _assert_negative_results(
    results: list[dict[str, Any]],
    records: dict[str, list[dict[str, Any]]],
) -> dict[str, dict[str, Any]]:
    expected_ids = {str(case["id"]) for case in _negative_cases()}
    result_ids = [result.get("id") for result in results]
    if len(results) != len(expected_ids) or any(not isinstance(result_id, str) for result_id in result_ids):
        raise ProbeError("generated extension did not return every malformed-result case")
    if len(set(result_ids)) != len(result_ids):
        raise ProbeError("generated extension returned duplicate malformed-result case IDs")
    by_id = {result["id"]: result for result in results}
    if set(by_id) != expected_ids:
        raise ProbeError("generated extension did not return every malformed-result case")
    evidence: dict[str, dict[str, Any]] = {}
    for case_id, result in by_id.items():
        matching = records.get(case_id, [])
        if not matching:
            raise ProbeError(f"negative CLI wrapper was not invoked for {case_id}")
        record = matching[-1]
        if case_id == "negative-nonzero-allow" and record.get("returncode") == 0:
            raise ProbeError("negative nonzero CLI case unexpectedly exited zero")
        preserved = result.get("preserved") is True
        response: dict[str, Any] | None = None
        if case_id == "negative-observe":
            response = _response_from_record(record)
            if record.get("returncode") != 0:
                raise ProbeError("explicit observe response exited nonzero")
            if not preserved or not isinstance(response, dict):
                raise ProbeError("explicit observe response was not preserved")
            if response.get("decision") != "allow" or response.get("observe_mode") is not True:
                raise ProbeError("explicit observe response lacked canonical allow metadata")
        elif preserved:
            raise ProbeError(f"malformed result silently preserved output: {case_id}")
        else:
            returned = result.get("result")
            if not isinstance(returned, dict) or returned.get("isError") is not True:
                raise ProbeError(f"malformed result was not visibly blocked: {case_id}")
        evidence[case_id] = {
            "cli_invocations": len(matching),
            "preserved": preserved,
            "observe_mode": (
                response.get("observe_mode") if case_id == "negative-observe" and isinstance(response, dict) else None
            ),
            "is_error": bool(isinstance(result.get("result"), dict) and result["result"].get("isError")),
        }
    return evidence


def _probe_native_identity() -> tuple[Any, Any, Any]:
    from codex_plugin_scanner.guard.config import hook_fast_path_enabled
    from codex_plugin_scanner.guard.native_runtime import native_mode, native_runtime_status

    if native_mode() != "auto":
        raise ProbeError(f"unexpected native mode: {native_mode()}")
    if not hook_fast_path_enabled():
        raise ProbeError("unset fast-path configuration must be enabled")
    status = native_runtime_status()
    if not status.available or not status.compatible or status.reason != "native_ready":
        raise ProbeError(f"installed native runtime is not ready: {status}")
    if status.identity is None or status.capabilities is None:
        raise ProbeError(f"installed native runtime identity is incomplete: {status}")
    return status, status.identity, status.capabilities


def _close_startup_resource(resource: Any | None) -> BaseException | None:
    """Close a public startup resource when daemon construction aborts."""
    if resource is None:
        return None
    for method_name in ("close", "shutdown"):
        method = getattr(resource, method_name, None)
        if not callable(method):
            continue
        try:
            if method() is False:
                return ProbeCleanupUnsafeError(f"startup resource {method_name} did not complete")
        except BaseException as exc:
            return exc
        return None
    return None


def _start_installed_daemon(*, guard_home: Path, home: Path, workspace: Path, identity: Any) -> Any:
    """Start the installed Guard daemon that the generated extension will use."""
    from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
    from codex_plugin_scanner.guard.store import GuardStore

    store: Any | None = None
    daemon: Any | None = None
    try:
        store = GuardStore(
            guard_home,
            source="default",
            prime_policy_integrity=False,
            allow_system_keyring=False,
        )
        daemon = GuardDaemonServer(
            store,
            host="127.0.0.1",
            port=0,
            home_dir=home,
            workspace_dir=workspace,
        )
        # Match the native default probe: publish the policy overlay before the
        # first generated-extension request pays the workspace registration cost.
        register_workspace = getattr(
            daemon._server.hook_worker.policy_snapshot_publisher,
            "register_workspace",
            None,
        )
        if callable(register_workspace):
            _ = register_workspace(workspace)
        daemon.start()
    except BaseException as startup_error:
        cleanup_failure: BaseException | None = None
        cleanup_unsafe = False
        if daemon is not None:
            try:
                _cleanup_installed_daemon(daemon)
            except BaseException as exc:
                cleanup_failure = exc
                cleanup_unsafe = isinstance(exc, ProbeCleanupUnsafeError)
        else:
            # GuardDaemonServer owns rollback for any partially constructed
            # HTTP/publisher resources. Keep the root unsafe because no daemon
            # containment signal exists when construction never completed.
            resource_failure = _close_startup_resource(store)
            publisher = getattr(store, "policy_snapshot_publisher", None)
            if publisher is not None and publisher is not store:
                resource_failure = resource_failure or _close_startup_resource(publisher)
            cleanup_failure = resource_failure or ProbeCleanupUnsafeError(
                "installed Guard daemon construction did not complete"
            )
            cleanup_unsafe = True
        if not cleanup_unsafe:
            try:
                _cleanup_native(identity, guard_home)
            except BaseException as exc:
                cleanup_failure = cleanup_failure or exc
        if cleanup_failure is not None:
            cleanup_error_type = ProbeCleanupUnsafeError if cleanup_unsafe else ProbeCleanupError
            raise cleanup_error_type(
                f"installed Guard daemon startup cleanup failed: {type(cleanup_failure).__name__}"
            ) from startup_error
        raise
    return daemon


def _prepare_installed_daemon_workspace(daemon: Any, workspace: Path) -> Any:
    """Synchronously publish the workspace policy before exercising Node."""
    hook_worker = getattr(getattr(daemon, "_server", None), "hook_worker", None)
    prepare = getattr(hook_worker, "prepare_workspace_policy", None)
    if not callable(prepare):
        raise ProbeError("installed Guard daemon did not expose workspace readiness")
    deadline = time.monotonic() + _DAEMON_READINESS_TIMEOUT
    try:
        prepared = prepare(workspace, deadline=deadline)
    except BaseException as exc:
        raise ProbeError(f"installed Guard daemon workspace readiness failed: {type(exc).__name__}") from exc
    if prepared is None:
        raise ProbeError("installed Guard daemon workspace policy was not ready")
    return prepared


def _restore_alarm_state(
    *,
    prior_handler: Any,
    prior_timer: tuple[float, float],
    elapsed: float,
) -> None:
    """Restore SIGALRM even when setup or the bounded call failed."""
    restoration_error: BaseException | None = None
    try:
        signal.setitimer(signal.ITIMER_REAL, 0)
    except BaseException as exc:
        restoration_error = exc

    handler_restored = False
    try:
        signal.signal(signal.SIGALRM, prior_handler)
        handler_restored = True
    except BaseException as exc:
        restoration_error = restoration_error or exc

    if handler_restored:
        prior_remaining, prior_interval = prior_timer
        if prior_remaining > 0:
            remaining = prior_remaining - elapsed
            if remaining <= 0:
                # The prior timer may have expired while this bounded call ran.
                # Deliver it shortly instead of silently discarding it.
                remaining = 0.001
            try:
                signal.setitimer(signal.ITIMER_REAL, remaining, prior_interval)
            except BaseException as exc:
                restoration_error = restoration_error or exc

    if restoration_error is not None:
        raise ProbeCleanupUnsafeError("Guard daemon alarm state restoration failed") from restoration_error


def _bounded_daemon_call(daemon: Any, method_name: str) -> object | None:
    if threading.current_thread() is not threading.main_thread():
        raise ProbeError("bounded Guard daemon cleanup must run on the main thread")
    method = getattr(daemon, method_name, None)
    if not callable(method):
        raise ProbeError(f"installed Guard daemon {method_name} signal is unavailable")

    try:
        prior_handler = signal.getsignal(signal.SIGALRM)
        prior_timer = signal.getitimer(signal.ITIMER_REAL)
    except BaseException as exc:
        raise ProbeCleanupUnsafeError("Guard daemon alarm state could not be inspected") from exc
    started = time.monotonic()

    def timeout_handler(_signum: int, _frame: Any) -> None:
        raise _DaemonCallTimeoutError(f"authenticated Guard daemon {method_name} timed out")

    try:
        signal.signal(signal.SIGALRM, timeout_handler)
        signal.setitimer(signal.ITIMER_REAL, _DAEMON_CLEANUP_TIMEOUT)
        return method()
    except _DaemonCallTimeoutError:
        raise
    except BaseException as exc:
        if method_name == "stop":
            raise ProbeError(f"authenticated Guard daemon cleanup failed: {type(exc).__name__}") from exc
        raise ProbeError(f"authenticated Guard daemon {method_name} failed: {type(exc).__name__}") from exc
    finally:
        elapsed = time.monotonic() - started
        _restore_alarm_state(prior_handler=prior_handler, prior_timer=prior_timer, elapsed=elapsed)


def _bounded_daemon_finish(daemon: Any) -> bool:
    # GuardDaemonServer has no public containment status; use its bounded
    # lifecycle completion and quarantine signals rather than trusting stop().
    return _bounded_daemon_call(daemon, "_finish_service") is True


def _cleanup_installed_daemon(daemon: Any) -> None:
    try:
        _bounded_daemon_call(daemon, "stop")
        if not _bounded_daemon_finish(daemon):
            raise ProbeCleanupUnsafeError("authenticated Guard daemon containment was not confirmed")
        is_quarantined = getattr(daemon, "_is_quarantined", None)
        if callable(is_quarantined) and is_quarantined() is not False:
            raise ProbeCleanupUnsafeError("authenticated Guard daemon remained quarantined")
        serve_thread = getattr(daemon, "_thread", None)
        is_alive = getattr(serve_thread, "is_alive", None)
        if callable(is_alive) and is_alive():
            raise ProbeCleanupUnsafeError("authenticated Guard daemon serve thread remained alive")
    except BaseException as exc:
        if isinstance(exc, ProbeCleanupUnsafeError):
            raise exc
        if isinstance(exc, ProbeError):
            raise ProbeCleanupUnsafeError(str(exc)) from exc
        raise ProbeCleanupUnsafeError(f"authenticated Guard daemon cleanup failed: {type(exc).__name__}") from exc


def _native_state_files(guard_home: Path) -> tuple[Path, ...]:
    try:
        return tuple((guard_home / "native-runtime").glob("resident-v3-*/generation-*.json"))
    except (OSError, RuntimeError):
        return ()


def _native_cleanup_environment() -> dict[str, str]:
    allowed = {
        "COMSPEC",
        "HOME",
        "LANG",
        "PATHEXT",
        "SYSTEMROOT",
        "TEMP",
        "TMPDIR",
        "USERPROFILE",
        "WINDIR",
    }
    return {key: value for key, value in os.environ.items() if key in allowed or key.upper().startswith("LC_")}


def _cleanup_native(identity: Any, guard_home: Path) -> None:
    from codex_plugin_scanner.guard.native_resident_client import (
        close_native_residents,
        stop_native_resident,
    )

    cleanup_error: OSError | RuntimeError | None = None
    try:
        contained = close_native_residents(guard_home)
    except (OSError, RuntimeError) as exc:
        contained = False
        cleanup_error = exc
    if _native_state_files(guard_home):
        try:
            if not stop_native_resident(
                executable=identity.path,
                state_dir=guard_home / "native-runtime",
                environment=_native_cleanup_environment(),
                timeout_seconds=2.0,
            ):
                cleanup_error = cleanup_error or RuntimeError("native resident stop did not complete")
        except (OSError, RuntimeError) as exc:
            cleanup_error = cleanup_error or exc
    if cleanup_error is None and not contained:
        try:
            contained = close_native_residents(guard_home)
        except (OSError, RuntimeError) as exc:
            cleanup_error = exc
    if cleanup_error is None and not contained:
        cleanup_error = RuntimeError("native resident containment did not complete")
    if cleanup_error is None and _native_state_files(guard_home):
        cleanup_error = RuntimeError("native resident state remained after cleanup")
    if cleanup_error is not None:
        raise ProbeError(f"authenticated native cleanup failed: {type(cleanup_error).__name__}") from cleanup_error


def _remove_probe_path(path: Path) -> bool:
    try:
        if not path.exists() and not path.is_symlink():
            return True
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path)
        else:
            path.unlink()
    except OSError:
        return False
    return True


def _scrub_probe_root(root: Path, *, preserve_native_state: bool = False) -> int:
    """Remove probe captures while preserving only scoped native retry state."""
    if not root.exists():
        return 0
    if root.is_symlink():
        return 1
    try:
        children = tuple(root.iterdir())
    except OSError:
        return 1
    failures = 0
    for child in children:
        if preserve_native_state and child == root / "guard-home" and child.is_dir() and not child.is_symlink():
            native_state = child / "native-runtime"
            preserve_state = native_state.is_dir() and not native_state.is_symlink()
            if not preserve_state:
                if not _remove_probe_path(child):
                    failures += 1
                continue
            try:
                nested = tuple(child.iterdir())
            except OSError:
                failures += 1
                continue
            for nested_child in nested:
                if preserve_state and nested_child == native_state:
                    continue
                if not _remove_probe_path(nested_child):
                    failures += 1
            continue
        if not _remove_probe_path(child):
            failures += 1
    return failures


def _remaining_probe_paths(root: Path, *, preserve_native_state: bool = False) -> int:
    if not root.exists():
        return 0
    if root.is_symlink():
        return 1
    try:
        children = tuple(root.iterdir())
    except OSError:
        return 1
    remaining = 0
    for child in children:
        if preserve_native_state and child == root / "guard-home" and child.is_dir() and not child.is_symlink():
            native_state = child / "native-runtime"
            preserve_state = native_state.is_dir() and not native_state.is_symlink()
            if not preserve_state:
                remaining += 1
                continue
            try:
                nested = tuple(child.iterdir())
            except OSError:
                remaining += 1
                continue
            remaining += sum(not (preserve_state and nested_child == native_state) for nested_child in nested)
            continue
        remaining += 1
    return remaining


def _retain_private_native_retry_state(root: Path) -> bool:
    """Keep authenticated retry state private when cleanup must be deferred."""
    guard_home = root / "guard-home"
    native_state = guard_home / "native-runtime"
    try:
        guard_info = os.lstat(guard_home)
        native_info = os.lstat(native_state)
    except OSError:
        return False
    if any(stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) for info in (guard_info, native_info)):
        return False
    expected_owner = getattr(guard_info, "st_uid", None)
    try:
        for path in (guard_home, native_state):
            path.chmod(0o700)
        guard_info = os.lstat(guard_home)
        native_info = os.lstat(native_state)
    except OSError:
        return False
    pending = [(guard_home, guard_info), (native_state, native_info)]
    while pending:
        current, info = pending.pop()
        mode = stat.S_IMODE(info.st_mode)
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or mode != 0o700:
            return False
        if expected_owner is not None and getattr(info, "st_uid", None) != expected_owner:
            return False
        try:
            with os.scandir(current) as entries:
                children = tuple(entries)
        except OSError:
            return False
        for entry in children:
            try:
                child_info = os.lstat(entry.path)
            except OSError:
                return False
            if expected_owner is not None and getattr(child_info, "st_uid", None) != expected_owner:
                return False
            if stat.S_ISLNK(child_info.st_mode):
                return False
            if stat.S_ISDIR(child_info.st_mode):
                pending.append((Path(entry.path), child_info))
            elif not stat.S_ISREG(child_info.st_mode) or stat.S_IMODE(child_info.st_mode) != 0o600:
                return False
    return True


def _retain_cleanup_receipt(root: Path, failure: BaseException) -> None:
    """Retain only redacted retry state when authenticated cleanup cannot finish."""
    scrub_failures = _scrub_probe_root(root, preserve_native_state=True)
    native_state = root / "guard-home" / "native-runtime"
    native_state_present = native_state.is_dir() and not native_state.is_symlink()
    private_native_retry_state = _retain_private_native_retry_state(root)
    if native_state_present and not private_native_retry_state:
        scrub_failures += 1
    remaining_paths = _remaining_probe_paths(root, preserve_native_state=True)
    try:
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        (root / "cleanup-failure.json").write_text(
            json.dumps(
                {
                    "schema": "hol-guard.installed-pi-cleanup-failure.v1",
                    "probe_root": str(root),
                    "error_type": type(failure).__name__,
                    "remaining_nonretry_paths": remaining_paths,
                    "retry_required": True,
                    "scrub_complete": scrub_failures == 0 and remaining_paths == 0,
                    "scrub_failures": scrub_failures,
                    "private_native_retry_state_retained": private_native_retry_state,
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
    except OSError as exc:
        raise ProbeError("redacted cleanup receipt could not be written") from exc
    if scrub_failures or remaining_paths:
        raise ProbeError("probe capture scrub could not be confirmed")


def _retain_unsafe_cleanup_marker(root: Path, failure: BaseException) -> None:
    """Record a redacted timeout marker without touching a possibly live root."""
    try:
        root_info = os.lstat(root)
        if stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode):
            raise OSError("probe root is not a private directory")
        root.chmod(0o700)
        root_info = os.lstat(root)
        if stat.S_IMODE(root_info.st_mode) != 0o700:
            raise OSError("probe root could not be made private")
        marker = root / "cleanup-failure.json"
        marker.write_text(
            json.dumps(
                {
                    "schema": "hol-guard.installed-pi-cleanup-failure.v1",
                    "probe_root": str(root),
                    "error_type": type(failure).__name__,
                    "retry_required": True,
                    "cleanup_deferred": True,
                    "private_native_retry_state_retained": False,
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        marker.chmod(0o600)
    except OSError as exc:
        raise ProbeError("redacted timeout cleanup marker could not be written safely") from exc


def _remove_probe_root(root: Path) -> None:
    try:
        shutil.rmtree(root)
    except OSError as exc:
        try:
            _retain_cleanup_receipt(root, exc)
        except ProbeError as scrub_failure:
            raise scrub_failure from exc
        raise ProbeError("probe scratch cleanup failed") from exc


def _run_probe(*, json_path: Path | None = None) -> dict[str, Any]:
    if os.name == "nt":
        raise ProbeError("installed Pi/native output probe is POSIX-only")
    _installed_package_path(_REPO_ROOT)
    status, identity, capabilities = _probe_native_identity()
    node = _node_command()
    python_path = _probe_python_path()

    root = Path(tempfile.mkdtemp(prefix="hg-pi-native-", dir=_short_temp_parent()))
    daemon: Any | None = None
    native_started = False
    startup_cleanup_failure: ProbeError | None = None
    receipt: dict[str, Any] | None = None
    try:
        home = root / "home"
        guard_home = root / "guard-home"
        workspace = root / "workspace"
        for directory in (home, guard_home, workspace):
            directory.mkdir(mode=0o700)
        settings = root / "settings.json"
        settings.write_text("{}\n", encoding="utf-8")
        runner = root / "run-extension.mjs"
        _write_node_runner(runner)
        cases = _cases()
        cases_path = root / "cases.json"
        cases_path.write_text(json.dumps(cases, ensure_ascii=True), encoding="utf-8")
        real_log = root / "real-cli.jsonl"
        real_cli = home / ".local" / "bin" / "hol-guard"
        real_cli.parent.mkdir(mode=0o700, parents=True)
        _write_cli_wrapper(real_cli, python_path=python_path, log_path=real_log, negative=False)
        extension = root / "extension.ts"
        _generate_extension(
            extension,
            guard_home=guard_home,
            home=home,
            settings_path=settings,
        )
        version_module = importlib.import_module("codex_plugin_scanner.version")
        package_version = str(getattr(version_module, "__version__", "unknown"))
        try:
            daemon = _start_installed_daemon(
                guard_home=guard_home,
                home=home,
                workspace=workspace,
                identity=identity,
            )
        except ProbeCleanupError as exc:
            startup_cleanup_failure = exc
            raise
        native_started = True
        _prepare_installed_daemon_workspace(daemon, workspace)
        real_results, real_fetches = _run_node_cases(
            node=node,
            extension=extension,
            runner=runner,
            cases=cases_path,
            cwd=workspace,
            env=_isolated_env(home=home, python_path=python_path),
        )
        _assert_no_positive_cli_fallback(real_log)
        real_output_evidence = _assert_real_results(real_results, cases)
        real_fetch_evidence = _assert_fetch_evidence(real_fetches, real_results, cases)
        native_routes = _wait_for_native_route_metrics(daemon, len(cases))
        negative_home = root / "negative-home"
        negative_guard_home = root / "negative-guard-home"
        negative_workspace = root / "negative-workspace"
        for directory in (negative_home, negative_guard_home, negative_workspace):
            directory.mkdir(mode=0o700)
        negative_log = root / "negative-cli.jsonl"
        negative_cli = negative_home / ".local" / "bin" / "hol-guard"
        negative_cli.parent.mkdir(mode=0o700, parents=True)
        _write_cli_wrapper(negative_cli, python_path=python_path, log_path=negative_log, negative=True)
        negative_extension = root / "negative-extension.ts"
        _generate_extension(
            negative_extension,
            guard_home=negative_guard_home,
            home=negative_home,
            settings_path=root / "negative-settings.json",
        )
        negative_cases = _negative_cases()
        negative_results = []
        negative_errors = []
        for case in negative_cases:
            # Each malformed fallback must start with a fresh extension runtime.
            # A timed-out child can leave containment state set for that process.
            negative_cases_path = root / f"{case['id']}-cases.json"
            negative_cases_path.write_text(json.dumps([case], ensure_ascii=True), encoding="utf-8")
            try:
                case_results, _ = _run_node_cases(
                    node=node,
                    extension=negative_extension,
                    runner=runner,
                    cases=negative_cases_path,
                    cwd=negative_workspace,
                    env=_isolated_env(home=negative_home, python_path=python_path),
                )
            except ProbeError as exc:
                negative_errors.append((case["id"], exc))
                continue
            negative_results.extend(case_results)
        if negative_errors:
            failed_cases = ", ".join(str(case_id) for case_id, _ in negative_errors)
            raise ProbeError(f"generated Pi extension failed negative cases: {failed_cases}") from negative_errors[0][1]
        negative_evidence = _assert_negative_results(negative_results, _read_records(negative_log))
        receipt = {
            "schema": "hol-guard.installed-pi-native-output.v1",
            "package_version": package_version,
            "source_sha": getattr(capabilities, "build_sha", None),
            "package_origin_kind": "non-editable-distribution-manifest",
            "source_checkout_import": False,
            "execution_path": "unmodified-generated-extension-via-scoped-installed-daemon-native-resident",
            "native_prerequisite": "default-auto-status-checked",
            "workflow_order": "after-native-default-auto-probe",
            "daemon": "scoped-installed-GuardDaemonServer",
            "runtime": {
                "mode": status.mode,
                "reason": status.reason,
                "target": getattr(capabilities, "target", None),
                "runtime_version": getattr(capabilities, "runtime_version", None),
                "build_sha": getattr(capabilities, "build_sha", None),
                "runtime_sha256": getattr(identity, "sha256", None),
            },
            "generated_extension": {
                "harness": "omp",
                "real_cases": {
                    case_id: {
                        **real_output_evidence[case_id],
                        "daemon_response": real_fetch_evidence[case_id],
                    }
                    for case_id in real_output_evidence
                },
                "malformed_result_cases": negative_evidence,
            },
            "native_route_metrics": {"native_resident": native_routes["native_resident"]},
            "cleanup": "authenticated_daemon_stop_then_native_resident_stop",
        }
    finally:
        cleanup_failure: ProbeError | None = startup_cleanup_failure
        cleanup_unsafe = isinstance(cleanup_failure, ProbeCleanupUnsafeError)
        if daemon is not None:
            try:
                _cleanup_installed_daemon(daemon)
            except ProbeError as exc:
                cleanup_failure = exc
                cleanup_unsafe = isinstance(exc, ProbeCleanupUnsafeError)
        if native_started and not cleanup_unsafe:
            try:
                _cleanup_native(identity, guard_home)
            except ProbeError as exc:
                cleanup_failure = cleanup_failure or exc
        if cleanup_failure is not None:
            try:
                if cleanup_unsafe:
                    _retain_unsafe_cleanup_marker(root, cleanup_failure)
                else:
                    _retain_cleanup_receipt(root, cleanup_failure)
            except ProbeError as scrub_failure:
                raise scrub_failure from cleanup_failure
            raise cleanup_failure
        _remove_probe_root(root)

    if receipt is None:
        raise ProbeError("installed Pi/native probe did not produce a receipt")
    if json_path is not None:
        json_path.write_text(json.dumps(receipt, sort_keys=True) + "\n", encoding="utf-8")
    return receipt


def main(*, json_path: Path | None = None) -> int:
    receipt = _run_probe(json_path=json_path)
    print(json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()
    try:
        raise SystemExit(main(json_path=args.json))
    except (ProbeError, OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
