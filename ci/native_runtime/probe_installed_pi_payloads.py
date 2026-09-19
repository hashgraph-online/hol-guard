"""Installed Pi probe payloads helpers; dependencies remain bound to its public entry point."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .probe_installed_pi_api import probe_api


def _cases() -> list[dict[str, Any]]:
    _api = probe_api()
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
    _api = probe_api()
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
    _api = probe_api()
    text = "".join(item["text"] for item in content if item.get("type") == "text" and isinstance(item.get("text"), str))
    return _api.hashlib.sha256(text.encode("utf-8")).hexdigest(), len(text), text[: _api._TEXT_LIMIT]


def _canonical_content_digest(content: list[dict[str, Any]]) -> str:
    _api = probe_api()
    canonical = _api.json.dumps(content, ensure_ascii=False, separators=(",", ":"))
    return _api.hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _write_cli_wrapper(path: Path, *, python_path: Path, log_path: Path, negative: bool) -> None:
    _api = probe_api()
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
    path.write_text(_api.textwrap.dedent(source), encoding="utf-8")
    path.chmod(0o700)


def _write_node_runner(path: Path) -> None:
    _api = probe_api()
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
    _api = probe_api()
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
    _api = probe_api()
    completed = _api._run(
        [*node, str(runner), str(extension), str(cases), str(cwd)],
        env=env,
        cwd=cwd,
        timeout=180,
        label="generated Pi extension",
    )
    try:
        payload = _api.json.loads(completed.stdout.decode("utf-8"))
        results = payload["results"]
        fetches = payload["fetches"]
    except (KeyError, TypeError, ValueError, UnicodeDecodeError) as exc:
        raise _api.ProbeError("generated Pi extension returned invalid result JSON") from exc
    if not isinstance(results, list) or not all(isinstance(result, dict) for result in results):
        raise _api.ProbeError("generated Pi extension returned an invalid result list")
    if not isinstance(fetches, list) or not all(isinstance(fetch, dict) for fetch in fetches):
        raise _api.ProbeError("generated Pi extension returned invalid fetch evidence")
    return results, fetches
