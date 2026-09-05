"""Managed Cline AgentPlugin transport for full pre/post tool mediation."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from contextlib import suppress
from hashlib import sha256
from pathlib import Path

from .base import HarnessContext
from .cline_paths import cline_plugin_root as _resolve_cline_plugin_root
from .guard_cli_attestation import guard_hook_command, resolve_attested_guard_cli

_MANAGED_MARKER = "HOL_GUARD_MANAGED_CLINE_PLUGIN_V1"
_SCHEMA_VERSION = 1
_PLUGIN_NAME = "hol-guard"
_PLUGIN_TIMEOUT_MS = 9_000
_MAX_PAYLOAD_BYTES = 256 * 1024
_MAX_PRETOOL_INPUT_BYTES = 64 * 1024
_PROOF_MAX_AGE_SECONDS = 7 * 24 * 60 * 60


def cline_plugin_root(context: HarnessContext) -> Path:
    return _resolve_cline_plugin_root(context)


def _state_path(context: HarnessContext) -> Path:
    return context.guard_home / "managed" / "cline" / "plugin-state.json"


def _adapter_state_path(context: HarnessContext) -> Path:
    return context.guard_home / "managed" / "cline" / "adapter-state.json"


def _proof_path(context: HarnessContext, name: str) -> Path:
    return context.guard_home / "managed" / "cline" / "proofs" / f"plugin-{name}.json"


def _atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.hol-guard.tmp-{os.getpid()}")
    with temporary.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def _is_managed_source(source: str) -> bool:
    return _MANAGED_MARKER in source


def _is_managed_plugin(path: Path) -> bool:
    try:
        return path.is_file() and not path.is_symlink() and _is_managed_source(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError):
        return False


def _plugin_source(context: HarnessContext, guard_cli: list[str]) -> str:
    proof_loaded = str(_proof_path(context, "loaded"))
    proof_pre = str(_proof_path(context, "pretool"))
    proof_post = str(_proof_path(context, "posttool"))
    adapter_state = str(_adapter_state_path(context))
    return f"""// {_MANAGED_MARKER}
// schema_version={_SCHEMA_VERSION}
import {{ spawnSync }} from "node:child_process";
import {{ mkdirSync, readFileSync, renameSync, writeFileSync }} from "node:fs";
import {{ dirname }} from "node:path";

const GUARD_CLI = {json.dumps(guard_cli)};
const TIMEOUT_MS = {_PLUGIN_TIMEOUT_MS};
const MAX_BYTES = {_MAX_PAYLOAD_BYTES};
const MAX_PRETOOL_INPUT_BYTES = {_MAX_PRETOOL_INPUT_BYTES};
const ADAPTER_STATE = {json.dumps(adapter_state)};
const BLOCK_DECISIONS = ["deny", "block", "ask"];
const REVIEW_ACTIONS = ["review", "require-reapproval", "sandbox-required", "block"];
const PROOFS = {{
  loaded: {json.dumps(proof_loaded)},
  pretool: {json.dumps(proof_pre)},
  posttool: {json.dumps(proof_post)},
}};

function proof(name, outcome) {{
  try {{
    const target = PROOFS[name];
    const durableOutcome = name === "pretool" ? "blocked" : name === "posttool" ? "replaced" : undefined;
    if (durableOutcome && outcome !== durableOutcome) {{
      try {{
        const current = JSON.parse(readFileSync(target, "utf8"));
        if (
          current &&
          current.source === "cline-plugin" &&
          current.proof === name &&
          current.outcome === durableOutcome
        ) return;
      }} catch {{}}
    }}
    mkdirSync(dirname(target), {{ recursive: true }});
    const temporary = `${{target}}.tmp`;
    writeFileSync(temporary, JSON.stringify({{
      schema_version: 1,
      source: "cline-plugin",
      proof: name,
      outcome,
      timestamp: Date.now() / 1000,
    }}));
    renameSync(temporary, target);
  }} catch {{
    // Proof persistence is diagnostic; enforcement still follows Guard's decision.
  }}
}}

function activeTransport() {{
  try {{
    const state = JSON.parse(readFileSync(ADAPTER_STATE, "utf8"));
    if (state && typeof state === "object" && typeof state.active_transport === "string") {{
      return state.active_transport;
    }}
  }} catch {{}}
  return undefined;
}}

function jsonBytes(value) {{
  try {{
    return Buffer.byteLength(JSON.stringify(value), "utf8");
  }} catch {{
    return Number.POSITIVE_INFINITY;
  }}
}}

function extractJson(stdout) {{
  const text = String(stdout ?? "").trim();
  if (!text) return undefined;
  const candidates = [text, ...text.split(/\\r?\\n/).filter(Boolean).reverse()];
  for (const candidate of candidates) {{
    if (!candidate.trim().startsWith("{{")) continue;
    try {{
      const value = JSON.parse(candidate);
      if (value && typeof value === "object" && !Array.isArray(value)) return value;
    }} catch {{}}
  }}
  return undefined;
}}

function guardReason(payload) {{
  if (!payload || typeof payload !== "object") return undefined;
  for (const key of ["reason", "stopReason", "review_hint", "systemMessage", "message", "error"]) {{
    if (typeof payload[key] === "string" && payload[key].trim()) return payload[key].trim();
  }}
  const specific = payload.hookSpecificOutput;
  if (specific && typeof specific === "object") {{
    for (const key of ["permissionDecisionReason", "additionalContext"]) {{
      if (typeof specific[key] === "string" && specific[key].trim()) return specific[key].trim();
    }}
    if (specific.decision && typeof specific.decision === "object") {{
      if (typeof specific.decision.message === "string") return specific.decision.message.trim();
    }}
  }}
  return undefined;
}}

function guardBlocks(payload) {{
  if (!payload || typeof payload !== "object") return true;
  if (payload.blocked === true || payload.continue === false) return true;
  if (typeof payload.decision === "string") {{
    if (BLOCK_DECISIONS.includes(payload.decision.toLowerCase())) return true;
  }}
  const action = payload.policy_action ?? payload.policyAction;
  if (typeof action === "string") {{
    if (REVIEW_ACTIONS.includes(action.toLowerCase())) return true;
  }}
  const specific = payload.hookSpecificOutput;
  if (specific && typeof specific === "object") {{
    if (typeof specific.permissionDecision === "string") {{
      if (BLOCK_DECISIONS.includes(specific.permissionDecision.toLowerCase())) return true;
    }}
    const nested = specific.decision;
    if (nested && typeof nested === "object" && typeof nested.behavior === "string") {{
      if (BLOCK_DECISIONS.includes(nested.behavior.toLowerCase())) return true;
    }}
  }}
  return false;
}}

function reviewedOutput(payload) {{
  if (!payload || typeof payload !== "object") return undefined;
  for (const key of ["reviewed_output", "reviewedOutput", "safe_output", "safeOutput", "replacement", "excerpt"]) {{
    if (typeof payload[key] === "string") return payload[key];
  }}
  return undefined;
}}

function mapParameters(input) {{
  if (!input || typeof input !== "object" || Array.isArray(input)) return {{}};
  const output = {{}};
  for (const [key, value] of Object.entries(input)) {{
    if (typeof value === "string") {{
      output[key] = value;
    }} else {{
      output[key] = JSON.stringify(value);
    }}
  }}
  return output;
}}

function payloadsForGuard(eventName, toolCall, input, result) {{
  const id = toolCall?.toolCallId ?? "";
  const name = toolCall?.toolName ?? "unknown";
  let current;
  const base = {{ hookName: eventName, hook_event_name: eventName }};
  if (eventName === "PostToolUse") {{
    current = {{ id, name, input, output: result?.output }};
    let resultText;
    if (typeof result?.output === "string") {{
      resultText = result.output;
    }} else {{
      resultText = JSON.stringify(result?.output);
    }}
    base.tool_result = current;
    base.postToolUse = {{
      toolName: current.name,
      parameters: mapParameters(input),
      result: resultText,
      success: result?.isError !== true,
      executionTimeMs: 0,
    }};
  }} else {{
    current = {{ id, name, input }};
    base.tool_call = current;
    base.preToolUse = {{ toolName: current.name, parameters: mapParameters(input) }};
  }}
  if (eventName !== "PreToolUse" || current.name !== "run_commands") return [base];
  let commands = input;
  if (input && typeof input === "object" && !Array.isArray(input)) {{
    commands = input.commands ?? input.command ?? input.cmd;
  }}
  if (typeof commands === "string") commands = [commands];
  if (!Array.isArray(commands)) return [base];
  const expanded = [];
  for (const item of commands) {{
    let command;
    if (typeof item === "string") {{
      command = item;
    }} else if (item && typeof item === "object") {{
      command = item.command ?? item.cmd;
    }}
    if (typeof command !== "string" || !command.trim()) continue;
    expanded.push({{
      hookName: eventName,
      hook_event_name: eventName,
      tool_call: {{ id: current.id, name: "run_command", input: {{ command }} }},
    }});
  }}
  if (expanded.length) return expanded;
  return [base];
}}

function invokeGuard(eventName, toolCall, input, result) {{
  if (eventName === "PreToolUse" && jsonBytes(input) > MAX_PRETOOL_INPUT_BYTES) {{
    return {{ ok: false, reason: "HOL Guard rejected an oversized Cline pre-tool request." }};
  }}
  let lastPayload;
  for (const payload of payloadsForGuard(eventName, toolCall, input, result)) {{
    const encoded = JSON.stringify(payload);
    if (Buffer.byteLength(encoded, "utf8") > MAX_BYTES) {{
      return {{ ok: false, reason: "HOL Guard rejected an oversized Cline plugin request." }};
    }}
    const child = spawnSync(GUARD_CLI[0], [...GUARD_CLI.slice(1), "--harness", "cline", "--json"], {{
      input: encoded,
      encoding: "utf8",
      timeout: TIMEOUT_MS,
      maxBuffer: MAX_BYTES * 2,
      windowsHide: true,
    }});
    const badExit = typeof child.status === "number" && child.status !== 0;
    const missingOutput = !String(child.stdout ?? "").trim();
    if (child.error || child.signal || (badExit && missingOutput)) {{
      return {{
        ok: false,
        reason: "HOL Guard evaluation was unavailable; this Cline action was not allowed to proceed.",
      }};
    }}
    const parsed = extractJson(child.stdout);
    if (!parsed) {{
      return {{
        ok: false,
        reason: "HOL Guard returned an invalid decision; this Cline action was not allowed to proceed.",
      }};
    }}
    lastPayload = parsed;
    if (guardBlocks(parsed)) return {{ ok: true, payload: parsed }};
  }}
  return {{ ok: true, payload: lastPayload ?? {{}} }};
}}

function blockedResult(reason, metadata) {{
  const safeResult = {{ output: reason, isError: true }};
  if (metadata) safeResult.metadata = metadata;
  return {{ result: safeResult }};
}}

const plugin = {{
  name: "hol-guard",
  manifest: {{ capabilities: ["hooks"] }},
  hooks: {{
    async beforeRun() {{
      proof("loaded", "loaded");
      return undefined;
    }},
    async beforeTool({{ toolCall, input }}) {{
      const active = activeTransport();
      if (active !== "plugin") {{
        if (active !== undefined) return undefined;
        proof("pretool", "blocked");
        return {{
          skip: true,
          reason: "HOL Guard Cline transport state is unavailable; this action was not allowed to proceed safely.",
        }};
      }}
      const decision = invokeGuard("PreToolUse", toolCall, input, undefined);
      if (!decision.ok) {{
        proof("pretool", "blocked");
        return {{ skip: true, reason: decision.reason }};
      }}
      if (!guardBlocks(decision.payload)) {{
        proof("pretool", "allowed");
        return undefined;
      }}
      proof("pretool", "blocked");
      return {{ skip: true, reason: guardReason(decision.payload) || "HOL Guard blocked this action." }};
    }},
    async afterTool({{ toolCall, input, result }}) {{
      const active = activeTransport();
      if (active !== "plugin") {{
        proof("posttool", "unchanged");
        return undefined;
      }}
      const decision = invokeGuard("PostToolUse", toolCall, input, result);
      if (!decision.ok) {{
        proof("posttool", "unchanged");
        return undefined;
      }}
      const replacement = reviewedOutput(decision.payload);
      if (guardBlocks(decision.payload)) {{
        proof("posttool", "replaced");
        const reason = guardReason(decision.payload) || "HOL Guard withheld this tool result.";
        return blockedResult(reason, result?.metadata);
      }}
      if (replacement !== undefined) {{
        proof("posttool", "replaced");
        return {{ result: {{ ...result, output: replacement }} }};
      }}
      proof("posttool", "unchanged");
      return undefined;
    }},
  }},
}};

export default plugin;
"""


def _package_json() -> str:
    payload = {
        "name": "hol-guard-cline-plugin",
        "version": "1.0.0",
        "private": True,
        "type": "module",
        "cline": {"plugins": [{"paths": ["./index.js"], "capabilities": ["hooks"]}]},
    }
    return json.dumps(payload, indent=2) + "\n"


def _load_state(context: HarnessContext) -> dict[str, object]:
    try:
        payload = json.loads(_state_path(context).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def install_cline_plugin(context: HarnessContext) -> dict[str, object]:
    """Install a Guard-owned Cline plugin without replacing user-owned files."""

    root = cline_plugin_root(context)
    index_path = root / "index.js"
    package_path = root / "package.json"
    if root.is_symlink() or index_path.is_symlink() or package_path.is_symlink():
        raise RuntimeError("Guard refused a symlinked Cline plugin destination")
    if index_path.exists() and not _is_managed_plugin(index_path):
        raise RuntimeError(f"Cline plugin path is user-owned; Guard will not overwrite {index_path}")
    for proof_name in ("loaded", "pretool", "posttool"):
        with suppress(OSError):
            _proof_path(context, proof_name).unlink()
    attested = resolve_attested_guard_cli(context)
    source = _plugin_source(context, guard_hook_command(attested, harness="cline")[:-3])
    root.mkdir(parents=True, exist_ok=True)
    _atomic_write(index_path, source)
    _atomic_write(package_path, _package_json())
    state = {
        "schema_version": _SCHEMA_VERSION,
        "transport": "plugin",
        "root": str(root),
        "index_path": str(index_path),
        "package_path": str(package_path),
        "index_sha256": sha256(source.encode("utf-8")).hexdigest(),
        "guard_cli_identity": attested.manifest_payload(),
    }
    _atomic_write(_state_path(context), json.dumps(state, indent=2, sort_keys=True) + "\n")
    return {
        "transport": "plugin",
        "managed_plugin_path": str(index_path),
        "managed_plugin_package": str(package_path),
        "plugin_sha256": state["index_sha256"],
        "guard_cli_identity": attested.manifest_payload(),
        "post_tool_output_mediation": "replaceable",
    }


def _proof_state(context: HarnessContext, name: str) -> dict[str, object]:
    try:
        payload = json.loads(_proof_path(context, name).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"present": False, "fresh": False, "live": False}
    timestamp = payload.get("timestamp") if isinstance(payload, dict) else None
    fresh = isinstance(timestamp, (int, float)) and time.time() - float(timestamp) <= _PROOF_MAX_AGE_SECONDS
    return {
        "present": True,
        "fresh": fresh,
        "live": fresh and payload.get("source") == "cline-plugin",
        "proof": name,
        "outcome": payload.get("outcome"),
    }


def cline_plugin_state(context: HarnessContext) -> dict[str, object]:
    state = _load_state(context)
    index_path_value = state.get("index_path")
    expected = state.get("index_sha256")
    integrity_ok = False
    installed = isinstance(index_path_value, str) and Path(index_path_value).is_file()
    if isinstance(index_path_value, str) and installed and isinstance(expected, str):
        path = Path(index_path_value)
        try:
            integrity_ok = _is_managed_plugin(path) and sha256(path.read_bytes()).hexdigest() == expected
        except OSError:
            integrity_ok = False
    loaded = _proof_state(context, "loaded")
    pretool = _proof_state(context, "pretool")
    posttool = _proof_state(context, "posttool")
    pretool_blocking_proven = pretool.get("live") is True and pretool.get("outcome") == "blocked"
    posttool_replacement_proven = posttool.get("live") is True and posttool.get("outcome") == "replaced"
    return {
        "installed": installed,
        "integrity_ok": integrity_ok,
        "loaded_proof": loaded,
        "live_pretool_proof": pretool,
        "live_posttool_proof": posttool,
        "pretool_blocking_proven": pretool_blocking_proven,
        "posttool_replacement_proven": posttool_replacement_proven,
        "post_tool_output_mediation": "replaceable",
        "ready": bool(
            integrity_ok
            and loaded.get("live") is True
            and loaded.get("outcome") == "loaded"
            and pretool_blocking_proven
            and posttool_replacement_proven
        ),
    }


def cline_plugin_syntax_probe(context: HarnessContext) -> dict[str, object]:
    """Validate generated JavaScript without executing plugin code when Node is available."""

    state = _load_state(context)
    path_value = state.get("index_path")
    node = shutil.which("node")
    if not isinstance(path_value, str):
        return {"ok": False, "reason": "plugin_state_missing"}
    try:
        index_path = cline_plugin_root(context) / "index.js"
    except (OSError, RuntimeError, ValueError):
        return {"ok": False, "reason": "plugin_path_unsafe"}
    if path_value != str(index_path):
        return {"ok": False, "reason": "plugin_state_path_mismatch"}
    if node is None:
        return {"ok": True, "skipped": True, "reason": "node_not_available"}
    try:
        result = subprocess.run(
            [node, "--check", "--", str(index_path)],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return {"ok": False, "reason": type(exc).__name__}
    return {"ok": result.returncode == 0, "return_code": result.returncode}


def uninstall_cline_plugin(context: HarnessContext) -> dict[str, object]:
    state = _load_state(context)
    index_value = state.get("index_path")
    package_value = state.get("package_path")
    retained: list[str] = []
    removed: list[str] = []
    if isinstance(index_value, str):
        index_path = Path(index_value)
        if index_path.exists():
            if _is_managed_plugin(index_path):
                index_path.unlink()
                removed.append(str(index_path))
            else:
                retained.append(str(index_path))
    if not retained and isinstance(package_value, str):
        package_path = Path(package_value)
        if package_path.is_file():
            try:
                payload = json.loads(package_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                payload = None
            if isinstance(payload, dict) and payload.get("name") == "hol-guard-cline-plugin":
                package_path.unlink()
                removed.append(str(package_path))
    root = cline_plugin_root(context)
    if not retained and root.is_dir():
        with suppress(OSError):
            root.rmdir()
    if not retained and _state_path(context).is_file():
        _state_path(context).unlink()
    return {
        "transport": "plugin",
        "removed": removed,
        "retained_modified_or_unowned": retained,
        "complete": not retained,
    }


__all__ = [
    "cline_plugin_root",
    "cline_plugin_state",
    "cline_plugin_syntax_probe",
    "install_cline_plugin",
    "uninstall_cline_plugin",
]
