"""Actual adapter host observations used only to discover a native owner route."""

from __future__ import annotations

import json

_ENVIRONMENT_NAMES = (
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "LC_COLLATE",
    "LC_MESSAGES",
    "LC_NUMERIC",
    "LC_TIME",
    "LC_MONETARY",
    "TMPDIR",
)


def with_bound_bash_host_observation(source: str, *, harness: str) -> str:
    if harness not in {"omp", "pi"}:
        return source
    marker = "  let payloadToSend = {\n    ...payload,\n"
    if source.count(marker) != 1:
        raise ValueError("Pi-family host observation insertion point changed")
    host = "omp-input-rewrite-v1" if harness == "omp" else "pi-input-mutation-v1"
    stamp = (
        "  // A preview stamp grants no permission. The execution sink observes its own context.\n"
        "  const boundBashHost = process.platform === 'darwin' &&\n"
        "    Number.isSafeInteger(process.pid) && process.pid > 1 &&\n"
        "    payload.hook_event_name === 'PreToolUse' && payload.tool_name === 'bash' &&\n"
        "    !GUARD_CLI_WRAPPER_ACCEPTS_JSON_ARGS && GUARD_CLI_WRAPPER_COMMAND.startsWith('/')\n"
        "    ? { schema: 'guard-native-bash-host-delivery.v3', owner_pid: process.pid,\n"
        f"        host: {json.dumps(host)}, file_creation_mask: process.umask(),\n"
        "        environment: Object.fromEntries(\n"
        f"          {json.dumps(_ENVIRONMENT_NAMES)}.filter((name) =>\n"
        "            typeof activeEnvironment[name] === 'string').map((name) => [name, activeEnvironment[name]])\n"
        "        ) } : undefined;\n"
        + marker
        + "    ...(boundBashHost ? { guard_bound_bash_host: boundBashHost } : {}),\n"
    )
    return source.replace(marker, stamp, 1)
