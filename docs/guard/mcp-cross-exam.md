# MCP Cross Exam in HOL Guard

HOL Guard enforces policy on agent commands. MCP Cross Exam is a separate auditor for MCP protocol and schema behavior. Guard orchestrates, authorizes, and displays. Cross Exam owns probes, scoring, and evidence.

A passing Cross Exam score does not bypass Guard. Findings never become allow-authority.

## Install

Cross Exam is not a Guard extra. Guard pins `mcp>=1.30,<2`; Cross Exam pins a newer `mcp` line, so the two must not share one environment.

Install the auditor independently, then leave it on `PATH`:

```bash
pipx install mcp-cross-exam
mcp-cross-exam --version
```

Minimum supported version: `0.1.0`. Guard does not download, install, or upgrade it.

## Enable local audits

Audits are off until a local admin turns them on. This setting is a file under Guard home, not a synced GuardConfig key.

```bash
hol-guard settings set mcp-cross-exam on
hol-guard settings set mcp-cross-exam off
```

Enabling this does not enable the complementary `command.mcp-cross-exam` review matchers. Those stay inert until `hol-guard command controls apply command.mcp-cross-exam --state enabled`.

## HTTP and SSE

Loopback targets are allowed. Guard resolves the host and requires every address to be loopback, including IPv4-mapped IPv6. Inventory presence is not authorization.

```bash
hol-guard mcp audit http://127.0.0.1:8765/mcp
hol-guard mcp audit --sse http://127.0.0.1:8765/mcp
```

Remote HTTP/SSE requires `--not-production`, which maps to Cross Exam `--target-is-not-production`. Guard never invents `[target] allow` entries. If Cross Exam exits 2 because of its production guard, Guard reports a configuration failure.

## Stdio

Stdio audits need an explicit command after `--`. Guard resolves the executable to an absolute path and rejects shell wrappers. Settings-on is not enough; the remainder is the extra authorization.

```bash
hol-guard mcp audit -- python /absolute/path/to/server.py
hol-guard mcp audit -- /usr/bin/node server.js
```

`--cwd` must be a real directory. Use `--env-from` / `--bearer-env` / `--header-env` to forward named variables. Ambient tokens are not inherited.

## Read-only and writes

Default mode is `--read-only`. `--allow-writes` requires enablement plus the flag. Tool annotations are not verified side-effect guarantees. Guard never retries writes automatically.

Probe families stay on Cross Exam flags: `--family schema`, `--family` for transport/session probes, and writes only with `--allow-writes`.

## Artifacts

Scanner cwd is disposable, so `--out-dir` is created as an absolute directory. Default: `./mcp-cross-exam-results`. Guard reads `report.json` from that directory and leaves evidence in place.

```text
MCP Cross Exam Audit
Target:    http://127.0.0.1:8765/mcp
Transport: http
Mode:      read-only
Status:    completed | incomplete | failed | unreachable | cancelled
Score:     <from report or n/a>
Auditor:   mcp-cross-exam 0.1.0
```

Incomplete coverage is reported as status `incomplete`. That is not a Guard policy verdict.

## Exit codes

| Code | Meaning |
| ---: | --- |
| 0 | Parsed the report. Do not assume zero findings. |
| 1 | Guard or auditor internal failure, including timeout or missing report. |
| 2 | Usage or configuration, including disabled setting, missing binary, or bad target. |
| 3 | Parsed the report and findings are present. |
| 4 | Target unreachable. This is not score 0. |
| 130 | Cancelled. |

`hol-guard mcp serve` and `hol-guard mcp list` are unchanged. Ordinary Guard use works when `mcp-cross-exam` is absent.

## Command-source vs adapter

- **Adapter:** `hol-guard mcp audit` after `settings set mcp-cross-exam on`. Guard spawns the auditor.
- **Command-source:** `command.mcp-cross-exam` reviews agent shells that run `mcp-cross-exam` themselves. It does not execute audits.

Package launchers (`uvx`, `pipx run`) stay on `command.package.python`. `--help`, `--version`, `probes list`, `probes plan`, and `config show` are unmatched and keep first-party floors.

## Dashboard

The MCP Audit tab under Supply Chain shows local summaries only. It does not launch audits, block, or remediate. Evidence paths are local file references. Results are never uploaded.

## Troubleshooting

- **Missing binary:** install with pipx/uvx and confirm `mcp-cross-exam --version`.
- **Production guard:** loopback the target or pass `--not-production` for an explicit non-production remote.
- **Timeout:** raise `--timeout` (default 180s) or reduce `--jobs` (default 1, cap 4). macOS scanner seats deny `process-fork`.
- **Sandbox:** the bounded scanner subprocess scrubs the environment. Forward only named bearer/header/env values.
