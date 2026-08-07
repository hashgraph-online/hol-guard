# `release/3.0` isolation implementations and containment baseline

Status: wave-zero baseline. Audience: execution-assurance gate reviewers. Source evidence snapshot: `origin/release/3.1` at `10348fd40fa53ef60d9363bb6c37591b8bb60a61`; release identity migrated to 3.0 and revalidated in PR #1901.

Characterizes every isolation implementation by actual enforced behavior, then records the macOS/Linux containment guarantee matrix. Guarantees are derived from the enforcement code, never inferred from class or file names.

## Isolation implementations

### 1. macOS Seatbelt (`sandbox-exec`)

`runtime/containment_executor.py:331-356` builds a Seatbelt profile with `(deny default)` (`:339`), grants read-only access to system roots, read-write to the bounded temp root, `(deny network*)` (`:352`), and denies process-fork. The executable is pinned: copied to `temp_root/guard-exec`, mode `0o500`, with SHA-256 digest verified before spawn (`:198-221`). Executable or input drift fails closed before the process starts (`tests/test_guard_containment_executor.py:62,78`).

### 2. Linux Bubblewrap (`bwrap`)

`runtime/containment_executor.py:357-382` builds the bwrap argv with `--unshare-all` (`:366`, includes `--unshare-net`), read-only binds for system libraries (`--ro-bind`, `:379`), `--chdir` to the sandbox cwd, and `--clearenv` with explicit per-variable `--setenv` (`:382`). Backend selected at `:159-162` (`/usr/bin/sandbox-exec` for macOS, `/usr/bin/bwrap`/`/bin/bwrap` for Linux).

### 3. Restricted pytest

`runtime/restricted_pytest_sandbox.py` builds the OS sandbox for test runs. `_macos_profile()` (`:82-115`) produces `(deny default)` with `(allow process-fork)`, `(allow process-exec)`, and file-read/file-write scoped to workspace + temp root. `_bubblewrap_argv()` (`:154-180`) adds `--unshare-net`, `--tmpfs /tmp`, read-only system binds, and a workspace bind. `_run_backend_process()` (`:203-255`) applies resource limits: CPU 20m, memory 4GB, file 256MB, 256 open files, 64 processes. `runtime/restricted_pytest_model.py:26-74` defines environment scrubbing: 28 denied keys (`AWS_*`, `DOCKER_*`, `KUBECONFIG`, `SSH_AUTH_SOCK`, `*KEY`, `*PASSWORD`, `*SECRET`, `*TOKEN`), proxy keys stripped, a safe-key allowlist, and a `_SECRET_ENV_PATTERN` regex matching API/AUTH/BEARER/CREDENTIAL/PASSWORD/SECRET/TOKEN. Denied capabilities: network, docker-socket, write-outside-workspace-and-private-temp, unapproved-process-exec, privileged-operation.

### 4. Safe Decode scanning

`runtime/safe_decode.py` is a pure text-decoding pipeline for encoded commands/prompts. Hard limits: `_MAX_INPUT_BYTES` 256KB, `_MAX_DECODED_BYTES` 512KB, `_MAX_RECURSION_DEPTH` 3, `_MAX_DECODE_TIME_MS` 50ms (`:12-18`). Thirteen encoding types are unwrapped (`:20-26`). `_recursive_decode()` (`:65-83`) enforces size/depth/time limits with early return and never calls `eval`/`exec`/`marshal.loads`. Detected eval/exec/marshal signals are regex pattern matches on decoded text only (`:87-141`); decoded content is never executed.

### 5. Temporary-directory runners

`contained_node_execution.py`, `contained_package_script_execution.py`, `contained_typescript_execution.py`, `contained_workspace_write_execution.py` all delegate to `containment_executor.execute_contained()`. Each scrubs the environment to a safe allowlist (`LANG`/`LC_ALL`/`LC_CTYPE`/`NO_COLOR`/`TERM` passthrough), canonicalizes the workspace, and bounds output to 64KB (`containment_executor.py:33`). `runtime/offline_archive_sandbox.py` adds a Python audit hook that denies write opens and capability grants (`:73-87`, `:93-133`), applies RLIMIT_AS/CPU/FSIZE/NOFILE/NPROC in the child (`:32-67`), and wraps with `sandbox-exec -p '(deny network*)'` on macOS (`:149-159`).

### 6. Docker labs

No runtime code under `guard/` builds or runs Docker containers for isolation. Docker references are classification rules (docker-sensitive command action classes), secret-path patterns (`.docker/config.json`), inventory schema fields, and CLI lab-host allowlisting (`host.docker.internal`). Docker is not an isolation backend in this baseline.

## Containment guarantee matrix (macOS / Linux)

| Control | macOS Seatbelt | Linux Bubblewrap | Enforcement |
| --- | --- | --- | --- |
| Filesystem | read-only system roots; write only to bounded temp root | `--ro-bind` system libs; workspace bind only | `containment_executor.py:339-356`, `:357-382` |
| Network | `(deny network*)` | `--unshare-all` (incl `--unshare-net`) | `:352`, `:366` |
| Process | `(deny process-fork)` | `--new-session`, NPROC limit | `:339-356`, `:366`; `restricted_pytest_sandbox.py:203-255` |
| Secret (env) | `--clearenv` + explicit `--setenv` | `--clearenv` + explicit `--setenv` | `:382`; `restricted_pytest_model.py:26-74` |
| Output | 64KB bounded capture | 64KB bounded capture | `containment_executor.py:33` |
| Timeout | `subprocess.TimeoutExpired` → `os.killpg` | `subprocess.TimeoutExpired` → `os.killpg` | `containment_executor.py:298-315` |
| Cleanup | process-group SIGKILL; temp root bounded | process-group SIGKILL; temp root bounded | `containment_executor.py:298-315` |
| Identity | executable pinned + SHA-256 verified before spawn | executable pinned + SHA-256 verified before spawn | `containment_executor.py:198-221`, `:334-354` |

Where a control is not enforced by the backend it is omitted rather than inferred. Unsupported controls lower guarantees via the action lattice (sandbox-required never collapses to review).

## Behavioral tests

- `tests/test_guard_containment_executor.py` — backend selection fallback, executable/input drift fails closed.
- `tests/test_guard_containment_contract.py` — attestation immutability, failure reason codes.
- `tests/test_guard_containment_health.py` — compatibility signals, sandbox status.
- `tests/test_guard_containment_external_executable.py` — pin/digest/0o500 verification, immutable rejection, replacement fails closed.
- `tests/test_guard_contained_{node,package_script,typescript,workspace_write}_execution.py` — backend success/failure paths.
- `tests/test_guard_contained_workspace_write_contract.py` — policy/request/declared-output validation.
- `tests/test_guard_daemon_containment_health.py` — daemon `/v1/runtime/containment-health` auth.
- `tests/test_guard_daemon_adversarial_transport.py` — owner retained until worker containment.

## Notes

- This baseline records current enforced behavior; it does not authorize new isolation backends.
- Real-backend isolated runs (macOS Seatbelt, Linux bwrap) are exercised by CI on their respective platforms; this document does not substitute for that matrix.
