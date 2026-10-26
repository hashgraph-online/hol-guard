# Contribute a harness adapter

A harness adapter connects HOL Guard to an AI coding app such as Codex, Cursor, Cline, or Pi. It discovers the app, identifies its configuration and tool surfaces, installs or removes Guard-owned integration, and reports which actions can actually be protected.

**This is not a command extension.** To add rules for a CLI without integrating a new agent host, use the [command extension guide](extensions/contributing.md). To add MCP server knowledge, use [MCP server contributions](mcp-server-contributions.md).

## 1. Verify the host interface

Before writing code, record in your pull request:

- The upstream CLI, SDK, or editor documentation and supported app/OS versions.
- Exact config locations, ownership boundaries, launch mechanisms, and discovery behavior.
- The real pre-execution and post-execution events, event JSON, response schema, exit codes, and timeouts.
- Which actions can be denied **before** execution, which are observation-only, and which are unavailable.
- What happens if Guard is missing, times out, sees malformed input, or receives an unsupported tool.
- How install, repair, uninstall, and host upgrades preserve user-owned files and settings.

A detected app or installed shim is not proof that Guard intercepts its tools. Do not claim pre-tool protection for a post-tool event or for an unverified host version. See [harness support](harness-support.md) and [native hook ownership](native-hook-data-plane-ownership.md).

Search [open adapter PRs](https://github.com/hashgraph-online/hol-guard/pulls?q=is%3Aopen+adapter) before choosing a harness ID. Use the existing canonical harness name and aliases where applicable.

## 2. Find the implementation

| Responsibility | Location |
| --- | --- |
| Public Python adapter classes and registrations | `src/codex_plugin_scanner/guard/adapters/<harness>.py` and `adapters/__init__.py` |
| Shared adapter context and install ownership | `adapters/base.py` |
| Static setup, event coverage, and known blind spots | `adapters/contract_registry.py`, `adapters/contracts.py`, `adapters/contract_*capabilities.py` |
| Python helper modules grouped by harness | `adapters/_modules/<family>/` |
| Native harness discovery | `rust/crates/guard-runtime/src/adapters/detection/<harness>_detect.rs` |
| Native hook request handling | `rust/crates/guard-runtime/src/adapters/hook_adapter_op.rs` |
| Native hook payload preparation and redaction | `rust/crates/guard-command/src/adapters/hook/` |
| Wire contracts | `rust/crates/guard-contracts/src/hook_adapter.rs` |
| Existing adapter tests | `tests/test_<harness>_adapter.py`, `tests/test_guard_harness_*.py`, and native vector tests |

Public harness classes stay at their existing adapter entrypoints. Internal helpers use ordinary Python package imports, such as `codex_plugin_scanner.guard.adapters._modules.cursor.cursor_hook_events`. Each family and `_modules/` has an `__init__.py`, so Python, static analysis, and frozen builds discover the same modules. Put a new public harness class at the adapter root and its supporting files in the corresponding family package; do not extend `__path__` or create a second import identity.

Begin with [Gemini](../../src/codex_plugin_scanner/guard/adapters/gemini.py) or [Antigravity](../../src/codex_plugin_scanner/guard/adapters/antigravity.py) for discovery-only examples, and [Cline](../../src/codex_plugin_scanner/guard/adapters/cline.py) or [Cursor](../../src/codex_plugin_scanner/guard/adapters/cursor.py) for hook installation. Review the actual host contract before copying a strategy.

## 3. Add discovery and registration

1. Implement a `HarnessAdapter` subclass in `src/codex_plugin_scanner/guard/adapters/<harness>.py`. Specify `harness`, executable, aliases, and `detect(context)` as appropriate. Return a `HarnessDetection` with observed paths, artifacts, and warnings; do not infer enforcement from an executable being present.
2. Implement the bounded native discovery operation in `rust/crates/guard-runtime/src/adapters/detection/` and wire it into the resident's operation dispatch. Python calls it through `native_adapter_detection_with_warnings`, using `detection_request` to preserve home, workspace, and cwd boundaries.
3. Add the class to `_ADAPTER_SPECS` in `adapters/__init__.py`. Use the exact import path and class name. Check that `get_adapter` resolves canonical names and aliases without collision.
4. Add a `HarnessProtectionContract` to `adapters/contract_registry.py`: installation aliases, observed config paths, event surfaces, smoke command, and **specific** known blind spots. Declare real event capabilities in the relevant `contract_hook_capabilities.py` or `contract_agent_capabilities.py`. An aspirational hook is not a supported capability.
5. Update [harness support](harness-support.md) with tested behavior and limits. If the host has version-specific coverage, follow [version coverage](harness-version-coverage.md) rather than claiming support for untested versions.

Public adapter entrypoints are stable. When relocating an internal helper, update its imports and callers, source-path references, and ownership manifests together. Files bound by authenticated manifests, including `codex_daemon_hook_resume.py`, stay at their established paths unless the complete identity and upgrade contract is migrated.

## 4. Implement protection safely

- Use Guard's established managed-install and runtime-transition interfaces. Preserve exact user-owned config, handle conflicting edits, make installation and removal idempotent, and verify managed ownership before cleanup.
- Respect `HarnessContext` home, workspace, and Guard-home roots. Avoid path traversal, symlink escapes, uncontrolled shell quoting, and copying secrets into logs, payloads, or diagnostics.
- Native Rust authority must determine tool/action semantics and security decisions. Python bridges should only perform bounded transport, lifecycle management, and host-specific response rendering. Do not introduce a parallel Python policy engine or a permissive fallback.
- Normalize complete raw hook events. Cover each native tool spelling and arguments actually exposed by the host. A malformed or unknown action-bearing request must not silently become an allow.
- Use host-specific documented deny/approval responses and exit codes. Follow [harness support](harness-support.md#hook-verdict-exit-codes) and existing tests; a nonzero exit is not uniformly a deny across hosts.
- Keep pre-tool blocking distinct from post-tool observation, and verify resumed approvals are tied to the original request. Do not treat installation or process liveness as successful enforcement evidence.

For new normalization behavior, extend the native hook adapter modules and their parity vectors under `rust/crates/guard-command/src/adapters/hook/`. For discovery behavior, add fixtures to the native runtime detection tests. Do not weaken unrelated safety floors to make a host test pass.

## 5. Test the complete lifecycle

Start from a clean disposable home and workspace. Exercise no-install discovery, first install, repeat install, repair, deliberate drift, uninstall, and preservation of unrelated config. Include Linux/macOS/Windows where the host claims them.

At minimum, test:

1. A real harmless command or tool event is allowed without requiring unnecessary approval.
2. For each declared pre-tool blocking event, a dangerous synthetic event reaches the hook, is denied **before side effects**, and cannot bypass via aliases or malformed arguments. Test observation-only and unavailable events against their documented behavior instead; do not require pre-tool denial for those surfaces.
3. Agent responses and exit codes match the host's contract. Unsupported, timed-out, and disconnected paths fail according to the documented policy.
4. Detection never writes files, and install/uninstall never destroy user-managed entries.
5. Hook events and their generated files have bounded size and deadlines. Evidence and logs omit credentials.
6. The installed wheel and, if applicable, a verified native build behave like the source checkout.

Typical checks from the repo root:

```bash
uv run --no-sync python -m ruff check src tests
uv run --no-sync python -m ruff format --check src tests
uv run --no-sync pytest tests/test_adapter_module_layout.py tests/test_adapter_packaged_manifest.py tests/test_guard_harness_contracts.py tests/test_guard_harness_setup.py tests/test_guard_harness_smoke.py --tb=short
uv run --no-sync pytest tests/test_<harness>_adapter.py --tb=short

cargo +1.88.0 fmt --manifest-path rust/Cargo.toml --all --check
cargo +1.88.0 clippy --locked --manifest-path rust/Cargo.toml --workspace --all-targets -- -D warnings
cargo +1.88.0 test --locked --manifest-path rust/Cargo.toml --workspace --all-targets
```

Replace `<harness>` with the actual test module name and add event-specific tests. Test requirements and native projections are described in [CONTRIBUTING.md](../../CONTRIBUTING.md). For hook or policy behavior changes, run the [Guard Gauntlet](../../ci/gauntlet/README.md) live-agent acceptance workflow and attach verifiable benign/security-pair evidence for the final PR head. Unit tests alone do not constitute live enforcement proof.

## 6. Keep ownership checks intact

Several security checks pin adapter source paths and glob patterns: `docs/guard/contracts/hook-data-plane-ownership.v2.json`, `runtime-majority-scope.v1.json`, and `python-capability-ownership.v1.json`. Moving a module without updating its ownership paths is a safety regression. Keep old patterns where required for coverage of existing files, add coverage for new subfolders, and run the ownership and source-layout checks. Do not move files with path-sensitive `__file__` behavior without correcting their path calculations and tests.

Open a PR against `main` with the upstream host reference, capability table, installation and rollback design, benign/security fixtures, validation commands, and remaining blind spots. A supported app is not automatically an authoritative protected app until the hooks are verified.
