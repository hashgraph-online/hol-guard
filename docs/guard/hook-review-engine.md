# Hook Review Engine

## Architecture

The hook review engine is a daemon-resident, typed decision core that avoids Python startup/import cost and CLI command layering for normal hook decisions.

## Components

### `HookReviewRequest` / `HookReviewResponse`

The typed API contract between adapters, the daemon worker, the CLI fallback, and the engine. Defined in `runtime/hook_review_types.py`.

Key fields:
- `model_output_action`: Controls what the adapter does with the output (`allow_original`, `replace_with_reviewed_excerpt`, `block`, `not_applicable`)
- `reviewed_output_sha256`: The hash the adapter must verify before preserving original content
- `reason_code`: Machine-readable reason for the decision

### `ContentScanner`

A bounded streaming scanner wrapping `classify_secret_content()` with:
- Byte budget (`max_bytes`)
- Match limit (`HOOK_SCANNER_MAX_MATCHES`)
- Wall-clock deadline (`deadline_monotonic`)
- Rolling context window (`HOOK_SCANNER_CONTEXT_CHARS`)

Never produces secret sample text. Never runs an LLM. Never calls the network.

### `HookDecisionCache`

Exact source-read cache using the existing `scanner_cache` SQLite table. Cache key includes:
- Content hash, stat metadata (dev, ino, size, mtime_ns)
- Scanner version, source classifier version
- Policy fingerprint, config fingerprint
- Harness, event, realpath, workspace

Any change in any field invalidates the cache entry.

### `evaluate_source_file_ref()`

The source-read fast-path evaluator with:
- Shape validation (event, source ref, action type, target paths)
- Path resolution and sensitive path rejection
- TOCTOU guard (stat-before/read/stat-after)
- Output hash verification
- Streaming scan
- Cache check and save

### `HookReviewEngine`

The resident decision core:
1. Loads config
2. Normalizes payload into `GuardActionEnvelope`
3. Tries source-read fast path for PostToolUse with `guard_source_ref`
4. Falls back to standard path for non-source or inconclusive requests
5. Fail-safe deny/block on any exception

### `HookWorker`

The daemon HTTP handler:
- Builds `HookReviewRequest` from HTTP payload
- Calls `HookReviewEngine.review()`
- Returns `HookReviewResponse.to_harness_json()`
- Never calls `run_guard_command()`

## Budgets

```python
HOOK_ENGINE_TOTAL_BUDGET_MS = 9000      # Total budget under the 10s timeout
HOOK_ENGINE_NORMAL_BUDGET_MS = 1000    # Normal decision target
HOOK_SOURCE_FAST_PATH_BUDGET_MS = 250   # Source-read fast path budget
HOOK_SCANNER_DEFAULT_BUDGET_MS = 750    # Scanner budget
ARBITRARY_STDOUT_FULL_ALLOW_BYTES = 256 * 1024  # Max arbitrary stdout for full allow
```

## Integration Points

- **Daemon**: `daemon/server.py` `_handle_runtime_hook()` dispatches to fast worker or legacy CLI
- **CLI**: `cli/commands_hook.py` `_try_source_ref_fast_path()` calls the engine for source-ref payloads
- **Adapter**: Pi extension generates `guard_source_ref` and verifies `reviewed_output_sha256`
