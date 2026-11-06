# Fast Hook Review for Pi/OMP

## Overview

HOL Guard's fast hook review engine enables extremely fast hook review for AI harnesses — especially Pi and Oh-My-Pi — while preserving best-in-class local security. Normal daemon-backed hook review targets ~200ms p95, making the 10s hook timeout ample headroom rather than the normal operating budget.

## How It Works

### Source-File Read Fast Path

When a Pi/OMP tool reads a direct source file (e.g., `src/foo.ts`, `docs/spec.md`), the managed extension can include a `guard_source_ref` object in the hook payload. This reference contains:

- The file path
- An output SHA-256 hash computed over the model-visible text
- The output character count
- Optional adapter stat metadata

The Guard daemon (or CLI fallback) uses this reference to:

1. **Re-read the file** from disk (never trusts the adapter's claim alone)
2. **Verify path safety** — rejects symlinks, path escapes, sensitive basenames (`.env`, `.npmrc`, etc.), and unsafe hidden directories
3. **TOCTOU guard** — stat before read, stat after read, compare identity
4. **Verify output hash** — the file content hash must match the adapter's claimed `output_sha256`
5. **Scan for secrets** — streaming scan with byte, match, and deadline budgets
6. **Cache the decision** — keyed by content hash, stat metadata, policy/config fingerprint, and scanner version

When all checks pass, the engine returns `model_output_action: "allow_original"` with the `reviewed_output_sha256`. The Pi extension verifies this hash matches its locally computed digest before returning `undefined` (preserving original content).

### Arbitrary Stdout

Arbitrary stdout (shell commands, crash dumps, env output) remains conservative. If full safety cannot be proven within budget, the engine returns a reviewed safe excerpt, blocks, or requires approval.

## When Excerpts Still Happen

- **Output hash mismatch**: The adapter's claimed hash doesn't match the file content
- **Symlink path**: Any path component is a symlink
- **Sensitive path**: The file is `.env`, `.npmrc`, credentials, etc.
- **Secret in file**: The scanner found a credential pattern
- **Binary file**: The file contains null bytes
- **Invalid UTF-8**: The file is not valid UTF-8
- **File too large**: Exceeds the 5MB scan limit
- **Scanner budget exhausted**: The deadline expired before scanning completed
- **File changed during read**: TOCTOU detection triggered
- **Cache miss with no source ref**: No `guard_source_ref` was provided

## Feature Flags

```bash
# Enable the daemon fast path (default: off)
export HOL_GUARD_HOOK_FAST_PATH=1

# Enable source-ref generation in the Pi extension (default: on)
export HOL_GUARD_HOOK_SOURCE_REF=1

# Shadow mode: evaluate fast path but return legacy behavior (for testing)
export HOL_GUARD_HOOK_FAST_PATH_SHADOW=1
```

## No Cloud Dependency

Local allow/block decisions work fully offline. Guard Cloud can sync redacted receipts later, but the hot path never calls the network.

## Security Guarantees

- Never lets unreviewed tool output reach the model
- Never passes raw oversized output through on timeout, daemon failure, or malformed payload
- Never weakens credential detection, sensitive file protections, deny policies, or approval gates
- Never uses an LLM in the allow/block hot path
- Never depends on Guard Cloud for local decisions
- Fail-safe: oversized or adversarial payloads block, require approval, or return only a reviewed safe excerpt
