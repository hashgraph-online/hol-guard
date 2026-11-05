# Antigravity Harness Support Specification

<!-- contract-version: guard.antigravity-harness-support.v1 -->

This specification defines the architectural model, discovery invariants, MCP proxy mediation, and enforcement boundary for Google DeepMind's Antigravity platform in HOL Guard.

## Overview

HOL Guard integrates with the Antigravity harness through:
1. **Rust Native Runner Authority (`antigravity_detect`)**: High-performance, zero-allocation discovery of settings, extensions, MCP configurations, and multi-root skills.
2. **Python Adapter Layer (`AntigravityHarnessAdapter`)**: Thin launcher and lifecycle coordinator integrating with workspace AIBOM (AI Bill of Materials).
3. **Managed MCP Proxy Relay**: Transparent stdio interception for registered MCP servers, enabling pre-tool execution evaluation and user approval routing.

---

## Supported Surfaces & Protection Matrix

| Surface | Detection Source | Enforcement Mechanism | Target Grade |
| :--- | :--- | :--- | :--- |
| **User Settings** | `~/.config/antigravity/user/settings.json`<br>`~/.config/Antigravity/User/settings.json`<br>`~/Library/Application Support/Antigravity/User/settings.json`<br>`%APPDATA%\Antigravity\User\settings.json` | Preflight configuration validation & drift detection | `verified` |
| **Extensions** | `~/.antigravity/extensions/extensions.json` | Manifest scanning & supply-chain provenance check | `verified` |
| **Skills (Multi-Root)** | `.gemini/antigravity/skills/` (`skills`)<br>`.gemini/antigravity/builtin/skills/` (`builtin-skills`)<br>`.gemini/config/plugins/*/skills/` (`plugin-skills`)<br>Workspace `.agents/skills/` (`agents-skills`) | Recursive directory hashing, symlink traversal containment, and script integrity | `verified` |
| **MCP Servers** | `.gemini/antigravity/mcp_config.json`<br>Settings `mcpServers` | Native Managed stdio MCP Proxy Relay (`hol-guard mcp-relay`) | `managed_proxy_active` |
| **Subagents** | Dynamic subagent invocation (`invoke_subagent`, `define_subagent`) | Workspace mode isolation enforcement (`branch`, `share`, `inherit`) | `enforceable_guard` |

---

## Skill Directory Identity & Namespace Invariants

Skill discovery in `antigravity_detect.rs` binds approval and inventory identity to the complete directory structure:
- **Canonical Roots**:
  - `skills`: User-authored global skills under `.gemini/antigravity/skills/`.
  - `builtin-skills`: Antigravity bundled skills under `.gemini/antigravity/builtin/skills/`.
  - `plugin-skills`: Skills shipped by installed plugins under `.gemini/config/plugins/<plugin>/skills/`.
  - `agents-skills`: Project-scoped workspace skills under `<workspace>/.agents/skills/`.
- **Prefix Segregation Invariant**: Each root prefix occupies exactly one path segment. A nested directory inside the primary `skills` root cannot collide with or reuse a distinct root's artifact ID.
- **Symlink Containment**: A skill containing a symlink that references an external path outside its declared tree is flagged with `reusable = false`. The security warning is emitted without disclosing absolute external host paths.

---

## XDG Case-Insensitivity & Path Normalization

On case-insensitive filesystems (such as standard macOS APFS and Windows NTFS), the lowercase path `~/.config/antigravity/user/settings.json` and uppercase path `~/.config/Antigravity/User/settings.json` resolve to the same underlying inode:
- If both entries point to the same physical file, Guard emits a single deduplicated artifact (`settings:xdg-user`).
- If the underlying filesystem is case-sensitive and both files exist independently, Guard tracks both files with distinct scoped artifact IDs (`settings:xdg-user` and `settings:xdg-user-lower`).

---

## Managed Stdio MCP Proxy Relay

To elevate Antigravity from preflight observation to active runtime protection:

### 1. Transparent Configuration Rewrite
When `hol-guard apps connect antigravity` or `hol-guard run antigravity` runs:
1. Guard reads `.gemini/antigravity/mcp_config.json` and eligible `mcpServers` declarations.
2. An atomic journal backup is written to `.guard/backup/antigravity_mcp_backup.json`.
3. Stdio server commands are rewritten to target Guard's native relay:
   ```json
   {
     "mcpServers": {
       "target-server": {
         "command": "hol-guard",
         "args": ["mcp-relay", "--harness", "antigravity", "--server", "target-server", "--", "original-cmd", "arg1"]
       }
     }
   }
   ```

### 2. Zero-Overhead Tool Call Interception
- All JSON-RPC `tools/call` requests from Antigravity pass through the native Rust resident (`guard-runtime`).
- The evaluation engine checks tool parameters against policy (destructive filesystem operations, sensitive credential exfiltration, suspicious outbound network commands).
- **Sub-3ms Decision Path**: Evaluated locally via Rust zero-copy framing without external network or LLM roundtrips.

---

## Approval Invariant Enforcement

Every tool invocation intercepted by Guard strictly honors the repository **Approval Invariant** (`docs/guard/approval-invariant.md`):
1. **Allow Once**: Authorizes the specific invocation attempt. The retry binding incorporates the tool name, arguments, working directory, and session context.
2. **Always Allow**: Persisted permanently against the cryptographic hash of the action and parameters. Subsequent invocations matching the hash proceed without prompting.
3. Guard never presents a review choice that cannot be approved or executed.

---

## Grade Transition Roadmap

```
Current Status:               Target Status (Phase 1):        Final Status (Phase 2):
+-----------------------+     +--------------------------+    +-----------------------+
| observe_only_degraded | --> |  managed_proxy_active    | -> |   full_managed_guard  |
| (Preflight scan only) |     |  (Live MCP Tool Defense) |    |   (+ Subagent Hooks)  |
+-----------------------+     +--------------------------+    +-----------------------+
```

1. **Current (`observe_only_degraded`)**: Artifact discovery and preflight diffing completed.
2. **Phase 1 (`managed_proxy_active`)**: Implement `mcp_relay_native` configuration rewrite and atomic restore for Antigravity.
3. **Phase 2 (`full_managed_guard`)**: Subagent sandbox boundary verification and runtime prompt/output guardrails.

---

## Verification & Test Acceptance Matrix

All Antigravity implementations must pass:
- `tests/test_antigravity_adapter.py`:
  - `test_antigravity_skill_identity_covers_primary_and_nested_files`
  - `test_antigravity_incomplete_skill_identity_warns_without_external_path_disclosure`
  - `test_antigravity_detect_xdg_lowercase_settings`
  - `test_xdg_case_variants_keep_distinct_mcp_ids_when_both_files_exist`
  - `test_same_skill_name_in_two_roots_keeps_distinct_ids`
  - `test_antigravity_mcp_relay_rewrite_and_atomic_restore` (New for Phase 1)
- Rust unit tests in `guard-runtime`:
  - `test_antigravity_detect_clean_tree`
  - `test_antigravity_detect_symlink_ceiling`

