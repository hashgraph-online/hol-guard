# Antigravity Harness Support Specification

<!-- contract-version: guard.antigravity-harness-support.v1 -->

This specification defines the architectural model, discovery invariants, MCP proxy mediation, and enforcement boundary for Google DeepMind's Antigravity platform in HOL Guard.

## Overview

HOL Guard integrates with the Antigravity harness through:
1. **Rust Native Runner Authority (`antigravity_detect`)**: High-performance preflight discovery of user settings, extensions, MCP configurations, and multi-root skills.
2. **Python Adapter Layer (`AntigravityHarnessAdapter`)**: Thin launcher and lifecycle coordinator integrating with workspace AIBOM (AI Bill of Materials) and local approval-center routing.
3. **Planned Managed Stdio MCP Proxy Relay (Phase 1 Roadmap Target)**: Transparent stdio interception for registered MCP servers, enabling pre-tool execution evaluation and user approval routing.

---

## Supported Surfaces & Protection Matrix

> [!NOTE]
> Antigravity is currently classified as `observe_only_degraded` in `release-3-0-harness-grades.md` with pre-launch detection and artifact hashing. Active runtime interception is a planned roadmap capability for subsequent phases as detailed below.

| Surface | Detection Source | Enforcement Mechanism | Current Grade | Target Grade (Roadmap) |
| :--- | :--- | :--- | :--- | :--- |
| **User Settings** | `~/.config/antigravity/user/settings.json`<br>`~/.config/Antigravity/User/settings.json`<br>`~/Library/Application Support/Antigravity/User/settings.json`<br>`~/AppData/Roaming/Antigravity/User/settings.json` *(redirected APPDATA locations outside `~/AppData/Roaming` are not detected)* | Preflight MCP configuration discovery & `mcpServers` artifact drift detection | `observe_only_degraded` | `verified` |
| **Extensions** | `~/.antigravity/extensions/extensions.json` | Manifest scanning & supply-chain provenance check | `observe_only_degraded` | `verified` |
| **Skills (Multi-Root)** | `.gemini/antigravity/skills/` (`skills`)<br>`.gemini/antigravity/builtin/skills/` (`builtin-skills`)<br>`.gemini/config/plugins/*/skills/` (`plugin-skills`)<br>Workspace `.agents/skills/` (`agents-skills`) | Recursive directory hashing, symlink traversal containment, and script integrity | `observe_only_degraded` | `verified` |
| **MCP Servers** | `.gemini/antigravity/mcp_config.json`<br>Settings `mcpServers` | Planned native Managed stdio MCP Proxy Relay (`hol-guard mcp-relay`) | `observe_only_degraded` | `managed_proxy_active` (Phase 1) |
| **Subagents** | Not currently observed *(dynamic subagent invocation detection planned)* | Planned workspace mode isolation enforcement (`branch`, `share`, `inherit`) | `observe_only_degraded` | `enforceable_guard` (Phase 2) |

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

On case-insensitive filesystems (such as standard macOS APFS and Windows NTFS), the lowercase path `~/.config/antigravity/user/settings.json` and uppercase path `~/.config/Antigravity/User/settings.json` resolve to the same underlying file:
- If both entries point to the same physical file, Guard emits a single deduplicated artifact (`settings:xdg-user`).
- If the underlying filesystem is case-sensitive and both files exist independently, Guard tracks both files with distinct scoped artifact IDs (`settings:xdg-user` and `settings:xdg-user-lower`).

---

## Planned Managed Stdio MCP Proxy Relay (Phase 1 Proposal)

Phase 1 plans to elevate Antigravity from preflight observation (`observe_only_degraded`) to active runtime protection:

### 1. Transparent Configuration Rewrite
When `hol-guard apps connect antigravity` or `hol-guard run antigravity` runs in future releases:
1. Guard reads `.gemini/antigravity/mcp_config.json` and eligible `mcpServers` declarations.
2. An atomic journal backup is written to `.guard/backup/antigravity_mcp_backup.json`.
3. Stdio server commands are rewritten to target Guard's native relay according to the repository's native relay contract:
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
   *(Exact CLI invocation arguments remain subject to final design stabilization before Phase 1 ships).*

### 2. Planned Native Tool Call Interception
- JSON-RPC `tools/call` requests from rewritten eligible stdio servers pass through the native Rust resident (`guard-runtime`). Calls to other unrewritten MCP servers do not pass through this relay.
- The evaluation engine checks tool parameters against policy (destructive filesystem operations, sensitive credential exfiltration, suspicious outbound network commands).
- **Decision Path**: Evaluated locally via Rust framing without external network or LLM roundtrips.

---

## Approval Invariant Enforcement

Every command and tool invocation paused for review strictly honors the repository **Approval Invariant** (`approval-invariant.md`):
1. **Allow Once**: Authorizes the agent's retry of that specific tool call or artifact through. The retry binding omits the ephemeral call ID while session ID is present, and preserves the command/tool name, arguments, working directory, session, and policy.
2. **Always Allow**: Saved against the exact action token ([What the hash covers](approval-invariant.md#what-the-hash-covers)). The strong token binds resolved executable contents where Guard can prove the command, while the command-hash fallback does not establish content binding. The saved approval ends only when:
   - the user explicitly removes it, or
   - the command or artifact hash changes.
   Saved approvals survive rule or advisory changes, but never lower terminal `block` or `sandbox-required` verdicts.
3. **No Unexecutable Choices**: Guard never presents a review choice that cannot be approved or executed (`Allow once` and `Always allow` are always both offered for reviewable verdicts).

---

## Grade Transition Roadmap

```
Current Status:               Target Status (Phase 1):        Final Status (Phase 2):
+-----------------------+     +--------------------------+    +-----------------------+
| observe_only_degraded | --> |  managed_proxy_active    | -> |   full_managed_guard  |
| (Preflight scan only) |     |  (Live MCP Tool Defense) |    |   (+ Subagent Hooks)  |
+-----------------------+     +--------------------------+    +-----------------------+
```

1. **Current (`observe_only_degraded`)**: Artifact discovery, settings normalization, and preflight diffing completed.
2. **Phase 1 (`managed_proxy_active`)**: Implement `mcp_relay_native` configuration rewrite and atomic restore for Antigravity.
3. **Phase 2 (`full_managed_guard`)**: Subagent sandbox boundary verification and runtime prompt/output guardrails.

---

## Verification & Test Acceptance Matrix

All Antigravity implementations must pass:
- `tests/test_antigravity_adapter.py`:
  - `test_antigravity_skill_identity_covers_primary_and_nested_files`
  - `test_antigravity_incomplete_skill_identity_warns_without_external_path_disclosure`
  - `test_antigravity_policy_path_workspace_and_global`
  - `test_antigravity_detect_xdg_lowercase_settings`
  - `test_xdg_case_variants_keep_distinct_mcp_ids_when_both_files_exist`
  - `test_same_skill_name_in_two_roots_keeps_distinct_ids`
  - `test_home_agents_skills_are_not_antigravity`
  - `test_antigravity_detect_plugin_skills`
  - `test_antigravity_detect_workspace_agent_skills`
  - `test_antigravity_detect_mcp_config_and_extensions`
- Rust unit tests in `rust/crates/guard-runtime/src/adapters/detection/antigravity_detect.rs`:
  - `lowercase_xdg_source_stays_distinct_when_the_path_is_only_the_suffix`
  - `lowercase_xdg_settings_keep_a_distinct_mcp_id`
  - `xdg_case_variants_do_not_collapse_when_they_are_different_files` (Unix only)
  - `home_agents_skills_are_not_antigravity_and_do_not_admit_editor_settings`
  - `workspace_agents_skills_and_builtin_skills_keep_distinct_ids`
  - `nested_primary_skills_do_not_reuse_other_root_ids`
