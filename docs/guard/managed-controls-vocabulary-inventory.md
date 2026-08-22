# HOL Guard 3.0 Managed Controls Vocabulary Inventory

This inventory classifies language that overlaps between Extensions and policy. It is intentionally scoped to product-critical surfaces and protocol contracts. Repository search and tests enforce the high-risk replacements listed below.

## Classification rules

- **Product language:** visible navigation, headings, descriptions, buttons, empty states, badges, accessibility labels, onboarding, help, and support copy.
- **Technical protocol language:** schemas, APIs, type names, database fields, compiler names, bundle names, and security evidence.
- **Compatibility language:** established routes, CLI flags, environment variables, migration names, and aliases retained to avoid breaking clients.

## Required product-language mapping

| Previous or ambiguous term | Product-language replacement | Classification | Notes |
|---|---|---|---|
| Policy, local navigation | Rules & exceptions | Product | Keep `/policy` as a compatibility route. |
| Saved decisions and local controls | Remembered decisions, Guard Cloud rules, and exceptions | Product | Do not imply Extension posture is edited here. |
| Managed extensions and integrations | Tools and capabilities protected on this device | Product | Extensions are capability boundaries, not integrations. |
| Policy Builder | Control Set Builder | Product | Cloud migration is implemented in the Portal. |
| Policy, Cloud page title | Managed controls | Product | The primary Cloud object is a Control Set. |
| Managed | Managed by `<workspace>` or Workspace restriction | Product | Always identify source and authority. |
| Inherited | Synced from Guard Cloud or Required by HOL Guard | Product | State where the value came from. |
| Cloud | Guard Cloud plus the exact object or source | Product | Avoid an unexplained Cloud badge. |
| Module | Extension | Product | Module may remain in third-party technical names. |
| Rule, detector implementation | Detector rule under Technical details | Product/technical | Keep rule IDs in evidence. |
| Policy rule, approval memory | Remembered decision or remembered rule | Product | Remembering is not a canonical policy action. |
| Permission | Permission | Product | Use for independently configurable Extension capabilities. |

## Product-critical HOL Guard occurrences

| Path | Current object | Classification | Required behavior |
|---|---|---|---|
| `dashboard/src/shell-navigation-model.ts` | `/policy` navigation item | Product plus compatibility route | Label Rules & exceptions. Keep href and view unchanged. |
| `dashboard/src/shell-navigation-model.ts` | `/extensions` navigation item | Product | Describe tools and capabilities protected on this device. |
| `dashboard/src/policy-workspace-page.tsx` | Policy workspace heading | Product | Explain remembered decisions, Guard Cloud rules, exceptions, and decision order. |
| `dashboard/src/policy-workspace.tsx` | remembered-rule and exception content | Product | Use source-aware labels. Do not add an Extension editor. |
| `dashboard/src/extension-control-center*` | local Extension posture | Product | Use Built into HOL Guard, On this device, Synced from Guard Cloud, and Managed by workspace. |
| `docs/guard/command-extension-architecture.md` | Extension, rule, policy authority | Technical documentation | Preserve detector and policy distinction and link ADR 0011. |
| `src/codex_plugin_scanner/guard/runtime/command_extensions.py` | Extension registry and sources | Technical protocol | Keep stable type and source values. |
| `src/codex_plugin_scanner/guard/runtime/extension_control_contract.py` | local-admin and signed-cloud layers | Technical protocol | Keep wire values. Product UI translates them. |
| `src/codex_plugin_scanner/guard/policy_bundle_v2.py` | policy bundle | Technical protocol | Keep compatibility name and signing contract. |
| `/policy` | local route | Compatibility | Preserve deep links and browser history. |

## Terms intentionally retained

The following technical and compatibility terms are not product-copy defects:

- `GuardPolicy`
- `policy_bundle_v2`
- policy compiler
- policy document
- policy version
- policy evaluation
- detector rule ID
- `/policy`
- existing policy CLI and environment variable names

## Review checklist

A product-copy change is incomplete when any of these are true:

1. An Extension setting is called a policy.
2. A bare Managed, Inherited, or Cloud badge appears without source and authority.
3. The Rules & exceptions surface offers a duplicate Extension editor.
4. Remember is presented as a canonical policy action.
5. A route or wire name is renamed without a compatibility alias.
6. Accessibility labels disagree with visible product language.
7. Technical evidence loses stable rule, Extension, or permission identity.
