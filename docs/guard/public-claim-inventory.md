# Public claim inventory

This inventory is the source-of-truth checklist for claims that may be repeated by hol.org, package metadata, structured data, `llms.txt`, release notes, and press copy.

| Claim family | Core source | Publication rule |
|---|---|---|
| Harness compatibility | `src/codex_plugin_scanner/guard/adapters/contracts.py` + `public-support-manifest.v1.json` | Publish only the selected release channel and always expose per-surface limitations. |
| Approval behavior | runtime policy + harness contract | Never say every invocation requires approval. Use allow, observe, ask, block, or unsupported. |
| Prompt-injection protection | prompt/runtime tests and safe labs | Describe the intercepted surface. Never claim universal model-level filtering. |
| Supply-chain scanning | scanner commands and package/skill/MCP evaluators | Keep scan-time detection separate from pre-action runtime enforcement. |
| Privacy | local/cloud transport and privacy docs | Local-only claims apply only when Cloud sync and remote intelligence are disabled. |
| Platforms | package CI/install tests | Publish only platforms covered by release tests. |
| Pricing | hol.org pricing service | Do not pin changing prices in core docs. |
| Download/star/adoption counts | external measurement | Date, denominator, and expiry required. Never present broader HOL activity as Guard-specific. |

## Current name migration

The previous website fact claiming standalone **Windsurf** support is retracted. HOL's product naming has moved to **Devin**, but no Devin adapter is present in the current Guard source contract. Therefore neither Windsurf nor Devin may be listed as supported until an adapter and reproducible proof land.

## Material claim fields

Every material public claim must provide: source/ref, observed date, expiry, release channel, owner, method, limitations, and known consumers.
