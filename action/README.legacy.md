# HOL AI Plugin Scanner GitHub Action

[![Latest Release](https://img.shields.io/github/v/release/hashgraph-online/hol-codex-plugin-scanner-action?display_name=tag)](https://github.com/hashgraph-online/hol-codex-plugin-scanner-action/releases/latest)
[![Compatibility Alias](https://img.shields.io/badge/legacy-slug-supported-6b7280)](https://github.com/hashgraph-online/hol-codex-plugin-scanner-action)
[![Canonical Repository](https://img.shields.io/badge/canonical-ai--plugin--scanner--action-0A84FF)](https://github.com/hashgraph-online/ai-plugin-scanner-action)
[![Source of Truth](https://img.shields.io/badge/source-ai--plugin--scanner-111827)](https://github.com/hashgraph-online/ai-plugin-scanner/tree/main/action)

This repository remains supported as a compatibility alias for existing workflows that use:

```yaml
uses: hashgraph-online/hol-codex-plugin-scanner-action@v1
```

New integrations should move to the canonical action slug:

```yaml
uses: hashgraph-online/ai-plugin-scanner-action@v1
```

The action behavior, release train, and source of truth are shared with the canonical repository:

- Canonical action repo: [hashgraph-online/ai-plugin-scanner-action](https://github.com/hashgraph-online/ai-plugin-scanner-action)
- Source repo: [hashgraph-online/ai-plugin-scanner](https://github.com/hashgraph-online/ai-plugin-scanner)

The compatibility alias continues to receive the same reviewed root bundle, release tags, and floating `v1` major tag so existing consumers do not break during the identity migration.
