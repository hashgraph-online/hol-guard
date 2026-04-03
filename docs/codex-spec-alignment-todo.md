# Codex Spec Alignment Todo

## Implementation workstreams

### Marketplace model and compatibility

- Add a shared marketplace loader that resolves the preferred path `.agents/plugins/marketplace.json` and a deprecated fallback `marketplace.json`.
- Normalize marketplace context around two roots:
  - repository root
  - marketplace file parent directory
- Replace string-only `plugin.source` handling with support for `source.source` and `source.path`.
- Add validation helpers for:
  - required `plugins[].policy.installation`
  - required `plugins[].policy.authentication`
  - required `plugins[].category`
  - optional marketplace `interface.displayName`
  - `source.path` `./` prefix
  - `source.path` staying within the marketplace root
- Keep legacy root marketplace parsing but mark it as compatibility mode in messages/findings.

### Manifest and autofix alignment

- Remove `interface.type` from the required interface metadata set.
- Centralize path normalization logic so manifest and marketplace checks share the same `./`-prefixed relative-path policy.
- Update autofix behavior to:
  - preserve existing valid `./` prefixes
  - add `./` for eligible local paths in plugin and marketplace JSON
  - avoid mutating remote URLs or non-path string fields

### MCP verification lifecycle

- Introduce a small JSON-RPC transport helper for newline-delimited stdio MCP sessions.
- Send `initialize` with:
  - `protocolVersion`
  - `capabilities`
  - `clientInfo`
- Parse the initialize result and, when successful, send `notifications/initialized`.
- Probe optional capabilities with:
  - `tools/list`
  - `resources/list`
  - `prompts/list`
- Record requests and responses in runtime traces for `doctor`.
- Preserve strict timeouts and guaranteed subprocess cleanup.

### Action ergonomics

- Extend `action/action.yml` inputs with:
  - `upload_sarif`
  - `sarif_category`
- Extend Action outputs with:
  - `policy_pass`
  - `verify_pass`
- Update `action_runner.py` to emit those outputs and write a default SARIF path when upload is requested.
- Add a conditional `github/codeql-action/upload-sarif` step pinned by SHA.

### Documentation and fixtures

- Update README examples for:
  - `.agents/plugins/marketplace.json`
  - `lint --fix`
  - SARIF upload usage
- Add or update fixtures for:
  - valid Codex marketplace repo layout
  - legacy marketplace compatibility
  - MCP stdio stub server handshake

## Test plan

- `tests/test_marketplace.py`
  - preferred marketplace path
  - legacy fallback
  - `source.path` prefix and containment
  - required category and policy fields
- `tests/test_manifest.py`
  - interface metadata passes without `type`
- `tests/test_verification.py`
  - MCP initialize + initialized
  - capability enumeration traces
  - doctor bundle includes real lifecycle traces
- `tests/test_cli.py`
  - `lint --fix` preserves or adds `./`
- `tests/test_action_runner.py`
  - SARIF upload path preparation
  - `policy_pass` and `verify_pass` outputs
- `tests/test_action_bundle.py`
  - Action metadata and new upload inputs
