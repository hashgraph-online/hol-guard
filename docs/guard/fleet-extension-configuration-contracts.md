# Fleet Extension Configuration contracts

HOL Guard `release/3.2` reads the shared contracts under `contracts/managed-controls/v2` through packaged copies under `codex_plugin_scanner.guard.managed_controls.contracts.v2`.

## Supported contracts

| Kind | Schema version | Purpose |
|---|---|---|
| Fleet configuration | `guard.fleet-extension-configuration.v1` | Immutable Extension and Custom Extension intent |
| Assignment | `guard.managed-control-assignment.v1` | Durable selector and exclusion intent with continuous enrollment |
| Custom definition | `guard.custom-extension-definition.v2` | Portable opaque identity, command semantics, reviewed local variants |
| Custom configuration | `guard.custom-extension-configuration.v2` | Exact approved variants and allow/block command settings |
| Catalog semantics | `guard.catalog-semantic-fingerprint.v2` | Runtime Extension and permission meaning used for compatibility admission |

## Reader contract

`validate_fleet_contract()` enforces JSON Schema and bounded semantic invariants. It rejects unknown fields, invalid identifiers, noncanonical UTC timestamps, byte or item limit violations, duplicates, selector ambiguity, empty assignments, managed broadening, unreviewed trusted variants, unsupported schema versions, and invalid exact-binding modes.

`canonical_fleet_contract_bytes()` sorts authority-bearing collections using ordinal string order and emits deterministic JSON bytes. `fleet_contract_digest()` hashes a domain separator followed by those bytes. Frozen Cloud/Core vectors prevent accidental signing drift.

`negotiate_fleet_capabilities()` requires the complete reader, signed-delivery, and composite-apply capability set. Missing capability support excludes the runtime instead of downgrading meaning.

## Packaging

The reader uses `importlib.resources`; it never assumes a source checkout. `verify_packaged_contract_manifest()` validates every package resource against the manifest. CI builds and installs a wheel in an external directory and repeats the manifest and digest checks.

## Privacy boundary

Contracts must not contain raw paths, full commands, source text, environment values, credentials, tokens, secrets, or a machine-global Custom Extension identity. Errors expose stable reason codes and bounded operator copy, never rejected values.
