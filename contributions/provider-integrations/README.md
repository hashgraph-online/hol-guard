# Provider integrations

Each file here is a provider integration manifest. It lets a security product the user already
uses add evidence to Guard's browser reviews through Guard's hooks. Guard does the checks it can do
on its own; a connected provider can only make a review stricter or add context to it. A provider
can never allow an action, and its verdict map has no allow value.

For what a provider can change, the noise caps and the calibration report needed for `verified`,
see the [provider integration guide](../../docs/guard/extensions/provider-integration-contributing.md).

## Files

- Name the file `<id>.json`, for example `provider.exampleshield.json`.
- `id` is `provider.<slug>`: lowercase letters, digits and hyphens.
- The file must validate against
  `contracts/provider-integrations/provider.v1.schema.json`.
- Hosts are exact HTTPS host names. Wildcards, IP literals, ports and loopback names are rejected.
- Request bodies are built only from Guard's closed fact set, and `shares` must list exactly the
  facts the request uses, because the connect dialog shows the user that list.
- The API key travels in a header. Paths cannot carry a query string.
- Use invented names and hosts in examples and fixtures.

## Trust

Every manifest needs a trust binding in `contracts/extensions/trust/<id>.v1.json`. Run:

```bash
python scripts/refresh_extension_artifacts.py --trust-only
```

New manifests are bound as `external`, so a provider does nothing until the user connects it.
Include the new binding file in the same pull request.
`python scripts/refresh_extension_artifacts.py --check-trust` fails when a manifest has no binding.

## Packaging

This directory ships in the wheel under
`codex_plugin_scanner/guard/contracts/data/provider_integrations/contributions`.
