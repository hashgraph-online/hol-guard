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

## Recorded responses

Every manifest needs recorded responses at
`tests/fixtures/provider_integrations/<slug>/recordings.json`, where `<slug>` is the part of the id
after `provider.`. Record, for each capability, one response for every verdict the map can produce,
one that maps to `unknown`, and one each for a refused key (`401`), rate limiting (`429`), an oversize
body and a malformed body. The format is described in
`rust/crates/guard-provider-integrations/src/conformance_fixtures.rs`, and
`tests/fixtures/provider_integrations/exampleshield/` is a complete example.

Run the checks on your manifest with the released CLI from a checkout of this repository:

```bash
hol-guard integrations conformance contributions/provider-integrations/provider.<slug>.json
```

It exits `0` when all five checks pass and `1` when one fails, and prints each problem.
`cargo test -p guard-provider-integrations --test conformance_kit` runs the same kit over every
manifest here in CI: the manifest compiles, every recording reads as recorded, the request carries exactly
the declared facts, the provider adds no prompt to the benign browser corpus, and `caution` on every
subject stays inside the noise caps.

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
