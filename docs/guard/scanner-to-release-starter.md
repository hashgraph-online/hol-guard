# Scanner to release evidence starter

This workflow connects a release scan to the existing HOL Plugin Release evidence contract. It runs the trusted reusable workflow, keeps registration opt-in, and records a commit-scoped attested result.

## Copyable workflow

Save this as `.github/workflows/hol-plugin-release.yml` in the plugin repository. Review the pinned workflow commit against the current HOL Guard release before merging.

```yaml
name: HOL Plugin Release

on:
  release:
    types: [published]

permissions: {}

jobs:
  hol-plugin-release:
    permissions:
      contents: read
      id-token: write
      attestations: write
      artifact-metadata: write
      security-events: write
    uses: hashgraph-online/hol-guard/.github/workflows/plugin-release.yml@1a0f5b01b431218aaea87bc469e47f0ddffda650
    with:
      plugin_dir: "."
      register_release: false
      upload_sarif: false
      offer_line: false
```

The pinned commit is the reviewed baseline for this starter. A release maintainer should update it only with a reviewed HOL Guard release and the corresponding provenance checks.

## What the workflow produces

- Scanner score, grade, severity summary, and policy profile
- Plugin Kit check result and supported runtime count
- Redacted release evidence with a digest
- GitHub artifact attestation bound to the evidence
- A 90-day workflow artifact containing the evidence and SBOM when the release declares packages

`register_release: false` keeps HOL registration disabled in the starter. A trusted workflow owner can enable registration after reviewing the listing, OIDC, visibility, retention, and duplicate-registration behavior. The pinned reusable workflow requests `security-events: write` even when SARIF upload is disabled, so the caller grants that scope.

## Claim language

Use the evidence contract's scoped language in release notes and listings:

> This commit was scanned by HOL Guard and checked by the HOL Plugin Kit under the recorded versions, and the evidence carries a GitHub-signed provenance attestation.

The evidence describes the checked commit and recorded policy. It carries the static-analysis limitations and the packaged-runtime boundary from the attestation contract.

## Review checklist

- The workflow uses a full commit SHA and the SHA is reviewed against the intended reusable workflow.
- The caller workflow grants only the permissions required by the selected features.
- Release registration remains an explicit decision by the workflow owner.
- Fork pull requests use a separate validation path that does not expose release credentials.
- Evidence output contains repository, commit, run, tool versions, policy, aggregate findings, digest, and expiry fields required by the contract.
- Source, prompts, secrets, raw paths, environment values, and finding text stay outside the evidence payload.
- A repeated release run is checked for idempotent evidence and listing behavior.

