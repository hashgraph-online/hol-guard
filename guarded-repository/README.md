# HOL Guarded Repository

HOL Guarded Repository runs the current HOL Guard scanner against a repository, emits SARIF, creates sanitized scan evidence, and asks GitHub to produce signed provenance for that evidence.

Public or private verification at `hol.org` is available only through the trusted reusable workflow in `.github/workflows/guarded-repository.yml`. The verifier requires GitHub's `job_workflow_ref` claim for that HOL-owned workflow instead of trusting an arbitrary caller workflow.

## What this means

> Guarded Repository means this commit completed a versioned HOL Guard repository scan under the recorded configuration and produced a GitHub-signed provenance attestation. It does not mean vulnerability-free and does not prove runtime protection.

Do not shorten this into “secure repository,” “certified secure,” or any claim that a repository scan proves local runtime enforcement.

## Recommended usage

During the 3.0 alpha cycle, call the reusable workflow from `release/3.0`. Pin an immutable reviewed release or commit when available for production use.

```yaml
name: Guarded Repository

on:
  push:
  pull_request:

jobs:
  guard:
    permissions:
      contents: read
      id-token: write
      attestations: write
      artifact-metadata: write
      security-events: write
    uses: hashgraph-online/hol-guard/.github/workflows/guarded-repository.yml@release/3.0
    with:
      profile: strict-security
      fail_on_severity: critical
      upload_sarif: true
      visibility: public
```

The reusable workflow checks out the caller repository with credentials disabled, runs the scanner, optionally uploads SARIF, creates GitHub provenance for the sanitized evidence file, then requests an OIDC token whose audience is bound to that evidence digest before registration.

`security-events: write` is used only for the optional SARIF upload step. `artifact-metadata: write` is required by GitHub's attestation action. No repository-content write permission, issue permission, pull-request permission, package permission, or long-lived signing secret is required.

## Direct action usage

`guarded-repository/action.yml` can be used directly for scan, SARIF, and GitHub provenance without portal registration. Its `register_verification` input defaults to `false`.

Do not enable portal registration from an arbitrary direct caller workflow. The verifier intentionally requires the HOL Guard reusable workflow identity.

## Evidence and expiry

The portal receives only repository/commit/run identity, scanner metadata, aggregate scan counts, and hashes. It does not receive source code, raw SARIF findings, prompts, commands, paths, credentials, tokens, or runtime data.

`visibility: private` creates no public URL or badge. `visibility: public` is available only for public GitHub repositories and exposes a short-lived verification. A verification expires seven days after the evidence was generated and must be renewed by running the workflow again.
