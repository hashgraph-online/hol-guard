# Guarded Repository attestation

Guarded Repository is a repository-scan provenance workflow for HOL Guard. It runs the existing scanner, can upload SARIF to GitHub code scanning, produces sanitized scan evidence, and asks GitHub to attest that evidence artifact.

The supported claim is intentionally narrow:

> Guarded Repository means this commit completed a versioned HOL Guard repository scan under the recorded configuration and produced a GitHub-signed provenance attestation. It does not mean vulnerability-free and does not prove runtime protection.

## Trusted workflow

Portal registration is supported only through `.github/workflows/guarded-repository.yml`. The verifier uses GitHub OIDC `job_workflow_ref` and `job_workflow_sha` to distinguish the HOL-owned reusable workflow from an arbitrary caller workflow.

The workflow uses read-only repository contents, GitHub OIDC, artifact-attestation permissions, artifact metadata, and optional code-scanning upload. Checkout does not persist credentials.

Direct use of `guarded-repository/action.yml` remains available for scan, SARIF, and GitHub provenance, but portal registration defaults off.

## Evidence contract

Only coarse scan metadata is sent to the verifier: repository and exact commit SHA, workflow run ID, scanner version/profile, score/grade, maximum finding severity, finding count, SARIF SHA-256, generated time, and evidence visibility.

The evidence does not include source code, raw SARIF findings, local paths, prompts, commands, credentials, tokens, or runtime data.

## Registration identity

The registration helper requests a fresh GitHub OIDC token with audience `hol-guard-repository:<evidence-sha256>`. The token is sent as a bearer credential and is not embedded in the JSON evidence. The verifier rejects repository, commit, workflow-run, reusable-workflow, runner, or audience mismatches.

## Public and private modes

Public mode is for public GitHub repositories whose evidence subject can be observed through GitHub's public attestations API. Public verification produces a short-lived page and badge. Private mode stores no public URL or badge.

## Renewal

A verification is tied to one commit and expires seven days after the evidence was generated. Re-run the workflow for a new commit or refreshed scan. An expired badge must not be represented as current evidence.
