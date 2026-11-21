# HOL Plugin Release attestation

HOL Plugin Release is a release-time workflow for AI plugin authors. On each release it scans the plugin with the HOL Guard scanner, checks it with the Plugin Kit (`hol-guard plugin check`), records what the release ships, and asks GitHub to attest that record. HOL can then mark the version as checked on the plugin's listing and show what changed since the previous release.

The supported claim is intentionally narrow:

> This commit was scanned by HOL Guard and checked by the HOL Plugin Kit under the recorded versions, and the evidence carries a GitHub-signed provenance attestation. It does not mean vulnerability-free, and packaged runtimes were not load-tested.

"Packaged for N runtimes" means the Kit can build a package for that runtime. It does not mean the plugin was run there.

## Pieces

- `plugin-release/action.yml` is the composite action. It installs a pinned, hash-checked `hol-guard` Linux wheel after verifying its provenance against this repository, runs the scan and the Kit check, builds the evidence, and attests it. Registration with HOL defaults off. The `fail_on_severity` and `fail_on_check_errors` gates run after the attestation, so a release that fails a gate still gets an attested record of why.
- `src/codex_plugin_scanner/plugin_release_evidence.py` defines the evidence contract.
- `src/codex_plugin_scanner/plugin_release_sbom.py` builds the CycloneDX SBOM.
- `src/codex_plugin_scanner/plugin_release_runner.py` runs the evidence, registration and summary steps.

The composite runs the evidence code from the installed wheel, so it needs a `hol-guard` release that contains these modules. `plugin-release/guard-version.txt` and `plugin-release/guard-sha256.txt` pin that wheel. A stable pin is downloaded from PyPI and its PyPI provenance is verified. An alpha pin (`X.Y.ZaN`) is downloaded from the `alpha/vX.Y.ZaN` GitHub prerelease, because alpha native wheels are not published to PyPI, and its GitHub attestation must name this repository's `publish.yml` on `main` as the signer. Either way the SHA-256 must match the pin. `.github/workflows/plugin-release-smoke.yml` runs the composite on a Plugin Kit fixture when a pull request from a branch in this repository changes the pin or the locks. Pull requests from forks skip it, because the job installs the pinned Guard release with repository permissions; a maintainer runs it for a fork change with `workflow_dispatch` on the fork's commit after review. The trusted reusable workflow `.github/workflows/plugin-release.yml` pins this composite by commit, the same way `guarded-repository.yml` pins its composite.

## Trusted workflow

HOL accepts registration only from the reusable workflow. Its verifier checks the GitHub OIDC `job_workflow_ref` and `job_workflow_sha`, so a caller workflow that runs the composite directly cannot register forged evidence.

A plugin repository calls it from its release workflow, pinned by commit SHA:

```yaml
name: Release
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
    uses: hashgraph-online/hol-guard/.github/workflows/plugin-release.yml@<commit-sha>
    with:
      plugin_dir: "."
```

The job needs `id-token: write` for the OIDC token HOL verifies and `attestations: write` for the GitHub attestation. `security-events: write` is needed only with `upload_sarif: true`. The workflow sends the attested evidence to HOL by default; set `register_release: false` to attest without registering. HOL records every verified registration and shows it on the releases page of the listing whose repository matches; `release_url` is empty when no public listing matches.

When the matching listing has no HOL Blue or Gold membership, the job summary of the repository's first recorded release in 28 days carries one line about HOL Blue. HOL only decides whether the line appears and supplies a link to its own promote page; Guard writes the text and drops any link that is not on `https://hol.org/guard/plugins/promote`. Set `offer_line: false` to turn the line off. It never changes the evidence, the score or the listing.

## Evidence contract

The evidence records the repository and exact commit SHA, ref, workflow run ID, `hol-guard` version, scan profile, score and grade, highest finding severity, finding count, the Kit check result with its error and warning counts and diagnostic codes, the runtimes the Kit can package for, counts of skills, commands and agents, whether hooks ship, and one entry per MCP server:

- transport (`stdio`, `http` or `sse`);
- for stdio servers, the program's file name and, for `npx`, `bunx`, `pnpx` and `uvx`, the package it starts when the argument is shaped like a package name (for example `npx -y @acme/weather-mcp` records `npx` and `@acme/weather-mcp`); other programs record no package;
- for remote servers, the host name only;
- the names of the environment variables the server reads, taken from `env` values and `${NAME}` header templates.

A plugin that declares more than 50 MCP servers gets no evidence rather than a partial surface.

The evidence never includes source code, scanner findings, file contents, local paths, URLs beyond the host, environment variable values, header values, prompts, credentials or actor identity.

## SBOM

When the release declares third-party packages, the evidence step also writes a CycloneDX 1.6 SBOM (`sbom_path` output) and the evidence records its format, spec version, SHA-256 and component count under `sbom`. Because the evidence is attested, the attestation binds the SBOM file by digest. The SBOM lists:

- the non-development entries of `package-lock.json` (lockfile versions 1 to 3), with their SHA-512 integrity hashes;
- exact `==` pins in `requirements*.txt`, except development files such as `requirements-dev.txt` or `requirements-test.txt`;
- registry and git packages in `uv.lock`, without the plugin's own editable or local entries;
- the packages MCP servers start through `npx`, `bunx`, `pnpx` or `uvx`, without a version when the launch names a tag or range or no version at all. An unversioned launch of a package the lockfile already lists is left out.

Only files directly in `plugin_dir` are read. Symbolic links, files over 32 MiB and files that do not parse are skipped. A release with no packages, or more than 50,000, gets no SBOM rather than a partial one, and its evidence has no `sbom` key. The document records no run time, so rerunning a release of the same commit with the same Guard version reproduces the same digest. A `uv.lock` package installed from git carries its repository in a `vcs_url` qualifier, so it never merges with the registry release of the same name and version. The reusable workflow keeps the evidence and the SBOM as the `hol-plugin-release` run artifact for 90 days.

## Changes since the previous release

When HOL records a release, it compares the evidence with the previous checked version of the same repository and returns what the new version can newly reach or run: new MCP servers, network destinations, environment variables or launched packages, hooks that were not there before, a higher scan severity, or a Plugin Kit check that now fails. The job summary lists these under "Changes since X" and each one becomes a warning annotation on the run. They never fail the job. Guard keeps only the known kinds of change, at most 20, as plain single-line text.

## Canonical form

The evidence file is canonical JSON (sorted keys, two-space indent, ASCII escapes, trailing newline). Its SHA-256 is the attestation subject and is bound into the OIDC audience `hol-plugin-release:<evidence-sha256>`, so a token cannot be replayed for other evidence.
