# Guard 3.0 final release evidence

The final release record is a reproducible, privacy-safe summary of the
artifact, installed-runtime, Desktop Core, security, and review gates. It
contains hashes, bounded labels, counts, statuses, and the reproducible
command names. It does not contain command output, source text, local paths,
hook payloads, credentials, or attestation secrets.

## Artifact identity

Build each native wheel from the exact source commit and validate the wheel
set offline:

```text
python scripts/ci/validate_release_artifacts.py \
  --dist-dir dist \
  --version <version> \
  --source-sha <40-lowercase-hex> \
  --rule-digest <64-lowercase-hex> \
  --windows-waiver <reason> \
  --policy-identity policy-identity.json \
  --sbom release.sbom.json \
  --provenance release.intoto.jsonl \
  --output artifact-evidence.json
```

The validator binds every native wheel to its PEP 425 platform tag, Rust
target, package version, source commit, rule digest, runtime size, and runtime
SHA-256. It rejects symlinks, duplicate archive members, oversized members,
foreign binaries, incomplete matrices, and Windows omissions without an
explicit waiver. SBOM and provenance files are hashed and structurally
validated; they are never fetched by the validator.

## Desktop Core

Stage the runtime from a validated native wheel, build Core, sign it, seal the
manifest, and verify the post-sign bytes with the matching sidecar marker:

```text
python scripts/release/verify_desktop_core_attestation.py \
  --binary <core-binary> \
  --manifest <core-binary>.json \
  --marker <core-binary>.attested.json \
  --version <version> \
  --source-commit <40-lowercase-hex> \
  --source-tag <tag> \
  --target <target> \
  --team-id <team-id> \
  --output desktop-core-evidence.json
```

The check binds the signed binary, update manifest, attestation marker, Core
version/source/target, and Apple team identity. It invokes the existing
PyInstaller native-runtime verifier after signing, so a manifest from before
signing cannot authorize changed bytes.

## Installed matrix

The installed matrix must exercise clean install, upgrade, reinstall,
rollback, and fault-injection scenarios on every available Tier-1 platform.
Each scenario records only `pass`, `fail-safe`, or `degraded`, plus bounded
counts and the booleans proving that production environment variables were
unset, the native runtime was selected, no Python semantic fallback was used,
and neither PATH discovery nor runtime download occurred:

The all-harness set is the release-3.0 canonical set: Codex, Claude Code,
Copilot, Cursor, Gemini, Hermes, OpenClaw, Antigravity, OpenCode, Kimi, Grok,
Pi, and ZCode. Every scenario must name all 13 identifiers; the validator
normalizes the result to aggregate fields only.

```text
python scripts/ci/verify_installed_release_matrix.py \
  --matrix installed-release-matrix.json \
  --version <version> \
  --source-sha <40-lowercase-hex> \
  --rule-digest <64-lowercase-hex> \
  --windows-waiver <reason> \
  --output installed-release-matrix.normalized.json
```

If Windows evidence is unavailable, the final record must carry a visible
`windows.status=waived` entry. A waiver does not convert a failed Windows
run into a pass and does not weaken any non-Windows gate.

## Final gate and signature

The final record names these independent gates: CI, CodeQL, fuzzing,
adversarial coverage, parity, mutation, source-race, approval-replay,
fault-injection, soak, privacy, and independent review. It also records the
exact CI run, exact source/base commits, required-check state, component
evidence hashes, and the reproducible command set:

```text
python scripts/ci/final_release_evidence.py \
  --evidence final-release-evidence.json \
  --version <version> \
  --source-sha <40-lowercase-hex> \
  --rule-digest <64-lowercase-hex>
```

The validator reports `release_ready=false` until an external detached
Ed25519 signature binds the canonical unsigned bytes. A release may record
ordinary runtime evidence while approval remains fail-closed, but it must
never claim an approval-capable release unless the dedicated enrollment root,
root fingerprint, signer ceremony, and resident enrollment evidence are all
present. No private key belongs in this repository or its CI logs.

For a signed final record, pass `--require-signature` together with an
independently configured `--trusted-public-key` and `--trusted-key-id`. The
signature record must identify that purpose-specific key ID and bind the
SHA-256 of the canonical unsigned evidence projection. Its embedded public key
must match the independent trust anchor before the detached signature is
verified and `release_ready=true` is set. The signing ceremony is external to
the repository and is recorded by reference only.
