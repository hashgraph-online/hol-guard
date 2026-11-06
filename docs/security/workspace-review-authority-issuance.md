# Workspace Review Authority Issuance

Native workspace review accepts an Ed25519 workspace signer only after the
release enrollment root certifies its workspace, device, installation and scope
bindings. Cloud sign-in alone does not create this certificate.

## Prepare the Public Request

Prepare the unsigned `guard-native-workspace-review-authority.v1` record from
the authenticated enrollment request. Include every authority field except
`enrollment_signature`. The request contains public keys and binding digests;
it must contain neither the workspace signing key nor the release root seed.

Validate the request before presenting it to the custodian:

```sh
uv run --no-sync python scripts/approval/issue_workspace_review_authority.py \
  --request authority-request.json --validate-only
```

Confirm the originating workspace and installation, intended scope, signer
public key and current enrollment generation. A key ID is the SHA-256 digest of
the raw Ed25519 public key. Certificate validity is bounded authentication
authority; it does not limit the lifetime of business review requests.

## Certify With the Release Root

Configure the `guard-approval-root` GitHub environment with required user custodians,
self-review prevention and administrator bypass disabled. Team-only reviewer
rules are not supported. The issuance workflow checks required reviewers and
self-review prevention, then verifies an actual custodian approval before
exposing the seed. Dispatch **Issue workspace review authority** from `main`
with the unsigned request JSON. Signing is restricted to the first run attempt;
start a fresh dispatch instead of rerunning a previous issuance.

The validation job publishes the public request and its SHA-256 digest for
review. A custodian who did not initiate the run verifies these bindings and
approves the signing job with the exact `authority-request-sha256:<digest>`
comment shown in the validation summary. The workflow requires the approver to
be a configured custodian other than the original or rerun initiator. Bypassing
the waiting job without that approval does not permit signing. The signing step verifies that the reviewed request
is unchanged and that the root seed matches the pinned public root and
fingerprint. It emits only the signed public certificate.

Download the `workspace-review-authority` artifact. Retain the request digest,
certificate digest, workflow run URL and custodian approval in the issuance
record before the artifact retention period ends. Provision the certificate to
the workspace authority registry. Configure the workspace signing key through
its protected key-management path; it is never an issuance input or artifact.

The standalone signer supports the same operation when a custodian supplies
the root seed and matching pins through a protected process environment. Pass
the SHA-256 digest retained during the independent request review; do not
compute it from the request again at signing time:

Write the certificate into a directory owned by the signing user. On POSIX
systems, the output directory must not be a symlink or writable by other users.
The signer refuses an existing output and verifies the published file identity.

```sh
uv run --no-sync python scripts/approval/issue_workspace_review_authority.py \
  --request authority-request.json --expected-request-sha256 <reviewed-sha256> \
  --output workspace-review-authority.json
```

## Rotation and Revocation

Use the next enrollment generation and the native authority transition
contract. Rotation identifies the previous key; revocation preserves the
current key identity. Keep previous certificates and issuance records so
generation changes can be audited. Verify the new certificate through the
installed native runtime before activating the registry entry.

The issuer does not generate keys, change client consent, configure a registry,
or publish policies. Those operations retain their existing authenticated
owners.

## Replay Evidence

The resident retains consumed claims permanently, including their semantic
decision digests after transport expiry. The platform secure store anchors an
immutable hash-verified index for new decisions. Older installations retain a
bounded inline history during migration. Each new decision moves at most one
inline record and commits both representations
atomically; no consumed evidence is discarded to make room.

Authority rotation and revocation preserve this index. Missing or modified
index objects fail closed, and uncommitted objects cannot authorize a decision.
An indexed receipt proves decision consumption, not external action execution.

The inline migration tail is limited to 1,024 records; validation and secure
state writes remain proportional to that bounded tail until it drains. Index
insertion writes a bounded tree path and retains unreachable objects after
interrupted writes. Disk quotas and authenticated garbage collection are not
implemented here. Platform secure-store crash and rollback guarantees still
require platform-specific verification; file-backed tests do not prove them.
