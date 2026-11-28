# Secret Management and Secret Reads Research

Research snapshot: 2026-11-27. This report supports the proposed [PRD](./secret-management-prd.md) and
provider contract. It records public design evidence and the Guard-specific conclusions derived from it.
Provider APIs, limits and product policies change. Adapter owners must refresh the official sources before
implementation and release.

## Executive summary

The strongest product boundary is local-first secret custody with a provider-neutral reference and a bounded
delivery API. Operating-system secure stores should hold the first-party user secrets and external connection
credentials. The agent should ask for a capability and destination, while the broker resolves a reference
and materializes it into a disposable process. Values should not flow through agent text, arguments, files,
logs or cloud telemetry.

External providers are commercially valuable when Guard owns the contract, trust binding, approval and
delivery boundary. A provider can add read, version, lease or verification evidence. It cannot create an
allow, grant itself authority, execute a command, or make a sponsor placement affect policy. This makes an
adapter a reviewable contribution and creates future sponsor surfaces through conformance, fleet policy,
audit metadata and setup content.

The research points to six implementation choices

1. Use OS secure storage as a distinct first-party scope and expose an explicit unavailable state for
   unsupported or headless systems.
2. Prefer workload identity and short-lived exchanges over long-lived provider keys.
3. Bind approvals to the complete operation context and version state, but never to the secret value.
4. Keep provider network work off the ordinary hook path with bounded workers and caches.
5. Treat leases, rotation, revocation and audit as provider-specific capabilities behind a closed contract.
6. Defer hosted value brokering. Start with metadata-only fleet policy and audit.

## Questions researched

- What do local secure stores guarantee and how do their lookup and prompt models differ?
- Which cloud and vault features are common enough for a provider-neutral contract?
- How can Guard support dynamic secrets, versioning, rotation and revocation without exposing values?
- How should external providers authenticate without asking agents to carry static credentials?
- What contribution and sponsorship surfaces can grow without turning payment or provider responses into
  runtime authority?
- Which cloud, password-manager and workload-identity integrations are sensible first adapters?

## Findings from local repository inspection

Guard already has useful floors and primitives

- `rust/crates/guard-command/src/environment_secret_dump.rs` classifies direct environment and shell secret
  reads. A provider API must not make those raw reads quiet.
- `rust/crates/guard-runtime/src/mcp_sensitive_read.rs` handles sensitive file reads with approval and
  fail-closed behavior. Secret delivery should reuse its binding and unavailable semantics where compatible.
- `rust/crates/guard-runtime/src/encrypted_secret_store.rs` is an internal encrypted file store. It should
  remain distinct from a user-facing OS-backed secret provider until a separate threat review accepts a file
  fallback.
- `rust/crates/guard-runtime/src/approval_enrollment_platform.rs` already demonstrates native platform
  credential storage. User secrets require a separate service scope and data model.
- `rust/crates/guard-runtime/src/secrets_cli.rs` provides a native scanner entry point that can be extended
  with a reference and delivery CLI without moving hot-path logic into Python.
- Existing extension guidance requires external contributions to be opt-in, generated artifacts to come from
  the supported flow, and runtime logic to live in Rust.

These findings support a sibling secret-provider substrate that can share trust, contract generation and
conformance ideas with the browser provider work, while keeping secret values out of browser and provider
signals.

## Local secure storage research

### macOS Keychain

Apple describes Keychain Services as a way to store small pieces of sensitive data. Generic password items
provide a natural record for a user secret. Service and account attributes form a stable lookup tuple, while
access controls determine which applications or contexts may use an item. Guard should use a distinct service
scope, bounded account and label fields, and treat user approval or access denial as typed outcomes.

[Keychain Services](https://developer.apple.com/documentation/security/keychain-services), [generic password items](https://developer.apple.com/documentation/security/ksecclassgenericpassword?changes=__9&language=objc), [access control lists](https://developer.apple.com/documentation/security/access-control-lists)

Guard-specific conclusion

- Use generic-password items for native user secrets.
- Keep service, account and display metadata free of secret values.
- Do not conflate Keychain access controls with a Guard approval. The broker still binds the delivery action.
- Test missing item, duplicate item, user cancellation, denied access and successful read separately.

### Linux Secret Service

The freedesktop Secret Service specification models a user-session service with collections and items. Items
have labels and lookup attributes, and the service may prompt to unlock or authorize access. Attributes are
lookup metadata and should not be assumed to have the same secrecy as the item value. Guard should treat a
missing session bus, locked collection, prompt denial and service absence as explicit unavailable states.

[Secret Service specification](https://specifications.freedesktop.org/secret-service/latest/)

Guard-specific conclusion

- Keep attributes to bounded synthetic-safe identifiers.
- Do not promise headless availability when a user session service is absent.
- Do not replace a failed Secret Service call with a plaintext or silent file fallback.
- Add a deterministic unavailable backend for CI and headless environments.

### Windows Credential Manager

Windows exposes per-user credential operations through Credential Manager APIs. The platform documentation
recommends Credential Manager for application credentials and warns against logging password material. Guard
should use a stable target name, isolate user-secret records from approval enrollment and keep API errors
typed and value-free.

[CredRead](https://learn.microsoft.com/en-us/windows/win32/api/wincred/nf-wincred-credreada), [handling passwords](https://learn.microsoft.com/en-us/windows/win32/SecBP/handling-passwords)

Guard-specific conclusion

- Use per-user generic credentials for the native backend.
- Treat target mismatch, unavailable API, denied access and missing credential as different diagnostic states.
- Do not add a DPAPI or file fallback without a separate decision and recovery model.

## Common secret-management controls

OWASP guidance consistently emphasizes short-lived or dynamic credentials, rotation, least privilege, audit
of who accessed what and when, no logging of secret material, workload identity where possible and minimizing
plaintext lifetime. These controls match the proposed broker and delivery boundary.

[OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)

Guard-specific conclusions

- A secret reference is a better agent interface than a value-bearing environment variable or file.
- A secret value should be resident only for the operation that needs it.
- Audit events should contain a provider, capability, reference digest, version digest, outcome and bounded
  timing fields. They should not contain the reference value, token or response body.
- Rotation and revocation must invalidate cached values and any approval whose version binding changed.

## Cloud secret-manager research

### AWS Secrets Manager

AWS exposes `GetSecretValue` with version id and version stage parameters. AWS recommends least-privilege
IAM, rotation, client-side caching and CloudTrail monitoring. The API documentation also warns against putting
sensitive information in request parameters because request metadata can be logged. This supports explicit
version selectors, connection identity in the approval binding, bounded cache state and metadata-only audit.

[GetSecretValue](https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html), [best practices](https://docs.aws.amazon.com/secretsmanager/latest/userguide/best-practices.html), [CloudTrail monitoring](https://docs.aws.amazon.com/secretsmanager/latest/userguide/monitoring-cloudtrail.html), [service authorization](https://docs.aws.amazon.com/service-authorization/latest/reference/list_secretsmanager.html)

Guard-specific conclusions

- Do not put a secret value or provider token in a URL, query parameter or request journal.
- Bind the resolved version or stage to the operation for pinned references.
- Treat AWS audit correlation as metadata and keep tenant exports opt-in.
- Prefer role or workload identity over static access keys.

### Google Secret Manager

Google documents versioned secret resources, IAM access control, data access audit logs and workload identity
federation. Its guidance favors avoiding long-lived service-account keys and using workload identity where
possible. Version selection and disabling a version before destruction provide useful rotation state.

- [Secret Manager best practices](https://docs.cloud.google.com/secret-manager/docs/best-practices)
- [Access control](https://docs.cloud.google.com/secret-manager/docs/access-control)
- [Audit logging](https://docs.cloud.google.com/secret-manager/docs/audit-logging)
- [Workload Identity Federation](https://docs.cloud.google.com/iam/docs/workload-identity-federation)
- [Service-account credential guidance](https://docs.cloud.google.com/iam/docs/best-practices-for-managing-service-account-keys)

Guard-specific conclusions

- Make an explicit version selector the default for high-risk values.
- Prefer WIF and short-lived exchanges. Do not accept a service-account key as a default contribution path.
- Preserve provider version and IAM scope metadata without returning it to an agent.

### Azure Key Vault

Azure Key Vault combines Entra authentication, role-based access control, versioned secrets, monitoring and
managed identities. Microsoft guidance covers RBAC, logging and managed identity use. A Guard adapter should
bind the vault, secret version, tenant or connection identity and selected sink, while leaving Entra and
provider policy as the provider's responsibility.

[Key Vault overview](https://learn.microsoft.com/azure/key-vault/general/overview), [RBAC guide](https://learn.microsoft.com/en-us/azure/key-vault/general/rbac-guide), [logging](https://learn.microsoft.com/en-us/azure/key-vault/general/howto-logging), [managed identities](https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/)

Guard-specific conclusions

- Use managed identity or an equivalent short-lived flow where available.
- Treat versioned secret URIs and disabled state as part of cache invalidation.
- Keep tenant and resource names bounded and out of public evidence when they identify private systems.

## Vault and dynamic credentials

HashiCorp Vault documents leases with time-to-live, renewal and revocation semantics. JWT authentication can
use claims and audience binding, while Vault audit devices record requests and HMAC sensitive values. Vault
also documents that if all audit devices fail, the service can become unavailable. That failure direction is
compatible with a typed unavailable result and a no-new-delivery rule.

[Vault leases](https://developer.hashicorp.com/vault/docs/concepts/lease), [JWT auth](https://developer.hashicorp.com/vault/docs/auth/jwt), [audit](https://developer.hashicorp.com/vault/docs/audit), [audit schema](https://developer.hashicorp.com/vault/docs/audit/schema), [audit best practices](https://developer.hashicorp.com/vault/docs/audit/best-practices)

Guard-specific conclusions

- Model lease id, expiry, renewable and revoked as metadata with a separate capability.
- Do not automatically renew in the first adapter. Add explicit renewal with a fresh approval and idempotent
  provider operation.
- Prefer JWT or OIDC workload identity over a static Vault token where the deployment supports it.
- Treat provider audit failure as unavailable rather than continuing a value path that cannot be audited.

## Password-manager and developer-config providers

### 1Password Connect

1Password Connect is a customer-hosted service with a REST interface and cache in customer infrastructure.
1Password secret references provide a stable CLI and automation syntax, and `op run` injects values into a
  process environment while masking output. Guard should use a customer-controlled endpoint, scoped service
  account and resident delivery, without spawning the CLI or copying its environment behavior blindly.

[1Password Connect](https://www.1password.dev/connect), [secret references](https://www.1password.dev/cli/secret-references)

Guard-specific conclusions

- Require an explicit connection record and local endpoint policy.
- Bind vault, item, field and service-account scope into the approval.
- Keep the Connect token in the native store and do not send it to the agent.

### Bitwarden Secrets Manager

Bitwarden documents machine accounts with project scope, one-time access-token display, event logs and
client-side secret decryption. These concepts fit a read-only project adapter and metadata-only audit, but the
adapter must preserve Bitwarden's decryption boundary and never treat a machine-account token as a user-facing
secret value.

[Machine accounts](https://bitwarden.com/help/machine-accounts/), [Secrets Manager overview](https://bitwarden.com/help/secrets-manager-overview/), [developer quick start](https://bitwarden.com/help/developer-quick-start/), [secret decryption](https://bitwarden.com/en-gb/help/secret-decryption/)

Guard-specific conclusions

- Require a project scope and read-only permission for the first adapter.
- Treat a one-time access token as connection material stored in the native backend.
- Record project and secret digests, not account names or token values, in evidence.

### Doppler and Infisical

Doppler documents scoped service tokens and API access. Infisical describes machine identities with a
universal-auth exchange and TTL or use limits. These are useful developer-config providers, but they must be
implemented only after scoped-token, expiry, rate-limit and rotation tests exist.

[Doppler service tokens](https://docs.doppler.com/docs/service-tokens), [Doppler API](https://docs.doppler.com/reference/api), [Infisical machine identities](https://infisical.com/blog/introducing-machine-identities)

Guard-specific conclusions

- Make project, environment and config scope part of the connection and approval binding.
- Prefer short-lived machine identity exchange over a long-lived service token.
- Keep provider rate limits and expiry in typed unavailable or stale states.

## Workload identity research

SPIFFE models a workload identity as a short-lived X.509 or JWT SVID delivered through a Workload API and
rotated by the workload platform. Google Workload Identity Federation and Azure managed identity express
similar goals for cloud providers. The common principle is to avoid a static bootstrap key in an agent
workspace or environment.

[SPIFFE concepts](https://spiffe.io/docs/latest/spiffe-about/spiffe-concepts/), [SPIFFE Workload API](https://spiffe.io/docs/latest/spiffe-specs/spiffe_workload_api/), [Google WIF](https://docs.cloud.google.com/iam/docs/workload-identity-federation), [Azure managed identities](https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/)

Guard-specific conclusions

- Use workload identity as an adapter authentication mode rather than requiring a static secret.
- Bind audience, subject, workload selector, provider connection and expiry metadata.
- Keep the Workload API or managed identity transport behind a reviewed local adapter.
- Do not allow a manifest to discover arbitrary sockets, processes or files.

## Provider and protocol ecosystem research

External Secrets Operator demonstrates a broad provider ecosystem with a common container resource model
and provider feature matrix. It is useful evidence that users value one reference surface across backends, but
Guard should not copy its controller or cluster trust model into a local agent hook.

[External Secrets provider documentation](https://external-secrets.io/latest/provider/hashicorp-vault/), [API reference](https://external-secrets.io/latest/api/spec/)

OAuth protected-resource metadata and token-exchange standards are relevant if a future hosted broker or MCP
resource server is added. A hosted MCP endpoint should validate resource audience and use the authorization
server metadata flow. The current local product does not need to become an OAuth server or carry provider
tokens through an MCP conversation.

[OAuth protected resource metadata](https://datatracker.ietf.org/doc/html/rfc9728), [OAuth token exchange](https://datatracker.ietf.org/doc/html/rfc8693), [MCP authorization](https://py.sdk.modelcontextprotocol.io/run/authorization/)

Guard-specific conclusions

- Keep cloud control-plane policy and audit metadata separate from local secret delivery.
- If a hosted service later brokers values, require a separate threat model, tenant-owned envelope keys,
  regional policy and incident response before implementation.

## Architecture alternatives considered

### Plain environment variables as the main API

This is convenient but makes a value visible to the agent, child inspection, crash reports and copied command
text. Keep environment delivery as a bounded sink for a selected child process, not as the reference API.

### Provider CLI execution

This would reduce adapter code but moves authority, output parsing, shell behavior, credential discovery and
network policy into an unreviewed process. The provider contract should use typed adapters and prohibit
subprocess execution from manifests.

### Encrypted file store as the default backend

This offers portability but introduces key management, file permissions, backup and process exposure questions.
Existing encrypted state can remain an internal Guard mechanism. Native OS stores should be the first user
secret backend, with a future file fallback requiring its own ADR.

### Hosted brokered secret values in v1

This could create a direct cloud product, but it expands the blast radius and requires tenant key ownership,
envelope encryption, regional controls, retention, compliance, incident response and offline semantics. Start
with metadata-only policy, audit and conformance products.

### One provider-specific API

This would ship faster for a design partner but would make sponsorship and future adapters expensive. A closed
capability contract with provider-specific typed implementations preserves a stable local product boundary.

## Recommended pilot

Build native storage, reference parsing, resident delivery and the offline conformance harness first. Select
Vault as the first external adapter if dynamic leases are the priority. Select AWS or Google as the first cloud
adapter if a sponsor can provide workload-identity test infrastructure. In either case, keep the synthetic
fixture provider as the required contract reference and add a second provider before declaring the contract
provider-neutral.

## Research gaps to resolve before release

- Exact macOS access-control behavior for the supported packaging and signing model.
- Secret Service prompt behavior in the supported Linux desktop and headless runners.
- Windows credential target lifecycle under packaged and unpackaged binaries.
- Provider-specific version and lease semantics for the chosen sponsor adapter.
- Private endpoint proof and proxy behavior for customer-hosted connectors.
- Memory lifetime and output redaction measurements on each supported platform.
- Tenant, region, key ownership and deletion requirements for any future hosted value path.

## Source refresh procedure

Before an adapter pull request or release

1. Re-open the official provider documentation in the matrix and confirm authentication, version, lease,
   audit and rate-limit behavior.
2. Record the documentation date and adapter version in the provider conformance report.
3. Re-run schema, fixture, offline and installed-runtime tests with synthetic credentials.
4. Check the outgoing public text and artifacts for private hosts, account names, local paths, request ids,
   tokens and secret-like values.
5. Revisit the threat model when a provider adds a capability, a new sink or a hosted data path.
