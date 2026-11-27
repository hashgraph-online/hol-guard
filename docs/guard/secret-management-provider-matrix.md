# Secret Provider Matrix

This matrix is a product-planning snapshot for the [secret-management PRD](./secret-management-prd.md).
It compares integration shapes, not security guarantees. Every adapter still needs the same Guard contract,
fixture suite, privacy review, conformance result and installed-runtime evidence.

## Selection criteria

- A provider must support a scoped read path and a customer-controlled authorization boundary.
- Version, expiry, rotation or revocation metadata must be available when the provider exposes it.
- The adapter should prefer workload identity, OIDC, SPIFFE or short-lived exchange over a long-lived key.
- Guard stores connection credentials in a native OS store and never sends them through an agent request.
- Provider responses are evidence. Guard policy remains the authority for delivery and approval.
- A hosted or sponsored surface must be useful with metadata only and must not require secret-value telemetry.

## Matrix

| Provider or backend | Connection and identity | Read, version and lease shape | Audit and control signals | Guard adapter shape | Suggested phase | Sponsorship fit |
| --- | --- | --- | --- | --- | --- | --- |
| macOS Keychain | User account and Keychain access controls | Generic-password item keyed by service and account. No provider lease | OS access result and local metadata | First-party `native_keychain` backend | 1 | Native Guard feature, platform test sponsorship |
| Linux Secret Service | User session service and collection prompt | Item lookup by attributes and label. No provider lease | Service availability, lock and prompt outcome | First-party `native-secret-service` backend | 1 | Linux support and desktop integration |
| Windows Credential Manager | Per-user Credential Manager target | Generic credential target. No provider lease | API result and local metadata | First-party `native-credential-manager` backend | 1 | Windows support and enterprise qualification |
| HashiCorp Vault | JWT or OIDC workload identity, AppRole where required, or scoped token | KV reads with version metadata. Dynamic secrets expose leases, renewal and revocation | Audit devices, lease state and auth metadata | Typed HTTPS adapter with separate lease capability | 2 | Enterprise policy, dynamic credentials and verified adapter |
| AWS Secrets Manager | IAM role, workload identity or short-lived exchange | `GetSecretValue` supports version id and version stage. Rotation and CloudTrail metadata | IAM, CloudTrail and rotation configuration | Typed cloud adapter with version binding | 3 | Cloud design partner, fleet policy and audit export |
| Google Secret Manager | Workload Identity Federation or service identity with least privilege | Versioned secret resource and explicit version selector | IAM, data access audit logs and version state | Typed cloud adapter with pinned version default | 3 | WIF migration and policy packs |
| Azure Key Vault | Entra ID, managed identity and RBAC | Versioned secret URI, rotation metadata and disabled state | Azure Monitor logs, RBAC and managed identity | Typed cloud adapter with version binding | 4 | Enterprise identity, regional policy and audit |
| 1Password Connect | Customer-hosted Connect server and scoped service account | Vault, item and field references. Connect caches in customer infrastructure | Service-account vault scope and Connect health | Customer endpoint adapter with explicit local-host proof | 5 | Team password workflows and co-funded connector |
| Bitwarden Secrets Manager | Machine account, project scope and access token | Project and secret reads with client-side decryption | Event logs, project permissions and machine-account scope | Read-only project adapter with token in native store | 5 | Password-manager integration and verified connector |
| Doppler | Scoped service token or machine identity | Project and config reads with environment/config scope | Token scope and rate-limit responses | Typed API adapter with short-lived cache | 6 | Developer workflow and sponsored setup content |
| Infisical | Machine identity and short-lived universal-auth exchange | Project, environment and secret reads with TTL or use limits | Machine identity scope, expiry and audit metadata | Typed API adapter with connection rotation | 6 | Open-source cloud and self-hosted policy |
| SPIFFE workload identity | Workload API with X.509 or JWT SVID | Identity credential is short-lived and rotated by the workload platform | SVID expiry, audience and workload selector | Local or reviewed sidecar transport, no static token | 5 design track | Infrastructure identity and cloud-neutral enterprise support |

## Recommended order

1. Native backends establish the storage and unavailable behavior without a network dependency.
2. Vault proves a provider with both ordinary reads and dynamic leases.
3. AWS or Google proves cloud reads with workload identity and version binding. The first sponsor decides
   which adapter lands first, but the contract must not branch around that provider.
4. The second cloud adapter tests provider neutrality and audit metadata differences.
5. 1Password Connect or Bitwarden covers customer-controlled password-manager infrastructure.
6. Doppler and Infisical cover scoped developer configuration and machine-identity exchange.
7. SPIFFE remains a local workload-identity design track until a stable transport and platform test lane are
   available.

## Adapter requirements by class

### Native backends

- Store one logical record per provider, scope, name and optional field.
- Keep lookup attributes bounded and non-sensitive.
- Return availability and prompt outcomes as typed errors.
- Do not silently write an encrypted file when the platform store is unavailable.

### Enterprise and cloud providers

- Prefer workload identity, OIDC, WIF, managed identity or SPIFFE over static keys.
- Make version selectors explicit and bind resolved versions into approval and cache state.
- Keep provider audit correlation ids as metadata only and redact them from public artifacts if they can
  identify a private account.
- Cap response bytes, JSON depth, fields, timeout, retries and redirects before allocation.

### Customer-hosted connectors

- Require an explicit connection record and endpoint locality policy.
- Permit private-network endpoints only through a reviewed local adapter or an explicit local proof.
- Keep the customer service account or machine token in the native store.
- Treat Connect, machine-account and project scope as part of the approval binding.

## Public source notes

The following sources support the capabilities summarized above. Provider APIs and product limits can change,
so an adapter owner must refresh the source set before implementation and release.

- Apple Keychain Services, generic password items and access controls. [Keychain Services](https://developer.apple.com/documentation/security/keychain-services), [generic password items](https://developer.apple.com/documentation/security/ksecclassgenericpassword?changes=__9&language=objc), [access control lists](https://developer.apple.com/documentation/security/access-control-lists)
- Freedesktop Secret Service specification. [Secret Service](https://specifications.freedesktop.org/secret-service/latest/)
- Windows Credential Manager. [CredRead](https://learn.microsoft.com/en-us/windows/win32/api/wincred/nf-wincred-credreada)
- HashiCorp Vault leases, JWT authentication and audit. [Leases](https://developer.hashicorp.com/vault/docs/concepts/lease), [JWT auth](https://developer.hashicorp.com/vault/docs/auth/jwt), [audit](https://developer.hashicorp.com/vault/docs/audit)
- AWS Secrets Manager versioned reads, best practices and CloudTrail. [GetSecretValue](https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html), [best practices](https://docs.aws.amazon.com/secretsmanager/latest/userguide/best-practices.html), [CloudTrail](https://docs.aws.amazon.com/secretsmanager/latest/userguide/monitoring-cloudtrail.html)
- Google Secret Manager, access control, audit logging and workload identity federation. [Best practices](https://docs.cloud.google.com/secret-manager/docs/best-practices), [access control](https://docs.cloud.google.com/secret-manager/docs/access-control), [audit logging](https://docs.cloud.google.com/secret-manager/docs/audit-logging), [WIF](https://docs.cloud.google.com/iam/docs/workload-identity-federation)
- Azure Key Vault, RBAC, logging and managed identities. [Key Vault overview](https://learn.microsoft.com/azure/key-vault/general/overview), [RBAC guide](https://learn.microsoft.com/en-us/azure/key-vault/general/rbac-guide), [logging](https://learn.microsoft.com/en-us/azure/key-vault/general/howto-logging), [managed identities](https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/)
- 1Password Connect and secret references. [Connect](https://www.1password.dev/connect), [secret references](https://www.1password.dev/cli/secret-references)
- Bitwarden machine accounts and Secrets Manager. [Machine accounts](https://bitwarden.com/help/machine-accounts/), [Secrets Manager overview](https://bitwarden.com/help/secrets-manager-overview/), [secret decryption](https://bitwarden.com/en-gb/help/secret-decryption/)
- Doppler service tokens and API behavior. [Service tokens](https://docs.doppler.com/docs/service-tokens), [API reference](https://docs.doppler.com/reference/api)
- Infisical machine identities. [Machine identities](https://infisical.com/blog/introducing-machine-identities)
- SPIFFE workload identity and Workload API. [SPIFFE concepts](https://spiffe.io/docs/latest/spiffe-about/spiffe-concepts/), [Workload API](https://spiffe.io/docs/latest/spiffe-specs/spiffe_workload_api/)
