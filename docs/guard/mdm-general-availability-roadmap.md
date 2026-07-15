# HOL Guard MDM General Availability Roadmap

HOL Guard's managed deployment contract is organization-neutral. Every organization receives the same signed artifacts and lifecycle behavior. Tenant-specific policy, trust, proxy, enrollment, assignment, and retention values enter through managed configuration rather than source changes or custom packages.

## P0: production foundation

1. Publish signed, notarized macOS packages and Authenticode-signed Windows installers for every supported OS/architecture combination.
2. Publish a versioned support matrix and conformance results for package lifecycle, user activation, managed policy, enterprise networking, and removal.
3. Freeze and version the managed-policy, deployment-profile, status, event, and exit-code schemas with backward-compatibility tests.
4. Build a repeatable real-device lab covering generic Apple MDM and Windows MDM contracts, with Intune as an adapter rather than the product boundary.
5. Ship an organization intake template that produces policy and deployment profiles without code changes or embedded secrets.
6. Run pilots with at least two organizations using different MDM vendors and network models; publish anonymized pass/fail evidence.

## P1: broad administrator usability

1. Certify vendor adapter packs in demand order, initially Intune and one Apple-focused platform such as Jamf Pro, Kandji, or Mosyle.
2. Provide a local validator that checks organization policy, certificates, proxy settings, package compatibility, and detection configuration before rollout.
3. Add fleet health export and SIEM mappings based on the canonical event schema, without making Guard Cloud mandatory.
4. Publish migration, coexistence, rollback, incident-response, certificate-rotation, and support runbooks.
5. Define a deprecation policy for schemas, OS versions, architectures, signing identities, and vendor adapters.

## P2: ecosystem scale

1. Publish a vendor-adapter conformance kit so partners and customers can validate additional MDM products without changing Guard core.
2. Automate certification evidence collection and release attestations.
3. Add optional zero-touch workspace enrollment using short-lived, organization-scoped bootstrap credentials.
4. Establish compatibility SLAs and a public support matrix tied to Guard release channels.

## Generalization rules

- One artifact per platform and architecture, never per organization.
- One canonical policy and lifecycle contract, never vendor-specific core behavior.
- Vendor adapters translate packaging, assignment, detection, and remediation only.
- Organization identifiers and secrets remain outside installers and repositories.
- Local enforcement and health reporting continue when Guard Cloud or an MDM control plane is unavailable.
- A compatibility claim requires repeatable evidence from the published matrix, not success in a single customer environment.
