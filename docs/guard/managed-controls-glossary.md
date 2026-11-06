# Managed Controls Product Glossary

This glossary is the shared product-language contract for HOL Guard 3.0 and Guard Cloud. Protocol and compatibility names may remain technical where changing them would break clients or increase release risk.

## Core objects

### Extension

A stable Local capability boundary for a protected tool or capability domain, such as Git, Docker, Kubernetes, GitHub, npm, or MCP. An Extension groups permissions, detector rules, dependencies, safer guidance, and source metadata.

Use **Extension** in customer-facing copy. Do not call an Extension a policy, module, integration, or rule.

### Permission

An independently configurable capability inside an Extension. A permission owns the detector rules and typed capabilities needed to recognize that behavior.

Use **permission** when the user can understand and configure a discrete capability. Keep detector implementation details under Technical details.

### Detector rule

A Local implementation detail that recognizes security-relevant evidence. Detector rules produce evidence. They do not grant authority or make final policy decisions.

Use **detector rule** only in technical documentation, diagnostics, receipts, and advanced authoring.

### Local setting

A device-specific Extension or permission preference. A Local setting may preserve or strengthen protection but cannot weaken a required floor or managed restriction.

Use **On this device**, **Local preference**, or **Local block** in the interface rather than the ambiguous label **managed**.

### Remembered rule

A contextual decision remembered from an approval. A remembered rule answers how Guard should handle an equivalent future request. It is not an Extension setting and cannot bypass a managed restriction.

Use **remembered decision** or **remembered rule** in customer-facing copy. Avoid calling remembered decisions policies.

### Control Set

A versioned, scoped, simulated, reviewed, signed, deployed, acknowledged, and auditable collection of Extension controls and contextual rules in Guard Cloud.

Use **Control Set** as the primary customer-facing Cloud object. Technical `GuardPolicy`, policy document, policy version, and bundle names remain valid implementation terms.

### Managed controls

The Guard Cloud product surface for creating, reviewing, deploying, monitoring, and auditing Control Sets.

Use **Managed controls** as the page and navigation label. Keep `/guard/controls` canonical and `/guard/policy` as a compatibility alias.

### Managed restriction

A signed `managed-restrictive` workspace floor that can disable an Extension, disable a permission, or activate global lockdown. It cannot be weakened locally in release 3.0.

Use **Managed by <workspace>** when the workspace name is available. Use **Workspace restriction** when it is not. Do not use a bare **Managed** badge.

### Deployment

A signed Control Set version delivered to an eligible runtime cohort with acknowledgement, drift, pause, rollback, and audit state.

Use **deployment** for the lifecycle. Use **rollout** for staged delivery within a deployment.

### Exception

A time-bounded, reviewed contextual deviation with reason, evidence, expiry, and reviewer state. In release 3.0, an exception cannot weaken a managed-restrictive Extension or permission block.

## Authority modes

### Personal shared

`personal-shared` applies shared posture to a user's authorized devices. Local tightening remains valid.

### Workspace shared

`workspace-shared` applies shared workspace posture. Local tightening remains valid.

### Managed restrictive

`managed-restrictive` creates a signed workspace floor. Release 3.0 limits this mode to Extension disable, permission disable, and global lockdown.

## Decision outcomes

### Permit

The contextual policy action `allow`. Permit does not override a required floor, a Local block, a shared restrictive control, or a managed restriction.

### Review

The contextual policy action `review`. Guard pauses for an authorized decision according to the existing approval workflow.

### Block

The contextual policy action `block`. Guard denies the contextual request.

### No contextual decision

No contextual policy action is authored for the selected Extension or permission. Extension posture and existing runtime floors still apply.

Do not present **Warn** or **Remember** as canonical Control Set outcomes. Warning is presentation behavior derived from a representable policy action. Remembering is an approval-memory operation, not a policy action.

## Source labels

Use precise labels that explain authority and provenance:

- **Built into HOL Guard**
- **On this device**
- **Synced from Guard Cloud**
- **Managed by <workspace>**
- **Required by HOL Guard**
- **Package Firewall**
- **Custom Extension, local only**

Avoid bare **Managed**, **Inherited**, or **Cloud** labels without an explanation of source and effect.

## Compatibility language

The following remain valid in protocol, API, database, route, and migration contexts:

- `GuardPolicy`
- policy document
- policy bundle
- policy version
- policy compiler
- policy route
- `/policy`
- `/guard/policy`

Customer-facing headings should use Managed controls, Control Sets, Extensions, permissions, remembered decisions, and Rules & exceptions unless a technical detail is being shown explicitly.
