# Guard Cloud control and evidence paths inventory

Status: wave-zero baseline. Audience: execution-assurance gate reviewers. Pinned refs: `hol-points-portal` `main` at `8d6d20daae94144bcda4e61f7fb575437751b8db`; HOL Guard source snapshot `release/3.1` at `10348fd40fa53ef60d9363bb6c37591b8bb60a61`, migrated to release 3.0 in PR #1901.

Maps Guard Cloud policy distribution, identity, device, evidence, command, session, protection, remediation, incident, notification, and MDM/EDR paths to their routes, repositories, schemas, and UI, with workspace/tenant authorization.

## Authorization model

Every Guard Cloud route resolves an actor through `resolveGuardActor()` (`src/lib/guard/guard-cloud-auth.ts`). The actor carries `workspaceId` (`:249-267`), resolved from the session's default workspace. Tenant isolation is by workspace: queries filter on `workspaceId` (e.g. OAuth grants at `:789`, `:848`, `:886`, `:912`, `:931`, `:942`). Routes return a stable error via `getGuardRouteErrorMessage`/`getGuardRouteErrorStatus` (`guard-cloud-route-error.ts`).

## Control and evidence matrix

| Capability | Route(s) | Repository / service | Schema (Drizzle) | Authorization |
| --- | --- | --- | --- | --- |
| Policy distribution | `GET/PUT app/api/guard/policy/route.ts`; `policy/plane`, `policy/defaults`, `policy/draft/*`, `policy/sync/{ack,summary}`, `policy/simulation/*`, `policy/test/*`, `team/policy-pack` | `src/lib/guard/service/policy-service.ts`, `guard-cloud-service.ts` | `hol-guard-cloud-schema.ts`, `hol-guard-protection-control-schema.ts` | `resolveGuardActor`, workspace-scoped |
| OAuth / device identity | `app/api/guard/oauth/{authorize,device,grants,jwks,register,revoke,token}` | `src/lib/guard/guard-cloud-auth.ts` | `hol-guard-oauth-core-schema.ts` (clients, redirect URIs, secrets, JWKS keys, assertion JTIs, auth codes, device codes, DPoP proofs, consents), `hol-guard-oauth-platform-schema.ts`, `hol-guard-oauth-schema.ts` | OAuth grant + workspace claims |
| Device inventory | `app/api/guard/devices/route.ts`, `app/api/guard/fleet/devices` | device service | `hol-guard-lifecycle-schema.ts`, `hol-guard-remote-pairing-schema.ts` | workspace-scoped (`workspaceId` query + actor) |
| Evidence ingestion | `app/api/guard/supply-chain/evidence` | supply-chain service | `hol-guard-supply-chain-schema.ts`, `hol-guard-supply-chain-feed-schema.ts`, `hol-guard-supply-chain-workspace-schema.ts` | workspace-scoped |
| Command queue | `app/api/guard/commands`, `commands/[jobId]/{cancel,heartbeat}`, `commands/device-state`, `commands/lease` | command service | `hol-guard-command-schema.ts` (`holGuardCommandJobs`, `holGuardCommandJobEvents`, `holGuardCommandDeviceCursors`, `holGuardCommandPendingLocalRequests`) | workspace-scoped |
| Runtime sessions | `app/api/guard/runtime/sessions`, `app/api/guard/session` | session service | `hol-guard-lifecycle-schema.ts` (`holGuardLifecycleEnrollments`, `holGuardLifecycleTouchState`) | workspace-scoped |
| Protection state | `app/api/guard/runtime/protection`, `jobs/protection-expiry` | protection service | `hol-guard-protection-schema.ts`, `hol-guard-protection-control-schema.ts` | workspace-scoped |
| Signed remediation | policy draft export + team policy-pack | policy service | `hol-guard-protection-control-schema.ts` | workspace-scoped |
| Incidents | `app/api/guard/incidents`, `incidents/[incidentId]/{assign,resolve}` | incident service | `hol-guard-cloud-schema.ts` | workspace-scoped |
| Notifications | `app/api/guard/notifications/{,deliveries,rules}` | notification service | `hol-guard-cloud-schema.ts` | workspace-scoped |
| MDM / EDR seams | lifecycle scheduler | lifecycle service | `hol-guard-lifecycle-schema.ts` (`holGuardLifecycleSchedulerCursor`, `holGuardLifecycleSchedulerState`) | workspace-scoped |

## Capability negotiation

Cloud ships new policy fields and routes behind entitlement/allowlist and client capability negotiation, reusing the existing `commandPatternExpressions` capability pattern rather than a separate feature-flag subsystem. Cloud never emits an isolation requirement to a client that did not advertise the compatible 3.0 contract version. Existing 2.1/2.2 clients retain current policy, receipt, runtime-session, protection, and approval behavior.

## Notes

- Affiliate, AEO, SEO, billing, CRM, funnel, and analytics guard routes are excluded; they are not control/evidence enforcement paths.
- `hol-guard-enterprise-intake-schema.ts`, `hol-guard-install-handoff-schema.ts`, `hol-guard-risk-assessment-schema.ts`, `hol-guard-conversion-schema.ts` support onboarding/install flows, not runtime control.
- This inventory records current routes and schemas; it does not authorize new Cloud persistence or authority.
