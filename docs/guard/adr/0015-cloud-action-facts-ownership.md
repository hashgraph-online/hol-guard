# ADR 0015: Cloud action facts ownership

Status: accepted.

## Decision

- `guard.action-facts.v2` and its fact selector live in `guard-contracts`. They are pure data: strict bounded decoding, consistency checks, and a three-valued match (`yes`, `no`, `unknown`). No other crate defines what a cloud action is.
- The v1 business-action facts (`guard.business-action.v1`) and policy match stay as they are. `ActionFactsV2::from_business_action_v1` lifts v1 facts, and `BusinessPolicyMatchV1::lift_to_fact_selectors_v2` (in `guard-policy-snapshot`) lifts v1 selectors. On every complete v1 fact the lifted selectors answer exactly as v1 does. Selectors with account bindings have no v2 form and stay on v1.
- The cloud action evaluator (`guard-command`, `cloud_action.rs`) is the one decision engine for both request versions. Pack compilation and `inspect` also belong to `guard-command`. Hosted services call the shipped runtime; they do not re-implement selectors or the join.
- An unknown fact never takes the lenient branch. A selector whose answer depends on an unknown fact is treated as matching for stricter outcomes and as not matching for looser ones.
- Text produced by a model never sets a fact. Facts come from the request arguments, provider metadata, and detectors, and detectors only add findings.

## Consequences

Policy, packs, and hosted gateways share one vocabulary and one evaluator, so a fact means the same thing wherever a decision is made. The approval rules in [the approval invariant](../approval-invariant.md) are unchanged: the evaluator still offers Allow once and Always allow for every reviewable action, and a saved consent never applies to a fact it could not see. Hook-path ownership in [native hook data plane ownership](../native-hook-data-plane-ownership.md) is unchanged.
