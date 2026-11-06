import { ExtensionControlApiError } from "./extension-controls-api";
import type { EffectiveExtensionControls, ExtensionMutationPreview } from "./extension-controls-api";
import { extensionPolicyAuthorityUnchanged } from "./extension-policy-draft";

/**
 * Guard refuses a policy mutation that names a revision it no longer holds.
 * That refusal is what stops one admin from overwriting another's policy, and
 * it is reported under one of these codes whether the revision, the catalog or
 * the authority record moved.
 */
const POLICY_CONFLICT_CODES = ["revision_conflict", "catalog_conflict", "authority_conflict"];

export function isExtensionPolicyConflict(caught: unknown): boolean {
  return caught instanceof ExtensionControlApiError && POLICY_CONFLICT_CODES.includes(caught.code ?? "");
}

/**
 * The revision a refused draft may be re-seeded on without asking the operator.
 *
 * A refusal does not by itself mean the policy changed. The committed revision
 * moves on its own: a second Guard install reading this home under a different
 * command catalog restamps the controls, and integrity or lockdown transitions
 * re-publish them. When the authority Guard now holds is the one the draft was
 * composed against, the draft overlaps nothing and there is no decision left to
 * take, so it is re-seeded in place and tried once more. A revision that did
 * not move cannot make the retry succeed, and anything that changed the policy
 * itself keeps the draft stale and asks.
 */
export function extensionPolicyRepairBase(
  base: EffectiveExtensionControls,
  latest: EffectiveExtensionControls,
): EffectiveExtensionControls | null {
  if (latest.revision === base.revision) return null;
  return extensionPolicyAuthorityUnchanged(base, latest) ? latest : null;
}

/**
 * Whether `candidate` still carries the change the operator reviewed.
 *
 * A preview composed against the same revision is identified by its canonical
 * digest, which covers the exact bytes that were approved. A draft re-seeded on
 * a revision that moved digests differently by construction, because the digest
 * covers `previous_revision`, so that case is held to the effect the reviewed
 * preview describes instead.
 */
export function sameReviewedExtensionPolicyEffect(
  candidate: ExtensionMutationPreview,
  reviewed: ExtensionMutationPreview,
): boolean {
  if (candidate.previous_revision === reviewed.previous_revision) {
    return candidate.canonical_diff_digest === reviewed.canonical_diff_digest;
  }
  return candidate.catalog_digest === reviewed.catalog_digest
    && candidate.global_lockdown === reviewed.global_lockdown
    && candidate.controls === reviewed.controls
    && JSON.stringify(candidate.semantic_preview) === JSON.stringify(reviewed.semantic_preview);
}
