const PROTECTION_REASON_COPY: Record<string, string> = {
  // Runtime registration and heartbeat.
  daemon_registration_missing:
    "Guard is re-registering the running local runtime. This clears on the next check.",
  daemon_registration_unavailable:
    "Guard could not write the local runtime registration.",
  daemon_registration_foreign:
    "A different Guard session owns the runtime registration, so this runtime will not overwrite it.",
  daemon_runtime_unavailable:
    "The local Guard runtime is not answering. Restart Guard to restore local protection.",
  daemon_heartbeat_stale:
    "The local Guard runtime stopped reporting heartbeats. Restart Guard to restore local protection.",
  daemon_heartbeat_unavailable: "Guard has no recorded heartbeat for the local runtime yet.",
  daemon_heartbeat_invalid: "The recorded runtime heartbeat is unreadable.",
  daemon_heartbeat_future:
    "The recorded runtime heartbeat is dated in the future, so Guard cannot trust it yet.",
  daemon_healthy: "The local Guard runtime is healthy.",
  daemon_runtime_drift:
    "The running runtime does not match the registered runtime. Restart Guard to converge.",
  daemon_containment_health_invalid:
    "The runtime reported unreadable containment health. Guard stays fail-closed.",
  // Containment compatibility.
  containment_health_invalid:
    "Guard could not read containment health from the local runtime.",
  containment_health_unavailable:
    "Guard could not obtain containment health from the local runtime.",
  containment_probe_failed:
    "The containment self-probe did not confirm enforcement. Guard stays fail-closed.",
  containment_probe_stale:
    "The containment self-probe proof is stale and needs to be refreshed.",
  containment_probe_future:
    "The containment self-probe proof is dated in the future, so Guard cannot trust it yet.",
  containment_schema_mismatch:
    "The containment schema version does not match this Guard build.",
  policy_version_mismatch: "The containment policy version does not match this Guard build.",
  policy_digest_mismatch: "The containment policy contents do not match this Guard build.",
  effect_contract_mismatch:
    "The effect contract version does not match this Guard build.",
  decision_plane_mismatch:
    "The decision plane schema version does not match this Guard build.",
  unsupported_platform: "Containment controls are not available on this platform.",
  // Command evidence.
  native_evaluation_unavailable:
    "Guard could not run the native policy engine to prove command evidence.",
  decision_stream_degraded:
    "Guard could not restore command evidence persistence.",
  decision_stream_health_unavailable:
    "Guard could not read the command evidence health store.",
  // App hooks.
  no_managed_harness: "No managed AI app is connected, so there are no hooks to verify.",
  hook_verification_failed: "Guard could not verify the managed app hooks.",
  one_or_more_hooks_inactive: "One or more managed app hooks are inactive.",
  hooks_inactive: "One or more managed app hooks are inactive.",
  hook_attestation_unavailable: "Guard could not obtain hook attestation proof.",
  hook_repair_failed: "Guard tried to repair managed app hooks and some did not recover.",
  hook_repair_unknown: "Guard could not confirm whether managed app hook repair finished.",
  // Integrity.
  rule_pack_runtime_proof_unavailable:
    "Guard has no runtime proof for the active local rule packs yet.",
  rule_packs_disabled: "Local rule packs are disabled until their integrity is proven.",
  tamper_checks_failed: "Managed Guard files or hooks did not pass integrity checks.",
  tamper_proof_unavailable: "Guard has no integrity proof for its managed files yet.",
  local_integrity_unproven: "Guard could not establish a local integrity proof.",
  proof_unavailable: "Guard has no proof for this check yet.",
};

export function protectionReasonText(reasonCode: string): string | null {
  return PROTECTION_REASON_COPY[reasonCode] ?? null;
}
