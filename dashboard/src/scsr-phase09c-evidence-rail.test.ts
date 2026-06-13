import type { GuardReceipt, GuardRuntimeSnapshot } from "./guard-types";
import {
  deriveSupplyChainEvidenceRail,
  resolveSupplyChainCloudDegradedState,
  supplyChainEvidenceHref,
} from "./supply-chain-evidence-rail";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

const baseSnapshot: GuardRuntimeSnapshot = {
  generated_at: new Date().toISOString(),
  approval_center_url: null,
  runtime_state: {},
  device: {
    installation_id: "install-1",
    device_label: "Test Machine",
    local_registered: false,
  },
  latest_connect_state: null,
  proof_status: {
    state: "not_connected",
    label: "Not connected",
    detail: "",
    request_id: null,
    pairing_completed_at: null,
    first_synced_at: null,
    receipts_stored: 0,
    inventory_items: 0,
    runtime_session_id: null,
    runtime_session_synced_at: null,
  },
  pending_count: 0,
  receipt_count: 0,
  headline_state: "local_only",
  headline_label: "Local only",
  headline_detail: "",
  sync_configured: false,
  cloud_state: "local_only",
  cloud_state_label: "Offline, free",
  cloud_state_detail: "Running locally without Guard Cloud.",
  cloud_pairing_state: {
    state: "local_only",
    label: "Not connected",
    detail: "",
    sync_configured: false,
    dashboard_url: "",
    inbox_url: "",
    fleet_url: "",
    connect_url: "",
  },
  cloud_sync_health: {
    state: "disabled",
    label: "Sync disabled",
    detail: "Cloud sync is turned off.",
    pending_events: 0,
    last_synced_at: null,
    next_retry_after: null,
  },
  dashboard_url: "",
  inbox_url: "",
  fleet_url: "",
  connect_url: "",
  items: [],
  latest_receipts: [],
  managed_installs: [],
  supply_chain: undefined,
};

const blockReceipt: GuardReceipt = {
  receipt_id: "receipt-block-1",
  harness: "claude",
  artifact_id: "package-request:lodash",
  artifact_hash: "hash-block",
  policy_decision: "block",
  capabilities_summary: "Guard blocked lodash before install.",
  changed_capabilities: [],
  provenance_summary: "",
  user_override: null,
  artifact_name: "lodash@4.17.20",
  source_scope: "/workspace",
  timestamp: "2026-06-09T14:00:00.000Z",
};

const auditReceipt: GuardReceipt = {
  receipt_id: "receipt-audit-1",
  harness: "package-firewall",
  artifact_id: "headless:package-firewall:audit",
  artifact_hash: "hash-audit",
  policy_decision: "warn",
  capabilities_summary: "Workspace audit completed with warn decision across 3 packages.",
  changed_capabilities: ["audit"],
  provenance_summary: "",
  user_override: null,
  artifact_name: "Workspace supply-chain audit",
  source_scope: "/workspace",
  timestamp: "2026-06-09T13:00:00.000Z",
  scanner_evidence: [
    {
      operation: "audit",
      audit_decision: "warn",
      blocked_package_count: 1,
      total_packages: 3,
    },
  ] as unknown as GuardReceipt["scanner_evidence"],
};

const syncReceipt: GuardReceipt = {
  receipt_id: "receipt-sync-1",
  harness: "package-firewall",
  artifact_id: "headless:package-firewall:sync",
  artifact_hash: "hash-sync",
  policy_decision: "allow",
  capabilities_summary: "Guard refreshed local supply-chain policy.",
  changed_capabilities: ["sync"],
  provenance_summary: "",
  user_override: null,
  artifact_name: "Headless sync",
  source_scope: "local-daemon",
  timestamp: "2026-06-09T12:00:00.000Z",
  scanner_evidence: [
    {
      operation: "sync",
      status: "completed",
    },
  ] as unknown as GuardReceipt["scanner_evidence"],
};

const rail = deriveSupplyChainEvidenceRail([syncReceipt, auditReceipt, blockReceipt]);

assert(rail.block.receiptId === "receipt-block-1", "SCSR154: latest block receipt surfaces on evidence rail");
assert(rail.block.title.includes("lodash"), "SCSR154: block title includes package name");
assert(rail.audit.receiptId === "receipt-audit-1", "SCSR154: latest audit receipt surfaces on evidence rail");
assert(rail.sync.receiptId === "receipt-sync-1", "SCSR154: latest sync receipt surfaces on evidence rail");

const emptyRail = deriveSupplyChainEvidenceRail([]);
assert(emptyRail.block.timestamp === null, "SCSR154-B: empty receipts keep waiting block state");
assert(emptyRail.audit.timestamp === null, "SCSR154-B: empty receipts keep waiting audit state");
assert(emptyRail.sync.timestamp === null, "SCSR154-B: empty receipts keep waiting sync state");

const cloudDegraded = resolveSupplyChainCloudDegradedState(baseSnapshot);
assert(cloudDegraded.active, "SCSR163: local_only cloud state activates degraded banner");
assert(
  cloudDegraded.detail.includes("Running locally without Guard Cloud"),
  "SCSR163: degraded banner uses snapshot cloud detail",
);

const pairedSnapshot = { ...baseSnapshot, cloud_state: "paired_active" as const };
assert(!resolveSupplyChainCloudDegradedState(pairedSnapshot).active, "SCSR163-B: paired cloud clears degraded banner");

const href = supplyChainEvidenceHref("receipt-audit-1", "package-firewall");
assert(href !== null && href.includes("receipt-audit-1"), "SCSR154-C: evidence href encodes receipt id");
assert(href !== null && href.includes("harness=package-firewall"), "SCSR154-D: audit evidence href keeps harness");

const blockedHref = supplyChainEvidenceHref("receipt-block-1", "claude");
assert(blockedHref !== null && blockedHref.includes("harness=claude"), "SCSR154-E: block evidence href uses receipt harness");

const blockedAuditReceipt: GuardReceipt = {
  ...auditReceipt,
  receipt_id: "receipt-audit-block-1",
  policy_decision: "block",
  timestamp: "2026-06-09T15:00:00.000Z",
};
const mixedRail = deriveSupplyChainEvidenceRail([blockedAuditReceipt, blockReceipt]);
assert(
  mixedRail.block.receiptId === "receipt-block-1",
  "SCSR154-F: blocked audit receipts stay in audit slot, not block slot",
);
assert(
  mixedRail.audit.receiptId === "receipt-audit-block-1",
  "SCSR154-G: blocked audit receipts still surface in audit slot",
);

const incompleteAuditReceipt: GuardReceipt = {
  ...auditReceipt,
  receipt_id: "receipt-audit-incomplete-1",
  policy_decision: "ask",
  capabilities_summary: "Sync Guard supply-chain intel on this device before auditing workspace packages.",
  timestamp: "2026-06-09T16:00:00.000Z",
  scanner_evidence: [
    {
      operation: "audit",
      audit_status: "incomplete",
      audit_decision: "monitor",
      blocked_package_count: 0,
      total_packages: 0,
    },
  ] as unknown as GuardReceipt["scanner_evidence"],
};
const incompleteRail = deriveSupplyChainEvidenceRail([incompleteAuditReceipt]);
assert(
  incompleteRail.audit.title === "Workspace audit did not complete",
  "SCSR154-H: incomplete audit receipts surface warning copy on evidence rail",
);
assert(incompleteRail.audit.tone === "attention", "SCSR154-I: incomplete audit receipts use attention tone");

console.log("scsr-phase09c-evidence-rail.test.ts: all assertions passed");
