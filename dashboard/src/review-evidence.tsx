import { HiMiniExclamationTriangle, HiMiniInformationCircle } from "react-icons/hi2";
import { resolveSecondaryRiskSummary } from "./approval-center-utils";
import {
  deriveDataFlowEvidence,
  deriveEncodedLayerSignals,
  deriveSkillRiskSignals,
  deriveSupplyChainRiskSignals,
} from "./approval-center-utils";
import { type EvidenceItem } from "./consolidated-evidence-alert";
import { DataFlowEvidenceCard } from "./data-flow-evidence-card";
import { whyPaused } from "./evidence/plain-english";
import type { GuardApprovalRequest } from "./guard-types";
import { DecodedLayerCard, SkillRiskCard, SupplyChainRiskCard } from "./risk-signal-cards";
import { ScannerEvidenceSection } from "./scanner-evidence-badge";

export function buildTopAlertItems(item: GuardApprovalRequest): EvidenceItem[] {
  const items: EvidenceItem[] = [];
  const secondaryRiskSummary = resolveSecondaryRiskSummary(item);
  const pauseReason = whyPaused(item);
  if (secondaryRiskSummary) {
    items.push({
      id: "secondary-risk",
      title: "Additional risk",
      tone: "amber",
      icon: HiMiniExclamationTriangle,
      content: <p className="text-sm text-brand-dark">{secondaryRiskSummary}</p>,
    });
  }
  if (pauseReason) {
    items.push({
      id: "why-paused",
      title: "Why paused",
      tone: "blue",
      icon: HiMiniInformationCircle,
      content: <p className="text-sm text-brand-dark">{pauseReason}</p>,
    });
  }
  return items;
}

export function buildEvidenceItems(item: GuardApprovalRequest): EvidenceItem[] {
  const items: EvidenceItem[] = [];
  const allSignals = item.decision_v2_json?.signals ?? [];
  if (allSignals.some((signal) => signal.category === "skill" || signal.category === "mcp")) {
    items.push({
      id: "scanner",
      title: "Scanner evidence",
      tone: "blue",
      content: <ScannerEvidenceSection signals={allSignals} />,
    });
  }
  if (item.why_now) {
    items.push({
      id: "why-now",
      title: "Why now",
      tone: "purple",
      content: <p className="text-sm text-brand-dark">{item.why_now}</p>,
    });
  }
  if (deriveDataFlowEvidence(item) !== null) {
    items.push({
      id: "data-flow",
      title: "Data flow detected",
      tone: "blue",
      content: <DataFlowEvidenceCard item={item} />,
    });
  }
  if (deriveSkillRiskSignals(item).length > 0) {
    items.push({
      id: "skill-risk",
      title: "Skill risk",
      tone: "blue",
      content: <SkillRiskCard item={item} />,
    });
  }
  const isSupplyChainArtifact =
    item.artifact_type === "supply_chain" ||
    item.artifact_type === "package_request" ||
    (typeof item.artifact_type === "string" && item.artifact_type.endsWith("_package"));
  if (deriveSupplyChainRiskSignals(item).length > 0 || isSupplyChainArtifact) {
    items.push({
      id: "supply-chain",
      title: "Supply chain risk",
      tone: "amber",
      content: <SupplyChainRiskCard item={item} />,
    });
  }
  if (deriveEncodedLayerSignals(item).length > 0) {
    items.push({
      id: "decoded-layer",
      title: "Decoded layer",
      tone: "slate",
      content: <DecodedLayerCard item={item} />,
    });
  }
  return items;
}
