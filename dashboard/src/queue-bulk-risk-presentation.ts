import { HiMiniExclamationTriangle, HiMiniShieldCheck } from "react-icons/hi2";
import type { BulkRiskTone } from "./queue-bulk-risk-disclosure";

export function toneRing(tone: BulkRiskTone): string {
  if (tone === "attention") {
    return "border-brand-attention/30 bg-brand-attention/[0.06]";
  }
  if (tone === "amber") {
    return "border-amber-300/60 bg-amber-50/70";
  }
  return "border-brand-green/30 bg-brand-green-bg/40";
}

export function toneChip(tone: BulkRiskTone): string {
  if (tone === "attention") {
    return "bg-brand-attention/10 text-brand-attention";
  }
  if (tone === "amber") {
    return "bg-amber-100 text-amber-800";
  }
  return "bg-brand-green/15 text-brand-green-text";
}

export function toneIcon(tone: BulkRiskTone) {
  if (tone === "attention" || tone === "amber") {
    return HiMiniExclamationTriangle;
  }
  return HiMiniShieldCheck;
}
