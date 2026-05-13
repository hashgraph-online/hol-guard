import React from "react";
import type { GuardReceipt } from "../guard-types";
import {
  HiMiniLockClosed,
  HiMiniGlobeAlt,
  HiMiniExclamationTriangle,
  HiMiniEyeSlash,
  HiMiniDocumentText,
  HiMiniWrenchScrewdriver,
  HiMiniCircleStack,
} from "react-icons/hi2";

export type ReceiptCategory =
  | "secret"
  | "network"
  | "destructive"
  | "hidden"
  | "file-write"
  | "tool-call"
  | "other";

export interface CategoryInfo {
  key: ReceiptCategory;
  label: string;
  icon: React.ReactNode;
  color: string;
  description: string;
}

export const CATEGORIES: CategoryInfo[] = [
  {
    key: "secret",
    label: "Secret read",
    icon: <HiMiniLockClosed className="h-5 w-5" aria-hidden="true" />,
    color: "text-brand-attention",
    description: "Reading files that contain passwords or keys",
  },
  {
    key: "network",
    label: "Network",
    icon: <HiMiniGlobeAlt className="h-5 w-5" aria-hidden="true" />,
    color: "text-brand-blue",
    description: "Connecting to websites or external services",
  },
  {
    key: "destructive",
    label: "Destructive",
    icon: <HiMiniExclamationTriangle className="h-5 w-5" aria-hidden="true" />,
    color: "text-brand-purple",
    description: "Commands that delete or overwrite files",
  },
  {
    key: "hidden",
    label: "Hidden script",
    icon: <HiMiniEyeSlash className="h-5 w-5" aria-hidden="true" />,
    color: "text-brand-attention",
    description: "Encoded or obfuscated code",
  },
  {
    key: "file-write",
    label: "File write",
    icon: <HiMiniDocumentText className="h-5 w-5" aria-hidden="true" />,
    color: "text-brand-green",
    description: "Writing or modifying files",
  },
  {
    key: "tool-call",
    label: "Tool call",
    icon: <HiMiniWrenchScrewdriver className="h-5 w-5" aria-hidden="true" />,
    color: "text-brand-blue",
    description: "Using external tools or MCP servers",
  },
  {
    key: "other",
    label: "Other",
    icon: <HiMiniCircleStack className="h-5 w-5" aria-hidden="true" />,
    color: "text-slate-500",
    description: "Other actions",
  },
];

const SECRET_PATTERNS = [
  /\.env/i,
  /\.env\.local/i,
  /\.env\.production/i,
  /\.npmrc/i,
  /\.netrc/i,
  /id_rsa/i,
  /id_ed25519/i,
  /\.aws\/credentials/i,
  /\.docker\/config\.json/i,
  /secret/i,
  /password/i,
  /token/i,
  /key/i,
  /credential/i,
  /private/i,
];

const NETWORK_PATTERNS = [
  /curl\s/i,
  /wget\s/i,
  /fetch\s/i,
  /http/i,
  /api\./i,
  /\.com/i,
  /\.org/i,
  /\.net/i,
];

const DESTRUCTIVE_PATTERNS = [
  /rm\s+-rf/i,
  /rm\s+-r/i,
  /rmdir/i,
  /truncate/i,
  /dd\s+if=/i,
  />\s*\//i,
  /mv\s+.*\s+.*\/dev\/null/i,
];

const HIDDEN_PATTERNS = [
  /base64/i,
  /eval\s*\(/i,
  /decode/i,
  /encoded/i,
  /obfusc/i,
  /encrypted.*script/i,
];

const TOOL_PATTERNS = [
  /mcp/i,
  /tool_call/i,
  /tool\./i,
];

export function detectCategory(receipt: GuardReceipt): ReceiptCategory {
  const name = (receipt.artifact_name ?? receipt.artifact_id ?? "").toLowerCase();
  const summary = (receipt.capabilities_summary ?? "").toLowerCase();
  const artifactType = (receipt.artifact_type ?? "").toLowerCase();

  const text = `${name} ${summary} ${artifactType}`;

  if (SECRET_PATTERNS.some((p) => p.test(text))) return "secret";
  if (DESTRUCTIVE_PATTERNS.some((p) => p.test(text))) return "destructive";
  if (HIDDEN_PATTERNS.some((p) => p.test(text))) return "hidden";
  if (NETWORK_PATTERNS.some((p) => p.test(text))) return "network";
  if (TOOL_PATTERNS.some((p) => p.test(text))) return "tool-call";
  if (artifactType.includes("file_write") || artifactType.includes("write")) return "file-write";
  if (artifactType.includes("file_read") || artifactType.includes("read")) return "other";

  return "other";
}

export function getCategoryInfo(key: ReceiptCategory): CategoryInfo {
  return CATEGORIES.find((c) => c.key === key) ?? CATEGORIES[CATEGORIES.length - 1];
}

export function groupByCategory(receipts: GuardReceipt[]): Map<ReceiptCategory, GuardReceipt[]> {
  const map = new Map<ReceiptCategory, GuardReceipt[]>();
  for (const receipt of receipts) {
    const cat = detectCategory(receipt);
    if (!map.has(cat)) map.set(cat, []);
    map.get(cat)!.push(receipt);
  }
  return map;
}
