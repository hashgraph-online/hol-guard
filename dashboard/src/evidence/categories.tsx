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
  HiMiniCpuChip,
  HiMiniBolt,
  HiMiniArchiveBox,
  HiMiniTableCells,
} from "react-icons/hi2";

export type ReceiptCategory =
  | "secret"
  | "network"
  | "destructive"
  | "hidden"
  | "file-write"
  | "mcp"
  | "skill"
  | "supply-chain"
  | "data"
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
    key: "mcp",
    label: "MCP tool",
    icon: <HiMiniCpuChip className="h-5 w-5" aria-hidden="true" />,
    color: "text-brand-blue",
    description: "Using a Model Context Protocol tool server",
  },
  {
    key: "skill",
    label: "Skill / plugin",
    icon: <HiMiniBolt className="h-5 w-5" aria-hidden="true" />,
    color: "text-brand-purple",
    description: "Running an AI skill or browser extension",
  },
  {
    key: "supply-chain",
    label: "Supply chain",
    icon: <HiMiniArchiveBox className="h-5 w-5" aria-hidden="true" />,
    color: "text-brand-attention",
    description: "Installing or running a package or script",
  },
  {
    key: "data",
    label: "Data access",
    icon: <HiMiniTableCells className="h-5 w-5" aria-hidden="true" />,
    color: "text-brand-blue",
    description: "Reading from or writing to a database",
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

const MCP_PATTERNS = [
  /mcp_tool/i,
  /mcp[._-]/i,
  /\bmcp\b/i,
];

const SKILL_PATTERNS = [
  /\bskill\b/i,
  /\bplugin\b/i,
  /\bextension\b/i,
];

const SUPPLY_CHAIN_PATTERNS = [
  /package_script/i,
  /\bnpm\s/i,
  /\bpip\s/i,
  /supply.?chain/i,
  /requirements\.txt/i,
  /pyproject\.toml/i,
];

const TOOL_PATTERNS = [
  /tool_call/i,
  /tool\./i,
];

const DATA_PATTERNS = [
  /\bdatabase\b/i,
  /\bsqlite\b/i,
  /\bpostgres\b/i,
  /\bmysql\b/i,
  /\bmongo\b/i,
  /\bquery\b/i,
];

const FILE_WRITE_PATTERNS = [
  /write.*file/i,
  /file.*write/i,
  /writes.*to.*disk/i,
  /\bwrite_file\b/i,
  /\bfile_write\b/i,
  /\bcreate_file\b/i,
  /saves.*to.*disk/i,
];

export function detectCategory(receipt: GuardReceipt): ReceiptCategory {
  const name = (receipt.artifact_name ?? receipt.artifact_id ?? "").toLowerCase();
  const summary = (receipt.capabilities_summary ?? "").toLowerCase();
  const artifactType = (receipt.artifact_type ?? "").toLowerCase();

  const text = `${name} ${summary} ${artifactType}`;

  if (SECRET_PATTERNS.some((p) => p.test(text))) return "secret";
  if (DESTRUCTIVE_PATTERNS.some((p) => p.test(text))) return "destructive";
  if (HIDDEN_PATTERNS.some((p) => p.test(text))) return "hidden";
  if (artifactType === "mcp_tool" || MCP_PATTERNS.some((p) => p.test(text))) return "mcp";
  if (SKILL_PATTERNS.some((p) => p.test(text))) return "skill";
  if (artifactType === "package_script" || SUPPLY_CHAIN_PATTERNS.some((p) => p.test(text))) return "supply-chain";
  if (NETWORK_PATTERNS.some((p) => p.test(text))) return "network";
  if (TOOL_PATTERNS.some((p) => p.test(text))) return "tool-call";
  if (artifactType.includes("file_write") || artifactType.includes("write") || FILE_WRITE_PATTERNS.some((p) => p.test(text))) return "file-write";
  if (DATA_PATTERNS.some((p) => p.test(text))) return "data";
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
