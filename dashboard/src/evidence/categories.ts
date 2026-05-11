import type { GuardReceipt } from "../guard-types";

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
  icon: string; // lucide icon name
  color: string;
  description: string;
}

export const CATEGORIES: CategoryInfo[] = [
  {
    key: "secret",
    label: "Secret read",
    icon: "Lock",
    color: "text-amber-600",
    description: "Reading files that contain passwords or keys",
  },
  {
    key: "network",
    label: "Network",
    icon: "Globe",
    color: "text-sky-600",
    description: "Connecting to websites or external services",
  },
  {
    key: "destructive",
    label: "Destructive",
    icon: "Bomb",
    color: "text-rose-600",
    description: "Commands that delete or overwrite files",
  },
  {
    key: "hidden",
    label: "Hidden script",
    icon: "Mask",
    color: "text-violet-600",
    description: "Encoded or obfuscated code",
  },
  {
    key: "file-write",
    label: "File write",
    icon: "FileEdit",
    color: "text-emerald-600",
    description: "Writing or modifying files",
  },
  {
    key: "tool-call",
    label: "Tool call",
    icon: "Wrench",
    color: "text-indigo-600",
    description: "Using external tools or MCP servers",
  },
  {
    key: "other",
    label: "Other",
    icon: "CircleDot",
    color: "text-slate-500",
    description: "Other actions",
  },
];

const SECRET_PATTERNS = [
  /\.env/i,
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
