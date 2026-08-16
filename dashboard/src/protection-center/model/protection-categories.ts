import type { ExtensionCatalogItem } from "../../extension-controls-api";

export type ProtectionCategoryId =
  | "source-control"
  | "packages"
  | "files-secrets"
  | "cloud-infrastructure"
  | "network-downloads"
  | "data-databases"
  | "deployments-ci"
  | "messaging-collaboration"
  | "system-shell"
  | "ai-workflows";

export type ProtectionCategory = {
  id: ProtectionCategoryId;
  label: string;
  description: string;
  searchAliases: readonly string[];
};

export const PROTECTION_CATEGORIES: readonly ProtectionCategory[] = [
  { id: "source-control", label: "Source control", description: "Protect repository history, branches, and source-control operations.", searchAliases: ["git", "github", "repository", "source"] },
  { id: "packages", label: "Packages and dependencies", description: "Protect dependency installs, package managers, and supply-chain changes.", searchAliases: ["npm", "pnpm", "yarn", "pip", "package", "dependency"] },
  { id: "files-secrets", label: "Files and secrets", description: "Protect sensitive files, credentials, and secret-bearing operations.", searchAliases: ["file", "secret", "credential", "environment"] },
  { id: "cloud-infrastructure", label: "Cloud and infrastructure", description: "Protect infrastructure, cloud resources, and administrative actions.", searchAliases: ["aws", "gcp", "azure", "terraform", "cloud", "infrastructure"] },
  { id: "network-downloads", label: "Network and downloads", description: "Protect downloads, remote access, and network-facing operations.", searchAliases: ["curl", "wget", "ssh", "network", "download", "remote"] },
  { id: "data-databases", label: "Data and databases", description: "Protect databases, storage, backups, and destructive data operations.", searchAliases: ["database", "sql", "postgres", "mysql", "redis", "data", "backup"] },
  { id: "deployments-ci", label: "Deployments and CI", description: "Protect deployment, build, release, and CI/CD operations.", searchAliases: ["deploy", "release", "ci", "cd", "workflow", "pipeline"] },
  { id: "messaging-collaboration", label: "Messaging and collaboration", description: "Protect actions in messaging, search, and collaboration tools.", searchAliases: ["slack", "message", "collaboration", "search"] },
  { id: "system-shell", label: "System and shell actions", description: "Protect high-impact local shell, process, and system operations.", searchAliases: ["shell", "system", "bash", "terminal", "process"] },
  { id: "ai-workflows", label: "AI tools and agent workflows", description: "Protect AI-agent, tool, and automated workflow actions.", searchAliases: ["ai", "agent", "mcp", "tool", "workflow"] },
] as const;

const CATEGORY_BY_ID = new Map(PROTECTION_CATEGORIES.map((category) => [category.id, category]));

function searchableExtensionText(extension: ExtensionCatalogItem): string {
  return [
    extension.extension_id,
    extension.name,
    extension.description,
    ...extension.ecosystem_ids,
    ...extension.executables,
    ...extension.action_classes,
    ...extension.risk_classes,
  ].join(" ").toLowerCase();
}

export function protectionCategoryIdForExtension(extension: ExtensionCatalogItem): ProtectionCategoryId {
  const text = searchableExtensionText(extension);
  if (/\bgit\b|github|source.?control|repository|branch|commit/.test(text)) return "source-control";
  if (/package|dependency|npm|pnpm|yarn|pip|poetry|cargo|composer|gem|supply.?chain/.test(text)) return "packages";
  if (/secret|credential|\.env|filesystem|sensitive.?file|keychain/.test(text)) return "files-secrets";
  if (/aws|azure|gcp|cloud|terraform|kubectl|kubernetes|infrastructure|platform/.test(text)) return "cloud-infrastructure";
  if (/network|egress|download|curl|wget|ssh|remote|http|ftp/.test(text)) return "network-downloads";
  if (/database|sql|postgres|mysql|sqlite|redis|mongo|storage|backup|data/.test(text)) return "data-databases";
  if (/deploy|release|ci.?cd|pipeline|workflow|build|artifact/.test(text)) return "deployments-ci";
  if (/slack|discord|message|collaboration|search|email/.test(text)) return "messaging-collaboration";
  if (/agent|\bmcp\b|assistant|model|prompt|ai.?tool/.test(text)) return "ai-workflows";
  return "system-shell";
}

export function protectionCategoryForExtension(extension: ExtensionCatalogItem): ProtectionCategory {
  const id = protectionCategoryIdForExtension(extension);
  return CATEGORY_BY_ID.get(id) ?? PROTECTION_CATEGORIES[8]!;
}

export function groupProtectionModules(extensions: readonly ExtensionCatalogItem[]): Map<ProtectionCategoryId, ExtensionCatalogItem[]> {
  const groups = new Map<ProtectionCategoryId, ExtensionCatalogItem[]>();
  for (const extension of extensions) {
    const id = protectionCategoryIdForExtension(extension);
    const existing = groups.get(id) ?? [];
    existing.push(extension);
    groups.set(id, existing);
  }
  for (const items of groups.values()) items.sort((left, right) => left.name.localeCompare(right.name));
  return groups;
}
