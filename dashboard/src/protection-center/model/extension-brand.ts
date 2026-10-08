export type ExtensionBrandSlug =
  | "git"
  | "github"
  | "github-actions"
  | "gitlab"
  | "circleci"
  | "aws"
  | "gcp"
  | "azure"
  | "postgresql"
  | "mysql"
  | "mongodb"
  | "redis"
  | "sqlite"
  | "supabase"
  | "vercel"
  | "netlify"
  | "heroku"
  | "minio"
  | "elasticsearch"
  | "kafka"
  | "rabbitmq"
  | "nats"
  | "docker"
  | "kubernetes"
  | "helm"
  | "launchdarkly"
  | "stripe"
  | "npm"
  | "node"
  | "python"
  | "rust"
  | "go"
  | "ruby"
  | "php"
  | "composer"
  | "maven"
  | "gradle"
  | "homebrew"
  | "debian"
  | "terraform"
  | "opentofu"
  | "pulumi"
  | "windows"
  | "rclone"
  | "restic"
  | "borg"
  | "velero"
  | "openssh";

export type ExtensionBrandFallback =
  | "shield"
  | "folder"
  | "terminal"
  | "server"
  | "cloud"
  | "lock"
  | "cube"
  | "globe"
  | "bolt";

export type ExtensionBrandSpec = {
  slug: ExtensionBrandSlug;
  label: string;
  color: string;
};

export type ExtensionBrandResolution =
  | { kind: "guard"; marks: []; fallback: "shield" }
  | { kind: "marks"; marks: ExtensionBrandSpec[]; fallback: ExtensionBrandFallback }
  | { kind: "fallback"; marks: []; fallback: ExtensionBrandFallback };

export type ExtensionBrandInput = {
  extension_id: string;
  name?: string;
  executables?: readonly string[];
  ecosystem_ids?: readonly string[];
};

export const EXTENSION_BRANDS: Record<ExtensionBrandSlug, ExtensionBrandSpec> = {
  git: { slug: "git", label: "Git", color: "F05032" },
  github: { slug: "github", label: "GitHub", color: "181717" },
  "github-actions": { slug: "github-actions", label: "GitHub Actions", color: "2088FF" },
  gitlab: { slug: "gitlab", label: "GitLab", color: "FC6D26" },
  circleci: { slug: "circleci", label: "CircleCI", color: "343434" },
  aws: { slug: "aws", label: "AWS", color: "FF9900" },
  gcp: { slug: "gcp", label: "Google Cloud", color: "4285F4" },
  azure: { slug: "azure", label: "Azure", color: "0078D4" },
  postgresql: { slug: "postgresql", label: "PostgreSQL", color: "4169E1" },
  mysql: { slug: "mysql", label: "MySQL", color: "4479A1" },
  mongodb: { slug: "mongodb", label: "MongoDB", color: "47A248" },
  redis: { slug: "redis", label: "Redis", color: "FF4438" },
  sqlite: { slug: "sqlite", label: "SQLite", color: "003B57" },
  supabase: { slug: "supabase", label: "Supabase", color: "3FCF8E" },
  vercel: { slug: "vercel", label: "Vercel", color: "000000" },
  netlify: { slug: "netlify", label: "Netlify", color: "00C7B7" },
  heroku: { slug: "heroku", label: "Heroku", color: "430098" },
  minio: { slug: "minio", label: "MinIO", color: "C72E49" },
  elasticsearch: { slug: "elasticsearch", label: "Elasticsearch", color: "005571" },
  kafka: { slug: "kafka", label: "Apache Kafka", color: "231F20" },
  rabbitmq: { slug: "rabbitmq", label: "RabbitMQ", color: "FF6600" },
  nats: { slug: "nats", label: "NATS", color: "27AAE1" },
  docker: { slug: "docker", label: "Docker", color: "2496ED" },
  kubernetes: { slug: "kubernetes", label: "Kubernetes", color: "326CE5" },
  helm: { slug: "helm", label: "Helm", color: "0F1689" },
  launchdarkly: { slug: "launchdarkly", label: "LaunchDarkly", color: "A34FDE" },
  stripe: { slug: "stripe", label: "Stripe", color: "635BFF" },
  npm: { slug: "npm", label: "npm", color: "CB3837" },
  node: { slug: "node", label: "Node.js", color: "5FA04E" },
  python: { slug: "python", label: "Python", color: "3776AB" },
  rust: { slug: "rust", label: "Rust", color: "000000" },
  go: { slug: "go", label: "Go", color: "00ADD8" },
  ruby: { slug: "ruby", label: "Ruby", color: "CC342D" },
  php: { slug: "php", label: "PHP", color: "777BB4" },
  composer: { slug: "composer", label: "Composer", color: "885630" },
  maven: { slug: "maven", label: "Maven", color: "C71A36" },
  gradle: { slug: "gradle", label: "Gradle", color: "02303A" },
  homebrew: { slug: "homebrew", label: "Homebrew", color: "FBB040" },
  debian: { slug: "debian", label: "Debian", color: "A81D33" },
  terraform: { slug: "terraform", label: "Terraform", color: "844FBA" },
  opentofu: { slug: "opentofu", label: "OpenTofu", color: "FFDA18" },
  pulumi: { slug: "pulumi", label: "Pulumi", color: "8A3391" },
  windows: { slug: "windows", label: "Windows", color: "0078D4" },
  rclone: { slug: "rclone", label: "Rclone", color: "3F79AD" },
  restic: { slug: "restic", label: "Restic", color: "2EA043" },
  borg: { slug: "borg", label: "Borg", color: "00B000" },
  velero: { slug: "velero", label: "Velero", color: "326CE5" },
  openssh: { slug: "openssh", label: "OpenSSH", color: "F2CA30" },
};

const CLOUD_CLUSTER: ExtensionBrandSlug[] = ["aws", "gcp", "azure"];

const BY_EXTENSION_ID: Record<string, ExtensionBrandSlug[]> = {
  "command.git": ["git"],
  "command.github": ["github"],
  "command.filesystem": [],
  "command.system": [],
  "command.windows": ["windows"],
  "command.container-runtime": ["docker"],
  "command.data-protection": [],
  "command.encoded-execution": [],
  "command.guard-self-protection": [],
  "command.kubernetes-secrets": ["kubernetes"],
  "command.shell-mutations": [],
  "command.package.node": ["node", "npm"],
  "command.package.python": ["python"],
  "command.package.rust": ["rust"],
  "command.package.go": ["go"],
  "command.package.jvm": ["maven", "gradle"],
  "command.package.ruby": ["ruby"],
  "command.package.php": ["php", "composer"],
  "command.package.system": ["homebrew", "debian"],
  "command.cloud.aws": ["aws"],
  "command.cloud.gcp": ["gcp"],
  "command.cloud.azure": ["azure"],
  "command.database.postgresql": ["postgresql"],
  "command.database.mysql": ["mysql"],
  "command.database.mongodb": ["mongodb"],
  "command.database.redis": ["redis"],
  "command.database.sqlite": ["sqlite"],
  "command.database.supabase": ["supabase"],
  "command.storage.aws-s3": ["aws"],
  "command.storage.google-cloud": ["gcp"],
  "command.storage.azure-blob": ["azure"],
  "command.storage.minio": ["minio"],
  "command.backup.rclone": ["rclone"],
  "command.backup.restic": ["restic"],
  "command.backup.borg": ["borg"],
  "command.backup.velero": ["velero"],
  "command.remote.ssh": [],
  "command.remote.scp": [],
  "command.remote.rsync": [],
  "command.cicd.github": ["github-actions"],
  "command.cicd.gitlab": ["gitlab"],
  "command.cicd.circleci": ["circleci"],
  "command.platform.vercel": ["vercel"],
  "command.platform.netlify": ["netlify"],
  "command.platform.heroku": ["heroku"],
  "command.dns.aws": ["aws"],
  "command.dns.gcp": ["gcp"],
  "command.dns.azure": ["azure"],
  "command.cdn": CLOUD_CLUSTER,
  "command.api-gateway": CLOUD_CLUSTER,
  "command.load-balancer": CLOUD_CLUSTER,
  "command.monitoring": CLOUD_CLUSTER,
  "command.email": ["aws"],
  "command.feature-flags": ["launchdarkly"],
  "command.payment": ["stripe"],
  "command.search.elasticsearch": ["elasticsearch"],
  "command.messaging.kafka": ["kafka"],
  "command.messaging.rabbitmq": ["rabbitmq"],
  "command.messaging.nats": ["nats"],
  "command.kubernetes-operations": ["kubernetes", "helm"],
  "command.infrastructure-as-code": ["terraform", "opentofu", "pulumi"],
};

export const CATALOG_EXTENSION_IDS = Object.freeze(Object.keys(BY_EXTENSION_ID));

const INFERENCE: ReadonlyArray<{ slug: ExtensionBrandSlug; pattern: RegExp }> = [
  { slug: "github-actions", pattern: /\bgithub actions\b/ },
  { slug: "github", pattern: /\bgithub\b/ },
  { slug: "gitlab", pattern: /\bgitlab\b/ },
  { slug: "circleci", pattern: /\bcircleci\b/ },
  { slug: "git", pattern: /\bgit\b/ },
  { slug: "aws", pattern: /\b(?:aws|amazon|s3)\b/ },
  { slug: "gcp", pattern: /\b(?:gcp|gcloud|google cloud)\b/ },
  { slug: "azure", pattern: /\bazure\b/ },
  { slug: "postgresql", pattern: /\b(?:postgres|postgresql|psql)\b/ },
  { slug: "mysql", pattern: /\bmysql\b/ },
  { slug: "mongodb", pattern: /\b(?:mongo|mongodb)\b/ },
  { slug: "redis", pattern: /\bredis\b/ },
  { slug: "sqlite", pattern: /\bsqlite\b/ },
  { slug: "supabase", pattern: /\bsupabase\b/ },
  { slug: "vercel", pattern: /\bvercel\b/ },
  { slug: "netlify", pattern: /\bnetlify\b/ },
  { slug: "heroku", pattern: /\bheroku\b/ },
  { slug: "minio", pattern: /\bminio\b/ },
  { slug: "elasticsearch", pattern: /\b(?:elastic|elasticsearch)\b/ },
  { slug: "kafka", pattern: /\bkafka\b/ },
  { slug: "rabbitmq", pattern: /\brabbit(?:mq)?\b/ },
  { slug: "nats", pattern: /\bnats\b/ },
  { slug: "docker", pattern: /\b(?:docker|podman|container)\b/ },
  { slug: "kubernetes", pattern: /\b(?:kubernetes|kubectl|k8s)\b/ },
  { slug: "helm", pattern: /\bhelm\b/ },
  { slug: "launchdarkly", pattern: /\b(?:launchdarkly|feature.?flag)\b/ },
  { slug: "stripe", pattern: /\bstripe\b/ },
  { slug: "npm", pattern: /\bnpm\b/ },
  { slug: "node", pattern: /\b(?:node|nodejs|nodedotjs)\b/ },
  { slug: "python", pattern: /\b(?:python|pip|poetry)\b/ },
  { slug: "rust", pattern: /\b(?:rust|cargo)\b/ },
  { slug: "go", pattern: /\bgolang\b|\bgo\b/ },
  { slug: "ruby", pattern: /\b(?:ruby|gem|bundler)\b/ },
  { slug: "php", pattern: /\bphp\b/ },
  { slug: "composer", pattern: /\bcomposer\b/ },
  { slug: "maven", pattern: /\b(?:maven|mvn)\b/ },
  { slug: "gradle", pattern: /\bgradle\b/ },
  { slug: "homebrew", pattern: /\b(?:homebrew|brew)\b/ },
  { slug: "debian", pattern: /\b(?:debian|apt)\b/ },
  { slug: "terraform", pattern: /\bterraform\b/ },
  { slug: "opentofu", pattern: /\b(?:opentofu|tofu)\b/ },
  { slug: "pulumi", pattern: /\bpulumi\b/ },
  { slug: "windows", pattern: /\bwindows\b/ },
  { slug: "rclone", pattern: /\brclone\b/ },
  { slug: "restic", pattern: /\brestic\b/ },
  { slug: "borg", pattern: /\bborg\b/ },
  { slug: "velero", pattern: /\bvelero\b/ },
  { slug: "openssh", pattern: /\b(?:ssh|scp|openssh)\b/ },
];

function searchableText(input: ExtensionBrandInput): string {
  return [
    input.extension_id,
    input.name ?? "",
    ...(input.executables ?? []),
    ...(input.ecosystem_ids ?? []),
  ]
    .join(" ")
    .replace(/[._/-]+/g, " ")
    .toLowerCase();
}

function uniqueSlugs(slugs: readonly ExtensionBrandSlug[]): ExtensionBrandSlug[] {
  const seen = new Set<ExtensionBrandSlug>();
  const ordered: ExtensionBrandSlug[] = [];
  for (const slug of slugs) {
    if (seen.has(slug)) continue;
    seen.add(slug);
    ordered.push(slug);
  }
  return ordered.slice(0, 3);
}

function inferSlugs(input: ExtensionBrandInput): ExtensionBrandSlug[] {
  const text = searchableText(input);
  const found: ExtensionBrandSlug[] = [];
  for (const entry of INFERENCE) {
    if (entry.pattern.test(text)) found.push(entry.slug);
  }
  return uniqueSlugs(found);
}

export function fallbackForExtensionId(extensionId: string): ExtensionBrandFallback {
  if (extensionId === "command.guard-self-protection") return "shield";
  if (extensionId.includes("secret") || extensionId.includes("data-protection")) return "lock";
  if (extensionId.includes("package")) return "cube";
  if (extensionId.includes("cloud") || extensionId.includes("platform")) return "cloud";
  if (extensionId.includes("database") || extensionId.includes("storage") || extensionId.includes("backup")) return "server";
  if (extensionId.includes("remote") || extensionId.includes("network")) return "globe";
  if (extensionId.includes("filesystem")) return "folder";
  if (extensionId.includes("shell") || extensionId.includes("system") || extensionId.includes("encoded") || extensionId.includes("rsync")) return "terminal";
  if (extensionId.includes("payment") || extensionId.includes("feature")) return "bolt";
  return "shield";
}

export function isNearBlackBrand(color: string): boolean {
  const hex = color.toLowerCase();
  return hex === "000000" || hex === "181717" || hex === "231f20" || hex === "343434";
}

export function resolveExtensionBrand(input: ExtensionBrandInput): ExtensionBrandResolution {
  const fallback = fallbackForExtensionId(input.extension_id);
  if (input.extension_id === "command.guard-self-protection") {
    return { kind: "guard", marks: [], fallback: "shield" };
  }
  const mapped = BY_EXTENSION_ID[input.extension_id];
  const slugs = uniqueSlugs(mapped ?? inferSlugs(input));
  if (slugs.length === 0) {
    return { kind: "fallback", marks: [], fallback };
  }
  return {
    kind: "marks",
    marks: slugs.map((slug) => EXTENSION_BRANDS[slug]),
    fallback,
  };
}

export function extensionBrandTestId(resolution: ExtensionBrandResolution): string {
  if (resolution.kind === "guard") return "guard";
  if (resolution.kind === "marks") return resolution.marks.map((mark) => mark.slug).join(" ");
  return `fallback-${resolution.fallback}`;
}
