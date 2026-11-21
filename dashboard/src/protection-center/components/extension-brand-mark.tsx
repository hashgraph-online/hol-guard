import type { CSSProperties, ReactElement, ReactNode } from "react";
import type { IconType } from "react-icons";
import { FaAws, FaWindows } from "react-icons/fa";
import {
  HiMiniBolt,
  HiMiniCloud,
  HiMiniCommandLine,
  HiMiniCube,
  HiMiniFolder,
  HiMiniGlobeAlt,
  HiMiniLockClosed,
  HiMiniServerStack,
  HiMiniShieldCheck,
} from "react-icons/hi2";
import {
  SiApachekafka,
  SiApachemaven,
  SiBorgbackup,
  SiCircleci,
  SiCloudflare,
  SiComposer,
  SiDebian,
  SiDocker,
  SiElasticsearch,
  SiGit,
  SiGithub,
  SiGithubactions,
  SiGitlab,
  SiGo,
  SiGooglecloud,
  SiGradle,
  SiHelm,
  SiHeroku,
  SiHomebrew,
  SiKubernetes,
  SiMinio,
  SiMongodb,
  SiMysql,
  SiNatsdotio,
  SiNetlify,
  SiNodedotjs,
  SiNpm,
  SiOpenbsd,
  SiOpentofu,
  SiPhp,
  SiPostgresql,
  SiPulumi,
  SiPython,
  SiRabbitmq,
  SiRclone,
  SiRedis,
  SiRuby,
  SiRust,
  SiSqlite,
  SiStripe,
  SiSupabase,
  SiTerraform,
  SiVercel,
} from "react-icons/si";
import { VscAzure } from "react-icons/vsc";

import {
  extensionBrandTestId,
  isNearBlackBrand,
  resolveExtensionBrand,
  type ExtensionBrandFallback,
  type ExtensionBrandInput,
  type ExtensionBrandSlug,
} from "../model/extension-brand";

type MarkIcon = IconType | ((props: { className?: string }) => ReactElement);

function OriginalMark(props: { className?: string; children: ReactNode }) {
  return (
    <svg viewBox="0 0 24 24" className={props.className} aria-hidden="true" focusable="false">
      {props.children}
    </svg>
  );
}

function LaunchDarklyMark({ className }: { className?: string }) {
  return (
    <OriginalMark className={className}>
      <rect x="2.5" y="8" width="19" height="8" rx="4" />
      <circle cx="15.5" cy="12" r="2.6" fill="#fff" />
    </OriginalMark>
  );
}

function ResticMark({ className }: { className?: string }) {
  return (
    <OriginalMark className={className}>
      <ellipse cx="12" cy="6.5" rx="8" ry="2.6" />
      <path d="M4 6.5v11c0 1.5 3.6 2.6 8 2.6s8-1.1 8-2.6v-11" fill="none" stroke="currentColor" strokeWidth="2" />
      <ellipse cx="12" cy="12" rx="8" ry="2.6" fill="none" stroke="currentColor" strokeWidth="2" />
    </OriginalMark>
  );
}

function VeleroMark({ className }: { className?: string }) {
  return (
    <OriginalMark className={className}>
      <path d="M5 20V4l14 9.5H9.5z" />
    </OriginalMark>
  );
}

const BRAND_ICONS: Record<ExtensionBrandSlug, MarkIcon> = {
  git: SiGit,
  github: SiGithub,
  "github-actions": SiGithubactions,
  gitlab: SiGitlab,
  circleci: SiCircleci,
  aws: FaAws,
  gcp: SiGooglecloud,
  azure: VscAzure,
  postgresql: SiPostgresql,
  mysql: SiMysql,
  mongodb: SiMongodb,
  redis: SiRedis,
  sqlite: SiSqlite,
  supabase: SiSupabase,
  vercel: SiVercel,
  netlify: SiNetlify,
  heroku: SiHeroku,
  minio: SiMinio,
  elasticsearch: SiElasticsearch,
  kafka: SiApachekafka,
  rabbitmq: SiRabbitmq,
  nats: SiNatsdotio,
  docker: SiDocker,
  kubernetes: SiKubernetes,
  helm: SiHelm,
  launchdarkly: LaunchDarklyMark,
  stripe: SiStripe,
  npm: SiNpm,
  node: SiNodedotjs,
  python: SiPython,
  rust: SiRust,
  go: SiGo,
  ruby: SiRuby,
  php: SiPhp,
  composer: SiComposer,
  maven: SiApachemaven,
  gradle: SiGradle,
  homebrew: SiHomebrew,
  debian: SiDebian,
  terraform: SiTerraform,
  opentofu: SiOpentofu,
  pulumi: SiPulumi,
  windows: FaWindows,
  rclone: SiRclone,
  restic: ResticMark,
  borg: SiBorgbackup,
  velero: VeleroMark,
  openssh: SiOpenbsd,
  cloudflare: SiCloudflare,
};

const FALLBACK_ICONS: Record<ExtensionBrandFallback, MarkIcon> = {
  shield: HiMiniShieldCheck,
  folder: HiMiniFolder,
  terminal: HiMiniCommandLine,
  server: HiMiniServerStack,
  cloud: HiMiniCloud,
  lock: HiMiniLockClosed,
  cube: HiMiniCube,
  globe: HiMiniGlobeAlt,
  bolt: HiMiniBolt,
};

export type ExtensionBrandMarkSize = "sm" | "md" | "lg";

function tileStyle(color: string): CSSProperties {
  const hex = isNearBlackBrand(color) ? "3f4174" : color;
  return { ["--extension-brand" as string]: `#${hex}` };
}

function MarkTile(props: {
  color: string;
  label: string;
  size: ExtensionBrandMarkSize;
  stacked?: boolean;
  children: React.ReactNode;
}) {
  return (
    <span
      className="guard-extension-mark"
      data-size={props.size}
      data-stacked={props.stacked ? "true" : undefined}
      style={tileStyle(props.color)}
      title={props.label}
      aria-hidden="true"
    >
      {props.children}
    </span>
  );
}

export function ExtensionBrandMark(props: ExtensionBrandInput & { size?: ExtensionBrandMarkSize }) {
  const size = props.size ?? "md";
  const resolution = resolveExtensionBrand(props);
  const testId = extensionBrandTestId(resolution);

  if (resolution.kind === "guard") {
    return (
      <span className="guard-extension-mark" data-size={size} data-extension-brand={testId} data-kind="guard" aria-hidden="true">
        <img src="/brand/Logo_Icon_Dark.png" alt="" />
      </span>
    );
  }

  if (resolution.kind === "fallback") {
    const FallbackIcon = FALLBACK_ICONS[resolution.fallback];
    return (
      <span className="guard-extension-mark" data-size={size} data-extension-brand={testId} data-kind="fallback" style={tileStyle("5599fe")} aria-hidden="true">
        <FallbackIcon />
      </span>
    );
  }

  if (resolution.marks.length === 1) {
    const mark = resolution.marks[0]!;
    const Icon = BRAND_ICONS[mark.slug];
    return (
      <span data-extension-brand={testId} data-kind="marks" aria-hidden="true">
        <MarkTile color={mark.color} label={mark.label} size={size}>
          <Icon />
        </MarkTile>
      </span>
    );
  }

  return (
    <span className="guard-extension-mark-cluster" data-extension-brand={testId} data-kind="marks" data-size={size} aria-hidden="true">
      {resolution.marks.map((mark) => {
        const Icon = BRAND_ICONS[mark.slug];
        return (
          <MarkTile key={mark.slug} color={mark.color} label={mark.label} size={size} stacked>
            <Icon />
          </MarkTile>
        );
      })}
    </span>
  );
}
