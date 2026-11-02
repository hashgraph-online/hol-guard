import type { ReactNode } from "react";
import { HiMiniArrowUpCircle, HiMiniCheckCircle, HiMiniPauseCircle, HiMiniSparkles } from "react-icons/hi2";
import { Tag } from "../approval-center-primitives";
import type { ContextAssistanceStatus } from "./types";
import { cigarBuildBlock } from "./versions-actions";
import type { CigarCatalogBuild } from "./versions-catalog";
import type { CigarVersionsData } from "./versions-data";
import { platformLabel } from "./versions-view";

type Standing =
  | { kind: "none"; installed: number }
  | { kind: "current" | "behind"; version: string; running: boolean; newest: string | null; block: string | null };

/** Numeric release order; pre-release tags sort before their release. */
export function compareCigarVersions(a: string, b: string): number {
  const parse = (v: string) => { const [core, pre = ""] = v.replace(/^v/, "").split("-", 2); return { parts: core.split(".").map((n) => Number.parseInt(n, 10) || 0), pre }; };
  const x = parse(a), y = parse(b);
  for (let i = 0; i < Math.max(x.parts.length, y.parts.length); i += 1) {
    const d = (x.parts[i] ?? 0) - (y.parts[i] ?? 0);
    if (d) return d;
  }
  if (x.pre === y.pre) return 0;
  if (!x.pre) return 1;
  if (!y.pre) return -1;
  return x.pre < y.pre ? -1 : 1;
}

/** Where this computer stands, answered before any list of builds. */
export function cigarStanding(status: ContextAssistanceStatus | null, data: CigarVersionsData | null): Standing {
  const selectedId = status?.preferences.runtime_id ?? "";
  const installed = data?.installations.find((item) => item.runtime_id === selectedId);
  const running = status?.runtime?.active === true && status.effective_enabled;
  const version = running ? status!.runtime!.package_version : installed?.sdk_version ?? (selectedId ? status?.last_check?.package_version : undefined);
  if (!version) return { kind: "none", installed: data?.installations.length ?? 0 };
  const host = data?.catalog.host_platform;
  let newest: CigarCatalogBuild | null = null;
  for (const build of data?.catalog.builds ?? []) {
    if (build.withdrawn || build.channel !== "stable" || !build.platforms.some((platform) => platform.platform === host)) continue;
    if (!newest || compareCigarVersions(build.identity.sdk_version, newest.identity.sdk_version) > 0) newest = build;
  }
  const behind = newest !== null && compareCigarVersions(newest.identity.sdk_version, version) > 0;
  const block = behind && data ? cigarBuildBlock(data.catalog, newest!, data.updates) : null;
  return { kind: behind ? "behind" : "current", version, running, newest: newest?.identity.sdk_version ?? null, block };
}

const markers = {
  behind: [HiMiniArrowUpCircle, "bg-brand-blue/10 text-brand-blue"],
  none: [HiMiniSparkles, "bg-brand-dark/[0.06] text-brand-dark/55"],
  running: [HiMiniCheckCircle, "bg-brand-green-bg text-brand-green-text"],
  off: [HiMiniPauseCircle, "bg-brand-dark/[0.06] text-brand-dark/55"],
} as const;

function markerKey(standing: Standing): keyof typeof markers {
  if (standing.kind !== "current") return standing.kind;
  return standing.running ? "running" : "off";
}

function Marker({ standing }: { standing: Standing }) {
  const [Icon, tone] = markers[markerKey(standing)];
  return <span className={"flex size-10 shrink-0 items-center justify-center rounded-full " + tone} aria-hidden="true"><Icon className="size-5" /></span>;
}

function standingBody(standing: Standing): string {
  if (standing.kind === "none") {
    return standing.installed
      ? "A version is installed but none is selected. Pick one under Versions below, or turn on CIGAR and Guard picks for you."
      : "Nothing is installed yet. Turn on CIGAR and Guard installs the version it approved for this computer. You don't need to pick one here.";
  }
  if (standing.kind === "behind") {
    return standing.block
      ? `CIGAR ${standing.newest} is listed, but it can't be prepared yet: ${standing.block} Your current version keeps working.`
      : `CIGAR ${standing.newest} is ready to prepare. Your current version keeps working until you choose to switch.`;
  }
  return standing.running
    ? "This is the newest version Guard has approved for this computer. Nothing to do."
    : "This version is installed but CIGAR is off. Turn it on from the top of the page whenever you like.";
}

function standingTitle(standing: Standing, loading: boolean): string {
  if (standing.kind !== "none") return standing.version;
  if (loading) return "Checking this computer…";
  return standing.installed ? "Installed, not selected" : "Not installed yet";
}

type Props = { status: ContextAssistanceStatus | null; data: CigarVersionsData | null; loading: boolean; actions: ReactNode };

export function CigarVersionStatusBand({ status, data, loading, actions }: Props) {
  const standing = cigarStanding(status, data);
  const surface = standing.kind === "behind" ? "border-brand-blue/20 bg-brand-blue/[0.04]" : "border-brand-dark/10 bg-white";
  const body = standingBody(standing);
  const python = status?.runtime?.interpreter.version ?? status?.last_check?.interpreter.version;
  const catalog = data?.catalog.catalog;
  return <section aria-labelledby="cigar-version-standing" className={"guard-surface-in rounded-2xl border p-4 sm:p-5 " + surface}>
    <div className="flex flex-wrap items-start gap-x-6 gap-y-4">
      <div className="flex min-w-0 flex-[1_1_20rem] items-start gap-3.5">
        <Marker standing={standing} />
        <div className="min-w-0 space-y-2">
          <h3 id="cigar-version-standing" className="flex flex-wrap items-center gap-x-3 gap-y-2">
            <span className={standing.kind === "none"
              ? "text-xl font-semibold leading-tight tracking-[-0.01em] text-brand-dark"
              : "font-mono text-[1.75rem] font-semibold leading-none tracking-[-0.02em] tabular-nums text-brand-dark"}>
              {standingTitle(standing, loading)}
            </span>
            {standing.kind !== "none" ? <Tag tone={standing.running ? "green" : "slate"}>{standing.running ? "Running" : "Off"}</Tag> : null}
            {standing.kind === "behind" ? <Tag tone="blue">Update available</Tag> : null}
          </h3>
          <p className="max-w-[62ch] text-sm leading-6 text-brand-dark/75">{body}</p>
          <ul className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-brand-dark/60" aria-label="This computer">
            <li>{platformLabel(data?.catalog.host_platform ?? status?.runtime?.interpreter.platform)}</li>
            {python ? <li>Python {python.join(".")}</li> : null}
            {catalog ? <li>{catalog.fresh_for_preparation ? "Version list is current" : "Version list needs a refresh"}</li> : null}
          </ul>
        </div>
      </div>
      <div className="flex shrink-0 flex-wrap items-center gap-2">{actions}</div>
    </div>
  </section>;
}
