import type { ReactNode } from "react";
import { HiMiniArrowUpCircle, HiMiniCheckCircle, HiMiniPauseCircle, HiMiniSparkles } from "react-icons/hi2";
import { Tag } from "../approval-center-primitives";
import type { ContextAssistanceStatus } from "./types";
import type { CigarVersionsData } from "./versions-data";
import { platformLabel } from "./versions-view";

type Standing =
  | { kind: "none" }
  | { kind: "current" | "behind"; version: string; running: boolean; newest: string | null };

/** Where this computer stands, answered before any list of builds. */
export function cigarStanding(status: ContextAssistanceStatus | null, data: CigarVersionsData | null): Standing {
  const selectedId = status?.preferences.runtime_id ?? "";
  const installed = data?.installations.find((item) => item.runtime_id === selectedId);
  const running = status?.runtime?.active === true && status.effective_enabled;
  const version = running ? status!.runtime!.package_version : installed?.sdk_version ?? (selectedId ? status?.last_check?.package_version : undefined);
  if (!version) return { kind: "none" };
  const host = data?.catalog.host_platform;
  const newest = data?.catalog.builds.find((build) => !build.withdrawn && build.channel === "stable"
    && build.platforms.some((platform) => platform.platform === host)) ?? null;
  const behind = newest !== null && newest.identity.sdk_version !== version
    && (installed?.build_id ?? null) !== newest.identity.build_id;
  return { kind: behind ? "behind" : "current", version, running, newest: newest?.identity.sdk_version ?? null };
}

function Marker({ standing }: { standing: Standing }) {
  const [Icon, tone] = standing.kind === "behind" ? [HiMiniArrowUpCircle, "bg-brand-blue/10 text-brand-blue"]
    : standing.kind === "none" ? [HiMiniSparkles, "bg-brand-dark/[0.06] text-brand-dark/55"]
    : standing.running ? [HiMiniCheckCircle, "bg-brand-green-bg text-brand-green-text"]
    : [HiMiniPauseCircle, "bg-brand-dark/[0.06] text-brand-dark/55"];
  return <span className={"flex size-10 shrink-0 items-center justify-center rounded-full " + tone} aria-hidden="true"><Icon className="size-5" /></span>;
}

type Props = { status: ContextAssistanceStatus | null; data: CigarVersionsData | null; loading: boolean; actions: ReactNode };

export function CigarVersionStatusBand({ status, data, loading, actions }: Props) {
  const standing = cigarStanding(status, data);
  const surface = standing.kind === "behind" ? "border-brand-blue/20 bg-brand-blue/[0.04]" : "border-brand-dark/10 bg-white";
  const body = standing.kind === "none"
    ? "Nothing is installed yet. Turn on CIGAR and Guard installs the version it approved for this computer. You don't need to pick one here."
    : standing.kind === "behind"
    ? `CIGAR ${standing.newest} is ready to prepare. Your current version keeps working until you choose to switch.`
    : standing.running
    ? "This is the newest version Guard has approved for this computer. Nothing to do."
    : "This version is installed but CIGAR is off. Turn it on from the top of the page whenever you like.";
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
              {standing.kind === "none" ? (loading ? "Checking this computer…" : "Not installed yet") : standing.version}
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
