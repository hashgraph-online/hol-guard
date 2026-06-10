import {
  HiMiniBeaker,
  HiMiniCheckCircle,
  HiMiniClock,
  HiMiniExclamationTriangle,
  HiMiniMagnifyingGlass,
} from "react-icons/hi2";
import { formatRelativeTime } from "./approval-center-utils";
import { Tag } from "./approval-center-primitives";
import type { PackageShimEntry } from "./guard-types";
import { resolveShimStatus } from "./supply-chain-firewall-manager-row";

type SupplyChainManagerCardsProps = {
  managers: string[];
  shims: PackageShimEntry[];
};

type ManagerCardProps = {
  manager: string;
  shim: PackageShimEntry | undefined;
};

function testedLabel(shim: PackageShimEntry | undefined): { label: string; tone: "green" | "slate" | "attention" } {
  if (shim === undefined || !shim.installed) {
    return { label: "Not protected yet", tone: "attention" };
  }
  if (shim.last_intercept_proof_at !== null) {
    return {
      label: `Tested ${formatRelativeTime(shim.last_intercept_proof_at)}`,
      tone: "green",
    };
  }
  if (shim.tested) {
    return { label: "Test recorded", tone: "green" };
  }
  return { label: "Not tested yet", tone: "slate" };
}

function ManagerCard({ manager, shim }: ManagerCardProps) {
  const status = resolveShimStatus(shim);
  const tested = testedLabel(shim);

  return (
    <article
      className="min-w-0 rounded-xl border border-slate-100 bg-white p-4 shadow-sm"
      data-testid={`supply-chain-manager-card-${manager}`}
    >
      <div className="flex items-start justify-between gap-2">
        <p className="truncate font-mono text-sm font-semibold text-brand-dark">{manager}</p>
        <Tag tone={status.tone}>{status.label}</Tag>
      </div>
      <dl className="mt-3 space-y-2 text-xs text-slate-600">
        <div className="flex items-center gap-2">
          <dt className="sr-only">Detected</dt>
          <HiMiniMagnifyingGlass className="h-3.5 w-3.5 shrink-0 text-slate-400" aria-hidden="true" />
          <dd>{shim?.detected ? "Detected on this device" : "Not detected on PATH"}</dd>
        </div>
        <div className="flex items-center gap-2">
          <dt className="sr-only">Protected</dt>
          {status.tone === "green" ? (
            <HiMiniCheckCircle className="h-3.5 w-3.5 shrink-0 text-brand-green" aria-hidden="true" />
          ) : (
            <HiMiniExclamationTriangle className="h-3.5 w-3.5 shrink-0 text-brand-attention" aria-hidden="true" />
          )}
          <dd>
            {shim?.installed
              ? status.label
              : "Install protection to block risky package commands"}
          </dd>
        </div>
        <div className="flex items-center gap-2">
          <dt className="sr-only">Tested</dt>
          {tested.tone === "green" ? (
            <HiMiniBeaker className="h-3.5 w-3.5 shrink-0 text-brand-green" aria-hidden="true" />
          ) : (
            <HiMiniClock className="h-3.5 w-3.5 shrink-0 text-slate-400" aria-hidden="true" />
          )}
          <dd className={tested.tone === "attention" ? "text-brand-attention" : undefined}>{tested.label}</dd>
        </div>
      </dl>
    </article>
  );
}

export function SupplyChainManagerCards({ managers, shims }: SupplyChainManagerCardsProps) {
  if (managers.length === 0) {
    return null;
  }

  return (
    <section
      className="space-y-3"
      aria-label="Package tool status cards"
      data-testid="supply-chain-manager-cards"
    >
      <div>
        <h3 className="text-sm font-semibold text-brand-dark">Package tools on this device</h3>
        <p className="mt-0.5 text-xs leading-relaxed text-slate-500">
          Detected, protected, and tested status for each manager Guard can watch.
        </p>
      </div>
      <div className="grid min-w-0 gap-3 sm:grid-cols-2 xl:grid-cols-3">
        {managers.map((manager) => {
          const shim = shims.find((entry) => entry.manager === manager);
          return <ManagerCard key={manager} manager={manager} shim={shim} />;
        })}
      </div>
    </section>
  );
}
