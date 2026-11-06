import {
  HiMiniArrowPath,
  HiMiniExclamationTriangle,
  HiMiniInformationCircle,
  HiMiniShieldExclamation,
} from "react-icons/hi2";
import type { SupplyChainPostureAlert } from "./supply-chain-posture";

type SupplyChainPostureBannersProps = {
  alerts: SupplyChainPostureAlert[];
};

function alertToneClass(tone: SupplyChainPostureAlert["tone"]): string {
  if (tone === "blue") {
    return "border-brand-blue/20 bg-brand-blue/[0.04]";
  }
  if (tone === "attention") {
    return "border-brand-attention/20 bg-brand-attention/[0.04]";
  }
  return "border-slate-200 bg-slate-50/80";
}

function alertIcon(alert: SupplyChainPostureAlert) {
  if (alert.kind === "partial_protection") {
    return HiMiniShieldExclamation;
  }
  if (alert.kind === "path_repair") {
    return alert.tone === "blue" ? HiMiniInformationCircle : HiMiniExclamationTriangle;
  }
  return HiMiniArrowPath;
}

function alertIconClass(tone: SupplyChainPostureAlert["tone"]): string {
  if (tone === "blue") {
    return "text-brand-blue";
  }
  if (tone === "attention") {
    return "text-brand-attention";
  }
  return "text-slate-500";
}

function PostureBanner({ alert }: { alert: SupplyChainPostureAlert }) {
  const Icon = alertIcon(alert);
  const textClass = "text-slate-600";
  const titleClass = "text-brand-dark";

  return (
    <div
      className={`rounded-2xl border px-4 py-3 ${alertToneClass(alert.tone)}`}
      role="status"
      data-testid={`supply-chain-posture-${alert.kind}`}
    >
      <div className="flex items-start gap-2.5">
        <Icon className={`mt-0.5 h-4 w-4 shrink-0 ${alertIconClass(alert.tone)}`} aria-hidden="true" />
        <div className="min-w-0 break-words">
          <p className={`text-sm font-medium ${titleClass}`}>{alert.title}</p>
          <p className={`mt-1 text-xs leading-relaxed ${textClass}`}>{alert.detail}</p>
        </div>
      </div>
    </div>
  );
}

export function SupplyChainPostureBanners({ alerts }: SupplyChainPostureBannersProps) {
  if (alerts.length === 0) {
    return null;
  }

  return (
    <section
      className="space-y-3"
      aria-label="Supply chain posture alerts"
      data-testid="supply-chain-posture-banners"
    >
      {alerts.map((alert) => (
        <PostureBanner key={alert.kind} alert={alert} />
      ))}
    </section>
  );
}
