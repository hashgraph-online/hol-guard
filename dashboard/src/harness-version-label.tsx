import {
  HiMiniCheckBadge,
  HiMiniExclamationTriangle,
  HiMiniMinusCircle,
  HiMiniQuestionMarkCircle,
} from "react-icons/hi2";

import {
  versionCheckUnsupported,
  versionRowLabel,
  type HarnessVersionCompatibility,
} from "./harness-version-compatibility";

function toneFor(compatibility: HarnessVersionCompatibility): { className: string; Icon: typeof HiMiniCheckBadge } {
  if (compatibility.state === "tested") return { className: "text-emerald-600", Icon: HiMiniCheckBadge };
  if (compatibility.state === "untested") {
    return compatibility.acknowledgement.acknowledged
      ? { className: "text-slate-500", Icon: HiMiniExclamationTriangle }
      : { className: "text-amber-700", Icon: HiMiniExclamationTriangle };
  }
  if (compatibility.state === "coverage_unavailable") return { className: "text-slate-500", Icon: HiMiniMinusCircle };
  return { className: "text-slate-500", Icon: HiMiniQuestionMarkCircle };
}

/** Compact version-coverage label for an App coverage row. Never color alone. */
export function HarnessVersionLabel({ compatibility }: { compatibility: HarnessVersionCompatibility | null }) {
  if (!compatibility || versionCheckUnsupported(compatibility)) return null;
  const { className, Icon } = toneFor(compatibility);
  const label = versionRowLabel(compatibility);
  const version = compatibility.detectedVersion;
  return (
    <span
      className={`inline-flex items-center gap-1 text-xs font-medium ${className}`}
      data-version-state={compatibility.state}
    >
      <Icon className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
      <span>{version ? `${label} · ${version}` : label}</span>
    </span>
  );
}
