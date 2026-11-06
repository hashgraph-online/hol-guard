import type { ComponentType } from "react";
import {
  HiMiniCloud,
  HiMiniNoSymbol,
  HiMiniQueueList,
  HiMiniShieldCheck,
} from "react-icons/hi2";

export const POLICY_PANEL_CARD_CLASS =
  "rounded-2xl border border-slate-200/80 bg-white shadow-[0_1px_2px_rgba(15,23,42,0.04),0_10px_28px_rgba(15,23,42,0.05)]";

export const STRICT_CONFIG_EVALUATION_STEPS: Array<{
  label: string;
  description: string;
  icon: ComponentType<{ className?: string }>;
  surfaceClass: string;
  iconClass: string;
}> = [
  {
    label: "Local rule",
    description: "If a remembered local rule matches, apply it.",
    icon: HiMiniQueueList,
    surfaceClass: "border-violet-200 bg-violet-50",
    iconClass: "text-violet-600",
  },
  {
    label: "Cloud policy",
    description: "Then apply the signed Cloud policy bundle.",
    icon: HiMiniCloud,
    surfaceClass: "border-sky-200 bg-sky-50",
    iconClass: "text-sky-600",
  },
  {
    label: "Cloud exception",
    description: "Matching Cloud exception allows the action.",
    icon: HiMiniCloud,
    surfaceClass: "border-cyan-200 bg-cyan-50",
    iconClass: "text-cyan-700",
  },
  {
    label: "Strict fallback",
    description: "If nothing allows it, this strict config is used.",
    icon: HiMiniShieldCheck,
    surfaceClass: "border-amber-200 bg-amber-50",
    iconClass: "text-amber-700",
  },
  {
    label: "Ask or block",
    description: "Guard asks (or blocks) according to your choice.",
    icon: HiMiniNoSymbol,
    surfaceClass: "border-rose-200 bg-rose-50",
    iconClass: "text-rose-600",
  },
];

export const STRICT_CONFIG_WHAT_CHANGES = [
  "First-time actions follow your default strict action.",
  "Changed tool hashes trigger your configured review path.",
  "New network domains and subprocesses use strict fallback rules.",
] as const;

export const STRICT_CONFIG_SCENARIOS = [
  { id: "first-time", label: "New tool contacting unknown domain" },
  { id: "remembered-allow", label: "Remembered allow wins" },
  { id: "cloud-exception", label: "Active Cloud exception" },
] as const;
