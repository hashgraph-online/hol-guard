import type { PeriodComparison } from "./evidence-metrics";

export function periodComparisonText(comparison: PeriodComparison): string {
  const { periodDays, currentTotal, previousTotal, currentBlocked, blockedDelta, totalDelta } = comparison;

  const periodLabel = periodDays === 7 ? "7 days" : `${periodDays} days`;

  if (currentTotal === 0 && previousTotal === 0) {
    return `No actions recorded in the past ${periodLabel}.`;
  }

  const parts: string[] = [];

  if (totalDelta === 0) {
    parts.push(`Same number of actions as the prior ${periodLabel} (${currentTotal} total).`);
  } else if (totalDelta > 0) {
    parts.push(`${totalDelta} more action${totalDelta !== 1 ? "s" : ""} than the prior ${periodLabel} (${currentTotal} vs ${previousTotal}).`);
  } else {
    const abs = Math.abs(totalDelta);
    parts.push(`${abs} fewer action${abs !== 1 ? "s" : ""} than the prior ${periodLabel} (${currentTotal} vs ${previousTotal}).`);
  }

  if (currentBlocked > 0) {
    if (blockedDelta === 0) {
      parts.push(`Guard stopped ${currentBlocked} action${currentBlocked !== 1 ? "s" : ""}, same as before.`);
    } else if (blockedDelta > 0) {
      parts.push(`Guard stopped ${currentBlocked} action${currentBlocked !== 1 ? "s" : ""}, up ${blockedDelta} from prior period.`);
    } else {
      const abs = Math.abs(blockedDelta);
      parts.push(`Guard stopped ${currentBlocked} action${currentBlocked !== 1 ? "s" : ""}, down ${abs} from prior period.`);
    }
  } else {
    parts.push("No actions were stopped in this period.");
  }

  return parts.join(" ");
}
