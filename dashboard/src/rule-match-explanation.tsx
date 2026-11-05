import { coverageStepLabel } from "./approval-extension-coverage";
import type {
  GuardApprovalExtensionCoverage,
  GuardCoveredRule,
  GuardCoveredSegment,
} from "./approval-extension-coverage-types";

/**
 * The extension rules Guard matched on a paused command, in the catalog's own
 * words, for the card's "Why paused" item.
 *
 * Coverage lists the rules that matched, not the one that paused the command:
 * a rule whose permission is already allowed, or one a safe variant covers,
 * can still be listed. So every line says "matched", never "paused because".
 * A rule the matcher could only flag as uncertain is named as something Guard
 * could not rule out, never described as what the step does. Nothing here
 * reads the command text: the step and its executable come from Core.
 */
export type RuleMatchLine = {
  readonly key: string;
  /** "Step 2 · rm" on a compound command, the executable alone otherwise. */
  readonly step: string | null;
  readonly text: string;
  readonly safer: string | null;
};

const MAX_LINES = 4;

export function ruleMatchLines(coverage: GuardApprovalExtensionCoverage | null | undefined): RuleMatchLine[] {
  if (!coverage) {
    return [];
  }
  const showStep = coverage.compound || coverage.segments.length > 1;
  const lines: RuleMatchLine[] = [];
  for (const segment of coverage.segments) {
    for (const rule of segment.rules) {
      const line = ruleLine(segment, rule, showStep);
      if (line !== null) {
        lines.push(line);
      }
    }
  }
  return lines.slice(0, MAX_LINES);
}

function ruleLine(segment: GuardCoveredSegment, rule: GuardCoveredRule, showStep: boolean): RuleMatchLine | null {
  const title = rule.title;
  const description = rule.description ?? null;
  if (title === null && description === null) {
    return null;
  }
  const key = `${segment.index}:${rule.rule_id}`;
  const step = showStep ? coverageStepLabel(segment) : segment.executable;
  if (rule.uncertain === true) {
    const subject = title !== null ? `“${title}”` : `a rule that looks for this: ${description}`;
    return {
      key,
      step,
      text: `Guard could not fully read this part, so it could not rule out ${subject}.`,
      safer: null,
    };
  }
  const named = title !== null ? `Matched the rule “${title}”.` : "Matched a Guard rule.";
  const text = description !== null ? `${named} ${description}` : named;
  const safer = rule.safer_alternatives?.[0] ?? null;
  return { key, step, text, safer };
}

export function RuleMatchExplanation({ lines }: { lines: readonly RuleMatchLine[] }) {
  return (
    <div className="space-y-2">
      <p className="text-sm text-brand-dark">What Guard's command rules found:</p>
      <ul className="space-y-2">
        {lines.map((line) => (
          <li key={line.key} className="text-sm leading-relaxed text-brand-dark">
            {line.step !== null && (
              <span className="mr-1.5 rounded bg-slate-100 px-1.5 py-0.5 font-mono text-[11px] text-brand-dark/80">
                {line.step}
              </span>
            )}
            <span>{line.text}</span>
            {line.safer !== null && (
              <span className="mt-0.5 block text-xs text-muted-foreground">Safer: {line.safer}</span>
            )}
          </li>
        ))}
      </ul>
    </div>
  );
}
