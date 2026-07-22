import type { GuardTemporaryMcpGrantDuration, GuardTemporaryMcpGrantTarget } from "./guard-types";
import {
  browserCapabilityLabel,
  temporaryMcpDurationLabel,
  temporaryMcpExpiryLabel,
  temporaryMcpSummary,
  temporaryMcpTargetLabel,
  type TemporaryMcpApprovalOptions,
} from "./temporary-mcp-approval";

type Props = {
  options: TemporaryMcpApprovalOptions;
  target: GuardTemporaryMcpGrantTarget;
  duration: GuardTemporaryMcpGrantDuration;
  onTargetChange: (target: GuardTemporaryMcpGrantTarget) => void;
  onDurationChange: (duration: GuardTemporaryMcpGrantDuration) => void;
};

const EXCLUSION_COPY =
  "Privileged browser access, file transfer, secrets, command execution, destructive actions, and shared-profile access still require review.";

export function TemporaryMcpApprovalControls(props: Props) {
  const expiry = temporaryMcpExpiryLabel(props.duration);
  const descriptionId = "temporary-mcp-boundary";
  return (
    <div className="mt-6 space-y-5">
      <fieldset aria-describedby={descriptionId}>
        <legend className="text-xs font-semibold uppercase tracking-[0.16em] text-brand-blue">
          How long should this choice last?
        </legend>
        <div className="mt-2 grid grid-cols-2 gap-2 sm:grid-cols-4">
          {props.options.allowed_durations.map((duration) => (
            <label
              key={duration}
              className={`flex min-h-11 cursor-pointer items-center justify-center rounded-lg border px-3 text-sm font-medium transition-colors focus-within:ring-2 focus-within:ring-brand-blue/30 ${
                props.duration === duration
                  ? "border-brand-blue bg-brand-blue/[0.06] text-brand-dark"
                  : "border-slate-200/70 bg-white text-brand-dark hover:bg-slate-50"
              }`}
            >
              <input
                className="sr-only"
                type="radio"
                name="temporary-mcp-duration"
                value={duration}
                checked={props.duration === duration}
                onChange={() => props.onDurationChange(duration)}
              />
              {temporaryMcpDurationLabel(duration)}
            </label>
          ))}
        </div>
      </fieldset>

      <fieldset aria-describedby={descriptionId}>
        <legend className="text-xs font-semibold uppercase tracking-[0.16em] text-brand-blue">
          What should it cover?
        </legend>
        <div className="mt-2 grid grid-cols-1 gap-2 md:grid-cols-2">
          {props.options.allowed_targets.map((target) => (
            <label
              key={target}
              className={`flex min-h-11 cursor-pointer items-start gap-3 rounded-lg border px-4 py-3 transition-colors focus-within:ring-2 focus-within:ring-brand-blue/30 ${
                props.target === target
                  ? "border-brand-blue bg-brand-blue/[0.06]"
                  : "border-slate-200/70 bg-white hover:bg-slate-50"
              }`}
            >
              <input
                className="mt-0.5 h-4 w-4 shrink-0 accent-brand-blue"
                type="radio"
                name="temporary-mcp-target"
                value={target}
                checked={props.target === target}
                onChange={() => props.onTargetChange(target)}
              />
              <span>
                <span className="block text-sm font-medium text-brand-dark">
                  {temporaryMcpTargetLabel(target, props.options)}
                </span>
                <span className="mt-0.5 block text-xs text-muted-foreground">
                  {target === "exact"
                    ? "Only the current tool call."
                    : target === "category"
                      ? `${browserCapabilityLabel(props.options.category)} calls from this exact server.`
                      : "Eligible routine browser calls from this exact server. High-risk calls stay blocked."}
                </span>
              </span>
            </label>
          ))}
        </div>
      </fieldset>

      <div className="border-y border-slate-200/70 py-3" aria-live="polite">
        <p className="text-sm font-semibold text-brand-dark">
          {temporaryMcpSummary(props.options, props.target, props.duration)}
        </p>
        {expiry !== null && <p className="mt-1 text-xs text-muted-foreground">Expires around {expiry}. The Guard service sets the final expiry.</p>}
      </div>
      <p id={descriptionId} className="text-xs leading-5 text-brand-dark/70">
        {EXCLUSION_COPY}
      </p>
    </div>
  );
}
