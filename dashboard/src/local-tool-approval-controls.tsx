import type { GuardLocalToolGrantDuration, GuardLocalToolGrantTarget } from "./guard-types";
import {
  localToolDurationLabel,
  localToolExpiryLabel,
  localToolReadOnlyReasonLabel,
  localToolSummary,
  localToolTargetLabel,
  type LocalToolApprovalOptions,
} from "./local-tool-approval";

type Props = {
  options: LocalToolApprovalOptions;
  target: GuardLocalToolGrantTarget;
  duration: GuardLocalToolGrantDuration;
  onTargetChange: (target: GuardLocalToolGrantTarget) => void;
  onDurationChange: (duration: GuardLocalToolGrantDuration) => void;
};

export function LocalToolApprovalControls(props: Props) {
  const expiry = localToolExpiryLabel(props.duration);
  const durationDescriptionId = "local-tool-duration-description";
  const targetDescriptionId = "local-tool-target-description";
  return (
    <div className="mt-6 space-y-5">
      <div className="border-y border-slate-200/70 py-3">
        <p className="text-sm font-semibold text-brand-dark">
          Trust read-only calls from {props.options.tool_name}
        </p>
        <p className="mt-1 text-xs leading-5 text-muted-foreground">
          Guard identified this as {localToolReadOnlyReasonLabel(props.options.read_only_reason)}. Argument values may vary, but the tool files, option names, and selected capability must still match.
        </p>
      </div>

      <fieldset aria-describedby={durationDescriptionId}>
        <legend className="text-xs font-semibold uppercase tracking-[0.16em] text-brand-blue">
          How long should this choice last?
        </legend>
        <p id={durationDescriptionId} className="mt-1 text-xs text-muted-foreground">
          Choose one-time approval or an explicit reusable trust window.
        </p>
        <div className="mt-2 grid grid-cols-2 gap-2 sm:grid-cols-5">
          {props.options.allowed_durations.map((duration) => (
            <label
              key={duration}
              className={`flex min-h-11 cursor-pointer items-center justify-center rounded-lg border px-3 text-center text-sm font-medium transition-colors focus-within:ring-2 focus-within:ring-brand-blue/30 ${
                props.duration === duration
                  ? "border-brand-blue bg-brand-blue/[0.06] text-brand-dark"
                  : "border-slate-200/70 bg-white text-brand-dark hover:bg-slate-50"
              }`}
            >
              <input
                className="sr-only"
                type="radio"
                name="local-tool-duration"
                value={duration}
                checked={props.duration === duration}
                onChange={() => props.onDurationChange(duration)}
              />
              {localToolDurationLabel(duration)}
            </label>
          ))}
        </div>
      </fieldset>

      <fieldset aria-describedby={targetDescriptionId}>
        <legend className="text-xs font-semibold uppercase tracking-[0.16em] text-brand-blue">
          What should it cover?
        </legend>
        <p id={targetDescriptionId} className="mt-1 text-xs text-muted-foreground">
          Limit trust to this capability, or include other calls Guard independently recognizes as read-only.
        </p>
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
                name="local-tool-target"
                value={target}
                checked={props.target === target}
                onChange={() => props.onTargetChange(target)}
              />
              <span>
                <span className="block text-sm font-medium text-brand-dark">
                  {localToolTargetLabel(target, props.options)}
                </span>
                <span className="mt-0.5 block text-xs text-muted-foreground">
                  {target === "capability"
                    ? "The selected read-only operation may use different IDs, filters, and timestamps."
                    : "Other operations run only when Guard independently recognizes them as read-only."}
                </span>
              </span>
            </label>
          ))}
        </div>
      </fieldset>

      <div className="border-y border-slate-200/70 py-3" aria-live="polite">
        <p className="text-sm font-semibold text-brand-dark">
          {localToolSummary(props.options, props.target, props.duration)}
        </p>
        {expiry !== null && (
          <p className="mt-1 text-xs text-muted-foreground">
            Expires around {expiry}. The Guard service sets the final expiry.
          </p>
        )}
        {props.duration === "version" && (
          <p className="mt-1 text-xs text-muted-foreground">
            Trust ends automatically when the executable, script, or approved output processor changes.
          </p>
        )}
        {props.duration === "always" && (
          <p className="mt-1 text-xs text-muted-foreground">
            Guard still checks package safety, command behavior, paths, and environment settings on every call.
          </p>
        )}
      </div>
      <p className="text-xs leading-5 text-brand-dark/70">
        {props.options.trust_basis === "package-profile"
          ? "Only recognized local scan calls are covered. Package risks, URLs, writes, unsafe paths, shell composition, and changed runner files still require review."
          : "Guard rechecks the executable and script before every call. Writes, shell chaining, redirects, embedded commands, environment overrides, and changed tool files still require review."}
      </p>
    </div>
  );
}
