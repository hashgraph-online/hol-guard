import { useCallback, useMemo, type ChangeEvent, type ReactNode } from "react";

import type { CommandActivityFilters } from "./command-activity-state";
import { safeEvidenceId } from "./command-activity-presenters";
import type { CommandActivityAnalytics, CommandExtensionsPage } from "./command-activity-types";

interface FilterOption {
  label: string;
  value: string;
}

function preserveActiveOption(options: FilterOption[], activeValue: string | null): FilterOption[] {
  if (activeValue === null || options.some((option) => option.value === activeValue)) return options;
  const label = safeEvidenceId(activeValue);
  if (label === "Unavailable") return options;
  return [...options, { label, value: activeValue }];
}

function SelectField(props: {
  label: string;
  value: string;
  onChange: (event: ChangeEvent<HTMLSelectElement>) => void;
  children: ReactNode;
}) {
  return (
    <label className="min-w-0 text-xs font-medium text-slate-600">
      <span className="mb-1 block">{props.label}</span>
      <select
        value={props.value}
        onChange={props.onChange}
        className="h-10 w-full min-w-0 rounded-lg border border-slate-200 bg-white px-2.5 text-sm text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/15"
      >
        {props.children}
      </select>
    </label>
  );
}

export function CommandActivityFiltersPanel(props: {
  filters: CommandActivityFilters;
  extensions: CommandExtensionsPage | null;
  analytics: CommandActivityAnalytics | null;
  lockedHarness: string | null;
  resultCount: number | null;
  onChange: (patch: Partial<CommandActivityFilters>) => void;
}) {
  let interactionValue = "";
  if (props.filters.prompted === true) interactionValue = "prompted";
  if (props.filters.prompted === false) interactionValue = "not_prompted";
  const harnesses = useMemo(
    () => preserveActiveOption(
      props.analytics?.dimensions.harness
        .map((bucket) => safeEvidenceId(bucket.value))
        .filter((value) => value !== "Unavailable")
        .map((value) => ({ label: value, value })) ?? [],
      props.filters.harness,
    ),
    [props.analytics, props.filters.harness],
  );
  const selectedExtension = props.extensions?.items.find(
    (extension) => extension.extension_id === props.filters.extension_id,
  );
  const extensions = useMemo(
    () => preserveActiveOption(
      props.extensions?.items.map((extension) => ({ label: extension.name, value: extension.extension_id })) ?? [],
      props.filters.extension_id,
    ),
    [props.extensions, props.filters.extension_id],
  );
  const rules = useMemo(
    () => preserveActiveOption(
      selectedExtension?.rules.map((rule) => ({ label: rule.title, value: rule.rule_id })) ?? [],
      props.filters.rule_id,
    ),
    [props.filters.rule_id, selectedExtension],
  );

  const handleHarness = useCallback(
    (event: ChangeEvent<HTMLSelectElement>) => props.onChange({ harness: event.target.value || null }),
    [props.onChange],
  );
  const handleExtension = useCallback(
    (event: ChangeEvent<HTMLSelectElement>) => props.onChange({ extension_id: event.target.value || null, rule_id: null }),
    [props.onChange],
  );
  const handleRule = useCallback(
    (event: ChangeEvent<HTMLSelectElement>) => props.onChange({ rule_id: event.target.value || null }),
    [props.onChange],
  );
  const handleExecution = useCallback(
    (event: ChangeEvent<HTMLSelectElement>) => props.onChange({ execution_status: (event.target.value || null) as CommandActivityFilters["execution_status"] }),
    [props.onChange],
  );
  const handleProof = useCallback(
    (event: ChangeEvent<HTMLSelectElement>) => props.onChange({ proof_level: (event.target.value || null) as CommandActivityFilters["proof_level"] }),
    [props.onChange],
  );
  const handlePrompted = useCallback(
    (event: ChangeEvent<HTMLSelectElement>) => {
      const value = event.target.value;
      let prompted: boolean | null = null;
      if (value === "prompted") prompted = true;
      if (value === "not_prompted") prompted = false;
      props.onChange({ prompted });
    },
    [props.onChange],
  );
  const handleReuse = useCallback(
    (event: ChangeEvent<HTMLSelectElement>) => props.onChange({ approval_reuse_status: (event.target.value || null) as CommandActivityFilters["approval_reuse_status"] }),
    [props.onChange],
  );

  return (
    <section aria-label="Command activity filters" className="rounded-lg border border-slate-200 bg-slate-50/60 p-3">
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4 xl:grid-cols-7">
        {props.lockedHarness === null ? (
          <SelectField label="App" value={props.filters.harness ?? ""} onChange={handleHarness}>
            <option value="">All apps</option>
            {harnesses.map((harness) => <option key={harness.value} value={harness.value}>{harness.label}</option>)}
          </SelectField>
        ) : null}
        <SelectField label="Extension" value={props.filters.extension_id ?? ""} onChange={handleExtension}>
          <option value="">All extensions</option>
          {extensions.map((extension) => (
            <option key={extension.value} value={extension.value}>{extension.label}</option>
          ))}
        </SelectField>
        <SelectField label="Rule" value={props.filters.rule_id ?? ""} onChange={handleRule}>
          <option value="">All rules</option>
          {rules.map((rule) => (
            <option key={rule.value} value={rule.value}>{rule.label}</option>
          ))}
        </SelectField>
        <SelectField label="Execution proof" value={props.filters.execution_status ?? ""} onChange={handleExecution}>
          <option value="">All execution states</option>
          <option value="prevented">Prevented</option>
          <option value="allowed_unconfirmed">Allowed, unconfirmed</option>
          <option value="confirmed_success">Confirmed success</option>
          <option value="confirmed_failure">Confirmed failure</option>
          <option value="unpaired_post">Unpaired post proof</option>
        </SelectField>
        <SelectField label="Proof source" value={props.filters.proof_level ?? ""} onChange={handleProof}>
          <option value="">All proof sources</option>
          <option value="pre_hook">Pre-execution only</option>
          <option value="post_hook">Post-execution</option>
          <option value="unpaired_post">Unpaired post proof</option>
        </SelectField>
        <SelectField
          label="Interaction"
          value={interactionValue}
          onChange={handlePrompted}
        >
          <option value="">All interactions</option>
          <option value="prompted">Review requested</option>
          <option value="not_prompted">No review prompt</option>
        </SelectField>
        <SelectField label="Authorization reuse" value={props.filters.approval_reuse_status ?? ""} onChange={handleReuse}>
          <option value="">All reuse states</option>
          <option value="accepted">Accepted</option>
          <option value="rejected">Rejected</option>
          <option value="not-applicable">Not applicable</option>
        </SelectField>
      </div>
      <p className="mt-2 min-h-5 text-xs text-slate-500" aria-live="polite">
        {props.resultCount === null ? "Loading command activity…" : `${props.resultCount.toLocaleString()} records on this page`}
      </p>
    </section>
  );
}
