import { useCallback, useEffect, useState } from "react";
import { HiMiniChevronRight, HiMiniCommandLine } from "react-icons/hi2";

import { fetchCommandActivityApi } from "../guard-api";
import { createCommandActivityClient } from "./command-activity-api";
import { homeCommandActivityModel } from "./command-activity-presenters";
import type { CommandActivityAnalytics } from "./command-activity-types";

const client = createCommandActivityClient(fetchCommandActivityApi);

export function HomeCommandActivityCard(props: { onOpen: () => void }) {
  const [analytics, setAnalytics] = useState<CommandActivityAnalytics | null>(null);
  useEffect(() => {
    const controller = new AbortController();
    client.fetchAnalytics({ days: 90, top_limit: 10, dimension: null, dimension_value: null }, controller.signal).then(
      (data) => setAnalytics(data),
      () => undefined,
    );
    return () => controller.abort();
  }, []);
  const handleOpen = useCallback(() => props.onOpen(), [props.onOpen]);
  const model = analytics === null ? null : homeCommandActivityModel(analytics);
  if (model === null) return null;
  return (
    <section className="rounded-lg border border-slate-200 bg-white p-4 shadow-sm" aria-labelledby="home-command-activity-title">
      <div className="flex items-start justify-between gap-4">
        <div className="flex min-w-0 items-start gap-3">
          <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-brand-blue/[0.08] text-brand-blue">
            <HiMiniCommandLine className="h-5 w-5" aria-hidden="true" />
          </div>
          <div className="min-w-0">
            <h2 id="home-command-activity-title" className="text-sm font-semibold text-brand-dark">Commands checked</h2>
            <p className="mt-0.5 text-xs text-slate-500">{model.window}</p>
          </div>
        </div>
        <button type="button" onClick={handleOpen} aria-label="Open command activity" className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg text-slate-500 hover:bg-slate-100 hover:text-brand-dark">
          <HiMiniChevronRight className="h-5 w-5" aria-hidden="true" />
        </button>
      </div>
      <div className="mt-4 grid grid-cols-3 gap-3">
        <div><p className="text-xl font-semibold text-brand-dark">{model.metrics.commandsChecked.toLocaleString()}</p><p className="text-xs text-slate-500">Checked</p></div>
        <div><p className="text-xl font-semibold text-brand-dark">{model.metrics.prompted.toLocaleString()}</p><p className="text-xs text-slate-500">Review prompts</p></div>
        <div><p className="text-xl font-semibold text-brand-dark">{model.metrics.postProof.toLocaleString()}</p><p className="text-xs text-slate-500">Post proof</p></div>
      </div>
      <p className={`mt-3 text-xs ${model.health ? "text-amber-700" : "text-slate-500"}`}>{model.health ?? "Evidence store reporting normally."}</p>
    </section>
  );
}
