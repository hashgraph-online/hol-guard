import { useEffect, useState } from "react";
import { HiMiniExclamationTriangle } from "react-icons/hi2";
import { EmptyState, Tag } from "./approval-center-primitives";
import { fetchGuardApi } from "./guard-api";

const RESULTS_PATH = "/v1/mcp-cross-exam/results";

type JsonObject = { readonly [key: string]: Json };
type Json = string | number | boolean | null | Json[] | JsonObject;

type AuditRun = {
  runId: string | null;
  target: string;
  transport: string;
  status: string;
  score: number | null;
  coverage: string | null;
  findingCount: number;
  severities: string[];
  probes: string[];
  tools: string[];
  artifacts: string[];
  auditorVersion: string | null;
  finishedAt: string | null;
};

type ResultsState = {
  enabled: boolean;
  runs: AuditRun[];
};

function isObject(value: Json): value is JsonObject {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function text(value: Json | undefined): string | null {
  return typeof value === "string" && value.trim() ? value : null;
}

function count(value: Json | undefined): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function texts(value: Json | undefined): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string" && Boolean(item)) : [];
}

function runFrom(item: JsonObject): AuditRun {
  return {
    runId: text(item.run_id),
    target: text(item.target) ?? "unknown",
    transport: text(item.transport) ?? "unknown",
    status: text(item.status) ?? "unknown",
    score: count(item.score),
    coverage: text(item.coverage),
    findingCount: count(item.finding_count) ?? 0,
    severities: texts(item.severities),
    probes: texts(item.probes),
    tools: texts(item.tools),
    artifacts: texts(item.artifacts),
    auditorVersion: text(item.auditor_version),
    finishedAt: text(item.finished_at),
  };
}

export function normalizeMCPCrossExamResults(payload: Json): ResultsState {
  const record = isObject(payload) ? payload : {};
  const runs = Array.isArray(record.runs) ? record.runs : [];
  return {
    enabled: record.enabled === true,
    runs: runs.filter(isObject).map(runFrom),
  };
}

function readJson(text: string): Json {
  try {
    return JSON.parse(text, (_key: string, value: Json) => value);
  } catch {
    return null;
  }
}

export async function fetchMCPCrossExamResults(signal?: AbortSignal): Promise<ResultsState> {
  const response = await fetchGuardApi(RESULTS_PATH, { signal });
  const body = readJson(await response.text());
  if (!response.ok) {
    throw new Error("Guard could not load MCP Cross Exam results.");
  }
  return normalizeMCPCrossExamResults(body);
}

function statusTone(status: string): "amber" | "warning" | "slate" {
  if (status === "failed" || status === "unreachable" || status === "incomplete") {
    return "warning";
  }
  return "amber";
}

export function MCPCrossExamWorkspace() {
  const [state, setState] = useState<ResultsState | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    fetchMCPCrossExamResults(controller.signal)
      .then((payload) => {
        setState(payload);
        setError(null);
      })
      .catch((reason) => {
        if (controller.signal.aborted) {
          return;
        }
        setError(reason instanceof Error ? reason.message : "Guard could not load MCP Cross Exam results.");
      });
    return () => controller.abort();
  }, []);

  return (
    <div className="space-y-6" data-testid="mcp-cross-exam-workspace">
      <div className="flex items-start gap-2 rounded-xl border border-amber-200 bg-amber-50/60 px-3 py-2.5" role="status">
        <HiMiniExclamationTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-600" aria-hidden="true" />
        <div>
          <div className="flex flex-wrap items-center gap-2">
            <Tag tone="warning">Warning</Tag>
            <p className="text-sm font-semibold text-amber-800">Protocol audit, not a policy decision</p>
          </div>
          <p className="text-xs text-amber-700 mt-0.5">
            MCP Cross Exam findings stay on this machine. A passing score does not bypass Guard, and this page never blocks or remediates.
            Enable or disable audits with <code>hol-guard settings set mcp-cross-exam</code>.
          </p>
        </div>
      </div>
      {error ? (
        <EmptyState title="MCP audit results unavailable" body={error} />
      ) : state === null ? (
        <div className="guard-skeleton h-24 w-full" />
      ) : (
        <>
          <p className="text-sm text-slate-600" data-testid="mcp-cross-exam-enablement">
            {state.enabled
              ? "MCP Cross Exam is on for this machine. Run hol-guard mcp audit to collect a new local summary."
              : "MCP Cross Exam is off. Run hol-guard settings set mcp-cross-exam on before auditing."}
          </p>
          {state.runs.length === 0 ? (
            <EmptyState
              title="No local MCP audits yet"
              body="Summaries appear here after hol-guard mcp audit finishes. Incomplete coverage is called out on each run."
            />
          ) : (
            <ul className="space-y-4">
              {state.runs.map((run, index) => (
                <li key={run.runId ?? `${run.target}-${index}`} className="rounded-2xl border border-slate-100 bg-white p-5 shadow-sm space-y-3">
                  <div className="flex flex-wrap items-center gap-2">
                    <Tag tone={statusTone(run.status)}>Warning</Tag>
                    <Tag tone="amber">{run.status}</Tag>
                    {run.coverage === "partial" ? <Tag tone="warning">Incomplete coverage</Tag> : null}
                    {run.score !== null ? <Tag tone="slate">Score {run.score}</Tag> : null}
                  </div>
                  <p className="text-sm font-semibold text-brand-dark">{run.target}</p>
                  <p className="text-xs text-slate-500">
                    {run.transport} · {run.findingCount} finding{run.findingCount === 1 ? "" : "s"}
                    {run.auditorVersion ? ` · mcp-cross-exam ${run.auditorVersion}` : ""}
                    {run.finishedAt ? ` · ${run.finishedAt}` : ""}
                  </p>
                  {run.probes.length > 0 ? (
                    <p className="text-xs text-slate-600">Probes: {run.probes.join(", ")}</p>
                  ) : null}
                  {run.tools.length > 0 ? (
                    <p className="text-xs text-slate-600">Tools: {run.tools.join(", ")}</p>
                  ) : null}
                  {run.artifacts.length > 0 ? (
                    <div>
                      <p className="text-xs font-semibold text-slate-500">Local evidence</p>
                      <ul className="mt-1 space-y-1">
                        {run.artifacts.map((path) => (
                          <li key={path} className="font-mono text-xs text-slate-600">
                            {path}
                          </li>
                        ))}
                      </ul>
                    </div>
                  ) : null}
                </li>
              ))}
            </ul>
          )}
        </>
      )}
    </div>
  );
}
