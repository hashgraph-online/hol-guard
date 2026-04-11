import { type ReactNode, useEffect, useState } from "react";

import {
  fetchDiff,
  fetchPolicy,
  fetchReceipts,
  fetchRequest,
  fetchRequests,
  resolveRequest
} from "./guard-api";
import type {
  GuardApprovalRequest,
  GuardArtifactDiff,
  GuardPolicyDecision,
  GuardReceipt
} from "./guard-types";

type RequestState =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; items: GuardApprovalRequest[] };

type DetailState =
  | { kind: "idle" }
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | {
      kind: "ready";
      item: GuardApprovalRequest;
      diff: GuardArtifactDiff | null;
      receipt: GuardReceipt | null;
      policy: GuardPolicyDecision[];
    };

const navItems = [
  { href: "/", label: "Approval center", summary: "Pending launches Guard stopped" },
  { href: "/v1/receipts", label: "Stored receipts", summary: "Decisions Guard already remembers" },
  { href: "https://hol.org/guard", label: "hol.org Guard", summary: "Synced history and team controls" }
] as const;

const approvalLoop = [
  {
    title: "Pause the harness cleanly",
    body: "Guard interrupts the risky launch without dumping you into an unexplained terminal stop."
  },
  {
    title: "Inspect only what changed",
    body: "See the exact fields that drifted from the last trusted version before you decide."
  },
  {
    title: "Resume with one choice",
    body: "Allow this version, widen trust carefully, or block it and keep the harness stopped."
  }
] as const;

const footerSections = [
  {
    title: "Guard",
    links: [
      { href: "https://hol.org/guard", label: "Cloud dashboard" },
      { href: "https://hol.org/guard/pricing", label: "Pricing" }
    ]
  },
  {
    title: "Docs",
    links: [
      { href: "https://hol.org/docs/registry-broker/mcp-server", label: "Hashnet MCP server" },
      { href: "https://hol.org/docs/libraries/standards-sdk", label: "Standards SDK" }
    ]
  },
  {
    title: "Community",
    links: [
      { href: "https://x.com/HashgraphOnline", label: "X" },
      { href: "https://t.me/hashinals", label: "Telegram" }
    ]
  },
  {
    title: "More",
    links: [
      { href: "https://hol.org/blog", label: "Blog" },
      { href: "https://github.com/hashgraph-online", label: "GitHub" }
    ]
  }
] as const;

const scopeOptions = [
  {
    value: "artifact",
    title: "Allow this version only",
    body: "Trust only this exact package, skill, or MCP server fingerprint."
  },
  {
    value: "workspace",
    title: "Allow inside this workspace",
    body: "Remember the decision only for the current project or repo path."
  },
  {
    value: "publisher",
    title: "Trust this publisher here",
    body: "Accept future versions from the same publisher inside this harness."
  },
  {
    value: "harness",
    title: "Trust inside this harness",
    body: "Stop prompting for similar launches in this harness."
  },
  {
    value: "global",
    title: "Trust everywhere",
    body: "Use only when you want the broadest possible trust rule."
  }
] as const;

const holLogoUrl = "/brand/Logo_Whole.png";

function usePathname(): string {
  const [pathname, setPathname] = useState(window.location.pathname);

  useEffect(() => {
    const onPopState = () => setPathname(window.location.pathname);
    window.addEventListener("popstate", onPopState);
    return () => window.removeEventListener("popstate", onPopState);
  }, []);

  return pathname;
}

function navigate(pathname: string): void {
  window.history.pushState({}, "", pathname);
  window.dispatchEvent(new PopStateEvent("popstate"));
}

function parseRequestId(pathname: string): string | null {
  if (pathname.startsWith("/requests/")) {
    return pathname.slice("/requests/".length);
  }
  if (pathname.startsWith("/approvals/")) {
    return pathname.slice("/approvals/".length);
  }
  return null;
}

async function loadDetail(requestId: string): Promise<Exclude<DetailState, { kind: "idle" | "loading" }>> {
  try {
    const item = await fetchRequest(requestId);
    const [diff, receipts, policy] = await Promise.all([
      fetchDiff(item.artifact_id, item.harness),
      fetchReceipts(),
      fetchPolicy(item.harness)
    ]);
    const receipt = receipts.find((entry) => entry.artifact_id === item.artifact_id) ?? null;
    return { kind: "ready", item, diff, receipt, policy };
  } catch (error) {
    return {
      kind: "error",
      message: error instanceof Error ? error.message : "Unable to load the approval request."
    };
  }
}

function humanizeChangedFields(fields: string[]): string {
  if (fields.length === 0) {
    return "no tracked fields";
  }
  if (fields.length === 1) {
    return fields[0];
  }
  if (fields.length === 2) {
    return `${fields[0]} and ${fields[1]}`;
  }
  return `${fields.slice(0, -1).join(", ")}, and ${fields.at(-1)}`;
}

function buildPauseSummary(item: GuardApprovalRequest): string {
  return `Guard paused ${item.artifact_name} before ${item.harness} could use it because ${humanizeChangedFields(item.changed_fields)} changed since the last trusted version.`;
}

function buildDecisionHint(item: GuardApprovalRequest): string {
  if (item.policy_action === "block") {
    return "Guard recommends blocking this launch until you review the drift.";
  }
  if (item.policy_action === "require-reapproval") {
    return "Guard needs a fresh approval before this launch can continue.";
  }
  return "Guard found a change and needs a decision before the launch continues.";
}

export function App() {
  const pathname = usePathname();
  const requestId = parseRequestId(pathname);
  const [requests, setRequests] = useState<RequestState>({ kind: "loading" });
  const [detail, setDetail] = useState<DetailState>({ kind: "idle" });
  const [resolutionMessage, setResolutionMessage] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    fetchRequests()
      .then((items) => {
        if (!cancelled) {
          setRequests({ kind: "ready", items });
        }
      })
      .catch((error: unknown) => {
        if (!cancelled) {
          setRequests({
            kind: "error",
            message: error instanceof Error ? error.message : "Unable to load the local queue."
          });
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const queuedItems = requests.kind === "ready" ? requests.items : [];
  const activeRequestId = requestId ?? queuedItems[0]?.request_id ?? null;

  useEffect(() => {
    if (activeRequestId === null) {
      setDetail({ kind: "idle" });
      return;
    }
    let cancelled = false;
    setDetail({ kind: "loading" });
    loadDetail(activeRequestId).then((nextState) => {
      if (!cancelled) {
        setDetail(nextState);
      }
    });
    return () => {
      cancelled = true;
    };
  }, [activeRequestId]);

  const featuredItem = queuedItems[0] ?? null;

  return (
    <div className="min-h-screen bg-transparent text-brand-dark">
      <header className="sticky top-0 z-40 bg-gradient-to-r from-[#3f4174] to-brand-blue text-white shadow-[0_20px_40px_-30px_rgba(17,24,39,0.6)]">
        <div className="mx-auto flex w-[min(1200px,calc(100vw-32px))] items-center justify-between gap-6 py-3">
          <button type="button" className="flex items-center gap-3 text-left" onClick={() => navigate("/")}>
            <img src={holLogoUrl} alt="HOL Logo" className="h-8 w-auto sm:h-9" />
            <div className="flex items-center gap-2">
              <span className="rounded-full bg-white/12 px-2.5 py-1 text-[11px] font-bold uppercase tracking-[0.16em] text-white/85">
                Guard
              </span>
            </div>
          </button>

          <nav className="hidden items-center gap-1.5 lg:flex">
            {navItems.map((item) => (
              <a
                key={item.href}
                href={item.href}
                target={item.href.startsWith("https://") ? "_blank" : undefined}
                rel={item.href.startsWith("https://") ? "noreferrer" : undefined}
                className="inline-flex min-h-10 items-center rounded-md px-3 py-1.5 font-mono text-[15px] font-medium text-white/95 transition-colors duration-200 hover:bg-white/10 hover:text-white"
              >
                {item.label}
              </a>
            ))}
            <a
              href="https://hol.org/guard"
              target="_blank"
              rel="noreferrer"
              className="ml-2 inline-flex min-h-9 items-center rounded-lg bg-white/14 px-4 py-1.5 text-sm font-bold text-white shadow-sm transition-colors duration-200 hover:bg-white/20"
            >
              Dashboard
            </a>
          </nav>
        </div>
      </header>

      <main className="mx-auto w-[min(1200px,calc(100vw-32px))] py-6 sm:py-8">
        <section className="rounded-[34px] border border-slate-200/55 bg-white/82 p-6 shadow-[0_24px_60px_-36px_rgba(17,24,39,0.25)] backdrop-blur-xl sm:p-8">
          {featuredItem ? (
            <div className="grid gap-5 lg:grid-cols-[minmax(0,1fr)_320px] lg:items-start">
              <div className="space-y-5">
                <div className="flex flex-wrap items-center gap-2">
                  <Tag tone="blue">Launch paused</Tag>
                  <Tag tone="green">{featuredItem.harness}</Tag>
                  <Tag tone="slate">{featuredItem.source_scope}</Tag>
                </div>
                <div className="space-y-3">
                  <p className="font-mono text-xs font-black uppercase tracking-[0.2em] text-brand-blue">Current request</p>
                  <h1 className="max-w-3xl text-[clamp(1.9rem,2.8vw,2.8rem)] font-semibold leading-[1] tracking-[-0.05em] text-brand-dark">
                    {featuredItem.artifact_name} wants to run in {featuredItem.harness}, and Guard stopped it.
                  </h1>
                  <p className="max-w-3xl text-[0.98rem] leading-7 text-brand-dark/66">{buildPauseSummary(featuredItem)}</p>
                </div>
                <div className="grid gap-3 rounded-[24px] border border-slate-200/75 bg-slate-50/88 p-5 lg:grid-cols-3">
                  <InfoRow label="Why Guard stopped it" value={buildDecisionHint(featuredItem)} />
                  <InfoRow label="What changed" value={humanizeChangedFields(featuredItem.changed_fields)} />
                  <InfoRow label="Recommended first move" value={scopeOptions.find((item) => item.value === featuredItem.recommended_scope)?.title ?? featuredItem.recommended_scope} />
                </div>
              </div>
              <SurfaceCard tone="accent">
                <div className="space-y-4">
                  <p className="font-mono text-xs font-black uppercase tracking-[0.2em] text-brand-blue">Next safe action</p>
                  <DetailList
                    items={[
                      ["Review this request", "Open the detail view and inspect the drift before saving a rule."],
                      ["Allow narrowly", "Start with the smallest rule that gets this launch moving again."],
                      ["Block if unsure", "Keep the session stopped until you understand the change."]
                    ]}
                  />
                  <div className="flex flex-wrap gap-3">
                    <button
                      type="button"
                      className="inline-flex min-h-11 items-center justify-center rounded-full bg-brand-blue px-5 text-sm font-semibold text-white shadow-sm shadow-brand-blue/30 transition-colors duration-200 hover:bg-brand-blue/90"
                      onClick={() => navigate(`/requests/${featuredItem.request_id}`)}
                    >
                      Open decision console
                    </button>
                    <a
                      href="https://hol.org/guard"
                      target="_blank"
                      rel="noreferrer"
                      className="inline-flex min-h-11 items-center justify-center rounded-full border border-slate-200/75 bg-white/80 px-5 text-sm font-semibold text-brand-dark transition-colors duration-200 hover:border-brand-blue/20 hover:text-brand-blue"
                    >
                      Open hol.org Guard
                    </a>
                  </div>
                </div>
              </SurfaceCard>
            </div>
          ) : (
            <EmptyState
              title="Nothing is paused right now"
              body="When a package, skill, or MCP server changes, Guard will hold the launch here and explain what changed before you decide."
            />
          )}
        </section>

        <section className="mt-5 grid gap-5 lg:grid-cols-[320px_minmax(0,1fr)]">
          <aside className="space-y-5">
            <SurfaceCard>
              <div className="space-y-4">
                <p className="font-mono text-xs font-black uppercase tracking-[0.2em] text-brand-blue">Blocked launches</p>
                <div className="space-y-2">
                  <h2 className="text-[1.65rem] font-semibold tracking-[-0.045em] text-brand-dark">What needs a decision</h2>
                  <p className="text-sm leading-6 text-brand-dark/64">
                    Each row is a launch Guard stopped because it was first seen or changed after an earlier approval.
                  </p>
                </div>
                <div className="space-y-2">
                  {queuedItems.map((item) => {
                    const active = activeRequestId === item.request_id;
                    return (
                      <button
                        key={item.request_id}
                        type="button"
                        className={`block rounded-[18px] border px-4 py-3 transition-colors duration-200 ${
                          active
                            ? "border-brand-blue/20 bg-brand-blue/8 text-brand-dark"
                            : "border-transparent bg-slate-50/85 text-brand-dark/70 hover:border-slate-200/70 hover:text-brand-dark"
                        }`}
                        onClick={() => navigate(`/requests/${item.request_id}`)}
                      >
                        <strong className="block text-sm font-semibold tracking-[-0.02em]">
                          {item.artifact_name} in {item.harness}
                        </strong>
                        <span className="mt-1 block text-xs leading-5">{humanizeChangedFields(item.changed_fields)} changed</span>
                      </button>
                    );
                  })}
                  {queuedItems.length === 0 ? (
                    <ParagraphBlock>No blocked launches are waiting right now.</ParagraphBlock>
                  ) : null}
                </div>
              </div>
            </SurfaceCard>

            <SurfaceCard>
              <div className="space-y-3">
                <p className="font-mono text-xs font-black uppercase tracking-[0.2em] text-brand-blue">Advanced</p>
                <InfoRow label="Stored receipts" value="Past decisions Guard already remembers for future launches." />
                <InfoRow label="hol.org Guard" value="Optional synced history, teams, alerts, and policy packs." />
                <div className="flex flex-wrap gap-2">
                  <a
                    href="/v1/receipts"
                    className="inline-flex min-h-10 items-center rounded-full border border-slate-200/75 px-4 py-2 text-sm font-semibold text-brand-dark/75"
                  >
                    Raw receipts
                  </a>
                  <a
                    href="https://hol.org/guard"
                    target="_blank"
                    rel="noreferrer"
                    className="inline-flex min-h-10 items-center rounded-full border border-slate-200/75 px-4 py-2 text-sm font-semibold text-brand-dark/75"
                  >
                    hol.org Guard
                  </a>
                </div>
              </div>
            </SurfaceCard>
          </aside>

          <div className="space-y-5">
            {resolutionMessage ? (
              <SurfaceCard tone="success">
                <p className="text-sm font-semibold text-brand-green-text">{resolutionMessage}</p>
              </SurfaceCard>
            ) : null}

            {activeRequestId === null ? (
              <SurfaceCard>
                <EmptyState
                  title="Nothing to review"
                  body="Guard will place the next blocked launch here with the exact change that needs approval."
                />
              </SurfaceCard>
            ) : (
              <DetailWorkspace
                detail={detail}
                onBack={() => navigate("/")}
                showBack={requestId !== null}
                onResolved={(message) => {
                  setResolutionMessage(message);
                  navigate("/");
                  fetchRequests()
                    .then((items) => setRequests({ kind: "ready", items }))
                    .catch(() => undefined);
                }}
              />
            )}
          </div>
        </section>
      </main>

      <footer className="mt-10 bg-gradient-to-r from-[#3f4174] to-brand-blue text-indigo-200">
        <nav aria-label="Footer Navigation" className="mx-auto w-[min(1200px,calc(100vw-32px))] px-0 py-8 lg:py-12">
          <div className="grid grid-cols-1 gap-0 sm:grid-cols-2 sm:gap-8 lg:grid-cols-4">
            {footerSections.map((section) => (
              <FooterSection key={section.title} title={section.title} links={[...section.links]} />
            ))}
          </div>
          <div className="mt-8 border-t border-indigo-200/20 pt-8">
            <p className="text-center text-[13px] font-medium text-blue-200">
              Copyright © {new Date().getFullYear()} HOL DAO LLC. All rights reserved.
            </p>
          </div>
        </nav>
      </footer>
    </div>
  );
}

function QueueWorkspace(props: {
  requests: RequestState;
  onOpen: (requestId: string) => void;
}) {
  return (
    <SurfaceCard>
      <div className="space-y-5">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <p className="font-mono text-xs font-black uppercase tracking-[0.2em] text-brand-blue">Approval queue</p>
            <h2 className="mt-2 text-[1.9rem] font-semibold tracking-[-0.04em] text-brand-dark">Guard stopped these launches</h2>
          </div>
          <a
            href="/v1/requests"
            className="inline-flex min-h-10 items-center rounded-full border border-slate-200/75 px-4 py-2 text-sm font-semibold text-brand-dark/75"
          >
            Raw queue data
          </a>
        </div>
        {props.requests.kind === "loading" ? (
          <EmptyState
            title="Loading approvals"
            body="Guard is reading the local approval queue."
          />
        ) : null}
        {props.requests.kind === "error" ? (
          <EmptyState title="Queue unavailable" body={props.requests.message} />
        ) : null}
        {props.requests.kind === "ready" && props.requests.items.length === 0 ? (
          <EmptyState
            title="No pending approvals"
            body="Guard has not stopped any launches right now. When a package, skill, or MCP server changes, it will show up here with the reason and the safest trust scope."
          />
        ) : null}
        {props.requests.kind === "ready" && props.requests.items.length > 0 ? (
          <div className="space-y-3">
            {props.requests.items.map((item) => (
              <button
                key={item.request_id}
                type="button"
                className="grid w-full gap-4 rounded-[24px] border border-slate-200/70 bg-slate-50/88 px-5 py-5 text-left shadow-[0_18px_36px_-30px_rgba(15,23,42,0.18)] transition-[border-color,transform,background-color,box-shadow] duration-200 hover:-translate-y-0.5 hover:border-brand-blue/25 hover:bg-white hover:shadow-[0_24px_44px_-28px_rgba(85,153,254,0.2)] sm:grid-cols-[minmax(0,1fr)_220px]"
                onClick={() => props.onOpen(item.request_id)}
              >
                <div className="space-y-3">
                  <div className="flex flex-wrap items-center gap-2">
                    <Tag tone="slate">{item.harness}</Tag>
                    <Tag tone="blue">{item.source_scope}</Tag>
                    <Tag tone={item.policy_action === "block" ? "purple" : "green"}>
                      {item.policy_action}
                    </Tag>
                  </div>
                  <div>
                    <h3 className="text-[1.45rem] font-semibold tracking-[-0.04em] text-brand-dark">{item.artifact_name}</h3>
                    <p className="mt-2 text-sm leading-7 text-brand-dark/68">{buildPauseSummary(item)}</p>
                    <p className="mt-1 text-sm leading-6 text-brand-dark/55">{buildDecisionHint(item)}</p>
                  </div>
                </div>
                <div className="grid content-between gap-4 rounded-[18px] border border-slate-200/70 bg-white px-4 py-4">
                  <InfoRow label="Suggested scope" value={item.recommended_scope} />
                  <InfoRow label="Publisher" value={item.publisher ?? "Not reported"} />
                </div>
              </button>
            ))}
          </div>
        ) : null}
      </div>
    </SurfaceCard>
  );
}

function DetailWorkspace(props: {
  detail: DetailState;
  onBack: () => void;
  onResolved: (message: string) => void;
  showBack?: boolean;
}) {
  const [scope, setScope] = useState("artifact");
  const [workspace, setWorkspace] = useState("");
  const [reason, setReason] = useState("approved in local approval center");
  const [submitting, setSubmitting] = useState<"allow" | "block" | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  useEffect(() => {
    if (props.detail.kind === "ready") {
      setScope(props.detail.item.recommended_scope);
    }
  }, [props.detail]);

  if (props.detail.kind === "loading" || props.detail.kind === "idle") {
    return (
      <SurfaceCard>
        <EmptyState title="Loading approval" body="Guard is loading the latest diff, receipt, and policy context." />
      </SurfaceCard>
    );
  }

  if (props.detail.kind === "error") {
    return (
      <SurfaceCard>
        <EmptyState title="Approval unavailable" body={props.detail.message} />
      </SurfaceCard>
    );
  }

  const { item, diff, receipt, policy } = props.detail;

  async function handleResolve(action: "allow" | "block") {
    setSubmitting(action);
    setErrorMessage(null);
    try {
      await resolveRequest({
        requestId: item.request_id,
        action,
        scope,
        workspace,
        reason
      });
      props.onResolved("Guard recorded your decision. You can return to the harness.");
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : "Unable to save decision.");
    } finally {
      setSubmitting(null);
    }
  }

  const profileItems: Array<[string, string]> = [
    ["Artifact ID", item.artifact_id],
    ["Changed fields", item.changed_fields.join(", ") || "none"],
    ["Artifact hash", item.artifact_hash],
    ["Recommended scope", item.recommended_scope],
    ["Recommendation", item.policy_action]
  ];
  if (item.publisher) {
    profileItems.splice(3, 0, ["Publisher", item.publisher]);
  }

  return (
    <div className="grid gap-5 lg:grid-cols-[minmax(0,1fr)_320px]">
      <SurfaceCard>
        <div className="space-y-6">
          {props.showBack ? (
            <button
              type="button"
              className="text-sm font-semibold text-brand-dark/70 transition-colors duration-200 hover:text-brand-dark"
              onClick={props.onBack}
            >
              ← Back to pending approvals
            </button>
          ) : null}
          <div className="space-y-3">
            <p className="font-mono text-xs font-black uppercase tracking-[0.2em] text-brand-blue">
              {item.harness} approval
            </p>
            <h2 className="text-[clamp(2.2rem,4vw,3.8rem)] font-semibold leading-[0.94] tracking-[-0.06em] text-brand-dark">
              {item.artifact_name}
            </h2>
            <p className="max-w-3xl text-base leading-7 text-brand-dark/70">
              {buildPauseSummary(item)}
            </p>
          </div>
          <div className="rounded-[22px] border border-brand-blue/14 bg-brand-blue/6 px-5 py-4">
            <p className="font-mono text-[11px] font-black uppercase tracking-[0.18em] text-brand-blue">What to do here</p>
            <p className="mt-2 text-sm leading-7 text-brand-dark/72">
              Review the changed fields, decide how broadly you want to trust this launch, and then either allow this version or block it for now.
            </p>
          </div>
          <div className="grid gap-4 lg:grid-cols-2">
            <DetailPanel title="What Guard saw">
              <DetailList items={profileItems} />
            </DetailPanel>
            <DetailPanel title="What changed">
              {diff ? (
                <DetailList
                  items={[
                    ["Changed fields", humanizeChangedFields(diff.changed_fields)],
                    ["Previous hash", diff.previous_hash ?? "none"],
                    ["Current hash", diff.current_hash]
                  ]}
                />
              ) : (
                <ParagraphBlock>Guard does not have a previous diff stored for this item yet.</ParagraphBlock>
              )}
            </DetailPanel>
            <DetailPanel title="Last trusted version">
              {receipt ? (
                <DetailList
                  items={[
                    ["Previous decision", receipt.policy_decision],
                    ["Capabilities", receipt.capabilities_summary],
                    ["Provenance", receipt.provenance_summary]
                  ]}
                />
              ) : (
                <ParagraphBlock>There is no older receipt stored for this item yet.</ParagraphBlock>
              )}
            </DetailPanel>
            <DetailPanel title="Guard will remember">
              {policy.length > 0 ? (
                <DetailList
                  items={policy.slice(0, 3).map((entry) => [
                    `${entry.scope} · ${entry.action}`,
                    entry.publisher ?? entry.workspace ?? entry.artifact_id ?? "Harness-wide rule"
                  ])}
                />
              ) : (
                <ParagraphBlock>No saved policy yet for this harness.</ParagraphBlock>
              )}
            </DetailPanel>
          </div>
        </div>
      </SurfaceCard>

      <SurfaceCard tone="accent">
        <div className="space-y-5">
          <div className="space-y-2">
            <p className="font-mono text-xs font-black uppercase tracking-[0.2em] text-brand-blue">Decision</p>
            <h3 className="text-2xl font-semibold tracking-[-0.04em] text-brand-dark">Approve or block</h3>
            <p className="text-sm leading-7 text-brand-dark/70">
              Pick the narrowest trust rule that gets you moving again.
            </p>
          </div>

          <div className="space-y-2">
            <span className="block text-sm font-semibold text-brand-dark">Decision scope</span>
            <div className="space-y-2">
              {scopeOptions.map((option) => (
                <button
                  key={option.value}
                  type="button"
                  className={`block w-full rounded-[18px] border px-4 py-3 text-left transition-colors ${
                    scope === option.value
                      ? "border-brand-blue/25 bg-brand-blue/8"
                      : "border-slate-200/70 bg-white hover:border-slate-300"
                  }`}
                  onClick={() => setScope(option.value)}
                >
                  <strong className="block text-sm font-semibold text-brand-dark">{option.title}</strong>
                  <span className="mt-1 block text-sm leading-6 text-brand-dark/62">{option.body}</span>
                </button>
              ))}
            </div>
          </div>

          {scope === "workspace" ? (
            <label className="block text-sm font-semibold text-brand-dark">
              <span className="mb-2 block">Workspace path</span>
              <input
                className="w-full rounded-[18px] border border-slate-200/70 bg-white px-4 py-3 text-sm text-brand-dark"
                value={workspace}
                onChange={(event) => setWorkspace(event.target.value)}
                placeholder="Required for workspace scope"
              />
            </label>
          ) : null}

          <label className="block text-sm font-semibold text-brand-dark">
            <span className="mb-2 block">Reason</span>
            <input
              className="w-full rounded-[18px] border border-slate-200/70 bg-white px-4 py-3 text-sm text-brand-dark"
              value={reason}
              onChange={(event) => setReason(event.target.value)}
            />
          </label>

          {errorMessage ? (
            <div className="rounded-[18px] border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
              {errorMessage}
            </div>
          ) : null}

          <div className="flex flex-wrap gap-3">
            <button
              type="button"
              className="inline-flex min-h-11 items-center justify-center rounded-full bg-brand-blue px-5 text-sm font-semibold text-white shadow-sm shadow-brand-blue/30 transition-colors duration-200 hover:bg-brand-blue/90"
              disabled={submitting !== null}
              onClick={() => void handleResolve("allow")}
            >
              {submitting === "allow" ? "Saving..." : "Allow this launch"}
            </button>
            <button
              type="button"
              className="inline-flex min-h-11 items-center justify-center rounded-full border border-slate-200/70 px-5 text-sm font-semibold text-brand-dark"
              disabled={submitting !== null}
              onClick={() => void handleResolve("block")}
            >
              {submitting === "block" ? "Saving..." : "Block for now"}
            </button>
          </div>
        </div>
      </SurfaceCard>
    </div>
  );
}

function SurfaceCard(props: {
  children: ReactNode;
  tone?: "default" | "success" | "accent";
}) {
  const toneClass =
    props.tone === "success"
      ? "border-brand-green/20 bg-brand-green-bg"
      : props.tone === "accent"
        ? "border-slate-200/65 bg-white/88"
        : "border-slate-200/55 bg-white/78";
  return (
    <section className={`rounded-[28px] border p-6 shadow-[0_24px_60px_-36px_rgba(17,24,39,0.25)] ${toneClass}`}>
      {props.children}
    </section>
  );
}

function DetailPanel(props: { title: string; children: ReactNode }) {
  return (
    <article className="rounded-[22px] border border-slate-200/70 bg-slate-50/85 p-5">
      <p className="mb-3 font-mono text-xs font-black uppercase tracking-[0.18em] text-brand-blue">{props.title}</p>
      {props.children}
    </article>
  );
}

function DetailList(props: { items: Array<[string, string]> }) {
  return (
    <ul className="space-y-4 text-sm text-brand-dark/80">
      {props.items.map(([label, value]) => (
        <li key={`${label}-${value}`}>
          <strong className="block text-[11px] uppercase tracking-[0.18em] text-brand-dark/50">{label}</strong>
          <span className="mt-1 block">{value}</span>
        </li>
      ))}
    </ul>
  );
}

function EmptyState(props: { title: string; body: string }) {
  return (
    <div className="rounded-[24px] border border-dashed border-slate-200/80 bg-slate-50/60 px-6 py-10 text-center">
      <h3 className="text-2xl font-semibold tracking-[-0.04em] text-brand-dark">{props.title}</h3>
      <p className="mx-auto mt-3 max-w-2xl text-sm leading-7 text-brand-dark/70">{props.body}</p>
    </div>
  );
}

function ParagraphBlock(props: { children: ReactNode }) {
  return <p className="text-sm leading-7 text-brand-dark/70">{props.children}</p>;
}

function Tag(props: { children: ReactNode; tone: "blue" | "green" | "purple" | "slate" }) {
  const toneClass =
    props.tone === "blue"
      ? "bg-brand-blue/10 text-brand-blue"
      : props.tone === "green"
        ? "bg-brand-green/14 text-brand-green-text"
        : props.tone === "purple"
          ? "bg-brand-purple/12 text-brand-purple"
          : "bg-slate-900/5 text-slate-500";
  return (
    <span className={`inline-flex min-h-8 items-center rounded-full px-3 text-xs font-bold uppercase tracking-[0.14em] ${toneClass}`}>
      {props.children}
    </span>
  );
}

function SummaryChip(props: {
  label: string;
  value: string;
}) {
  return (
    <div className="rounded-[20px] border border-slate-200/65 bg-slate-50/80 px-4 py-4">
      <strong className="block font-mono text-[11px] font-black uppercase tracking-[0.18em] text-brand-dark/50">
        {props.label}
      </strong>
      <p className="mt-2 text-base font-semibold tracking-[-0.03em] text-brand-dark">{props.value}</p>
    </div>
  );
}

function InfoRow(props: { label: string; value: string }) {
  return (
    <div className="space-y-1">
      <strong className="block font-mono text-[11px] font-black uppercase tracking-[0.18em] text-brand-dark/50">
        {props.label}
      </strong>
      <p className="text-sm leading-7 text-brand-dark/80">{props.value}</p>
    </div>
  );
}

function FooterSection(props: {
  title: string;
  links: Array<{ href: string; label: string }>;
}) {
  return (
    <details className="group border-b border-indigo-200/20 py-2 sm:border-none sm:py-0">
      <summary className="flex cursor-pointer list-none items-center justify-between py-2 text-[15px] font-bold text-white transition-colors hover:text-indigo-100 [&::-webkit-details-marker]:hidden">
        {props.title}
        <span className="text-indigo-300 transition-transform duration-300 group-open:rotate-180">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="m6 9 6 6 6-6" />
          </svg>
        </span>
      </summary>
      <ul className="mt-3 space-y-4 pb-4 sm:pb-0">
        {props.links.map((link) => (
          <li key={`${props.title}-${link.href}`}>
            <a
              href={link.href}
              target="_blank"
              rel="noreferrer"
              className="block p-1 text-[15px] font-medium text-indigo-100 transition-colors hover:text-white"
            >
              {link.label}
            </a>
          </li>
        ))}
      </ul>
    </details>
  );
}
