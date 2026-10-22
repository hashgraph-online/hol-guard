import { j as jsxRuntimeExports, A as ActionButton, T as Tag, H as HiMiniChevronRight, dW as HiMiniArrowDownTray, bS as HiMiniInformationCircle, cn as HiMiniArrowTopRightOnSquare, Z as HiMiniSparkles, _ as HiMiniXMark, d$ as fetchReleaseFeedApi, r as reactExports, N as EmptyState } from "../guard-dashboard.js";
const CHANGE_ORDER = [
  "security",
  "added",
  "changed",
  "fixed",
  "removed",
  "other"
];
const CHANGE_LABELS = {
  security: "Security",
  added: "Added",
  changed: "Changed",
  fixed: "Fixed",
  removed: "Removed",
  other: "Also in this release"
};
function groupChangesByKind(changes) {
  return CHANGE_ORDER.map((kind) => ({
    kind,
    label: CHANGE_LABELS[kind],
    changes: changes.filter((change) => change.kind === kind)
  })).filter((section) => section.changes.length > 0);
}
function normalizeVersionLabel(version) {
  const trimmed = version.trim();
  return trimmed.startsWith("v") ? trimmed.slice(1) : trimmed;
}
function installedRelease(releases, installedVersion) {
  if (!installedVersion) return null;
  const wanted = normalizeVersionLabel(installedVersion);
  if (!wanted) return null;
  return releases.find((release) => normalizeVersionLabel(release.versionLabel) === wanted) ?? null;
}
const WHATS_NEW_STORAGE_PREFIX = "guard.releases.whats-new.";
function whatsNewStorageKey(versionLabel) {
  return `${WHATS_NEW_STORAGE_PREFIX}${normalizeVersionLabel(versionLabel)}`;
}
function isWhatsNewDismissed(versionLabel) {
  try {
    return window.localStorage.getItem(whatsNewStorageKey(versionLabel)) === "dismissed";
  } catch {
    return false;
  }
}
function dismissWhatsNew(versionLabel) {
  try {
    window.localStorage.setItem(whatsNewStorageKey(versionLabel), "dismissed");
  } catch {
  }
}
function channelLabel(channel) {
  return channel === "stable" ? "Stable" : "Preview";
}
function formatReleaseDate(instant) {
  const parsed = new Date(instant);
  if (Number.isNaN(parsed.getTime())) {
    return instant;
  }
  return parsed.toLocaleDateString(void 0, { year: "numeric", month: "long", day: "numeric" });
}
function coverageNote(coverage) {
  if (coverage.attributionState === "complete" && coverage.historyCoverage === "complete") {
    return null;
  }
  if (coverage.attributionState === "unknown") {
    return "Contributor attribution for this release has not been verified yet, so the list below may be incomplete.";
  }
  if (coverage.attributionState === "in-progress") {
    return "Contributor attribution for this release is still being verified; names may still be added.";
  }
  return "Guard's published history does not cover every release before this one.";
}
function comparisonLine(comparison) {
  if (comparison.available) {
    return `Changes since ${comparison.predecessorRawTag}.`;
  }
  if (comparison.reason === "first-release") {
    return "The first published release, so there is nothing to compare it against.";
  }
  return "The release before this one has not been verified, so the change list is not a verified comparison.";
}
function contributorName(contributor) {
  if (contributor.login) return contributor.login;
  return `GitHub user ${contributor.githubNumericId}`;
}
const VERIFICATION_LABELS = {
  "pull-request-author": "Verified from the merged pull request",
  "verified-direct-commit-author": "Verified from a signed commit",
  "verified-coauthor": "Verified co-author trailer"
};
function verificationLabel(method) {
  return VERIFICATION_LABELS[method];
}
function installedNote(releases, installedVersion) {
  const label = normalizeVersionLabel((installedVersion ?? "").trim());
  if (!label) return "";
  if (installedRelease(releases, installedVersion)) return ` This device is running ${label}.`;
  return ` This device is running ${label}, which is not on this page of the archive.`;
}
const FAILURE_COPY = {
  offline: {
    title: "Guard could not reach the release archive",
    body: "The archive is published by hol.org and read through Guard on this device. Check this device's connection and try again."
  },
  unavailable: {
    title: "The release archive did not answer",
    body: "hol.org could not serve the archive just now. Nothing on this device is affected; try again in a few minutes."
  },
  "not-found": {
    title: "That release is not published",
    body: "Guard only shows releases that have been published and verified. Pick another version from the list."
  },
  unsupported: {
    title: "This Guard build cannot read the archive",
    body: "The release archive needs Guard's native runtime. Update Guard to see release history here."
  },
  disabled: {
    title: "Release history is turned off on this device",
    body: "Guard is set to skip the release archive (HOL_GUARD_RELEASE_FEED=off). Nothing on hol.org is affected; clear that setting and restart Guard to read release history here."
  }
};
function failureCopy(failure) {
  return FAILURE_COPY[failure];
}
function isRetryable(failure) {
  return failure === "unavailable" || failure === "offline";
}
function openingSlug(releases, installedVersion, current, readerChose) {
  const held = current !== null && releases.some((release) => release.slug === current);
  if (held && readerChose) return current;
  return installedRelease(releases, installedVersion)?.slug ?? releases[0]?.slug ?? null;
}
function hasNextPage(index) {
  return index.page < index.totalPages;
}
function hasPreviousPage(index) {
  return index.page > 1;
}
function pageRangeLabel(index) {
  if (index.total === 0) return "No published releases";
  const first = (index.page - 1) * index.pageSize + 1;
  const last = Math.min(index.total, first + index.releases.length - 1);
  return `Showing ${first}–${last} of ${index.total} ${index.total === 1 ? "release" : "releases"}`;
}
function ReleaseRow(props) {
  const { release } = props;
  return /* @__PURE__ */ jsxRuntimeExports.jsx("li", { children: /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "button",
    {
      type: "button",
      "aria-current": props.selected ? "true" : void 0,
      onClick: () => props.onSelect(release.slug),
      className: `group flex w-full min-h-11 items-center gap-3 rounded-xl border px-3 py-3 text-left transition-colors duration-150 motion-reduce:transition-none ${props.selected ? "border-brand-blue/40 bg-brand-blue/[0.06]" : "border-transparent hover:border-brand-dark/10 hover:bg-brand-dark/[0.03]"}`,
      children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "min-w-0 flex-1", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "flex flex-wrap items-center gap-2", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { className: "text-sm font-semibold text-brand-dark", children: normalizeVersionLabel(release.versionLabel) }),
            release.channel === "preview" ? /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: "amber", children: "Preview" }) : null,
            props.installed ? /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: "blue", children: "Installed here" }) : null
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "mt-0.5 block truncate text-sm text-brand-dark/70", children: release.title }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "mt-0.5 block text-xs text-brand-dark/55", children: [
            channelLabel(release.channel),
            " · ",
            formatReleaseDate(release.publishedAt)
          ] })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          HiMiniChevronRight,
          {
            className: "size-5 shrink-0 text-brand-dark/35 transition-transform duration-150 group-hover:translate-x-0.5 motion-reduce:transition-none",
            "aria-hidden": "true"
          }
        )
      ]
    }
  ) });
}
function ReleaseArchiveList(props) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("nav", { "aria-label": "Published Guard releases", className: "space-y-3", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "space-y-1", children: props.index.releases.map((release) => /* @__PURE__ */ jsxRuntimeExports.jsx(
      ReleaseRow,
      {
        release,
        selected: release.slug === props.selectedSlug,
        installed: release.slug === props.installedSlug,
        onSelect: props.onSelect
      },
      release.slug
    )) }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center justify-between gap-2 border-t border-brand-dark/10 pt-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-brand-dark/55", children: pageRangeLabel(props.index) }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          ActionButton,
          {
            variant: "outline",
            disabled: !hasPreviousPage(props.index),
            onClick: () => props.onPage(props.index.page - 1),
            children: "Newer"
          }
        ),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          ActionButton,
          {
            variant: "outline",
            disabled: !hasNextPage(props.index),
            onClick: () => props.onPage(props.index.page + 1),
            children: "Older"
          }
        )
      ] })
    ] })
  ] });
}
function CoverageNote({ note }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "flex items-start gap-2 rounded-xl border border-amber-200 bg-amber-50 px-3 py-2 text-sm text-amber-900", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniInformationCircle, { className: "mt-0.5 size-4 shrink-0", "aria-hidden": "true" }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: note })
  ] });
}
function ChangeItem({ change }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { className: "text-sm leading-6 text-brand-dark/80", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "whitespace-pre-line", children: change.summary }),
    change.evidenceUrl ? /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
      " ",
      /* @__PURE__ */ jsxRuntimeExports.jsxs(
        "a",
        {
          href: change.evidenceUrl,
          target: "_blank",
          rel: "noopener noreferrer",
          className: "inline-flex items-center gap-1 font-semibold text-brand-blue underline decoration-brand-blue/40 underline-offset-2 hover:decoration-brand-blue",
          children: [
            "Evidence",
            /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowTopRightOnSquare, { className: "size-3.5", "aria-hidden": "true" })
          ]
        }
      )
    ] }) : null
  ] });
}
function ContributorRow({ contributor }) {
  const name = contributorName(contributor);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { className: "flex flex-wrap items-baseline gap-x-2 gap-y-0.5 text-sm", children: [
    contributor.evidenceUrl ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      "a",
      {
        href: contributor.evidenceUrl,
        target: "_blank",
        rel: "noopener noreferrer",
        className: "font-semibold text-brand-blue underline decoration-brand-blue/40 underline-offset-2 hover:decoration-brand-blue",
        children: name
      }
    ) : /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-semibold text-brand-dark", children: name }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-brand-dark/70", children: contributor.roles.join(", ") }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs text-brand-dark/55", children: verificationLabel(contributor.verificationMethod) })
  ] });
}
function ReleaseDetailPanel({ detail }) {
  const sections = groupChangesByKind(detail.changes);
  const note = coverageNote(detail.coverage);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "article",
    {
      "aria-labelledby": "release-detail-heading",
      className: "guard-surface-in space-y-6 rounded-xl border border-brand-dark/10 bg-white p-4 sm:p-6",
      children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("header", { className: "space-y-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsxs("h2", { id: "release-detail-heading", className: "text-xl font-semibold tracking-tight text-brand-dark", children: [
              "Guard ",
              normalizeVersionLabel(detail.versionLabel)
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: detail.channel === "stable" ? "green" : "amber", children: channelLabel(detail.channel) })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "text-sm text-brand-dark/70", children: [
            detail.title,
            " · released ",
            formatReleaseDate(detail.publishedAt),
            " · tagged ",
            detail.rawTag
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-brand-dark/60", children: comparisonLine(detail.comparison) })
        ] }),
        note ? /* @__PURE__ */ jsxRuntimeExports.jsx(CoverageNote, { note }) : null,
        detail.summary ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "whitespace-pre-line text-sm leading-6 text-brand-dark/80", children: detail.summary }) : null,
        sections.length > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "space-y-5", children: sections.map((section) => /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { "aria-labelledby": `release-changes-${section.kind}`, className: "space-y-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            "h3",
            {
              id: `release-changes-${section.kind}`,
              className: "text-sm font-semibold text-brand-dark",
              children: section.label
            }
          ),
          /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "list-disc space-y-1.5 pl-5", children: section.changes.map((change) => /* @__PURE__ */ jsxRuntimeExports.jsx(ChangeItem, { change }, change.id)) })
        ] }, section.kind)) }) : /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-brand-dark/70", children: "No itemised changes were published for this release." }),
        detail.roster.length > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { "aria-labelledby": "release-roster-heading", className: "space-y-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { id: "release-roster-heading", className: "text-sm font-semibold text-brand-dark", children: "Verified contributors" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "space-y-1.5", children: detail.roster.map((contributor) => /* @__PURE__ */ jsxRuntimeExports.jsx(ContributorRow, { contributor }, contributor.creditId)) })
        ] }) : null,
        detail.assets.length > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { "aria-labelledby": "release-assets-heading", className: "space-y-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { id: "release-assets-heading", className: "text-sm font-semibold text-brand-dark", children: "Downloads" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "flex flex-wrap gap-2", children: detail.assets.map((asset) => /* @__PURE__ */ jsxRuntimeExports.jsx("li", { children: /* @__PURE__ */ jsxRuntimeExports.jsxs(
            "a",
            {
              href: asset.url,
              target: "_blank",
              rel: "noopener noreferrer",
              className: "inline-flex min-h-11 items-center gap-2 rounded-xl border border-brand-dark/15 px-3 text-sm font-semibold text-brand-dark hover:border-brand-blue/40 hover:bg-brand-blue/[0.04]",
              children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowDownTray, { className: "size-4", "aria-hidden": "true" }),
                asset.name
              ]
            }
          ) }, asset.url)) })
        ] }) : null,
        detail.sourceNotes ? /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { "aria-labelledby": "release-source-heading", className: "space-y-2 border-t border-brand-dark/10 pt-4", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { id: "release-source-heading", className: "text-sm font-semibold text-brand-dark", children: detail.sourceNotes.scope === "exact_release" ? "Published release notes" : `Release notes for the ${detail.train} series` }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "whitespace-pre-line text-sm leading-6 text-brand-dark/75", children: detail.sourceNotes.text })
        ] }) : null
      ]
    },
    detail.slug
  );
}
function WhatsNewCard(props) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx(
    "section",
    {
      "aria-labelledby": "whats-new-heading",
      className: "guard-surface-in relative overflow-hidden rounded-xl border border-brand-blue/20 bg-brand-blue/[0.04] p-4 sm:p-5",
      children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-start gap-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "span",
          {
            className: "flex size-9 shrink-0 items-center justify-center rounded-full bg-brand-blue/10 text-brand-blue",
            "aria-hidden": "true",
            children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniSparkles, { className: "size-5" })
          }
        ),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0 flex-1 space-y-1", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("h2", { id: "whats-new-heading", className: "text-base font-semibold text-brand-dark", children: [
            "What's new in Guard ",
            normalizeVersionLabel(props.release.versionLabel)
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "text-sm text-brand-dark/70", children: [
            props.release.title,
            " · ",
            channelLabel(props.release.channel),
            " · released",
            " ",
            formatReleaseDate(props.release.publishedAt)
          ] })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { variant: "primary", onClick: props.onRead, children: "Read the notes" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            "button",
            {
              type: "button",
              onClick: props.onDismiss,
              "aria-label": `Dismiss what's new in Guard ${normalizeVersionLabel(props.release.versionLabel)}`,
              className: "flex size-11 items-center justify-center rounded-xl text-brand-dark/55 hover:bg-brand-dark/5 hover:text-brand-dark",
              children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniXMark, { className: "size-5", "aria-hidden": "true" })
            }
          )
        ] })
      ] })
    }
  );
}
const RELEASES_PAGE_SIZE = 25;
const CAPABILITY_UNAVAILABLE = "release_feed_capability_unavailable";
function isRecord(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
async function errorCode(response) {
  try {
    const payload = await response.json();
    return isRecord(payload) && typeof payload.error === "string" ? payload.error : null;
  } catch {
    return null;
  }
}
async function failureForResponse(response) {
  if (response.status === 404) return "not-found";
  if (response.status === 501) return "unsupported";
  if (response.status === 503 && await errorCode(response) === CAPABILITY_UNAVAILABLE) {
    return "disabled";
  }
  return "unavailable";
}
async function readDocument(path, kind, signal) {
  let response;
  try {
    response = await fetchReleaseFeedApi(path, { signal, redirect: "error" });
  } catch {
    return { status: "failed", failure: "offline" };
  }
  if (!response.ok) {
    return { status: "failed", failure: await failureForResponse(response) };
  }
  let payload;
  try {
    payload = await response.json();
  } catch {
    return { status: "failed", failure: "unavailable" };
  }
  if (!isRecord(payload) || payload.kind !== kind) {
    return { status: "failed", failure: "unavailable" };
  }
  return { status: "ok", document: payload };
}
async function fetchReleaseIndex(options = {}) {
  const page = Number.isInteger(options.page) && options.page >= 1 ? options.page : 1;
  const result = await readDocument(
    `/v1/releases/index?page=${page}&pageSize=${RELEASES_PAGE_SIZE}`,
    "index",
    options.signal
  );
  if (result.status === "failed") {
    return result;
  }
  return { status: "ok", index: result.document };
}
async function fetchReleaseDetail(slug, options = {}) {
  if (!/^[a-z0-9][a-z0-9.-]{0,127}$/.test(slug)) {
    return { status: "failed", failure: "not-found" };
  }
  const result = await readDocument(`/v1/releases/release?slug=${slug}`, "detail", options.signal);
  if (result.status === "failed") {
    return result;
  }
  return { status: "ok", detail: result.document };
}
function FailureNotice(props) {
  const copy = failureCopy(props.failure);
  return /* @__PURE__ */ jsxRuntimeExports.jsx(
    EmptyState,
    {
      title: copy.title,
      body: copy.body,
      action: props.onRetry ? /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { variant: "outline", onClick: props.onRetry, children: "Try again" }) : void 0
    }
  );
}
function LoadingNotice({ label }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "status", className: "py-8 text-center text-sm text-brand-dark/60", children: label });
}
function ReleasesWorkspace({ installedVersion }) {
  const [page, setPage] = reactExports.useState(1);
  const [indexState, setIndexState] = reactExports.useState({ kind: "loading" });
  const [selectedSlug, setSelectedSlug] = reactExports.useState(null);
  const [detailState, setDetailState] = reactExports.useState({ kind: "idle" });
  const [dismissedLabel, setDismissedLabel] = reactExports.useState(null);
  const [reloadToken, setReloadToken] = reactExports.useState(0);
  const [detailToken, setDetailToken] = reactExports.useState(0);
  const detailHeadingRef = reactExports.useRef(null);
  const readerChose = reactExports.useRef(false);
  reactExports.useEffect(() => {
    const controller = new AbortController();
    setIndexState({ kind: "loading" });
    fetchReleaseIndex({ page, signal: controller.signal }).then((result) => {
      if (controller.signal.aborted) return;
      if (result.status === "failed") {
        setIndexState({ kind: "failed", failure: result.failure });
        return;
      }
      setIndexState({ kind: "ready", index: result.index });
    }).catch(() => {
      if (!controller.signal.aborted) {
        setIndexState({ kind: "failed", failure: "unavailable" });
      }
    });
    return () => controller.abort();
  }, [page, reloadToken]);
  reactExports.useEffect(() => {
    if (indexState.kind !== "ready") return;
    const releases = indexState.index.releases;
    setSelectedSlug((current) => openingSlug(releases, installedVersion, current, readerChose.current));
  }, [indexState, installedVersion]);
  reactExports.useEffect(() => {
    if (!selectedSlug) {
      setDetailState({ kind: "idle" });
      return;
    }
    const controller = new AbortController();
    setDetailState({ kind: "loading" });
    fetchReleaseDetail(selectedSlug, { signal: controller.signal }).then((result) => {
      if (controller.signal.aborted) return;
      setDetailState(
        result.status === "failed" ? { kind: "failed", failure: result.failure } : { kind: "ready", detail: result.detail }
      );
    }).catch(() => {
      if (!controller.signal.aborted) {
        setDetailState({ kind: "failed", failure: "unavailable" });
      }
    });
    return () => controller.abort();
  }, [selectedSlug, detailToken]);
  const installed = indexState.kind === "ready" ? installedRelease(indexState.index.releases, installedVersion) : null;
  const installedLabel = installed?.versionLabel ?? null;
  const dismissedBefore = reactExports.useMemo(
    () => installedLabel === null ? false : isWhatsNewDismissed(installedLabel),
    [installedLabel]
  );
  const whatsNewDismissed = dismissedBefore || dismissedLabel === installedLabel;
  const handleSelect = reactExports.useCallback((slug) => {
    readerChose.current = true;
    setSelectedSlug(slug);
    detailHeadingRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
  }, []);
  const handleReadWhatsNew = reactExports.useCallback(() => {
    if (installed) handleSelect(installed.slug);
  }, [installed, handleSelect]);
  const handleDismissWhatsNew = reactExports.useCallback(() => {
    if (!installedLabel) return;
    dismissWhatsNew(installedLabel);
    setDismissedLabel(installedLabel);
  }, [installedLabel]);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-6 pb-10", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("header", { className: "space-y-1", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h1", { className: "text-2xl font-semibold tracking-tight text-brand-dark", children: "Releases" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "text-sm text-brand-dark/65", children: [
        "Every published Guard version, what it changed, and who is verified to have changed it.",
        indexState.kind === "ready" ? installedNote(indexState.index.releases, installedVersion) : ""
      ] })
    ] }),
    installed && !whatsNewDismissed ? /* @__PURE__ */ jsxRuntimeExports.jsx(WhatsNewCard, { release: installed, onRead: handleReadWhatsNew, onDismiss: handleDismissWhatsNew }) : null,
    indexState.kind === "loading" ? /* @__PURE__ */ jsxRuntimeExports.jsx(LoadingNotice, { label: "Reading the release archive…" }) : null,
    indexState.kind === "failed" ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      FailureNotice,
      {
        failure: indexState.failure,
        onRetry: isRetryable(indexState.failure) ? () => setReloadToken((token) => token + 1) : void 0
      }
    ) : null,
    indexState.kind === "ready" && indexState.index.releases.length === 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      EmptyState,
      {
        title: "No releases are published yet",
        body: "Once a Guard release is published and verified, it appears here with its notes and contributors."
      }
    ) : null,
    indexState.kind === "ready" && indexState.index.releases.length > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-6 lg:grid-cols-[minmax(0,20rem)_minmax(0,1fr)]", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        ReleaseArchiveList,
        {
          index: indexState.index,
          selectedSlug,
          installedSlug: installed?.slug ?? null,
          onSelect: handleSelect,
          onPage: setPage
        }
      ),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { ref: detailHeadingRef, className: "min-w-0", children: [
        detailState.kind === "loading" ? /* @__PURE__ */ jsxRuntimeExports.jsx(LoadingNotice, { label: "Reading this release…" }) : null,
        detailState.kind === "failed" ? /* @__PURE__ */ jsxRuntimeExports.jsx(
          FailureNotice,
          {
            failure: detailState.failure,
            onRetry: isRetryable(detailState.failure) ? () => setDetailToken((token) => token + 1) : void 0
          }
        ) : null,
        detailState.kind === "ready" ? /* @__PURE__ */ jsxRuntimeExports.jsx(ReleaseDetailPanel, { detail: detailState.detail }) : null
      ] })
    ] }) : null
  ] });
}
export {
  ReleasesWorkspace
};
